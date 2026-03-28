"""Configuration loading and management.

This module handles loading YAML configuration files with environment-specific
overrides and environment variable substitution.
"""

import os
import yaml
from typing import Any, Dict, Optional
from pathlib import Path


ENV_ALIASES = {
    "development": "dev",
    "dev": "dev",
    "production": "prod",
    "prod": "prod",
}


def load_config(
    config_path: str = "config/default.yaml",
    env: str = "dev",
    allow_env_override: bool = True,
) -> Dict[str, Any]:
    """Load configuration from YAML files.

    Loads base configuration from default.yaml, then merges environment-specific
    overrides from dev.yaml or prod.yaml, and finally applies environment
    variable substitution.

    Args:
        config_path: Path to base configuration file.
        env: Environment name (dev, prod).
        allow_env_override: If True, substitute ${VAR} placeholders with env vars.

    Returns:
        Dictionary containing merged configuration.
    """
    env = ENV_ALIASES.get(os.environ.get("ENVIRONMENT", env), env)
    base_path = Path(config_path)
    if not base_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {base_path}")

    # Load base config
    with open(base_path, "r") as f:
        config = yaml.safe_load(f) or {}

    # Load environment-specific config if exists
    env_config_path = base_path.parent / f"{env}.yaml"
    if env_config_path.exists():
        with open(env_config_path, "r") as f:
            env_config = yaml.safe_load(f) or {}
        # Deep merge
        config = deep_merge(config, env_config)

    # Load modular component configurations and fold them into the runtime config.
    config = load_component_configs(base_path.parent, config)

    # Environment variable substitution
    if allow_env_override:
        config = substitute_env_vars(config)
        config = apply_runtime_env_overrides(config)

    return config


def load_component_configs(config_root: Path, config: Dict[str, Any]) -> Dict[str, Any]:
    """Load modular detection/mitigation config fragments and integrate them."""
    result = deep_merge(config, {})

    detection_dir = config_root / "detection"
    if detection_dir.exists():
        detection_config = result.setdefault("detection", {})
        for path in sorted(detection_dir.glob("*.yaml")):
            with open(path, "r") as f:
                detection_config[path.stem] = yaml.safe_load(f) or {}

    mitigation_dir = config_root / "mitigation"
    if mitigation_dir.exists():
        mitigation_config = result.setdefault("mitigation", {})
        for path in sorted(mitigation_dir.glob("*.yaml")):
            with open(path, "r") as f:
                mitigation_config[path.stem] = yaml.safe_load(f) or {}

    return integrate_component_configs(result)


def integrate_component_configs(config: Dict[str, Any]) -> Dict[str, Any]:
    """Project modular config fragments into the runtime sections used by services."""
    result = deep_merge(config, {})

    detection = result.setdefault("detection", {})
    anomaly = detection.setdefault("anomaly", {})
    volumetric_profile = detection.get("volumetric", {})
    if volumetric_profile:
        volumetric_cfg = anomaly.setdefault("volumetric", {})
        mbps_cfg = volumetric_profile.get("mbps", {})
        pps_cfg = volumetric_profile.get("pps", {})
        windows_cfg = volumetric_profile.get("windows", {})
        if "critical" in mbps_cfg:
            volumetric_cfg.setdefault("threshold_mbps", mbps_cfg["critical"])
        if "critical" in pps_cfg:
            volumetric_cfg.setdefault("threshold_pps", pps_cfg["critical"])
        if windows_cfg:
            anomaly.setdefault("windows", {})
            anomaly["windows"] = deep_merge(windows_cfg, anomaly["windows"])

    behavioral_profile = detection.get("behavioral", {})
    if behavioral_profile:
        entropy_cfg = behavioral_profile.get("entropy", {})
        if entropy_cfg:
            anomaly.setdefault("entropy", {})
            if "threshold" in entropy_cfg:
                anomaly["entropy"].setdefault("threshold", entropy_cfg["threshold"])
            if "features" in entropy_cfg:
                anomaly["entropy"].setdefault("features", entropy_cfg["features"])
            if "window" in entropy_cfg:
                anomaly.setdefault("windows", {})
                anomaly["windows"].setdefault("short", entropy_cfg["window"])
            if "baseline_window" in entropy_cfg:
                anomaly.setdefault("windows", {})
                anomaly["windows"].setdefault("long", entropy_cfg["baseline_window"])

        tcp_cfg = behavioral_profile.get("tcp", {})
        if tcp_cfg.get("syn_flood"):
            anomaly.setdefault("syn_flood", {})
            anomaly["syn_flood"].setdefault("threshold", tcp_cfg["syn_flood"].get("threshold"))

        icmp_cfg = behavioral_profile.get("icmp", {})
        if icmp_cfg:
            anomaly.setdefault("icmp_flood", {})
            anomaly["icmp_flood"].setdefault(
                "threshold",
                icmp_cfg.get("flood_threshold", icmp_cfg.get("echo_flood_threshold")),
            )

        baseline_cfg = behavioral_profile.get("baseline", {})
        if baseline_cfg.get("deviation_factor") is not None:
            anomaly.setdefault("deviation_factor", baseline_cfg["deviation_factor"])

        anomaly["behavioral_profile"] = behavioral_profile

    ml_profile = detection.get("ml_models", {})
    if ml_profile:
        ml_cfg = detection.setdefault("ml", {})
        general_cfg = ml_profile.get("general", {})
        model_cfg = ml_profile.get("models", {}).get("ensemble", {})
        feature_cfg = ml_profile.get("feature_extractor", {})
        if "enabled" in general_cfg:
            ml_cfg.setdefault("enabled", general_cfg["enabled"])
        if "batch_size" in general_cfg:
            ml_cfg.setdefault("batch_size", general_cfg["batch_size"])
        if "confidence_threshold" in general_cfg:
            ml_cfg.setdefault("confidence_threshold", general_cfg["confidence_threshold"])
        if "inference_mode" in general_cfg:
            ml_cfg.setdefault("inference_mode", general_cfg["inference_mode"])
        if model_cfg.get("path"):
            ml_cfg.setdefault("model_path", model_cfg["path"])
        if feature_cfg.get("path"):
            ml_cfg.setdefault("feature_extractor_path", feature_cfg["path"])
        if feature_cfg.get("features"):
            ml_cfg.setdefault("features", feature_cfg["features"])
        ml_cfg["model_profile"] = ml_profile

    mitigation = result.setdefault("mitigation", {})
    rate_limits_profile = mitigation.get("rate_limits", {})
    if rate_limits_profile:
        rate_limiting = mitigation.setdefault("rate_limiting", {})
        global_cfg = rate_limits_profile.get("global", {})
        if global_cfg:
            rate_limiting.setdefault("default_mbps", global_cfg.get("mbps", rate_limiting.get("default_mbps", 100)))
            rate_limiting.setdefault("default_pps", global_cfg.get("pps", rate_limiting.get("default_pps", 5000)))
            if global_cfg.get("per_ip"):
                rate_limiting.setdefault("per_ip", {})
                rate_limiting["per_ip"] = deep_merge(global_cfg["per_ip"], rate_limiting["per_ip"])
            if global_cfg.get("per_subnet"):
                rate_limiting.setdefault("per_subnet", {})
                rate_limiting["per_subnet"] = deep_merge(global_cfg["per_subnet"], rate_limiting["per_subnet"])
        rate_limiting["policy_profile"] = rate_limits_profile

    scrubbing_profile = mitigation.get("scrubbing_centers", {})
    if scrubbing_profile:
        if scrubbing_profile.get("scrubbing_centers"):
            mitigation["scrubbing_centers"] = scrubbing_profile["scrubbing_centers"]
        defaults_cfg = scrubbing_profile.get("defaults", {})
        if defaults_cfg:
            mitigation.setdefault("bgp", {})
            if defaults_cfg.get("announcement_duration") is not None:
                mitigation["bgp"].setdefault("announcement_duration", defaults_cfg["announcement_duration"])
            if defaults_cfg.get("community") is not None:
                mitigation["bgp"].setdefault("community", defaults_cfg["community"])
        mitigation["scrubbing_profile"] = scrubbing_profile

    return result


def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Deep merge two dictionaries.

    Args:
        base: Base dictionary.
        override: Override dictionary (values take precedence).

    Returns:
        Merged dictionary.
    """
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def substitute_env_vars(obj: Any) -> Any:
    """Recursively substitute ${VAR} placeholders with environment variables.

    Args:
        obj: Object to process (dict, list, str, or other).

    Returns:
        Object with environment variables substituted.
    """
    if isinstance(obj, dict):
        return {k: substitute_env_vars(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [substitute_env_vars(v) for v in obj]
    elif isinstance(obj, str):
        # Simple ${VAR} substitution
        import re
        def replacer(match):
            var_name = match.group(1)
            return os.environ.get(var_name, match.group(0))
        return re.sub(r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}', replacer, obj)
    else:
        return obj


def apply_runtime_env_overrides(config: Dict[str, Any]) -> Dict[str, Any]:
    """Apply common runtime overrides from environment variables."""
    config = deep_merge(config, {})

    kafka_servers = os.environ.get("KAFKA_BOOTSTRAP_SERVERS")
    if kafka_servers:
        kafka_config = config.setdefault("kafka", {})
        kafka_config["bootstrap_servers"] = [
            server.strip() for server in kafka_servers.split(",") if server.strip()
        ]

    database_config = config.setdefault("database", {})
    if os.environ.get("DB_HOST"):
        database_config["host"] = os.environ["DB_HOST"]
    if os.environ.get("DB_PORT"):
        database_config["port"] = int(os.environ["DB_PORT"])
    if os.environ.get("DB_NAME"):
        database_config["name"] = os.environ["DB_NAME"]
    if os.environ.get("DB_USER"):
        database_config["user"] = os.environ["DB_USER"]
    if os.environ.get("DB_PASSWORD"):
        database_config["password"] = os.environ["DB_PASSWORD"]

    redis_config = config.setdefault("redis", {})
    if os.environ.get("REDIS_HOST"):
        redis_config["host"] = os.environ["REDIS_HOST"]
    if os.environ.get("REDIS_PORT"):
        redis_config["port"] = int(os.environ["REDIS_PORT"])

    return config
