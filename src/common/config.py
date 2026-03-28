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

    # Environment variable substitution
    if allow_env_override:
        config = substitute_env_vars(config)
        config = apply_runtime_env_overrides(config)

    return config


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
