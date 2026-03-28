# Configuration Guide

The DDoS Defense Platform is highly configurable through YAML files. This guide explains the key configuration sections and how to tune them for your environment.

## Configuration File Structure

All configuration files reside in the `config/` directory. The base configuration is `config/default.yaml`. Environment‑specific overrides (e.g., `dev.yaml`, `prod.yaml`) are merged on top of it.

### Loading Order
1. `config/default.yaml` – loaded first.
2. `config/<env>.yaml` – if `--env` flag is provided, values override default.
3. Environment variables – if `allow_env_override: true`, `${VAR}` placeholders are substituted.

## Global Settings

```yaml
environment: production   # development, staging, production
log_level: INFO           # DEBUG, INFO, WARNING, ERROR
debug: false              # Enable debug mode
Telemetry Ingestion
Packet Capture
yaml
ingestion:
  packet_capture:
    enabled: true
    interface: eth0               # Network interface to capture from
    backend: auto                 # auto, scapy, pcapy, pfring
    promiscuous: true
    snaplen: 1518
    buffer_size: 2097152          # 2 MB
    filter: ""                    # BPF filter (e.g., "port 80")
Flow Collector (NetFlow/sFlow)
yaml
ingestion:
  flow_collector:
    enabled: false
    listen_host: 0.0.0.0
    listen_port: 2055
    protocol: udp                 # udp or tcp
    collector_type: netflow       # netflow, sflow
    buffer_size: 65536
gNMI Telemetry
yaml
ingestion:
  gnmi:
    enabled: false
    target_host: router.example.com
    target_port: 9339
    username: admin
    password: ${GNMI_PASSWORD}
    tls: true
    ca_cert: /etc/ssl/certs/ca.pem
    subscribe_paths:
      - /interfaces/interface/state/counters
    sample_interval_ms: 1000
Kafka
yaml
kafka:
  bootstrap_servers:
    - kafka1:9092
    - kafka2:9092
  topics:
    telemetry_raw: ddos.telemetry.raw
    flows: ddos.telemetry.flows
    alerts: ddos.alerts
    mitigation_events: ddos.mitigation.events
  consumer_group: ddos-defense-platform
  producer_batch_size: 16384
  producer_linger_ms: 5
  security_protocol: PLAINTEXT    # PLAINTEXT, SSL, SASL_SSL
  ssl_cafile: /etc/kafka/secrets/ca.pem
  ssl_certfile: /etc/kafka/secrets/client.pem
  ssl_keyfile: /etc/kafka/secrets/client.key
Detection
Signature Detector
yaml
detection:
  signature:
    enabled: true
    engine: snort                # snort, suricata
    rules_path: /etc/snort/rules/
    reload_interval: 300         # seconds
    batch_size: 1000
    timeout_ms: 1000
Anomaly Detector
yaml
detection:
  anomaly:
    enabled: true
    windows:
      short: 60      # seconds
      medium: 300
      long: 3600
    volumetric:
      threshold_mbps: 1000
      threshold_pps: 500000
    entropy:
      threshold: 3.5
    syn_flood:
      threshold: 1000   # SYN packets per second per destination
    icmp_flood:
      threshold: 500    # ICMP packets per second
    deviation_factor: 3.0
Machine Learning Detector
yaml
detection:
  ml:
    enabled: true
    model_path: /opt/ddos-defense/models/ensemble_model.joblib
    feature_extractor_path: /opt/ddos-defense/models/feature_extractor.joblib
    confidence_threshold: 0.85
    inference_mode: batch         # sync, async, batch
    batch_size: 100
    features:
      - bytes_per_flow
      - packets_per_flow
      - src_ip_entropy
      - dst_ip_entropy
Ensemble
yaml
detection:
  ensemble:
    enabled: true
    voting: weighted              # weighted, majority, consensus
    weights:
      signature: 0.2
      anomaly: 0.4
      ml: 0.4
    alert_threshold: 0.6
    window_seconds: 10
    min_votes: 2
Alert Generator
yaml
detection:
  alert_generator:
    enabled: true
    enrichment_enabled: true
    batch_size: 50
    batch_timeout_ms: 500
Mitigation
yaml
mitigation:
  auto_response: true
  dry_run: false
  action_timeout: 30
  retry_count: 3
  rollback_delay: 300   # seconds

  rate_limiting:
    default_mbps: 100
    default_pps: 5000
    per_ip:
      enabled: true
      limit_mbps: 10
      limit_pps: 500
    per_subnet:
      enabled: true
      prefix_length: 24
      limit_mbps: 50
      limit_pps: 2500

  bgp:
    enabled: false
    asn: 65000
    router_ip: 192.168.1.1
    scrubber_next_hop: 10.0.0.1
    community: "65000:666"
    announcement_duration: 3600

  sdn:
    enabled: false
    controller_type: onos
    controller_url: https://onos-cluster:8443
    flow_priority: 5000
    idle_timeout: 60
    hard_timeout: 3600

  cloud:
    provider: none   # aws, azure, gcp
    aws:
      security_group_rules: true
      waf_acl: true
      shield_advanced: false
    azure:
      nsg_rules: true
      ddos_protection: false
    gcp:
      firewall_rules: true
      cloud_armor: false

  scrubbing_centers:
    - name: primary
      ip_range: 203.0.113.0/24
      capacity_mbps: 10000
      bgp_next_hop: 203.0.113.1
API Server
yaml
api:
  host: 0.0.0.0
  port: 8000
  workers: 4
  reload: false
  cors_origins:
    - https://dashboard.ddos-defense.internal
  jwt_secret: ${JWT_SECRET}
  jwt_expiration_minutes: 1440
Database (TimescaleDB)
yaml
database:
  host: postgres
  port: 5432
  name: ddos_platform
  user: ddos_user
  password: ${DB_PASSWORD}
  ssl_mode: disable
  pool_size: 10
  max_overflow: 20
Redis
yaml
redis:
  host: redis
  port: 6379
  password: ${REDIS_PASSWORD}
  db: 0
  ssl: false
  pool_size: 10
Monitoring
yaml
monitoring:
  prometheus:
    enabled: true
    port: 9090
    metrics_path: /metrics
  opentelemetry:
    enabled: false
    endpoint: http://otel-collector:4317
    service_name: ddos-defense-platform
Storage
yaml
storage:
  telemetry_retention_days: 7
  alerts_retention_days: 90
  backup_path: /data/backups/
  backup_schedule: "0 2 * * *"   # cron expression
Security
yaml
security:
  tls:
    enabled: false
    cert_file: /etc/ssl/certs/ddos-platform.crt
    key_file: /etc/ssl/private/ddos-platform.key
  api_rate_limit:
    enabled: true
    requests_per_minute: 120
  allowed_ips:
    - 10.0.0.0/8
    - 172.16.0.0/12
Environment‑Specific Overrides
config/dev.yaml
Typically lowers thresholds and disables certain features for testing:

yaml
environment: development
log_level: DEBUG
detection:
  anomaly:
    volumetric:
      threshold_mbps: 10        # lower for easy testing
mitigation:
  dry_run: true                 # don't actually apply changes
config/prod.yaml
Production‑grade settings with higher thresholds and enabled security:

yaml
environment: production
log_level: INFO
detection:
  anomaly:
    volumetric:
      threshold_mbps: 1000
mitigation:
  dry_run: false
security:
  tls:
    enabled: true
  api_rate_limit:
    enabled: true
Environment Variable Substitution
Any value containing ${VAR} will be replaced by the environment variable VAR. For example:

yaml
database:
  password: ${DB_PASSWORD}
If DB_PASSWORD is not set, the placeholder remains as is (not replaced). This allows injection of secrets without hardcoding.

Hot Reload
Some configuration changes (e.g., thresholds, ML model path) require a service restart. Others (e.g., rule files) are reloaded periodically without restart.

Signature rules: reloaded every reload_interval seconds.

ML model: restart required to load a new model file.

Recommended Tuning
Volumetric thresholds: Set based on your peak legitimate traffic plus a safety margin.

Entropy threshold: Start with 3.5; lower if you see false positives, higher if you miss attacks.

ML confidence: Start with 0.85; adjust based on false positive/negative trade‑off.

Ensemble weights: If your environment has few signature rules, reduce weight; if ML is highly accurate, increase its weight.

Rollback delay: Set to at least 2× average attack duration.

For more details, refer to the Deployment Guide and Detection Algorithms.