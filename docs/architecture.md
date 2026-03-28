# DDoS Defense Platform Architecture

## Overview

The DDoS Defense Platform is a real-time distributed system for detecting and mitigating DDoS attacks in cloud networks. It is designed with a microservices architecture, leveraging event-driven communication via Kafka, and provides a REST API for management and monitoring.

## High-Level Architecture
┌─────────────────────────────────────────────────────────────────────────────┐
│ Edge / Cloud Network │
│ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ │
│ │ Packet │ │ Flow │ │ gNMI │ │ Cloud API │ │
│ │ Capture │ │ Collector │ │ Telemetry │ │ Integration │ │
│ └──────┬──────┘ └──────┬──────┘ └──────┬──────┘ └──────┬──────┘ │
│ │ │ │ │ │
│ └────────────────┼────────────────┼────────────────┘ │
│ │ │ │
│ ▼ ▼ │
│ ┌──────────────────────────┐ │
│ │ Kafka Cluster │ │
│ │ (Telemetry, Alerts, │ │
│ │ Control Messages) │ │
│ └───────────┬──────────────┘ │
│ │ │
│ ┌─────────────────────────────┼─────────────────────────────────────────┐ │
│ │ Detection Services │ │ │
│ │ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ │ │
│ │ │ Signature │ │ Anomaly │ │ ML │ │ │
│ │ │ Detector │ │ Detector │ │ Detector │ │ │
│ │ └──────┬───────┘ └──────┬───────┘ └──────┬───────┘ │ │
│ │ └─────────────────┼─────────────────┘ │ │
│ │ ▼ │ │
│ │ ┌──────────────┐ │ │
│ │ │ Ensemble │ │ │
│ │ │ Detector │ │ │
│ │ └──────┬───────┘ │ │
│ │ ▼ │ │
│ │ ┌──────────────┐ │ │
│ │ │ Alert │ │ │
│ │ │ Generator │ │ │
│ │ └──────┬───────┘ │ │
│ └───────────────────────────┼──────────────────────────────────────────┘ │
│ │ │
│ ▼ │
│ ┌───────────────────────────────────────────────────────────────────────┐│
│ │ Mitigation Orchestrator ││
│ │ ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐ ││
│ │ │ Rate │ │ BGP │ │ SDN │ │ Cloud │ ││
│ │ │ Limiter │ │ Announcer │ │ Controller │ │ Security │ ││
│ │ └────────────┘ └────────────┘ └────────────┘ └────────────┘ ││
│ └───────────────────────────────────────────────────────────────────────┘│
│ │
│ ┌───────────────────────────────────────────────────────────────────────┐│
│ │ REST API & Monitoring ││
│ │ - FastAPI endpoints for status, alerts, configuration ││
│ │ - Prometheus metrics export ││
│ │ - Grafana dashboards ││
│ └───────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘

text

## Components

### 1. Telemetry Ingestion

- **Packet Capture**: Uses `scapy`, `pcapy`, or `PF_RING` to capture raw packets from network interfaces. Sends packet metadata to Kafka topic `telemetry.raw`.
- **Flow Collector**: Listens for NetFlow v5/v9/IPFIX and sFlow exports. Parses flows and sends to Kafka topic `telemetry.flows`.
- **gNMI Telemetry**: Streams telemetry from network devices via gRPC/gNMI, pushing structured data to `telemetry.grpc`.

### 2. Detection Layer

- **Signature Detector**: Applies Snort/Suricata rules to raw packets. Generates alerts on known attack patterns.
- **Anomaly Detector**: Computes statistical features (entropy, volume rates, protocol ratios) over sliding windows. Triggers on deviations from baseline.
- **ML Detector**: Uses pre-trained models (Random Forest, XGBoost) to classify flows as benign or attack. Produces confidence scores.
- **Ensemble Detector**: Correlates alerts from all detectors within a time window using weighted voting. Generates final detection events.
- **Alert Generator**: Enriches detection events with metadata (description, severity, suggested actions) and publishes to `alerts.enriched`.

### 3. Mitigation Layer

- **Orchestrator**: Consumes enriched alerts and executes mitigation actions based on severity and attack type. Supports dry-run mode.
- **Rate Limiter**: Applies per-IP or per-subnet rate limits using iptables/nftables or cloud APIs.
- **BGP Route Announcer**: Triggers route announcements to divert traffic to scrubbing centers.
- **SDN Controller**: Injects flow rules into programmable switches to drop or redirect attack traffic.
- **Cloud Security Groups**: Modifies cloud provider security groups to block attack sources.
- **Blacklist Manager**: Maintains a dynamic blacklist of malicious IPs.
- **Rollback Manager**: Reverts mitigation actions after attack subsides (configurable delay).

### 4. Storage & State

- **TimescaleDB (PostgreSQL)**: Stores alerts, mitigation actions, and time-series metrics for historical analysis.
- **Redis**: Used for ephemeral state (rate limiter counters, active mitigation tracking).

### 5. Messaging (Kafka)

All inter-service communication is event-driven via Kafka. Topics:
- `telemetry.raw`: raw packet metadata
- `telemetry.flows`: aggregated flow records
- `telemetry.grpc`: gNMI telemetry
- `detection.signature.alerts`
- `detection.anomaly.alerts`
- `detection.ml.alerts`
- `detection.ensemble.alerts`
- `alerts.enriched`
- `mitigation.events`
- `control` (for manual overrides)

### 6. API & Monitoring

- **REST API**: FastAPI-based endpoints for health, alerts, configuration, manual mitigation, and metrics.
- **Prometheus**: Scrapes metrics from all services for monitoring and alerting.
- **Grafana**: Pre-configured dashboards for visualizing traffic, alerts, and system health.

## Data Flow

1. **Ingestion** → Packets/flows/telemetry published to Kafka.
2. **Detection** → Services consume telemetry, produce detection alerts.
3. **Ensemble** → Combines alerts, enriches, and publishes.
4. **Mitigation** → Consumes enriched alerts, applies actions, tracks state.
5. **Rollback** → After attack window, automatically reverts actions.
6. **API** → External control and visibility.

## Deployment

The platform can be deployed on Kubernetes (EKS, AKS, GKE) using provided Helm charts or manifests. Alternatively, Docker Compose is provided for development.

- **Scalability**: Each microservice can be horizontally scaled.
- **Resilience**: Kafka provides buffering; services reconnect automatically.
- **Security**: TLS for internal communication, secrets managed via Kubernetes Secrets.

## Performance Considerations

- **Packet Capture**: Use PF_RING or DPDK for high-throughput (10Gbps+).
- **Detection Latency**: ML inference optimized with batch processing; ensemble window configurable.
- **Mitigation Speed**: BGP announcements can take seconds; rate limiting is immediate via iptables.

## Future Enhancements

- Integration with cloud-native DDoS protection services (AWS Shield, Azure DDoS Protection).
- Advanced ML models (LSTM, Graph Neural Networks) for flow correlation.
- Federated learning across multiple cloud tenants.
- Anomaly detection for encrypted traffic using TLS fingerprinting.
