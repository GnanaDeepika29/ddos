# DDoS Defense Platform

Real-time distributed denial of service (DDoS) attack detection and mitigation for cloud networks.

## Overview

This platform provides a modular, scalable, and automated system for detecting and mitigating DDoS attacks in real time. It combines:
- **Ingestion**: High-performance telemetry collection from packets, flows, and streaming telemetry.
- **Detection**: Multi-layered detection using signatures, statistical anomalies, and machine learning.
- **Mitigation**: Automated responses including BGP route announcements, SDN rule injection, rate limiting, and traffic scrubbing.
- **API**: RESTful control plane for configuration, status, and alerts.
- **Observability**: Built-in metrics with Prometheus and structured logging.

The system is designed for cloud-native deployment with Docker, Kubernetes, and Terraform workflows.

## Architecture

Architecture diagram: pending addition to `docs/`.

- **Ingestion Layer**: Collects telemetry from edge routers, virtual switches, and cloud APIs.
- **Stream Processing**: Kafka transports telemetry to downstream services.
- **Detection Engine**: Evaluates traffic using multiple detectors and generates alerts.
- **Mitigation Orchestrator**: Applies response actions based on attack type and severity.
- **API and Observability**: Exposes management endpoints, metrics, and dashboards.

## Getting Started

### Prerequisites

- Python 3.9+
- Docker and Docker Compose
- Kafka
- Redis
- TimescaleDB

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-org/ddos-defense-platform.git
   cd ddos-defense-platform
   ```
2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```
5. Edit `.env` with your local configuration.

### Running With Docker

```bash
docker-compose -f docker/docker-compose.yml up -d
```

### Running a Service Directly

```bash
python -m src.ingestion.main --config config/default.yaml --env dev
```

## Configuration

Configuration files are located in `config/`. See the documentation in `docs/` for more detail.

## Deployment

Deployment assets are available under `scripts/deploy/` for Kubernetes and Terraform-based environments.

## Contributing

Please read `CONTRIBUTING.md` for contribution guidelines and workflow expectations.

## License

This project is licensed under the MIT License. See `LICENSE` for details.
