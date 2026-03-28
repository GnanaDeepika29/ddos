# Deployment Guide

This guide explains how to deploy the DDoS Defense Platform in various environments: development, staging, and production.

## Prerequisites

- **Docker** (>= 20.10) and **Docker Compose** (>= 2.0) for local development
- **Kubernetes** (>= 1.24) cluster for production (EKS, AKS, GKE, or on-prem)
- **Helm** (>= 3.0) for Kubernetes package management
- **Terraform** (>= 1.0) for infrastructure provisioning (optional)
- **Python** (>= 3.9) for development

## Deployment Options

1. **Local Development** – using Docker Compose
2. **Production** – using Kubernetes + Terraform

---

## 1. Local Development with Docker Compose

This is the fastest way to get a full stack running for testing and development.

### Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/your-org/ddos-defense-platform.git
   cd ddos-defense-platform
Create a .env file from the example:

bash
cp .env.example .env
Edit .env as needed (set ENVIRONMENT=development, etc.).

Start all services:

bash
make docker-up
This will start:

Kafka, Zookeeper

PostgreSQL (TimescaleDB)

Redis

Prometheus, Grafana, Kafka UI

Ingestion, Detection, Mitigation, API services

Verify services are running:

API: http://localhost:8000

Grafana: http://localhost:3000 (admin/admin)

Kafka UI: http://localhost:8080

Stop the stack:

bash
make docker-down
Development Tips
To run a single service (e.g., detection) in isolation:

bash
python -m src.detection.main --config config/dev.yaml
Logs are streamed to console. Use docker-compose logs -f <service> to follow logs.

2. Production Deployment on Kubernetes
2.1 Infrastructure Provisioning (AWS Example)
We provide Terraform scripts to create the necessary AWS infrastructure (VPC, EKS cluster, etc.) in scripts/deploy/terraform/.

Configure Terraform variables:

bash
cd scripts/deploy/terraform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your AWS region, instance types, etc.
Initialize and apply:

bash
terraform init
terraform plan
terraform apply
Once infrastructure is created, configure kubectl to connect to the new EKS cluster:

bash
aws eks update-kubeconfig --region <region> --name ddos-defense-cluster
2.2 Deploy the Platform
Create the namespace:

bash
kubectl create namespace ddos-defense
Create secrets from the template:

bash
kubectl apply -f scripts/deploy/kubernetes/secrets.yaml
Important: Edit secrets.yaml with real credentials before applying.

Apply ConfigMaps:

bash
kubectl apply -f scripts/deploy/kubernetes/configmap.yaml
Deploy the services:

bash
kubectl apply -f scripts/deploy/kubernetes/deployment.yaml
Verify pods are running:

bash
kubectl get pods -n ddos-defense
2.3 Access the API
After deployment, the API service is exposed via a LoadBalancer. Get the external IP:

bash
kubectl get svc api -n ddos-defense
Access the API at http://<external-ip>:8000.

2.4 Monitoring Setup
Prometheus is deployed as part of the stack. It scrapes metrics from all services.

Grafana dashboards are auto-provisioned. Access Grafana via port-forward:

bash
kubectl port-forward -n ddos-defense svc/grafana 3000:3000
Then browse to http://localhost:3000 (default credentials: admin/admin).

2.5 Scaling
Scale individual services based on load:

bash
kubectl scale deployment detection -n ddos-defense --replicas=3
kubectl scale deployment ingestion -n ddos-defense --replicas=2
Horizontal Pod Autoscaler (HPA) can be configured for automatic scaling.

3. Configuration Management
Environment Variables
All services read configuration from YAML files under config/. Environment-specific overrides are loaded via dev.yaml or prod.yaml.

Secrets
Sensitive values (passwords, API keys) are injected via Kubernetes Secrets or environment variables. In development, they are read from .env.

Changing Detection Thresholds
Edit config/detection/volumetric.yaml and config/detection/behavioral.yaml to adjust thresholds. For Kubernetes, update the ConfigMap and restart services:

bash
kubectl edit configmap ddos-config -n ddos-defense
kubectl rollout restart deployment/detection -n ddos-defense
4. Testing the Platform
Generate Simulated Traffic
To test the detection pipeline, you can generate test traffic using tools like hping3 or scapy.

Example: simulate a SYN flood:

bash
sudo hping3 -S -p 80 --flood 10.0.0.1
The detection service should generate alerts within a few seconds.

Verify Mitigation
Set auto_response: true and dry_run: false in configuration, then launch an attack. Check the API for mitigation actions:

bash
curl http://localhost:8000/alerts
5. Backup and Disaster Recovery
Database: Use pg_dump to back up the TimescaleDB database. Retention policies are configured to keep metrics for 14 days.

Kafka: Enable topic replication and configure acks=all for durability.

Models: ML models are stored in a persistent volume. Back up the /opt/ddos-defense/models directory.

6. Troubleshooting
Issue	Solution
No alerts appearing	Check Kafka consumer lag; ensure detection services are running and consuming telemetry.
Mitigation not applied	Verify auto_response is true and dry_run is false. Check service logs for errors.
API returns 500	Inspect logs with kubectl logs -n ddos-defense api-<pod> or docker-compose logs api.
High CPU usage	Increase replicas for detection service; consider reducing window size or batch sizes.
7. Security Considerations
Use TLS for all service communication in production (set tls: true in config).

Restrict access to the API using network policies and firewalls.

Rotate secrets regularly.

Run mitigation services with limited privileges unless absolutely necessary (e.g., iptables may require privileged mode).

Monitor for unauthorized configuration changes.

8. Upgrading
To upgrade the platform:

Pull the latest code.

Update Docker images (or rebuild).

Apply any new Kubernetes manifests.

Run database migrations if any (provided in scripts/migrations/).

bash
kubectl apply -f scripts/deploy/kubernetes/deployment.yaml
kubectl rollout status deployment -n ddos-defense
9. Uninstalling
Docker Compose: make docker-down and remove volumes if needed.

Kubernetes: kubectl delete namespace ddos-defense to remove all resources.

Terraform: terraform destroy to tear down infrastructure.

For more details, refer to the Architecture and API Reference documents.
