# Makefile for DDoS Defense Platform

.PHONY: help install test lint format clean run-ingestion run-detection run-mitigation run-api docker-build docker-up deploy

help:
	@echo "Available targets:"
	@echo "  install          Install Python dependencies"
	@echo "  test             Run unit tests"
	@echo "  lint             Run linters (flake8, pylint)"
	@echo "  format           Format code with black"
	@echo "  clean            Remove cache and build artifacts"
	@echo "  run-ingestion    Start ingestion service"
	@echo "  run-detection    Start detection engine"
	@echo "  run-mitigation   Start mitigation orchestrator"
	@echo "  run-api          Start REST API server"
	@echo "  docker-build     Build Docker images"
	@echo "  docker-up        Start services with docker-compose"
	@echo "  deploy           Deploy to Kubernetes (requires kubectl)"

install:
	pip install -r requirements.txt
	pip install -e .

test:
	pytest tests/unit -v --cov=src --cov-report=term-missing

lint:
	flake8 src tests
	pylint src tests --rcfile=.pylintrc

format:
	black src tests

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name ".coverage" -delete
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name "*.egg-info" -exec rm -rf {} +

run-ingestion:
	python src/ingestion/main.py

run-detection:
	python src/detection/main.py

run-mitigation:
	python src/mitigation/main.py

run-api:
	python src/api/app.py

docker-build:
	docker build -t ddos-defense-ingestion:latest -f docker/ingestion/Dockerfile .
	docker build -t ddos-defense-detection:latest -f docker/detection/Dockerfile .
	docker build -t ddos-defense-mitigation:latest -f docker/mitigation/Dockerfile .
	docker build -t ddos-defense-api:latest -f docker/api/Dockerfile .

docker-up:
	docker-compose -f docker/docker-compose.yml up -d

docker-down:
	docker-compose -f docker/docker-compose.yml down

deploy:
	kubectl apply -f scripts/deploy/kubernetes/