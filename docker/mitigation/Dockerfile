# Mitigation service Dockerfile
FROM python:3.11-slim

# Install system dependencies for network operations (iptables, BGP tools, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    iproute2 \
    net-tools \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install Python dependencies
COPY docker/mitigation/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and configuration
COPY src/ ./src/
COPY config/ ./config/

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Run mitigation service
# Use privileged mode in docker-compose for iptables access
CMD ["python", "-m", "src.mitigation.main"]
