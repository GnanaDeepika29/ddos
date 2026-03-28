"""Common utilities for DDoS Defense Platform.

This module provides shared components including:
- Logging configuration and structured logging
- Metrics collection (Prometheus)
- Configuration loading
- Kafka consumer helper
- Database connections
"""

from .logging import get_logger, setup_logging
from .metrics import metrics
from .config import load_config
from .kafka_consumer import KafkaConsumerHelper

try:
    from .database import DatabaseConnection
except ImportError:
    DatabaseConnection = None

__all__ = [
    "get_logger",
    "setup_logging",
    "metrics",
    "load_config",
    "KafkaConsumerHelper",
    "DatabaseConnection",
]
