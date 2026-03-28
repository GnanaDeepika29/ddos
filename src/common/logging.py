"""Structured logging configuration using structlog.

This module sets up structured logging with JSON output for production
and pretty console output for development. It integrates with Python's
standard logging for compatibility with third-party libraries.
"""

import logging
import sys
from typing import Any, Dict, Optional

import structlog
from structlog.types import EventDict, Processor


def add_log_level(_: Any, __: Any, event_dict: EventDict) -> EventDict:
    """Add log level to the event dict."""
    # The log level is already present via structlog's built-in processor,
    # but we ensure it's there.
    if "level" not in event_dict:
        # Fallback: try to infer from logger name or context
        event_dict["level"] = "info"
    return event_dict


def add_service_name(service_name: str = "ddos-defense") -> Processor:
    """Add a service name to all log events."""
    def processor(_, __, event_dict: EventDict) -> EventDict:
        event_dict["service"] = service_name
        return event_dict
    return processor


def setup_logging(
    level: str = "INFO",
    json_output: bool = False,
    service_name: str = "ddos-defense",
) -> None:
    """Configure structured logging.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        json_output: If True, output JSON lines; otherwise pretty console.
        service_name: Name of the service for log correlation.
    """
    log_level = getattr(logging, level.upper(), logging.INFO)

    # Configure standard logging for third-party libraries
    logging.basicConfig(
        format="%(message)s",
        level=log_level,
        handlers=[logging.StreamHandler(sys.stdout)],
    )

    # Define processors
    processors = [
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        add_log_level,
        add_service_name(service_name),
    ]

    if json_output:
        # JSON output for production
        processors.append(structlog.processors.JSONRenderer())
    else:
        # Pretty console output for development
        processors.append(structlog.dev.ConsoleRenderer())

    # Configure structlog
    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Silence noisy third-party loggers
    for lib in ("kafka", "urllib3", "asyncio"):
        logging.getLogger(lib).setLevel(logging.WARNING)


def get_logger(name: Optional[str] = None) -> structlog.BoundLogger:
    """Get a structlog logger instance.

    Args:
        name: Logger name (typically __name__).

    Returns:
        Configured structlog logger.
    """
    if name:
        return structlog.get_logger(name)
    return structlog.get_logger()