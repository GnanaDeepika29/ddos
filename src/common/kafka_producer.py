"""Compatibility wrapper for the shared telemetry producer."""

from ..ingestion.kafka_producer import TelemetryProducer, create_producer

__all__ = ["TelemetryProducer", "create_producer"]
