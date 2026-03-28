"""Kafka consumer helper with async interface and batch processing.

This module provides an asynchronous wrapper around Kafka consumer with
batching capabilities for efficient message processing.
"""

import asyncio
import time
from typing import Optional, List, Dict, Any, AsyncIterator, Callable
from collections import deque

import structlog

try:
    from kafka import KafkaConsumer as SyncKafkaConsumer
    from kafka import KafkaProducer as SyncKafkaProducer
    from kafka.errors import KafkaError
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False
    SyncKafkaConsumer = None
    SyncKafkaProducer = None

from .logging import get_logger
from .metrics import metrics

logger = get_logger(__name__)


class KafkaConsumerHelper:
    """Asynchronous Kafka consumer with batch support.

    This class wraps a synchronous Kafka consumer and provides an async
    iterator that yields batches of messages.
    """

    def __init__(
        self,
        bootstrap_servers: List[str],
        topic: str,
        group_id: str,
        batch_size: int = 100,
        batch_timeout_ms: int = 1000,
        auto_offset_reset: str = "latest",
        enable_auto_commit: bool = True,
        consumer_timeout_ms: int = 1000,
        producer: Optional["TelemetryProducer"] = None,
        **kwargs,
    ):
        """Initialize Kafka consumer helper.

        Args:
            bootstrap_servers: List of Kafka broker addresses.
            topic: Topic to consume from.
            group_id: Consumer group ID.
            batch_size: Number of messages per batch.
            batch_timeout_ms: Maximum time to wait for batch.
            auto_offset_reset: Reset policy (earliest, latest).
            enable_auto_commit: Whether to auto-commit offsets.
            consumer_timeout_ms: Timeout for consumer.poll().
            producer: Optional producer for forwarding messages.
            **kwargs: Additional arguments for KafkaConsumer.
        """
        if not KAFKA_AVAILABLE:
            raise ImportError("kafka-python is not installed")

        self.bootstrap_servers = bootstrap_servers
        self.topic = topic
        self.group_id = group_id
        self.batch_size = batch_size
        self.batch_timeout_ms = batch_timeout_ms
        self.auto_offset_reset = auto_offset_reset
        self.enable_auto_commit = enable_auto_commit
        self.consumer_timeout_ms = consumer_timeout_ms
        self.producer = producer

        self._consumer: Optional[SyncKafkaConsumer] = None
        self._running = False
        self._stats = {
            "messages_consumed": 0,
            "batches_consumed": 0,
            "errors": 0,
        }

        self._consumer_config = {
            "bootstrap_servers": self.bootstrap_servers,
            "group_id": self.group_id,
            "auto_offset_reset": self.auto_offset_reset,
            "enable_auto_commit": self.enable_auto_commit,
            "consumer_timeout_ms": self.consumer_timeout_ms,
            "value_deserializer": self._deserialize,
            **kwargs,
        }

    def _deserialize(self, value: bytes) -> Any:
        """Deserialize message value from JSON."""
        if value is None:
            return None
        import json
        try:
            return json.loads(value.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return value.decode("utf-8", errors="ignore")

    async def start(self):
        """Start the consumer."""
        if self._running:
            logger.warning("Consumer already running")
            return

        self._running = True
        self._consumer = SyncKafkaConsumer(**self._consumer_config)
        self._consumer.subscribe([self.topic])
        logger.info("Kafka consumer started", topic=self.topic, group=self.group_id)

    async def stop(self):
        """Stop the consumer."""
        if not self._running:
            return
        self._running = False
        if self._consumer:
            self._consumer.close()
            self._consumer = None
        logger.info("Kafka consumer stopped")

    async def consume_batches(self) -> AsyncIterator[List[Dict[str, Any]]]:
        """Async iterator that yields batches of messages.

        Yields:
            List of message values (deserialized).
        """
        if not self._consumer:
            raise RuntimeError("Consumer not started")

        batch = []
        batch_deadline = None

        while self._running:
            try:
                # Poll for messages
                messages = self._consumer.poll(timeout_ms=self.batch_timeout_ms)
                if not messages:
                    # If we have a partial batch and deadline passed, yield it
                    if batch and batch_deadline and time.time() >= batch_deadline:
                        yield batch
                        batch = []
                        batch_deadline = None
                    continue

                for tp, msgs in messages.items():
                    for msg in msgs:
                        if msg.value is not None:
                            # Convert to dict if needed
                            value = msg.value
                            # Add metadata
                            if isinstance(value, dict):
                                value["_kafka_metadata"] = {
                                    "topic": msg.topic,
                                    "partition": msg.partition,
                                    "offset": msg.offset,
                                    "timestamp": msg.timestamp,
                                }
                            batch.append(value)
                            self._stats["messages_consumed"] += 1
                            metrics.kafka_messages_received.inc()

                            # If batch is full, yield it
                            if len(batch) >= self.batch_size:
                                yield batch
                                batch = []
                                batch_deadline = None
                            else:
                                # Set deadline for this batch
                                if batch_deadline is None:
                                    batch_deadline = time.time() + self.batch_timeout_ms / 1000.0

            except KafkaError as e:
                logger.error("Kafka consumer error", error=str(e))
                self._stats["errors"] += 1
                metrics.kafka_errors_total.inc()
                await asyncio.sleep(1)  # backoff
            except Exception as e:
                logger.error("Unexpected consumer error", error=str(e))
                self._stats["errors"] += 1
                await asyncio.sleep(1)

        # Yield remaining batch if any
        if batch:
            yield batch

    def get_stats(self) -> Dict[str, Any]:
        """Get consumer statistics."""
        return self._stats.copy()


# Alias for backward compatibility
KafkaConsumerHelper = KafkaConsumerHelper