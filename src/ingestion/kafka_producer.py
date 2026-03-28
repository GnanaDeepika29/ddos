"""Kafka producer module for telemetry streaming.

This module provides an asynchronous Kafka producer with batching, retries,
and metrics integration.
"""

import asyncio
import json
import time
from typing import Optional, List, Dict, Any
from collections import deque
import logging

from kafka import KafkaProducer as SyncKafkaProducer
from kafka.errors import KafkaError
import structlog

from ..common.logging import get_logger
from ..common.metrics import metrics

logger = get_logger(__name__)


class TelemetryProducer:
    """Async Kafka producer with batching and retry support."""

    def __init__(
        self,
        bootstrap_servers: Optional[List[str]] = None,
        topic: str = "telemetry.raw",
        batch_size: int = 100,
        batch_timeout_ms: int = 100,
        send_timeout_ms: int = 10000,
        retries: int = 3,
        compression_type: str = "gzip",
        dry_run: bool = False,
        **kwargs,
    ):
        """Initialize Kafka producer.

        Args:
            bootstrap_servers: List of Kafka broker addresses.
            topic: Default topic for messages.
            batch_size: Maximum number of messages per batch.
            batch_timeout_ms: Maximum time to wait before flushing a batch.
            send_timeout_ms: Maximum time to wait for broker acknowledgement.
            retries: Number of retries on failure.
            compression_type: Compression codec (none, gzip, snappy, lz4).
            **kwargs: Additional arguments for KafkaProducer.
        """
        self.bootstrap_servers = bootstrap_servers or ["localhost:9092"]
        self.default_topic = topic
        self.batch_size = batch_size
        self.batch_timeout_ms = batch_timeout_ms
        self.send_timeout_ms = send_timeout_ms
        self.retries = retries
        self.compression_type = compression_type
        self.dry_run = dry_run

        # Internal queue for batching
        self._queue: deque = deque()
        self._queue_lock = asyncio.Lock()
        self._flush_task: Optional[asyncio.Task] = None
        self._running = False

        # Sync Kafka producer (runs in thread)
        self._producer: Optional[SyncKafkaProducer] = None

        # Stats
        self._stats = {
            "messages_sent": 0,
            "messages_failed": 0,
            "batches_sent": 0,
            "last_error": None,
        }

        # Additional config for sync producer
        self._producer_config = {
            "bootstrap_servers": self.bootstrap_servers,
            "compression_type": self.compression_type,
            "retries": self.retries,
            "value_serializer": self._serialize,
            **kwargs,
        }

    def _serialize(self, msg: Any) -> bytes:
        """Serialize message to JSON bytes."""
        if isinstance(msg, (dict, list)):
            return json.dumps(msg, default=str).encode("utf-8")
        elif isinstance(msg, str):
            return msg.encode("utf-8")
        elif isinstance(msg, bytes):
            return msg
        else:
            return str(msg).encode("utf-8")

    def _init_sync_producer(self):
        """Initialize the synchronous Kafka producer."""
        if self.dry_run:
            logger.info("Kafka producer running in dry-run mode", servers=self.bootstrap_servers)
            self._producer = None
            return
        try:
            self._producer = SyncKafkaProducer(**self._producer_config)
            logger.info("Kafka producer initialized", servers=self.bootstrap_servers)
        except Exception as e:
            logger.error("Failed to initialize Kafka producer", error=str(e))
            raise

    async def start(self):
        """Start the producer and flush task."""
        if self._running:
            logger.warning("Producer already running")
            return

        self._running = True
        last_error: Optional[Exception] = None
        for attempt in range(1, 11):
            try:
                self._init_sync_producer()
                break
            except Exception as e:
                last_error = e
                logger.warning(
                    "Kafka producer startup attempt failed",
                    error=str(e),
                    attempt=attempt,
                    servers=self.bootstrap_servers,
                )
                if attempt == 10:
                    self._running = False
                    raise
                await asyncio.sleep(2)
        self._flush_task = asyncio.create_task(self._flush_loop())
        logger.info("Telemetry producer started")

    async def stop(self):
        """Stop the producer and flush remaining messages."""
        if not self._running:
            return

        self._running = False
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass

        # Flush remaining messages
        await self.flush()
        if self._producer:
            self._producer.flush()
            self._producer.close()
        logger.info("Telemetry producer stopped")

    async def send(self, message: Any, topic: Optional[str] = None, key: Optional[str] = None):
        """Send a single message asynchronously (adds to batch queue)."""
        if not self._running:
            logger.warning("Producer not running, dropping message")
            return

        async with self._queue_lock:
            self._queue.append({
                "topic": topic or self.default_topic,
                "value": message,
                "key": key,
                "timestamp": time.time(),
            })

        # If queue size reaches batch size, trigger flush
        if len(self._queue) >= self.batch_size:
            asyncio.create_task(self.flush())

    async def send_batch(self, messages: List[Any], topic: Optional[str] = None, keys: Optional[List[str]] = None):
        """Send a batch of messages directly (bypasses queue)."""
        if not self._running:
            logger.warning("Producer not running, dropping batch")
            return

        topic = topic or self.default_topic
        for i, msg in enumerate(messages):
            key = keys[i] if keys and i < len(keys) else None
            try:
                if self.dry_run:
                    await asyncio.sleep(0)
                else:
                    future = self._producer.send(topic, value=msg, key=key)
                    # Wait for broker acknowledgement using a real delivery timeout.
                    await asyncio.get_event_loop().run_in_executor(None, future.get, self.send_timeout_ms / 1000)
                self._stats["messages_sent"] += 1
                metrics.kafka_messages_sent.inc()
            except Exception as e:
                self._stats["messages_failed"] += 1
                self._stats["last_error"] = str(e)
                logger.error("Failed to send batch message", error=str(e))
                metrics.kafka_errors_total.inc()

        self._stats["batches_sent"] += 1

    async def flush(self):
        """Flush the current batch of queued messages."""
        if not self._running:
            return

        async with self._queue_lock:
            if not self._queue:
                return
            batch = list(self._queue)
            self._queue.clear()

        # Process batch
        if batch:
            try:
                # Group by topic
                topic_groups: Dict[str, List[Any]] = {}
                key_groups: Dict[str, List[str]] = {}
                for item in batch:
                    t = item["topic"]
                    topic_groups.setdefault(t, []).append(item["value"])
                    if item.get("key"):
                        key_groups.setdefault(t, []).append(item["key"])

                # Send each topic group
                for topic, msgs in topic_groups.items():
                    keys = key_groups.get(topic, [None] * len(msgs))
                    for i, msg in enumerate(msgs):
                        try:
                            if self.dry_run:
                                await asyncio.sleep(0)
                            else:
                                future = self._producer.send(topic, value=msg, key=keys[i] if i < len(keys) else None)
                                # Wait for broker acknowledgement using a real delivery timeout.
                                await asyncio.get_event_loop().run_in_executor(None, future.get, self.send_timeout_ms / 1000)
                            self._stats["messages_sent"] += 1
                            metrics.kafka_messages_sent.inc()
                        except Exception as e:
                            self._stats["messages_failed"] += 1
                            self._stats["last_error"] = str(e)
                            logger.error("Failed to send message", error=str(e))
                            metrics.kafka_errors_total.inc()

                    self._stats["batches_sent"] += 1

            except Exception as e:
                logger.error("Failed to flush batch", error=str(e))
                # Requeue? For now, drop.
                self._stats["messages_failed"] += len(batch)

    async def _flush_loop(self):
        """Periodic flush loop."""
        while self._running:
            await asyncio.sleep(self.batch_timeout_ms / 1000.0)
            await self.flush()

    def get_stats(self) -> Dict[str, Any]:
        """Get producer statistics."""
        stats = self._stats.copy()
        if self._producer:
            stats["producer_metrics"] = self._producer.metrics()
        return stats


# Convenience async function to create a producer
async def create_producer(**kwargs) -> TelemetryProducer:
    """Create and start a TelemetryProducer."""
    producer = TelemetryProducer(**kwargs)
    await producer.start()
    return producer


if __name__ == "__main__":
    # Simple test
    import asyncio

    async def test():
        producer = TelemetryProducer(bootstrap_servers=["localhost:9092"])
        await producer.start()
        try:
            for i in range(10):
                await producer.send(message={"test": i, "timestamp": time.time()})
                await asyncio.sleep(0.1)
            await asyncio.sleep(2)  # allow flush
        finally:
            await producer.stop()

    asyncio.run(test())
