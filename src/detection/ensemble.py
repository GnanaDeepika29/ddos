"""Ensemble detection combining multiple detection engines.

This module implements a weighted ensemble that combines results from
signature, anomaly, and ML detectors to produce a final alert with
aggregated confidence and severity.
"""

import asyncio
import time
from typing import Optional, Dict, Any, List, Tuple
from collections import defaultdict, deque
from dataclasses import dataclass, field

import structlog

from ..common.logging import get_logger
from ..common.metrics import metrics
from ..common.kafka_consumer import KafkaConsumerHelper
from ..common.kafka_producer import TelemetryProducer

logger = get_logger(__name__)


@dataclass
class DetectorResult:
    """Result from a single detector."""
    detector_type: str  # signature, anomaly, ml
    alert: Dict[str, Any]
    confidence: float
    timestamp: float
    severity: int


class EnsembleDetector:
    """Ensemble detector that combines multiple detection sources."""

    def __init__(
        self,
        input_topics: Optional[List[str]] = None,
        output_topic: str = "detection.ensemble.alerts",
        bootstrap_servers: Optional[List[str]] = None,
        batch_size: int = 100,
        batch_timeout_ms: int = 1000,
        weights: Optional[Dict[str, float]] = None,
        alert_threshold: float = 0.6,
        window_seconds: int = 10,
        min_votes: int = 2,
        voting: str = "weighted",  # weighted, majority, consensus
        producer: Optional[TelemetryProducer] = None,
    ):
        """Initialize ensemble detector.

        Args:
            input_topics: List of Kafka topics to consume alerts from.
            output_topic: Kafka topic to publish ensemble alerts.
            bootstrap_servers: Kafka broker list.
            batch_size: Number of alerts per batch.
            batch_timeout_ms: Batch timeout.
            weights: Dictionary mapping detector type to weight (0-1).
            alert_threshold: Minimum weighted score to generate alert.
            window_seconds: Time window to correlate alerts.
            min_votes: Minimum number of detectors that must agree.
            voting: Voting mechanism (weighted, majority, consensus).
        """
        self.input_topics = input_topics or [
            "detection.signature.alerts",
            "detection.anomaly.alerts",
            "detection.ml.alerts",
        ]
        self.output_topic = output_topic
        self.bootstrap_servers = bootstrap_servers or ["localhost:9092"]
        self.batch_size = batch_size
        self.batch_timeout_ms = batch_timeout_ms
        self.weights = weights or {
            "signature": 0.2,
            "anomaly": 0.4,
            "ml": 0.4,
        }
        self.alert_threshold = alert_threshold
        self.window_seconds = window_seconds
        self.min_votes = min_votes
        self.voting = voting
        self.producer = producer

        self._running = False
        self._consumers: List[KafkaConsumerHelper] = []
        self._alerts_queue: deque = deque()  # queue of incoming alerts
        self._queue_lock = asyncio.Lock()
        self._stats = {
            "alerts_received": 0,
            "alerts_generated": 0,
            "errors": 0,
        }

    def _calculate_weighted_score(self, results: List[DetectorResult]) -> float:
        """Calculate weighted score from detector results."""
        total_weight = 0.0
        weighted_sum = 0.0
        for res in results:
            weight = self.weights.get(res.detector_type, 0.0)
            total_weight += weight
            weighted_sum += weight * res.confidence
        if total_weight == 0:
            return 0.0
        return weighted_sum / total_weight

    def _majority_vote(self, results: List[DetectorResult]) -> Tuple[bool, float]:
        """Majority vote - at least min_votes agree it's an attack."""
        attack_votes = sum(1 for r in results if r.confidence >= 0.5)
        total = len(results)
        if total == 0:
            return False, 0.0
        is_attack = attack_votes >= max(self.min_votes, total // 2 + 1)
        confidence = attack_votes / total if total > 0 else 0.0
        return is_attack, confidence

    def _consensus(self, results: List[DetectorResult]) -> Tuple[bool, float]:
        """Consensus - all detectors must agree."""
        if not results:
            return False, 0.0
        attack_votes = sum(1 for r in results if r.confidence >= 0.5)
        is_attack = attack_votes == len(results)
        confidence = attack_votes / len(results)
        return is_attack, confidence

    async def _correlate_alerts(self) -> List[Dict[str, Any]]:
        """Correlate alerts within the time window and produce ensemble alerts."""
        now = time.time()
        window_start = now - self.window_seconds

        # Collect alerts within window
        alerts_in_window = []
        async with self._queue_lock:
            while self._alerts_queue and self._alerts_queue[0].timestamp < window_start:
                self._alerts_queue.popleft()
            alerts_in_window = list(self._alerts_queue)

        if not alerts_in_window:
            return []

        # Group by target (if present) or by flow hash
        # For simplicity, we group by (target_ip, target_port) or use a hash
        groups: Dict[str, List[DetectorResult]] = defaultdict(list)
        for alert in alerts_in_window:
            # Extract grouping key: typically target IP
            target = alert.alert.get("target_ip") or alert.alert.get("flow", {}).get("dst_ip") or "unknown"
            # Also consider attack type for grouping
            attack_type = alert.alert.get("type", "unknown")
            key = f"{target}:{attack_type}"
            groups[key].append(alert)

        ensemble_alerts = []
        for key, results in groups.items():
            if self.voting == "weighted":
                score = self._calculate_weighted_score(results)
                is_attack = score >= self.alert_threshold
                confidence = score
            elif self.voting == "majority":
                is_attack, confidence = self._majority_vote(results)
            elif self.voting == "consensus":
                is_attack, confidence = self._consensus(results)
            else:
                raise ValueError(f"Unknown voting method: {self.voting}")

            if is_attack:
                # Determine highest severity among detectors
                max_severity = max((r.severity for r in results), default=1)
                source_ips = sorted({
                    ip
                    for r in results
                    for ip in (r.alert.get("source_ips") or ([r.alert.get("source_ip")] if r.alert.get("source_ip") else []))
                    if ip
                })
                target_ip = next(
                    (
                        r.alert.get("target_ip")
                        for r in results
                        if r.alert.get("target_ip") and r.alert.get("target_ip") != "unknown"
                    ),
                    "unknown",
                )
                # Aggregate alert details
                detectors_triggered = [r.detector_type for r in results]
                combined_alert = {
                    "detector": "ensemble",
                    "type": "ddos_attack",
                    "confidence": confidence,
                    "severity": max_severity,
                    "detectors": detectors_triggered,
                    "source_ips": source_ips,
                    "target_ip": target_ip,
                    "target": key,
                    "telemetry_source": "correlated_detection",
                    "timestamp": now,
                    "details": {
                        "alerts": [r.alert for r in results],
                    },
                }
                ensemble_alerts.append(combined_alert)

        return ensemble_alerts

    async def _consume_alerts(self, consumer: KafkaConsumerHelper, detector_type: str):
        """Consume alerts from a single detector topic."""
        try:
            async for batch in consumer.consume_batches():
                if not self._running:
                    break
                for msg in batch:
                    # Convert message to DetectorResult
                    result = DetectorResult(
                        detector_type=msg.get("detector", detector_type),
                        alert=msg,
                        confidence=msg.get("confidence", msg.get("score", 0.5)),
                        timestamp=msg.get("timestamp", time.time()),
                        severity=msg.get("severity", 2),
                    )
                    async with self._queue_lock:
                        self._alerts_queue.append(result)
                    self._stats["alerts_received"] += 1
        except asyncio.CancelledError:
            logger.info(f"Consumer for {detector_type} cancelled")
        except Exception as e:
            logger.error(f"Error in consumer for {detector_type}", error=str(e))
            self._stats["errors"] += 1

    async def _correlate_loop(self):
        """Periodically correlate alerts and produce ensemble alerts."""
        while self._running:
            await asyncio.sleep(self.window_seconds / 2)  # Run twice per window
            try:
                ensemble_alerts = await self._correlate_alerts()
                if ensemble_alerts:
                    # Send ensemble alerts to Kafka
                    if self._consumers and self._consumers[0].producer:
                        await self._consumers[0].producer.send_batch(
                            topic=self.output_topic,
                            messages=ensemble_alerts,
                        )
                    self._stats["alerts_generated"] += len(ensemble_alerts)
                    metrics.alerts_total.inc(len(ensemble_alerts))
                    logger.info("Ensemble alerts generated", count=len(ensemble_alerts))
            except Exception as e:
                logger.error("Error in correlation loop", error=str(e))
                self._stats["errors"] += 1

    async def start(self):
        """Start the ensemble detector."""
        if self._running:
            logger.warning("Ensemble detector already running")
            return

        self._running = True

        # Create consumers for each input topic
        for idx, topic in enumerate(self.input_topics):
            detector_type = topic.split(".")[-2]  # e.g., "signature"
            consumer = KafkaConsumerHelper(
                bootstrap_servers=self.bootstrap_servers,
                topic=topic,
                group_id=f"ensemble-detector-{detector_type}",
                batch_size=self.batch_size,
                batch_timeout_ms=self.batch_timeout_ms,
                producer=self.producer,
            )
            await consumer.start()
            self._consumers.append(consumer)

        # Start consumer tasks
        consumer_tasks = []
        for consumer in self._consumers:
            detector_type = consumer.topic.split(".")[-2]
            task = asyncio.create_task(self._consume_alerts(consumer, detector_type))
            consumer_tasks.append(task)

        # Start correlation loop
        correlate_task = asyncio.create_task(self._correlate_loop())

        # Wait for tasks
        try:
            await asyncio.gather(*consumer_tasks, correlate_task)
        except asyncio.CancelledError:
            logger.info("Ensemble detector cancelled")
        finally:
            await self.stop()

    async def stop(self):
        """Stop the ensemble detector."""
        if not self._running:
            return
        self._running = False
        for consumer in self._consumers:
            await consumer.stop()
        self._consumers.clear()
        logger.info("Ensemble detector stopped")

    def get_stats(self) -> Dict[str, Any]:
        """Get detector statistics."""
        return self._stats.copy()
