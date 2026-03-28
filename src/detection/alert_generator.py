"""Alert generation and enrichment module.

This module takes detection results from various detectors, enriches them
with additional context, and publishes standardized alerts to Kafka for
the mitigation system.
"""

import asyncio
import time
import uuid
from typing import Optional, Dict, Any, List
from collections import defaultdict
import json

import structlog

from ..common.logging import get_logger
from ..common.metrics import metrics
from ..common.kafka_consumer import KafkaConsumerHelper
from ..common.kafka_producer import TelemetryProducer
from ..common.database import db

logger = get_logger(__name__)


class AlertGenerator:
    """Generate, enrich, and publish alerts from detection engines."""

    def __init__(
        self,
        input_topic: str = "detection.ensemble.alerts",
        output_topic: str = "alerts.enriched",
        bootstrap_servers: Optional[List[str]] = None,
        batch_size: int = 50,
        batch_timeout_ms: int = 500,
        enrichment_enabled: bool = True,
        producer: Optional[TelemetryProducer] = None,
    ):
        """Initialize alert generator.

        Args:
            input_topic: Kafka topic to consume raw alerts from.
            output_topic: Kafka topic to publish enriched alerts.
            bootstrap_servers: Kafka broker list.
            batch_size: Number of alerts per batch.
            batch_timeout_ms: Batch timeout.
            enrichment_enabled: Whether to perform enrichment.
        """
        self.input_topic = input_topic
        self.output_topic = output_topic
        self.bootstrap_servers = bootstrap_servers or ["localhost:9092"]
        self.batch_size = batch_size
        self.batch_timeout_ms = batch_timeout_ms
        self.enrichment_enabled = enrichment_enabled
        self.producer = producer

        self._running = False
        self._consumer: Optional[KafkaConsumerHelper] = None
        self._stats = {
            "alerts_received": 0,
            "alerts_published": 0,
            "errors": 0,
        }

    def _normalize_alert_contract(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        normalized = alert.copy()
        flow = normalized.get("flow", {}) or {}
        packet = normalized.get("packet", {}) or {}

        target_ip = (
            normalized.get("target_ip")
            or flow.get("dst_ip")
            or packet.get("dst_ip")
            or "unknown"
        )
        source_ip = (
            normalized.get("source_ip")
            or flow.get("src_ip")
            or packet.get("src_ip")
            or None
        )
        source_ips = normalized.get("source_ips") or ([source_ip] if source_ip else [])

        normalized.setdefault("detector", "unknown")
        normalized.setdefault("target_ip", target_ip)
        normalized.setdefault("target", target_ip if target_ip != "unknown" else normalized.get("target", "unknown"))
        normalized.setdefault("source_ip", source_ip)
        normalized["source_ips"] = [ip for ip in source_ips if ip]
        normalized.setdefault("telemetry_source", "unified_pipeline")
        normalized.setdefault("schema_version", "1.0")
        normalized.setdefault(
            "platform",
            "Real-Time Distributed Denial of Service Attack Detection and Mitigation in Cloud Networks",
        )
        normalized.setdefault("pipeline_stage", "enriched_alert")
        normalized.setdefault("confidence", round(min(0.99, 0.45 + 0.1 * normalized.get("severity", 2)), 3))
        return normalized

    def _enrich_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich alert with additional metadata."""
        enriched = self._normalize_alert_contract(alert)

        # Add unique alert ID if not present
        if "alert_id" not in enriched:
            enriched["alert_id"] = str(uuid.uuid4())

        # Add timestamp if missing
        if "timestamp" not in enriched:
            enriched["timestamp"] = time.time()

        # Normalize severity to integer 1-5
        severity = enriched.get("severity", 2)
        if isinstance(severity, str):
            severity_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
            severity = severity_map.get(severity.lower(), 2)
        enriched["severity"] = max(1, min(5, int(severity)))

        # Add attack category based on type
        attack_type = enriched.get("type", "unknown")
        enriched["category"] = self._map_attack_category(attack_type)

        # Add human-readable description
        enriched["description"] = self._generate_description(enriched)

        # Add mitigation suggestions
        enriched["suggested_actions"] = self._suggest_actions(enriched)

        # Add geo-ip enrichment (placeholder)
        if self.enrichment_enabled:
            target = enriched.get("target", "unknown")
            if isinstance(target, dict):
                target_ip = target.get("ip") or target.get("target_ip") or "unknown"
            else:
                target_ip = enriched.get("target_ip") or str(target).split(":")[0]
            if target_ip and target_ip != "unknown":
                # In production, call GeoIP service
                enriched["geo"] = {
                    "country": "Unknown",
                    "asn": "Unknown",
                }

        return enriched

    def _map_attack_category(self, attack_type: str) -> str:
        """Map attack type to category."""
        mapping = {
            "volumetric": "Volumetric",
            "syn_flood": "Protocol",
            "icmp_flood": "Volumetric",
            "entropy": "Anomaly",
            "ml_detection": "Application",
            "ddos_attack": "Volumetric",
        }
        return mapping.get(attack_type, "Unknown")

    def _generate_description(self, alert: Dict[str, Any]) -> str:
        """Generate human-readable description of the alert."""
        attack_type = alert.get("type", "attack")
        confidence = alert.get("confidence", 0.0)
        target = alert.get("target_ip") or alert.get("target", "unknown")
        severity = alert.get("severity", 2)

        base = f"Potential {attack_type} DDoS attack detected"
        if target != "unknown":
            base += f" targeting {target}"
        base += f" with confidence {confidence:.2f}"
        if severity >= 4:
            base += " (Critical)"
        elif severity >= 3:
            base += " (High)"
        return base

    def _suggest_actions(self, alert: Dict[str, Any]) -> List[str]:
        """Suggest mitigation actions based on alert type and severity."""
        actions = []
        severity = alert.get("severity", 2)
        attack_type = alert.get("type", "")

        if severity >= 3:
            actions.append("rate_limit")
        if severity >= 4:
            actions.append("blacklist_sources")
        if "volumetric" in attack_type or "flood" in attack_type:
            actions.append("scrubbing")
        if "syn" in attack_type:
            actions.append("syn_cookie")
        if not actions:
            actions.append("monitor")
        return actions

    async def _process_batch(self, messages: List[Dict[str, Any]]):
        """Process a batch of alerts."""
        enriched_alerts = []
        for msg in messages:
            try:
                if self.enrichment_enabled:
                    enriched = self._enrich_alert(msg)
                else:
                    enriched = msg
                enriched_alerts.append(enriched)
            except Exception as e:
                logger.error("Alert enrichment failed", error=str(e))
                self._stats["errors"] += 1

        if enriched_alerts:
            # Publish enriched alerts to Kafka
            if self._consumer and self._consumer.producer:
                await self._consumer.producer.send_batch(
                    topic=self.output_topic,
                    messages=enriched_alerts,
                )
            for alert in enriched_alerts:
                if db._running:
                    try:
                        await db.insert_alert(alert)
                    except Exception as e:
                        logger.error("Alert persistence failed", error=str(e), alert_id=alert.get("alert_id"))
                        self._stats["errors"] += 1
            for alert in enriched_alerts:
                metrics.record_attack(alert.get("type", "unknown"), alert.get("severity", 2))
            self._stats["alerts_published"] += len(enriched_alerts)
            metrics.alerts_published_total.inc(len(enriched_alerts))

        self._stats["alerts_received"] += len(messages)

    async def start(self):
        """Start the alert generator."""
        if self._running:
            logger.warning("Alert generator already running")
            return

        self._running = True

        # Initialize Kafka consumer
        self._consumer = KafkaConsumerHelper(
            bootstrap_servers=self.bootstrap_servers,
            topic=self.input_topic,
            group_id="alert-generator",
            batch_size=self.batch_size,
            batch_timeout_ms=self.batch_timeout_ms,
            producer=self.producer,
        )
        await self._consumer.start()

        # Main processing loop
        try:
            async for batch in self._consumer.consume_batches():
                if not self._running:
                    break
                await self._process_batch(batch)
        except asyncio.CancelledError:
            logger.info("Alert generator cancelled")
        finally:
            await self.stop()

    async def stop(self):
        """Stop the alert generator."""
        if not self._running:
            return
        self._running = False
        if self._consumer:
            await self._consumer.stop()
        logger.info("Alert generator stopped")

    def get_stats(self) -> Dict[str, Any]:
        """Get generator statistics."""
        return self._stats.copy()
