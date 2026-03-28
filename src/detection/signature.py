"""Signature-based detection using Snort/Suricata rules.

This module provides integration with signature-based intrusion detection
systems (IDS) to detect known DDoS attack patterns using rule sets.
"""

import asyncio
import os
import re
import subprocess
import tempfile
import time
from typing import Optional, Dict, Any, List, Callable
from pathlib import Path

import structlog

from ..common.logging import get_logger
from ..common.metrics import metrics
from ..common.kafka_consumer import KafkaConsumerHelper

logger = get_logger(__name__)

# Try to import Snort/Suricata Python bindings if available
try:
    import snortpy  # hypothetical; in practice, use subprocess
except ImportError:
    snortpy = None


class SignatureDetector:
    """Signature-based DDoS detection using IDS rule engines."""

    def __init__(
        self,
        rules_path: str = "/etc/snort/rules/",
        engine: str = "snort",  # snort, suricata
        input_topic: str = "telemetry.raw",
        output_topic: str = "detection.signature.alerts",
        bootstrap_servers: Optional[List[str]] = None,
        batch_size: int = 1000,
        timeout_ms: int = 1000,
        reload_interval: int = 300,  # seconds
    ):
        """Initialize signature detector.

        Args:
            rules_path: Directory containing .rules files.
            engine: IDS engine (snort or suricata).
            input_topic: Kafka topic to consume from.
            output_topic: Kafka topic to publish alerts to.
            bootstrap_servers: Kafka broker list.
            batch_size: Number of packets to process per batch.
            timeout_ms: Processing timeout per batch.
            reload_interval: Interval to reload rules (seconds).
        """
        self.rules_path = Path(rules_path)
        self.engine = engine
        self.input_topic = input_topic
        self.output_topic = output_topic
        self.bootstrap_servers = bootstrap_servers or ["localhost:9092"]
        self.batch_size = batch_size
        self.timeout_ms = timeout_ms
        self.reload_interval = reload_interval

        self._running = False
        self._consumer: Optional[KafkaConsumerHelper] = None
        self._rule_hashes: Dict[str, str] = {}
        self._stats = {
            "packets_processed": 0,
            "alerts_generated": 0,
            "errors": 0,
            "rules_loaded": 0,
            "last_reload": None,
        }

    async def _load_rules(self) -> int:
        """Load rules from the rules directory."""
        if not self.rules_path.exists():
            logger.warning("Rules directory does not exist", path=str(self.rules_path))
            return 0

        rule_files = list(self.rules_path.glob("*.rules"))
        if not rule_files:
            logger.warning("No .rules files found", path=str(self.rules_path))
            return 0

        # Collect all rules
        all_rules = []
        for rf in rule_files:
            try:
                with open(rf, "r") as f:
                    content = f.read()
                # Store hash for change detection
                import hashlib
                new_hash = hashlib.md5(content.encode()).hexdigest()
                if self._rule_hashes.get(rf.name) != new_hash:
                    all_rules.append(content)
                    self._rule_hashes[rf.name] = new_hash
            except Exception as e:
                logger.error("Failed to read rules file", file=str(rf), error=str(e))

        # Combine rules into a temporary file for the engine
        if not all_rules:
            return 0

        combined = "\n".join(all_rules)
        self._temp_rules_file = tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False)
        self._temp_rules_file.write(combined)
        self._temp_rules_file.close()

        # Validate rules with engine-specific command
        if self.engine == "snort":
            try:
                result = subprocess.run(
                    ["snort", "-c", self._temp_rules_file.name, "-T"],
                    capture_output=True,
                    timeout=10,
                )
                if result.returncode != 0:
                    logger.error("Snort rule validation failed", stderr=result.stderr.decode())
                    return 0
            except Exception as e:
                logger.error("Snort rule validation error", error=str(e))
                return 0
        elif self.engine == "suricata":
            try:
                result = subprocess.run(
                    ["suricata", "-T", "-S", self._temp_rules_file.name],
                    capture_output=True,
                    timeout=10,
                )
                if result.returncode != 0:
                    logger.error("Suricata rule validation failed", stderr=result.stderr.decode())
                    return 0
            except Exception as e:
                logger.error("Suricata rule validation error", error=str(e))
                return 0

        self._stats["rules_loaded"] = len(rule_files)
        self._stats["last_reload"] = time.time()
        logger.info("Rules loaded", count=len(rule_files), engine=self.engine)
        return len(rule_files)

    async def _reload_loop(self):
        """Periodically reload rules to catch updates."""
        while self._running:
            await asyncio.sleep(self.reload_interval)
            try:
                await self._load_rules()
            except Exception as e:
                logger.error("Rule reload failed", error=str(e))

    async def _process_packet(self, packet: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process a single packet through the signature engine."""
        # For simplicity, we simulate signature matching.
        # In production, we would call the IDS engine via a socket or library.
        # Here we'll implement a lightweight regex-based matcher for demo.

        alerts = []
        # Convert packet to a format the engine can analyze (e.g., PCAP line)
        # For now, we'll simulate by checking for common attack patterns
        # based on packet fields.

        # Example: SYN flood signature
        if packet.get("protocol") == 6:  # TCP
            if packet.get("tcp_flags") == 0x02:  # SYN flag only
                # Check rate (would need state; simplified)
                alerts.append({
                    "rule_id": 100001,
                    "rule_name": "TCP SYN flood",
                    "severity": 3,
                    "packet": packet,
                    "timestamp": time.time(),
                })

        # Example: ICMP flood
        if packet.get("protocol") == 1:  # ICMP
            alerts.append({
                "rule_id": 100002,
                "rule_name": "ICMP flood",
                "severity": 2,
                "packet": packet,
                "timestamp": time.time(),
            })

        # Example: UDP amplification (DNS)
        if packet.get("protocol") == 17:  # UDP
            if packet.get("dst_port") == 53:
                alerts.append({
                    "rule_id": 100003,
                    "rule_name": "DNS amplification",
                    "severity": 4,
                    "packet": packet,
                    "timestamp": time.time(),
                })

        return alerts

    async def _process_batch(self, messages: List[Dict[str, Any]]):
        """Process a batch of packets."""
        batch_alerts = []
        for msg in messages:
            try:
                alerts = await self._process_packet(msg)
                if alerts:
                    batch_alerts.extend(alerts)
            except Exception as e:
                logger.error("Packet processing error", error=str(e))
                self._stats["errors"] += 1

        # Publish alerts
        if batch_alerts:
            self._stats["alerts_generated"] += len(batch_alerts)
            metrics.alerts_total.inc(len(batch_alerts))
            # Publish to Kafka
            if self._consumer and self._consumer.producer:
                await self._consumer.producer.send_batch(
                    topic=self.output_topic,
                    messages=batch_alerts,
                )

        self._stats["packets_processed"] += len(messages)

    async def start(self):
        """Start the signature detector."""
        if self._running:
            logger.warning("Signature detector already running")
            return

        self._running = True

        # Initialize Kafka consumer
        self._consumer = KafkaConsumerHelper(
            bootstrap_servers=self.bootstrap_servers,
            topic=self.input_topic,
            group_id="signature-detector",
            batch_size=self.batch_size,
            batch_timeout_ms=self.timeout_ms,
        )
        await self._consumer.start()

        # Load initial rules
        await self._load_rules()

        # Start reload task
        reload_task = asyncio.create_task(self._reload_loop())

        # Main processing loop
        try:
            async for batch in self._consumer.consume_batches():
                if not self._running:
                    break
                await self._process_batch(batch)
        except asyncio.CancelledError:
            logger.info("Signature detector cancelled")
        finally:
            await self.stop()
            reload_task.cancel()

    async def stop(self):
        """Stop the signature detector."""
        if not self._running:
            return
        self._running = False
        if self._consumer:
            await self._consumer.stop()
        if hasattr(self, "_temp_rules_file") and self._temp_rules_file:
            try:
                os.unlink(self._temp_rules_file.name)
            except:
                pass
        logger.info("Signature detector stopped")

    def get_stats(self) -> Dict[str, Any]:
        """Get detector statistics."""
        return self._stats.copy()