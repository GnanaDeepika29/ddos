"""Statistical anomaly detection for DDoS attacks.

This module implements statistical and behavioral anomaly detection using
techniques such as entropy calculation, threshold-based detection,
time-series forecasting, and correlation analysis.
"""

import asyncio
import time
import math
import numpy as np
from collections import defaultdict, deque
from typing import Optional, Dict, Any, List, Tuple, DefaultDict
from dataclasses import dataclass, field
import statistics

import structlog

from ..common.logging import get_logger
from ..common.metrics import metrics
from ..common.kafka_consumer import KafkaConsumerHelper

logger = get_logger(__name__)


@dataclass
class FeatureWindow:
    """Sliding window for a feature."""
    values: deque = field(default_factory=lambda: deque(maxlen=1000))
    timestamps: deque = field(default_factory=lambda: deque(maxlen=1000))
    window_seconds: int = 60

    def add(self, value: float, timestamp: float):
        self.values.append(value)
        self.timestamps.append(timestamp)
        # Remove old entries outside window
        while self.timestamps and self.timestamps[0] < timestamp - self.window_seconds:
            self.timestamps.popleft()
            self.values.popleft()

    def mean(self) -> float:
        return statistics.mean(self.values) if self.values else 0.0

    def std(self) -> float:
        return statistics.stdev(self.values) if len(self.values) > 1 else 0.0

    def variance(self) -> float:
        return statistics.variance(self.values) if len(self.values) > 1 else 0.0

    def percentile(self, p: float) -> float:
        if not self.values:
            return 0.0
        sorted_vals = sorted(self.values)
        idx = int(len(sorted_vals) * p / 100.0)
        return sorted_vals[min(idx, len(sorted_vals)-1)]


class AnomalyDetector:
    """Statistical anomaly detection engine."""

    def __init__(
        self,
        input_topic: str = "telemetry.flows",
        output_topic: str = "detection.anomaly.alerts",
        bootstrap_servers: Optional[List[str]] = None,
        batch_size: int = 100,
        batch_timeout_ms: int = 1000,
        # Thresholds from config
        volumetric_mbps_threshold: float = 1000.0,
        volumetric_pps_threshold: float = 500000.0,
        entropy_threshold: float = 3.5,
        syn_flood_threshold: float = 1000.0,
        icmp_flood_threshold: float = 500.0,
        window_seconds: int = 60,
        baseline_window_seconds: int = 3600,
        deviation_factor: float = 3.0,
    ):
        """Initialize anomaly detector.

        Args:
            input_topic: Kafka topic for flow data.
            output_topic: Kafka topic for alerts.
            bootstrap_servers: Kafka broker list.
            batch_size: Number of flows per batch.
            batch_timeout_ms: Batch timeout.
            volumetric_mbps_threshold: Mbps threshold for volumetric detection.
            volumetric_pps_threshold: PPS threshold for volumetric detection.
            entropy_threshold: Entropy threshold (below this indicates attack).
            syn_flood_threshold: SYN packets per second per destination.
            icmp_flood_threshold: ICMP packets per second.
            window_seconds: Analysis window size.
            baseline_window_seconds: Baseline learning window.
            deviation_factor: Number of standard deviations for anomaly.
        """
        self.input_topic = input_topic
        self.output_topic = output_topic
        self.bootstrap_servers = bootstrap_servers or ["localhost:9092"]
        self.batch_size = batch_size
        self.batch_timeout_ms = batch_timeout_ms

        # Thresholds
        self.volumetric_mbps_threshold = volumetric_mbps_threshold
        self.volumetric_pps_threshold = volumetric_pps_threshold
        self.entropy_threshold = entropy_threshold
        self.syn_flood_threshold = syn_flood_threshold
        self.icmp_flood_threshold = icmp_flood_threshold
        self.window_seconds = window_seconds
        self.baseline_window_seconds = baseline_window_seconds
        self.deviation_factor = deviation_factor

        # Internal state
        self._running = False
        self._consumer: Optional[KafkaConsumerHelper] = None
        self._stats = {
            "flows_processed": 0,
            "alerts_generated": 0,
            "errors": 0,
        }

        # Feature windows for baselining
        self._feature_windows: Dict[str, FeatureWindow] = {}

        # Per-second counters
        self._bytes_per_sec: DefaultDict[int, float] = defaultdict(float)
        self._packets_per_sec: DefaultDict[int, int] = defaultdict(int)
        self._syn_per_sec: DefaultDict[Tuple[int, int], int] = defaultdict(int)  # (dst_ip, sec)
        self._icmp_per_sec: DefaultDict[int, int] = defaultdict(int)

        # Entropy tracking: per window
        self._src_ip_counts: DefaultDict[str, int] = defaultdict(int)
        self._dst_ip_counts: DefaultDict[str, int] = defaultdict(int)
        self._src_port_counts: DefaultDict[int, int] = defaultdict(int)
        self._dst_port_counts: DefaultDict[int, int] = defaultdict(int)
        self._protocol_counts: DefaultDict[int, int] = defaultdict(int)

        self._window_start = time.time()
        self._window_flows = 0

    def _compute_entropy(self, counts: Dict[Any, int]) -> float:
        """Compute Shannon entropy of a distribution."""
        total = sum(counts.values())
        if total == 0:
            return 0.0
        entropy = 0.0
        for cnt in counts.values():
            p = cnt / total
            entropy -= p * math.log2(p)
        return entropy

    def _update_windows(self, flow: Dict[str, Any]):
        """Update statistical windows with flow data."""
        timestamp = flow.get("timestamp", time.time())
        sec = int(timestamp)
        bytes_val = flow.get("bytes", 0)
        packets = flow.get("packets", 0)
        protocol = flow.get("protocol", 0)
        src_ip = flow.get("src_ip", "")
        dst_ip = flow.get("dst_ip", "")
        src_port = flow.get("src_port", 0)
        dst_port = flow.get("dst_port", 0)

        # Per-second counters
        self._bytes_per_sec[sec] += bytes_val
        self._packets_per_sec[sec] += packets

        # SYN flood: TCP with SYN flag
        tcp_flags = flow.get("tcp_flags", 0)
        if protocol == 6 and (tcp_flags & 0x02):  # TCP SYN
            self._syn_per_sec[(dst_ip, sec)] += 1

        # ICMP flood
        if protocol == 1:
            self._icmp_per_sec[sec] += packets

        # Entropy tracking per window
        if timestamp - self._window_start < self.window_seconds:
            self._src_ip_counts[src_ip] += packets
            self._dst_ip_counts[dst_ip] += packets
            self._src_port_counts[src_port] += packets
            self._dst_port_counts[dst_port] += packets
            self._protocol_counts[protocol] += packets
            self._window_flows += 1
        else:
            # Window expired, process it
            self._process_window()
            # Reset for new window
            self._window_start = timestamp
            self._src_ip_counts.clear()
            self._dst_ip_counts.clear()
            self._src_port_counts.clear()
            self._dst_port_counts.clear()
            self._protocol_counts.clear()
            self._window_flows = 0
            # Add current flow to new window
            self._src_ip_counts[src_ip] += packets
            self._dst_ip_counts[dst_ip] += packets
            self._src_port_counts[src_port] += packets
            self._dst_port_counts[dst_port] += packets
            self._protocol_counts[protocol] += packets
            self._window_flows = 1

    def _process_window(self):
        """Process a completed time window for anomaly detection."""
        # Volumetric detection
        total_bytes = sum(self._bytes_per_sec.values())
        total_packets = sum(self._packets_per_sec.values())
        mbps = (total_bytes * 8) / (self.window_seconds * 1_000_000)
        pps = total_packets / self.window_seconds

        alerts = []
        if mbps > self.volumetric_mbps_threshold:
            alerts.append({
                "type": "volumetric",
                "subtype": "bandwidth",
                "severity": 3,
                "value": mbps,
                "threshold": self.volumetric_mbps_threshold,
                "window_seconds": self.window_seconds,
                "timestamp": time.time(),
            })
        if pps > self.volumetric_pps_threshold:
            alerts.append({
                "type": "volumetric",
                "subtype": "packet_rate",
                "severity": 3,
                "value": pps,
                "threshold": self.volumetric_pps_threshold,
                "window_seconds": self.window_seconds,
                "timestamp": time.time(),
            })

        # Entropy detection
        src_entropy = self._compute_entropy(self._src_ip_counts)
        dst_entropy = self._compute_entropy(self._dst_ip_counts)
        src_port_entropy = self._compute_entropy(self._src_port_counts)
        dst_port_entropy = self._compute_entropy(self._dst_port_counts)
        protocol_entropy = self._compute_entropy(self._protocol_counts)

        if src_entropy < self.entropy_threshold:
            alerts.append({
                "type": "entropy",
                "subtype": "src_ip",
                "severity": 2,
                "value": src_entropy,
                "threshold": self.entropy_threshold,
                "window_seconds": self.window_seconds,
                "timestamp": time.time(),
            })
        if dst_entropy < self.entropy_threshold:
            alerts.append({
                "type": "entropy",
                "subtype": "dst_ip",
                "severity": 2,
                "value": dst_entropy,
                "threshold": self.entropy_threshold,
                "window_seconds": self.window_seconds,
                "timestamp": time.time(),
            })

        # Protocol-specific detection
        # SYN flood per destination
        for (dst_ip, sec), count in self._syn_per_sec.items():
            if sec >= self._window_start and count > self.syn_flood_threshold:
                alerts.append({
                    "type": "syn_flood",
                    "subtype": "tcp_syn",
                    "severity": 4,
                    "target_ip": dst_ip,
                    "value": count,
                    "threshold": self.syn_flood_threshold,
                    "timestamp": sec,
                })
        # ICMP flood
        for sec, count in self._icmp_per_sec.items():
            if sec >= self._window_start and count > self.icmp_flood_threshold:
                alerts.append({
                    "type": "icmp_flood",
                    "subtype": "icmp",
                    "severity": 3,
                    "value": count,
                    "threshold": self.icmp_flood_threshold,
                    "timestamp": sec,
                })

        # Clean up old per-second counters
        current_sec = int(time.time())
        for sec in list(self._bytes_per_sec.keys()):
            if sec < current_sec - self.window_seconds:
                del self._bytes_per_sec[sec]
        for sec in list(self._packets_per_sec.keys()):
            if sec < current_sec - self.window_seconds:
                del self._packets_per_sec[sec]
        for (dst_ip, sec) in list(self._syn_per_sec.keys()):
            if sec < current_sec - self.window_seconds:
                del self._syn_per_sec[(dst_ip, sec)]
        for sec in list(self._icmp_per_sec.keys()):
            if sec < current_sec - self.window_seconds:
                del self._icmp_per_sec[sec]

        # Publish alerts
        if alerts:
            self._stats["alerts_generated"] += len(alerts)
            metrics.alerts_total.inc(len(alerts))
            # Alerts are sent via consumer's producer in process_batch
            # We'll store them to be sent later
            self._pending_alerts.extend(alerts)

    async def _process_batch(self, messages: List[Dict[str, Any]]):
        """Process a batch of flow messages."""
        self._pending_alerts = []
        for msg in messages:
            try:
                self._update_windows(msg)
            except Exception as e:
                logger.error("Error processing flow", error=str(e))
                self._stats["errors"] += 1

        # Publish any alerts generated during processing
        if self._pending_alerts and self._consumer and self._consumer.producer:
            await self._consumer.producer.send_batch(
                topic=self.output_topic,
                messages=self._pending_alerts,
            )

        self._stats["flows_processed"] += len(messages)

    async def start(self):
        """Start the anomaly detector."""
        if self._running:
            logger.warning("Anomaly detector already running")
            return

        self._running = True

        # Initialize Kafka consumer
        self._consumer = KafkaConsumerHelper(
            bootstrap_servers=self.bootstrap_servers,
            topic=self.input_topic,
            group_id="anomaly-detector",
            batch_size=self.batch_size,
            batch_timeout_ms=self.batch_timeout_ms,
        )
        await self._consumer.start()

        # Main processing loop
        try:
            async for batch in self._consumer.consume_batches():
                if not self._running:
                    break
                await self._process_batch(batch)
        except asyncio.CancelledError:
            logger.info("Anomaly detector cancelled")
        finally:
            await self.stop()

    async def stop(self):
        """Stop the anomaly detector."""
        if not self._running:
            return
        self._running = False
        if self._consumer:
            await self._consumer.stop()
        logger.info("Anomaly detector stopped")

    def get_stats(self) -> Dict[str, Any]:
        """Get detector statistics."""
        return self._stats.copy()