"""Prometheus metrics collection.

This module provides a central metrics registry and helper functions
for instrumenting the DDoS defense platform.
"""

import time
from typing import Optional

# Try to import prometheus_client; if not available, use dummy stubs
try:
    from prometheus_client import Counter, Gauge, Histogram, Summary, CollectorRegistry, REGISTRY
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    # Dummy classes for when prometheus_client is not installed
    class Counter:
        def __init__(self, *args, **kwargs): pass
        def inc(self, amount=1): pass
        def labels(self, **kwargs): return self
    class Gauge:
        def __init__(self, *args, **kwargs): pass
        def set(self, value): pass
        def inc(self, amount=1): pass
        def dec(self, amount=1): pass
        def labels(self, **kwargs): return self
    class Histogram:
        def __init__(self, *args, **kwargs): pass
        def observe(self, value): pass
        def labels(self, **kwargs): return self
    class Summary:
        def __init__(self, *args, **kwargs): pass
        def observe(self, value): pass
        def labels(self, **kwargs): return self
    CollectorRegistry = object
    REGISTRY = None


class Metrics:
    """Central metrics registry for the platform."""

    def __init__(self, namespace: str = "ddos_defense"):
        """Initialize metrics.

        Args:
            namespace: Namespace prefix for all metrics.
        """
        self.namespace = namespace
        self._registry = CollectorRegistry() if PROMETHEUS_AVAILABLE else None

        # Ingested telemetry
        self.packets_total = self._counter("packets_total", "Total number of packets ingested")
        self.flows_total = self._counter("flows_total", "Total number of flows ingested")
        self.telemetry_updates_total = self._counter("telemetry_updates_total", "Total number of telemetry updates")

        # Detection metrics
        self.alerts_total = self._counter("alerts_total", "Total number of alerts generated")
        self.alerts_published_total = self._counter("alerts_published_total", "Total number of alerts published")
        self.detection_latency = self._histogram("detection_latency_seconds", "Detection latency in seconds")
        self.detection_errors_total = self._counter("detection_errors_total", "Total detection errors")

        # Mitigation metrics
        self.mitigation_actions_total = self._counter("mitigation_actions_total", "Total mitigation actions taken")
        self.mitigation_latency = self._histogram("mitigation_latency_seconds", "Mitigation action latency")
        self.mitigation_errors_total = self._counter("mitigation_errors_total", "Total mitigation errors")

        # Service health
        self.service_up = self._gauge("service_up", "Service health (1 = up, 0 = down)", labelnames=["service"])
        self.service_up.labels(service="ingestion").set(1)
        self.service_up.labels(service="detection").set(1)
        self.service_up.labels(service="mitigation").set(1)

        # Kafka metrics
        self.kafka_messages_sent = self._counter("kafka_messages_sent", "Kafka messages sent")
        self.kafka_messages_received = self._counter("kafka_messages_received", "Kafka messages received")
        self.kafka_errors_total = self._counter("kafka_errors_total", "Kafka errors")

        # Attack metrics (with labels)
        self.attacks_detected = self._counter("attacks_detected", "Attacks detected by type",
                                              labelnames=["attack_type", "severity"])

        # Performance
        self.inference_time_ms = self._summary("inference_time_milliseconds", "ML inference time")
        self.queue_size = self._gauge("queue_size", "Current queue size", labelnames=["queue_name"])

    def _counter(self, name: str, documentation: str, labelnames: Optional[list] = None) -> Counter:
        """Create or get a counter metric."""
        full_name = f"{self.namespace}_{name}"
        if PROMETHEUS_AVAILABLE:
            return Counter(full_name, documentation, labelnames=labelnames or [], registry=self._registry)
        return Counter()

    def _gauge(self, name: str, documentation: str, labelnames: Optional[list] = None) -> Gauge:
        """Create or get a gauge metric."""
        full_name = f"{self.namespace}_{name}"
        if PROMETHEUS_AVAILABLE:
            return Gauge(full_name, documentation, labelnames=labelnames or [], registry=self._registry)
        return Gauge()

    def _histogram(self, name: str, documentation: str, buckets: Optional[list] = None) -> Histogram:
        """Create or get a histogram metric."""
        full_name = f"{self.namespace}_{name}"
        if PROMETHEUS_AVAILABLE:
            histogram_kwargs = {"registry": self._registry}
            if buckets is not None:
                histogram_kwargs["buckets"] = buckets
            return Histogram(full_name, documentation, **histogram_kwargs)
        return Histogram()

    def _summary(self, name: str, documentation: str) -> Summary:
        """Create or get a summary metric."""
        full_name = f"{self.namespace}_{name}"
        if PROMETHEUS_AVAILABLE:
            return Summary(full_name, documentation, registry=self._registry)
        return Summary()

    def record_attack(self, attack_type: str, severity: int):
        """Record a detected attack."""
        self.attacks_detected.labels(attack_type=attack_type, severity=str(severity)).inc()

    def time_detection(self, func):
        """Decorator to measure detection latency."""
        async def wrapper(*args, **kwargs):
            start = time.time()
            try:
                result = await func(*args, **kwargs)
                return result
            finally:
                duration = time.time() - start
                self.detection_latency.observe(duration)
        return wrapper

    def time_mitigation(self, func):
        """Decorator to measure mitigation latency."""
        async def wrapper(*args, **kwargs):
            start = time.time()
            try:
                result = await func(*args, **kwargs)
                return result
            finally:
                duration = time.time() - start
                self.mitigation_latency.observe(duration)
        return wrapper


# Global metrics instance
metrics = Metrics()
