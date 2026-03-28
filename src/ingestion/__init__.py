"""Ingestion module for telemetry collection.

This module provides high-performance collection of network telemetry from
various sources including packet capture, flow export (NetFlow/sFlow/IPFIX),
and streaming telemetry (gNMI).

Modules:
    packet_capture: Raw packet capture using scapy/pcapy
    flow_collector: NetFlow/sFlow collector
    telemetry_grpc: gNMI telemetry streaming
    kafka_producer: Kafka producer for telemetry streaming
"""

try:
    from .packet_capture import PacketCapture
except Exception:
    PacketCapture = None

try:
    from .flow_collector import FlowCollector
except Exception:
    FlowCollector = None

try:
    from .telemetry_grpc import TelemetryGRPC
except Exception:
    TelemetryGRPC = None

from .kafka_producer import TelemetryProducer

__all__ = [
    "PacketCapture",
    "FlowCollector",
    "TelemetryGRPC",
    "TelemetryProducer",
]
