"""Integration-oriented tests for the unified DDoS pipeline.

These tests avoid depending on a live Kafka broker and instead verify that the
major pipeline stages interoperate through their current contracts.
"""

import asyncio
import time
from collections import deque
from unittest.mock import AsyncMock, Mock

import pytest

from src.detection.alert_generator import AlertGenerator
from src.detection.anomaly import AnomalyDetector
from src.detection.ensemble import DetectorResult, EnsembleDetector
from src.ingestion.packet_capture import PacketCapture
from src.ingestion.kafka_producer import TelemetryProducer
from src.mitigation.orchestrator import MitigationOrchestrator


@pytest.mark.asyncio
class TestUnifiedPipeline:
    """Validate the contracts between major pipeline stages."""

    async def test_packet_capture_to_detection_contract(self):
        producer = Mock(spec=TelemetryProducer)
        producer.send_batch = AsyncMock()

        capture = PacketCapture(
            interface="lo",
            backend="scapy",
            promiscuous=False,
            producer=producer,
            output_topic="ddos.telemetry.raw.dev",
        )

        detector = AnomalyDetector(
            input_topic="ddos.telemetry.flows.dev",
            output_topic="detection.anomaly.alerts",
            batch_size=10,
            batch_timeout_ms=100,
            volumetric_mbps_threshold=10,
            volumetric_pps_threshold=1000,
            producer=producer,
        )
        detector._consumer = Mock(producer=producer)

        now = time.time()
        flows = []
        for idx in range(12):
            flows.append(
                {
                    "timestamp": now,
                    "bytes": 250000,
                    "packets": 200,
                    "protocol": 6,
                    "src_ip": f"198.51.100.{idx + 1}",
                    "dst_ip": "192.0.2.10",
                    "src_port": 4000 + idx,
                    "dst_port": 80,
                    "tcp_flags": 0x02,
                }
            )

        await detector._process_batch(flows)

        assert detector._stats["flows_processed"] == len(flows)
        producer.send_batch.assert_called_once()
        _, kwargs = producer.send_batch.call_args
        assert kwargs["topic"] == "detection.anomaly.alerts"
        assert kwargs["messages"]
        assert kwargs["messages"][0]["detector"] == "anomaly"
        assert kwargs["messages"][0]["target_ip"] == "192.0.2.10"

    async def test_ensemble_to_alert_generator_contract(self):
        now = time.time()
        detector = EnsembleDetector(
            weights={"signature": 0.3, "anomaly": 0.7, "ml": 0.0},
            alert_threshold=0.5,
            window_seconds=10,
        )
        detector._alerts_queue = deque(
            [
                DetectorResult(
                    "signature",
                    {
                        "detector": "signature",
                        "type": "syn_flood",
                        "target_ip": "192.0.2.10",
                        "source_ips": ["198.51.100.21"],
                    },
                    0.72,
                    now,
                    3,
                ),
                DetectorResult(
                    "anomaly",
                    {
                        "detector": "anomaly",
                        "type": "syn_flood",
                        "target_ip": "192.0.2.10",
                        "source_ips": ["198.51.100.21", "198.51.100.22"],
                    },
                    0.92,
                    now,
                    4,
                ),
            ]
        )

        alerts = await detector._correlate_alerts()
        assert len(alerts) == 1

        generator = AlertGenerator(enrichment_enabled=True)
        enriched = generator._enrich_alert(alerts[0])

        assert enriched["detector"] == "ensemble"
        assert enriched["platform"] == "Real-Time Distributed Denial of Service Attack Detection and Mitigation in Cloud Networks"
        assert enriched["pipeline_stage"] == "enriched_alert"
        assert enriched["target_ip"] == "192.0.2.10"
        assert "suggested_actions" in enriched
        assert enriched["schema_version"] == "1.0"

    async def test_alert_to_mitigation_contract(self):
        producer = Mock(spec=TelemetryProducer)
        producer.send = AsyncMock()

        orchestrator = MitigationOrchestrator(
            input_topic="ddos.alerts.dev",
            output_topic="ddos.mitigation.events.dev",
            auto_response=True,
            dry_run=True,
            rollback_delay=1,
            producer=producer,
        )
        orchestrator._consumer = Mock(producer=producer)

        alert = {
            "alert_id": "integration-test-alert",
            "detector": "ensemble",
            "type": "ddos_attack",
            "severity": 4,
            "confidence": 0.88,
            "target_ip": "192.0.2.10",
            "target": "192.0.2.10:syn_flood",
            "source_ips": ["198.51.100.21", "198.51.100.22"],
            "telemetry_source": "correlated_detection",
            "pipeline_stage": "enriched_alert",
            "platform": "Real-Time Distributed Denial of Service Attack Detection and Mitigation in Cloud Networks",
            "schema_version": "1.0",
            "suggested_actions": ["rate_limit", "blacklist_sources"],
            "timestamp": time.time(),
        }

        await orchestrator._process_batch([alert])

        assert orchestrator._stats["alerts_processed"] == 1
        producer.send.assert_awaited_once()
        _, kwargs = producer.send.call_args
        assert kwargs["topic"] == "ddos.mitigation.events.dev"
        assert kwargs["message"]["type"] == "mitigation"
        assert kwargs["message"]["status"] == "dry_run"
        assert kwargs["message"]["actions"] == ["rate_limit", "blacklist_sources"]
