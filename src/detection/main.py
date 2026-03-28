"""Main entry point for the detection service.

This service orchestrates the multi-layer detection engine, consuming telemetry
from Kafka, running signature, anomaly, and ML detectors, and producing
enriched alerts to Kafka for the mitigation service.
"""

import asyncio
import signal
import argparse
from typing import Optional

import structlog
from prometheus_client import start_http_server

from ..common.logging import get_logger, setup_logging
from ..common.config import load_config
from ..common.kafka_producer import TelemetryProducer
from ..common.kafka_consumer import KafkaConsumerHelper
from ..common.metrics import metrics
from .signature import SignatureDetector
from .anomaly import AnomalyDetector
from .ensemble import EnsembleDetector
from .alert_generator import AlertGenerator

logger = get_logger(__name__)


class DetectionService:
    """Main detection service orchestrator."""

    def __init__(self, config: dict):
        """Initialize detection service.

        Args:
            config: Configuration dictionary.
        """
        self.config = config
        self.producer: Optional[TelemetryProducer] = None
        self.signature_detector: Optional[SignatureDetector] = None
        self.anomaly_detector: Optional[AnomalyDetector] = None
        self.ml_detector: Optional[MLDetector] = None
        self.ensemble_detector: Optional[EnsembleDetector] = None
        self.alert_generator: Optional[AlertGenerator] = None

        self._running = False
        self._tasks = []

    async def start(self):
        """Start all detection components."""
        if self._running:
            logger.warning("Detection service already running")
            return

        self._running = True

        # Initialize Kafka producer (shared for all detection outputs)
        kafka_config = self.config.get("kafka", {})
        kafka_topics = kafka_config.get("topics", {})
        raw_topic = kafka_topics.get("telemetry_raw", "telemetry.raw")
        flows_topic = kafka_topics.get("flows", "telemetry.flows")
        alerts_topic = kafka_topics.get("alerts", "alerts.enriched")
        self.producer = TelemetryProducer(
            bootstrap_servers=kafka_config.get("bootstrap_servers"),
            batch_size=kafka_config.get("producer_batch_size", 100),
            batch_timeout_ms=kafka_config.get("producer_linger_ms", 100),
            send_timeout_ms=kafka_config.get("producer_send_timeout_ms", 10000),
            compression_type=kafka_config.get("compression_type", "gzip"),
        )
        await self.producer.start()
        logger.info("Kafka producer started")

        # Initialize detectors based on configuration
        detection_cfg = self.config.get("detection", {})

        # Signature detector
        sig_cfg = detection_cfg.get("signature", {})
        if sig_cfg.get("enabled", True):
            self.signature_detector = SignatureDetector(
                rules_path=sig_cfg.get("rules_path", "/etc/snort/rules/"),
                engine=sig_cfg.get("engine", "snort"),
                input_topic=sig_cfg.get("input_topic", raw_topic),
                output_topic=sig_cfg.get("output_topic", "detection.signature.alerts"),
                bootstrap_servers=kafka_config.get("bootstrap_servers"),
                batch_size=sig_cfg.get("batch_size", 1000),
                timeout_ms=sig_cfg.get("timeout_ms", 1000),
                reload_interval=sig_cfg.get("reload_interval", 300),
                producer=self.producer,
            )
            task = asyncio.create_task(self.signature_detector.start())
            self._tasks.append(task)
            logger.info("Signature detector started")

        # Anomaly detector
        anomaly_cfg = detection_cfg.get("anomaly", {})
        if anomaly_cfg.get("enabled", True):
            volumetric = anomaly_cfg.get("volumetric", {})
            entropy = anomaly_cfg.get("entropy", {})
            syn_flood = anomaly_cfg.get("syn_flood", {})
            icmp_flood = anomaly_cfg.get("icmp_flood", {})

            self.anomaly_detector = AnomalyDetector(
                input_topic=anomaly_cfg.get("input_topic", flows_topic),
                output_topic=anomaly_cfg.get("output_topic", "detection.anomaly.alerts"),
                bootstrap_servers=kafka_config.get("bootstrap_servers"),
                batch_size=anomaly_cfg.get("batch_size", 100),
                batch_timeout_ms=anomaly_cfg.get("batch_timeout_ms", 1000),
                volumetric_mbps_threshold=volumetric.get("threshold_mbps", 1000.0),
                volumetric_pps_threshold=volumetric.get("threshold_pps", 500000.0),
                entropy_threshold=entropy.get("threshold", 3.5),
                syn_flood_threshold=syn_flood.get("threshold", 1000.0),
                icmp_flood_threshold=icmp_flood.get("threshold", 500.0),
                window_seconds=anomaly_cfg.get("windows", {}).get("short", 60),
                baseline_window_seconds=anomaly_cfg.get("windows", {}).get("long", 3600),
                deviation_factor=anomaly_cfg.get("deviation_factor", 3.0),
                producer=self.producer,
            )
            task = asyncio.create_task(self.anomaly_detector.start())
            self._tasks.append(task)
            logger.info("Anomaly detector started")

        # ML detector
        ml_cfg = detection_cfg.get("ml", {})
        if ml_cfg.get("enabled", False):
            from .ml import MLDetector

            self.ml_detector = MLDetector(
                model_path=ml_cfg.get("model_path", "/opt/ddos-defense/models/ensemble_model.joblib"),
                feature_extractor_path=ml_cfg.get("feature_extractor_path"),
                input_topic=ml_cfg.get("input_topic", flows_topic),
                output_topic=ml_cfg.get("output_topic", "detection.ml.alerts"),
                bootstrap_servers=kafka_config.get("bootstrap_servers"),
                batch_size=ml_cfg.get("batch_size", 100),
                batch_timeout_ms=ml_cfg.get("batch_timeout_ms", 1000),
                confidence_threshold=ml_cfg.get("confidence_threshold", 0.85),
                inference_mode=ml_cfg.get("inference_mode", "batch"),
                producer=self.producer,
            )
            task = asyncio.create_task(self.ml_detector.start())
            self._tasks.append(task)
            logger.info("ML detector started")

        # Ensemble detector
        ensemble_cfg = detection_cfg.get("ensemble", {})
        if ensemble_cfg.get("enabled", True):
            self.ensemble_detector = EnsembleDetector(
                input_topics=[
                    "detection.signature.alerts",
                    "detection.anomaly.alerts",
                    "detection.ml.alerts",
                ],
                output_topic=ensemble_cfg.get("output_topic", "detection.ensemble.alerts"),
                bootstrap_servers=kafka_config.get("bootstrap_servers"),
                batch_size=ensemble_cfg.get("batch_size", 100),
                batch_timeout_ms=ensemble_cfg.get("batch_timeout_ms", 1000),
                weights=ensemble_cfg.get("weights", {"signature": 0.2, "anomaly": 0.4, "ml": 0.4}),
                alert_threshold=ensemble_cfg.get("alert_threshold", 0.6),
                window_seconds=ensemble_cfg.get("window_seconds", 10),
                min_votes=ensemble_cfg.get("min_votes", 2),
                voting=ensemble_cfg.get("voting", "weighted"),
                producer=self.producer,
            )
            task = asyncio.create_task(self.ensemble_detector.start())
            self._tasks.append(task)
            logger.info("Ensemble detector started")

        # Alert generator
        alert_cfg = detection_cfg.get("alert_generator", {})
        if alert_cfg.get("enabled", True):
            self.alert_generator = AlertGenerator(
                input_topic=alert_cfg.get("input_topic", "detection.ensemble.alerts"),
                output_topic=alert_cfg.get("output_topic", alerts_topic),
                bootstrap_servers=kafka_config.get("bootstrap_servers"),
                batch_size=alert_cfg.get("batch_size", 50),
                batch_timeout_ms=alert_cfg.get("batch_timeout_ms", 500),
                enrichment_enabled=alert_cfg.get("enrichment_enabled", True),
                producer=self.producer,
            )
            task = asyncio.create_task(self.alert_generator.start())
            self._tasks.append(task)
            logger.info("Alert generator started")

        # Wait for all tasks
        try:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        except asyncio.CancelledError:
            logger.info("Detection tasks cancelled")
        except Exception as e:
            logger.exception("Unexpected error in detection tasks", error=str(e))

    async def stop(self):
        """Stop all detection components."""
        if not self._running:
            return

        logger.info("Stopping detection service")
        self._running = False

        # Cancel all tasks
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)

        # Stop components
        if self.signature_detector:
            await self.signature_detector.stop()
        if self.anomaly_detector:
            await self.anomaly_detector.stop()
        if self.ml_detector:
            await self.ml_detector.stop()
        if self.ensemble_detector:
            await self.ensemble_detector.stop()
        if self.alert_generator:
            await self.alert_generator.stop()
        if self.producer:
            await self.producer.stop()

        logger.info("Detection service stopped")


async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="DDoS Defense Platform - Detection Service")
    parser.add_argument("--config", default="config/default.yaml", help="Configuration file path")
    parser.add_argument("--env", choices=["dev", "prod"], default="dev", help="Environment")
    args = parser.parse_args()

    # Load configuration
    config = load_config(args.config, env=args.env)

    # Setup logging
    setup_logging(level=config.get("log_level", "INFO"))
    prom_cfg = config.get("monitoring", {}).get("prometheus", {})
    metrics_port = prom_cfg.get("port", 9090)
    if prom_cfg.get("enabled", True):
        start_http_server(metrics_port, registry=metrics._registry)
    metrics.service_up.labels(service="detection").set(1)

    service = DetectionService(config)

    # Handle graceful shutdown
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def signal_handler():
        logger.info("Received shutdown signal")
        stop_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, signal_handler)

    try:
        # Start service
        service_task = asyncio.create_task(service.start())
        await stop_event.wait()
        await service.stop()
        service_task.cancel()
        await service_task
    except asyncio.CancelledError:
        pass
    finally:
        metrics.service_up.labels(service="detection").set(0)
        logger.info("Detection service exiting")


if __name__ == "__main__":
    asyncio.run(main())
