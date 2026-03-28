"""Main entry point for the mitigation service.

This service orchestrates automated mitigation actions based on incoming alerts.
It consumes enriched alerts from Kafka, applies mitigation measures, and manages
rollback after attacks subside.
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
from ..common.metrics import metrics
from .orchestrator import MitigationOrchestrator

logger = get_logger(__name__)


class MitigationService:
    """Main mitigation service orchestrator."""

    def __init__(self, config: dict):
        """Initialize mitigation service.

        Args:
            config: Configuration dictionary.
        """
        self.config = config
        self.orchestrator: Optional[MitigationOrchestrator] = None
        self.producer: Optional[TelemetryProducer] = None
        self._running = False

    async def start(self):
        """Start the mitigation service."""
        if self._running:
            logger.warning("Mitigation service already running")
            return

        self._running = True

        # Get mitigation configuration
        mit_config = self.config.get("mitigation", {})
        kafka_config = self.config.get("kafka", {})
        kafka_topics = kafka_config.get("topics", {})
        rate_limit_config = mit_config.get("rate_limits", mit_config.get("rate_limiting", {}))
        scrubbing_config = {
            "scrubbing_centers": mit_config.get("scrubbing_centers", []),
            "defaults": mit_config.get("scrubbing_profile", {}).get("defaults", {}),
            "routing_policies": mit_config.get("scrubbing_profile", {}).get("routing_policies", {}),
        }

        self.producer = TelemetryProducer(
            bootstrap_servers=kafka_config.get("bootstrap_servers"),
            batch_size=kafka_config.get("producer_batch_size", 100),
            batch_timeout_ms=kafka_config.get("producer_linger_ms", 100),
            send_timeout_ms=kafka_config.get("producer_send_timeout_ms", 10000),
            compression_type=kafka_config.get("compression_type", "gzip"),
            # Keep Kafka event publishing enabled in dry-run mode so the
            # integration pipeline remains observable end-to-end.
            dry_run=False,
        )
        await self.producer.start()

        # Initialize orchestrator
        self.orchestrator = MitigationOrchestrator(
            input_topic=mit_config.get("input_topic", kafka_topics.get("alerts", "alerts.enriched")),
            output_topic=mit_config.get("output_topic", kafka_topics.get("mitigation_events", "mitigation.events")),
            bootstrap_servers=kafka_config.get("bootstrap_servers"),
            batch_size=mit_config.get("batch_size", 10),
            batch_timeout_ms=mit_config.get("batch_timeout_ms", 500),
            auto_response=mit_config.get("auto_response", True),
            dry_run=mit_config.get("dry_run", False),
            action_timeout=mit_config.get("action_timeout", 30),
            rollback_delay=mit_config.get("rollback_delay", 300),
            producer=self.producer,
            rate_limit_config=rate_limit_config,
            scrubbing_config=scrubbing_config,
        )

        logger.info("Starting mitigation service")
        await self.orchestrator.start()

    async def stop(self):
        """Stop the mitigation service."""
        if not self._running:
            return

        logger.info("Stopping mitigation service")
        self._running = False

        if self.orchestrator:
            await self.orchestrator.stop()
        if self.producer:
            await self.producer.stop()

        logger.info("Mitigation service stopped")

    async def run(self):
        """Run the service (start and wait for shutdown)."""
        await self.start()
        # Keep running until stopped
        try:
            while self._running:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            await self.stop()


async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="DDoS Defense Platform - Mitigation Service")
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
    metrics.service_up.labels(service="mitigation").set(1)

    service = MitigationService(config)

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
        service_task = asyncio.create_task(service.run())
        await stop_event.wait()
        await service.stop()
        service_task.cancel()
        await service_task
    except asyncio.CancelledError:
        pass
    finally:
        metrics.service_up.labels(service="mitigation").set(0)
        logger.info("Mitigation service exiting")


if __name__ == "__main__":
    asyncio.run(main())
