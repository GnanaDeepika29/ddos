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

from ..common.logging import get_logger, setup_logging
from ..common.config import load_config
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

        # Initialize orchestrator
        self.orchestrator = MitigationOrchestrator(
            input_topic=mit_config.get("input_topic", "alerts.enriched"),
            output_topic=mit_config.get("output_topic", "mitigation.events"),
            bootstrap_servers=kafka_config.get("bootstrap_servers"),
            batch_size=mit_config.get("batch_size", 10),
            batch_timeout_ms=mit_config.get("batch_timeout_ms", 500),
            auto_response=mit_config.get("auto_response", True),
            dry_run=mit_config.get("dry_run", False),
            action_timeout=mit_config.get("action_timeout", 30),
            rollback_delay=mit_config.get("rollback_delay", 300),
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
        logger.info("Mitigation service exiting")


if __name__ == "__main__":
    asyncio.run(main())