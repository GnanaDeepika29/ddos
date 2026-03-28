"""Main entry point for the ingestion service.

This service orchestrates packet capture, flow collection, and gNMI telemetry
streaming, forwarding all telemetry to Kafka.
"""

import asyncio
import signal
import sys
import argparse
from typing import Optional

import structlog

from ..common.logging import get_logger, setup_logging
from ..common.config import load_config
from .packet_capture import PacketCapture
from .flow_collector import FlowCollector
from .telemetry_grpc import TelemetryGRPC
from .kafka_producer import TelemetryProducer

logger = get_logger(__name__)


class IngestionService:
    """Main ingestion service orchestrator."""

    def __init__(self, config: dict):
        """Initialize ingestion service.

        Args:
            config: Configuration dictionary.
        """
        self.config = config
        self.producer: Optional[TelemetryProducer] = None
        self.packet_capture: Optional[PacketCapture] = None
        self.flow_collector: Optional[FlowCollector] = None
        self.telemetry_grpc: Optional[TelemetryGRPC] = None

        self._running = False
        self._tasks = []

    async def start(self):
        """Start all ingestion components."""
        if self._running:
            logger.warning("Ingestion service already running")
            return

        self._running = True

        # Initialize Kafka producer
        kafka_config = self.config.get("kafka", {})
        self.producer = TelemetryProducer(
            bootstrap_servers=kafka_config.get("bootstrap_servers"),
            batch_size=kafka_config.get("producer_batch_size", 100),
            batch_timeout_ms=kafka_config.get("producer_linger_ms", 100),
            compression_type=kafka_config.get("compression_type", "gzip"),
        )
        await self.producer.start()
        logger.info("Kafka producer started")

        # Start packet capture if enabled
        capture_config = self.config.get("ingestion", {}).get("packet_capture", {})
        if capture_config.get("enabled", True):
            self.packet_capture = PacketCapture(
                interface=capture_config.get("interface", "eth0"),
                backend=capture_config.get("backend", "auto"),
                promiscuous=capture_config.get("promiscuous", True),
                snaplen=capture_config.get("snaplen", 1518),
                buffer_size=capture_config.get("buffer_size", 2097152),
                filter=capture_config.get("filter", ""),
                producer=self.producer,
            )
            # Packet capture runs its own tasks; we'll start it as an async task
            capture_task = asyncio.create_task(self.packet_capture.start())
            self._tasks.append(capture_task)
            logger.info("Packet capture started", interface=capture_config.get("interface"))

        # Start flow collector if enabled
        flow_config = self.config.get("ingestion", {}).get("flow_collector", {})
        if flow_config.get("enabled", False):
            self.flow_collector = FlowCollector(
                listen_host=flow_config.get("listen_host", "0.0.0.0"),
                listen_port=flow_config.get("listen_port", 2055),
                protocol=flow_config.get("protocol", "udp"),
                collector_type=flow_config.get("collector_type", "netflow"),
                producer=self.producer,
                buffer_size=flow_config.get("buffer_size", 65536),
            )
            flow_task = asyncio.create_task(self.flow_collector.start())
            self._tasks.append(flow_task)
            logger.info("Flow collector started", port=flow_config.get("listen_port"))

        # Start gNMI telemetry if enabled
        gnmi_config = self.config.get("ingestion", {}).get("gnmi", {})
        if gnmi_config.get("enabled", False):
            self.telemetry_grpc = TelemetryGRPC(
                target_host=gnmi_config.get("target_host"),
                target_port=gnmi_config.get("target_port", 9339),
                username=gnmi_config.get("username"),
                password=gnmi_config.get("password"),
                tls=gnmi_config.get("tls", True),
                ca_cert=gnmi_config.get("ca_cert"),
                producer=self.producer,
                subscribe_paths=gnmi_config.get("subscribe_paths", []),
                sample_interval_ms=gnmi_config.get("sample_interval_ms", 1000),
            )
            gnmi_task = asyncio.create_task(self.telemetry_grpc.start())
            self._tasks.append(gnmi_task)
            logger.info("gNMI telemetry started", target=gnmi_config.get("target_host"))

        # Wait for all tasks
        try:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        except asyncio.CancelledError:
            logger.info("Ingestion tasks cancelled")
        except Exception as e:
            logger.exception("Unexpected error in ingestion tasks", error=str(e))

    async def stop(self):
        """Stop all ingestion components."""
        if not self._running:
            return

        logger.info("Stopping ingestion service")
        self._running = False

        # Cancel tasks
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)

        # Stop components
        if self.packet_capture:
            await self.packet_capture.stop()
        if self.flow_collector:
            await self.flow_collector.stop()
        if self.telemetry_grpc:
            await self.telemetry_grpc.stop()
        if self.producer:
            await self.producer.stop()

        logger.info("Ingestion service stopped")


async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="DDoS Defense Platform - Ingestion Service")
    parser.add_argument("--config", default="config/default.yaml", help="Configuration file path")
    parser.add_argument("--env", choices=["dev", "prod"], default="dev", help="Environment")
    args = parser.parse_args()

    # Load configuration
    config = load_config(args.config, env=args.env)

    # Setup logging
    setup_logging(level=config.get("log_level", "INFO"))

    service = IngestionService(config)

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
        logger.info("Ingestion service exiting")


if __name__ == "__main__":
    asyncio.run(main())
