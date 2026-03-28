from __future__ import annotations

"""High-performance packet capture module.

This module provides packet capture capabilities using multiple backends
(scapy, pcapy, or PF_RING) for optimal performance. Captured packets are
processed and forwarded to Kafka for further analysis.
"""

import asyncio
import ipaddress
import os
import signal
import threading
import time
from typing import Optional, Callable, Dict, Any
from collections import deque
import multiprocessing as mp

import structlog
from kafka import KafkaProducer
import numpy as np

try:
    import pcapy
except ImportError:
    pcapy = None

try:
    import dpkt
except ImportError:
    dpkt = None

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
    from scapy.packet import Packet
except ImportError:
    sniff = None

try:
    from pfring import PfRing
except ImportError:
    PfRing = None

from ..common.logging import get_logger
from ..common.metrics import metrics
from .kafka_producer import TelemetryProducer

logger = get_logger(__name__)


class PacketCapture:
    """High-performance packet capture engine."""

    def __init__(
        self,
        interface: str = "eth0",
        backend: str = "auto",  # auto, scapy, pcapy, pfring
        promiscuous: bool = True,
        snaplen: int = 1518,
        buffer_size: int = 2_097_152,  # 2MB
        timeout_ms: int = 1000,
        filter: str = "",
        producer: Optional[TelemetryProducer] = None,
        max_queue_size: int = 10000,
        output_topic: str = "telemetry.raw",
    ):
        """Initialize packet capture.

        Args:
            interface: Network interface to capture from.
            backend: Capture backend (auto, scapy, pcapy, pfring).
            promiscuous: Enable promiscuous mode.
            snaplen: Maximum packet capture length.
            buffer_size: Capture buffer size in bytes.
            timeout_ms: Capture timeout in milliseconds.
            filter: BPF filter string.
            producer: Kafka producer instance.
            max_queue_size: Maximum size of internal queue.
        """
        self.interface = interface
        self.backend = backend
        self.promiscuous = promiscuous
        self.snaplen = snaplen
        self.buffer_size = buffer_size
        self.timeout_ms = timeout_ms
        self.filter = filter
        self._owns_producer = producer is None
        self.producer = producer or TelemetryProducer()
        self.max_queue_size = max_queue_size
        self.output_topic = output_topic

        self._running = False
        self._capture_thread: Optional[threading.Thread] = None
        self._stats = {
            "packets_processed": 0,
            "packets_dropped": 0,
            "errors": 0,
            "start_time": None,
        }
        self._queue = deque(maxlen=max_queue_size)
        self._queue_lock = threading.Lock()

        self._pcap = None
        self._pfring = None

    def _select_backend(self) -> str:
        """Select the best available backend."""
        if self.backend != "auto":
            return self.backend

        if PfRing is not None:
            return "pfring"
        elif pcapy is not None:
            return "pcapy"
        elif sniff is not None:
            return "scapy"
        else:
            raise RuntimeError("No suitable packet capture backend found")

    def _init_pcapy(self):
        """Initialize pcapy backend."""
        try:
            self._pcap = pcapy.open_live(
                self.interface,
                self.snaplen,
                self.promiscuous,
                self.timeout_ms,
            )
            if self.buffer_size:
                self._pcap.setbuff(self.buffer_size)
            if self.filter:
                self._pcap.setfilter(self.filter)
            logger.info("pcapy initialized", interface=self.interface)
            return True
        except Exception as e:
            logger.error("Failed to initialize pcapy", error=str(e))
            return False

    def _init_pfring(self):
        """Initialize PF_RING backend."""
        try:
            self._pfring = PfRing(
                self.interface,
                self.buffer_size,
                snaplen=self.snaplen,
                promisc=self.promiscuous,
            )
            if self.filter:
                self._pfring.set_filter(self.filter)
            logger.info("PF_RING initialized", interface=self.interface)
            return True
        except Exception as e:
            logger.error("Failed to initialize PF_RING", error=str(e))
            return False

    def _process_packet_scapy(self, packet: Packet):
        """Process packet from scapy."""
        try:
            # Convert to bytes for consistency
            raw_bytes = bytes(packet)
            self._process_raw_packet(raw_bytes)
        except Exception as e:
            logger.debug("Error processing packet", error=str(e))
            self._stats["errors"] += 1

    def _process_packet_pcapy(self, header: Any, data: bytes):
        """Process packet from pcapy."""
        try:
            self._process_raw_packet(data)
        except Exception as e:
            logger.debug("Error processing packet", error=str(e))
            self._stats["errors"] += 1

    def _process_raw_packet(self, data: bytes):
        """Extract features and forward to queue."""
        self._stats["packets_processed"] += 1
        metrics.packets_total.inc()

        # Basic packet features
        try:
            eth = dpkt.ethernet.Ethernet(data)
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                return

            proto = ip.p
            src_ip = str(ipaddress.ip_address(ip.src))
            dst_ip = str(ipaddress.ip_address(ip.dst))
            src_port = None
            dst_port = None

            # TCP/UDP
            if proto in (dpkt.ip.IP_PROTO_TCP, dpkt.ip.IP_PROTO_UDP):
                transport = ip.data
                src_port = transport.sport
                dst_port = transport.dport

            # Build packet metadata
            packet_info = {
                "timestamp": time.time(),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": proto,
                "src_port": src_port,
                "dst_port": dst_port,
                "length": len(data),
                "payload": data.hex() if len(data) <= 128 else None,  # limit size
            }

            # Add to queue for async processing
            with self._queue_lock:
                self._queue.append(packet_info)

        except Exception as e:
            logger.debug("Error parsing packet", error=str(e))
            self._stats["errors"] += 1

    def _capture_pcapy(self):
        """Capture loop using pcapy."""
        logger.info("Starting pcapy capture", interface=self.interface)
        try:
            # pcapy.loop() calls callback for each packet
            self._pcap.loop(
                -1,  # infinite
                self._process_packet_pcapy,
            )
        except Exception as e:
            logger.error("pcapy capture error", error=str(e))
            self._stats["errors"] += 1
        finally:
            self._running = False

    def _capture_pfring(self):
        """Capture loop using PF_RING."""
        logger.info("Starting PF_RING capture", interface=self.interface)
        try:
            while self._running:
                # PF_RING returns packet data
                ret, packet = self._pfring.recv()
                if ret > 0 and packet:
                    self._process_raw_packet(packet)
                elif ret < 0:
                    logger.warning("PF_RING recv error", code=ret)
        except Exception as e:
            logger.error("PF_RING capture error", error=str(e))
            self._stats["errors"] += 1
        finally:
            self._running = False

    def _capture_scapy(self):
        """Capture loop using scapy."""
        logger.info("Starting scapy capture", interface=self.interface)
        try:
            sniff(
                iface=self.interface,
                prn=self._process_packet_scapy,
                store=False,
                filter=self.filter,
                timeout=None,  # run until stopped
                stop_filter=lambda x: not self._running,
            )
        except Exception as e:
            logger.error("scapy capture error", error=str(e))
            self._stats["errors"] += 1
        finally:
            self._running = False

    def _capture_worker(self):
        """Main capture worker thread."""
        backend = self._select_backend()
        logger.info("Starting packet capture", backend=backend, interface=self.interface)

        self._stats["start_time"] = time.time()

        if backend == "pcapy":
            if not self._init_pcapy():
                logger.error("pcapy initialization failed, falling back to scapy")
                backend = "scapy"
        elif backend == "pfring":
            if not self._init_pfring():
                logger.error("PF_RING initialization failed, falling back to pcapy")
                backend = "pcapy"
                if not self._init_pcapy():
                    backend = "scapy"

        if backend == "pcapy":
            self._capture_pcapy()
        elif backend == "pfring":
            self._capture_pfring()
        elif backend == "scapy":
            self._capture_scapy()
        else:
            raise RuntimeError("No suitable capture backend")

    async def _producer_worker(self):
        """Async worker to send packets to Kafka."""
        batch = []
        batch_size = 100  # configurable
        while self._running:
            # Collect a batch from queue
            with self._queue_lock:
                while self._queue and len(batch) < batch_size:
                    batch.append(self._queue.popleft())

            if batch:
                # Send batch to Kafka
                try:
                    await self.producer.send_batch(
                        topic=self.output_topic,
                        messages=batch,
                    )
                except Exception as e:
                    logger.error("Failed to send batch to Kafka", error=str(e))
                    # Put packets back? For now just drop.
                    self._stats["packets_dropped"] += len(batch)
                batch.clear()

            # Wait a bit before next batch
            await asyncio.sleep(0.01)

    async def start(self):
        """Start packet capture and Kafka producer."""
        if self._running:
            logger.warning("Capture already running")
            return

        self._running = True

        # Start capture thread
        self._capture_thread = threading.Thread(target=self._capture_worker, daemon=True)
        self._capture_thread.start()

        # Start async producer worker
        producer_task = asyncio.create_task(self._producer_worker())

        try:
            await producer_task
        except asyncio.CancelledError:
            logger.info("Producer worker cancelled")
        finally:
            await self.stop()

    async def stop(self):
        """Stop packet capture."""
        if not self._running:
            return

        logger.info("Stopping packet capture")
        self._running = False

        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=5.0)

        if self._pcap:
            self._pcap.close()
        if self._pfring:
            self._pfring.close()

        if self._owns_producer:
            await self.producer.stop()

    def get_stats(self) -> Dict[str, Any]:
        """Get capture statistics."""
        stats = self._stats.copy()
        if stats["start_time"]:
            stats["uptime_seconds"] = time.time() - stats["start_time"]
        return stats


def main():
    """Entry point for testing."""
    import asyncio
    import sys

    if len(sys.argv) < 2:
        print("Usage: python packet_capture.py <interface>")
        sys.exit(1)

    interface = sys.argv[1]
    capture = PacketCapture(interface=interface)

    async def run():
        await capture.start()
        try:
            while True:
                await asyncio.sleep(1)
                stats = capture.get_stats()
                print(f"Packets: {stats['packets_processed']}, "
                      f"Dropped: {stats['packets_dropped']}, "
                      f"Errors: {stats['errors']}")
        except KeyboardInterrupt:
            await capture.stop()

    asyncio.run(run())


if __name__ == "__main__":
    main()
