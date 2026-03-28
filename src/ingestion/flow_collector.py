"""NetFlow/sFlow collector module.

This module implements a high-performance flow collector supporting:
- NetFlow v5, v9, IPFIX
- sFlow v5
- Configurable export to Kafka for further analysis
"""

import asyncio
import socket
import struct
import threading
import time
from typing import Optional, Dict, Any, List, Tuple
from collections import defaultdict
import ipaddress

import structlog
from kafka import KafkaProducer

try:
    from nfstream import NFStreamer, NFPlugin
except ImportError:
    NFStreamer = None
    NFPlugin = None

from ..common.logging import get_logger
from ..common.metrics import metrics
from .kafka_producer import TelemetryProducer

logger = get_logger(__name__)


# NetFlow v5 header format
NETFLOW_V5_HEADER_FMT = ">HHIIIIIIHHII"
NETFLOW_V5_RECORD_FMT = ">IIIIHHIIII"

# NetFlow v9/IPFIX templates
class FlowCollector:
    """High-performance flow collector for NetFlow/sFlow."""

    def __init__(
        self,
        listen_host: str = "0.0.0.0",
        listen_port: int = 2055,
        protocol: str = "udp",  # udp, tcp
        collector_type: str = "netflow",  # netflow, sflow, nfstream
        producer: Optional[TelemetryProducer] = None,
        buffer_size: int = 65536,
        output_topic: str = "telemetry.flows",
    ):
        """Initialize flow collector.

        Args:
            listen_host: Interface to listen on.
            listen_port: UDP/TCP port for flow export.
            protocol: Transport protocol (udp/tcp).
            collector_type: Type of collector (netflow, sflow, nfstream).
            producer: Kafka producer instance.
            buffer_size: Socket receive buffer size.
        """
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.protocol = protocol
        self.collector_type = collector_type
        self._owns_producer = producer is None
        self.producer = producer or TelemetryProducer()
        self.buffer_size = buffer_size
        self.output_topic = output_topic

        self._running = False
        self._sock: Optional[socket.socket] = None
        self._stats = {
            "flows_received": 0,
            "packets_received": 0,
            "errors": 0,
            "start_time": None,
        }

        # Template cache for NetFlow v9/IPFIX
        self._templates: Dict[int, Dict[str, Any]] = {}

        # sFlow sample cache
        self._sflow_samples: Dict[str, Any] = {}

        # NFStream plugin (if used)
        self._nfstream = None

    async def _handle_netflow_packet(self, data: bytes, addr: Tuple[str, int]):
        """Parse and handle NetFlow v5/v9/IPFIX packets."""
        if len(data) < 4:
            return

        version = struct.unpack(">H", data[0:2])[0]

        if version == 5:
            await self._parse_netflow_v5(data, addr)
        elif version == 9:
            await self._parse_netflow_v9(data, addr)
        elif version == 10:  # IPFIX
            await self._parse_ipfix(data, addr)
        else:
            logger.debug("Unknown NetFlow version", version=version)

    async def _parse_netflow_v5(self, data: bytes, addr: Tuple[str, int]):
        """Parse NetFlow v5 packet."""
        # Header
        header_size = struct.calcsize(NETFLOW_V5_HEADER_FMT)
        if len(data) < header_size:
            return

        header = struct.unpack(NETFLOW_V5_HEADER_FMT, data[:header_size])
        # version, count, sys_uptime, unix_secs, unix_nsecs, flow_sequence, engine_type, engine_id, sampling_interval
        count = header[1]

        # Parse records
        record_size = struct.calcsize(NETFLOW_V5_RECORD_FMT)
        records = []
        for i in range(count):
            offset = header_size + i * record_size
            if offset + record_size > len(data):
                break
            record_data = data[offset:offset + record_size]
            record = struct.unpack(NETFLOW_V5_RECORD_FMT, record_data)
            # srcaddr, dstaddr, nexthop, input, output, dPkts, dOctets, First, Last, srcport, dstport, pad1, tcp_flags, prot, tos, src_as, dst_as, src_mask, dst_mask, pad2
            flow = {
                "version": 5,
                "exporter_ip": addr[0],
                "timestamp": time.time(),
                "src_ip": socket.inet_ntoa(struct.pack("!I", record[0])),
                "dst_ip": socket.inet_ntoa(struct.pack("!I", record[1])),
                "next_hop": socket.inet_ntoa(struct.pack("!I", record[2])),
                "input_iface": record[3],
                "output_iface": record[4],
                "packets": record[5],
                "bytes": record[6],
                "first_seen": header[3] + record[7] / 1000.0,  # approximate
                "last_seen": header[3] + record[8] / 1000.0,
                "src_port": record[9],
                "dst_port": record[10],
                "tcp_flags": record[12],
                "protocol": record[13],
                "tos": record[14],
                "src_as": record[15],
                "dst_as": record[16],
                "src_mask": record[17],
                "dst_mask": record[18],
            }
            records.append(flow)

        # Send to Kafka
        await self._send_flows(records)
        self._stats["flows_received"] += len(records)
        self._stats["packets_received"] += 1

    async def _parse_netflow_v9(self, data: bytes, addr: Tuple[str, int]):
        """Parse NetFlow v9 packet."""
        # Basic header
        # Version (2 bytes), Count (2 bytes), SysUptime (4), UnixSecs (4), Sequence (4), SourceID (4)
        if len(data) < 20:
            return

        version, count, sys_uptime, unix_secs, seq, source_id = struct.unpack(">HHIIII", data[:20])
        offset = 20

        flows = []
        for _ in range(count):
            if offset + 4 > len(data):
                break
            flowset_id, flowset_length = struct.unpack(">HH", data[offset:offset+4])
            offset += 4
            if flowset_length < 4:
                continue

            if flowset_id == 0:  # Template flowset
                # Parse templates
                self._parse_v9_template(data, offset, flowset_length - 4)
            elif flowset_id == 1:  # Options template
                pass  # skip for now
            else:  # Data flowset
                template_id = flowset_id
                if template_id in self._templates:
                    template = self._templates[template_id]
                    record_size = sum(field["length"] for field in template["fields"])
                    num_records = (flowset_length - 4) // record_size
                    for i in range(num_records):
                        record_offset = offset + i * record_size
                        if record_offset + record_size > len(data):
                            break
                        flow = self._parse_v9_data(data[record_offset:record_offset+record_size], template, unix_secs, addr)
                        if flow:
                            flows.append(flow)
            offset += flowset_length - 4

        if flows:
            await self._send_flows(flows)
            self._stats["flows_received"] += len(flows)
            self._stats["packets_received"] += 1

    def _parse_v9_template(self, data: bytes, offset: int, length: int):
        """Parse NetFlow v9 template."""
        if length < 4:
            return
        template_id, field_count = struct.unpack(">HH", data[offset:offset+4])
        offset += 4
        fields = []
        for _ in range(field_count):
            if offset + 4 > len(data):
                break
            field_type, field_length = struct.unpack(">HH", data[offset:offset+4])
            offset += 4
            fields.append({
                "type": field_type,
                "length": field_length,
                "name": self._get_field_name(field_type),
            })
        self._templates[template_id] = {
            "id": template_id,
            "fields": fields,
        }

    def _parse_v9_data(self, data: bytes, template: Dict, unix_secs: int, exporter_addr: Tuple[str, int]) -> Optional[Dict]:
        """Parse NetFlow v9 data record."""
        flow = {
            "version": 9,
            "exporter_ip": exporter_addr[0],
            "timestamp": time.time(),
            "first_seen": unix_secs,
            "last_seen": unix_secs,
        }
        offset = 0
        for field in template["fields"]:
            if offset + field["length"] > len(data):
                break
            raw = data[offset:offset+field["length"]]
            value = self._decode_field(raw, field["type"])
            flow[field["name"]] = value
            offset += field["length"]
        return flow

    async def _parse_ipfix(self, data: bytes, addr: Tuple[str, int]):
        """Parse IPFIX packet (simplified)."""
        # IPFIX uses same structure as NetFlow v9 but with different field types
        # For simplicity, we'll reuse v9 parsing (field types differ, but we handle known ones)
        await self._parse_netflow_v9(data, addr)

    async def _parse_sflow_packet(self, data: bytes, addr: Tuple[str, int]):
        """Parse sFlow v5 packet."""
        # sFlow header: version (4 bytes), agent IP (4), sub_agent_id (4), datagram_seq (4), uptime (4), samples (4)
        if len(data) < 24:
            return
        version = struct.unpack(">I", data[:4])[0]
        if version != 5:
            return

        agent_ip = socket.inet_ntoa(data[4:8])
        sub_agent_id = struct.unpack(">I", data[8:12])[0]
        datagram_seq = struct.unpack(">I", data[12:16])[0]
        uptime = struct.unpack(">I", data[16:20])[0]
        sample_count = struct.unpack(">I", data[20:24])[0]

        offset = 24
        flows = []
        for _ in range(sample_count):
            if offset + 4 > len(data):
                break
            sample_type = struct.unpack(">I", data[offset:offset+4])[0]
            offset += 4
            if sample_type == 1:  # flow_sample
                flow = self._parse_sflow_flow_sample(data, offset, agent_ip)
                if flow:
                    flows.append(flow)
            # skip other sample types for brevity

        if flows:
            await self._send_flows(flows)
            self._stats["flows_received"] += len(flows)
            self._stats["packets_received"] += 1

    def _parse_sflow_flow_sample(self, data: bytes, offset: int, agent_ip: str) -> Optional[Dict]:
        """Parse sFlow flow sample."""
        # Simplified: extract basic flow info
        # Format: sequence_number (4), source_id (4), sampling_rate (4), sample_pool (4), drops (4), input (4), output (4), record_count (4)
        # then records...
        if offset + 32 > len(data):
            return None
        seq, source_id, sampling_rate, sample_pool, drops, input_if, output_if, record_count = struct.unpack(">IIIIIIII", data[offset:offset+32])
        offset += 32

        flow = {
            "version": "sflow5",
            "exporter_ip": agent_ip,
            "timestamp": time.time(),
            "sampling_rate": sampling_rate,
            "input_iface": input_if,
            "output_iface": output_if,
        }

        # Parse first record (simplified: assume extended_switch or raw packet)
        # For now, we just return basic info
        return flow

    def _decode_field(self, raw: bytes, field_type: int) -> Any:
        """Decode NetFlow/IPFIX field based on type."""
        # Common field types (IANA IPFIX)
        if field_type == 8:  # sourceIPv4Address
            return socket.inet_ntoa(raw[:4])
        elif field_type == 12:  # destinationIPv4Address
            return socket.inet_ntoa(raw[:4])
        elif field_type == 7:  # sourceTransportPort
            return struct.unpack(">H", raw[:2])[0]
        elif field_type == 11:  # destinationTransportPort
            return struct.unpack(">H", raw[:2])[0]
        elif field_type == 4:  # protocolIdentifier
            return raw[0]
        elif field_type == 1:  # octetDeltaCount
            return struct.unpack(">Q", raw[:8])[0] if len(raw) >= 8 else struct.unpack(">I", raw[:4])[0]
        elif field_type == 2:  # packetDeltaCount
            return struct.unpack(">Q", raw[:8])[0] if len(raw) >= 8 else struct.unpack(">I", raw[:4])[0]
        else:
            return raw.hex()

    def _get_field_name(self, field_type: int) -> str:
        """Map field type to human-readable name."""
        mapping = {
            8: "src_ip",
            12: "dst_ip",
            7: "src_port",
            11: "dst_port",
            4: "protocol",
            1: "bytes",
            2: "packets",
            14: "tcp_flags",
            21: "first_seen",
            22: "last_seen",
        }
        return mapping.get(field_type, f"field_{field_type}")

    async def _send_flows(self, flows: List[Dict]):
        """Send flows to Kafka."""
        if not flows:
            return
        try:
            await self.producer.send_batch(
                topic=self.output_topic,
                messages=flows,
            )
            metrics.flows_total.inc(len(flows))
        except Exception as e:
            logger.error("Failed to send flows to Kafka", error=str(e))
            self._stats["errors"] += 1

    async def _udp_listener(self):
        """UDP listener for flow packets."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.buffer_size)
        self._sock.bind((self.listen_host, self.listen_port))

        logger.info("UDP flow collector listening", host=self.listen_host, port=self.listen_port)

        loop = asyncio.get_event_loop()
        while self._running:
            try:
                data, addr = await loop.sock_recv(self._sock, self.buffer_size)
                if self.collector_type == "netflow":
                    await self._handle_netflow_packet(data, addr)
                elif self.collector_type == "sflow":
                    await self._parse_sflow_packet(data, addr)
            except Exception as e:
                logger.error("Error receiving UDP packet", error=str(e))
                self._stats["errors"] += 1

    async def start(self):
        """Start the flow collector."""
        if self._running:
            logger.warning("Flow collector already running")
            return

        self._running = True
        self._stats["start_time"] = time.time()

        if self.protocol == "udp":
            await self._udp_listener()
        else:
            # TCP not implemented for brevity
            raise NotImplementedError("TCP collector not implemented")

    async def stop(self):
        """Stop the flow collector."""
        self._running = False
        if self._sock:
            self._sock.close()
        if self._owns_producer:
            await self.producer.stop()

    def get_stats(self) -> Dict[str, Any]:
        """Get collector statistics."""
        stats = self._stats.copy()
        if stats["start_time"]:
            stats["uptime_seconds"] = time.time() - stats["start_time"]
        return stats


# Alternative using nfstream for high-performance flow analysis
class NFStreamCollector:
    """Wrapper around nfstream for advanced flow analysis."""

    def __init__(self, interface: str = "eth0", producer: Optional[TelemetryProducer] = None):
        if NFStreamer is None:
            raise ImportError("nfstream not installed")
        self.interface = interface
        self.producer = producer or TelemetryProducer()
        self._running = False
        self._streamer = None

    async def start(self):
        """Start nfstream capture."""
        self._running = True
        # nfstream runs in a thread, we'll push to Kafka
        # For now, a placeholder
        pass

    async def stop(self):
        if self._owns_producer:
            await self.producer.stop()


def main():
    """Entry point for testing."""
    import asyncio
    import sys

    collector = FlowCollector(
        listen_host="0.0.0.0",
        listen_port=2055,
        protocol="udp",
        collector_type="netflow",
    )

    async def run():
        await collector.start()
        try:
            while True:
                await asyncio.sleep(5)
                stats = collector.get_stats()
                print(f"Flows: {stats['flows_received']}, Packets: {stats['packets_received']}, Errors: {stats['errors']}")
        except KeyboardInterrupt:
            await collector.stop()

    asyncio.run(run())


if __name__ == "__main__":
    main()
