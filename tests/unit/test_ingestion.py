"""Unit tests for ingestion components."""

import pytest
import asyncio
import time
from unittest.mock import Mock, AsyncMock, patch, MagicMock

from src.ingestion.packet_capture import PacketCapture
from src.ingestion.flow_collector import FlowCollector
from src.ingestion.telemetry_grpc import TelemetryGRPC
from src.ingestion.kafka_producer import TelemetryProducer


@pytest.mark.asyncio
class TestPacketCapture:
    """Test packet capture module."""

    @pytest.fixture
    def capture(self):
        return PacketCapture(
            interface="lo",
            backend="scapy",  # Use scapy for testing (no real capture)
            promiscuous=False,
            producer=Mock(spec=TelemetryProducer),
        )

    async def test_initialization(self, capture):
        assert capture.interface == "lo"
        assert capture.backend == "scapy"
        assert capture._running is False

    @patch("src.ingestion.packet_capture.sniff")
    async def test_start_stop(self, mock_sniff, capture):
        # Mock sniff to run a short time
        def stop_filter(x):
            return not capture._running

        mock_sniff.side_effect = lambda iface, prn, store, filter, stop_filter: None

        # Start capture (will run in thread)
        task = asyncio.create_task(capture.start())
        await asyncio.sleep(0.1)
        await capture.stop()
        task.cancel()
        await task

        assert capture._running is False
        assert capture.get_stats()["packets_processed"] == 0

    def test_select_backend(self, capture):
        # With backend forced to scapy, should return scapy
        assert capture._select_backend() == "scapy"

    def test_process_raw_packet(self, capture):
        # Mock a simple Ethernet/IP/TCP packet
        # Construct dummy bytes
        import dpkt
        eth = dpkt.ethernet.Ethernet()
        ip = dpkt.ip.IP(src="\xc0\xa8\x01\x01", dst="\x0a\x00\x00\x01")  # 192.168.1.1 -> 10.0.0.1
        tcp = dpkt.tcp.TCP(sport=12345, dport=80)
        ip.data = tcp
        eth.data = ip
        data = bytes(eth)

        capture._process_raw_packet(data)
        assert capture._stats["packets_processed"] == 1
        with capture._queue_lock:
            assert len(capture._queue) == 1
            packet_info = capture._queue[0]
            assert packet_info["src_ip"] == "192.168.1.1"
            assert packet_info["dst_ip"] == "10.0.0.1"
            assert packet_info["protocol"] == dpkt.ip.IP_PROTO_TCP
            assert packet_info["src_port"] == 12345
            assert packet_info["dst_port"] == 80


@pytest.mark.asyncio
class TestFlowCollector:
    """Test flow collector module."""

    @pytest.fixture
    def collector(self):
        return FlowCollector(
            listen_host="127.0.0.1",
            listen_port=2055,
            protocol="udp",
            collector_type="netflow",
            producer=Mock(spec=TelemetryProducer),
        )

    def test_initialization(self, collector):
        assert collector.listen_host == "127.0.0.1"
        assert collector.listen_port == 2055
        assert collector.collector_type == "netflow"

    def test_get_field_name(self, collector):
        assert collector._get_field_name(8) == "src_ip"
        assert collector._get_field_name(12) == "dst_ip"
        assert collector._get_field_name(999) == "field_999"

    def test_decode_field(self, collector):
        raw = b"\xc0\xa8\x01\x01"
        value = collector._decode_field(raw, 8)  # src_ip
        assert value == "192.168.1.1"

        raw = b"\x00\x50"  # port 80
        value = collector._decode_field(raw, 7)  # src_port
        assert value == 80

    async def test_send_flows(self, collector):
        flows = [{"test": "flow1"}, {"test": "flow2"}]
        collector.producer.send_batch = AsyncMock()
        await collector._send_flows(flows)
        collector.producer.send_batch.assert_called_once_with(
            topic="telemetry.flows",
            messages=flows,
        )


@pytest.mark.asyncio
class TestTelemetryGRPC:
    """Test gNMI telemetry client."""

    @pytest.fixture
    def telemetry(self):
        if not getattr(__import__("src.ingestion.telemetry_grpc", fromlist=["GNMI_AVAILABLE"]), "GNMI_AVAILABLE"):
            pytest.skip("gNMI proto modules not available in test environment")
        return TelemetryGRPC(
            target_host="localhost",
            target_port=9339,
            tls=False,
            producer=Mock(spec=TelemetryProducer),
        )

    def test_path_to_str(self, telemetry):
        # Mock path
        class Path:
            elem = [Mock(name="interfaces"), Mock(name="interface")]
        path = Path()
        path.elem[0].name = "interfaces"
        path.elem[1].name = "interface"
        assert telemetry._path_to_str(path) == "/interfaces/interface"

    def test_build_subscription_list(self, telemetry):
        sub_list = telemetry._build_subscription_list()
        assert sub_list.mode == 0  # STREAM
        assert len(sub_list.subscription) == len(telemetry.subscribe_paths)


@pytest.mark.asyncio
class TestTelemetryProducer:
    """Test Kafka producer helper."""

    @pytest.fixture
    def producer(self):
        return TelemetryProducer(
            bootstrap_servers=["localhost:9092"],
            batch_size=10,
            batch_timeout_ms=100,
        )

    async def test_start_stop(self, producer):
        # Mock internal sync producer
        producer._init_sync_producer = MagicMock()
        producer._init_sync_producer.return_value = None
        await producer.start()
        assert producer._running is True
        await producer.stop()
        assert producer._running is False

    async def test_send(self, producer):
        producer._init_sync_producer = MagicMock()
        producer._producer = MagicMock()
        await producer.start()
        await producer.send(message={"test": "data"})
        # Queue should have one item
        assert len(producer._queue) == 1
        await producer.stop()

    async def test_flush(self, producer):
        producer._init_sync_producer = MagicMock()
        producer._producer = MagicMock()
        producer._producer.send = MagicMock(return_value=MagicMock())
        await producer.start()
        await producer.send(message={"test": 1})
        await producer.flush()
        assert len(producer._queue) == 0
        assert producer._stats["messages_sent"] == 1
        await producer.stop()
