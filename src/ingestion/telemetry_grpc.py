from __future__ import annotations

"""gNMI telemetry streaming module.

This module provides gRPC-based telemetry collection from network devices
using gNMI (gRPC Network Management Interface) for streaming telemetry.
"""

import asyncio
import threading
import time
from typing import Optional, Dict, Any, List, Callable
from concurrent.futures import ThreadPoolExecutor

import structlog
import grpc

# gNMI proto imports (must be generated from .proto files)
# For this example, we assume the generated modules are available
# If not, this code will demonstrate the structure.
try:
    import gnmi_pb2
    import gnmi_pb2_grpc
    GNMI_AVAILABLE = True
except ImportError:
    GNMI_AVAILABLE = False
    # Stub for demonstration
    class gnmi_pb2: pass
    class gnmi_pb2_grpc: pass

from ..common.logging import get_logger
from ..common.metrics import metrics
from .kafka_producer import TelemetryProducer

logger = get_logger(__name__)


class TelemetryGRPC:
    """gNMI telemetry client for streaming from network devices."""

    def __init__(
        self,
        target_host: str,
        target_port: int = 9339,
        username: Optional[str] = None,
        password: Optional[str] = None,
        tls: bool = True,
        ca_cert: Optional[str] = None,
        producer: Optional[TelemetryProducer] = None,
        subscribe_paths: Optional[List[str]] = None,
        sample_interval_ms: int = 1000,
        output_topic: str = "telemetry.raw",
    ):
        """Initialize gNMI telemetry client.

        Args:
            target_host: Network device IP/hostname.
            target_port: gNMI port (default 9339).
            username: Username for authentication (optional).
            password: Password for authentication (optional).
            tls: Enable TLS encryption.
            ca_cert: Path to CA certificate for TLS.
            producer: Kafka producer instance.
            subscribe_paths: List of gNMI paths to subscribe to.
            sample_interval_ms: Sampling interval in milliseconds.
        """
        if not GNMI_AVAILABLE:
            raise ImportError("gNMI proto modules not available")

        self.target_host = target_host
        self.target_port = target_port
        self.username = username
        self.password = password
        self.tls = tls
        self.ca_cert = ca_cert
        self._owns_producer = producer is None
        self.producer = producer or TelemetryProducer()
        self.output_topic = output_topic
        self.subscribe_paths = subscribe_paths or [
            "/interfaces/interface/state/counters",
            "/components/component/state",
            "/system/memory/state",
            "/system/cpu/state",
        ]
        self.sample_interval_ms = sample_interval_ms

        self._running = False
        self._channel: Optional[grpc.Channel] = None
        self._stub: Optional[gnmi_pb2_grpc.gNMIStub] = None
        self._stats = {
            "updates_received": 0,
            "errors": 0,
            "start_time": None,
        }

    def _create_channel(self) -> grpc.Channel:
        """Create gRPC channel with optional TLS."""
        target = f"{self.target_host}:{self.target_port}"
        if self.tls:
            if self.ca_cert:
                with open(self.ca_cert, 'rb') as f:
                    creds = grpc.ssl_channel_credentials(f.read())
            else:
                creds = grpc.ssl_channel_credentials()
            return grpc.secure_channel(target, creds)
        else:
            return grpc.insecure_channel(target)

    def _create_credentials(self) -> Optional[grpc.CallCredentials]:
        """Create authentication credentials if provided."""
        if self.username and self.password:
            # Use metadata for basic auth
            def auth_callback(context):
                context.set_auth_metadata((
                    ('username', self.username),
                    ('password', self.password),
                ))
            return grpc.metadata_call_credentials(auth_callback)
        return None

    def _build_subscription_list(self) -> gnmi_pb2.SubscriptionList:
        """Build gNMI subscription list from configured paths."""
        subscriptions = []
        for path_str in self.subscribe_paths:
            # Parse path string into proto (simplified)
            # In real implementation, use path parsing library
            path = gnmi_pb2.Path()
            # Simulate parsing: split by '/'
            if path_str == "/":
                elem = gnmi_pb2.PathElem(name="")
                path.elem.append(elem)
            else:
                for elem in path_str.strip('/').split('/'):
                    if elem:
                        path.elem.append(gnmi_pb2.PathElem(name=elem))
            subscription = gnmi_pb2.Subscription(
                path=path,
                mode=gnmi_pb2.SubscriptionMode.SAMPLE,
                sample_interval=self.sample_interval_ms * 1000000,  # nanoseconds
            )
            subscriptions.append(subscription)

        return gnmi_pb2.SubscriptionList(
            subscription=subscriptions,
            mode=gnmi_pb2.SubscriptionListMode.STREAM,
            qos=gnmi_pb2.QOSMarking(),
            use_aliases=False,
        )

    def _process_update(self, update: gnmi_pb2.Notification):
        """Process a single telemetry update."""
        try:
            timestamp = update.timestamp / 1e9  # convert to seconds
            for update_msg in update.update:
                # Extract value and path
                path_str = self._path_to_str(update_msg.path)
                value = self._value_to_json(update_msg.val)

                telemetry_data = {
                    "timestamp": timestamp,
                    "source": self.target_host,
                    "path": path_str,
                    "value": value,
                }

                # Send to Kafka
                asyncio.create_task(
                    self.producer.send(
                        topic=self.output_topic,
                        message=telemetry_data,
                    )
                )

            self._stats["updates_received"] += 1
            metrics.telemetry_updates_total.inc()

        except Exception as e:
            logger.error("Error processing gNMI update", error=str(e))
            self._stats["errors"] += 1

    def _path_to_str(self, path: gnmi_pb2.Path) -> str:
        """Convert gNMI Path to string."""
        if path.elem:
            return "/" + "/".join(elem.name for elem in path.elem)
        return "/"

    def _value_to_json(self, val: gnmi_pb2.TypedValue) -> Any:
        """Convert gNMI TypedValue to Python native type."""
        # Map gNMI value to JSON-serializable
        if val.HasField("json_val"):
            return val.json_val
        elif val.HasField("json_ietf_val"):
            return val.json_ietf_val
        elif val.HasField("ascii_val"):
            return val.ascii_val
        elif val.HasField("string_val"):
            return val.string_val
        elif val.HasField("int_val"):
            return val.int_val
        elif val.HasField("uint_val"):
            return val.uint_val
        elif val.HasField("bool_val"):
            return val.bool_val
        elif val.HasField("bytes_val"):
            return val.bytes_val.hex()
        elif val.HasField("float_val"):
            return val.float_val
        elif val.HasField("decimal_val"):
            return {"digits": val.decimal_val.digits, "precision": val.decimal_val.precision}
        elif val.HasField("leaflist_val"):
            return [self._value_to_json(v) for v in val.leaflist_val.element]
        else:
            return None

    def _stream_updates(self):
        """Stream updates from gNMI subscribe."""
        try:
            # Create subscription request
            sub_list = self._build_subscription_list()
            request = gnmi_pb2.SubscribeRequest(
                subscribe=sub_list
            )

            # Open stream
            stream = self._stub.Subscribe(iter([request]), metadata=self._auth_metadata())

            for response in stream:
                if response.HasField("update"):
                    self._process_update(response.update)
                elif response.HasField("sync_response"):
                    logger.info("gNMI sync response received")
                elif response.HasField("error"):
                    logger.error("gNMI error response", message=response.error.message)
        except grpc.RpcError as e:
            logger.error("gNMI stream RPC error", code=e.code(), details=e.details())
            self._stats["errors"] += 1
        except Exception as e:
            logger.error("Unexpected error in gNMI stream", error=str(e))
            self._stats["errors"] += 1

    def _auth_metadata(self):
        """Return authentication metadata for gRPC call."""
        if self.username and self.password:
            return [('username', self.username), ('password', self.password)]
        return []

    async def start(self):
        """Start gNMI telemetry streaming."""
        if not GNMI_AVAILABLE:
            logger.error("gNMI not available - install grpc and generate protos")
            return

        if self._running:
            logger.warning("Telemetry streaming already running")
            return

        self._running = True
        self._stats["start_time"] = time.time()

        logger.info("Starting gNMI telemetry stream", target=self.target_host, port=self.target_port)

        # Create channel and stub
        self._channel = self._create_channel()
        if self._channel is None:
            logger.error("Failed to create gRPC channel")
            return

        # Add authentication if present
        if self.username and self.password:
            call_creds = self._create_credentials()
            if call_creds:
                self._channel = grpc.intercept_channel(self._channel, call_creds)

        self._stub = gnmi_pb2_grpc.gNMIStub(self._channel)

        # Run streaming in thread to avoid blocking asyncio
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._stream_updates)

    async def stop(self):
        """Stop telemetry streaming."""
        if not self._running:
            return
        self._running = False
        if self._channel:
            self._channel.close()
        if self._owns_producer:
            await self.producer.stop()
        logger.info("gNMI telemetry stopped")

    def get_stats(self) -> Dict[str, Any]:
        """Get collector statistics."""
        stats = self._stats.copy()
        if stats["start_time"]:
            stats["uptime_seconds"] = time.time() - stats["start_time"]
        return stats


def main():
    """Entry point for testing."""
    import asyncio
    import sys

    if len(sys.argv) < 2:
        print("Usage: python telemetry_grpc.py <device_host> [port]")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 9339

    telemetry = TelemetryGRPC(
        target_host=host,
        target_port=port,
        tls=False,  # for testing
        subscribe_paths=[
            "/interfaces/interface/state/counters",
        ],
    )

    async def run():
        await telemetry.start()
        try:
            while True:
                await asyncio.sleep(5)
                stats = telemetry.get_stats()
                print(f"Updates: {stats['updates_received']}, Errors: {stats['errors']}")
        except KeyboardInterrupt:
            await telemetry.stop()

    asyncio.run(run())


if __name__ == "__main__":
    main()
