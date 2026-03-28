"""Unit tests for detection components."""

import pytest
import asyncio
import time
from unittest.mock import Mock, AsyncMock, patch
from src.detection.anomaly import AnomalyDetector
from src.detection.signature import SignatureDetector
from src.detection.ml import MLDetector, FeatureExtractor
from src.detection.ensemble import EnsembleDetector, DetectorResult


@pytest.mark.asyncio
class TestAnomalyDetector:
    """Test anomaly detection."""

    @pytest.fixture
    def detector(self):
        return AnomalyDetector(
            volumetric_mbps_threshold=1000,
            volumetric_pps_threshold=500000,
            entropy_threshold=3.5,
            syn_flood_threshold=1000,
            icmp_flood_threshold=500,
            window_seconds=60,
        )

    def test_compute_entropy(self, detector):
        counts = {"a": 10, "b": 10, "c": 10}
        entropy = detector._compute_entropy(counts)
        assert round(entropy, 2) == 1.58  # log2(3)

        counts = {"a": 100}
        entropy = detector._compute_entropy(counts)
        assert entropy == 0.0

    def test_update_windows(self, detector):
        flow = {
            "timestamp": time.time(),
            "bytes": 1000,
            "packets": 10,
            "protocol": 6,
            "src_ip": "192.168.1.1",
            "dst_ip": "10.0.0.1",
            "src_port": 12345,
            "dst_port": 80,
            "tcp_flags": 0x02,  # SYN
        }
        detector._update_windows(flow)
        assert detector._bytes_per_sec[int(flow["timestamp"])] == 1000
        assert detector._packets_per_sec[int(flow["timestamp"])] == 10
        assert detector._syn_per_sec[("10.0.0.1", int(flow["timestamp"]))] == 10

    @patch("src.detection.anomaly.KafkaConsumerHelper")
    async def test_process_batch(self, mock_consumer, detector):
        detector._pending_alerts = []
        flows = [{"timestamp": time.time(), "bytes": 100, "packets": 1, "protocol": 6}]
        await detector._process_batch(flows)
        assert detector._stats["flows_processed"] == 1


@pytest.mark.asyncio
class TestMLDetector:
    """Test ML detector."""

    @pytest.fixture
    def feature_extractor(self):
        return FeatureExtractor(["bytes_per_flow", "packets_per_flow"])

    def test_feature_extractor(self, feature_extractor):
        flow = {"bytes_per_flow": 1500, "packets_per_flow": 10}
        features = feature_extractor.extract(flow)
        assert features.shape == (1, 2)
        assert features[0][0] == 1500
        assert features[0][1] == 10

    @patch("src.detection.ml.joblib.load")
    @patch("src.detection.ml.KafkaConsumerHelper")
    async def test_load_model(self, mock_consumer, mock_load, detector):
        # Skipped: would need actual model
        pass


@pytest.mark.asyncio
class TestEnsembleDetector:
    """Test ensemble detector."""

    @pytest.fixture
    def detector(self):
        return EnsembleDetector(
            weights={"signature": 0.2, "anomaly": 0.4, "ml": 0.4},
            alert_threshold=0.6,
            window_seconds=10,
            min_votes=2,
            voting="weighted",
        )

    def test_calculate_weighted_score(self, detector):
        results = [
            DetectorResult("signature", {"type": "test"}, 0.5, time.time(), 2),
            DetectorResult("anomaly", {"type": "test"}, 0.8, time.time(), 3),
            DetectorResult("ml", {"type": "test"}, 0.9, time.time(), 4),
        ]
        score = detector._calculate_weighted_score(results)
        # (0.2*0.5 + 0.4*0.8 + 0.4*0.9) / (0.2+0.4+0.4) = (0.1+0.32+0.36)/1 = 0.78
        assert round(score, 2) == 0.78

    def test_majority_vote(self, detector):
        results = [
            DetectorResult("sig", {}, 0.6, time.time(), 2),
            DetectorResult("anom", {}, 0.7, time.time(), 3),
            DetectorResult("ml", {}, 0.4, time.time(), 4),
        ]
        is_attack, conf = detector._majority_vote(results)
        assert is_attack is True  # 2 out of 3 agree (confidence >= 0.5)
        assert round(conf, 2) == 0.67

    def test_consensus(self, detector):
        results = [
            DetectorResult("sig", {}, 0.8, time.time(), 2),
            DetectorResult("anom", {}, 0.9, time.time(), 3),
        ]
        is_attack, conf = detector._consensus(results)
        assert is_attack is True
        assert conf == 1.0

        results.append(DetectorResult("ml", {}, 0.4, time.time(), 4))
        is_attack, conf = detector._consensus(results)
        assert is_attack is False
        assert conf == 2/3

    @patch("src.detection.ensemble.KafkaConsumerHelper")
    async def test_correlate_alerts(self, mock_consumer, detector):
        now = time.time()
        alert1 = DetectorResult("signature", {"type": "flood", "target_ip": "10.0.0.1"}, 0.9, now, 3)
        alert2 = DetectorResult("anomaly", {"type": "volumetric", "target_ip": "10.0.0.1"}, 0.8, now, 3)
        detector._alerts_queue = [alert1, alert2]
        ensemble_alerts = detector._correlate_alerts()
        assert len(ensemble_alerts) == 1
        assert ensemble_alerts[0]["confidence"] == 0.78
        assert ensemble_alerts[0]["target"] == "10.0.0.1:flood"