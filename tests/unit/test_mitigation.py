"""Unit tests for mitigation components."""

import pytest
import time
from unittest.mock import AsyncMock, patch
from src.mitigation.orchestrator import MitigationOrchestrator
from src.mitigation.actions import (
    RateLimiter,
    BGPRouteAnnouncer,
    SDNController,
    CloudSecurityGroups,
    BlacklistManager,
)
from src.mitigation.rollback import RollbackManager


@pytest.mark.asyncio
class TestRateLimiter:
    """Test rate limiter actions."""

    @pytest.fixture
    def rate_limiter(self):
        return RateLimiter(dry_run=True)

    async def test_apply_dry_run(self, rate_limiter):
        result = await rate_limiter.apply("192.168.1.1", {"timestamp": time.time()})
        assert result["status"] == "dry_run"
        assert result["target"] == "192.168.1.1"
        assert "192.168.1.1" in rate_limiter._active_limits

    async def test_remove_dry_run(self, rate_limiter):
        rate_limiter._active_limits["192.168.1.1"] = {}
        result = await rate_limiter.remove("192.168.1.1")
        assert result["status"] == "dry_run"
        assert "192.168.1.1" not in rate_limiter._active_limits

    async def test_remove_not_found(self, rate_limiter):
        result = await rate_limiter.remove("192.168.1.2")
        assert result["status"] == "not_found"


@pytest.mark.asyncio
class TestBGPRouteAnnouncer:
    """Test BGP announcer actions."""

    @pytest.fixture
    def bgp(self):
        return BGPRouteAnnouncer(dry_run=True)

    async def test_apply_dry_run(self, bgp):
        result = await bgp.apply("10.0.0.1", {"timestamp": time.time()})
        assert result["status"] == "dry_run"
        assert result["target"] == "10.0.0.1"

    async def test_remove_dry_run(self, bgp):
        bgp._active_announcements["10.0.0.1"] = {}
        result = await bgp.remove("10.0.0.1")
        assert result["status"] == "dry_run"
        assert "10.0.0.1" not in bgp._active_announcements


@pytest.mark.asyncio
class TestSDNController:
    """Test SDN controller actions."""

    @pytest.fixture
    def sdn(self):
        return SDNController(dry_run=True)

    async def test_enable_syn_cookie(self, sdn):
        result = await sdn.enable_syn_cookie("10.0.0.1", {"timestamp": time.time()})
        assert result["status"] == "dry_run"


@pytest.mark.asyncio
class TestCloudSecurityGroups:
    """Test cloud security group actions."""

    @pytest.fixture
    def cloud(self):
        return CloudSecurityGroups(dry_run=True)

    async def test_apply_dry_run(self, cloud):
        result = await cloud.apply("192.168.1.1", {"timestamp": time.time()})
        assert result["status"] == "dry_run"
        assert result["target"] == "192.168.1.1"

    async def test_remove_dry_run(self, cloud):
        cloud._active_rules["192.168.1.1"] = {}
        result = await cloud.remove("192.168.1.1")
        assert result["status"] == "dry_run"


@pytest.mark.asyncio
class TestBlacklistManager:
    """Test blacklist manager."""

    @pytest.fixture
    def blacklist(self):
        return BlacklistManager(dry_run=True)

    async def test_apply_dry_run(self, blacklist):
        result = await blacklist.apply(["1.2.3.4", "5.6.7.8"], {"timestamp": time.time()})
        assert result["overall_status"] == "success"
        assert len(result["results"]) == 2
        for r in result["results"]:
            assert r["status"] == "dry_run"
        assert "1.2.3.4" in blacklist._blacklist

    async def test_remove_dry_run(self, blacklist):
        blacklist._blacklist["1.2.3.4"] = {}
        result = await blacklist.remove(["1.2.3.4"])
        assert result["results"][0]["status"] == "dry_run"
        assert "1.2.3.4" not in blacklist._blacklist


@pytest.mark.asyncio
class TestRollbackManager:
    """Test rollback manager."""

    @pytest.fixture
    def rollback(self):
        return RollbackManager(dry_run=True)

    async def test_record_and_rollback(self, rollback):
        alert_id = "test-alert-id"
        actions = [{"action": "rate_limit", "target": "192.168.1.1"}]
        rollback.record_mitigation(alert_id, actions)
        assert alert_id in rollback._rollback_history
        assert rollback._rollback_history[alert_id] == actions

        result = await rollback.rollback(alert_id, {"suggested_actions": ["rate_limit"], "target_ip": "192.168.1.1"})
        assert result["status"] == "dry_run"
        assert alert_id not in rollback._rollback_history


@pytest.mark.asyncio
class TestMitigationOrchestrator:
    """Test mitigation orchestrator."""

    @pytest.fixture
    def orchestrator(self):
        return MitigationOrchestrator(
            auto_response=True,
            dry_run=True,
            rollback_delay=1,
        )

    @patch("src.mitigation.orchestrator.RateLimiter")
    @patch("src.mitigation.orchestrator.BGPRouteAnnouncer")
    @patch("src.mitigation.orchestrator.SDNController")
    @patch("src.mitigation.orchestrator.CloudSecurityGroups")
    @patch("src.mitigation.orchestrator.BlacklistManager")
    @patch("src.mitigation.orchestrator.RollbackManager")
    async def test_apply_mitigation(
        self, mock_rollback, mock_blacklist, mock_cloud, mock_sdn, mock_bgp, mock_rate, orchestrator
    ):
        # Setup mocks
        orchestrator.dry_run = False
        orchestrator.rate_limiter.apply = AsyncMock(return_value={"action": "rate_limit", "status": "success"})
        orchestrator.blacklist_manager.apply = AsyncMock(return_value={"action": "blacklist", "status": "success"})

        alert = {
            "alert_id": "test-123",
            "severity": 3,
            "type": "flood",
            "target_ip": "10.0.0.1",
            "suggested_actions": ["rate_limit", "blacklist_sources"],
            "source_ips": ["1.2.3.4"],
        }

        result = await orchestrator._apply_mitigation(alert)
        assert result["status"] == "success"
        assert len(result["actions"]) == 2
        assert result["actions"][0]["action"] == "rate_limit"
        assert result["actions"][1]["action"] == "blacklist"

    async def test_apply_mitigation_disabled(self, orchestrator):
        orchestrator.auto_response = False
        alert = {"alert_id": "test-123", "suggested_actions": ["rate_limit"]}
        result = await orchestrator._apply_mitigation(alert)
        assert result["status"] == "skipped"

    async def test_apply_mitigation_dry_run(self, orchestrator):
        orchestrator.dry_run = True
        alert = {"alert_id": "test-123", "suggested_actions": ["rate_limit"], "target_ip": "10.0.0.1"}
        result = await orchestrator._apply_mitigation(alert)
        assert result["status"] == "dry_run"
        assert result["actions"] == ["rate_limit"]
