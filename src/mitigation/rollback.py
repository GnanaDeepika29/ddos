"""Rollback management for mitigation actions.

This module handles the reversal of mitigation actions after an attack
subsides, ensuring that normal traffic flow is restored.
"""

import asyncio
import time
from typing import Optional, Dict, Any, List
from collections import defaultdict

import structlog

from ..common.logging import get_logger
from .actions import (
    RateLimiter,
    BGPRouteAnnouncer,
    SDNController,
    CloudSecurityGroups,
    BlacklistManager,
)

logger = get_logger(__name__)


class RollbackManager:
    """Manage rollback of mitigation actions."""

    def __init__(
        self,
        dry_run: bool = False,
        action_timeout: int = 30,
    ):
        """Initialize rollback manager.

        Args:
            dry_run: If True, log actions but do not apply.
            action_timeout: Timeout for each rollback action in seconds.
        """
        self.dry_run = dry_run
        self.action_timeout = action_timeout
        self._rollback_history: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        # Action modules (reused from mitigation)
        self.rate_limiter = RateLimiter(dry_run=dry_run)
        self.bgp_announcer = BGPRouteAnnouncer(dry_run=dry_run)
        self.sdn_controller = SDNController(dry_run=dry_run)
        self.cloud_security = CloudSecurityGroups(dry_run=dry_run)
        self.blacklist_manager = BlacklistManager(dry_run=dry_run)

    async def start(self):
        """Initialize action modules."""
        await self.rate_limiter.start()
        await self.bgp_announcer.start()
        await self.sdn_controller.start()
        await self.cloud_security.start()
        await self.blacklist_manager.start()
        logger.info("RollbackManager started", dry_run=self.dry_run)

    async def stop(self):
        """Clean up action modules."""
        await self.rate_limiter.stop()
        await self.bgp_announcer.stop()
        await self.sdn_controller.stop()
        await self.cloud_security.stop()
        await self.blacklist_manager.stop()
        logger.info("RollbackManager stopped")

    async def rollback(self, alert_id: str, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Rollback actions associated with an alert.

        Args:
            alert_id: Unique identifier of the alert.
            alert: Original alert that triggered the mitigation.

        Returns:
            Dict with rollback result.
        """
        result = {
            "alert_id": alert_id,
            "timestamp": time.time(),
            "actions": [],
            "status": "pending",
        }

        # Determine which actions were applied (stored in history)
        actions_applied = self._rollback_history.get(alert_id, [])
        if not actions_applied:
            # If no history, try to infer from alert
            suggested_actions = alert.get("suggested_actions", [])
            logger.warning("No rollback history, inferring from alert", alert_id=alert_id, actions=suggested_actions)
            actions_applied = [{"action": a, "target": alert.get("target_ip")} for a in suggested_actions]

        if self.dry_run:
            logger.info("DRY RUN: Would rollback actions", alert_id=alert_id, actions=actions_applied)
            result["status"] = "dry_run"
            result["actions"] = actions_applied
            return result

        # Reverse each action
        for action_record in reversed(actions_applied):  # reverse order of application
            action = action_record.get("action")
            target = action_record.get("target")
            try:
                if action == "rate_limit":
                    if target:
                        res = await self.rate_limiter.remove(target)
                    else:
                        res = {"action": "rate_limit_remove", "status": "error", "error": "No target"}
                elif action == "blacklist_sources":
                    sources = action_record.get("sources", [])
                    if sources:
                        res = await self.blacklist_manager.remove(sources)
                    else:
                        res = {"action": "unblacklist", "status": "error", "error": "No sources"}
                elif action == "scrubbing":
                    if target:
                        res = await self.bgp_announcer.remove(target)
                    else:
                        res = {"action": "bgp_withdraw", "status": "error", "error": "No target"}
                elif action == "syn_cookie":
                    # SYN cookie may be global; we might not revert automatically
                    # For simplicity, we log and consider success
                    res = {"action": "syn_cookie_disable", "status": "not_implemented", "info": "SYN cookie may need manual revert"}
                elif action == "monitor":
                    res = {"action": "monitor", "status": "success"}
                elif action == "cloud_block":
                    if target:
                        res = await self.cloud_security.remove(target)
                    else:
                        res = {"action": "cloud_unblock", "status": "error", "error": "No target"}
                else:
                    res = {"action": action, "status": "unknown", "error": "Unsupported rollback action"}
            except Exception as e:
                logger.error("Rollback action error", action=action, error=str(e))
                res = {"action": action, "status": "error", "error": str(e)}
            result["actions"].append(res)

        # Determine overall status
        if any(a.get("status") == "error" for a in result["actions"]):
            result["status"] = "partial_failure"
        else:
            result["status"] = "success"
            # Clean up history
            if alert_id in self._rollback_history:
                del self._rollback_history[alert_id]

        return result

    def record_mitigation(self, alert_id: str, actions: List[Dict[str, Any]]):
        """Record applied mitigation actions for later rollback.

        Args:
            alert_id: Unique identifier of the alert.
            actions: List of action records (each containing action type and target).
        """
        self._rollback_history[alert_id] = actions
        logger.debug("Recorded mitigation for rollback", alert_id=alert_id, actions=len(actions))