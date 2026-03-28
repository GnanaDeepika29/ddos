"""Mitigation orchestration engine.

This module coordinates all mitigation actions based on incoming alerts.
It decides which actions to take, in what order, and manages rollback.
"""

import asyncio
import time
from typing import Optional, Dict, Any, List, Set
from collections import defaultdict, deque

import structlog

from ..common.logging import get_logger
from ..common.metrics import metrics
from ..common.kafka_consumer import KafkaConsumerHelper
from .actions import (
    RateLimiter,
    BGPRouteAnnouncer,
    SDNController,
    CloudSecurityGroups,
    BlacklistManager,
)
from .rollback import RollbackManager

logger = get_logger(__name__)


class MitigationOrchestrator:
    """Orchestrates mitigation actions based on alerts."""

    def __init__(
        self,
        input_topic: str = "alerts.enriched",
        output_topic: str = "mitigation.events",
        bootstrap_servers: Optional[List[str]] = None,
        batch_size: int = 10,
        batch_timeout_ms: int = 500,
        auto_response: bool = True,
        dry_run: bool = False,
        action_timeout: int = 30,
        rollback_delay: int = 300,
    ):
        """Initialize mitigation orchestrator.

        Args:
            input_topic: Kafka topic for alerts.
            output_topic: Kafka topic for mitigation events.
            bootstrap_servers: Kafka broker list.
            batch_size: Number of alerts per batch.
            batch_timeout_ms: Batch timeout.
            auto_response: Whether to automatically apply mitigation.
            dry_run: If True, log actions but do not apply.
            action_timeout: Timeout for each action in seconds.
            rollback_delay: Seconds to wait before rolling back.
        """
        self.input_topic = input_topic
        self.output_topic = output_topic
        self.bootstrap_servers = bootstrap_servers or ["localhost:9092"]
        self.batch_size = batch_size
        self.batch_timeout_ms = batch_timeout_ms
        self.auto_response = auto_response
        self.dry_run = dry_run
        self.action_timeout = action_timeout
        self.rollback_delay = rollback_delay

        self._running = False
        self._consumer: Optional[KafkaConsumerHelper] = None
        self._active_mitigations: Dict[str, Dict[str, Any]] = {}  # alert_id -> mitigation details
        self._mitigation_queue: deque = deque()
        self._stats = {
            "alerts_processed": 0,
            "actions_taken": 0,
            "rollbacks": 0,
            "errors": 0,
        }

        # Initialize action modules
        self.rate_limiter = RateLimiter(dry_run=dry_run)
        self.bgp_announcer = BGPRouteAnnouncer(dry_run=dry_run)
        self.sdn_controller = SDNController(dry_run=dry_run)
        self.cloud_security = CloudSecurityGroups(dry_run=dry_run)
        self.blacklist_manager = BlacklistManager(dry_run=dry_run)
        self.rollback_manager = RollbackManager(dry_run=dry_run)

    async def _apply_mitigation(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Apply mitigation actions based on alert."""
        alert_id = alert.get("alert_id")
        severity = alert.get("severity", 2)
        attack_type = alert.get("type", "")
        target = alert.get("target_ip") or alert.get("target", "")
        suggested_actions = alert.get("suggested_actions", [])

        mitigation_result = {
            "alert_id": alert_id,
            "timestamp": time.time(),
            "actions": [],
            "status": "pending",
        }

        if not self.auto_response:
            logger.info("Auto-response disabled, skipping mitigation", alert_id=alert_id)
            mitigation_result["status"] = "skipped"
            return mitigation_result

        if self.dry_run:
            logger.info("DRY RUN: Would apply mitigation", alert_id=alert_id, actions=suggested_actions)
            mitigation_result["status"] = "dry_run"
            mitigation_result["actions"] = suggested_actions
            return mitigation_result

        # Execute actions in order
        for action in suggested_actions:
            try:
                if action == "rate_limit":
                    result = await self.rate_limiter.apply(target, alert)
                elif action == "blacklist_sources":
                    # Extract source IPs from alert if available
                    sources = alert.get("source_ips", [])
                    result = await self.blacklist_manager.apply(sources, alert)
                elif action == "scrubbing":
                    result = await self.bgp_announcer.apply(target, alert)
                elif action == "syn_cookie":
                    result = await self.sdn_controller.enable_syn_cookie(target, alert)
                elif action == "monitor":
                    result = {"action": "monitor", "status": "success"}
                else:
                    result = {"action": action, "status": "unknown", "error": "Unsupported action"}

                mitigation_result["actions"].append(result)
                if result.get("status") != "success":
                    logger.warning("Action failed", action=action, result=result)
            except Exception as e:
                logger.error("Action execution error", action=action, error=str(e))
                mitigation_result["actions"].append({"action": action, "status": "error", "error": str(e)})
                self._stats["errors"] += 1

        # Determine overall status
        if any(a.get("status") == "error" for a in mitigation_result["actions"]):
            mitigation_result["status"] = "partial_failure"
        elif all(a.get("status") == "success" for a in mitigation_result["actions"]):
            mitigation_result["status"] = "success"
            self._stats["actions_taken"] += len(mitigation_result["actions"])
            # Schedule rollback
            asyncio.create_task(self._schedule_rollback(alert_id, target, alert))
        else:
            mitigation_result["status"] = "unknown"

        return mitigation_result

    async def _schedule_rollback(self, alert_id: str, target: str, alert: Dict[str, Any]):
        """Schedule rollback after delay."""
        await asyncio.sleep(self.rollback_delay)
        await self._rollback(alert_id, target, alert)

    async def _rollback(self, alert_id: str, target: str, alert: Dict[str, Any]):
        """Rollback mitigation actions."""
        if alert_id not in self._active_mitigations:
            return

        logger.info("Rolling back mitigation", alert_id=alert_id, target=target)
        result = await self.rollback_manager.rollback(alert_id, alert)
        if result.get("status") == "success":
            self._stats["rollbacks"] += 1
            del self._active_mitigations[alert_id]
            # Publish rollback event
            if self._consumer and self._consumer.producer:
                await self._consumer.producer.send(
                    topic=self.output_topic,
                    message={
                        "type": "rollback",
                        "alert_id": alert_id,
                        "timestamp": time.time(),
                        "result": result,
                    },
                )
        else:
            logger.error("Rollback failed", alert_id=alert_id, result=result)

    async def _process_batch(self, messages: List[Dict[str, Any]]):
        """Process a batch of alerts."""
        for msg in messages:
            try:
                mitigation = await self._apply_mitigation(msg)
                # Store active mitigation for rollback tracking
                if mitigation["status"] in ("success", "partial_failure"):
                    self._active_mitigations[msg.get("alert_id")] = mitigation
                # Publish mitigation event
                if self._consumer and self._consumer.producer:
                    await self._consumer.producer.send(
                        topic=self.output_topic,
                        message={
                            "type": "mitigation",
                            **mitigation,
                        },
                    )
                self._stats["alerts_processed"] += 1
                metrics.mitigation_actions_total.inc(len(mitigation.get("actions", [])))
            except Exception as e:
                logger.error("Error processing alert", error=str(e))
                self._stats["errors"] += 1

    async def start(self):
        """Start the mitigation orchestrator."""
        if self._running:
            logger.warning("Mitigation orchestrator already running")
            return

        self._running = True

        # Initialize Kafka consumer
        self._consumer = KafkaConsumerHelper(
            bootstrap_servers=self.bootstrap_servers,
            topic=self.input_topic,
            group_id="mitigation-orchestrator",
            batch_size=self.batch_size,
            batch_timeout_ms=self.batch_timeout_ms,
        )
        await self._consumer.start()

        # Initialize action modules
        await self.rate_limiter.start()
        await self.bgp_announcer.start()
        await self.sdn_controller.start()
        await self.cloud_security.start()
        await self.blacklist_manager.start()

        # Main processing loop
        try:
            async for batch in self._consumer.consume_batches():
                if not self._running:
                    break
                await self._process_batch(batch)
        except asyncio.CancelledError:
            logger.info("Mitigation orchestrator cancelled")
        finally:
            await self.stop()

    async def stop(self):
        """Stop the mitigation orchestrator."""
        if not self._running:
            return
        self._running = False
        if self._consumer:
            await self._consumer.stop()
        await self.rate_limiter.stop()
        await self.bgp_announcer.stop()
        await self.sdn_controller.stop()
        await self.cloud_security.stop()
        await self.blacklist_manager.stop()
        logger.info("Mitigation orchestrator stopped")

    def get_stats(self) -> Dict[str, Any]:
        """Get orchestrator statistics."""
        return self._stats.copy()