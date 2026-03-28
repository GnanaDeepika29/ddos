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
from ..common.kafka_producer import TelemetryProducer
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
        control_topic: Optional[str] = None,
        bootstrap_servers: Optional[List[str]] = None,
        batch_size: int = 10,
        batch_timeout_ms: int = 500,
        auto_response: bool = True,
        dry_run: bool = False,
        action_timeout: int = 30,
        rollback_delay: int = 300,
        producer: Optional[TelemetryProducer] = None,
        rate_limit_config: Optional[Dict[str, Any]] = None,
        scrubbing_config: Optional[Dict[str, Any]] = None,
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
        self.control_topic = control_topic
        self.bootstrap_servers = bootstrap_servers or ["localhost:9092"]
        self.batch_size = batch_size
        self.batch_timeout_ms = batch_timeout_ms
        self.auto_response = auto_response
        self.dry_run = dry_run
        self.action_timeout = action_timeout
        self.rollback_delay = rollback_delay
        self.producer = producer
        self.rate_limit_config = rate_limit_config or {}
        self.scrubbing_config = scrubbing_config or {}

        self._running = False
        self._consumer: Optional[KafkaConsumerHelper] = None
        self._control_consumer: Optional[KafkaConsumerHelper] = None
        self._active_mitigations: Dict[str, Dict[str, Any]] = {}  # alert_id -> mitigation details
        self._mitigation_queue: deque = deque()
        self.manual_override = False
        self._stats = {
            "alerts_processed": 0,
            "actions_taken": 0,
            "rollbacks": 0,
            "errors": 0,
        }

        # Initialize action modules
        self.rate_limiter = RateLimiter(dry_run=dry_run, policy_config=self.rate_limit_config)
        self.bgp_announcer = BGPRouteAnnouncer(dry_run=dry_run, config=self.scrubbing_config)
        self.sdn_controller = SDNController(dry_run=dry_run)
        self.cloud_security = CloudSecurityGroups(dry_run=dry_run)
        self.blacklist_manager = BlacklistManager(dry_run=dry_run)
        self.rollback_manager = RollbackManager(dry_run=dry_run)

    async def _execute_actions(
        self,
        *,
        action_id: str,
        target: str,
        suggested_actions: List[str],
        alert: Dict[str, Any],
        allow_skip_checks: bool = False,
    ) -> Dict[str, Any]:
        """Execute mitigation actions for a target."""
        target = alert.get("target_ip") or alert.get("target", "")

        mitigation_result = {
            "alert_id": action_id,
            "timestamp": time.time(),
            "actions": [],
            "status": "pending",
        }

        if not allow_skip_checks and not self.auto_response:
            logger.info("Auto-response disabled, skipping mitigation", alert_id=action_id)
            mitigation_result["status"] = "skipped"
            return mitigation_result

        if not allow_skip_checks and self.manual_override:
            logger.info("Manual override enabled, skipping automatic mitigation", alert_id=action_id)
            mitigation_result["status"] = "manual_override"
            return mitigation_result

        if self.dry_run:
            logger.info("DRY RUN: Would apply mitigation", alert_id=action_id, actions=suggested_actions)
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
            action_records = []
            for action_name, action_result in zip(suggested_actions, mitigation_result["actions"]):
                record = {
                    "action": action_name,
                    "target": target,
                }
                if action_name == "blacklist_sources":
                    record["sources"] = alert.get("source_ips", [])
                action_records.append(record)
            self.rollback_manager.record_mitigation(action_id, action_records)
            asyncio.create_task(self._schedule_rollback(action_id, target, alert))
        else:
            mitigation_result["status"] = "unknown"

        return mitigation_result

    async def _apply_mitigation(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Apply mitigation actions based on alert."""
        alert_id = alert.get("alert_id")
        target = alert.get("target_ip") or alert.get("target", "")
        suggested_actions = alert.get("suggested_actions", [])
        return await self._execute_actions(
            action_id=alert_id,
            target=target,
            suggested_actions=suggested_actions,
            alert=alert,
            allow_skip_checks=False,
        )

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

    async def _handle_control_message(self, message: Dict[str, Any]) -> None:
        """Handle a mitigation control-plane command."""
        command_type = message.get("type")
        command_id = message.get("command_id", str(time.time()))

        if command_type == "mitigation_apply":
            alert = {
                "alert_id": command_id,
                "type": "manual_mitigation",
                "severity": message.get("severity", 3),
                "target_ip": message.get("target"),
                "target": message.get("target"),
                "source_ips": message.get("source_ips", []),
                "suggested_actions": [message.get("action")] if message.get("action") else [],
                "telemetry_source": "api_control_plane",
                "timestamp": time.time(),
            }
            result = await self._execute_actions(
                action_id=command_id,
                target=message.get("target", ""),
                suggested_actions=alert["suggested_actions"],
                alert=alert,
                allow_skip_checks=True,
            )
            if self.producer:
                await self.producer.send(
                    {
                        "type": "mitigation_control",
                        "command": command_type,
                        "command_id": command_id,
                        "result": result,
                        "timestamp": time.time(),
                    },
                    topic=self.output_topic,
                )
        elif command_type == "mitigation_rollback":
            alert_id = message.get("action_id")
            alert = {
                "target_ip": message.get("target"),
                "suggested_actions": [message.get("action")] if message.get("action") else [],
            }
            result = await self.rollback_manager.rollback(alert_id, alert)
            if alert_id in self._active_mitigations:
                del self._active_mitigations[alert_id]
            if self.producer:
                await self.producer.send(
                    {
                        "type": "rollback",
                        "command": command_type,
                        "alert_id": alert_id,
                        "result": result,
                        "timestamp": time.time(),
                    },
                    topic=self.output_topic,
                )
        elif command_type == "mitigation_override":
            self.manual_override = bool(message.get("enabled"))
            if self.producer:
                await self.producer.send(
                    {
                        "type": "mitigation_override",
                        "enabled": self.manual_override,
                        "reason": message.get("reason"),
                        "duration": message.get("duration"),
                        "command_id": command_id,
                        "timestamp": time.time(),
                    },
                    topic=self.output_topic,
                )
        else:
            logger.warning("Unknown control command", command_type=command_type, command_id=command_id)

    async def _consume_alert_stream(self) -> None:
        """Consume alert stream."""
        if not self._consumer:
            return
        async for batch in self._consumer.consume_batches():
            if not self._running:
                break
            await self._process_batch(batch)

    async def _consume_control_stream(self) -> None:
        """Consume control stream."""
        if not self._control_consumer:
            return
        async for batch in self._control_consumer.consume_batches():
            if not self._running:
                break
            for message in batch:
                try:
                    await self._handle_control_message(message)
                except Exception as e:
                    logger.error("Error processing control command", error=str(e), message=message)
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
            producer=self.producer,
        )
        await self._consumer.start()

        if self.control_topic:
            self._control_consumer = KafkaConsumerHelper(
                bootstrap_servers=self.bootstrap_servers,
                topic=self.control_topic,
                group_id="mitigation-control",
                batch_size=self.batch_size,
                batch_timeout_ms=self.batch_timeout_ms,
                producer=self.producer,
            )
            await self._control_consumer.start()

        # Initialize action modules
        await self.rate_limiter.start()
        await self.bgp_announcer.start()
        await self.sdn_controller.start()
        await self.cloud_security.start()
        await self.blacklist_manager.start()
        await self.rollback_manager.start()

        # Main processing loop
        try:
            tasks = [asyncio.create_task(self._consume_alert_stream())]
            if self._control_consumer:
                tasks.append(asyncio.create_task(self._consume_control_stream()))
            await asyncio.gather(*tasks)
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
        if self._control_consumer:
            await self._control_consumer.stop()
        await self.rate_limiter.stop()
        await self.bgp_announcer.stop()
        await self.sdn_controller.stop()
        await self.cloud_security.stop()
        await self.blacklist_manager.stop()
        await self.rollback_manager.stop()
        logger.info("Mitigation orchestrator stopped")

    def get_stats(self) -> Dict[str, Any]:
        """Get orchestrator statistics."""
        return self._stats.copy()
