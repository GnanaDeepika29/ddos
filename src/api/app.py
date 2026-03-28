"""FastAPI REST API for DDoS Defense Platform.

Provides endpoints for system status, alerts, mitigation control,
configuration management, and health checks.
"""

import asyncio
import json
import time
import uuid
from typing import Dict, Any, List, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query, Path, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, Field
import structlog

from ..common.logging import get_logger, setup_logging
from ..common.metrics import metrics
from ..common.config import load_config
from ..common.database import db

logger = get_logger(__name__)

# Pydantic models for request/response


class HealthResponse(BaseModel):
    status: str
    version: str
    timestamp: float
    components: Dict[str, str]


class AlertResponse(BaseModel):
    id: str
    type: str
    severity: int
    confidence: Optional[float] = None
    target: Optional[str] = None
    description: str
    timestamp: float
    details: Dict[str, Any]


class AlertListResponse(BaseModel):
    total: int
    alerts: List[AlertResponse]


class MitigationAction(BaseModel):
    action: str
    target: str
    duration: Optional[int] = 300


class MitigationResponse(BaseModel):
    success: bool
    message: str
    action_id: Optional[str] = None


class ConfigResponse(BaseModel):
    environment: str
    detection_thresholds: Dict[str, Any]
    mitigation_settings: Dict[str, Any]


class ManualOverride(BaseModel):
    enabled: bool
    reason: Optional[str] = None
    duration: Optional[int] = 3600  # seconds


# Global state
app_state = {
    "start_time": time.time(),
    "config": None,
    "manual_override": False,
    "override_reason": None,
    "override_expiry": None,
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup/shutdown events."""
    # Startup
    logger.info("Starting API server")
    # Load configuration
    app_state["config"] = load_config()
    # Connect to database
    db_config = app_state["config"].get("database", {})
    db.host = db_config.get("host", "localhost")
    db.port = db_config.get("port", 5432)
    db.database = db_config.get("name", "ddos_platform")
    db.user = db_config.get("user", "ddos_user")
    db.password = db_config.get("password")
    db.min_pool_size = db_config.get("pool_size", 10)
    db.max_pool_size = db_config.get("max_overflow", 20)
    await db.connect()
    # Ensure tables exist
    await db.create_tables()
    logger.info("Database connected")
    yield
    # Shutdown
    logger.info("Shutting down API server")
    await db.close()


# Create FastAPI app
app = FastAPI(
    title="DDoS Defense Platform API",
    description="REST API for DDoS detection and mitigation management",
    version="0.1.0",
    lifespan=lifespan,
)

# Configure CORS
cors_config = app_state["config"].get("api", {}).get("cors_origins", []) if app_state["config"] else []
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_config or ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check() -> HealthResponse:
    """Health check endpoint."""
    components = {
        "api": "healthy",
        "database": "healthy" if db._running else "unhealthy",
    }
    # Check Kafka connectivity (optional)
    # Could be added later
    return HealthResponse(
        status="healthy" if all(v == "healthy" for v in components.values()) else "degraded",
        version="0.1.0",
        timestamp=time.time(),
        components=components,
    )


@app.get("/metrics", tags=["System"])
async def prometheus_metrics():
    """Prometheus metrics endpoint."""
    from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
    return Response(content=generate_latest(metrics._registry), media_type=CONTENT_TYPE_LATEST)


@app.get("/alerts", response_model=AlertListResponse, tags=["Alerts"])
async def list_alerts(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    severity: Optional[int] = Query(None, ge=1, le=5),
    alert_type: Optional[str] = None,
) -> AlertListResponse:
    """List alerts with pagination and filtering."""
    query = """
        SELECT id, alert_type, severity, confidence, target, details, created_at
        FROM alerts
        WHERE 1=1
    """
    params = []
    if severity is not None:
        query += " AND severity = $" + str(len(params) + 1)
        params.append(severity)
    if alert_type is not None:
        query += " AND alert_type = $" + str(len(params) + 1)
        params.append(alert_type)

    # Count total
    count_query = query.replace("SELECT id, alert_type, severity, confidence, target, details, created_at", "SELECT COUNT(*)")
    total = await db.fetchval(count_query, *params) or 0

    # Fetch paginated
    query += " ORDER BY created_at DESC LIMIT $" + str(len(params) + 1) + " OFFSET $" + str(len(params) + 2)
    params.extend([limit, offset])
    rows = await db.fetch(query, *params)

    alerts = []
    for row in rows:
        details = row["details"] or {}
        alerts.append(AlertResponse(
            id=row["id"],
            type=row["alert_type"],
            severity=row["severity"],
            confidence=row["confidence"],
            target=row["target"],
            description=details.get("description", f"{row['alert_type']} attack detected"),
            timestamp=row["created_at"].timestamp(),
            details=details,
        ))

    return AlertListResponse(total=total, alerts=alerts)


@app.get("/alerts/{alert_id}", response_model=AlertResponse, tags=["Alerts"])
async def get_alert(alert_id: str = Path(..., pattern=r"^[0-9a-fA-F-]{36}$")) -> AlertResponse:
    """Get a specific alert by ID."""
    row = await db.fetchrow(
        "SELECT id, alert_type, severity, confidence, target, details, created_at FROM alerts WHERE id = $1",
        alert_id,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")
    details = row["details"] or {}
    return AlertResponse(
        id=row["id"],
        type=row["alert_type"],
        severity=row["severity"],
        confidence=row["confidence"],
        target=row["target"],
        description=details.get("description", f"{row['alert_type']} attack detected"),
        timestamp=row["created_at"].timestamp(),
        details=details,
    )


@app.post("/mitigation/apply", response_model=MitigationResponse, tags=["Mitigation"])
async def apply_mitigation(action: MitigationAction, background_tasks: BackgroundTasks) -> MitigationResponse:
    """Manually apply a mitigation action."""
    # Generate action ID
    action_id = str(uuid.uuid4())
    # In production, this would send a message to Kafka for the mitigation orchestrator
    # For now, we'll just log and return success
    logger.info(f"Manual mitigation action: {action.action} on {action.target} (id={action_id})")
    background_tasks.add_task(
        _send_mitigation_request,
        action_id,
        action.dict(),
    )
    return MitigationResponse(
        success=True,
        message=f"Mitigation action {action.action} scheduled for {action.target}",
        action_id=action_id,
    )


@app.post("/mitigation/rollback/{action_id}", response_model=MitigationResponse, tags=["Mitigation"])
async def rollback_mitigation(
    action_id: str = Path(..., pattern=r"^[0-9a-fA-F-]{36}$"),
    background_tasks: BackgroundTasks = None,
) -> MitigationResponse:
    """Rollback a previously applied mitigation action."""
    # This would look up the action and send a rollback request
    logger.info(f"Manual rollback requested for action {action_id}")
    background_tasks.add_task(_send_rollback_request, action_id)
    return MitigationResponse(
        success=True,
        message=f"Rollback requested for action {action_id}",
        action_id=action_id,
    )


@app.post("/mitigation/override", response_model=MitigationResponse, tags=["Mitigation"])
async def set_manual_override(override: ManualOverride) -> MitigationResponse:
    """Enable or disable manual override of automatic mitigation."""
    global app_state
    if override.enabled:
        app_state["manual_override"] = True
        app_state["override_reason"] = override.reason
        if override.duration:
            app_state["override_expiry"] = time.time() + override.duration
        else:
            app_state["override_expiry"] = None
        message = "Manual override enabled"
    else:
        app_state["manual_override"] = False
        app_state["override_reason"] = None
        app_state["override_expiry"] = None
        message = "Manual override disabled"
    logger.info(message)
    return MitigationResponse(
        success=True,
        message=message,
    )


@app.get("/config", response_model=ConfigResponse, tags=["System"])
async def get_config() -> ConfigResponse:
    """Get current configuration."""
    config = app_state["config"] or {}
    detection = config.get("detection", {})
    mitigation = config.get("mitigation", {})
    return ConfigResponse(
        environment=config.get("environment", "development"),
        detection_thresholds={
            "volumetric_mbps": detection.get("anomaly", {}).get("volumetric", {}).get("threshold_mbps", 1000),
            "volumetric_pps": detection.get("anomaly", {}).get("volumetric", {}).get("threshold_pps", 500000),
            "entropy": detection.get("anomaly", {}).get("entropy", {}).get("threshold", 3.5),
        },
        mitigation_settings={
            "auto_response": mitigation.get("auto_response", True),
            "dry_run": mitigation.get("dry_run", False),
            "rollback_delay": mitigation.get("rollback_delay", 300),
        },
    )


@app.get("/stats", tags=["System"])
async def get_stats() -> Dict[str, Any]:
    """Get system statistics."""
    uptime = time.time() - app_state["start_time"]
    return {
        "uptime_seconds": uptime,
        "manual_override": app_state["manual_override"],
        "override_reason": app_state["override_reason"],
        "override_expiry": app_state["override_expiry"],
        "timestamp": time.time(),
    }


async def _send_mitigation_request(action_id: str, action_data: Dict[str, Any]):
    """Send a mitigation request to Kafka (placeholder)."""
    # In a real implementation, we'd produce to Kafka
    from ..common.kafka_consumer import KafkaConsumerHelper
    # This is a placeholder - we'll just log
    logger.info(f"Sending mitigation request: {action_data}")


async def _send_rollback_request(action_id: str):
    """Send a rollback request to Kafka (placeholder)."""
    logger.info(f"Sending rollback request for action {action_id}")


def main():
    """Entry point for running the API server with uvicorn."""
    import uvicorn
    import argparse

    parser = argparse.ArgumentParser(description="DDoS Defense Platform API")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload")
    args = parser.parse_args()

    setup_logging(level="INFO")
    uvicorn.run(
        "src.api.app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
    )


if __name__ == "__main__":
    main()
