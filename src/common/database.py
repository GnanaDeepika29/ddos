"""Database connection and utility functions.

This module provides asynchronous database connection pooling and helper
functions for TimescaleDB (PostgreSQL) used for metrics and historical data.
"""

import asyncio
import contextlib
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, AsyncIterator, Union
from contextlib import asynccontextmanager

import structlog
import asyncpg
from asyncpg import Pool, Connection

from .logging import get_logger

logger = get_logger(__name__)


class DatabaseConnection:
    """Asynchronous database connection pool manager."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 5432,
        database: str = "ddos_platform",
        user: str = "ddos_user",
        password: Optional[str] = None,
        min_pool_size: int = 10,
        max_pool_size: int = 20,
        ssl_mode: str = "disable",
        command_timeout: int = 60,
    ):
        """Initialize database connection.

        Args:
            host: Database host.
            port: Database port.
            database: Database name.
            user: Database user.
            password: Database password.
            min_pool_size: Minimum pool size.
            max_pool_size: Maximum pool size.
            ssl_mode: SSL mode (disable, require, verify-ca, verify-full).
            command_timeout: Command timeout in seconds.
        """
        self.host = host
        self.port = port
        self.database = database
        self.user = user
        self.password = password
        self.min_pool_size = min_pool_size
        self.max_pool_size = max_pool_size
        self.ssl_mode = ssl_mode
        self.command_timeout = command_timeout

        self._pool: Optional[Pool] = None
        self._running = False

    async def connect(self) -> None:
        """Establish connection pool."""
        if self._running:
            logger.warning("Database already connected")
            return

        # Build connection parameters once and retry briefly during container startup.
        dsn = f"postgresql://{self.user}:{self.password}@{self.host}:{self.port}/{self.database}"
        last_error: Optional[Exception] = None

        for attempt in range(1, 11):
            try:
                self._pool = await asyncpg.create_pool(
                    dsn,
                    min_size=self.min_pool_size,
                    max_size=self.max_pool_size,
                    command_timeout=self.command_timeout,
                    ssl=self.ssl_mode != "disable",
                )
                self._running = True
                logger.info(
                    "Database connection pool created",
                    host=self.host,
                    database=self.database,
                    attempt=attempt,
                )
                return
            except Exception as e:
                last_error = e
                logger.warning(
                    "Database connection attempt failed",
                    error=str(e),
                    attempt=attempt,
                    host=self.host,
                    database=self.database,
                )
                if attempt < 10:
                    await asyncio.sleep(2)

        logger.error("Failed to connect to database", error=str(last_error))
        raise last_error

    async def close(self) -> None:
        """Close connection pool."""
        if not self._running:
            return
        self._running = False
        if self._pool:
            await self._pool.close()
            self._pool = None
        logger.info("Database connection pool closed")

    @asynccontextmanager
    async def acquire(self) -> AsyncIterator[Connection]:
        """Acquire a connection from the pool.

        Yields:
            A database connection.
        """
        if not self._pool:
            raise RuntimeError("Database not connected")
        async with self._pool.acquire() as conn:
            yield conn

    async def execute(self, query: str, *args) -> str:
        """Execute a query (INSERT, UPDATE, DELETE, etc.).

        Args:
            query: SQL query string.
            *args: Query arguments.

        Returns:
            Command status.
        """
        async with self.acquire() as conn:
            return await conn.execute(query, *args)

    async def fetch(self, query: str, *args) -> List[asyncpg.Record]:
        """Fetch all rows from a query.

        Args:
            query: SQL query string.
            *args: Query arguments.

        Returns:
            List of rows.
        """
        async with self.acquire() as conn:
            return await conn.fetch(query, *args)

    async def fetchrow(self, query: str, *args) -> Optional[asyncpg.Record]:
        """Fetch a single row from a query.

        Args:
            query: SQL query string.
            *args: Query arguments.

        Returns:
            A single row or None.
        """
        async with self.acquire() as conn:
            return await conn.fetchrow(query, *args)

    async def fetchval(self, query: str, *args) -> Any:
        """Fetch a single value from a query.

        Args:
            query: SQL query string.
            *args: Query arguments.

        Returns:
            The first column of the first row.
        """
        async with self.acquire() as conn:
            return await conn.fetchval(query, *args)

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[Connection]:
        """Start a transaction.

        Yields:
            A connection with an active transaction.
        """
        async with self.acquire() as conn:
            async with conn.transaction():
                yield conn

    async def create_tables(self) -> None:
        """Create required tables if they don't exist."""
        # Metrics table (TimescaleDB hypertable)
        metrics_table = """
        CREATE TABLE IF NOT EXISTS metrics (
            time TIMESTAMPTZ NOT NULL,
            metric_name TEXT NOT NULL,
            value DOUBLE PRECISION NOT NULL,
            tags JSONB
        );
        """
        await self.execute(metrics_table)

        # Try to create hypertable if TimescaleDB is available
        try:
            await self.execute("SELECT create_hypertable('metrics', 'time', if_not_exists => TRUE);")
            logger.info("Created hypertable for metrics")
        except Exception:
            logger.debug("TimescaleDB hypertable creation skipped (maybe not installed)")

        # Alerts table
        alerts_table = """
        CREATE TABLE IF NOT EXISTS alerts (
            id UUID PRIMARY KEY,
            alert_type TEXT NOT NULL,
            severity INTEGER NOT NULL,
            confidence FLOAT,
            target TEXT,
            details JSONB,
            created_at TIMESTAMPTZ NOT NULL,
            resolved_at TIMESTAMPTZ
        );
        """
        await self.execute(alerts_table)

        # Mitigation actions table
        actions_table = """
        CREATE TABLE IF NOT EXISTS mitigation_actions (
            id UUID PRIMARY KEY,
            alert_id UUID REFERENCES alerts(id),
            action_type TEXT NOT NULL,
            target TEXT NOT NULL,
            status TEXT NOT NULL,
            details JSONB,
            created_at TIMESTAMPTZ NOT NULL,
            rolled_back_at TIMESTAMPTZ
        );
        """
        await self.execute(actions_table)

        # Create indexes
        await self.execute("CREATE INDEX IF NOT EXISTS idx_metrics_time ON metrics (time DESC);")
        await self.execute("CREATE INDEX IF NOT EXISTS idx_metrics_name ON metrics (metric_name);")
        await self.execute("CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts (created_at DESC);")
        await self.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);")
        await self.execute("CREATE INDEX IF NOT EXISTS idx_actions_alert_id ON mitigation_actions (alert_id);")

        logger.info("Database tables created")

    async def insert_alert(self, alert: Dict[str, Any]) -> None:
        """Insert an alert into the database.

        Args:
            alert: Alert dictionary.
        """
        from uuid import UUID
        import json

        alert_id = alert.get("alert_id")
        if not alert_id:
            import uuid
            alert_id = str(uuid.uuid4())
            alert["alert_id"] = alert_id

        query = """
        INSERT INTO alerts (id, alert_type, severity, confidence, target, details, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        """
        await self.execute(
            query,
            alert_id,
            alert.get("type", "unknown"),
            alert.get("severity", 2),
            alert.get("confidence"),
            alert.get("target"),
            json.dumps(alert),
            datetime.fromtimestamp(alert.get("timestamp", datetime.now(timezone.utc).timestamp()), tz=timezone.utc),
        )

    async def insert_metric(self, name: str, value: float, tags: Optional[Dict[str, Any]] = None) -> None:
        """Insert a metric point.

        Args:
            name: Metric name.
            value: Metric value.
            tags: Optional tags.
        """
        import json
        query = """
        INSERT INTO metrics (time, metric_name, value, tags)
        VALUES (NOW(), $1, $2, $3)
        """
        await self.execute(query, name, value, json.dumps(tags) if tags else None)


# Global database instance
db = DatabaseConnection()
