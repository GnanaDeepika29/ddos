"""Unit tests for common utilities."""

import pytest
import asyncio
import os
import tempfile
import yaml
from unittest.mock import patch, MagicMock, AsyncMock
import structlog

from src.common.logging import setup_logging, get_logger
from src.common.config import load_config, deep_merge, substitute_env_vars
from src.common.metrics import Metrics
from src.common.database import DatabaseConnection


class TestLogging:
    """Test logging setup."""

    def test_setup_logging_development(self):
        """Test logging setup in development mode."""
        setup_logging(level="DEBUG", json_output=False)
        logger = get_logger("test")
        assert logger is not None
        # Should not raise exceptions
        logger.info("Test log message")

    def test_setup_logging_production(self):
        """Test logging setup in production mode (JSON)."""
        setup_logging(level="INFO", json_output=True)
        logger = get_logger("test")
        assert logger is not None
        logger.info("Test JSON log")


class TestConfig:
    """Test configuration loading and utilities."""

    def test_deep_merge(self):
        base = {"a": 1, "b": {"c": 2, "d": 3}}
        override = {"b": {"c": 4}, "e": 5}
        result = deep_merge(base, override)
        assert result["a"] == 1
        assert result["b"]["c"] == 4
        assert result["b"]["d"] == 3
        assert result["e"] == 5

    def test_substitute_env_vars(self):
        with patch.dict(os.environ, {"TEST_VAR": "hello"}):
            obj = {"key": "${TEST_VAR}", "nested": {"inner": "prefix_${TEST_VAR}_suffix"}}
            result = substitute_env_vars(obj)
            assert result["key"] == "hello"
            assert result["nested"]["inner"] == "prefix_hello_suffix"

    def test_load_config(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump({"test": "value", "env": "${ENV_TEST}"}, f)
            f.close()
            with patch.dict(os.environ, {"ENV_TEST": "prod"}):
                config = load_config(f.name, env="dev")
                assert config["test"] == "value"
                # Environment substitution happens
                assert config["env"] == "prod"
            os.unlink(f.name)

    def test_load_config_with_env_override(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f_base:
            yaml.dump({"base": "value"}, f_base)
            f_base.close()
            base_path = f_base.name
            base_dir = os.path.dirname(base_path)
            dev_path = os.path.join(base_dir, "dev.yaml")
            with open(dev_path, "w") as f_dev:
                yaml.dump({"override": "dev_value"}, f_dev)
            config = load_config(base_path, env="dev")
            assert config["base"] == "value"
            assert config["override"] == "dev_value"
            os.unlink(base_path)
            os.unlink(dev_path)


class TestMetrics:
    """Test metrics collection."""

    def test_metrics_initialization(self):
        metrics = Metrics()
        assert metrics.packets_total is not None
        assert metrics.flows_total is not None
        assert metrics.alerts_total is not None

    def test_record_attack(self):
        metrics = Metrics()
        metrics.record_attack("volumetric", 3)
        # Just test that no exception is raised
        # In production with Prometheus, this would increment a counter


@pytest.mark.asyncio
class TestDatabase:
    """Test database connection utilities."""

    @pytest.fixture
    def db(self):
        return DatabaseConnection(
            host="localhost",
            port=5432,
            database="test_db",
            user="test_user",
            password="test_pass",
            min_pool_size=1,
            max_pool_size=2,
        )

    @patch("asyncpg.create_pool")
    async def test_connect(self, mock_create_pool, db):
        mock_pool = AsyncMock()
        mock_create_pool.return_value = mock_pool
        await db.connect()
        assert db._running is True
        assert db._pool is not None
        await db.close()
        mock_pool.close.assert_called_once()

    @patch("asyncpg.create_pool")
    async def test_execute(self, mock_create_pool, db):
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_pool.acquire.return_value.__aenter__.return_value = mock_conn
        mock_create_pool.return_value = mock_pool
        await db.connect()
        result = await db.execute("SELECT 1")
        mock_conn.execute.assert_called_once_with("SELECT 1")
        await db.close()

    @patch("asyncpg.create_pool")
    async def test_transaction(self, mock_create_pool, db):
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_pool.acquire.return_value.__aenter__.return_value = mock_conn
        mock_create_pool.return_value = mock_pool
        await db.connect()
        async with db.transaction():
            # Inside transaction
            pass
        mock_conn.transaction.assert_called_once()
        await db.close()