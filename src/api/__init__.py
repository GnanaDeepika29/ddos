"""REST API module for DDoS Defense Platform.

This module provides a FastAPI-based REST API for:
- System status and health checks
- Alert retrieval and management
- Configuration management
- Mitigation control (enable/disable, manual overrides)
"""

from .app import app

__all__ = ["app"]