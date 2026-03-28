"""Mitigation module for automated DDoS response.

This module provides automated mitigation actions including:
- Rate limiting (per IP, per subnet)
- BGP route announcements for traffic scrubbing
- SDN flow rule injection
- Cloud provider integration (AWS Security Groups, Azure NSG, GCP Firewall)
- Blacklist/whitelist management
- Rollback mechanisms
"""

from .orchestrator import MitigationOrchestrator
from .actions import (
    RateLimiter,
    BGPRouteAnnouncer,
    SDNController,
    CloudSecurityGroups,
    BlacklistManager,
)
from .rollback import RollbackManager

__all__ = [
    "MitigationOrchestrator",
    "RateLimiter",
    "BGPRouteAnnouncer",
    "SDNController",
    "CloudSecurityGroups",
    "BlacklistManager",
    "RollbackManager",
]