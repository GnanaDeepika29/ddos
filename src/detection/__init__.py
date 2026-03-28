"""Detection module for DDoS attack identification.

This module provides multi-layered detection capabilities including:
- Signature-based detection (Snort/Suricata rules)
- Statistical anomaly detection (entropy, thresholds, time-series)
- Machine learning detection (ensemble models, deep learning)

The detection engine combines results from all detectors using a weighted
ensemble approach to generate alerts for the mitigation system.
"""

from .signature import SignatureDetector
from .anomaly import AnomalyDetector
from .ensemble import EnsembleDetector
from .alert_generator import AlertGenerator

try:
    from .ml import MLDetector
except ImportError:
    MLDetector = None

__all__ = [
    "SignatureDetector",
    "AnomalyDetector",
    "MLDetector",
    "EnsembleDetector",
    "AlertGenerator",
]
