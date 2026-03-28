"""Machine learning detection submodule.

This package coexists with the legacy module at ``src/detection/ml.py``.
Load that module explicitly so ``src.detection.ml`` continues to expose the
runtime detector classes while this package exposes training/feature helpers.
"""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

_legacy_ml_path = Path(__file__).resolve().parents[1] / "ml.py"
_legacy_ml_spec = spec_from_file_location("src.detection._legacy_ml", _legacy_ml_path)
if _legacy_ml_spec is None or _legacy_ml_spec.loader is None:
    raise ImportError(f"Unable to load ML runtime module from {_legacy_ml_path}")

_legacy_ml = module_from_spec(_legacy_ml_spec)
_legacy_ml_spec.loader.exec_module(_legacy_ml)

MLDetector = _legacy_ml.MLDetector
FeatureExtractor = _legacy_ml.FeatureExtractor

from .trainer import ModelTrainer
from .features import FlowFeatureExtractor, PacketFeatureExtractor, extract_flow_features

__all__ = [
    "MLDetector",
    "FeatureExtractor",
    "ModelTrainer",
    "FlowFeatureExtractor",
    "PacketFeatureExtractor",
    "extract_flow_features",
]
