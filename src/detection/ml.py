"""Machine learning-based DDoS detection.

This module implements ML-based detection using pre-trained models
(Random Forest, XGBoost, Neural Networks) for flow-based classification.
"""

import asyncio
import joblib
import numpy as np
import time
from typing import Optional, Dict, Any, List, Tuple
from collections import deque
import json
import os

import structlog

from ..common.logging import get_logger
from ..common.metrics import metrics
from ..common.kafka_consumer import KafkaConsumerHelper

logger = get_logger(__name__)

# Optional deep learning imports
try:
    import tensorflow as tf
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False

try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False


class FeatureExtractor:
    """Extract features from flows for ML models."""

    def __init__(self, feature_names: List[str]):
        self.feature_names = feature_names

    def extract(self, flow: Dict[str, Any]) -> np.ndarray:
        """Extract feature vector from a flow dict."""
        # Map flow fields to feature vector
        features = []
        for name in self.feature_names:
            value = flow.get(name, 0.0)
            # Handle missing values
            if value is None:
                value = 0.0
            features.append(float(value))
        return np.array(features).reshape(1, -1)


class MLDetector:
    """Machine learning detector for DDoS attacks."""

    def __init__(
        self,
        model_path: str,
        feature_extractor_path: Optional[str] = None,
        input_topic: str = "telemetry.flows",
        output_topic: str = "detection.ml.alerts",
        bootstrap_servers: Optional[List[str]] = None,
        batch_size: int = 100,
        batch_timeout_ms: int = 1000,
        confidence_threshold: float = 0.85,
        inference_mode: str = "batch",  # sync, async, batch
    ):
        """Initialize ML detector.

        Args:
            model_path: Path to trained model file (joblib, h5, or pt).
            feature_extractor_path: Path to feature extractor (optional).
            input_topic: Kafka topic for flow data.
            output_topic: Kafka topic for alerts.
            bootstrap_servers: Kafka broker list.
            batch_size: Number of flows per batch.
            batch_timeout_ms: Batch timeout.
            confidence_threshold: Minimum confidence to generate alert.
            inference_mode: sync, async, or batch.
        """
        self.model_path = model_path
        self.feature_extractor_path = feature_extractor_path
        self.input_topic = input_topic
        self.output_topic = output_topic
        self.bootstrap_servers = bootstrap_servers or ["localhost:9092"]
        self.batch_size = batch_size
        self.batch_timeout_ms = batch_timeout_ms
        self.confidence_threshold = confidence_threshold
        self.inference_mode = inference_mode

        self._running = False
        self._consumer: Optional[KafkaConsumerHelper] = None
        self._model = None
        self._feature_extractor: Optional[FeatureExtractor] = None
        self._feature_names: List[str] = []
        self._model_type = None  # 'sklearn', 'tensorflow', 'pytorch'
        self._stats = {
            "flows_processed": 0,
            "alerts_generated": 0,
            "inference_time_ms": 0,
            "errors": 0,
        }

    def _load_model(self):
        """Load the ML model from disk."""
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(f"Model file not found: {self.model_path}")

        # Try to load based on extension
        if self.model_path.endswith('.joblib') or self.model_path.endswith('.pkl'):
            self._model = joblib.load(self.model_path)
            self._model_type = 'sklearn'
            logger.info("Loaded scikit-learn model", path=self.model_path)
        elif self.model_path.endswith('.h5'):
            if not TF_AVAILABLE:
                raise ImportError("TensorFlow not available for .h5 model")
            self._model = tf.keras.models.load_model(self.model_path)
            self._model_type = 'tensorflow'
            logger.info("Loaded TensorFlow model", path=self.model_path)
        elif self.model_path.endswith('.pt') or self.model_path.endswith('.pth'):
            if not TORCH_AVAILABLE:
                raise ImportError("PyTorch not available for .pt model")
            self._model = torch.load(self.model_path, map_location='cpu')
            self._model.eval()
            self._model_type = 'pytorch'
            logger.info("Loaded PyTorch model", path=self.model_path)
        else:
            raise ValueError(f"Unsupported model format: {self.model_path}")

        # Load feature extractor
        if self.feature_extractor_path and os.path.exists(self.feature_extractor_path):
            extractor_data = joblib.load(self.feature_extractor_path)
            if isinstance(extractor_data, dict):
                self._feature_names = extractor_data.get('feature_names', [])
                # Also could include scaler, etc.
            elif isinstance(extractor_data, list):
                self._feature_names = extractor_data
            self._feature_extractor = FeatureExtractor(self._feature_names)
            logger.info("Loaded feature extractor", features=len(self._feature_names))
        else:
            # Assume model has a feature_importances_ or similar
            if hasattr(self._model, 'feature_importances_'):
                # We don't know feature names, just use indices
                self._feature_names = [f"feature_{i}" for i in range(len(self._model.feature_importances_))]
            else:
                # Placeholder - user must provide feature extractor
                self._feature_names = []
            self._feature_extractor = FeatureExtractor(self._feature_names)

    async def _predict_sklearn(self, features: np.ndarray) -> Tuple[int, float]:
        """Predict using scikit-learn model."""
        start = time.time()
        if hasattr(self._model, 'predict_proba'):
            proba = self._model.predict_proba(features)
            # Assuming binary classification: class 1 = attack
            attack_prob = proba[0][1] if proba.shape[1] > 1 else proba[0][0]
            pred = 1 if attack_prob >= self.confidence_threshold else 0
        else:
            pred = self._model.predict(features)[0]
            attack_prob = float(pred)
        elapsed = (time.time() - start) * 1000
        return pred, attack_prob, elapsed

    async def _predict_tensorflow(self, features: np.ndarray) -> Tuple[int, float]:
        """Predict using TensorFlow model."""
        start = time.time()
        result = self._model.predict(features, verbose=0)
        if result.shape[-1] == 2:
            attack_prob = float(result[0][1])
            pred = 1 if attack_prob >= self.confidence_threshold else 0
        else:
            attack_prob = float(result[0])
            pred = 1 if attack_prob >= self.confidence_threshold else 0
        elapsed = (time.time() - start) * 1000
        return pred, attack_prob, elapsed

    async def _predict_pytorch(self, features: np.ndarray) -> Tuple[int, float]:
        """Predict using PyTorch model."""
        start = time.time()
        with torch.no_grad():
            input_tensor = torch.from_numpy(features).float()
            output = self._model(input_tensor)
            if output.shape[-1] == 2:
                proba = torch.softmax(output, dim=1)
                attack_prob = float(proba[0][1])
            else:
                attack_prob = float(torch.sigmoid(output)[0])
            pred = 1 if attack_prob >= self.confidence_threshold else 0
        elapsed = (time.time() - start) * 1000
        return pred, attack_prob, elapsed

    async def _predict(self, features: np.ndarray) -> Tuple[int, float, float]:
        """Dispatch prediction based on model type."""
        if self._model_type == 'sklearn':
            return await self._predict_sklearn(features)
        elif self._model_type == 'tensorflow':
            return await self._predict_tensorflow(features)
        elif self._model_type == 'pytorch':
            return await self._predict_pytorch(features)
        else:
            raise ValueError(f"Unknown model type: {self._model_type}")

    async def _process_flow(self, flow: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process a single flow, return alert if attack detected."""
        try:
            # Extract features
            if not self._feature_extractor:
                logger.warning("No feature extractor available")
                return None
            features = self._feature_extractor.extract(flow)
            if features is None or features.size == 0:
                return None

            # Predict
            pred, confidence, inference_ms = await self._predict(features)

            # Update stats
            self._stats["inference_time_ms"] += inference_ms

            if pred == 1 and confidence >= self.confidence_threshold:
                # Generate alert
                alert = {
                    "type": "ml_detection",
                    "model": os.path.basename(self.model_path),
                    "confidence": confidence,
                    "flow": flow,
                    "timestamp": time.time(),
                    "severity": 3 if confidence > 0.95 else 2,
                }
                return alert
        except Exception as e:
            logger.error("ML inference error", error=str(e))
            self._stats["errors"] += 1
        return None

    async def _process_batch(self, messages: List[Dict[str, Any]]):
        """Process a batch of flows."""
        alerts = []
        for msg in messages:
            alert = await self._process_flow(msg)
            if alert:
                alerts.append(alert)

        if alerts:
            self._stats["alerts_generated"] += len(alerts)
            metrics.alerts_total.inc(len(alerts))
            if self._consumer and self._consumer.producer:
                await self._consumer.producer.send_batch(
                    topic=self.output_topic,
                    messages=alerts,
                )

        self._stats["flows_processed"] += len(messages)

    async def start(self):
        """Start the ML detector."""
        if self._running:
            logger.warning("ML detector already running")
            return

        self._running = True

        # Load model and feature extractor
        try:
            self._load_model()
        except Exception as e:
            logger.error("Failed to load ML model", error=str(e))
            raise

        # Initialize Kafka consumer
        self._consumer = KafkaConsumerHelper(
            bootstrap_servers=self.bootstrap_servers,
            topic=self.input_topic,
            group_id="ml-detector",
            batch_size=self.batch_size,
            batch_timeout_ms=self.batch_timeout_ms,
        )
        await self._consumer.start()

        # Main processing loop
        try:
            async for batch in self._consumer.consume_batches():
                if not self._running:
                    break
                await self._process_batch(batch)
        except asyncio.CancelledError:
            logger.info("ML detector cancelled")
        finally:
            await self.stop()

    async def stop(self):
        """Stop the ML detector."""
        if not self._running:
            return
        self._running = False
        if self._consumer:
            await self._consumer.stop()
        logger.info("ML detector stopped")

    def get_stats(self) -> Dict[str, Any]:
        """Get detector statistics."""
        stats = self._stats.copy()
        if self._stats["flows_processed"] > 0:
            stats["avg_inference_ms"] = self._stats["inference_time_ms"] / self._stats["flows_processed"]
        return stats