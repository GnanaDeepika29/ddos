"""Model training pipeline for ML-based DDoS detection.

This module handles offline training of machine learning models using
historical data, with support for multiple algorithms and hyperparameter
tuning.
"""

import os
import json
import pickle
import joblib
import numpy as np
import pandas as pd
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime
from pathlib import Path
import logging

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score
import xgboost as xgb

from ...common.logging import get_logger
from ...common.config import load_config

logger = get_logger(__name__)


class ModelTrainer:
    """Train and evaluate DDoS detection models."""

    def __init__(
        self,
        data_path: str,
        model_output_dir: str = "/opt/ddos-defense/models",
        feature_list: Optional[List[str]] = None,
        target_column: str = "attack_label",
        test_size: float = 0.2,
        val_size: float = 0.1,
        random_state: int = 42,
        n_jobs: int = -1,
    ):
        """Initialize trainer.

        Args:
            data_path: Path to training data (CSV, Parquet).
            model_output_dir: Directory to save models.
            feature_list: List of feature column names (if None, use all except target).
            target_column: Name of the target column.
            test_size: Proportion of data for testing.
            val_size: Proportion of data for validation (from remaining after test).
            random_state: Random seed for reproducibility.
            n_jobs: Number of parallel jobs for training.
        """
        self.data_path = Path(data_path)
        self.model_output_dir = Path(model_output_dir)
        self.feature_list = feature_list
        self.target_column = target_column
        self.test_size = test_size
        self.val_size = val_size
        self.random_state = random_state
        self.n_jobs = n_jobs

        self.X_train: Optional[np.ndarray] = None
        self.X_val: Optional[np.ndarray] = None
        self.X_test: Optional[np.ndarray] = None
        self.y_train: Optional[np.ndarray] = None
        self.y_val: Optional[np.ndarray] = None
        self.y_test: Optional[np.ndarray] = None
        self.scaler: Optional[object] = None
        self.feature_names: Optional[List[str]] = None

        self.model_output_dir.mkdir(parents=True, exist_ok=True)

    def load_data(self) -> pd.DataFrame:
        """Load dataset from file."""
        logger.info(f"Loading data from {self.data_path}")
        if self.data_path.suffix == '.csv':
            df = pd.read_csv(self.data_path)
        elif self.data_path.suffix == '.parquet':
            df = pd.read_parquet(self.data_path)
        else:
            raise ValueError(f"Unsupported file format: {self.data_path.suffix}")

        logger.info(f"Loaded {len(df)} rows, {len(df.columns)} columns")
        return df

    def preprocess(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Preprocess data: feature selection, scaling, train/val/test split."""
        # Separate features and target
        if self.feature_list is None:
            self.feature_names = [c for c in df.columns if c != self.target_column]
        else:
            self.feature_names = self.feature_list
            # Ensure all features exist
            missing = set(self.feature_names) - set(df.columns)
            if missing:
                raise ValueError(f"Missing features: {missing}")

        X = df[self.feature_names].values
        y = df[self.target_column].values

        # Split: first separate test set
        X_temp, X_test, y_temp, y_test = train_test_split(
            X, y, test_size=self.test_size, random_state=self.random_state, stratify=y
        )
        # Then split temp into train and validation
        val_ratio = self.val_size / (1 - self.test_size)
        X_train, X_val, y_train, y_val = train_test_split(
            X_temp, y_temp, test_size=val_ratio, random_state=self.random_state, stratify=y_temp
        )

        logger.info(f"Train size: {len(X_train)}, Val size: {len(X_val)}, Test size: {len(X_test)}")

        # Scale features
        self.scaler = RobustScaler()  # Robust to outliers
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_val_scaled = self.scaler.transform(X_val)
        X_test_scaled = self.scaler.transform(X_test)

        self.X_train, self.y_train = X_train_scaled, y_train
        self.X_val, self.y_val = X_val_scaled, y_val
        self.X_test, self.y_test = X_test_scaled, y_test

        return X_train_scaled, y_train

    def train_random_forest(self, **kwargs) -> RandomForestClassifier:
        """Train a Random Forest classifier."""
        logger.info("Training Random Forest...")
        params = {
            'n_estimators': kwargs.get('n_estimators', 200),
            'max_depth': kwargs.get('max_depth', 20),
            'min_samples_split': kwargs.get('min_samples_split', 5),
            'min_samples_leaf': kwargs.get('min_samples_leaf', 2),
            'max_features': kwargs.get('max_features', 'sqrt'),
            'class_weight': kwargs.get('class_weight', 'balanced'),
            'n_jobs': self.n_jobs,
            'random_state': self.random_state,
        }
        model = RandomForestClassifier(**params)
        model.fit(self.X_train, self.y_train)
        logger.info("Random Forest training completed")
        return model

    def train_xgboost(self, **kwargs) -> xgb.XGBClassifier:
        """Train an XGBoost classifier."""
        logger.info("Training XGBoost...")
        params = {
            'n_estimators': kwargs.get('n_estimators', 200),
            'max_depth': kwargs.get('max_depth', 10),
            'learning_rate': kwargs.get('learning_rate', 0.1),
            'subsample': kwargs.get('subsample', 0.8),
            'colsample_bytree': kwargs.get('colsample_bytree', 0.8),
            'scale_pos_weight': kwargs.get('scale_pos_weight', 1),
            'random_state': self.random_state,
            'n_jobs': self.n_jobs,
        }
        model = xgb.XGBClassifier(**params)
        model.fit(self.X_train, self.y_train)
        logger.info("XGBoost training completed")
        return model

    def evaluate_model(self, model, X, y, name: str = "model") -> Dict[str, Any]:
        """Evaluate model on given dataset."""
        y_pred = model.predict(X)
        # For probabilities, if available
        if hasattr(model, 'predict_proba'):
            y_proba = model.predict_proba(X)[:, 1]
        else:
            y_proba = None

        metrics = {
            'precision': precision_score(y, y_pred, average='weighted'),
            'recall': recall_score(y, y_pred, average='weighted'),
            'f1': f1_score(y, y_pred, average='weighted'),
            'classification_report': classification_report(y, y_pred, output_dict=True),
            'confusion_matrix': confusion_matrix(y, y_pred).tolist(),
        }
        if y_proba is not None:
            from sklearn.metrics import roc_auc_score
            metrics['auc_roc'] = roc_auc_score(y, y_proba)

        logger.info(f"{name} evaluation: F1={metrics['f1']:.4f}, AUC={metrics.get('auc_roc', 0):.4f}")
        return metrics

    def hyperparameter_tuning(self, model_type: str, X, y, param_grid: Dict, cv: int = 3) -> object:
        """Perform grid search for hyperparameter tuning."""
        logger.info(f"Hyperparameter tuning for {model_type}")
        if model_type == 'rf':
            base_model = RandomForestClassifier(random_state=self.random_state, n_jobs=self.n_jobs)
        elif model_type == 'xgb':
            base_model = xgb.XGBClassifier(random_state=self.random_state, n_jobs=self.n_jobs)
        else:
            raise ValueError(f"Unknown model type: {model_type}")

        grid_search = GridSearchCV(
            base_model, param_grid, cv=cv, scoring='f1_weighted', n_jobs=self.n_jobs, verbose=1
        )
        grid_search.fit(X, y)
        logger.info(f"Best parameters: {grid_search.best_params_}")
        logger.info(f"Best score: {grid_search.best_score_:.4f}")
        return grid_search.best_estimator_

    def save_model(self, model, name: str, metadata: Optional[Dict] = None):
        """Save model and associated artifacts."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        model_path = self.model_output_dir / f"{name}_{timestamp}.joblib"
        scaler_path = self.model_output_dir / f"scaler_{name}_{timestamp}.joblib"
        metadata_path = self.model_output_dir / f"metadata_{name}_{timestamp}.json"

        # Save model
        joblib.dump(model, model_path)
        logger.info(f"Model saved to {model_path}")

        # Save scaler
        joblib.dump(self.scaler, scaler_path)
        logger.info(f"Scaler saved to {scaler_path}")

        # Save metadata
        meta = {
            'name': name,
            'timestamp': timestamp,
            'feature_names': self.feature_names,
            'target_column': self.target_column,
            'metadata': metadata or {},
        }
        with open(metadata_path, 'w') as f:
            json.dump(meta, f, indent=2)

        # Also create a symlink to "latest"
        latest_model = self.model_output_dir / f"{name}_latest.joblib"
        latest_scaler = self.model_output_dir / f"scaler_{name}_latest.joblib"
        latest_meta = self.model_output_dir / f"metadata_{name}_latest.json"
        if latest_model.exists():
            latest_model.unlink()
        if latest_scaler.exists():
            latest_scaler.unlink()
        if latest_meta.exists():
            latest_meta.unlink()
        latest_model.symlink_to(model_path.name)
        latest_scaler.symlink_to(scaler_path.name)
        latest_meta.symlink_to(metadata_path.name)

        return {'model_path': str(model_path), 'scaler_path': str(scaler_path), 'metadata': meta}

    def run_pipeline(self, model_type: str = 'rf', tune: bool = False) -> Dict[str, Any]:
        """Run full training pipeline.

        Args:
            model_type: Type of model ('rf' or 'xgb').
            tune: Whether to perform hyperparameter tuning.

        Returns:
            Dictionary with results and paths.
        """
        # Load data
        df = self.load_data()

        # Preprocess
        self.preprocess(df)

        # Optionally tune
        if tune:
            if model_type == 'rf':
                param_grid = {
                    'n_estimators': [100, 200, 300],
                    'max_depth': [10, 20, 30],
                    'min_samples_split': [2, 5, 10],
                }
            else:  # xgb
                param_grid = {
                    'n_estimators': [100, 200],
                    'max_depth': [5, 10, 15],
                    'learning_rate': [0.01, 0.1, 0.2],
                }
            model = self.hyperparameter_tuning(model_type, self.X_train, self.y_train, param_grid)
        else:
            if model_type == 'rf':
                model = self.train_random_forest()
            else:
                model = self.train_xgboost()

        # Evaluate on validation set
        val_metrics = self.evaluate_model(model, self.X_val, self.y_val, name="Validation")

        # Optionally evaluate on test set
        test_metrics = self.evaluate_model(model, self.X_test, self.y_test, name="Test")

        # Save model
        save_result = self.save_model(model, model_type, metadata={
            'val_metrics': val_metrics,
            'test_metrics': test_metrics,
            'tuned': tune,
        })

        return {
            'model': model,
            'scaler': self.scaler,
            'val_metrics': val_metrics,
            'test_metrics': test_metrics,
            'saved': save_result,
        }


def main():
    """Entry point for training script."""
    import argparse
    parser = argparse.ArgumentParser(description="Train DDoS detection models")
    parser.add_argument("--data", required=True, help="Path to training data")
    parser.add_argument("--output", default="/opt/ddos-defense/models", help="Output directory")
    parser.add_argument("--model", choices=["rf", "xgb"], default="rf", help="Model type")
    parser.add_argument("--tune", action="store_true", help="Perform hyperparameter tuning")
    parser.add_argument("--config", default="config/default.yaml", help="Config file")
    args = parser.parse_args()

    config = load_config(args.config)
    trainer = ModelTrainer(
        data_path=args.data,
        model_output_dir=args.output,
        feature_list=config.get("detection", {}).get("ml", {}).get("features"),
    )
    result = trainer.run_pipeline(model_type=args.model, tune=args.tune)
    print(json.dumps(result['saved'], indent=2))


if __name__ == "__main__":
    main()