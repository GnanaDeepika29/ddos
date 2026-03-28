#!/usr/bin/env python3
"""Preprocess raw network traffic data for DDoS detection.

This script reads raw packet captures or flow logs and transforms them into
feature vectors suitable for model training and inference.
"""

import argparse
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime
import logging
from tqdm import tqdm
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class DataPreprocessor:
    """Preprocess network traffic data for DDoS detection."""

    def __init__(self, window_size: int = 10):
        """Initialize preprocessor.

        Args:
            window_size: Time window in seconds for aggregating features.
        """
        self.window_size = window_size

    def load_csv(self, file_path: Path) -> pd.DataFrame:
        """Load CSV data."""
        logger.info(f"Loading {file_path}")
        return pd.read_csv(file_path)

    def load_parquet(self, file_path: Path) -> pd.DataFrame:
        """Load Parquet data."""
        logger.info(f"Loading {file_path}")
        return pd.read_parquet(file_path)

    def clean_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """Clean and validate data.

        - Remove rows with missing critical fields
        - Convert timestamps to numeric
        - Normalize IP addresses
        - Cap extreme values
        """
        logger.info("Cleaning data...")
        # Ensure timestamp is numeric
        if 'timestamp' in df.columns:
            if df['timestamp'].dtype == 'object':
                df['timestamp'] = pd.to_datetime(df['timestamp']).astype('int64') // 10**9
        else:
            # If no timestamp, create one using index
            df['timestamp'] = np.arange(len(df))

        # Fill missing numeric values with 0
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        df[numeric_cols] = df[numeric_cols].fillna(0)

        # Cap extreme values to 99th percentile
        for col in numeric_cols:
            cap = df[col].quantile(0.99)
            df[col] = df[col].clip(upper=cap)

        return df

    def compute_entropy(self, series):
        """Compute Shannon entropy of a series."""
        counts = series.value_counts()
        probs = counts / len(series)
        return -np.sum(probs * np.log2(probs + 1e-10))

    def extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract features from flow data.

        Args:
            df: DataFrame with flow records (each row is a flow).

        Returns:
            DataFrame with aggregated features per time window.
        """
        logger.info("Extracting features...")

        # Create time window index
        df['time_window'] = (df['timestamp'] // self.window_size).astype(int)

        # Aggregation functions
        agg_funcs = {
            'bytes': ['sum', 'mean', 'std'],
            'packets': ['sum', 'mean', 'std'],
            'duration': ['mean', 'std'],
        }

        # Add entropy for categorical fields if present
        categorical_fields = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol']
        for field in categorical_fields:
            if field in df.columns:
                agg_funcs[field] = [lambda x: self.compute_entropy(x)]

        # Perform aggregation
        grouped = df.groupby('time_window').agg(agg_funcs).reset_index()

        # Flatten column names
        grouped.columns = ['_'.join(col).strip() if isinstance(col, tuple) else col
                           for col in grouped.columns.values]

        # Rename entropy columns
        for field in categorical_fields:
            if field in df.columns:
                grouped.rename(columns={f"{field}_<lambda_0>": f"{field}_entropy"}, inplace=True)

        # Compute additional features
        if 'bytes_sum' in grouped.columns and 'packets_sum' in grouped.columns:
            grouped['avg_packet_size'] = grouped['bytes_sum'] / (grouped['packets_sum'] + 1)

        # Protocol ratios (if protocol available)
        if 'protocol' in df.columns:
            proto_counts = df.groupby('time_window')['protocol'].value_counts().unstack(fill_value=0)
            for proto in [6, 17, 1]:
                col_name = f'tcp_ratio' if proto == 6 else f'udp_ratio' if proto == 17 else f'icmp_ratio'
                if proto in proto_counts.columns:
                    grouped[col_name] = proto_counts[proto] / grouped['time_window_'].map(grouped['time_window_'].value_counts())
                else:
                    grouped[col_name] = 0

        # TCP flag ratios (if tcp_flags exists)
        if 'tcp_flags' in df.columns:
            flag_groups = df.groupby('time_window')['tcp_flags'].apply(lambda x: pd.Series({
                'syn_ratio': (x & 2 > 0).mean(),
                'rst_ratio': (x & 4 > 0).mean(),
                'fin_ratio': (x & 1 > 0).mean(),
                'ack_ratio': (x & 16 > 0).mean(),
            })).reset_index()
            grouped = grouped.merge(flag_groups, on='time_window', how='left')

        # Fill any NaN values with 0
        grouped = grouped.fillna(0)

        # Drop the raw time_window column (if not needed)
        if 'time_window_' in grouped.columns:
            grouped.drop('time_window_', axis=1, inplace=True)

        logger.info(f"Extracted {grouped.shape[1]} features from {len(df)} flows")
        return grouped

    def add_labels(self, features: pd.DataFrame, labels_df: pd.DataFrame, label_col: str = 'attack') -> pd.DataFrame:
        """Add attack labels to features based on time windows.

        Args:
            features: DataFrame with features per time window.
            labels_df: DataFrame with ground truth labels (must have 'timestamp' and 'attack').
            label_col: Name of the label column.

        Returns:
            Features with labels added.
        """
        # Ensure features have a timestamp column (we may have lost it)
        if 'timestamp_mean' in features.columns:
            features['timestamp'] = features['timestamp_mean']
        elif 'timestamp' in features.columns:
            features['timestamp'] = features['timestamp']

        # For each time window, find if any attack occurred within that window
        features[label_col] = 0
        if labels_df is not None and not labels_df.empty:
            for idx, row in features.iterrows():
                window_start = row['timestamp'] * self.window_size
                window_end = window_start + self.window_size
                mask = (labels_df['timestamp'] >= window_start) & (labels_df['timestamp'] < window_end)
                if mask.any():
                    features.loc[idx, label_col] = 1
        return features

    def save(self, df: pd.DataFrame, output_path: Path):
        """Save processed data."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if output_path.suffix == '.parquet':
            df.to_parquet(output_path, index=False)
        else:
            df.to_csv(output_path, index=False)
        logger.info(f"Saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Preprocess DDoS dataset")
    parser.add_argument("--input", required=True, help="Input file (CSV or Parquet)")
    parser.add_argument("--output", required=True, help="Output file (CSV or Parquet)")
    parser.add_argument("--window", type=int, default=10, help="Time window in seconds")
    parser.add_argument("--labels", help="Optional labels file (CSV)")
    parser.add_argument("--label-col", default="attack", help="Label column name")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        logger.error(f"Input file not found: {input_path}")
        sys.exit(1)

    preprocessor = DataPreprocessor(window_size=args.window)

    # Load data based on extension
    if input_path.suffix == '.csv':
        df = preprocessor.load_csv(input_path)
    elif input_path.suffix == '.parquet':
        df = preprocessor.load_parquet(input_path)
    else:
        logger.error(f"Unsupported file format: {input_path.suffix}")
        sys.exit(1)

    # Clean and preprocess
    df = preprocessor.clean_data(df)

    # Extract features
    features = preprocessor.extract_features(df)

    # Add labels if provided
    if args.labels:
        labels_path = Path(args.labels)
        if labels_path.suffix == '.csv':
            labels_df = pd.read_csv(labels_path)
        else:
            labels_df = pd.read_parquet(labels_path)
        features = preprocessor.add_labels(features, labels_df, args.label_col)

    # Save output
    output_path = Path(args.output)
    preprocessor.save(features, output_path)


if __name__ == "__main__":
    main()