"""Feature engineering for ML-based DDoS detection.

This module provides feature extraction from raw network flows and packet
capture data, transforming them into a format suitable for machine learning
models.
"""

import numpy as np
import pandas as pd
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict, deque
import math
import time

from ...common.logging import get_logger

logger = get_logger(__name__)


class FlowFeatureExtractor:
    """Extract features from flow records for ML models."""

    def __init__(
        self,
        window_size: int = 10,  # seconds
        feature_list: Optional[List[str]] = None,
    ):
        """Initialize feature extractor.

        Args:
            window_size: Time window for aggregating flow features.
            feature_list: List of feature names to extract (if None, extract all).
        """
        self.window_size = window_size
        self.feature_list = feature_list
        self._reset_window()

    def _reset_window(self):
        """Reset the current time window."""
        self.window_start = time.time()
        self.flows_in_window = []
        self.feature_cache = {}

    def _update_window(self, flow: Dict[str, Any]):
        """Add a flow to the current window."""
        self.flows_in_window.append(flow)
        # If window expired, process it
        if time.time() - self.window_start >= self.window_size:
            return self._process_window()
        return None

    def _process_window(self) -> Optional[Dict[str, Any]]:
        """Process flows in the current window and extract features."""
        if not self.flows_in_window:
            return None

        # Convert to DataFrame for easier aggregation
        df = pd.DataFrame(self.flows_in_window)

        features = {}

        # Basic volume features
        features['total_bytes'] = df['bytes'].sum() if 'bytes' in df else 0
        features['total_packets'] = df['packets'].sum() if 'packets' in df else 0
        features['avg_bytes_per_packet'] = features['total_bytes'] / max(features['total_packets'], 1)
        features['flow_count'] = len(df)

        # Rate features
        features['bytes_per_second'] = features['total_bytes'] / self.window_size
        features['packets_per_second'] = features['total_packets'] / self.window_size
        features['flows_per_second'] = features['flow_count'] / self.window_size

        # Protocol distribution
        if 'protocol' in df:
            proto_counts = df['protocol'].value_counts().to_dict()
            features['tcp_ratio'] = proto_counts.get(6, 0) / max(features['flow_count'], 1)
            features['udp_ratio'] = proto_counts.get(17, 0) / max(features['flow_count'], 1)
            features['icmp_ratio'] = proto_counts.get(1, 0) / max(features['flow_count'], 1)

        # Packet size statistics
        if 'packet_size' in df:
            sizes = df['packet_size']
            features['packet_size_mean'] = sizes.mean()
            features['packet_size_std'] = sizes.std()
            features['packet_size_min'] = sizes.min()
            features['packet_size_max'] = sizes.max()
            # Small packet ratio (e.g., < 64 bytes)
            features['small_packet_ratio'] = (sizes < 64).sum() / max(len(sizes), 1)

        # Duration statistics (if flows have duration)
        if 'duration' in df:
            durations = df['duration']
            features['duration_mean'] = durations.mean()
            features['duration_std'] = durations.std()
            features['duration_min'] = durations.min()
            features['duration_max'] = durations.max()

        # Inter-arrival time statistics (if timestamps available)
        if 'timestamp' in df:
            times = df['timestamp'].sort_values().values
            if len(times) > 1:
                inter_arrival = np.diff(times)
                features['inter_arrival_mean'] = inter_arrival.mean()
                features['inter_arrival_std'] = inter_arrival.std()
            else:
                features['inter_arrival_mean'] = 0
                features['inter_arrival_std'] = 0

        # Entropy features (source/destination IPs, ports)
        if 'src_ip' in df:
            features['src_ip_entropy'] = self._compute_entropy(df['src_ip'])
        if 'dst_ip' in df:
            features['dst_ip_entropy'] = self._compute_entropy(df['dst_ip'])
        if 'src_port' in df:
            features['src_port_entropy'] = self._compute_entropy(df['src_port'])
        if 'dst_port' in df:
            features['dst_port_entropy'] = self._compute_entropy(df['dst_port'])

        # TCP flag features
        if 'tcp_flags' in df:
            # SYN, RST, FIN, ACK flags
            tcp_flags = df['tcp_flags']
            features['syn_ratio'] = ((tcp_flags & 0x02) > 0).sum() / max(len(tcp_flags), 1)
            features['rst_ratio'] = ((tcp_flags & 0x04) > 0).sum() / max(len(tcp_flags), 1)
            features['fin_ratio'] = ((tcp_flags & 0x01) > 0).sum() / max(len(tcp_flags), 1)
            features['ack_ratio'] = ((tcp_flags & 0x10) > 0).sum() / max(len(tcp_flags), 1)

        # Unique IP counts
        if 'src_ip' in df:
            features['unique_src_ips'] = df['src_ip'].nunique()
            features['unique_src_ips_ratio'] = features['unique_src_ips'] / max(features['flow_count'], 1)
        if 'dst_ip' in df:
            features['unique_dst_ips'] = df['dst_ip'].nunique()
            features['unique_dst_ips_ratio'] = features['unique_dst_ips'] / max(features['flow_count'], 1)

        # Port range features (well-known vs ephemeral)
        if 'dst_port' in df:
            # Count of well-known ports (< 1024)
            well_known = (df['dst_port'] < 1024).sum()
            features['well_known_port_ratio'] = well_known / max(features['flow_count'], 1)

        # Subset features if requested
        if self.feature_list:
            features = {k: v for k, v in features.items() if k in self.feature_list}

        # Reset window for next batch
        self._reset_window()
        return features

    def _compute_entropy(self, series: pd.Series) -> float:
        """Compute Shannon entropy of a series."""
        counts = series.value_counts()
        total = counts.sum()
        if total == 0:
            return 0.0
        entropy = 0.0
        for cnt in counts:
            p = cnt / total
            entropy -= p * math.log2(p)
        return entropy

    def extract_features(self, flow: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract features from a single flow (aggregates over window)."""
        return self._update_window(flow)


class PacketFeatureExtractor:
    """Extract features from raw packets (low-level)."""

    def __init__(
        self,
        window_size: int = 5,  # seconds
        feature_list: Optional[List[str]] = None,
    ):
        self.window_size = window_size
        self.feature_list = feature_list
        self._reset_window()

    def _reset_window(self):
        self.window_start = time.time()
        self.packets_in_window = []

    def _process_window(self) -> Optional[Dict[str, Any]]:
        if not self.packets_in_window:
            return None

        df = pd.DataFrame(self.packets_in_window)

        features = {}
        features['packet_count'] = len(df)

        # Size features
        if 'length' in df:
            lengths = df['length']
            features['size_mean'] = lengths.mean()
            features['size_std'] = lengths.std()
            features['size_min'] = lengths.min()
            features['size_max'] = lengths.max()

        # Rate
        features['packets_per_second'] = features['packet_count'] / self.window_size

        # Protocol distribution
        if 'protocol' in df:
            proto_counts = df['protocol'].value_counts().to_dict()
            features['tcp_ratio'] = proto_counts.get(6, 0) / max(features['packet_count'], 1)
            features['udp_ratio'] = proto_counts.get(17, 0) / max(features['packet_count'], 1)
            features['icmp_ratio'] = proto_counts.get(1, 0) / max(features['packet_count'], 1)

        # TCP flag distribution (if available)
        if 'tcp_flags' in df:
            flags = df['tcp_flags']
            features['syn_ratio'] = ((flags & 0x02) > 0).sum() / max(features['packet_count'], 1)
            features['rst_ratio'] = ((flags & 0x04) > 0).sum() / max(features['packet_count'], 1)

        # Subset
        if self.feature_list:
            features = {k: v for k, v in features.items() if k in self.feature_list}

        self._reset_window()
        return features

    def extract_features(self, packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        self.packets_in_window.append(packet)
        if time.time() - self.window_start >= self.window_size:
            return self._process_window()
        return None


def extract_flow_features(flows: List[Dict[str, Any]]) -> pd.DataFrame:
    """Extract features from a list of flows (batch processing).

    Args:
        flows: List of flow dictionaries.

    Returns:
        DataFrame with features.
    """
    if not flows:
        return pd.DataFrame()

    df = pd.DataFrame(flows)

    # Create feature dictionary
    features = {}

    # Volume features
    features['total_bytes'] = df['bytes'].sum() if 'bytes' in df else 0
    features['total_packets'] = df['packets'].sum() if 'packets' in df else 0
    features['flow_count'] = len(df)

    # Rate features
    time_range = df['timestamp'].max() - df['timestamp'].min() if 'timestamp' in df else 1
    features['bytes_per_second'] = features['total_bytes'] / max(time_range, 0.001)
    features['packets_per_second'] = features['total_packets'] / max(time_range, 0.001)

    # Protocol distribution
    if 'protocol' in df:
        proto_counts = df['protocol'].value_counts()
        features['tcp_count'] = proto_counts.get(6, 0)
        features['udp_count'] = proto_counts.get(17, 0)
        features['icmp_count'] = proto_counts.get(1, 0)

    # Port entropy
    for port_field in ['src_port', 'dst_port']:
        if port_field in df:
            entropy = 0.0
            counts = df[port_field].value_counts()
            total = len(df)
            for cnt in counts:
                p = cnt / total
                entropy -= p * math.log2(p)
            features[f'{port_field}_entropy'] = entropy

    # IP entropy
    for ip_field in ['src_ip', 'dst_ip']:
        if ip_field in df:
            entropy = 0.0
            counts = df[ip_field].value_counts()
            total = len(df)
            for cnt in counts:
                p = cnt / total
                entropy -= p * math.log2(p)
            features[f'{ip_field}_entropy'] = entropy

    return pd.DataFrame([features])