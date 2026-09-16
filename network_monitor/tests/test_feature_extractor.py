"""
Unit tests for Feature Extractor and ML Predictor integration.
Verifies:
1. Normal synthetic flow object
2. Flow with no backward packets
3. Flow with only one packet
4. Flow with zero duration
5. Flow with missing TCP flags (e.g. UDP)
6. Division-by-zero situations
7. Zero NaN/Infinity in outputs
8. Exactly 20 features, exact names, exact order
9. Validated Decision Tree model prediction compatibility
"""

import sys
import types

# Windows Application Control compatibility fix for scipy.spatial
if "scipy.spatial._ckdtree" not in sys.modules:
    try:
        import scipy.spatial._ckdtree  # noqa: F401
    except ImportError:
        dummy_ckdtree = types.ModuleType("scipy.spatial._ckdtree")
        dummy_ckdtree.cKDTree = object
        dummy_ckdtree.cKDTreeNode = object
        sys.modules["scipy.spatial._ckdtree"] = dummy_ckdtree

import unittest
import math
import numpy as np
import pandas as pd

from network_monitor.config import TOP_20_FEATURES, MODEL_PATH
from network_monitor.flow_tracker import NetworkFlow, FlowTracker
from network_monitor.feature_extractor import extract_features
from network_monitor.ml_predictor import MLPredictor


class TestFeatureExtractor(unittest.TestCase):
    """Test suite for feature extraction and edge case stability."""

    @classmethod
    def setUpClass(cls):
        """Loads predictor once for model compatibility assertions."""
        cls.predictor = MLPredictor(model_path=MODEL_PATH)

    def _assert_valid_feature_dict(self, features: dict):
        """Helper to assert exact 20 features, names, order, and validity."""
        self.assertIsInstance(features, dict)
        self.assertEqual(len(features), 20, "Feature dict must contain exactly 20 features")
        
        # Check exact names and order
        feature_keys = list(features.keys())
        self.assertEqual(feature_keys, TOP_20_FEATURES, "Feature names and order must match TOP_20_FEATURES")

        # Check no NaN, None, or Infinity
        for k, v in features.items():
            self.assertIsNotNone(v, f"Feature '{k}' is None")
            self.assertIsInstance(v, (int, float, np.number), f"Feature '{k}' is not numeric")
            self.assertFalse(math.isnan(v), f"Feature '{k}' is NaN")
            self.assertFalse(math.isinf(v), f"Feature '{k}' is Infinity")

    def test_01_normal_synthetic_flow(self):
        """Test a normal bidirectional TCP flow with forward and backward packets."""
        flow = NetworkFlow(
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=443,
            protocol="TCP",
            start_time=1000.0
        )
        # Forward packet (SYN)
        flow.add_packet(pkt_len=64, timestamp=1000.0, is_forward=True, header_len=40,
                        tcp_flags={"SYN": True}, tcp_win=65535)
        # Backward packet (SYN-ACK)
        flow.add_packet(pkt_len=64, timestamp=1000.02, is_forward=False, header_len=40,
                        tcp_flags={"SYN": True, "ACK": True}, tcp_win=28960)
        # Forward packet (ACK + Data)
        flow.add_packet(pkt_len=512, timestamp=1000.05, is_forward=True, header_len=40,
                        tcp_flags={"ACK": True, "PSH": True})
        # Backward packet (Data)
        flow.add_packet(pkt_len=1420, timestamp=1000.10, is_forward=False, header_len=40,
                        tcp_flags={"ACK": True})

        features = extract_features(flow)
        self._assert_valid_feature_dict(features)

        # Check semantic expectations
        self.assertEqual(features["Inbound"], 1.0)
        self.assertEqual(features["Total Backward Packets"], 2.0)
        self.assertEqual(features["Min Packet Length"], 64.0)
        self.assertEqual(features["Init_Win_bytes_forward"], 65535.0)
        self.assertEqual(features["Init_Win_bytes_backward"], 28960.0)
        self.assertGreater(features["Fwd IAT Mean"], 0.0)
        self.assertGreater(features["Bwd IAT Mean"], 0.0)

        # Model prediction compatibility
        pred = self.predictor.predict_flow(features)
        self.assertIn(pred["prediction"], ["Normal", "DDoS"])
        self.assertIn(pred["label"], [0, 1])
        self.assertIn(pred["risk_level"], ["LOW", "HIGH"])

    def test_02_flow_with_no_backward_packets(self):
        """Test unidirectional flow (e.g. UDP stream or unanswered SYN flood)."""
        flow = NetworkFlow(
            src_ip="203.0.113.5",
            dst_ip="192.168.1.50",
            src_port=40000,
            dst_port=80,
            protocol="TCP",
            start_time=2000.0
        )
        for i in range(10):
            flow.add_packet(
                pkt_len=60,
                timestamp=2000.0 + (i * 0.01),
                is_forward=True,
                header_len=40,
                tcp_flags={"SYN": True},
                tcp_win=1024
            )

        features = extract_features(flow)
        self._assert_valid_feature_dict(features)

        self.assertEqual(features["Total Backward Packets"], 0.0)
        self.assertEqual(features["Bwd Header Length"], 0.0)
        self.assertEqual(features["Bwd IAT Max"], 0.0)
        self.assertEqual(features["Bwd IAT Mean"], 0.0)
        self.assertEqual(features["Bwd Packets/s"], 0.0)
        self.assertEqual(features["Down/Up Ratio"], 0.0)
        self.assertEqual(features["Init_Win_bytes_backward"], 0.0)

        # Predictor test
        pred = self.predictor.predict_flow(features)
        self.assertIn(pred["prediction"], ["Normal", "DDoS"])

    def test_03_flow_with_only_one_packet(self):
        """Test single-packet flow (instantaneous arrival, no intervals)."""
        flow = NetworkFlow(
            src_ip="10.0.0.5",
            dst_ip="10.0.0.1",
            src_port=1234,
            dst_port=53,
            protocol="UDP",
            start_time=3000.0
        )
        flow.add_packet(pkt_len=75, timestamp=3000.0, is_forward=True, header_len=28)

        features = extract_features(flow)
        self._assert_valid_feature_dict(features)

        self.assertEqual(features["Min Packet Length"], 75.0)
        self.assertEqual(features["Fwd Packet Length Min"], 75.0)
        self.assertEqual(features["Fwd Packet Length Mean"], 75.0)
        self.assertEqual(features["Average Packet Size"], 75.0)
        self.assertEqual(features["Fwd IAT Mean"], 0.0)
        self.assertEqual(features["Fwd IAT Std"], 0.0)
        self.assertEqual(features["Flow IAT Mean"], 0.0)

        pred = self.predictor.predict_flow(features)
        self.assertIn(pred["label"], [0, 1])

    def test_04_flow_with_zero_duration(self):
        """Test flow where multiple packets arrive at identical timestamp (duration = 0)."""
        flow = NetworkFlow(
            src_ip="192.168.1.2",
            dst_ip="192.168.1.1",
            src_port=5000,
            dst_port=8080,
            protocol="TCP",
            start_time=4000.0
        )
        # 3 packets at exact same timestamp
        flow.add_packet(pkt_len=100, timestamp=4000.0, is_forward=True, header_len=40)
        flow.add_packet(pkt_len=200, timestamp=4000.0, is_forward=False, header_len=40)
        flow.add_packet(pkt_len=300, timestamp=4000.0, is_forward=True, header_len=40)

        self.assertEqual(flow.duration_seconds, 0.0)

        features = extract_features(flow)
        self._assert_valid_feature_dict(features)
        # Bwd Packets/s must not divide by zero
        self.assertEqual(features["Bwd Packets/s"], 0.0)

        pred = self.predictor.predict_flow(features)
        self.assertIn(pred["label"], [0, 1])

    def test_05_flow_missing_tcp_flags(self):
        """Test UDP / ICMP traffic with no TCP flags or window headers."""
        flow = NetworkFlow(
            src_ip="172.16.0.4",
            dst_ip="8.8.8.8",
            src_port=55555,
            dst_port=53,
            protocol="UDP",
            start_time=5000.0
        )
        flow.add_packet(pkt_len=80, timestamp=5000.0, is_forward=True, header_len=28)
        flow.add_packet(pkt_len=150, timestamp=5000.05, is_forward=False, header_len=28)

        features = extract_features(flow)
        self._assert_valid_feature_dict(features)

        self.assertEqual(features["URG Flag Count"], 0.0)
        self.assertEqual(features["ACK Flag Count"], 0.0)
        self.assertEqual(features["Init_Win_bytes_forward"], 0.0)
        self.assertEqual(features["Init_Win_bytes_backward"], 0.0)
        self.assertEqual(features["Inbound"], 0.0)  # 8.8.8.8 is public

        pred = self.predictor.predict_flow(features)
        self.assertIn(pred["label"], [0, 1])

    def test_06_division_by_zero_and_empty_flow(self):
        """Test empty flow dictionary / zero packets guard."""
        empty_flow_dict = {
            "fwd_packet_lengths": [],
            "bwd_packet_lengths": [],
            "duration_seconds": 0.0,
            "bwd_header_length": 0,
            "urg_flag_count": 0,
            "ack_flag_count": 0,
            "init_win_bytes_fwd": 0,
            "init_win_bytes_bwd": 0,
            "dst_ip": "127.0.0.1"
        }

        features = extract_features(empty_flow_dict)
        self._assert_valid_feature_dict(features)

        # DataFrame format extraction test
        df = extract_features(empty_flow_dict, as_df=True)
        self.assertIsInstance(df, pd.DataFrame)
        self.assertEqual(list(df.columns), TOP_20_FEATURES)
        self.assertEqual(len(df), 1)

        pred = self.predictor.predict_flow(df)
        self.assertIn(pred["label"], [0, 1])


if __name__ == "__main__":
    unittest.main()
