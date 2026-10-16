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
10. Init_Win sentinel alignment: UDP/no-TCP window stays -1
11. Init_Win sentinel alignment: first TCP window (including 0) is recorded correctly
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

import os
import sys
import subprocess
import tempfile
import unittest
import math
import numpy as np
import pandas as pd
from pathlib import Path

from network_monitor.config import TOP_20_FEATURES, MODEL_PATH, PROJECT_ROOT, parse_monitored_subnets
from network_monitor.flow_tracker import NetworkFlow, FlowTracker
from network_monitor.feature_extractor import extract_features, is_inbound_traffic
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

        # Test with explicitly configured monitored subnet containing 10.0.0.1
        subnets = parse_monitored_subnets("10.0.0.0/8")
        features = extract_features(flow, monitored_subnets=subnets)
        self._assert_valid_feature_dict(features)

        # Check semantic expectations
        self.assertEqual(features["Inbound"], 1.0)
        self.assertEqual(features["Total Backward Packets"], 2.0)
        self.assertEqual(features["Min Packet Length"], 64.0)
        self.assertEqual(features["Init_Win_bytes_forward"], 65535.0)
        self.assertEqual(features["Init_Win_bytes_backward"], 28960.0)
        self.assertGreater(features["Fwd IAT Mean"], 0.0)
        self.assertGreater(features["Bwd IAT Mean"], 0.0)

        # Test when unconfigured, Inbound is 0.0
        unconf_features = extract_features(flow, monitored_subnets=[])
        self.assertEqual(unconf_features["Inbound"], 0.0)

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
        # No backward packet ever arrived, so the backward window sentinel stays -1
        self.assertEqual(features["Init_Win_bytes_backward"], -1.0)

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
        # UDP has no TCP window: sentinel must be -1 (matching CICFlowMeter convention)
        self.assertEqual(features["Init_Win_bytes_forward"], -1.0)
        self.assertEqual(features["Init_Win_bytes_backward"], -1.0)
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


    def test_07_init_win_sentinel_udp_stays_minus_one(self):
        """
        A UDP flow (no tcp_win ever provided) must leave both Init_Win fields at -1.
        -1 is the CICFlowMeter sentinel for non-TCP protocols and is required for the
        Decision Tree to route UDP flows through the correct branch (Node 54 threshold -0.5).
        """
        flow = NetworkFlow(
            src_ip="10.0.0.20",
            dst_ip="192.168.1.1",
            src_port=5353,
            dst_port=5353,
            protocol="UDP",
            start_time=7000.0
        )
        # Multiple UDP packets — tcp_win is never passed (None)
        flow.add_packet(pkt_len=100, timestamp=7000.0,  is_forward=True,  header_len=28)
        flow.add_packet(pkt_len=120, timestamp=7000.05, is_forward=False, header_len=28)
        flow.add_packet(pkt_len=100, timestamp=7000.10, is_forward=True,  header_len=28)

        self.assertEqual(flow.init_win_bytes_fwd, -1,
                         "UDP forward window must remain -1 (no TCP window present)")
        self.assertEqual(flow.init_win_bytes_bwd, -1,
                         "UDP backward window must remain -1 (no TCP window present)")

        features = extract_features(flow)
        self.assertEqual(features["Init_Win_bytes_forward"], -1.0)
        self.assertEqual(features["Init_Win_bytes_backward"], -1.0)
        self._assert_valid_feature_dict(features)

    def test_08_init_win_first_tcp_window_recorded(self):
        """
        The first TCP window observed in each direction replaces the -1 sentinel.
        Subsequent packets in the same direction must NOT overwrite the recorded value.
        """
        flow = NetworkFlow(
            src_ip="192.168.1.5",
            dst_ip="192.168.1.50",
            src_port=12345,
            dst_port=443,
            protocol="TCP",
            start_time=8000.0
        )
        # First forward packet: window=64240 (client SYN)
        flow.add_packet(pkt_len=60, timestamp=8000.0,  is_forward=True,
                        header_len=40, tcp_flags={"SYN": True}, tcp_win=64240)
        # First backward packet: window=65535 (server SYN-ACK)
        flow.add_packet(pkt_len=60, timestamp=8000.01, is_forward=False,
                        header_len=40, tcp_flags={"SYN": True, "ACK": True}, tcp_win=65535)
        # Second forward packet with a different window: must NOT overwrite 64240
        flow.add_packet(pkt_len=200, timestamp=8000.02, is_forward=True,
                        header_len=40, tcp_flags={"ACK": True}, tcp_win=32768)
        # Second backward packet with a different window: must NOT overwrite 65535
        flow.add_packet(pkt_len=400, timestamp=8000.03, is_forward=False,
                        header_len=40, tcp_flags={"ACK": True}, tcp_win=16384)

        self.assertEqual(flow.init_win_bytes_fwd, 64240,
                         "Forward window must be the first observed value (64240)")
        self.assertEqual(flow.init_win_bytes_bwd, 65535,
                         "Backward window must be the first observed value (65535)")

        features = extract_features(flow)
        self.assertEqual(features["Init_Win_bytes_forward"], 64240.0)
        self.assertEqual(features["Init_Win_bytes_backward"], 65535.0)
        self._assert_valid_feature_dict(features)

    def test_09_init_win_tcp_window_zero_is_valid(self):
        """
        A legitimate TCP window size of 0 (e.g. on an RST or zero-window probe) must be
        stored correctly, not confused with the uninitialised sentinel -1.
        After this packet is processed, the field must be 0, not -1.
        """
        flow = NetworkFlow(
            src_ip="10.10.0.1",
            dst_ip="10.10.0.2",
            src_port=9999,
            dst_port=80,
            protocol="TCP",
            start_time=9000.0
        )
        # Forward RST with window=0 — a real zero, not a missing value
        flow.add_packet(pkt_len=54, timestamp=9000.0, is_forward=True,
                        header_len=40, tcp_flags={"RST": True}, tcp_win=0)
        # Backward ACK with window=0
        flow.add_packet(pkt_len=54, timestamp=9000.005, is_forward=False,
                        header_len=40, tcp_flags={"ACK": True}, tcp_win=0)

        self.assertEqual(flow.init_win_bytes_fwd, 0,
                         "A real TCP window of 0 must be stored as 0, not remain as -1")
        self.assertEqual(flow.init_win_bytes_bwd, 0,
                         "A real TCP window of 0 must be stored as 0, not remain as -1")

        features = extract_features(flow)
        self.assertEqual(features["Init_Win_bytes_forward"], 0.0)
        self.assertEqual(features["Init_Win_bytes_backward"], 0.0)
        self._assert_valid_feature_dict(features)

    def test_10_inbound_destination_inside_subnet(self):
        """Destination IP inside configured subnet returns Inbound = 1.0."""
        subnets = parse_monitored_subnets("192.168.1.0/24")
        self.assertEqual(is_inbound_traffic("192.168.1.50", monitored_subnets=subnets), 1.0)
        self.assertEqual(is_inbound_traffic("192.168.1.1", monitored_subnets=subnets), 1.0)
        self.assertEqual(is_inbound_traffic("192.168.1.254", monitored_subnets=subnets), 1.0)

    def test_11_inbound_destination_outside_subnet(self):
        """Destination IP outside configured subnet returns Inbound = 0.0."""
        subnets = parse_monitored_subnets("192.168.1.0/24")
        self.assertEqual(is_inbound_traffic("192.168.2.1", monitored_subnets=subnets), 0.0)
        self.assertEqual(is_inbound_traffic("10.0.0.1", monitored_subnets=subnets), 0.0)
        self.assertEqual(is_inbound_traffic("8.8.8.8", monitored_subnets=subnets), 0.0)

    def test_12_inbound_multiple_subnets(self):
        """Multiple subnets configured correctly match any destination within the set."""
        subnets = parse_monitored_subnets("10.0.0.0/8, 172.16.0.0/16, 192.168.100.0/24")
        self.assertEqual(len(subnets), 3)
        self.assertEqual(is_inbound_traffic("10.50.1.2", monitored_subnets=subnets), 1.0)
        self.assertEqual(is_inbound_traffic("172.16.4.5", monitored_subnets=subnets), 1.0)
        self.assertEqual(is_inbound_traffic("192.168.100.10", monitored_subnets=subnets), 1.0)
        # Outside all three
        self.assertEqual(is_inbound_traffic("172.17.0.1", monitored_subnets=subnets), 0.0)
        self.assertEqual(is_inbound_traffic("192.168.1.1", monitored_subnets=subnets), 0.0)

    def test_13_inbound_unconfigured_missing_subnet_returns_zero(self):
        """When no subnet is configured, Inbound explicitly and safely defaults to 0.0."""
        # Unconfigured list / None
        self.assertEqual(is_inbound_traffic("192.168.1.1", monitored_subnets=[]), 0.0)
        self.assertEqual(is_inbound_traffic("10.0.0.1", monitored_subnets=[]), 0.0)
        self.assertEqual(is_inbound_traffic("172.16.0.1", monitored_subnets=[]), 0.0)
        self.assertEqual(is_inbound_traffic("127.0.0.1", monitored_subnets=[]), 0.0)

    def test_14_inbound_invalid_destination_ip(self):
        """Invalid or malformed destination IPs return 0.0 without raising exceptions."""
        subnets = parse_monitored_subnets("192.168.1.0/24")
        self.assertEqual(is_inbound_traffic("999.999.999.999", monitored_subnets=subnets), 0.0)
        self.assertEqual(is_inbound_traffic("not_an_ip", monitored_subnets=subnets), 0.0)
        self.assertEqual(is_inbound_traffic("", monitored_subnets=subnets), 0.0)
        self.assertEqual(is_inbound_traffic("   ", monitored_subnets=subnets), 0.0)
        self.assertEqual(is_inbound_traffic(None, monitored_subnets=subnets), 0.0)
        self.assertEqual(is_inbound_traffic(12345, monitored_subnets=subnets), 0.0)

    def test_15_inbound_invalid_subnet_configuration_handled_gracefully(self):
        """Invalid subnet strings in configuration are ignored safely while valid subnets are retained."""
        subnets = parse_monitored_subnets("invalid_subnet/33, 10.0.0.0/8, , 999.999.0.0/16")
        self.assertEqual(len(subnets), 1)
        self.assertEqual(is_inbound_traffic("10.1.2.3", monitored_subnets=subnets), 1.0)
        self.assertEqual(is_inbound_traffic("192.168.1.1", monitored_subnets=subnets), 0.0)

        # Empty/blank string returns empty list
        self.assertEqual(parse_monitored_subnets(""), [])
        self.assertEqual(parse_monitored_subnets("   "), [])

        # When MONITORED_SUBNET is unset, None returns empty list
        orig_env = os.environ.get("MONITORED_SUBNET")
        try:
            os.environ.pop("MONITORED_SUBNET", None)
            self.assertEqual(parse_monitored_subnets(None), [])
        finally:
            if orig_env is not None:
                os.environ["MONITORED_SUBNET"] = orig_env

    def test_16_inbound_localhost_resolution(self):
        """'localhost' string resolves to 127.0.0.1 and checks against configured subnets."""
        subnets = parse_monitored_subnets("127.0.0.0/8")
        self.assertEqual(is_inbound_traffic("localhost", monitored_subnets=subnets), 1.0)
        self.assertEqual(is_inbound_traffic("localhost", monitored_subnets=[]), 0.0)

    def test_17_env_var_subnet_configuration(self):
        """MONITORED_SUBNET environment variable is parsed correctly."""
        orig_env = os.environ.get("MONITORED_SUBNET")
        try:
            os.environ["MONITORED_SUBNET"] = "192.168.50.0/24"
            parsed = parse_monitored_subnets()
            self.assertEqual(len(parsed), 1)
            self.assertEqual(is_inbound_traffic("192.168.50.1", monitored_subnets=parsed), 1.0)
            self.assertEqual(is_inbound_traffic("192.168.1.1", monitored_subnets=parsed), 0.0)
        finally:
            if orig_env is not None:
                os.environ["MONITORED_SUBNET"] = orig_env
            else:
                os.environ.pop("MONITORED_SUBNET", None)

    def test_18_import_time_dotenv_loading_and_precedence(self):
        """
        Verify that importing network_monitor.config in a standalone process
        loads MONITORED_SUBNET from .env at import time, and preserves existing OS env vars.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_env_file = Path(temp_dir) / ".env"
            temp_env_file.write_text("MONITORED_SUBNET=10.99.0.0/16\n", encoding="utf-8")

            # 1. Unset OS MONITORED_SUBNET: verify config loads 10.99.0.0/16 on import
            child_env = os.environ.copy()
            child_env.pop("MONITORED_SUBNET", None)
            child_env["NETWORK_MONITOR_ENV_FILE"] = str(temp_env_file)
            child_env["PYTHONPATH"] = str(PROJECT_ROOT)

            code = (
                "import network_monitor.config as cfg; "
                "print(cfg.MONITORED_SUBNET_ENV); "
                "print(len(cfg.MONITORED_SUBNETS)); "
                "print(str(cfg.MONITORED_SUBNETS[0]))"
            )
            result = subprocess.run(
                [sys.executable, "-c", code],
                env=child_env,
                capture_output=True,
                text=True,
                check=True
            )
            stdout_lines = result.stdout.strip().splitlines()
            self.assertEqual(stdout_lines[0], "10.99.0.0/16")
            self.assertEqual(stdout_lines[1], "1")
            self.assertEqual(stdout_lines[2], "10.99.0.0/16")

            # 2. Pre-set OS MONITORED_SUBNET: verify OS env var takes precedence over .env
            child_env["MONITORED_SUBNET"] = "192.168.88.0/24"
            result_precedence = subprocess.run(
                [sys.executable, "-c", code],
                env=child_env,
                capture_output=True,
                text=True,
                check=True
            )
            stdout_prec = result_precedence.stdout.strip().splitlines()
            self.assertEqual(stdout_prec[0], "192.168.88.0/24")
            self.assertEqual(stdout_prec[1], "1")
            self.assertEqual(stdout_prec[2], "192.168.88.0/24")

    def test_19_monitored_subnet_inbound_direction_and_validation(self):
        """
        Focused test confirming:
        1. Destination IP inside configured subnet 10.15.20.0/24 returns Inbound=1.0.
        2. Destination IP outside 10.15.20.0/24 returns Inbound=0.0 (even if src_ip is inside).
        3. Invalid / malformed destination IPs return Inbound=0.0 without errors.
        4. Full NetworkFlow feature extraction correctly embeds Inbound value into the Top 20 features.
        """
        subnets = parse_monitored_subnets("10.15.20.0/24")

        # 1. Destination IP inside 10.15.20.0/24 -> Inbound = 1.0
        inside_ips = ["10.15.20.1", "10.15.20.15", "10.15.20.100", "10.15.20.254"]
        for ip in inside_ips:
            self.assertEqual(is_inbound_traffic(ip, monitored_subnets=subnets), 1.0,
                             f"Destination IP {ip} should be recognized as Inbound (1.0)")

        # 2. Destination IP outside 10.15.20.0/24 -> Inbound = 0.0
        outside_ips = ["10.15.21.1", "10.15.19.254", "10.0.0.1", "192.168.1.1", "8.8.8.8", "1.1.1.1"]
        for ip in outside_ips:
            self.assertEqual(is_inbound_traffic(ip, monitored_subnets=subnets), 0.0,
                             f"Destination IP {ip} outside subnet should return Inbound (0.0)")

        # 3. Invalid / malformed destination IPs -> Inbound = 0.0
        invalid_ips = ["", "   ", "invalid_ip", "999.999.999.999", "10.15.20.256", None, 12345]
        for ip in invalid_ips:
            self.assertEqual(is_inbound_traffic(ip, monitored_subnets=subnets), 0.0,
                             f"Invalid destination IP {ip!r} should return Inbound (0.0)")

        # 4. End-to-end flow feature extraction verifying destination-IP directionality
        # Inbound flow: external client -> monitored banking server (10.15.20.50)
        inbound_flow = NetworkFlow(
            src_ip="203.0.113.10",
            dst_ip="10.15.20.50",
            src_port=52345,
            dst_port=443,
            protocol="TCP",
            start_time=100.0
        )
        inbound_flow.add_packet(pkt_len=60, timestamp=100.0, is_forward=True, tcp_win=64240)
        inbound_features = extract_features(inbound_flow, monitored_subnets=subnets)
        self.assertEqual(inbound_features["Inbound"], 1.0,
                         "Flow directed to dst_ip in monitored subnet must have Inbound=1.0")

        # Outbound flow: monitored server (10.15.20.50) -> external host (203.0.113.10)
        outbound_flow = NetworkFlow(
            src_ip="10.15.20.50",
            dst_ip="203.0.113.10",
            src_port=443,
            dst_port=52345,
            protocol="TCP",
            start_time=200.0
        )
        outbound_flow.add_packet(pkt_len=60, timestamp=200.0, is_forward=True, tcp_win=64240)
        outbound_features = extract_features(outbound_flow, monitored_subnets=subnets)
        self.assertEqual(outbound_features["Inbound"], 0.0,
                         "Flow directed to dst_ip outside monitored subnet must have Inbound=0.0")

    def test_20_flow_orientation_syn_first(self):
        """Standard client-first SYN initializes flow with client as src and server as dst."""
        subnets = parse_monitored_subnets("10.15.230.0/24")
        tracker = FlowTracker()
        pkt1 = {
            "src_ip": "192.168.1.10", "dst_ip": "10.15.230.50",
            "src_port": 50000, "dst_port": 443, "protocol": "TCP",
            "tcp_flags": {"SYN": True, "ACK": False}, "tcp_window": 64240,
            "timestamp": 100.0, "length": 60, "header_length": 40
        }
        pkt2 = {
            "src_ip": "10.15.230.50", "dst_ip": "192.168.1.10",
            "src_port": 443, "dst_port": 50000, "protocol": "TCP",
            "tcp_flags": {"SYN": True, "ACK": True}, "tcp_window": 28960,
            "timestamp": 100.01, "length": 60, "header_length": 40
        }
        tracker.process_packet(pkt1)
        flow = tracker.process_packet(pkt2)

        self.assertEqual(flow.src_ip, "192.168.1.10")
        self.assertEqual(flow.dst_ip, "10.15.230.50")
        self.assertEqual(flow.total_fwd_packets, 1)
        self.assertEqual(flow.total_bwd_packets, 1)
        self.assertEqual(flow.init_win_bytes_fwd, 64240)
        self.assertEqual(flow.init_win_bytes_bwd, 28960)

        features = extract_features(flow, monitored_subnets=subnets)
        self.assertEqual(features["Inbound"], 1.0,
                         "Ingress flow targeting protected server 10.15.230.50 must have Inbound=1.0")

    def test_21_flow_orientation_handshake_syn_ack_first(self):
        """TCP handshake response (SYN-ACK) observed first orients client as src, server as dst, and SYN-ACK as backward."""
        subnets = parse_monitored_subnets("10.15.230.0/24")

        # Case A: External client connecting to protected server, server SYN-ACK observed first
        tracker_a = FlowTracker()
        pkt_syn_ack_in = {
            "src_ip": "10.15.230.50", "dst_ip": "192.168.1.10",
            "src_port": 443, "dst_port": 50000, "protocol": "TCP",
            "tcp_flags": {"SYN": True, "ACK": True}, "tcp_window": 28960,
            "timestamp": 100.0, "length": 60, "header_length": 40
        }
        pkt_ack_in = {
            "src_ip": "192.168.1.10", "dst_ip": "10.15.230.50",
            "src_port": 50000, "dst_port": 443, "protocol": "TCP",
            "tcp_flags": {"ACK": True}, "tcp_window": 64240,
            "timestamp": 100.01, "length": 52, "header_length": 40
        }
        tracker_a.process_packet(pkt_syn_ack_in)
        flow_a = tracker_a.process_packet(pkt_ack_in)

        self.assertEqual(flow_a.src_ip, "192.168.1.10", "Client must remain flow.src_ip")
        self.assertEqual(flow_a.dst_ip, "10.15.230.50", "Protected server must remain flow.dst_ip")
        self.assertEqual(flow_a.total_fwd_packets, 1)
        self.assertEqual(flow_a.total_bwd_packets, 1)
        self.assertEqual(flow_a.init_win_bytes_fwd, 64240)
        self.assertEqual(flow_a.init_win_bytes_bwd, 28960)
        features_a = extract_features(flow_a, monitored_subnets=subnets)
        self.assertEqual(features_a["Inbound"], 1.0, "Canonical destination is protected server -> Inbound=1.0")

        # Case B: Protected client connecting to external server, external server SYN-ACK observed first
        tracker_b = FlowTracker()
        pkt_syn_ack_out = {
            "src_ip": "34.54.84.110", "dst_ip": "10.15.230.159",
            "src_port": 443, "dst_port": 52450, "protocol": "TCP",
            "tcp_flags": {"SYN": True, "ACK": True}, "tcp_window": 28960,
            "timestamp": 200.0, "length": 60, "header_length": 40
        }
        flow_b = tracker_b.process_packet(pkt_syn_ack_out)

        self.assertEqual(flow_b.src_ip, "10.15.230.159", "Protected client must remain flow.src_ip")
        self.assertEqual(flow_b.dst_ip, "34.54.84.110", "External server must remain flow.dst_ip")
        self.assertEqual(flow_b.total_fwd_packets, 0)
        self.assertEqual(flow_b.total_bwd_packets, 1)
        self.assertEqual(flow_b.init_win_bytes_bwd, 28960)
        features_b = extract_features(flow_b, monitored_subnets=subnets)
        self.assertEqual(features_b["Inbound"], 0.0, "Canonical destination is external server -> Inbound=0.0")

    def test_22_flow_orientation_midstream_ack_first(self):
        """Mid-stream flow without SYN/SYN-ACK preserves temporal first-packet arrival orientation."""
        tracker = FlowTracker()
        pkt1 = {
            "src_ip": "10.15.230.159", "dst_ip": "34.54.84.110",
            "src_port": 52450, "dst_port": 443, "protocol": "TCP",
            "tcp_flags": {"ACK": True, "PSH": True}, "tcp_window": 64240,
            "timestamp": 200.0, "length": 200, "header_length": 40
        }
        flow = tracker.process_packet(pkt1)

        self.assertEqual(flow.src_ip, "10.15.230.159")
        self.assertEqual(flow.dst_ip, "34.54.84.110")
        self.assertEqual(flow.total_fwd_packets, 1)
        self.assertEqual(flow.total_bwd_packets, 0)


if __name__ == "__main__":
    unittest.main()

