"""
Network Monitor Configuration Module
Defines paths, feature schemas, default thresholds, and operational settings
for passive packet capture, flow tracking, feature extraction, and ML inference.
"""

from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent

# Model & Validation Artifact Paths
MODEL_PATH = PROJECT_ROOT / "ml" / "validation" / "results" / "best_validation_model.pkl"
TOP20_FEATURES_PATH = PROJECT_ROOT / "ml" / "validation" / "results" / "validation_top20_features.txt"

# Exact Top 20 validated features in strict order required by best_validation_model.pkl
TOP_20_FEATURES = [
    "Min Packet Length",
    "Inbound",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Avg Fwd Segment Size",
    "Average Packet Size",
    "Bwd IAT Max",
    "Bwd Packets/s",
    "Packet Length Mean",
    "Bwd Header Length",
    "URG Flag Count",
    "Total Backward Packets",
    "Fwd IAT Std",
    "Down/Up Ratio",
    "Fwd IAT Mean",
    "Flow IAT Mean",
    "ACK Flag Count",
    "Init_Win_bytes_forward",
    "Bwd IAT Mean",
    "Init_Win_bytes_backward"
]

# Capture Settings
DEFAULT_PACKET_COUNT = 100
DEFAULT_CAPTURE_TIMEOUT = 30  # seconds
DEFAULT_FLOW_TIMEOUT = 120.0  # seconds for flow expiry

# Risk Levels
RISK_LEVEL_MAP = {
    0: "LOW",   # Normal traffic
    1: "HIGH"   # DDoS traffic
}

# Prediction Labels
LABEL_MAP = {
    0: "Normal",
    1: "DDoS"
}

# Subnet / Inbound Heuristics
# By default, traffic addressed to RFC 1918 private IP ranges is classified as inbound
PRIVATE_IP_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                       "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                       "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                       "172.30.", "172.31.", "192.168.", "127.")
