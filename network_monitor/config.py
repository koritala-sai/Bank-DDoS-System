"""
Network Monitor Configuration Module
Defines paths, feature schemas, default thresholds, and operational settings
for passive packet capture, flow tracking, feature extraction, and ML inference.
"""

import os
import ipaddress
import logging
from pathlib import Path
from typing import List, Union
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
ENV_FILE = Path(os.getenv("NETWORK_MONITOR_ENV_FILE", PROJECT_ROOT / ".env"))

# Load environment variables from project-root .env without overwriting existing OS env vars
load_dotenv(ENV_FILE, override=False)

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

# Monitored Subnet Configuration
# Set via environment variable MONITORED_SUBNET (e.g. "192.168.1.0/24" or "10.0.0.0/8,192.168.1.0/24")
# If unconfigured, defaults to empty list [] (explicit safe behavior: traffic is NOT assumed to be inbound)
MONITORED_SUBNET_ENV = os.getenv("MONITORED_SUBNET", "").strip()


def parse_monitored_subnets(
    subnet_str: Union[str, None] = None
) -> List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
    """
    Parses a comma-separated string of CIDR notations or IP addresses into ipaddress Network objects.

    Args:
        subnet_str (str, optional): Comma-separated subnet strings. If None, reads from MONITORED_SUBNET env var.

    Returns:
        List of IPv4Network / IPv6Network objects. Returns empty list if unconfigured or invalid.
    """
    raw_str = subnet_str if subnet_str is not None else os.getenv("MONITORED_SUBNET", "")
    if not raw_str or not isinstance(raw_str, str):
        return []

    networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
    for item in raw_str.split(","):
        cleaned = item.strip()
        if not cleaned:
            continue
        try:
            # strict=False allows host bits to be set, e.g. "192.168.1.5/24" -> 192.168.1.0/24
            net = ipaddress.ip_network(cleaned, strict=False)
            networks.append(net)
        except ValueError as e:
            logger.warning("Invalid monitored subnet configured: '%s'. Error: %s", cleaned, e)
    return networks


MONITORED_SUBNETS = parse_monitored_subnets(MONITORED_SUBNET_ENV)

# Deprecated legacy prefixes kept for backward compatibility
PRIVATE_IP_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                       "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                       "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                       "172.30.", "172.31.", "192.168.", "127.")

# ---------------------------------------------------------------------------
# Feature Audit Log Configuration
# ---------------------------------------------------------------------------
# When FEATURE_AUDIT_ENABLED=true, each analyzed live flow writes one JSONL
# record containing the exact 20 feature values passed to the ML model, along
# with flow metadata, prediction, and confidence. No packet payloads are stored.
#
# Enable only during debugging or demo sessions.
# The logs/ directory should be excluded from version control (.gitignore).
# ---------------------------------------------------------------------------

FEATURE_AUDIT_ENABLED: bool = (
    os.getenv("FEATURE_AUDIT_ENABLED", "false").strip().lower() == "true"
)

FEATURE_AUDIT_LOG: Path = Path(
    os.getenv(
        "FEATURE_AUDIT_LOG",
        str(PROJECT_ROOT / "logs" / "feature_audit.jsonl")
    )
)

# Rotate the audit log when it exceeds this size (default: 50 MB)
FEATURE_AUDIT_MAX_BYTES: int = int(
    os.getenv("FEATURE_AUDIT_MAX_BYTES", str(50 * 1024 * 1024))
)
