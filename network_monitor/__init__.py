"""
Network Monitoring and Traffic Analysis Module (Module 2)
Banking DDoS Detection Capstone Project
"""

import sys
import types

# Windows Application Control / Smart App Control compatibility fix for scipy.spatial
if "scipy.spatial._ckdtree" not in sys.modules:
    try:
        import scipy.spatial._ckdtree  # noqa: F401
    except ImportError:
        dummy_ckdtree = types.ModuleType("scipy.spatial._ckdtree")
        dummy_ckdtree.cKDTree = object
        dummy_ckdtree.cKDTreeNode = object
        sys.modules["scipy.spatial._ckdtree"] = dummy_ckdtree

from .config import (
    TOP_20_FEATURES,
    MODEL_PATH,
    TOP20_FEATURES_PATH,
    LABEL_MAP,
    RISK_LEVEL_MAP,
    DEFAULT_PACKET_COUNT,
    DEFAULT_CAPTURE_TIMEOUT
)
from .packet_capture import PacketCapturer, start_capture, check_capture_prerequisites
from .flow_tracker import FlowTracker, NetworkFlow
from .feature_extractor import extract_features, is_inbound_traffic
from .ml_predictor import MLPredictor, predict_flow, get_predictor
from .traffic_analyzer import TrafficAnalyzer, analyze_traffic

__all__ = [
    "TOP_20_FEATURES",
    "MODEL_PATH",
    "TOP20_FEATURES_PATH",
    "LABEL_MAP",
    "RISK_LEVEL_MAP",
    "DEFAULT_PACKET_COUNT",
    "DEFAULT_CAPTURE_TIMEOUT",
    "PacketCapturer",
    "start_capture",
    "check_capture_prerequisites",
    "FlowTracker",
    "NetworkFlow",
    "extract_features",
    "is_inbound_traffic",
    "MLPredictor",
    "predict_flow",
    "get_predictor",
    "TrafficAnalyzer",
    "analyze_traffic"
]
