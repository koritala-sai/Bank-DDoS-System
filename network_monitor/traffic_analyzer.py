"""
Module 2: Network Monitoring and Traffic Analysis - Traffic Analyzer
End-to-end orchestration:
Packet Capture -> Flow Aggregation -> Feature Extraction -> ML Prediction -> Monitoring Record
"""

import time
import logging
from typing import List, Dict, Any, Optional, Union

from .flow_tracker import FlowTracker, NetworkFlow
from .feature_extractor import extract_features
from .ml_predictor import MLPredictor, get_predictor
from .packet_capture import PacketCapturer, start_capture

logger = logging.getLogger("network_monitor.traffic_analyzer")


class TrafficAnalyzer:
    """
    Orchestrates network traffic capture, flow tracking, feature extraction,
    and ML prediction to produce structured real-time monitoring records.
    """

    def __init__(
        self,
        predictor: Optional[MLPredictor] = None,
        flow_timeout: float = 120.0
    ):
        """
        Initialize the Traffic Analyzer.

        Args:
            predictor (MLPredictor, optional): Custom predictor instance.
            flow_timeout (float): Inactivity threshold for expiring flows.
        """
        self.predictor = predictor or get_predictor()
        self.flow_tracker = FlowTracker(flow_timeout=flow_timeout)

    def analyze_flow(self, flow: NetworkFlow) -> Dict[str, Any]:
        """
        Extracts features from an aggregated flow, predicts its class, and creates a monitoring record.

        Args:
            flow (NetworkFlow): The flow object to analyze.

        Returns:
            dict: Structured monitoring record with metadata, features, and prediction.
        """
        # 1. Feature Extraction (exact Top 20)
        features = extract_features(flow)

        # 2. ML Prediction
        pred_result = self.predictor.predict_flow(features)

        # 3. Construct Monitoring Record
        record = {
            "timestamp": flow.end_time,
            "flow_id": flow.flow_id,
            "source_ip": flow.src_ip,
            "destination_ip": flow.dst_ip,
            "source_port": flow.src_port,
            "destination_port": flow.dst_port,
            "protocol": flow.protocol,
            "packet_count": flow.total_packets,
            "flow_duration": flow.duration_seconds,
            "flow_duration_us": flow.duration_microseconds,
            "prediction": pred_result["prediction"],
            "label": pred_result["label"],
            "confidence": pred_result["confidence"],
            "risk_level": pred_result["risk_level"],
            "features": features
        }

        return record

    def analyze_packets(self, packets: List[Any]) -> List[Dict[str, Any]]:
        """
        Feeds a list of packets into the flow tracker and analyzes all completed/tracked flows.

        Args:
            packets (List): List of Scapy Packet objects or packet dicts.

        Returns:
            List[dict]: Monitoring records for all identified flows.
        """
        self.flow_tracker.clear()
        for pkt in packets:
            self.flow_tracker.process_packet(pkt)

        flows = self.flow_tracker.get_all_flows()
        records = [self.analyze_flow(f) for f in flows]
        return records

    def capture_and_analyze(
        self,
        interface: Optional[str] = None,
        packet_count: int = 100,
        timeout: int = 30
    ) -> List[Dict[str, Any]]:
        """
        Captures live packets from the network interface and analyzes the resulting flows.

        Args:
            interface (str, optional): Network interface to sniff on.
            packet_count (int): Maximum packets to capture.
            timeout (int): Capture timeout in seconds.

        Returns:
            List[dict]: Monitoring records for all captured flows.
        """
        capturer = PacketCapturer(interface=interface)
        packets = capturer.capture(packet_count=packet_count, timeout=timeout)
        return self.analyze_packets(packets)


def analyze_traffic(
    interface: Optional[str] = None,
    packet_count: int = 100,
    timeout: int = 30
) -> List[Dict[str, Any]]:
    """
    Convenience function for capturing and analyzing traffic.
    """
    analyzer = TrafficAnalyzer()
    return analyzer.capture_and_analyze(
        interface=interface,
        packet_count=packet_count,
        timeout=timeout
    )
