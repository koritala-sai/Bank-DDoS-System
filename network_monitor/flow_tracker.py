"""
Module 2: Network Monitoring and Traffic Analysis - Flow Tracker
Aggregates individual packets into bidirectional network flows and computes
flow-level metadata and packet arrival metrics.
"""

import time
from typing import Dict, List, Optional, Tuple, Any

# Scapy layer helpers
try:
    from scapy.all import IP, IPv6, TCP, UDP, ICMP
except ImportError:
    IP = IPv6 = TCP = UDP = ICMP = None


class NetworkFlow:
    """
    Represents a bidirectional network conversation between two endpoints.
    The initiator of the conversation defines the 'forward' direction.
    """

    def __init__(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        start_time: float
    ):
        # Identifying Metadata (NOT for ML model input)
        self.src_ip: str = src_ip
        self.dst_ip: str = dst_ip
        self.src_port: int = src_port
        self.dst_port: int = dst_port
        self.protocol: str = protocol
        self.flow_id: str = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"

        # Timing
        self.start_time: float = start_time
        self.end_time: float = start_time
        self.duration_seconds: float = 0.0
        self.duration_microseconds: float = 0.0

        # Packet Metrics
        self.total_fwd_packets: int = 0
        self.total_bwd_packets: int = 0
        self.fwd_packet_lengths: List[int] = []
        self.bwd_packet_lengths: List[int] = []

        # Timestamps & Inter-Arrival Times (IAT in microseconds)
        self.fwd_timestamps: List[float] = []
        self.bwd_timestamps: List[float] = []
        self.all_timestamps: List[float] = []

        self.fwd_iats_us: List[float] = []
        self.bwd_iats_us: List[float] = []
        self.flow_iats_us: List[float] = []

        # Header Lengths
        self.fwd_header_length: int = 0
        self.bwd_header_length: int = 0

        # TCP Flag Counts
        self.ack_flag_count: int = 0
        self.urg_flag_count: int = 0
        self.syn_flag_count: int = 0
        self.fin_flag_count: int = 0
        self.rst_flag_count: int = 0
        self.psh_flag_count: int = 0

        # TCP Window Sizes
        self.init_win_bytes_fwd: int = 0
        self.init_win_bytes_bwd: int = 0

    @property
    def total_packets(self) -> int:
        return self.total_fwd_packets + self.total_bwd_packets

    @property
    def total_bytes(self) -> int:
        return sum(self.fwd_packet_lengths) + sum(self.bwd_packet_lengths)

    def add_packet(
        self,
        pkt_len: int,
        timestamp: float,
        is_forward: bool,
        header_len: int = 0,
        tcp_flags: Optional[Dict[str, bool]] = None,
        tcp_win: Optional[int] = None
    ):
        """
        Ingests a packet into the flow, updating timing, lengths, flags, and IATs.

        Args:
            pkt_len (int): Total packet wire length in bytes.
            timestamp (float): Epoch timestamp in seconds.
            is_forward (bool): True if packet travels in forward direction, False if backward.
            header_len (int): Header length (IP + Transport) in bytes.
            tcp_flags (dict, optional): Map of TCP flags present on the packet.
            tcp_win (int, optional): TCP Advertised Window Size in bytes.
        """
        # Update flow timing
        if timestamp < self.start_time:
            self.start_time = timestamp
        if timestamp > self.end_time:
            self.end_time = timestamp

        self.duration_seconds = max(0.0, self.end_time - self.start_time)
        self.duration_microseconds = self.duration_seconds * 1_000_000.0

        # Flow-level IAT (microseconds)
        if self.all_timestamps:
            prev_time = self.all_timestamps[-1]
            flow_iat = max(0.0, (timestamp - prev_time) * 1_000_000.0)
            self.flow_iats_us.append(flow_iat)
        self.all_timestamps.append(timestamp)

        # Directional statistics
        if is_forward:
            self.total_fwd_packets += 1
            self.fwd_packet_lengths.append(pkt_len)
            self.fwd_header_length += header_len

            if self.fwd_timestamps:
                prev_fwd = self.fwd_timestamps[-1]
                fwd_iat = max(0.0, (timestamp - prev_fwd) * 1_000_000.0)
                self.fwd_iats_us.append(fwd_iat)
            self.fwd_timestamps.append(timestamp)

            # Record initial window size on first forward packet with TCP
            if self.init_win_bytes_fwd == 0 and tcp_win is not None:
                self.init_win_bytes_fwd = tcp_win

        else:
            self.total_bwd_packets += 1
            self.bwd_packet_lengths.append(pkt_len)
            self.bwd_header_length += header_len

            if self.bwd_timestamps:
                prev_bwd = self.bwd_timestamps[-1]
                bwd_iat = max(0.0, (timestamp - prev_bwd) * 1_000_000.0)
                self.bwd_iats_us.append(bwd_iat)
            self.bwd_timestamps.append(timestamp)

            # Record initial window size on first backward packet with TCP
            if self.init_win_bytes_bwd == 0 and tcp_win is not None:
                self.init_win_bytes_bwd = tcp_win

        # TCP Flags
        if tcp_flags:
            if tcp_flags.get("ACK", False):
                self.ack_flag_count += 1
            if tcp_flags.get("URG", False):
                self.urg_flag_count += 1
            if tcp_flags.get("SYN", False):
                self.syn_flag_count += 1
            if tcp_flags.get("FIN", False):
                self.fin_flag_count += 1
            if tcp_flags.get("RST", False):
                self.rst_flag_count += 1
            if tcp_flags.get("PSH", False):
                self.psh_flag_count += 1


class FlowTracker:
    """
    Manages active bidirectional flows, dispatches incoming packets to flows,
    and handles flow timeouts and eviction.
    """

    def __init__(self, flow_timeout: float = 120.0):
        """
        Args:
            flow_timeout (float): Inactive duration in seconds after which a flow is expired.
        """
        self.flow_timeout = flow_timeout
        self.flows: Dict[Tuple[str, str, int, int, str], NetworkFlow] = {}

    def get_flow_key(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str
    ) -> Tuple[Tuple[str, str, int, int, str], bool]:
        """
        Determines canonical flow key and direction.

        Returns:
            ((canonical_src, canonical_dst, canonical_sport, canonical_dport, proto), is_forward)
        """
        fwd_key = (src_ip, dst_ip, src_port, dst_port, protocol)
        bwd_key = (dst_ip, src_ip, dst_port, src_port, protocol)

        if fwd_key in self.flows:
            return fwd_key, True
        elif bwd_key in self.flows:
            return bwd_key, False
        else:
            # New flow: this packet establishes forward direction
            return fwd_key, True

    def process_packet(self, packet: Any, timestamp: Optional[float] = None) -> Optional[NetworkFlow]:
        """
        Extracts packet tuple from a Scapy Packet or dict, updates the flow, and returns the flow.

        Args:
            packet: Scapy Packet object or structured packet dict.
            timestamp: Optional explicit timestamp (uses packet.time if Scapy packet).

        Returns:
            NetworkFlow or None if packet does not contain IP layer.
        """
        if timestamp is None:
            timestamp = time.time()

        # Handle Scapy Packet object
        if IP is not None and (isinstance(packet, IP) or (hasattr(packet, "haslayer") and packet.haslayer(IP))):
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            proto_num = ip_layer.proto
            pkt_time = float(getattr(packet, "time", timestamp))
            pkt_len = int(len(packet))

            # Header length
            ip_hdr_len = int(getattr(ip_layer, "ihl", 5)) * 4
            trans_hdr_len = 0
            src_port = 0
            dst_port = 0
            proto_str = "OTHER"
            tcp_flags = None
            tcp_win = None

            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                proto_str = "TCP"
                src_port = int(tcp_layer.sport)
                dst_port = int(tcp_layer.dport)
                trans_hdr_len = int(getattr(tcp_layer, "dataofs", 5)) * 4
                flags_val = str(tcp_layer.flags)
                tcp_flags = {
                    "ACK": "A" in flags_val,
                    "URG": "U" in flags_val,
                    "SYN": "S" in flags_val,
                    "FIN": "F" in flags_val,
                    "RST": "R" in flags_val,
                    "PSH": "P" in flags_val,
                }
                tcp_win = int(tcp_layer.window)
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                proto_str = "UDP"
                src_port = int(udp_layer.sport)
                dst_port = int(udp_layer.dport)
                trans_hdr_len = 8
            elif packet.haslayer(ICMP):
                proto_str = "ICMP"
                trans_hdr_len = 8

            total_hdr_len = ip_hdr_len + trans_hdr_len

            canonical_key, is_fwd = self.get_flow_key(src_ip, dst_ip, src_port, dst_port, proto_str)
            if canonical_key not in self.flows:
                self.flows[canonical_key] = NetworkFlow(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=proto_str,
                    start_time=pkt_time
                )

            flow = self.flows[canonical_key]
            flow.add_packet(
                pkt_len=pkt_len,
                timestamp=pkt_time,
                is_forward=is_fwd,
                header_len=total_hdr_len,
                tcp_flags=tcp_flags,
                tcp_win=tcp_win
            )
            return flow

        # Handle structured dictionary representation (e.g. for testing / offline replay)
        elif isinstance(packet, dict):
            src_ip = packet.get("src_ip", "0.0.0.0")
            dst_ip = packet.get("dst_ip", "0.0.0.0")
            src_port = int(packet.get("src_port", 0))
            dst_port = int(packet.get("dst_port", 0))
            proto_str = packet.get("protocol", "TCP")
            pkt_time = float(packet.get("timestamp", timestamp))
            pkt_len = int(packet.get("length", 64))
            hdr_len = int(packet.get("header_length", 40))
            tcp_flags = packet.get("tcp_flags", None)
            tcp_win = packet.get("tcp_window", None)

            canonical_key, is_fwd = self.get_flow_key(src_ip, dst_ip, src_port, dst_port, proto_str)
            if canonical_key not in self.flows:
                self.flows[canonical_key] = NetworkFlow(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=proto_str,
                    start_time=pkt_time
                )

            flow = self.flows[canonical_key]
            flow.add_packet(
                pkt_len=pkt_len,
                timestamp=pkt_time,
                is_forward=is_fwd,
                header_len=hdr_len,
                tcp_flags=tcp_flags,
                tcp_win=tcp_win
            )
            return flow

        return None

    def get_all_flows(self) -> List[NetworkFlow]:
        """Returns list of all tracked flows."""
        return list(self.flows.values())

    def clear(self):
        """Resets all tracked flows."""
        self.flows.clear()
