"""
Module 2: Network Monitoring and Traffic Analysis - Feature Extractor
Extracts the exact Top 20 validated ML features from an aggregated NetworkFlow object.

Features generated:
 1. Min Packet Length
 2. Inbound
 3. Fwd Packet Length Min
 4. Fwd Packet Length Mean
 5. Avg Fwd Segment Size
 6. Average Packet Size
 7. Bwd IAT Max
 8. Bwd Packets/s
 9. Packet Length Mean
10. Bwd Header Length
11. URG Flag Count
12. Total Backward Packets
13. Fwd IAT Std
14. Down/Up Ratio
15. Fwd IAT Mean
16. Flow IAT Mean
17. ACK Flag Count
18. Init_Win_bytes_forward
19. Bwd IAT Mean
20. Init_Win_bytes_backward

CICFlowMeter / CIC-DDoS2019 Semantic Alignment & Live Capture Limitations:
-------------------------------------------------------------------------
1. Inbound:
   - In CIC-DDoS2019 dataset, 'Inbound' indicates whether a flow is directed towards the victim/monitored network.
   - In live passive capture, this is derived from destination IP address heuristics (e.g. RFC 1918 private subnet).
2. Inter-Arrival Times (IAT):
   - In CIC-DDoS2019 / CICFlowMeter, IAT metrics are measured in microseconds (us).
   - In this module, IATs are computed in microseconds (us) from packet timestamps.
3. Init_Win_bytes_forward / backward:
   - In CICFlowMeter, window sizes represent the advertised TCP receive window from the initial SYN / SYN-ACK handshake.
   - In live capture, if the 3-way handshake was not observed (e.g., flow captured mid-stream), window size from the first observed directional packet is used.
4. Avg Fwd Segment Size:
   - In CICFlowMeter, this equals the forward packet length mean (Total Forward Bytes / Total Forward Packets).
"""

import numpy as np
import pandas as pd
from typing import Dict, Union, Any

from .config import TOP_20_FEATURES, PRIVATE_IP_PREFIXES
from .flow_tracker import NetworkFlow


def is_inbound_traffic(dst_ip: str) -> float:
    """
    Heuristic to determine if traffic is inbound to local/private network.
    
    Args:
        dst_ip (str): Destination IP address string.
        
    Returns:
        float: 1.0 if inbound, 0.0 if outbound.
    """
    if not dst_ip or not isinstance(dst_ip, str):
        return 1.0
    
    clean_ip = dst_ip.strip()
    if clean_ip.startswith(PRIVATE_IP_PREFIXES) or clean_ip == "localhost":
        return 1.0
    return 0.0


def extract_features(flow: Union[NetworkFlow, Dict[str, Any]], as_df: bool = False) -> Union[Dict[str, float], pd.DataFrame]:
    """
    Extracts the exact Top 20 validated ML features from a NetworkFlow object.

    Args:
        flow: NetworkFlow instance or dictionary with equivalent attributes.
        as_df (bool): If True, returns a 1-row pandas DataFrame with correct column order.
                      If False, returns an ordered dictionary.

    Returns:
        dict or pd.DataFrame containing the 20 features with exact naming and order.
    """
    if isinstance(flow, NetworkFlow):
        # Extract from NetworkFlow object
        all_lengths = flow.fwd_packet_lengths + flow.bwd_packet_lengths
        fwd_lengths = flow.fwd_packet_lengths
        bwd_lengths = flow.bwd_packet_lengths
        
        tot_fwd = flow.total_fwd_packets
        tot_bwd = flow.total_bwd_packets
        tot_pkts = flow.total_packets
        
        fwd_iats = flow.fwd_iats_us
        bwd_iats = flow.bwd_iats_us
        flow_iats = flow.flow_iats_us
        
        duration_s = flow.duration_seconds
        bwd_hdr_len = flow.bwd_header_length
        
        urg_flags = flow.urg_flag_count
        ack_flags = flow.ack_flag_count
        
        init_win_fwd = flow.init_win_bytes_fwd
        init_win_bwd = flow.init_win_bytes_bwd
        
        dst_ip = flow.dst_ip

    elif isinstance(flow, dict):
        # Extract from dictionary representation
        fwd_lengths = flow.get("fwd_packet_lengths", [])
        bwd_lengths = flow.get("bwd_packet_lengths", [])
        all_lengths = fwd_lengths + bwd_lengths
        
        tot_fwd = flow.get("total_fwd_packets", len(fwd_lengths))
        tot_bwd = flow.get("total_bwd_packets", len(bwd_lengths))
        tot_pkts = tot_fwd + tot_bwd
        
        fwd_iats = flow.get("fwd_iats_us", [])
        bwd_iats = flow.get("bwd_iats_us", [])
        flow_iats = flow.get("flow_iats_us", [])
        
        duration_s = float(flow.get("duration_seconds", 0.0))
        bwd_hdr_len = int(flow.get("bwd_header_length", 0))
        
        urg_flags = int(flow.get("urg_flag_count", 0))
        ack_flags = int(flow.get("ack_flag_count", 0))
        
        init_win_fwd = int(flow.get("init_win_bytes_fwd", 0))
        init_win_bwd = int(flow.get("init_win_bytes_bwd", 0))
        
        dst_ip = flow.get("dst_ip", "192.168.1.1")
    else:
        raise TypeError(f"Expected NetworkFlow or dict, got {type(flow)}")

    # 1. Min Packet Length
    min_pkt_len = float(min(all_lengths)) if all_lengths else 0.0

    # 2. Inbound
    inbound_val = is_inbound_traffic(dst_ip)

    # 3. Fwd Packet Length Min
    fwd_len_min = float(min(fwd_lengths)) if fwd_lengths else 0.0

    # 4. Fwd Packet Length Mean
    fwd_len_mean = float(np.mean(fwd_lengths)) if fwd_lengths else 0.0

    # 5. Avg Fwd Segment Size (CICFlowMeter equivalent to Fwd Packet Length Mean)
    avg_fwd_seg_size = fwd_len_mean

    # 6. Average Packet Size
    avg_pkt_size = float(np.mean(all_lengths)) if all_lengths else 0.0

    # 7. Bwd IAT Max
    bwd_iat_max = float(max(bwd_iats)) if bwd_iats else 0.0

    # 8. Bwd Packets/s
    bwd_pkts_per_s = float(tot_bwd / duration_s) if duration_s > 0.0 else 0.0

    # 9. Packet Length Mean
    pkt_len_mean = float(np.mean(all_lengths)) if all_lengths else 0.0

    # 10. Bwd Header Length
    bwd_header_len = float(bwd_hdr_len)

    # 11. URG Flag Count
    urg_flag_cnt = float(urg_flags)

    # 12. Total Backward Packets
    total_bwd_pkts = float(tot_bwd)

    # 13. Fwd IAT Std
    fwd_iat_std = float(np.std(fwd_iats)) if fwd_iats else 0.0

    # 14. Down/Up Ratio
    down_up_ratio = float(tot_bwd / tot_fwd) if tot_fwd > 0 else 0.0

    # 15. Fwd IAT Mean
    fwd_iat_mean = float(np.mean(fwd_iats)) if fwd_iats else 0.0

    # 16. Flow IAT Mean
    flow_iat_mean = float(np.mean(flow_iats)) if flow_iats else 0.0

    # 17. ACK Flag Count
    ack_flag_cnt = float(ack_flags)

    # 18. Init_Win_bytes_forward
    init_win_fwd_val = float(init_win_fwd)

    # 19. Bwd IAT Mean
    bwd_iat_mean = float(np.mean(bwd_iats)) if bwd_iats else 0.0

    # 20. Init_Win_bytes_backward
    init_win_bwd_val = float(init_win_bwd)

    # Construct features in strict validated Top 20 order
    feature_dict = {
        "Min Packet Length": min_pkt_len,
        "Inbound": inbound_val,
        "Fwd Packet Length Min": fwd_len_min,
        "Fwd Packet Length Mean": fwd_len_mean,
        "Avg Fwd Segment Size": avg_fwd_seg_size,
        "Average Packet Size": avg_pkt_size,
        "Bwd IAT Max": bwd_iat_max,
        "Bwd Packets/s": bwd_pkts_per_s,
        "Packet Length Mean": pkt_len_mean,
        "Bwd Header Length": bwd_header_len,
        "URG Flag Count": urg_flag_cnt,
        "Total Backward Packets": total_bwd_pkts,
        "Fwd IAT Std": fwd_iat_std,
        "Down/Up Ratio": down_up_ratio,
        "Fwd IAT Mean": fwd_iat_mean,
        "Flow IAT Mean": flow_iat_mean,
        "ACK Flag Count": ack_flag_cnt,
        "Init_Win_bytes_forward": init_win_fwd_val,
        "Bwd IAT Mean": bwd_iat_mean,
        "Init_Win_bytes_backward": init_win_bwd_val
    }

    # Clean any accidental NaN / Inf values
    for k in feature_dict:
        val = feature_dict[k]
        if np.isnan(val) or np.isinf(val):
            feature_dict[k] = 0.0

    if as_df:
        return pd.DataFrame([feature_dict], columns=TOP_20_FEATURES)

    return feature_dict
