# Module 2: Network Monitoring and Traffic Analysis

This module provides real-time, passive network traffic capture, bidirectional flow aggregation, feature extraction, and ML-based DDoS detection for the banking DDoS detection capstone project.

---

## 1. Architecture Overview

```
Network Traffic (Interface / Live / Offline Replay)
                       ↓
         Packet Capture (`packet_capture.py`)
                       ↓
          Flow Tracking (`flow_tracker.py`)
                       ↓
        Feature Extraction (`feature_extractor.py`)
        [Extracts exact Top 20 validated features]
                       ↓
           ML Predictor (`ml_predictor.py`)
       [Loads validated Decision Tree model PKL]
                       ↓
         Traffic Analyzer (`traffic_analyzer.py`)
                       ↓
  Monitoring Record (Prediction, Confidence, Risk Level)
```

---

## 2. Component Descriptions

| File | Purpose |
|---|---|
| `config.py` | Central configuration defining the Top 20 feature list, model paths, subnets, and timeouts. |
| `packet_capture.py` | Passive packet capture wrapper using Scapy. Gracefully detects Windows Npcap requirements and privileges. |
| `flow_tracker.py` | Groups raw packets into bidirectional flows identified by `(src_ip, dst_ip, src_port, dst_port, protocol)`. |
| `feature_extractor.py` | Transforms flow objects into the exact 20 ML feature schema expected by the trained model. |
| `ml_predictor.py` | Loads `ml/validation/results/best_validation_model.pkl` and provides inference with risk level mappings. |
| `traffic_analyzer.py` | High-level orchestrator connecting capture, aggregation, extraction, and prediction into monitoring records. |
| `demo_monitor.py` | Safe offline verification script that runs end-to-end testing without needing administrative/driver privileges. |
| `tests/test_feature_extractor.py` | Unit tests covering edge cases (single packet, zero duration, missing flags, division-by-zero). |

---

## 3. The Top 20 Validated ML Features

The feature extractor produces the exact 20 features ranked during leakage-safe model validation:

1. `Min Packet Length`
2. `Inbound`
3. `Fwd Packet Length Min`
4. `Fwd Packet Length Mean`
5. `Avg Fwd Segment Size`
6. `Average Packet Size`
7. `Bwd IAT Max`
8. `Bwd Packets/s`
9. `Packet Length Mean`
10. `Bwd Header Length`
11. `URG Flag Count`
12. `Total Backward Packets`
13. `Fwd IAT Std`
14. `Down/Up Ratio`
15. `Fwd IAT Mean`
16. `Flow IAT Mean`
17. `ACK Flag Count`
18. `Init_Win_bytes_forward`
19. `Bwd IAT Mean`
20. `Init_Win_bytes_backward`

---

## 4. CIC-DDoS2019 Semantics vs. Live Packet Capture Limitations

> [!IMPORTANT]
> **Dataset Validation vs. Live Monitoring Distinction:**
> Offline ML training and validation was executed on curated CIC-DDoS2019 records generated using the Java-based `CICFlowMeter` tool. When reconstructing these features in real-time using Scapy, certain differences and approximations exist:

1. **Inbound Directionality:**
   - *Dataset Definition:* `Inbound` in CIC-DDoS2019 is a ground-truth binary indicator of whether a packet/flow was directed into the victim testbed network.
   - *Live Monitoring Implementation:* Live capture approximates `Inbound` using destination IP subnet heuristics (e.g. RFC 1918 private subnets such as `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
2. **TCP Initial Window Size (`Init_Win_bytes_forward` / `backward`):**
   - *Dataset Definition:* Represents the advertised receive window size from the initial TCP SYN / SYN-ACK 3-way handshake packets.
   - *Live Monitoring Implementation:* If packet capture starts after the handshake has already occurred, window sizes are taken from the first observed directional packet or defaulted to 0.
3. **Inter-Arrival Times (IAT):**
   - *Dataset Definition:* Measured in microseconds ($\mu s$).
   - *Live Monitoring Implementation:* High-resolution timestamps from Scapy packet capture are converted into microseconds ($\mu s$) to maintain numeric scale consistency.
4. **Segment Size Equivalence:**
   - In accordance with CICFlowMeter definitions, `Avg Fwd Segment Size` is computed as `Total Forward Bytes / Total Forward Packets` (`Fwd Packet Length Mean`).

---

## 5. Risk Level Mapping

| ML Prediction | Label | Risk Level | Meaning |
|---|---|---|---|
| `Normal` | `0` | `LOW` | Standard network traffic within baseline parameters. |
| `DDoS` | `1` | `HIGH` | Volumetric or protocol flood pattern detected. |

---

## 6. Operating Requirements & Windows Compatibility

### Linux / macOS
- Passive packet capture requires root/administrator privileges:
  ```bash
  sudo python -m network_monitor.traffic_analyzer
  ```

### Windows
- Live packet sniffing via Scapy on Windows requires **Npcap** or **WinPcap**.
- If Npcap is missing, `packet_capture.py` detects this condition and provides clear guidance without crashing.
- Download Npcap from: [https://npcap.com/](https://npcap.com/) (select *"Install Npcap in WinPcap API-compatible Mode"* during setup).
- Run PowerShell / Command Prompt as Administrator for live capture.

---

## 7. Running Unit Tests and Offline Demo

### Unit Tests
Run the unit test suite to verify feature extraction safety, zero NaN/Inf, edge-case resilience, and model compatibility:
```bash
python -m unittest discover -s network_monitor/tests -v
```

### Safe Offline Verification Demo
Run the offline demo to test simulated flow aggregation and model inference without live packet capture or attack generation:
```bash
python network_monitor/demo_monitor.py
```
