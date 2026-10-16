"""
Safe passive live-network verification test.
Captures existing traffic already occurring on the local machine and evaluates
it using the validated Decision Tree ML model. Does NOT generate, send, replay,
flood, or modify any packets. Does NOT create DDoS or attack traffic.

Usage:
    python network_monitor/live_test.py
    python network_monitor/live_test.py --duration 30
    python network_monitor/live_test.py --duration 30 --interface "Wi-Fi"
    python network_monitor/live_test.py --duration 30 --interface "Wi-Fi" --sync-backend
"""

import sys
import types
import time
import math
import json
import urllib.request
import urllib.error
import argparse
from pathlib import Path

# ── Windows Application Control compatibility fix for scipy.spatial ──────────
if "scipy.spatial._ckdtree" not in sys.modules:
    try:
        import scipy.spatial._ckdtree  # noqa: F401
    except ImportError:
        _dummy = types.ModuleType("scipy.spatial._ckdtree")
        _dummy.cKDTree = object
        _dummy.cKDTreeNode = object
        sys.modules["scipy.spatial._ckdtree"] = _dummy

# ── Project root on sys.path ─────────────────────────────────────────────────
_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

# ── Existing module imports ──────────────────────────────────────────────────
from network_monitor.config import TOP_20_FEATURES, MODEL_PATH, MONITORED_SUBNET_ENV, MONITORED_SUBNETS
from network_monitor.packet_capture import (
    PacketCapturer,
    check_capture_prerequisites,
    SCAPY_AVAILABLE,
)
from network_monitor.flow_tracker import FlowTracker
from network_monitor.feature_extractor import extract_features
from network_monitor.ml_predictor import MLPredictor
from network_monitor.feature_audit import write_audit_record, audit_log_path

# Try importing conf for interface listing (non-fatal)
try:
    from scapy.all import conf as scapy_conf
except ImportError:
    scapy_conf = None


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _list_interfaces():
    """Print available Scapy network interfaces, if possible."""
    if scapy_conf is None:
        print("  (Scapy not available – cannot list interfaces)")
        return
    try:
        ifaces = scapy_conf.ifaces
        if hasattr(ifaces, "data"):
            iface_list = ifaces.data.values()
        elif hasattr(ifaces, "values"):
            iface_list = ifaces.values()
        else:
            iface_list = list(ifaces)

        if not iface_list:
            print("  (No interfaces detected – is Npcap installed?)")
            return

        print("  Available interfaces:")
        for iface in iface_list:
            name = getattr(iface, "name", str(iface))
            desc = getattr(iface, "description", "")
            ip   = getattr(iface, "ip", "")
            line = f"    - {name}"
            if desc:
                line += f"  ({desc})"
            if ip:
                line += f"  [{ip}]"
            print(line)
    except Exception as exc:
        print(f"  (Could not enumerate interfaces: {exc})")


def _feature_sanity_check(features: dict) -> bool:
    """Return True if the feature dict has exactly 20 valid numeric values."""
    if len(features) != 20:
        return False
    for key in TOP_20_FEATURES:
        if key not in features:
            return False
        v = features[key]
        if not isinstance(v, (int, float)):
            return False
        if math.isnan(v) or math.isinf(v):
            return False
    return True


def _send_flow_to_backend(payload: dict, backend_url: str = "http://localhost:5000", timeout: int = 5) -> dict:
    """
    Sends an analyzed flow record to POST /api/traffic on the Flask backend.

    Args:
        payload (dict): Flow record dictionary matching backend /api/traffic schema.
        backend_url (str): Base URL of the Flask server.
        timeout (int): Request timeout in seconds.

    Returns:
        dict: Server response JSON.
    """
    endpoint = f"{backend_url.rstrip('/')}/api/traffic"
    data_bytes = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=data_bytes,
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8")
        return json.loads(body)


# ─────────────────────────────────────────────────────────────────────────────
# Main live test
# ─────────────────────────────────────────────────────────────────────────────

def run_live_test(
    duration: int = 30,
    interface: str = None,
    sync_backend: bool = False,
    backend_url: str = "http://localhost:5000"
):
    """
    End-to-end live-network verification test:
      1. Load model
      2. Verify feature schema
      3. Capture real packets (passive only)
      4. Aggregate into flows (existing FlowTracker)
      5. Extract 20 features (existing extract_features)
      6. Run ML prediction (existing MLPredictor)
      7. Display results table and summary (with optional backend sync)
    """

    print("=" * 70)
    print("         LIVE NETWORK MONITORING TEST")
    print("         ML prediction on observed live traffic")
    print("=" * 70)
    print()

    # ── Step 1: Scapy & driver prerequisites ─────────────────────────────
    print("[1/7] Checking Scapy & capture prerequisites ...")
    if not SCAPY_AVAILABLE:
        print("  ERROR: Scapy is not installed. Run:  pip install scapy")
        return
    prereqs = check_capture_prerequisites()
    print(f"  Status : {'AVAILABLE' if prereqs['available'] else 'UNAVAILABLE'}")
    print(f"  Detail : {prereqs['reason']}")
    _list_interfaces()
    print()

    if not prereqs["available"]:
        print("  Cannot proceed with live capture. Exiting.")
        return

    # ── Step 2: Load validated model ─────────────────────────────────────
    print("[2/7] Loading validated Decision Tree model ...")
    try:
        predictor = MLPredictor(model_path=MODEL_PATH)
        print(f"  Model loaded from: {MODEL_PATH}")
    except Exception as exc:
        print(f"  ERROR: Could not load model – {exc}")
        return
    print()

    # ── Step 3: Verify feature schema against model ──────────────────────
    print("[3/7] Verifying Top-20 feature schema ...")
    model_features = getattr(predictor.model, "feature_names_in_", None)
    if model_features is not None:
        model_list = list(model_features)
        match = model_list == TOP_20_FEATURES
        print(f"  Model expects {len(model_list)} features")
        print(f"  Config defines {len(TOP_20_FEATURES)} features")
        print(f"  Names & order match: {'YES' if match else 'NO'}")
        if not match:
            print("  WARNING: Feature mismatch detected. Results may be unreliable.")
    else:
        print("  Model does not expose feature_names_in_; using config order.")
    print(f"  Monitored subnet       : {MONITORED_SUBNET_ENV or '(None - Inbound defaults to 0.0)'}")
    print(f"  Parsed subnets         : {[str(s) for s in MONITORED_SUBNETS]}")
    print()

    # ── Step 4: Capture live packets ─────────────────────────────────────
    print(f"[4/7] Capturing live packets (passive sniff) ...")
    print(f"  Interface : {interface or '(default)'}")
    print(f"  Duration  : {duration} seconds")
    print(f"  Status    : CAPTURING ...")
    print()

    capturer = PacketCapturer(interface=interface)
    t_start = time.time()
    try:
        packets = capturer.capture(
            packet_count=0,      # no hard limit – rely on timeout
            timeout=duration,
        )
    except PermissionError as pe:
        print(f"  PERMISSION ERROR: {pe}")
        print("  On Windows, run this script as Administrator.")
        print("  On Linux/macOS, use sudo.")
        return
    except OSError as oe:
        print(f"  OS ERROR: {oe}")
        if sys.platform.startswith("win"):
            print("  Ensure Npcap is installed: https://npcap.com/")
        return
    except Exception as exc:
        print(f"  CAPTURE ERROR: {exc}")
        return
    t_elapsed = time.time() - t_start

    total_captured = len(packets)
    print(f"  Capture complete in {t_elapsed:.1f}s")
    print(f"  Packets captured: {total_captured}")
    print()

    if total_captured == 0:
        print("  No packets captured. Nothing to analyse.")
        print("  (Try increasing --duration, or check that the interface has traffic.)")
        return

    # ── Step 5: Aggregate into flows ─────────────────────────────────────
    print("[5/7] Aggregating packets into bidirectional flows ...")
    tracker = FlowTracker()
    skipped_packets = 0
    for pkt in packets:
        result = tracker.process_packet(pkt)
        if result is None:
            skipped_packets += 1

    flows = tracker.get_all_flows()
    print(f"  Flows detected : {len(flows)}")
    print(f"  Packets skipped (non-IP): {skipped_packets}")
    print()

    if not flows:
        print("  No usable IP flows found in captured traffic.")
        return

    # ── Step 6 & 7: Feature extraction + ML prediction ───────────────────
    print("[6/7] Extracting features & running ML predictions ...")
    print()

    results = []
    feature_errors = 0
    prediction_errors = 0
    sync_success_count = 0
    sync_failed_count = 0
    sync_alert_count = 0
    sync_errors = []

    for flow in flows:
        # Feature extraction
        try:
            features = extract_features(flow)
        except Exception as exc:
            feature_errors += 1
            continue

        if not _feature_sanity_check(features):
            feature_errors += 1
            continue

        # ML prediction
        try:
            pred = predictor.predict_flow(features)
        except Exception as exc:
            prediction_errors += 1
            continue

        # Write feature audit record (no-op unless FEATURE_AUDIT_ENABLED=true)
        write_audit_record(flow, features, pred, source_type="live")

        results.append({
            "flow_id": flow.flow_id,
            "protocol": flow.protocol,
            "packets": flow.total_packets,
            "inbound": int(features.get("Inbound", 0.0)),
            "prediction": pred["prediction"],
            "label": pred["label"],
            "confidence": pred["confidence"],
            "risk_level": pred["risk_level"],
        })

        # Optional synchronization to Flask backend / MySQL
        if sync_backend:
            payload = {
                "source_ip": flow.src_ip,
                "destination_ip": flow.dst_ip,
                "source_port": flow.src_port,
                "destination_port": flow.dst_port,
                "protocol": flow.protocol,
                "flow_duration": flow.duration_seconds,
                "packet_count": flow.total_packets,
                "prediction": pred["prediction"],
                "risk_level": pred["risk_level"],
                "confidence": pred["confidence"],
            }
            try:
                resp = _send_flow_to_backend(payload, backend_url=backend_url)
                sync_success_count += 1
                if resp.get("alert_created"):
                    sync_alert_count += 1
            except Exception as sync_err:
                sync_failed_count += 1
                if len(sync_errors) < 3:
                    sync_errors.append(str(sync_err))

    # ── Display results table ────────────────────────────────────────────
    print("[7/7] Results")
    print()
    print("  LIVE TRAFFIC ANALYSIS RESULTS")
    print("  (ML prediction on observed live traffic – not a definitive attack verdict)")
    print("  " + "-" * 96)
    header = (
        f"  {'Flow ID':<42} {'Proto':<6} {'Pkts':>5} {'Inb':>4} "
        f"{'Prediction':<10} {'Conf':>6} {'Risk':<5}"
    )
    print(header)
    print("  " + "-" * 96)

    for r in results:
        fid = r["flow_id"]
        if len(fid) > 40:
            fid = fid[:37] + "..."
        conf_str = f"{r['confidence']:.3f}" if r["confidence"] is not None else "N/A"
        print(
            f"  {fid:<42} {r['protocol']:<6} {r['packets']:>5} {r['inbound']:>4} "
            f"{r['prediction']:<10} {conf_str:>6} {r['risk_level']:<5}"
        )

    print("  " + "-" * 96)
    print()

    # ── Summary ──────────────────────────────────────────────────────────
    normal_count = sum(1 for r in results if r["label"] == 0)
    ddos_count   = sum(1 for r in results if r["label"] == 1)
    high_risk    = sum(1 for r in results if r["risk_level"] == "HIGH")
    inbound_1    = sum(1 for r in results if r.get("inbound") == 1)
    inbound_0    = sum(1 for r in results if r.get("inbound") == 0)

    print("  LIVE TEST SUMMARY")
    print("  " + "-" * 50)
    print(f"  Packets captured         : {total_captured}")
    print(f"  Flows detected           : {len(flows)}")
    print(f"  Flows analysed           : {len(results)}")
    print(f"  Monitored subnet         : {MONITORED_SUBNET_ENV or '(Unconfigured)'}")
    print(f"  Inbound flows (Inbound=1): {inbound_1}")
    print(f"  Outbound flows (Inbound=0): {inbound_0}")
    print(f"  Normal predictions       : {normal_count}")
    print(f"  DDoS predictions         : {ddos_count}")
    print(f"  High-risk flows          : {high_risk}")
    print(f"  Feature extraction errors: {feature_errors}")
    print(f"  Prediction errors        : {prediction_errors}")
    _audit_path = audit_log_path()
    if _audit_path:
        print(f"  Feature audit log        : {_audit_path}")
    else:
        print("  Feature audit log        : DISABLED (set FEATURE_AUDIT_ENABLED=true to record feature vectors)")
    if sync_backend:
        print(f"  Backend sync target      : {backend_url}")
        print(f"  Backend submissions      : {sync_success_count} succeeded, {sync_failed_count} failed")
        print(f"  Backend alerts created   : {sync_alert_count}")
        if sync_errors:
            print(f"  Sample sync error        : {sync_errors[0]}")
    else:
        print("  Backend sync status      : DISABLED (Console only; pass --sync-backend to persist)")
    print("  " + "-" * 50)
    print()

    if ddos_count > 0:
        print("  NOTE: DDoS predictions on normal live traffic do NOT necessarily")
        print("  indicate an actual attack. The model was trained on CIC-DDoS2019")
        print("  dataset features; live-captured feature distributions may differ.")
    print()
    print("  Live network monitoring test completed.")
    print("=" * 70)


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=(
            "Safe passive live-network verification test. "
            "Captures existing traffic and evaluates it using the validated ML model. "
            "Does NOT generate attack traffic."
        )
    )
    parser.add_argument(
        "--duration", type=int, default=30,
        help="Capture duration in seconds (default: 30)"
    )
    parser.add_argument(
        "--interface", type=str, default=None,
        help="Network interface name for Scapy (default: auto-detect)"
    )
    parser.add_argument(
        "--sync-backend", action="store_true", default=False,
        help="Sync successfully analyzed flows to the Flask backend (/api/traffic) and MySQL"
    )
    parser.add_argument(
        "--backend-url", type=str, default="http://localhost:5000",
        help="Backend base URL for flow synchronization (default: http://localhost:5000)"
    )
    args = parser.parse_args()

    run_live_test(
        duration=args.duration,
        interface=args.interface,
        sync_backend=args.sync_backend,
        backend_url=args.backend_url
    )
