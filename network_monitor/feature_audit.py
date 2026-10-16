"""
network_monitor/feature_audit.py

Feature Audit Log — writes one JSONL record per analyzed live flow, capturing
the exact 20 ML feature values, flow metadata, and prediction outcome.

Privacy:
  - Records only flow-level metadata (IPs, ports, protocol, timing) and
    numerical feature values. No packet payloads, application-layer content,
    credentials, or secrets are stored.
  - IPs recorded here are identical to what is already stored in MySQL traffic_records.
  - Enable only during debugging/demo sessions (FEATURE_AUDIT_ENABLED=true).
  - The logs/ directory should be excluded from version control (.gitignore).

Historical records:
  - Flows analyzed before this module was deployed have no stored feature vectors
    and cannot be recovered. This module only covers newly captured flows.
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("network_monitor.feature_audit")

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_config() -> tuple[bool, Path, int]:
    """
    Reads audit configuration from environment variables at call-time.
    Importing config directly would create a circular dependency risk; reading
    env vars here keeps feature_audit.py self-contained and independently testable.

    Returns:
        (enabled, log_path, max_bytes)
    """
    from .config import FEATURE_AUDIT_ENABLED, FEATURE_AUDIT_LOG, FEATURE_AUDIT_MAX_BYTES
    return FEATURE_AUDIT_ENABLED, FEATURE_AUDIT_LOG, FEATURE_AUDIT_MAX_BYTES


def _rotate_if_needed(log_path: Path, max_bytes: int) -> None:
    """
    Rotates the audit log when it exceeds max_bytes.
    Renames <log>.jsonl -> <log>.jsonl.1 (single backup, overwrites prior .1).
    """
    try:
        if log_path.exists() and log_path.stat().st_size >= max_bytes:
            backup = log_path.with_suffix(log_path.suffix + ".1")
            log_path.rename(backup)
            logger.info("Feature audit log rotated: %s -> %s", log_path.name, backup.name)
    except OSError as exc:
        logger.warning("Feature audit log rotation failed: %s", exc)


def _ensure_dir(log_path: Path) -> None:
    """Creates parent directories for the log file if they do not exist."""
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        logger.warning("Could not create feature audit log directory '%s': %s", log_path.parent, exc)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def write_audit_record(
    flow: Any,
    features: Dict[str, float],
    pred_result: Dict[str, Any],
    source_type: str = "live",
) -> None:
    """
    Appends one JSONL audit record for a single analyzed live flow.

    The record contains:
      - audit_schema_version: format version for future compatibility
      - capture_timestamp_utc: ISO-8601 UTC timestamp at write time
      - flow_id, source_ip, destination_ip, source_port, destination_port, protocol
      - packet_count, flow_duration_s
      - source_type: "live" for live capture flows
      - prediction, confidence, risk_level
      - features: the exact 20-value dict passed to the ML model

    Args:
        flow: NetworkFlow instance (or any object with the expected attributes).
        features: The exact feature dict returned by extract_features(), before
                  any modification. Must not be mutated after this call.
        pred_result: The dict returned by MLPredictor.predict_flow().
        source_type: Origin label — always "live" for live_test.py flows.

    Raises:
        Nothing. All errors are logged as warnings; capture continues unaffected.
    """
    try:
        enabled, log_path, max_bytes = _get_config()
    except Exception as cfg_exc:
        logger.warning("Feature audit config unavailable: %s", cfg_exc)
        return

    if not enabled:
        return

    try:
        _ensure_dir(log_path)
        _rotate_if_needed(log_path, max_bytes)

        record = {
            "audit_schema_version": "1",
            "capture_timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "flow_id": getattr(flow, "flow_id", None),
            "source_ip": getattr(flow, "src_ip", None),
            "destination_ip": getattr(flow, "dst_ip", None),
            "source_port": getattr(flow, "src_port", None),
            "destination_port": getattr(flow, "dst_port", None),
            "protocol": getattr(flow, "protocol", None),
            "packet_count": getattr(flow, "total_packets", None),
            "flow_duration_s": getattr(flow, "duration_seconds", None),
            "source_type": source_type,
            "prediction": pred_result.get("prediction"),
            "confidence": pred_result.get("confidence"),
            "risk_level": pred_result.get("risk_level"),
            "features": dict(features),  # shallow copy — never mutate caller's dict
        }

        line = json.dumps(record, ensure_ascii=False) + "\n"

        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(line)

    except Exception as exc:
        # Never propagate — a write failure must not interrupt live capture
        logger.warning("Feature audit write failed (capture continues): %s", exc)


def audit_log_path() -> Optional[Path]:
    """
    Returns the configured audit log path, or None if audit is disabled.
    Useful for displaying the path in summary output.
    """
    try:
        enabled, log_path, _ = _get_config()
        return log_path if enabled else None
    except Exception:
        return None
