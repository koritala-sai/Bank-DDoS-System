"""
Smoke tests for network_monitor.feature_audit.
Runs in isolation without Scapy, MySQL, or live capture.
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

# Ensure project root is on path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _make_flow(**kwargs):
    """Returns a minimal mock NetworkFlow-like object."""
    defaults = dict(
        flow_id="10.0.0.1:1234-10.0.0.2:53-UDP",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=1234,
        dst_port=53,
        protocol="UDP",
        total_packets=2,
        duration_seconds=0.05,
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def _make_features():
    """Returns a valid 20-feature dict (all zeros — safe for testing)."""
    from network_monitor.config import TOP_20_FEATURES
    return {f: 0.0 for f in TOP_20_FEATURES}


def _make_pred(prediction="DDoS", confidence=1.0, risk_level="HIGH"):
    return {"prediction": prediction, "label": 1, "confidence": confidence, "risk_level": risk_level}


class TestFeatureAuditDisabled(unittest.TestCase):
    """When FEATURE_AUDIT_ENABLED=false, no file is created."""

    def test_disabled_produces_no_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.jsonl"
            with patch.dict(os.environ, {
                "FEATURE_AUDIT_ENABLED": "false",
                "FEATURE_AUDIT_LOG": str(log_path),
            }):
                # Re-import config so env is picked up
                import importlib
                import network_monitor.config as cfg
                importlib.reload(cfg)
                import network_monitor.feature_audit as fa
                importlib.reload(fa)

                fa.write_audit_record(_make_flow(), _make_features(), _make_pred())

            self.assertFalse(log_path.exists(), "Log file must not be created when disabled")

    def test_audit_log_path_returns_none_when_disabled(self):
        with patch.dict(os.environ, {"FEATURE_AUDIT_ENABLED": "false"}):
            import importlib, network_monitor.config as cfg, network_monitor.feature_audit as fa
            importlib.reload(cfg)
            importlib.reload(fa)
            self.assertIsNone(fa.audit_log_path())


class TestFeatureAuditEnabled(unittest.TestCase):
    """When FEATURE_AUDIT_ENABLED=true, valid JSONL records are written."""

    def _write_one_record(self, tmpdir):
        log_path = Path(tmpdir) / "audit.jsonl"
        with patch.dict(os.environ, {
            "FEATURE_AUDIT_ENABLED": "true",
            "FEATURE_AUDIT_LOG": str(log_path),
            "FEATURE_AUDIT_MAX_BYTES": str(100 * 1024 * 1024),
        }):
            import importlib, network_monitor.config as cfg, network_monitor.feature_audit as fa
            importlib.reload(cfg)
            importlib.reload(fa)
            fa.write_audit_record(_make_flow(), _make_features(), _make_pred(), source_type="live")
        return log_path

    def test_enabled_creates_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = self._write_one_record(tmpdir)
            self.assertTrue(log_path.exists(), "Log file must be created when enabled")
            self.assertGreater(log_path.stat().st_size, 0)

    def test_record_is_valid_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = self._write_one_record(tmpdir)
            lines = log_path.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), 1)
            record = json.loads(lines[0])
            self.assertIsInstance(record, dict)

    def test_record_has_expected_top_level_keys(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = self._write_one_record(tmpdir)
            record = json.loads(log_path.read_text(encoding="utf-8").strip())
            expected = {
                "audit_schema_version", "capture_timestamp_utc",
                "flow_id", "source_ip", "destination_ip",
                "source_port", "destination_port", "protocol",
                "packet_count", "flow_duration_s", "source_type",
                "prediction", "confidence", "risk_level", "features",
            }
            self.assertEqual(set(record.keys()), expected)

    def test_features_contains_all_20_keys_in_order(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = self._write_one_record(tmpdir)
            record = json.loads(log_path.read_text(encoding="utf-8").strip())
            from network_monitor.config import TOP_20_FEATURES
            self.assertEqual(list(record["features"].keys()), TOP_20_FEATURES)

    def test_source_type_is_live(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = self._write_one_record(tmpdir)
            record = json.loads(log_path.read_text(encoding="utf-8").strip())
            self.assertEqual(record["source_type"], "live")

    def test_no_payload_fields_in_record(self):
        """Ensure no packet-payload-like keys exist in the record."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = self._write_one_record(tmpdir)
            record = json.loads(log_path.read_text(encoding="utf-8").strip())
            forbidden = {"payload", "raw", "data", "content", "body", "password", "secret", "key"}
            found = forbidden & set(record.keys())
            self.assertEqual(found, set(), f"Forbidden keys found in audit record: {found}")

    def test_multiple_records_append(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.jsonl"
            with patch.dict(os.environ, {
                "FEATURE_AUDIT_ENABLED": "true",
                "FEATURE_AUDIT_LOG": str(log_path),
                "FEATURE_AUDIT_MAX_BYTES": str(100 * 1024 * 1024),
            }):
                import importlib, network_monitor.config as cfg, network_monitor.feature_audit as fa
                importlib.reload(cfg)
                importlib.reload(fa)
                for _ in range(3):
                    fa.write_audit_record(_make_flow(), _make_features(), _make_pred())

            lines = log_path.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), 3, "Expected 3 JSONL records for 3 flows")
            for line in lines:
                json.loads(line)  # must be valid JSON

    def test_audit_log_path_returns_path_when_enabled(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.jsonl"
            with patch.dict(os.environ, {
                "FEATURE_AUDIT_ENABLED": "true",
                "FEATURE_AUDIT_LOG": str(log_path),
            }):
                import importlib, network_monitor.config as cfg, network_monitor.feature_audit as fa
                importlib.reload(cfg)
                importlib.reload(fa)
                result = fa.audit_log_path()
            self.assertIsNotNone(result)

    def test_write_never_raises_on_bad_path(self):
        """A write failure must not propagate an exception."""
        with patch.dict(os.environ, {
            "FEATURE_AUDIT_ENABLED": "true",
            "FEATURE_AUDIT_LOG": "//invalid:path?<>|/audit.jsonl",  # illegal on Windows
        }):
            import importlib, network_monitor.config as cfg, network_monitor.feature_audit as fa
            importlib.reload(cfg)
            importlib.reload(fa)
            # Must not raise
            fa.write_audit_record(_make_flow(), _make_features(), _make_pred())


class TestAuditRotation(unittest.TestCase):
    """Log rotation: when file exceeds max_bytes, it is renamed to .1."""

    def test_rotation_renames_old_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.jsonl"
            # Pre-create a large file that exceeds our tiny limit
            log_path.write_text("x" * 100, encoding="utf-8")

            with patch.dict(os.environ, {
                "FEATURE_AUDIT_ENABLED": "true",
                "FEATURE_AUDIT_LOG": str(log_path),
                "FEATURE_AUDIT_MAX_BYTES": "50",  # 50 bytes — tiny limit to force rotation
            }):
                import importlib, network_monitor.config as cfg, network_monitor.feature_audit as fa
                importlib.reload(cfg)
                importlib.reload(fa)
                fa.write_audit_record(_make_flow(), _make_features(), _make_pred())

            backup = log_path.with_suffix(log_path.suffix + ".1")
            self.assertTrue(backup.exists(), "Backup file (.1) must exist after rotation")
            self.assertEqual(backup.read_text(encoding="utf-8"), "x" * 100)
            # New log file should have just the new record
            self.assertTrue(log_path.exists())
            lines = log_path.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
