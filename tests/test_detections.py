import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from src.detections import detect
from src.io import load_events
from src.models import DetectionFinding, SysmonEvent, parse_utc
from src.reporting import metrics, render_markdown


class SysmonDetectionTests(unittest.TestCase):
    def event(self, **overrides):
        base = dict(
            event_id=1,
            record_id="evt-x",
            timestamp=datetime(2026, 9, 11, 8, 0, tzinfo=timezone.utc),
            host="LAB-WIN-01",
            user="LAB\\user",
            image="C:\\Windows\\System32\\cmd.exe",
        )
        base.update(overrides)
        return SysmonEvent(**base)

    def test_rejects_unsupported_event_id(self):
        with self.assertRaises(ValueError):
            self.event(event_id=999)

    def test_parse_utc_rejects_naive_timestamp(self):
        with self.assertRaises(ValueError):
            parse_utc("2026-09-11T08:00:00")

    def test_powershell_detection(self):
        event = self.event(image="powershell.exe", command_line="powershell.exe -EncodedCommand TEST")
        findings = detect([event])
        self.assertEqual(findings[0].title, "Suspicious PowerShell process creation")
        self.assertIn("T1059.001", findings[0].mitre_techniques)

    def test_lsass_access_detection(self):
        event = self.event(event_id=10, extra={"target_image": "C:\\Windows\\System32\\lsass.exe", "granted_access": "0x1fffff"})
        findings = detect([event])
        self.assertEqual(findings[0].severity, "Critical")

    def test_run_key_detection(self):
        event = self.event(event_id=13, target_object="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater")
        findings = detect([event])
        self.assertTrue(any("Run key" in f.title for f in findings))

    def test_unsigned_process_network_correlation(self):
        p = self.event(record_id="p1", image="C:\\Lab\\a.exe", signed=False)
        n = self.event(event_id=3, record_id="n1", timestamp=datetime(2026, 9, 11, 8, 1, tzinfo=timezone.utc), image="C:\\Lab\\a.exe", destination_ip="203.0.113.10", destination_port=8443)
        findings = detect([p, n])
        self.assertTrue(any("Unsigned process" in f.title for f in findings))

    def test_benign_signed_web_connection_is_not_flagged(self):
        p = self.event(record_id="p1", image="C:\\Lab\\signed.exe", signed=True)
        n = self.event(event_id=3, record_id="n1", timestamp=datetime(2026, 9, 11, 8, 1, tzinfo=timezone.utc), image="C:\\Lab\\signed.exe", destination_ip="192.0.2.10", destination_port=443)
        self.assertEqual(detect([p, n]), [])

    def test_duplicate_record_ids_fail_closed(self):
        payload = '[{"event_id":1,"record_id":"dup","timestamp":"2026-09-11T08:00:00Z","host":"H1","user":"U"},{"event_id":1,"record_id":"dup","timestamp":"2026-09-11T08:01:00Z","host":"H1","user":"U"}]'
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "events.json"
            path.write_text(payload, encoding="utf-8")
            with self.assertRaises(ValueError):
                load_events(path)

    def test_finding_requires_valid_score(self):
        with self.assertRaises(ValueError):
            DetectionFinding("id", "title", "host", "High", 101, 50, ("T1059.001",), ("e1",), "r", "x", "v")

    def test_reporting_metrics_and_validation_text(self):
        event = self.event(image="powershell.exe", command_line="powershell.exe -EncodedCommand TEST")
        findings = detect([event])
        self.assertEqual(metrics(findings)["total_findings"], 1)
        report = render_markdown(findings)
        self.assertIn("ATT&CK mappings provide investigation context", report)
        self.assertIn("Validation:", report)


if __name__ == "__main__":
    unittest.main()
