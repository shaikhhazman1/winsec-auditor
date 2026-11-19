import threading
import unittest
from unittest.mock import MagicMock, patch

from modules import adapters


class FakeFinding:
    def __init__(self, data):
        self.data = data

    def to_dict(self):
        return dict(self.data)


def scan_item(port=445):
    return {"check_id": f"PORT-{port}", "title": f"TCP {port} open",
            "status": "open", "severity": "MEDIUM", "port": port,
            "evidence": "handshake ok", "remediation": "Block it."}


class TestRunScan(unittest.TestCase):
    def make_scanner(self):
        report = MagicMock()
        report.to_findings.return_value = [FakeFinding(scan_item())]
        scanner = MagicMock()
        scanner.scan.return_value = report
        return scanner

    def test_adds_check_and_details_and_keeps_original_keys(self):
        scanner = self.make_scanner()
        with patch.object(adapters, "PortScanner", return_value=scanner):
            out = adapters.run_scan("127.0.0.1", [445], threading.Event(), 50.0, 2.0)
        self.assertEqual(out[0]["port"], 445)
        self.assertEqual(out[0]["status"], "open")
        self.assertIn("PORT-445", out[0]["check"])
        self.assertEqual(out[0]["details"], "handshake ok")

    def test_passes_stop_event_and_limits(self):
        scanner = self.make_scanner()
        stop = threading.Event()
        with patch.object(adapters, "PortScanner", return_value=scanner) as cls:
            adapters.run_scan("127.0.0.1", [445], stop, 50.0, 2.0)
        cls.assert_called_once_with(timeout=2.0, rate=50.0)
        self.assertIs(scanner.scan.call_args[0][2], stop)


def make_fake_auditor(stop, crash_first=False):
    class FakeAuditor:
        calls: list = []

        def check_a(self):
            FakeAuditor.calls.append("a")
            if crash_first:
                raise RuntimeError("boom")
            stop.set()
            return {"check_id": "A", "name": "Check A", "status": "FAIL",
                    "severity": "HIGH", "current_value": "1",
                    "expected_value": "0", "remediation": "fix"}

        def check_b(self):
            FakeAuditor.calls.append("b")
            return {"check_id": "B", "name": "Check B", "status": "PASS",
                    "severity": "LOW", "current_value": "0",
                    "expected_value": "0", "remediation": ""}
    return FakeAuditor


class TestRunAudit(unittest.TestCase):
    def test_stops_between_checks(self):
        stop = threading.Event()
        fake = make_fake_auditor(stop)
        with patch.object(adapters, "WindowsConfigAuditor", fake):
            out = adapters.run_audit(stop)
        self.assertEqual(fake.calls, ["a"])        # check_b never ran
        self.assertEqual(len(out), 1)

    def test_crashing_check_becomes_error_and_audit_continues(self):
        stop = threading.Event()
        fake = make_fake_auditor(stop, crash_first=True)
        with patch.object(adapters, "WindowsConfigAuditor", fake):
            out = adapters.run_audit(stop)
        self.assertEqual(fake.calls, ["a", "b"])
        self.assertEqual(out[0]["status"], "ERROR")
        self.assertEqual(out[1]["status"], "PASS")

    def test_details_built_from_current_and_expected(self):
        stop = threading.Event()
        fake = make_fake_auditor(stop)
        with patch.object(adapters, "WindowsConfigAuditor", fake):
            out = adapters.run_audit(stop)
        self.assertEqual(out[0]["details"], "Current: 1 | Expected: 0")
        self.assertEqual(out[0]["check"], "A: Check A")


if __name__ == "__main__":
    unittest.main()