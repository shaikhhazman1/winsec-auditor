import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock, patch

import main as app
from core import safety


def item(check="x", status="open", severity="INFO"):
    return {"check": check, "status": status, "severity": severity,
            "details": "", "remediation": ""}


class TestBuildResults(unittest.TestCase):
    def setUp(self):
        self.audit = [item("a", "PASS"), item("b", "FAIL"), item("c", "ERROR")]

    def test_without_correlation_lists_fail_and_error(self):
        out = app.build_results([item("p")], self.audit, None)
        self.assertEqual([r["check"] for r in out], ["p", "b", "c"])

    def test_with_correlation_uses_correlated_plus_errors(self):
        out = app.build_results([item("p")], self.audit, [item("corr")])
        self.assertEqual([r["check"] for r in out], ["p", "corr", "c"])


class TestMainFlow(unittest.TestCase):
    def setUp(self):
        safety.stop_event.clear()
        self.addCleanup(safety.stop_event.clear)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.scan = MagicMock(return_value=[item("PORT-445")])
        self.audit = MagicMock(return_value=[item("a", "FAIL", "HIGH")])
        self.corr = MagicMock(return_value=[item("corr", "VULNERABLE", "CRITICAL")])
        self.write = MagicMock()
        self.loader = MagicMock(
            return_value=(self.scan, self.audit, self.corr, self.write))
        self.resolve = MagicMock(return_value=[445])

    def run_main(self, extra=None, output=None, disclaimer=True):
        argv = ["main.py", "--output", output or self.tmp.name] + (extra or [])
        with patch("sys.argv", argv), \
                patch.object(app, "show_disclaimer", return_value=disclaimer), \
                patch.object(app, "register_kill_switch"), \
                patch.object(app, "resolve_ports", self.resolve), \
                patch.object(app, "load_stages", self.loader), \
                patch.object(app.platform, "system", return_value="Windows"), \
                redirect_stdout(io.StringIO()):
            return app.main()

    def test_full_local_run_uses_correlation(self):
        code = self.run_main()
        self.assertEqual(code, app.EXIT_OK)
        written = self.write.call_args[0][0]
        self.assertEqual([r["check"] for r in written], ["PORT-445", "corr"])

    def test_abort_keeps_partial_results_and_labels_them(self):
        def aborting_scan(*args):
            safety.stop_event.set()                 # simulate Ctrl+C
            return [item("PORT-80")]
        self.scan.side_effect = aborting_scan
        code = self.run_main()
        self.assertEqual(code, app.EXIT_ABORTED)
        self.audit.assert_not_called()
        written = self.write.call_args[0][0]
        self.assertEqual(written[-1]["check"], "run_status")
        self.assertEqual(written[-1]["status"], "PARTIAL")

    def test_module_crash_still_writes_report(self):
        self.scan.side_effect = RuntimeError("boom")
        code = self.run_main()
        self.assertEqual(code, app.EXIT_MODULE_FAILED)
        self.write.assert_called_once()

    def test_out_of_scope_loads_nothing(self):
        code = self.run_main(["--target", "8.8.8.8"])
        self.assertEqual(code, app.EXIT_ERROR)
        self.loader.assert_not_called()
        self.resolve.assert_not_called()

    def test_refused_disclaimer_loads_nothing(self):
        code = self.run_main(disclaimer=False)
        self.assertEqual(code, app.EXIT_ERROR)
        self.loader.assert_not_called()

    def test_dry_run_creates_and_loads_nothing(self):
        new_dir = str(Path(self.tmp.name) / "should_not_exist")
        code = self.run_main(["--dry-run"], output=new_dir)
        self.assertEqual(code, app.EXIT_OK)
        self.loader.assert_not_called()
        self.assertFalse(Path(new_dir).exists())

    def test_remote_target_skips_correlation(self):
        code = self.run_main(["--target", "192.168.1.10", "--scope", "192.168.1.0/24"])
        self.assertEqual(code, app.EXIT_OK)
        self.corr.assert_not_called()
        written = self.write.call_args[0][0]
        self.assertEqual([r["check"] for r in written], ["PORT-445", "a"])

    def test_empty_run_still_writes_a_summary_item(self):
        self.scan.return_value = []
        self.audit.return_value = []
        self.run_main()
        written = self.write.call_args[0][0]
        self.assertEqual(written[0]["check"], "summary")


if __name__ == "__main__":
    unittest.main()