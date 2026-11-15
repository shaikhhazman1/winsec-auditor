import unittest
from argparse import Namespace
from unittest.mock import patch

from main import plan_modules


def args(scan_only=False, audit_only=False):
    return Namespace(scan_only=scan_only, audit_only=audit_only)


class TestPlanModules(unittest.TestCase):
    @patch("platform.system", return_value="Windows")
    def test_windows_default_runs_both(self, _):
        modules, notes = plan_modules(args())
        self.assertEqual(modules, ["port scanner", "Windows audit"])
        self.assertEqual(notes, [])

    @patch("platform.system", return_value="Linux")
    def test_linux_skips_audit(self, _):
        modules, notes = plan_modules(args())
        self.assertEqual(modules, ["port scanner"])
        self.assertEqual(len(notes), 1)

    @patch("platform.system", return_value="Linux")
    def test_linux_audit_only_runs_nothing(self, _):
        modules, _ = plan_modules(args(audit_only=True))
        self.assertEqual(modules, [])

    @patch("platform.system", return_value="Windows")
    def test_scan_only(self, _):
        modules, _ = plan_modules(args(scan_only=True))
        self.assertEqual(modules, ["port scanner"])

    @patch("platform.system", return_value="Windows")
    def test_audit_only(self, _):
        modules, _ = plan_modules(args(audit_only=True))
        self.assertEqual(modules, ["Windows audit"])


if __name__ == "__main__":
    unittest.main()