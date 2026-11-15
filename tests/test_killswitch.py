import unittest

from core import safety


class TestKillSwitch(unittest.TestCase):
    def setUp(self):
        safety.stop_event.clear()

    def tearDown(self):
        safety.stop_event.clear()

    def test_first_signal_sets_event(self):
        safety._handle_abort(2, None)
        self.assertTrue(safety.stop_event.is_set())

    def test_second_signal_forces_exit(self):
        safety._handle_abort(2, None)
        with self.assertRaises(SystemExit) as ctx:
            safety._handle_abort(2, None)
        self.assertEqual(ctx.exception.code, 130)


if __name__ == "__main__":
    unittest.main()