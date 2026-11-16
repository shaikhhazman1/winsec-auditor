import unittest
from unittest.mock import patch
from core.safety import kill_switch_check

class TestKillSwitch(unittest.TestCase):
    @patch('builtins.input', return_value='')
    def test_killswitch_proceed(self, mock_input):
        # Simulate user tekan ENTER. Dia tak patut exit.
        try:
            kill_switch_check()
        except SystemExit:
            self.fail("Kill switch exited on ENTER press!")

if __name__ == '__main__':
    unittest.main()