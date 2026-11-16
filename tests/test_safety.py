import unittest
import sys
from core.safety import enforce_scope

class TestSafety(unittest.TestCase):
    def test_allowed_scope(self):
        # Test kalau target localhost, dia tak patut keluar (exit)
        try:
            enforce_scope("127.0.0.1")
        except SystemExit:
            self.fail("enforce_scope() exited on a valid target!")

if __name__ == '__main__':
    unittest.main()