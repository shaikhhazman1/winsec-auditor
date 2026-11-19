import unittest

from core.safety import is_in_scope


class TestScope(unittest.TestCase):
    def test_ip_inside_cidr(self):
        self.assertTrue(is_in_scope("127.0.0.1", "127.0.0.0/24")[0])

    def test_ip_outside_cidr(self):
        self.assertFalse(is_in_scope("8.8.8.8", "127.0.0.0/24")[0])

    def test_single_ip_scope(self):
        self.assertTrue(is_in_scope("127.0.0.1", "127.0.0.1")[0])

    def test_ipv6_inside(self):
        self.assertTrue(is_in_scope("::1", "::1/128")[0])

    def test_ipv4_target_ipv6_scope(self):
        self.assertFalse(is_in_scope("127.0.0.1", "::1/128")[0])

    def test_empty_target(self):
        self.assertFalse(is_in_scope("", "127.0.0.0/24")[0])

    def test_invalid_ip(self):
        self.assertFalse(is_in_scope("999.999.1.1", "127.0.0.0/24")[0])

    def test_unresolvable_hostname(self):
        # .invalid is a reserved TLD that never resolves
        self.assertFalse(is_in_scope("nonexistent.invalid", "127.0.0.0/24")[0])


if __name__ == "__main__":
    unittest.main()