"""Unit tests for the port scanner. Everything runs against 127.0.0.1 only.

Run:  python -m unittest discover -s tests -v
"""
import socket
import threading
import time
import unittest

from modules.scanner import PortScanner, PortState, RateLimiter, Severity, parse_ports
from modules.scanner.port_scanner import clean_banner, rate_severity, PortResult
from modules.scanner.services import identify_service


class FakeService:
    """Tiny local TCP server that sends a fixed banner (or stays silent)."""

    def __init__(self, banner: bytes = b""):
        self.banner = banner
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen()
        self.port = self.sock.getsockname()[1]
        self.running = True
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        self.sock.settimeout(0.2)
        while self.running:
            try:
                conn, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            with conn:
                if self.banner:
                    conn.sendall(self.banner)
                time.sleep(0.3)

    def close(self):
        self.running = False
        self.sock.close()


def free_port() -> int:
    """A port that is (almost certainly) closed: bind, read the number, release."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ParsePortsTests(unittest.TestCase):
    def test_list_range_and_dedup(self):
        self.assertEqual(parse_ports("22, 80,79-81,22"), [22, 79, 80, 81])

    def test_profiles(self):
        self.assertIn(445, parse_ports("quick"))
        self.assertIn(3389, parse_ports("windows"))
        self.assertEqual(len(parse_ports("all")), 65535)

    def test_invalid_input(self):
        for bad in ["", "0", "65536", "abc", "100-10", "1-x"]:
            with self.assertRaises(ValueError, msg=bad):
                parse_ports(bad)


class ServiceIdTests(unittest.TestCase):
    def test_banner_beats_port(self):
        self.assertEqual(identify_service(2222, "SSH-2.0-OpenSSH_for_Windows_8.1"),
                         ("ssh", "OpenSSH_for_Windows_8.1", "banner"))

    def test_http_server_header(self):
        service, product, conf = identify_service(80, "HTTP/1.1 200 OK | Server: Microsoft-IIS/10.0")
        self.assertEqual((service, product, conf), ("http", "Microsoft-IIS/10.0", "banner"))

    def test_port_fallback_and_unknown(self):
        self.assertEqual(identify_service(445, ""), ("microsoft-ds", "", "port"))
        self.assertEqual(identify_service(40000, ""), ("unknown", "", ""))

    def test_clean_banner_strips_cookies_and_control_chars(self):
        raw = b"HTTP/1.1 200 OK\r\nSet-Cookie: session=secret\r\nServer: IIS\r\n\r\n"
        self.assertEqual(clean_banner(raw), "HTTP/1.1 200 OK | Server: IIS")
        self.assertEqual(clean_banner(b"hi\x00\x07there\r\n"), "hi there")

    def test_weak_tls_raises_severity(self):
        result = PortResult(443, PortState.OPEN, tls_version="TLSv1")
        self.assertEqual(rate_severity(result)[0], Severity.MEDIUM)


class RateLimiterTests(unittest.TestCase):
    def test_limits_rate(self):
        limiter = RateLimiter(rate=20)
        start = time.monotonic()
        for _ in range(21):
            limiter.acquire()
        # 1 token up front, 20 more at 20/s, so about 1 second
        self.assertGreaterEqual(time.monotonic() - start, 0.9)

    def test_stop_event_wakes_waiters(self):
        limiter, stop = RateLimiter(rate=0.1), threading.Event()
        limiter.acquire(stop)          # use the only token
        stop.set()
        self.assertFalse(limiter.acquire(stop))


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.ssh = FakeService(b"SSH-2.0-TestSSH_1.0\r\n")
        self.silent = FakeService()
        self.closed = free_port()
        # Windows retries a refused connection for about 2 s before reporting it,
        # so the timeout must be longer than that or closed ports look "filtered".
        self.scanner = PortScanner(timeout=3.0, banner_timeout=0.5, threads=10, rate=0)

    def tearDown(self):
        self.ssh.close()
        self.silent.close()

    def test_states_and_banner(self):
        report = self.scanner.scan("127.0.0.1", [self.ssh.port, self.silent.port, self.closed])
        by_port = {r.port: r for r in report.results}
        self.assertEqual(by_port[self.ssh.port].state, PortState.OPEN)
        self.assertEqual(by_port[self.ssh.port].service, "ssh")
        self.assertEqual(by_port[self.ssh.port].product, "TestSSH_1.0")
        self.assertEqual(by_port[self.silent.port].state, PortState.OPEN)
        self.assertEqual(by_port[self.silent.port].banner, "")
        self.assertEqual(by_port[self.closed].state, PortState.CLOSED)
        self.assertFalse(report.interrupted)

    def test_findings_use_shared_format(self):
        report = self.scanner.scan("127.0.0.1", [self.ssh.port])
        finding = report.to_findings()[0].to_dict()
        self.assertEqual(finding["source"], "scanner")
        self.assertEqual(finding["check_id"], f"PORT-{self.ssh.port}")
        self.assertIn("TestSSH_1.0", finding["evidence"])

    def test_kill_switch_returns_partial_results(self):
        stop = threading.Event()
        slow = PortScanner(timeout=0.5, threads=2, rate=5)   # ~5 ports per second
        ports = list(range(50000, 50100))
        threading.Timer(0.5, stop.set).start()
        report = slow.scan("127.0.0.1", ports, stop_event=stop)
        self.assertTrue(report.interrupted)
        self.assertLess(len(report.results), len(ports))
        self.assertGreater(report.counts()["not_scanned"], 0)

    def test_progress_callback(self):
        seen = []
        self.scanner.scan("127.0.0.1", [self.ssh.port, self.closed],
                          progress=lambda done, total, r: seen.append((done, total)))
        self.assertEqual(sorted(seen), [(1, 2), (2, 2)])


if __name__ == "__main__":
    unittest.main()
