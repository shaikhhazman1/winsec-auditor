"""
Threaded TCP connect port scanner (Member 2).

How it works
------------
* TCP connect scan: a full three-way handshake through the operating
  system's normal socket API. No raw packets, so no admin rights are needed
  and the scan is easy to see in logs. That is the safe, auditable choice.
* A thread pool scans many ports at once. A token-bucket rate limiter caps
  how many new connections start per second across all threads, so the scan
  cannot flood the target.
* Each port ends up open / closed / filtered:
      handshake completes   -> open
      connection refused    -> closed   (host replied with RST)
      timeout / unreachable -> filtered (usually a firewall drop)
* On open ports a light, read-mostly fingerprint runs:
      - services that speak first (SSH, FTP, SMTP...) -> just read the banner
      - HTTP ports  -> one HEAD request
      - TLS ports   -> handshake only, record TLS version and cipher
  Unknown services are never sent data, so nothing unexpected is triggered.
* The scan watches a `threading.Event`. When Member 1's kill switch sets it,
  workers stop picking up ports and the partial results are still returned.

Scope checking, the legal banner and report files are handled by other
modules (main.py, correlation/report). This module assumes it was given an
already-authorised target.
"""
from __future__ import annotations

import ipaddress
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from typing import Callable, Iterable, List, Optional, Tuple

from .models import Finding, PortState, Severity, utc_now
from .services import (HTTP_PORTS, KNOWN_PORTS, PORT_PROFILES, TLS_HTTP_PORTS,
                       TLS_PORTS, UNKNOWN_ADVICE, UNKNOWN_SEVERITY,
                       identify_service)

MAX_BANNER_BYTES = 1024   # never read more than 1 KB from a service
MAX_BANNER_CHARS = 200    # and keep at most 200 characters in the report
WEAK_TLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
USER_AGENT = "WinComplianceScanner/1.0 (authorised audit)"

ProgressCallback = Callable[[int, int, "PortResult"], None]


# --------------------------------------------------------------------------
# Input helpers
# --------------------------------------------------------------------------
def parse_ports(spec: str) -> List[int]:
    """Turn '22,80,1000-1010,windows' into a sorted list of unique ports."""
    if not spec or not spec.strip():
        raise ValueError("empty port specification")
    ports = set()
    for part in spec.split(","):
        part = part.strip().lower()
        if not part:
            continue
        if part in PORT_PROFILES:
            ports.update(PORT_PROFILES[part])
        elif part == "all":
            ports.update(range(1, 65536))
        elif "-" in part:
            low_text, high_text = part.split("-", 1)
            low, high = _to_port(low_text), _to_port(high_text)
            if low > high:
                raise ValueError(f"invalid range '{part}': start is greater than end")
            ports.update(range(low, high + 1))
        else:
            ports.add(_to_port(part))
    if not ports:
        raise ValueError("no ports selected")
    return sorted(ports)


def _to_port(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        profiles = ", ".join(list(PORT_PROFILES) + ["all"])
        raise ValueError(f"'{text}' is not a port number or a profile ({profiles})") from None
    if not 1 <= value <= 65535:
        raise ValueError(f"port {value} is outside 1-65535")
    return value


def resolve_target(target: str) -> Tuple[int, str]:
    """Resolve a hostname or IP once, preferring IPv4. Returns (family, ip)."""
    try:
        infos = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"cannot resolve '{target}': {exc.strerror}") from None
    infos.sort(key=lambda info: info[0] != socket.AF_INET)
    family, _, _, _, sockaddr = infos[0]
    return family, sockaddr[0]


# --------------------------------------------------------------------------
# Rate limiting
# --------------------------------------------------------------------------
class RateLimiter:
    """Thread-safe token bucket: at most `rate` new connections per second.

    Tokens refill continuously. Each connection costs one token; a thread
    with no token waits just long enough for the next one. rate <= 0 turns
    limiting off.
    """

    def __init__(self, rate: float):
        self.rate = rate
        self.capacity = max(1.0, rate / 10)   # allow only a small burst
        self.tokens = self.capacity
        self.updated = time.monotonic()
        self.lock = threading.Lock()

    def acquire(self, stop_event: Optional[threading.Event] = None) -> bool:
        """Block until a token is free. Returns False if the scan was stopped."""
        if self.rate <= 0:
            return True
        while True:
            with self.lock:
                now = time.monotonic()
                self.tokens = min(self.capacity,
                                  self.tokens + (now - self.updated) * self.rate)
                self.updated = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return True
                wait = (1 - self.tokens) / self.rate
            # Waiting on the event (not sleep) lets the kill switch wake us at once.
            if stop_event is not None:
                if stop_event.wait(wait):
                    return False
            else:
                time.sleep(wait)


# --------------------------------------------------------------------------
# Result objects
# --------------------------------------------------------------------------
@dataclass
class PortResult:
    port: int
    state: PortState
    service: str = "unknown"
    product: str = ""
    confidence: str = ""        # "banner", "port" or ""
    banner: str = ""
    tls_version: str = ""
    tls_cipher: str = ""
    latency_ms: Optional[float] = None
    error: str = ""

    def to_dict(self) -> dict:
        data = asdict(self)
        data["state"] = self.state.value
        return data


@dataclass
class ScanReport:
    target: str
    ip: str
    ports_requested: int
    started: str
    finished: str = ""
    duration_s: float = 0.0
    interrupted: bool = False
    settings: dict = field(default_factory=dict)
    results: List[PortResult] = field(default_factory=list)

    @property
    def open_ports(self) -> List[PortResult]:
        return [r for r in self.results if r.state is PortState.OPEN]

    def counts(self) -> dict:
        summary = {state.value: 0 for state in PortState}
        for r in self.results:
            summary[r.state.value] += 1
        summary["not_scanned"] = self.ports_requested - len(self.results)
        return summary

    def to_dict(self) -> dict:
        return {
            "module": "port_scanner",
            "target": self.target,
            "ip": self.ip,
            "started": self.started,
            "finished": self.finished,
            "duration_s": self.duration_s,
            "interrupted": self.interrupted,
            "settings": self.settings,
            "ports_requested": self.ports_requested,
            "summary": self.counts(),
            "results": [r.to_dict() for r in self.results],
        }

    def to_findings(self) -> List[Finding]:
        """Open ports in the shared Finding format for correlation/reporting."""
        return [result_to_finding(self.target, r) for r in self.open_ports]


def rate_severity(result: PortResult) -> Tuple[Severity, str]:
    """Baseline risk from the port table, raised if old TLS was negotiated."""
    _, severity, advice = KNOWN_PORTS.get(
        result.port, ("unknown", UNKNOWN_SEVERITY, UNKNOWN_ADVICE))
    if result.tls_version in WEAK_TLS:
        severity = Severity.highest(severity, Severity.MEDIUM)
        advice += (f" The server accepted deprecated {result.tls_version}; "
                   "disable TLS 1.0/1.1 in the SCHANNEL registry settings.")
    return severity, advice


def result_to_finding(target: str, result: PortResult) -> Finding:
    severity, advice = rate_severity(result)
    evidence = [f"TCP handshake completed in {result.latency_ms} ms"]
    if result.banner:
        evidence.append(f"banner: {result.banner}")
    if result.tls_version:
        evidence.append(f"TLS: {result.tls_version} {result.tls_cipher}".strip())
    if result.confidence:
        evidence.append(f"service identified by {result.confidence}")
    label = result.service + (f" - {result.product}" if result.product else "")
    return Finding(
        source="scanner",
        check_id=f"PORT-{result.port}",
        title=f"TCP {result.port} open ({label})",
        status=PortState.OPEN.value,
        severity=severity,
        target=target,
        category="Network Exposure",
        port=result.port,
        protocol="tcp",
        service=result.service,
        evidence="; ".join(evidence),
        remediation=advice,
    )


# --------------------------------------------------------------------------
# Banner helpers
# --------------------------------------------------------------------------
def clean_banner(raw: bytes) -> str:
    """Make a banner safe to print: printable text only, one line, trimmed.

    For HTTP only the status line and a few identifying headers are kept, so
    cookies or other session data never land in the report.
    """
    if not raw:
        return ""
    text = raw.decode("utf-8", errors="replace")
    if text.startswith("HTTP/"):
        lines = text.splitlines()
        wanted = ("server:", "x-powered-by:", "www-authenticate:")
        kept = [lines[0]] + [ln for ln in lines[1:] if ln.lower().startswith(wanted)]
        text = " | ".join(kept)
    text = "".join(ch if ch.isprintable() else " " for ch in text)
    return " ".join(text.split())[:MAX_BANNER_CHARS]


def _recv_headers(sock: socket.socket) -> bytes:
    """Read until the end of the HTTP headers, the size cap, or a timeout."""
    data = b""
    while len(data) < MAX_BANNER_BYTES and b"\r\n\r\n" not in data:
        try:
            chunk = sock.recv(MAX_BANNER_BYTES - len(data))
        except (socket.timeout, TimeoutError):
            break
        if not chunk:
            break
        data += chunk
    return data


def _http_head(sock: socket.socket, ip: str) -> bytes:
    host = f"[{ip}]" if ":" in ip else ip
    request = (f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\n"
               "Connection: close\r\n\r\n")
    sock.sendall(request.encode("ascii"))
    return _recv_headers(sock)


def _tls_context() -> ssl.SSLContext:
    # We only read handshake metadata and never trust the certificate,
    # so verification is off. Old versions are allowed so we can detect them.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        pass  # some OpenSSL builds refuse; default settings are still fine
    return ctx


# --------------------------------------------------------------------------
# Scanner
# --------------------------------------------------------------------------
class PortScanner:
    """Scan one target's TCP ports. Safe defaults: 3 s timeout, 50 threads,
    100 new connections per second."""

    def __init__(self, timeout: float = 3.0, threads: int = 50,
                 rate: float = 100.0, grab_banners: bool = True,
                 banner_timeout: float = 2.0):
        if timeout <= 0 or banner_timeout <= 0:
            raise ValueError("timeouts must be greater than 0")
        if not 1 <= threads <= 500:
            raise ValueError("threads must be between 1 and 500")
        if rate < 0:
            raise ValueError("rate cannot be negative")
        self.timeout = timeout
        self.threads = threads
        self.rate = rate
        self.grab_banners = grab_banners
        self.banner_timeout = banner_timeout
        self.limiter = RateLimiter(rate)

    def settings(self) -> dict:
        return {"timeout": self.timeout, "threads": self.threads,
                "rate_per_s": self.rate, "grab_banners": self.grab_banners}

    # ---- public API ------------------------------------------------------
    def scan(self, target: str, ports: Iterable[int],
             stop_event: Optional[threading.Event] = None,
             progress: Optional[ProgressCallback] = None) -> ScanReport:
        """Scan `ports` on `target` and return a ScanReport.

        stop_event  set it (e.g. from a Ctrl+C handler) to stop early;
                    results gathered so far are still returned.
        progress    optional callback(done, total, result) after each port.
        """
        stop_event = stop_event or threading.Event()
        port_list = sorted(set(ports))
        family, ip = resolve_target(target)
        report = ScanReport(target=target, ip=ip, ports_requested=len(port_list),
                            started=utc_now(), settings=self.settings())
        started = time.perf_counter()

        pool = ThreadPoolExecutor(max_workers=max(1, min(self.threads, len(port_list))),
                                  thread_name_prefix="portscan")
        futures = []
        try:
            futures = [pool.submit(self._worker, family, ip, p, stop_event)
                       for p in port_list]
            done = 0
            for future in as_completed(futures):
                result = future.result()
                if result is not None and progress:
                    done += 1
                    progress(done, len(port_list), result)
        except KeyboardInterrupt:
            stop_event.set()   # fallback kill switch if no handler is installed
        finally:
            pool.shutdown(wait=True, cancel_futures=True)

        # Collect from the futures themselves so nothing is lost on interrupt.
        report.results = sorted(
            (f.result() for f in futures
             if f.done() and not f.cancelled() and f.result() is not None),
            key=lambda r: r.port)
        report.interrupted = stop_event.is_set()
        report.finished = utc_now()
        report.duration_s = round(time.perf_counter() - started, 2)
        return report

    def scan_port(self, family: int, ip: str, port: int) -> PortResult:
        """Probe a single port and fingerprint it if it is open."""
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            started = time.perf_counter()
            label = KNOWN_PORTS.get(port, ("unknown",))[0]
            try:
                sock.connect((ip, port))
            except ConnectionRefusedError:
                return PortResult(port, PortState.CLOSED, service=label)
            except (socket.timeout, TimeoutError):
                return PortResult(port, PortState.FILTERED, service=label,
                                  error="no response before timeout")
            except OSError as exc:   # e.g. host or network unreachable
                return PortResult(port, PortState.FILTERED, service=label,
                                  error=exc.strerror or str(exc))

            result = PortResult(port, PortState.OPEN,
                                latency_ms=round((time.perf_counter() - started) * 1000, 2))
            if self.grab_banners:
                self._fingerprint(sock, ip, result)

        result.service, result.product, result.confidence = identify_service(port, result.banner)
        return result

    # ---- internals -------------------------------------------------------
    def _worker(self, family: int, ip: str, port: int,
                stop_event: threading.Event) -> Optional[PortResult]:
        if stop_event.is_set() or not self.limiter.acquire(stop_event):
            return None   # scan was stopped before this port started
        try:
            return self.scan_port(family, ip, port)
        except Exception as exc:   # one bad port must never crash the whole scan
            return PortResult(port, PortState.ERROR, error=f"{type(exc).__name__}: {exc}")

    def _fingerprint(self, sock: socket.socket, ip: str, result: PortResult) -> None:
        """Grab a banner using the least intrusive method for the port."""
        sock.settimeout(self.banner_timeout)
        raw = b""
        try:
            if result.port in TLS_PORTS:
                with _tls_context().wrap_socket(sock) as tls:
                    result.tls_version = tls.version() or ""
                    result.tls_cipher = (tls.cipher() or ("",))[0]
                    if result.port in TLS_HTTP_PORTS:
                        raw = _http_head(tls, ip)
            elif result.port in HTTP_PORTS:
                raw = _http_head(sock, ip)
            else:
                raw = sock.recv(MAX_BANNER_BYTES)   # passive: wait for the service to speak
        except (socket.timeout, TimeoutError):
            pass   # silent service: open but no banner, which is normal (e.g. SMB, RDP)
        except ssl.SSLError as exc:
            result.error = f"TLS handshake failed: {exc.reason or exc}"
        except OSError as exc:
            result.error = f"banner read failed: {exc.strerror or exc}"
        result.banner = clean_banner(raw)


# --------------------------------------------------------------------------
# Console output and standalone test harness
# --------------------------------------------------------------------------
def format_table(report: ScanReport, show_closed: bool = False) -> str:
    rows = report.results if show_closed else report.open_ports
    lines = [f"Target: {report.target} ({report.ip})   "
             f"Ports: {report.ports_requested}   Time: {report.duration_s}s"
             + ("   [INTERRUPTED - partial results]" if report.interrupted else ""),
             "",
             f"{'PORT':<11}{'STATE':<10}{'SERVICE':<15}{'SEVERITY':<10}DETAILS",
             "-" * 81]
    for r in rows:
        severity = rate_severity(r)[0].value if r.state is PortState.OPEN else "-"
        details = r.product or r.banner or r.error
        if r.tls_version:
            details = f"[{r.tls_version}] {details}".strip()
        lines.append(f"{str(r.port) + '/tcp':<11}{r.state.value:<10}{r.service:<15}"
                     f"{severity:<10}{details[:40]}")
    if not rows:
        lines.append("(no open ports found)")
    summary = ", ".join(f"{k}={v}" for k, v in report.counts().items() if v)
    lines += ["", f"Summary: {summary}"]
    return "\n".join(lines)


def _standalone(argv: Optional[List[str]] = None) -> int:
    """Run only the scanner, for testing this module on its own.

    The full tool (main.py) adds the legal banner, authorisation prompt,
    scope validation and report files. To stay safe without those, this
    harness only accepts loopback or private (RFC 1918) addresses.
    """
    import argparse
    import json

    parser = argparse.ArgumentParser(
        prog="python -m modules.scanner",
        description="Standalone test harness for the port scanner module.",
        epilog="examples:\n"
               "  python -m modules.scanner                       # 127.0.0.1, quick profile\n"
               "  python -m modules.scanner 127.0.0.1 -p windows\n"
               "  python -m modules.scanner 192.168.56.10 -p 1-1024 --rate 50\n"
               "  python -m modules.scanner -p 80,443,8000-8100 --json",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target", nargs="?", default="127.0.0.1",
                        help="host to scan (default: 127.0.0.1)")
    parser.add_argument("-p", "--ports", default="quick",
                        help="ports, ranges or profiles: quick, windows, all (default: quick)")
    parser.add_argument("--timeout", type=float, default=3.0,
                        help="connect timeout in seconds (default 3; Windows needs ~2 s to report a closed port)")
    parser.add_argument("--threads", type=int, default=50, help="worker threads (1-500)")
    parser.add_argument("--rate", type=float, default=100.0,
                        help="max new connections per second, 0 = unlimited")
    parser.add_argument("--no-banner", action="store_true", help="skip banner grabbing")
    parser.add_argument("--show-closed", action="store_true", help="list closed/filtered ports too")
    parser.add_argument("--json", action="store_true", help="print JSON instead of a table")
    args = parser.parse_args(argv)

    try:
        ports = parse_ports(args.ports)
        _, ip = resolve_target(args.target)
        scanner = PortScanner(timeout=args.timeout, threads=args.threads,
                              rate=args.rate, grab_banners=not args.no_banner)
    except ValueError as exc:
        parser.error(str(exc))
    address = ipaddress.ip_address(ip)
    if not (address.is_loopback or address.is_private):
        parser.error(f"{ip} is not a loopback/private address. The standalone harness "
                     "refuses public targets; use main.py with a declared --scope.")

    print(f"[*] Scanning {len(ports)} port(s) on {args.target}  (Ctrl+C to stop)")
    report = scanner.scan(args.target, ports)
    print(json.dumps(report.to_dict(), indent=2) if args.json
          else format_table(report, args.show_closed))
    return 130 if report.interrupted else 0

