"""Adapters: make the teammates' modules fit what main.py expects.

The scanner (Member 2) and the audit (Member 3) are classes. These thin
wrappers call them and add two keys, 'check' and 'details', which the
report writer needs. Every original key is kept, so correlate() still
sees check_id, status, port, related_ports and so on.
"""
from modules.scanner import PortScanner
from modules.win_audit import WindowsConfigAuditor

DEFAULT_RATE = 100.0
DEFAULT_TIMEOUT = 3.0


def _with_aliases(item: dict) -> dict:
    """Return a copy of a result that also has 'check' and 'details'."""
    out = dict(item)
    check_id = item.get("check_id", "unknown")
    label = item.get("name") or item.get("title") or ""
    out.setdefault("check", f"{check_id}: {label}" if label else str(check_id))
    out.setdefault(
        "details",
        item.get("evidence")
        or f"Current: {item.get('current_value')} | Expected: {item.get('expected_value')}",
    )
    return out


def run_scan(target, ports, stop_event, rate=DEFAULT_RATE, timeout=DEFAULT_TIMEOUT):
    """Run the TCP port scan and return a list of result dicts.

    The scanner checks stop_event itself and returns partial results
    when it is set, so Ctrl+C never loses what was already found.
    """
    scanner = PortScanner(timeout=timeout, rate=rate)
    report = scanner.scan(target, ports, stop_event)
    return [_with_aliases(f.to_dict()) for f in report.to_findings()]


def run_audit(stop_event):
    """Run the read-only Windows checks one by one, honouring stop_event.

    The auditor has no stop_event of its own, so we call each check_*
    method ourselves and look at the flag between them. A check that
    crashes becomes an ERROR result instead of stopping the audit.
    """
    auditor = WindowsConfigAuditor()
    # vars() keeps the order the methods were written in the class.
    names = [name for name in vars(WindowsConfigAuditor) if name.startswith("check_")]

    results = []
    for name in names:
        if stop_event.is_set():
            break
        try:
            result = getattr(auditor, name)()
        except Exception as exc:  # one broken check must not kill the audit
            result = {
                "check_id": name,
                "name": name,
                "status": "ERROR",
                "severity": "MEDIUM",
                "current_value": f"check crashed: {exc}",
                "expected_value": "N/A",
                "related_ports": [],
                "remediation": "Run the terminal as Administrator and try again.",
            }
        results.append(_with_aliases(result))
    return results