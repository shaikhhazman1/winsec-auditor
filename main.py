#!/usr/bin/env python3
"""WinSec Auditor - Windows misconfiguration auditor and TCP port scanner."""
import argparse
import ipaddress
import platform
import sys
from pathlib import Path

from core.safety import (
    show_disclaimer, is_in_scope, resolve_host, register_kill_switch, stop_event,
)

DEFAULT_TARGET = "127.0.0.1"          # safe default: localhost only
DEFAULT_SCOPE = "127.0.0.0/24"        # safe default: loopback range
DEFAULT_PORTS = "quick"               # the scanner's small default profile
DEFAULT_OUTPUT = "./output/"
DEFAULT_RATE = 100.0                  # connections per second
MAX_RATE = 500.0                      # hard cap: the tool must not flood a host
DEFAULT_TIMEOUT = 3.0

EXIT_OK = 0
EXIT_ERROR = 1                        # refused, bad setup, nothing to run
EXIT_MODULE_FAILED = 3                # a module crashed, partial report written
EXIT_ABORTED = 130                    # standard exit code for Ctrl+C

# Every result written to the report must have these keys.
REQUIRED_KEYS = {"check", "status", "severity", "details", "remediation"}
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _bounded_float(value: str, low: float, high: float, name: str) -> float:
    """Parse a number and require low <= number <= high."""
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{name}: '{value}' is not a number")
    if not low <= number <= high:
        raise argparse.ArgumentTypeError(f"{name} must be between {low:g} and {high:g}")
    return number


def parse_rate(value: str) -> float:
    """1 to 500 connections/second. 0 or negative could disable throttling."""
    return _bounded_float(value, 1, MAX_RATE, "rate")


def parse_timeout(value: str) -> float:
    """0.1 to 30 seconds per connection attempt."""
    return _bounded_float(value, 0.1, 30, "timeout")


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser with help text and usage examples."""
    parser = argparse.ArgumentParser(
        prog="winsec-auditor",
        description=(
            "WinSec Auditor - Windows security misconfiguration auditor "
            "and TCP port scanner.\nFor AUTHORIZED testing only."
        ),
        epilog=(
            "examples:\n"
            "  python main.py --dry-run\n"
            "  python main.py --ports windows --rate 50\n"
            "  python main.py --target 192.168.56.101 --scope 192.168.56.0/24 --scan-only\n"
            "  python main.py --audit-only --output ./results/\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--target", default=DEFAULT_TARGET,
                        help=f"host to scan (default: {DEFAULT_TARGET})")
    parser.add_argument("--scope", default=DEFAULT_SCOPE,
                        help=f"authorized IP range or hostname (default: {DEFAULT_SCOPE})")
    parser.add_argument("--ports", default=DEFAULT_PORTS,
                        help="quick, windows, all, or e.g. 22,80,1-1024 "
                             f"(default: {DEFAULT_PORTS})")
    parser.add_argument("--rate", type=parse_rate, default=DEFAULT_RATE,
                        help=f"max connections per second, 1-{MAX_RATE:g} "
                             f"(default: {DEFAULT_RATE:g})")
    parser.add_argument("--timeout", type=parse_timeout, default=DEFAULT_TIMEOUT,
                        help=f"seconds per connection, 0.1-30 (default: {DEFAULT_TIMEOUT:g})")
    parser.add_argument("--output", default=DEFAULT_OUTPUT,
                        help=f"folder for results (default: {DEFAULT_OUTPUT})")
    parser.add_argument("--dry-run", action="store_true",
                        help="show what would run, without scanning or auditing")

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--scan-only", action="store_true",
                      help="run only the port scanner")
    mode.add_argument("--audit-only", action="store_true",
                      help="run only the Windows misconfiguration audit")

    return parser


def resolve_ports(spec: str) -> list[int]:
    """Turn a --ports value into a list of ports using the scanner's parser.

    Imported here, not at the top of the file, so no teammate code is
    loaded before the disclaimer and scope check have passed.
    Raises ValueError for a bad specification.
    """
    from modules.scanner import parse_ports
    return parse_ports(spec)


def load_stages():
    """Import the teammates' code. Called only after the safety checks pass."""
    from modules.adapters import run_scan, run_audit
    from modules.report import correlate, write_reports
    return run_scan, run_audit, correlate, write_reports


def plan_modules(args) -> tuple[list[str], list[str]]:
    """Decide which modules will run on this machine.

    The Windows audit needs winreg and Windows commands, so it is skipped
    on any other OS instead of crashing.
    """
    modules: list[str] = []
    notes: list[str] = []

    if not args.audit_only:
        modules.append("port scanner")

    if not args.scan_only:
        if platform.system() == "Windows":
            modules.append("Windows audit")
        else:
            notes.append(
                f"Windows audit skipped (running on {platform.system()}, not Windows)"
            )

    return modules, notes


def print_plan(args, ports: list[int], modules: list[str], notes: list[str]) -> None:
    """Print what the tool is about to do (used by --dry-run)."""
    print("\n[DRY RUN] Nothing will be scanned, audited or written.")
    print(f"  Target  : {args.target}")
    print(f"  Scope   : {args.scope}")
    print(f"  Ports   : {args.ports} ({len(ports)} port(s))")
    print(f"  Limits  : {args.rate:g} connections/s, {args.timeout:g}s timeout")
    print(f"  Output  : {args.output} (would be created on a real run)")
    print(f"  Modules : {', '.join(modules) if modules else 'none'}")
    if "Windows audit" in modules:
        print("            (the audit is read-only and checks THIS machine only)")
    for note in notes:
        print(f"  Note    : {note}")
    print()


def is_local_target(target: str) -> bool:
    """True only if EVERY IP the target resolves to is a loopback address.

    The audit reads THIS machine, so correlating it with the open ports
    of a different host would give wrong conclusions.
    """
    try:
        return all(ipaddress.ip_address(ip).is_loopback for ip in resolve_host(target))
    except ValueError:
        return False  # cannot resolve: treat as not local (safe default)


def validate_results(items, source: str) -> list[dict]:
    """Keep only well-formed result dicts and warn about the rest."""
    if not isinstance(items, list):
        print(f"[!] {source}: expected a list, got {type(items).__name__}. Output ignored.")
        return []

    good = [i for i in items if isinstance(i, dict) and REQUIRED_KEYS <= i.keys()]
    bad = len(items) - len(good)
    if bad:
        print(f"[!] {source}: dropped {bad} malformed result(s) "
              f"(each needs keys: {', '.join(sorted(REQUIRED_KEYS))})")
    return good


def run_stage(name: str, func, *args) -> tuple[list[dict], bool]:
    """Run one module safely. Returns (results, succeeded).

    A crash in one module must not take down the tool or lose the other
    modules' results. KeyboardInterrupt is not caught on purpose: the
    kill switch handles Ctrl+C.
    """
    try:
        return validate_results(func(*args), name), True
    except Exception as exc:
        print(f"[!] {name} failed: {exc}")
        return [], False


def build_results(scan: list[dict], audit: list[dict], correlated) -> list[dict]:
    """Choose what goes into the report.

    correlated is None when correlation did not run (remote target, abort
    or crash). Then failed and errored audit checks are listed directly.
    Otherwise correlate() already lists every failed audit check, so only
    the checks that could not run (ERROR) are added.
    """
    if correlated is None:
        return scan + [a for a in audit if a.get("status") in ("FAIL", "ERROR")]
    return scan + correlated + [a for a in audit if a.get("status") == "ERROR"]


def summarize(results: list[dict]) -> dict[str, int]:
    """Count results per severity level."""
    counts = {level: 0 for level in SEVERITY_ORDER}
    for item in results:
        level = str(item["severity"]).upper()
        counts[level] = counts.get(level, 0) + 1
    return counts


def print_summary(results: list[dict], aborted: bool, failed: list[str]) -> None:
    """Print the end-of-run summary."""
    counts = summarize(results)
    levels = SEVERITY_ORDER + sorted(k for k in counts if k not in SEVERITY_ORDER)
    print("\n" + "=" * 50)
    print(" RUN SUMMARY")
    print("=" * 50)
    print(f"  Status   : {'ABORTED (partial results)' if aborted else 'complete'}")
    print(f"  Findings : {len(results)} total")
    for level in levels:
        if counts.get(level):
            print(f"    {level:<9}: {counts[level]}")
    if failed:
        print(f"  Failed   : {', '.join(failed)}")
    print("=" * 50)


def main() -> int:
    """Run the tool and return the process exit code."""
    args = build_parser().parse_args()

    # 1. Disclaimer first: nothing else runs without confirmation.
    if not show_disclaimer():
        print("[!] Authorization not confirmed. Exiting.")
        return EXIT_ERROR
    print("[+] Authorization confirmed.")

    # 2. Clean the inputs once, so the value we check is the value we use.
    args.target = args.target.strip()
    args.scope = args.scope.strip()

    # 3. Scope check: refuse to continue if the target is not authorized.
    allowed, message = is_in_scope(args.target, args.scope)
    if not allowed:
        print(f"[!] Out of scope: {message}")
        return EXIT_ERROR
    print(f"[+] Scope OK: {message}")

    # 4. Ports (the scanner's parser is imported only now, after the checks).
    try:
        ports = resolve_ports(args.ports)
    except ValueError as exc:
        print(f"[!] Invalid --ports: {exc}")
        return EXIT_ERROR

    # 5. Work out what would run on this machine.
    modules, notes = plan_modules(args)

    # 6. Dry-run: show the plan and stop. No files are created.
    if args.dry_run:
        print_plan(args, ports, modules, notes)
        return EXIT_OK

    for note in notes:
        print(f"[!] {note}")
    if not modules:
        print("[!] Nothing to run on this system. Exiting.")
        return EXIT_ERROR

    # 7. Load the teammates' code, now that every safety check has passed.
    try:
        run_scan, run_audit, correlate, write_reports = load_stages()
    except Exception as exc:
        print(f"[!] Cannot load the tool's modules: {exc}")
        return EXIT_ERROR

    # 8. Create the output folder (real runs only).
    output_dir = Path(args.output)
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"[!] Cannot create output folder '{output_dir}': {exc}")
        return EXIT_ERROR

    # 9. Arm the kill switch only now, so Ctrl+C at the earlier
    #    prompts still behaves normally.
    register_kill_switch()
    print("[*] Kill switch active: press Ctrl+C to abort safely.")

    local = is_local_target(args.target)
    scan_results: list[dict] = []
    audit_results: list[dict] = []
    failed: list[str] = []

    # 10. Stage 1: port scan.
    if "port scanner" in modules:
        print(f"[*] Port scan: {args.target} ({len(ports)} port(s), max {args.rate:g}/s)")
        scan_results, ok = run_stage("scanner", run_scan, args.target, ports,
                                     stop_event, args.rate, args.timeout)
        if not ok:
            failed.append("scanner")

    # 11. Stage 2: Windows audit (skipped if the user already aborted).
    if "Windows audit" in modules and not stop_event.is_set():
        if not local:
            print("[!] Note: the audit checks THIS machine, not the scan target.")
        print("[*] Windows audit (read-only, local machine)")
        audit_results, ok = run_stage("audit", run_audit, stop_event)
        if not ok:
            failed.append("audit")

    # 12. Stage 3: correlation. Skipped after an abort (partial data could
    #     mislead) and for remote targets (the audit describes this machine).
    aborted = stop_event.is_set()
    correlated = None
    if audit_results and not aborted:
        if local:
            print("[*] Correlating scan and audit findings")
            extra, ok = run_stage("correlate", correlate,
                                  scan_results, audit_results, args.target)
            if ok:
                correlated = extra
            else:
                failed.append("correlate")
        else:
            print("[!] Correlation skipped: target is not this machine.")

    results = build_results(scan_results, audit_results, correlated)

    # 13. Label the run inside the data, so every report format shows it.
    if aborted:
        results.append({
            "check": "run_status", "status": "PARTIAL", "severity": "INFO",
            "details": "Run aborted by the user. Results are incomplete.",
            "remediation": "Run the tool again to get a complete report.",
        })
    elif not results and not failed:
        results.append({
            "check": "summary", "status": "PASS", "severity": "INFO",
            "details": "No open ports and no failed audit checks were found.",
            "remediation": "",
        })

    # 14. Always write what we have, even after an abort or a failure.
    try:
        write_reports(results, str(output_dir))
    except Exception as exc:
        print(f"[!] report failed: {exc}")
        failed.append("report")

    # 15. Summary and exit code.
    print_summary(results, aborted, failed)
    if aborted:
        return EXIT_ABORTED
    if failed:
        return EXIT_MODULE_FAILED
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())