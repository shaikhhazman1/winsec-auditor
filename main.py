#!/usr/bin/env python3
"""WinSec Auditor - Windows misconfiguration auditor and TCP port scanner."""
import argparse
import platform
import sys
import time

from core.safety import (
    show_disclaimer, is_in_scope, register_kill_switch, stop_event,
)

# ---------------------------------------------------------------
# Teammate modules. If a module is not written yet, use a harmless
# placeholder so main.py still runs. Each placeholder is recorded
# in PLACEHOLDERS so the user is always told about it.
# ---------------------------------------------------------------
PLACEHOLDERS: list[str] = []

try:
    from modules.scanner import run_scan
except ImportError:
    PLACEHOLDERS.append("scanner")

    def run_scan(target, ports, stop_event):
        return []

try:
    from modules.audit import run_audit
except ImportError:
    PLACEHOLDERS.append("audit")

    def run_audit(stop_event):
        return []

try:
    from modules.report import correlate, write_reports
except ImportError:
    PLACEHOLDERS.append("report")

    def correlate(scan_results, audit_results):
        return []

    def write_reports(results, output_dir):
        return None

DEFAULT_TARGET = "127.0.0.1"          # safe default: localhost only
DEFAULT_SCOPE = "127.0.0.0/24"        # safe default: loopback range
DEFAULT_PORTS = "21,22,80,135,139,443,445,3389"
DEFAULT_OUTPUT = "./output/"
EXIT_ABORTED = 130                    # standard exit code for Ctrl+C


def parse_ports(value: str) -> list[int]:
    """Convert '80,443,445' into [80, 443, 445], validating each port."""
    ports = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue  # tolerate trailing commas like "80,443,"
        try:
            port = int(item)
        except ValueError:
            raise argparse.ArgumentTypeError(f"'{item}' is not a number")
        if not 1 <= port <= 65535:
            raise argparse.ArgumentTypeError(f"port {port} is outside 1-65535")
        ports.append(port)
    if not ports:
        raise argparse.ArgumentTypeError("no ports given")
    return sorted(set(ports))


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
            "  python main.py --target 127.0.0.1 --scope 127.0.0.0/24 --ports 80,443,445\n"
            "  python main.py --audit-only --output ./results/\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--target", default=DEFAULT_TARGET,
                        help=f"host to scan (default: {DEFAULT_TARGET})")
    parser.add_argument("--scope", default=DEFAULT_SCOPE,
                        help=f"authorized IP range or hostname (default: {DEFAULT_SCOPE})")
    parser.add_argument("--ports", type=parse_ports, default=parse_ports(DEFAULT_PORTS),
                        help=f"comma-separated ports (default: {DEFAULT_PORTS})")
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


def plan_modules(args) -> tuple[list[str], list[str]]:
    """Decide which modules will run on this machine.

    Returns (modules_to_run, notes). The Windows audit needs winreg,
    netsh and PowerShell, so it is skipped on any other OS instead of
    crashing.
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


def print_plan(args, modules: list[str], notes: list[str]) -> None:
    """Print what the tool is about to do (used by --dry-run)."""
    print("\n[DRY RUN] Nothing will be scanned, audited or written.")
    print(f"  Target  : {args.target}")
    print(f"  Scope   : {args.scope}")
    print(f"  Ports   : {', '.join(str(p) for p in args.ports)}")
    print(f"  Output  : {args.output} (would be created on a real run)")
    print(f"  Modules : {', '.join(modules) if modules else 'none'}")
    if "Windows audit" in modules:
        print("            (the audit is read-only and checks THIS machine only)")
    for note in notes:
        print(f"  Note    : {note}")
    print()


def simulate_work(results: list, steps: int = 20) -> None:
    """TEMPORARY: fake workload so we can test the kill switch.

    Removed in Step 6 when the real modules are connected.
    """
    for i in range(1, steps + 1):
        if stop_event.is_set():
            return  # abort cleanly, keep what we have so far
        time.sleep(0.5)
        results.append({"check": f"fake-task-{i}", "status": "DONE"})
        print(f"    finished task {i}/{steps}")


def main() -> None:
    args = build_parser().parse_args()

    # 1. Disclaimer first: nothing else runs without confirmation.
    if not show_disclaimer():
        print("[!] Authorization not confirmed. Exiting.")
        sys.exit(1)
    print("[+] Authorization confirmed.")

    # 2. Scope check: refuse to continue if the target is not authorized.
    allowed, message = is_in_scope(args.target, args.scope)
    if not allowed:
        print(f"[!] Out of scope: {message}")
        sys.exit(1)
    print(f"[+] Scope OK: {message}")

    # 3. Work out what would run on this machine.
    modules, notes = plan_modules(args)
    if PLACEHOLDERS:
        print(f"[!] Placeholder in use for: {', '.join(PLACEHOLDERS)} (module not found)")

    # 4. Dry-run: show the plan and stop. No files are created.
    if args.dry_run:
        print_plan(args, modules, notes)
        sys.exit(0)

    for note in notes:
        print(f"[!] {note}")
    if not modules:
        print("[!] Nothing to run on this system. Exiting.")
        sys.exit(1)

    # 5. Arm the kill switch only now, so Ctrl+C at the earlier
    #    prompts still behaves normally.
    register_kill_switch()
    print("[*] Kill switch active: press Ctrl+C to abort safely.")

    # 6. Run the work (temporary stub until Step 6).
    results: list = []
    simulate_work(results)

    # 7. Report whether the run was complete or partial.
    if stop_event.is_set():
        print(f"[!] Run ABORTED. Partial results: {len(results)} item(s) kept.")
        sys.exit(EXIT_ABORTED)

    print(f"[+] Run complete. {len(results)} item(s) collected.")


if __name__ == "__main__":
    main()