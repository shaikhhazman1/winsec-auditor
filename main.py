#!/usr/bin/env python3
"""WinSec Auditor - Windows misconfiguration auditor and TCP port scanner."""
import argparse
import sys
import time

from core.safety import (
    show_disclaimer, is_in_scope, register_kill_switch, stop_event,
)

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


def simulate_work(results: list, steps: int = 20) -> None:
    """TEMPORARY: fake workload so we can test the kill switch.

    Mimics what the real scanner/audit loops must do: check
    stop_event every iteration and return early if it is set.
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

    # 3. Arm the kill switch only now, so Ctrl+C at the earlier
    #    prompts still behaves normally.
    register_kill_switch()
    print("[*] Kill switch active: press Ctrl+C to abort safely.")

    # 4. Run the work (temporary stub for now).
    results: list = []
    simulate_work(results)

    # 5. Report whether the run was complete or partial.
    if stop_event.is_set():
        print(f"[!] Run ABORTED. Partial results: {len(results)} item(s) kept.")
        sys.exit(EXIT_ABORTED)

    print(f"[+] Run complete. {len(results)} item(s) collected.")


if __name__ == "__main__":
    main()