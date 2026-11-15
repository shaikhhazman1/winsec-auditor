"""Safety and ethics layer for WinSec Auditor.

Step 2: legal disclaimer and typed authorization.
Step 3: scope validation.
"""
import ipaddress
import socket

CONFIRMATION_PHRASE = "I AUTHORIZE"

BANNER = """
============================================================
                 WinSec Auditor - LEGAL NOTICE
============================================================
This tool is for AUTHORIZED security testing ONLY.

Unauthorized access to computer material is a criminal
offence under the Computer Crimes Act 1997 (Malaysia).
Offenders may face fines and/or imprisonment.

You may only use this tool on systems that you:
  1. own, or
  2. have EXPLICIT WRITTEN PERMISSION to test.

The authors accept no liability for misuse.
============================================================
"""


def show_disclaimer() -> bool:
    """Show the legal banner and require a typed confirmation.

    Returns True only if the user types the exact phrase.
    Any other input, Ctrl+C, or closed input (EOF) returns False,
    so the default outcome is always "do not run".
    """
    print(BANNER)
    try:
        answer = input(f"Type '{CONFIRMATION_PHRASE}' to confirm you have authorization: ")
    except (EOFError, KeyboardInterrupt):
        print("\n[!] No confirmation given.")
        return False

    return answer.strip() == CONFIRMATION_PHRASE


def resolve_host(host: str) -> list[str]:
    """Return every unique IP address for a host (IP literal or hostname).

    Raises ValueError if the host cannot be resolved.
    """
    # If it is already a valid IP, no DNS lookup is needed.
    try:
        return [str(ipaddress.ip_address(host))]
    except ValueError:
        pass  # not an IP literal, so treat it as a hostname

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise ValueError(f"cannot resolve '{host}': {exc}")

    # getaddrinfo can return the same IP several times, and IPv6
    # addresses may carry a '%interface' suffix, so clean up.
    return sorted({info[4][0].split("%")[0] for info in infos})


def parse_scope(scope: str) -> list:
    """Turn a scope string into a list of IP networks.

    Accepts a CIDR range ('10.0.0.0/24'), a single IP, or a hostname.
    """
    try:
        return [ipaddress.ip_network(scope, strict=False)]
    except ValueError:
        pass  # not a range or IP, so try it as a hostname

    return [ipaddress.ip_network(ip) for ip in resolve_host(scope)]


def is_in_scope(target: str, scope: str) -> tuple[bool, str]:
    """Check that EVERY IP the target resolves to is inside the scope.

    Returns (True, message) if allowed, or (False, reason) if refused.
    Any error (bad input, DNS failure) returns False: the safe default
    is always "refuse".
    """
    target, scope = target.strip(), scope.strip()
    if not target or not scope:
        return False, "target and scope must not be empty"

    try:
        networks = parse_scope(scope)
        target_ips = resolve_host(target)
    except ValueError as exc:
        return False, str(exc)

    for ip in target_ips:
        address = ipaddress.ip_address(ip)
        # 'in' returns False when IP versions differ (IPv4 vs IPv6),
        # so a mismatch is refused automatically.
        if not any(address in network for network in networks):
            return False, f"{ip} (from '{target}') is outside the authorized scope '{scope}'"

    return True, f"'{target}' ({', '.join(target_ips)}) is within scope '{scope}'"