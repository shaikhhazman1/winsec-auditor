"""
Port knowledge base for Windows hosts.

Holds three things the scanner needs:
  1. KNOWN_PORTS   - what usually listens on a port, its baseline risk and advice
  2. port profiles - ready-made port lists ("quick", "windows")
  3. SIGNATURES    - regexes that recognise a service from its banner
"""
from __future__ import annotations

import re
from typing import Tuple

from .models import Severity

# port: (service label, baseline severity, why it matters + remediation)
KNOWN_PORTS = {
    21: ("ftp", Severity.HIGH,
         "FTP sends credentials in cleartext. Disable the IIS FTP role or move to SFTP/FTPS."),
    22: ("ssh", Severity.LOW,
         "OpenSSH Server is running. Confirm it is required and enforce key-based authentication."),
    23: ("telnet", Severity.CRITICAL,
         "Telnet is an unencrypted remote shell. Remove the Telnet Server feature."),
    25: ("smtp", Severity.LOW,
         "SMTP is listening. Confirm the server is not an open relay."),
    53: ("dns", Severity.INFO,
         "DNS server is listening. Expected only on DNS servers or domain controllers."),
    80: ("http", Severity.LOW,
         "Unencrypted web service (often IIS). Redirect to HTTPS or stop it if unused."),
    88: ("kerberos", Severity.INFO,
         "Kerberos KDC. Normal only on a domain controller."),
    110: ("pop3", Severity.MEDIUM,
          "POP3 is cleartext. Use POP3S (995) or disable the service."),
    135: ("msrpc", Severity.MEDIUM,
          "RPC Endpoint Mapper. Block it from untrusted networks with Windows Firewall."),
    139: ("netbios-ssn", Severity.MEDIUM,
          "Legacy NetBIOS session service. Disable NetBIOS over TCP/IP if it is not needed."),
    143: ("imap", Severity.MEDIUM,
          "IMAP is cleartext. Use IMAPS (993) or disable the service."),
    389: ("ldap", Severity.LOW,
          "LDAP without TLS. Require LDAP signing and prefer LDAPS (636)."),
    443: ("https", Severity.INFO,
          "HTTPS service. Review the negotiated TLS version in the evidence."),
    445: ("microsoft-ds", Severity.MEDIUM,
          "SMB file sharing is reachable. Block it from untrusted networks and make sure SMBv1 is disabled."),
    464: ("kpasswd", Severity.INFO,
          "Kerberos password change. Normal only on a domain controller."),
    593: ("http-rpc-epmap", Severity.MEDIUM,
          "RPC over HTTP endpoint mapper. Restrict access with Windows Firewall."),
    636: ("ldaps", Severity.INFO,
          "LDAP over TLS. Review the negotiated TLS version in the evidence."),
    1433: ("mssql", Severity.HIGH,
           "SQL Server is network-reachable. Bind it to localhost or firewall it, and use strong logins."),
    3268: ("globalcatalog", Severity.INFO,
           "Active Directory Global Catalog. Normal only on a domain controller."),
    3306: ("mysql", Severity.HIGH,
           "MySQL is network-reachable. Bind it to 127.0.0.1 or restrict it with the firewall."),
    3389: ("rdp", Severity.MEDIUM,
           "Remote Desktop is exposed. Require NLA and limit access to a VPN or trusted IPs."),
    5357: ("wsdapi", Severity.LOW,
           "Web Services for Devices (network discovery). Turn it off on public networks."),
    5432: ("postgresql", Severity.HIGH,
           "PostgreSQL is network-reachable. Restrict listen_addresses and pg_hba.conf."),
    5900: ("vnc", Severity.HIGH,
           "VNC often uses weak passwords. Remove it or tunnel it over a VPN or SSH."),
    5985: ("winrm-http", Severity.MEDIUM,
           "WinRM over HTTP. Prefer an HTTPS listener (5986) and restrict which hosts may connect."),
    5986: ("winrm-https", Severity.LOW,
           "WinRM over HTTPS. Confirm remote management is required on this host."),
    8080: ("http-alt", Severity.LOW,
           "Alternate HTTP port, often a development or admin server. Stop it if unused."),
    8443: ("https-alt", Severity.LOW,
           "Alternate HTTPS port, often an admin panel. Confirm it is required."),
    47001: ("winrm-mgmt", Severity.LOW,
            "HTTP.sys listener used by WinRM. Expected only if WinRM is enabled."),
}

UNKNOWN_SEVERITY = Severity.LOW
UNKNOWN_ADVICE = ("Unrecognised listening service. Find the owning process with "
                  "'netstat -ano' and stop it if it is not required.")

PORT_PROFILES = {
    "quick": [21, 22, 23, 80, 135, 139, 443, 445, 3389, 5985],
    "windows": sorted(KNOWN_PORTS),
}

# Ports where we send a harmless HTTP HEAD request to get the Server header.
HTTP_PORTS = {80, 5357, 5985, 8000, 8080, 8888, 47001}
# Ports where we only complete a TLS handshake to read the protocol version.
TLS_PORTS = {443, 636, 3269, 5986, 8443}
# TLS ports that also speak HTTP, so a HEAD request is sent inside TLS.
TLS_HTTP_PORTS = {443, 5986, 8443}

# (regex, service label). A named group "version" captures product/version text.
SIGNATURES = [
    (re.compile(r"^SSH-[\d.]+-(?P<version>\S+)"), "ssh"),
    (re.compile(r"^HTTP/\d(?:\.\d)?"), "http"),
    (re.compile(r"^220[ -](?P<version>.*ftp.*)", re.I), "ftp"),
    (re.compile(r"^220[ -](?P<version>.*(?:smtp|mail).*)", re.I), "smtp"),
    (re.compile(r"^\+OK"), "pop3"),
    (re.compile(r"^\* OK.*IMAP", re.I), "imap"),
    (re.compile(r"^RFB (?P<version>\d{3}\.\d{3})"), "vnc"),
    (re.compile(r"(?P<version>\d+\.\d+\.\d+[-\w.]*(?:MariaDB|mysql)?)", re.I), "mysql?"),
]
SERVER_HEADER = re.compile(r"Server:\s*(?P<version>[^|]+)", re.I)


def identify_service(port: int, banner: str) -> Tuple[str, str, str]:
    """Return (service, product, confidence).

    confidence is "banner" when the banner matched a signature, "port" when
    we fell back to the well-known port table, or "" when nothing matched.
    """
    known_label = KNOWN_PORTS.get(port, ("unknown",))[0]

    for pattern, label in SIGNATURES:
        if not banner:
            break
        match = pattern.search(banner)
        if not match:
            continue
        if label == "mysql?":
            # A bare version number is weak evidence: only trust it on DB ports.
            if port not in (3306, 3307):
                continue
            label = "mysql"
        if label == "http":
            server = SERVER_HEADER.search(banner)
            product = server.group("version").strip() if server else ""
            # Keep the more specific port label (e.g. winrm-http) when it is an HTTP service.
            label = known_label if "http" in known_label else label
            return label, product, "banner"
        product = match.groupdict().get("version") or ""
        return label, product.strip(), "banner"

    if port in KNOWN_PORTS:
        return known_label, "", "port"
    return "unknown", "", ""
