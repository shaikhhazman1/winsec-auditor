"""
Shared result format for the whole tool.

Both the port scanner (Member 2) and the Windows audit module (Member 3)
return `Finding` objects, so the correlation engine and report generator
(Member 4) only have to understand one shape of data.

Agree on this file with Members 3 and 4 before writing more code.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        """Numeric order so severities can be compared and raised."""
        return list(Severity).index(self)

    @staticmethod
    def highest(*levels: "Severity") -> "Severity":
        return max(levels, key=lambda s: s.rank)


class PortState(str, Enum):
    OPEN = "open"          # TCP handshake completed
    CLOSED = "closed"      # host answered with RST (connection refused)
    FILTERED = "filtered"  # no answer before timeout, usually a firewall drop
    ERROR = "error"        # unexpected local error while probing


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Finding:
    """One row in the final report, produced by either module.

    source    "scanner" or "audit"
    check_id  stable ID the correlation engine can match on,
              e.g. "PORT-445" (scanner) or "AUD-SMB1" (audit)
    status    scanner: "open"; audit: "PASS" / "FAIL" / "ERROR"
    """
    source: str
    check_id: str
    title: str
    status: str
    severity: Severity
    target: str
    category: str = ""
    port: Optional[int] = None
    protocol: Optional[str] = None
    service: Optional[str] = None
    evidence: str = ""
    remediation: str = ""
    timestamp: str = field(default_factory=utc_now)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data
