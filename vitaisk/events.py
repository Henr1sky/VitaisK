"""Normalized event model shared by every collector and consumer."""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Any, Optional


class Severity(IntEnum):
    """Ordered severities. Higher = more severe."""
    DEBUG    = 5
    INFO     = 10
    WARN     = 20
    ERROR    = 30
    CRITICAL = 40

    @classmethod
    def parse(cls, value: str | int | "Severity") -> "Severity":
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[value.strip().upper()]

    def label(self) -> str:
        return self.name


# Canonical source tags. Collectors must use these.
SOURCES = ("system", "network", "metrics", "audit", "kernel", "auth", "firewall")


@dataclass
class Event:
    """A single normalized observation from any source.

    The `raw` field always carries the original line / payload for forensics.
    Structured fields (src_ip, user, …) are best-effort extractions.
    """
    ts: float                                   # unix timestamp
    source: str                                 # one of SOURCES
    category: str                               # ssh, sudo, oom, port_scan, …
    severity: Severity
    message: str                                # human-readable one-liner
    raw: str = ""                               # original line
    host: str = ""
    pid: Optional[int] = None
    user: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    extra: dict[str, Any] = field(default_factory=dict)

    # ── serialization ───────────────────────────────────────────
    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = int(self.severity)
        d["severity_name"] = self.severity.name
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, separators=(",", ":"))

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Event":
        d = dict(d)
        d["severity"] = Severity.parse(d.get("severity", Severity.INFO))
        d.pop("severity_name", None)
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in known})

    # ── identity ────────────────────────────────────────────────
    def fingerprint(self) -> str:
        """Stable hash used for deduplication within a time window."""
        payload = f"{self.source}|{self.category}|{self.message}|{self.src_ip}|{self.user}"
        return hashlib.sha1(payload.encode("utf-8", "replace")).hexdigest()[:16]

    def is_at_least(self, sev: Severity) -> bool:
        return self.severity >= sev


def make_event(
    *,
    source: str,
    category: str,
    severity: Severity | str | int,
    message: str,
    raw: str = "",
    **kwargs,
) -> Event:
    """Convenience factory with validation + defaults."""
    if source not in SOURCES:
        raise ValueError(f"unknown source: {source!r}")
    return Event(
        ts=kwargs.pop("ts", time.time()),
        source=source,
        category=category,
        severity=Severity.parse(severity),
        message=message,
        raw=raw or message,
        **kwargs,
    )