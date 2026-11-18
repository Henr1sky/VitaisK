"""Collector registry and factory. Importing this module pulls all collectors in."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from ..utils import eprint
from .base import Collector, EventQueue
from .journal import JournalCollector
from .filetail import (
    SyslogCollector, AuthLogCollector, KernelLogCollector, FirewallLogCollector,
    find_log, SYSLOG_CANDIDATES, AUTH_CANDIDATES, KERNEL_CANDIDATES, FIREWALL_CANDIDATES,
)
from .audit import AuditCollector, DEFAULT_AUDIT_LOG
from .metrics import MetricsCollector
from .network import ConnectionsCollector, SniffCollector
from .manager import CollectorManager


def build_collectors(config, queue: EventQueue, stop_event) -> list[Collector]:
    """Instantiate only the collectors enabled in config and available on this system."""
    collectors: list[Collector] = []

    if config.journal_enabled:
        try:
            collectors.append(JournalCollector(queue, config, stop_event))
        except Exception as e:
            eprint(f"[build] journal collector disabled: {e}")

    if config.syslog_enabled and find_log(SYSLOG_CANDIDATES):
        try:
            collectors.append(SyslogCollector(queue, config, stop_event=stop_event))
        except FileNotFoundError:
            pass

    if config.auth_enabled and find_log(AUTH_CANDIDATES):
        try:
            collectors.append(AuthLogCollector(queue, config, stop_event=stop_event))
        except FileNotFoundError:
            pass

    if config.kern_enabled and find_log(KERNEL_CANDIDATES):
        try:
            collectors.append(KernelLogCollector(queue, config, stop_event=stop_event))
        except FileNotFoundError:
            pass

    if config.firewall_enabled and find_log(FIREWALL_CANDIDATES):
        try:
            collectors.append(FirewallLogCollector(queue, config, stop_event=stop_event))
        except FileNotFoundError:
            pass

    if config.audit_enabled:
        try:
            c = AuditCollector(queue, config, stop_event=stop_event)
            if c.path.exists():
                collectors.append(c)
            else:
                eprint(f"[build] audit enabled but {c.path} missing — skipped")
        except Exception as e:
            eprint(f"[build] audit collector disabled: {e}")

    if config.metrics_enabled:
        try:
            collectors.append(MetricsCollector(queue, config, stop_event))
        except Exception as e:
            eprint(f"[build] metrics collector disabled: {e}")

    if config.connections_enabled:
        try:
            collectors.append(ConnectionsCollector(queue, config, stop_event))
        except Exception as e:
            eprint(f"[build] connections collector disabled: {e}")

    if config.network_sniff_enabled:
        try:
            collectors.append(SniffCollector(queue, config, stop_event))
        except Exception as e:
            eprint(f"[build] sniff collector disabled: {e}")

    return collectors


__all__ = [
    "Collector", "EventQueue", "CollectorManager",
    "build_collectors",
    "JournalCollector", "SyslogCollector", "AuthLogCollector",
    "KernelLogCollector", "FirewallLogCollector",
    "AuditCollector", "MetricsCollector",
    "ConnectionsCollector", "SniffCollector",
    "find_log",
    "SYSLOG_CANDIDATES", "AUTH_CANDIDATES",
    "KERNEL_CANDIDATES", "FIREWALL_CANDIDATES",
    "DEFAULT_AUDIT_LOG",
]