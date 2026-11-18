#!/usr/bin/env python3
"""Testa um coletor isolado pela API.
Uso: python test_one.py <alvo> [--path P] [--dur S] [--interface I] [--sample-rate N]
Alvos: metrics|conn|sniff|journal|syslog|auth|kernel|firewall|audit
"""
import argparse, sys, time, threading, traceback
from pathlib import Path

def build(target, q, cfg, stop, path=None, interface="any", sample_rate=1):
    from vitaisk.collectors import (
        MetricsCollector, ConnectionsCollector, SniffCollector,
        JournalCollector, SyslogCollector, AuthLogCollector,
        KernelLogCollector, FirewallLogCollector, AuditCollector,
    )
    p = Path(path) if path else None
    if target == "metrics":  return MetricsCollector(q, cfg, stop)
    if target == "conn":     return ConnectionsCollector(q, cfg, stop)
    if target == "sniff":
        cfg.network_sniff_interface = interface
        cfg.network_sniff_sample_rate = max(1, int(sample_rate))
        return SniffCollector(q, cfg, stop)
    if target == "journal":  return JournalCollector(q, cfg, stop)
    if target == "syslog":   return SyslogCollector(q, cfg, p, stop)
    if target == "auth":     return AuthLogCollector(q, cfg, p, stop)
    if target == "kernel":   return KernelLogCollector(q, cfg, p, stop)
    if target == "firewall": return FirewallLogCollector(q, cfg, p, stop)
    if target == "audit":    return AuditCollector(q, cfg, p, stop)
    raise SystemExit(f"alvo invalido: {target}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--path", default=None)
    ap.add_argument("--dur", type=float, default=8.0)
    ap.add_argument("--interface", default="any")
    ap.add_argument("--sample-rate", type=int, default=1)
    a = ap.parse_args()

    from vitaisk.config import Config
    from vitaisk.collectors.base import EventQueue

    cfg = Config.load()
    q = EventQueue(maxsize=1000)
    stop = threading.Event()

    # passa os kwargs — NAO uses `a` dentro de build()
    c = build(a.target, q, cfg, stop, a.path,
              interface=a.interface, sample_rate=a.sample_rate)

    c.start()
    print(f"[{a.target}] started name={c.name} path={getattr(c,'path',None)}")
    try:
        t0, n = time.time(), 0
        while time.time() - t0 < a.dur:
            ev = q.get(timeout=0.5)
            if ev is None:
                continue
            n += 1
            sev = getattr(ev.severity, "name", str(ev.severity))
            print(f"{ev.source:10} {sev:8} {ev.category:20} {ev.message[:90]}")
        print(f"[{a.target}] total={n} queue={q.stats()}")
    finally:
        c.stop()
        print(f"[{a.target}] stopped emitted={c.events_emitted} err={c.error}")
    return 0

if __name__ == "__main__":
    try: sys.exit(main())
    except Exception:
        traceback.print_exc(); sys.exit(1)