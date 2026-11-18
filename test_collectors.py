#!/usr/bin/env python3
"""Bateria integrada dos coletores (Parte 2).
Roda: .venv/bin/python test_collectors.py
Para incluir journal/sniff: sudo .venv/bin/python test_collectors.py
"""
import sys, time, traceback, shutil

def main() -> int:
    from vitaisk.config import Config
    from vitaisk.collectors import CollectorManager

    cfg = Config.load()

    if not shutil.which("journalctl"):
        print("[warn] journalctl ausente")
    if not shutil.which("tcpdump"):
        print("[warn] tcpdump ausente -> sniff nao roda")
    if getattr(cfg, "audit_enabled", False):
        print("[warn] audit_enabled=true; esperado false na Parte 2")

    m = CollectorManager(cfg)
    print(f"[info] construidos: {[c.name for c in m.collectors]}")
    m.start()
    try:
        print(f"[info] running: {m.running()}")
        n, t0, dur = 0, time.time(), 12.0
        by_source = {}
        for ev in m.events():
            n += 1
            by_source[ev.source] = by_source.get(ev.source, 0) + 1
            if n <= 30:
                sev = ev.severity.name
                print(f"{ev.source:10} {sev:8} {ev.category:20} {ev.message[:90]}")
            if time.time() - t0 > dur:
                break

        st = m.stats()
        print(f"\n[resumo] total={n} em {dur:.0f}s | por fonte={by_source}")
        print(f"[resumo] queue={st['queue']}")
        for c in st["collectors"]:
            print(f"  - {c['name']:10} alive={c['alive']} events={c['events']} "
                  f"uptime={c['uptime']}s err={c['error']}")
        return 0
    except Exception:
        traceback.print_exc(); return 2
    finally:
        m.stop()
        print("[info] manager parado")

if __name__ == "__main__":
    sys.exit(main())