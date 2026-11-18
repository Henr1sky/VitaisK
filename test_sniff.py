#!/usr/bin/env python3
"""Teste dedicado ao SniffCollector.

Uso:
    sudo .venv/bin/python test_sniff.py [--interface eth0] [--dur 20] [--sample-rate 1]

O que faz:
  1. Checa root, tcpdump, interface.
  2. Arranca o SniffCollector (via API) consumindo a EventQueue.
  3. Em paralelo, arranca um `tcpdump` cru (mesmo filtro) para comparar
     quantas linhas o binario produz vs. quantas o coletor emite.
  4. No fim, imprime diagnostico: se o tcpdump cru viu SYNs mas o coletor
     nao, o problema esta no parse (_RE_TCPDUMP_SYN); se o cru nao viu nada,
     e rede/interface/NAT.
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import traceback
from pathlib import Path


SYN_FILTER = "(tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0)"


def check_env(iface: str) -> bool:
    ok = True
    if os.geteuid() != 0:
        print("[erro] precisa de root para tcpdump (use sudo)")
        ok = False
    if not shutil.which("tcpdump"):
        print("[erro] tcpdump nao encontrado (sudo apt install tcpdump)")
        ok = False
    # interface existe?
    try:
        out = subprocess.check_output(["ip", "-br", "link"], text=True)
        names = [ln.split()[0] for ln in out.splitlines() if ln.strip()]
        if iface not in names and iface != "any":
            print(f"[erro] interface '{iface}' nao existe; disponiveis: {names}")
            ok = False
    except Exception as e:
        print(f"[warn] nao consegui listar interfaces: {e}")
    return ok


def start_raw_tcpdump(iface: str, out_path: Path) -> subprocess.Popen:
    """tcpdump cru, mesmo filtro do coletor, para comparar."""
    cmd = [
        "tcpdump", "-l", "-n", "-tttt", "-q",
        "-i", iface, SYN_FILTER,
    ]
    f = open(out_path, "w", encoding="utf-8")
    p = subprocess.Popen(
        cmd, stdout=f, stderr=subprocess.DEVNULL, text=True,
        start_new_session=True,
    )
    p._raw_file = f  # type: ignore[attr-defined]
    return p


def stop_proc(p: subprocess.Popen) -> None:
    try:
        if p.poll() is None:
            os.killpg(os.getpgid(p.pid), 15)  # SIGTERM
        try:
            p.wait(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(p.pid), 9)   # SIGKILL
    except Exception:
        pass
    f = getattr(p, "_raw_file", None)
    if f:
        try: f.close()
        except Exception: pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--interface", default="eth0")
    ap.add_argument("--dur", type=float, default=20.0)
    ap.add_argument("--sample-rate", type=int, default=1)
    a = ap.parse_args()

    if not check_env(a.interface):
        return 2

    # imports depois do check, para nao falhar em ambientes sem o pacote
    from vitaisk.config import Config
    from vitaisk.collectors.base import EventQueue
    from vitaisk.collectors.network import SniffCollector, _RE_TCPDUMP_SYN

    cfg = Config.load()
    cfg.network_sniff_interface = a.interface
    cfg.network_sniff_sample_rate = max(1, a.sample_rate)
    # garante BPF default do coletor (o config pode ter outro)
    if not getattr(cfg, "network_sniff_filter", None):
        cfg.network_sniff_filter = "tcp or udp or icmp"

    q = EventQueue(maxsize=1000)
    stop = threading.Event()
    c = SniffCollector(q, cfg, stop)

    raw_path = Path("/tmp/vitaisk_sniff_raw.txt")
    raw = start_raw_tcpdump(a.interface, raw_path)

    print(f"[env] iface={a.interface} sample_rate={c.sample_rate} bpf={c.bpf!r}")
    print(f"[env] raw tcpdump -> {raw_path}")
    print(f"[run] a recolher eventos durante {a.dur:.0f}s… (gera trafego noutro terminal)")

    c.start()

    events: list = []
    parse_fail_samples: list[str] = []
    t0 = time.time()
    try:
        while time.time() - t0 < a.dur:
            ev = q.get(timeout=0.5)
            if ev is None:
                continue
            events.append(ev)
            print(
                f"{ev.ts:10.3f} {ev.severity.name:8} {ev.category:18} "
                f"src={ev.src_ip or '-':16} -> {ev.dst_ip or '-':16}:{ev.dst_port or '-'} "
                f"| {ev.message[:80]}"
            )
    except KeyboardInterrupt:
        print("\n[run] interrompido pelo utilizador")
    finally:
        stop.set()
        c.stop()
        time.sleep(0.3)
        stop_proc(raw)

    # ── analise da saida crua ────────────────────────────────
    raw_lines: list[str] = []
    if raw_path.exists():
        raw_lines = [ln for ln in raw_path.read_text(errors="replace").splitlines() if ln.strip()]

    matched = 0
    for ln in raw_lines:
        if _RE_TCPDUMP_SYN.match(ln.strip()):
            matched += 1
        elif len(parse_fail_samples) < 3:
            parse_fail_samples.append(ln)

    print("\n===== RESUMO =====")
    print(f"eventos emitidos pelo coletor : {len(events)}")
    print(f"linhas cruas do tcpdump       : {len(raw_lines)}")
    print(f"linhas cruas que casam regex  : {matched}")
    print(f"queue stats                   : {q.stats()}")
    print(f"collector emitted/err         : {c.events_emitted} / {c.error}")

    print("\n===== DIAGNOSTICO =====")
    if c.error:
        print(f"[X] coletor terminou com erro: {c.error!r}")
        return 3
    if len(raw_lines) == 0:
        print("[!] tcpdump cru NAO viu nenhum SYN.")
        print("    -> problema de rede/interface/NAT, nao do codigo.")
        print("    -> tenta: --interface any   e/ou --interface lo (com trafego local)")
        print("    -> tenta gerar trafego sem DNS: curl -s -m 2 https://1.1.1.1")
        return 4
    if matched == 0:
        print("[X] tcpdump viu SYNs, mas NENHUMA linha casou _RE_TCPDUMP_SYN.")
        print("    -> o problema esta na regex; exemplos que falharam:")
        for s in parse_fail_samples:
            print("      |", s[:120])
        return 5
    if len(events) == 0 and matched > 0:
        print("[X] regex casa, mas o coletor nao emitiu.")
        print("    -> verifica sample_rate/loop em _run; cola isto ao dev.")
        return 6

    print(f"[OK] sniff a funcionar: {len(events)} eventos, {matched} linhas validas.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        traceback.print_exc()
        sys.exit(1)