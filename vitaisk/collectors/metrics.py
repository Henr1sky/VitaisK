"""Collector for system vitals via psutil (CPU, RAM, disk, load, processes)."""
from __future__ import annotations

import time
from typing import Optional

import psutil

from ..events import Event, Severity, make_event
from ..utils import eprint
from .base import Collector, EventQueue


class MetricsCollector(Collector):
    name = "metrics"
    source = "metrics"

    def __init__(self, queue: EventQueue, config, stop_event=None):
        super().__init__(queue, config, stop_event)
        self.vitals: tuple[float, float, float | None] | None = None
        self.interval = float(getattr(config, "metrics_interval", 2.0))
        # Map of tracker name → timestamp when metric crossed its threshold
        self._state: dict[str, Severity] = {}
        self._high_since: dict[str, Optional[float]] = {
            "cpu": None, "memory": None, "disk": None, "load": None, "procs": None,
        }

        # Thresholds (percent) and durations (seconds)
        self.CPU_WARN = 85.0
        self.CPU_CRIT = 95.0
        self.CPU_WARN_DUR = 10.0
        self.CPU_CRIT_DUR = 30.0
        self.MEM_WARN = 85.0
        self.MEM_CRIT = 95.0
        self.MEM_WARN_DUR = 10.0
        self.MEM_CRIT_DUR = 30.0
        self.DISK_WARN = 85.0
        self.DISK_CRIT = 95.0

    def _run(self) -> None:
        try:
            psutil.cpu_percent(interval=None)  # prime the counter
        except Exception as e:
            eprint(f"[{self.name}] psutil init failed: {e}")
            return

        while not self.should_stop():
            try:
                self._sample()
            except Exception as e:
                eprint(f"[{self.name}] sample error: {e}")
            # Sleep in small increments so stop() is responsive
            deadline = time.time() + self.interval
            while time.time() < deadline and not self.should_stop():
                time.sleep(min(0.2, max(0.0, deadline - time.time())))

    def _sample(self) -> None:
        now = time.time()

        # ── CPU ────────────────────────────────────────────────
        cpu = psutil.cpu_percent(interval=None)
        self._check_sustained(
            "cpu", cpu, now,
            warn=self.CPU_WARN, crit=self.CPU_CRIT,
            warn_dur=self.CPU_WARN_DUR, crit_dur=self.CPU_CRIT_DUR,
            extra={"cpu_percent": cpu, "ncpu": psutil.cpu_count()},
        )

        # ── Memory ─────────────────────────────────────────────
        mem = psutil.virtual_memory()
        self._check_sustained(
            "memory", mem.percent, now,
            warn=self.MEM_WARN, crit=self.MEM_CRIT,
            warn_dur=self.MEM_WARN_DUR, crit_dur=self.MEM_CRIT_DUR,
            extra={
                "mem_percent": mem.percent,
                "used_mb": mem.used // (1024 * 1024),
                "total_mb": mem.total // (1024 * 1024),
            },
        )

        # ── Disk (root filesystem) ─────────────────────────────
        disk_percent = None
        try:
            disk = psutil.disk_usage("/")
            pct = disk_percent = disk.percent
            sev = Severity.INFO
            if pct >= self.DISK_CRIT:
                sev = Severity.CRITICAL
            elif pct >= self.DISK_WARN:
                sev = Severity.WARN
            self._transition("disk", sev, extra={
                "disk_percent": pct,
                "free_gb": round(disk.free / (1024**3), 1),
                "total_gb": round(disk.total / (1024**3), 1),
            })
        except Exception:
            pass

        self.vitals = (cpu, mem.percent, disk_percent)

        # ── Load average (if available) ────────────────────────
        try:
            la = psutil.getloadavg()
            ncpu = psutil.cpu_count() or 1
            if la[0] > ncpu * 2:
                self._transition("load", Severity.ERROR,
                                 extra={"load_1m": la[0], "ncpu": ncpu},
                                 message=f"load average {la[0]:.2f} > 2× CPUs ({ncpu})")
            elif la[0] > ncpu:
                self._transition("load", Severity.WARN,
                                 extra={"load_1m": la[0], "ncpu": ncpu},
                                 message=f"load average {la[0]:.2f} > CPUs ({ncpu})")
            else:
                self._transition("load", Severity.INFO)
        except (AttributeError, OSError):
            pass

        # ── Process count spike ────────────────────────────────
        try:
            nproc = len(psutil.pids())
            if nproc > 2000:
                self._transition("procs", Severity.WARN,
                                 extra={"process_count": nproc},
                                 message=f"process count {nproc}")
            else:
                self._transition("procs", Severity.INFO)
        except Exception:
            pass

    # ── helpers ────────────────────────────────────────────────
    def _check_sustained(
        self, name: str, value: float, now: float,
        warn: float, crit: float,
        warn_dur: float, crit_dur: float,
        extra: dict,
    ) -> None:
        """Emit only when the metric has been high for a minimum duration."""
        since = self._high_since.get(name)

        if value >= crit:
            if since is None:
                self._high_since[name] = now
                return
            if now - since >= crit_dur:
                self._transition(
                    name, Severity.CRITICAL, extra=extra,
                    message=f"{name} at {value:.0f}% for {now - since:.0f}s",
                )
            return

        if value >= warn:
            if since is None:
                self._high_since[name] = now
                return
            if now - since >= warn_dur:
                self._transition(
                    name, Severity.WARN, extra=extra,
                    message=f"{name} at {value:.0f}% for {now - since:.0f}s",
                )
            return

        # Below warn → reset the tracker
        self._high_since[name] = None
        self._transition(name, Severity.INFO)

    def _transition(self, name: str, severity: Severity,
                    extra: Optional[dict] = None, message: str = "") -> None:
        """Emit an event only on state change to a *higher* severity."""
        prev = self._state.get(name, Severity.INFO)
        if severity <= prev:
            # Repeated samples in the same state do not produce new events.
            if severity < prev:
                self._state[name] = Severity.INFO
            return
        if severity == Severity.INFO:
            # Only record downgrade — no event for returning to normal
            self._state[name] = Severity.INFO
            return
        self._state[name] = severity
        self.emit(make_event(
            source="metrics",
            category=f"{name}_{'critical' if severity == Severity.CRITICAL else 'warn'}",
            severity=severity,
            message=message or f"{name} {severity.name}",
            extra=extra or {},
        ))


# ── standalone test ───────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    from ..config import Config

    p = argparse.ArgumentParser(description="Test MetricsCollector in isolation")
    p.add_argument("--interval", type=float, default=2.0)
    args = p.parse_args()

    q = EventQueue(maxsize=1000)
    cfg = Config.load()
    cfg.metrics_interval = args.interval
    c = MetricsCollector(q, cfg)

    print(f"[metrics] sampling every {args.interval}s, Ctrl+C to stop\n")
    c.start()
    try:
        while True:
            ev = q.get(timeout=0.5)
            if ev:
                print(
                    f"{ev.ts:.0f} [{ev.severity.name:8}] {ev.category:20} "
                    f"{ev.message:60} {ev.extra}"
                )
    except KeyboardInterrupt:
        print("\n[metrics] stopping…")
    finally:
        c.stop()