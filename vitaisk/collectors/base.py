"""Abstract Collector + thread-safe EventQueue shared by every collector."""
from __future__ import annotations

import threading
import time
from abc import ABC, abstractmethod
from collections import deque
from typing import Optional

from ..events import Event
from ..utils import eprint


class EventQueue:
    """Bounded, thread-safe queue with drop-oldest policy.

    A monitoring tool must never block a collector. When the consumer is
    slow, dropping the oldest events keeps recent data available, which is
    what matters for anomaly detection.
    """

    def __init__(self, maxsize: int = 10000):
        self._maxsize = max(1, int(maxsize))
        self._dq: deque[Event] = deque()
        self._cond = threading.Condition(threading.Lock())
        self._closed = False
        self._dropped = 0
        self._total = 0

    def put(self, event: Event) -> bool:
        with self._cond:
            if self._closed:
                return False
            if len(self._dq) >= self._maxsize:
                self._dq.popleft()
                self._dropped += 1
            self._dq.append(event)
            self._total += 1
            self._cond.notify()
            return True

    def get(self, timeout: Optional[float] = None) -> Optional[Event]:
        with self._cond:
            if not self._dq:
                if self._closed:
                    return None
                if not self._cond.wait(timeout=timeout):
                    return None
                if not self._dq:
                    return None
            return self._dq.popleft()

    def close(self) -> None:
        with self._cond:
            self._closed = True
            self._cond.notify_all()

    @property
    def closed(self) -> bool:
        with self._cond:
            return self._closed

    def qsize(self) -> int:
        with self._cond:
            return len(self._dq)

    def stats(self) -> dict:
        with self._cond:
            return {
                "qsize": len(self._dq),
                "maxsize": self._maxsize,
                "total": self._total,
                "dropped": self._dropped,
                "closed": self._closed,
            }


class Collector(ABC):
    """Base class for all collectors.

    Lifecycle:
        c = SomeCollector(queue, config)
        c.start()     # spawns thread, runs _run() until stop_event is set
        c.stop()      # calls _on_stop(), sets stop_event, joins thread
        c.join()      # explicit join (stop() already joins with timeout)

    Subclasses override _run() (the main loop) and optionally _on_stop()
    for cleanup of external resources (subprocesses, sockets).
    """

    name: str = "base"
    source: str = "system"

    def __init__(self, queue: EventQueue, config, stop_event: Optional[threading.Event] = None):
        self.queue = queue
        self.config = config
        self.stop_event = stop_event or threading.Event()
        self.thread: Optional[threading.Thread] = None
        self._error: Optional[BaseException] = None
        self._events_emitted = 0
        self._started_at: Optional[float] = None

    # ── public API ─────────────────────────────────────────────
    def start(self) -> None:
        if self.thread and self.thread.is_alive():
            return
        self._started_at = time.time()
        self.thread = threading.Thread(
            target=self._run_wrapper,
            name=f"vitaisk-{self.name}",
            daemon=True,
        )
        self.thread.start()

    def stop(self, timeout: float = 3.0) -> None:
        try:
            self._on_stop()
        except Exception as e:
            eprint(f"[{self.name}] _on_stop error: {e}")
        self.stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=timeout)

    def join(self, timeout: Optional[float] = None) -> None:
        if self.thread:
            self.thread.join(timeout=timeout)

    def is_alive(self) -> bool:
        return bool(self.thread and self.thread.is_alive())

    # ── helpers for subclasses ─────────────────────────────────
    def emit(self, event: Event) -> None:
        event.extra.setdefault("collector", self.name)
        if self.queue.put(event):
            self._events_emitted += 1

    def should_stop(self) -> bool:
        return self.stop_event.is_set()

    @property
    def error(self) -> Optional[BaseException]:
        return self._error

    @property
    def events_emitted(self) -> int:
        return self._events_emitted

    @property
    def uptime(self) -> float:
        return time.time() - self._started_at if self._started_at else 0.0

    # ── abstract / overridable ─────────────────────────────────
    @abstractmethod
    def _run(self) -> None:
        """Main loop. Must return cleanly when should_stop() is True."""

    def _on_stop(self) -> None:
        """Optional: called by stop() before stop_event is set.

        Use for terminating subprocesses, closing sockets, etc.
        """

    # ── internal ───────────────────────────────────────────────
    def _run_wrapper(self) -> None:
        try:
            self._run()
        except Exception as e:
            self._error = e
            eprint(f"[{self.name}] crashed: {type(e).__name__}: {e}")