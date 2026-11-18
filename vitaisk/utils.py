"""Shared helpers: paths, permissions, humanization, file tailing, parsing."""
from __future__ import annotations

import gzip
import json
import os
import shutil
import stat
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator, Optional


# ── environment ────────────────────────────────────────────────────
def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)


# ── paths & permissions ────────────────────────────────────────────
def config_dir() -> Path:
    if is_root():
        return Path("/etc/vitaisk")
    base = os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")
    return Path(base) / "vitaisk"


def data_dir() -> Path:
    if is_root():
        return Path("/var/lib/vitaisk")
    base = os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share")
    return Path(base) / "vitaisk"


def ensure_private_dir(path: Path) -> Path:
    """Create directory with mode 0700 and verify ownership where possible."""
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except PermissionError:
        pass
    return path


def ensure_private_file(path: Path) -> Path:
    path.touch(exist_ok=True)
    try:
        os.chmod(path, 0o600)
    except PermissionError:
        pass
    return path


def is_private(path: Path) -> bool:
    try:
        return (path.stat().st_mode & 0o077) == 0
    except FileNotFoundError:
        return False


# ── humanization ───────────────────────────────────────────────────
def humanize_bytes(n: int | float) -> str:
    n = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024.0:
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024.0
    return f"{n:.1f} PiB"


def humanize_duration(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    m, s = divmod(seconds, 60)
    if m < 60:
        return f"{m}m{s:02d}s"
    h, m = divmod(m, 60)
    if h < 24:
        return f"{h}h{m:02d}m"
    d, h = divmod(h, 24)
    return f"{d}d{h:02d}h"


def humanize_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def short_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


# ── parsing CLI-friendly values ────────────────────────────────────
_SIZE_UNITS = {"B": 1, "K": 1024, "KB": 1024, "M": 1024**2, "MB": 1024**2,
               "G": 1024**3, "GB": 1024**3, "T": 1024**4, "TB": 1024**4}


def parse_size(text: str) -> int:
    """Parse '10M', '500MB', '2G' into bytes. Plain int = bytes."""
    text = text.strip().upper()
    if text.isdigit():
        return int(text)
    for suffix in sorted(_SIZE_UNITS, key=len, reverse=True):
        if text.endswith(suffix):
            num = text[: -len(suffix)].strip()
            return int(float(num) * _SIZE_UNITS[suffix])
    raise ValueError(f"invalid size: {text!r}")


_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_duration(text: str) -> float:
    """Parse '60', '60s', '5m', '1h30m' into seconds."""
    text = text.strip().lower()
    if not text:
        raise ValueError("empty duration")
    if text.replace(".", "", 1).isdigit():
        return float(text)
    total = 0.0
    num = ""
    for ch in text:
        if ch.isdigit() or ch == ".":
            num += ch
        elif ch in _DURATION_UNITS:
            if not num:
                raise ValueError(f"invalid duration: {text!r}")
            total += float(num) * _DURATION_UNITS[ch]
            num = ""
        else:
            raise ValueError(f"invalid duration: {text!r}")
    if num:
        total += float(num)
    return total


# ── json ───────────────────────────────────────────────────────────
def json_default(obj: Any) -> Any:
    if isinstance(obj, (datetime,)):
        return obj.isoformat()
    if isinstance(obj, (bytes, bytearray)):
        return obj.hex()
    return str(obj)


def dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, default=json_default, separators=(",", ":"))


# ── file tailing (for /var/log/* style files) ──────────────────────
def follow_file(path: str | Path, poll: float = 0.3,
                from_start: bool = False, stop_event=None) -> Iterator[str]:
    """Yield lines as they are appended. Survives rotation.

    Does not implement inotify (portable across distros/filesystems).
    Polling at 300 ms is fine for log files and very cheap on CPU.
    """
    path = str(path)
    fh: Optional[Any] = None
    inode: Optional[int] = None
    try:
        while stop_event is None or not stop_event.is_set():
            if fh is None:
                try:
                    fh = open(path, "r", errors="replace")
                    if not from_start:
                        fh.seek(0, os.SEEK_END)
                    inode = os.fstat(fh.fileno()).st_ino
                except FileNotFoundError:
                    if stop_event is None:
                        time.sleep(poll)
                    else:
                        stop_event.wait(poll)
                    continue
            line = fh.readline()
            if line:
                yield line.rstrip("\n")
                continue
            # No new data — check for rotation
            try:
                st = os.stat(path)
                if st.st_ino != inode or st.st_size < fh.tell():
                    fh.close()
                    fh = None
                    inode = None
                    continue
            except FileNotFoundError:
                fh.close()
                fh = None
                inode = None
                continue
            if stop_event is None:
                time.sleep(poll)
            else:
                stop_event.wait(poll)
    finally:
        if fh is not None:
            fh.close()


# ── misc ───────────────────────────────────────────────────────────
def eprint(*args, **kwargs) -> None:
    print(*args, file=sys.stderr, **kwargs)


def safe_unlink(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass

# ── utf8 ───────────────────────────────────────────────────────────
def stdout_is_utf8() -> bool:
    enc = (getattr(sys.stdout, "encoding", "") or "").lower().replace("-", "")
    return enc.startswith("utf8")