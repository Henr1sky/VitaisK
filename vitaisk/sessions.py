"""Private JSONL history with optional gzip compression."""
from collections import Counter
from datetime import datetime, timezone
import gzip
import json
import os
from pathlib import Path
import re
from uuid import uuid4

from .utils import ensure_private_dir


_SESSION = re.compile(r"\d{8}T\d{6}\.\d{6}Z-[0-9a-f]{8}\.jsonl(?:\.gz)?")


def session_files(directory):
    return sorted(path for path in directory.glob("*.jsonl*") if _SESSION.fullmatch(path.name))


def session_id(path):
    return path.name.split(".jsonl", 1)[0]


def resolve(directory, name):
    paths = session_files(directory)
    if name == "latest" and paths:
        return paths[-1]
    for path in paths:
        if session_id(path) == name:
            return path
    raise FileNotFoundError(name)


def prune(directory, *, keep=None, max_bytes=None, preserve_latest=False):
    paths = session_files(directory)
    sizes = {path: path.stat().st_size for path in paths}
    total = sum(sizes.values())
    removed = 0
    for index, path in enumerate(paths):
        excess_count = keep is not None and len(paths) - index > keep
        excess_size = max_bytes is not None and total > max_bytes
        if not (excess_count or excess_size) or (preserve_latest and index == len(paths) - 1):
            break
        path.unlink(missing_ok=True)
        total -= sizes[path]
        removed += 1
    return removed


class SessionWriter:
    def __init__(self, config):
        self.config = config
        self.directory = ensure_private_dir(config.data_path() / "sessions")
        self.limit = min(config.max_session_size_mb, config.max_history_size_mb) * 1024**2
        self.handle = None
        self.path = None
        self.buffered = False

    def _open(self):
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        self.path = self.directory / f"{stamp}-{uuid4().hex[:8]}.{self.config.session_format}.part"
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        opener = gzip.open if self.config.session_format == "jsonl.gz" else open
        self.handle = opener(self.path, "wt", encoding="utf-8")

    def write(self, event, anomalies):
        if self.handle is None:
            self._open()
        self.handle.write(event.to_json() if not anomalies else json.dumps({
            **event.to_dict(),
            "anomalies": [anomaly.to_dict() for anomaly in anomalies],
        }, ensure_ascii=False))
        self.handle.write("\n")
        self.buffered = True

    def flush(self):
        if self.handle is not None and self.buffered:
            self.handle.flush()
            self.buffered = False
            if self.path.stat().st_size >= self.limit:
                return self.close()
        return None

    def close(self):
        if self.handle is None:
            return None
        self.handle.close()
        self.handle = None
        target = self.path.with_suffix("")
        self.path.rename(target)
        prune(
            self.directory, keep=self.config.max_sessions,
            max_bytes=self.config.max_history_size_mb * 1024**2,
            preserve_latest=True,
        )
        return target


def records(path: Path):
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as handle:
        for line in handle:
            yield json.loads(line)


def summary(path):
    sources = Counter()
    levels = Counter()
    alerts = Counter()
    for row in records(path):
        sources[row["source"]] += 1
        levels[row["severity_name"]] += 1
        alerts.update(anomaly["rule_id"] for anomaly in row.get("anomalies", []))
    return {"session": session_id(path), "events": sum(sources.values()),
            "sources": dict(sources), "levels": dict(levels), "alerts": dict(alerts)}
