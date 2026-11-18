"""On-demand, local pcap recording with the system tcpdump."""
from contextlib import suppress
from datetime import datetime, timezone
import os
from pathlib import Path
import signal
import subprocess
import time
from uuid import uuid4

from .i18n import _
from .utils import ensure_private_dir, parse_duration, parse_size, which


def capture(config, interface, bpf, duration, output, max_size):
    tcpdump = which("tcpdump")
    if tcpdump is None:
        raise ValueError(_("capture.tcpdump_required"))
    seconds = parse_duration(duration) if duration is not None else config.pcap_default_duration
    limit = parse_size(max_size) if max_size is not None else config.pcap_max_size_mb * 1024**2
    if seconds <= 0 or limit <= 0:
        raise ValueError(_("capture.positive_limits"))

    if output is None:
        directory = ensure_private_dir(config.data_path() / "pcap")
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output = directory / f"{stamp}-{uuid4().hex[:8]}.pcap"
    path = Path(output)
    command = [tcpdump, "-i", interface, "-n", "-U", "-w", "-"]
    if bpf:
        command.extend(("--", bpf))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    complete = False
    try:
        with os.fdopen(fd, "wb") as handle:
            proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=handle)
            deadline = time.monotonic() + seconds
            stopping = False
            try:
                while proc.poll() is None:
                    if time.monotonic() >= deadline or os.fstat(handle.fileno()).st_size >= limit:
                        stopping = True
                        break
                    time.sleep(0.1)
            except KeyboardInterrupt:
                stopping = True
            finally:
                if proc.poll() is None:
                    with suppress(ProcessLookupError):
                        proc.send_signal(signal.SIGINT)
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
            complete = (proc.returncode == 0 or stopping) and os.fstat(handle.fileno()).st_size >= 24
    finally:
        if not complete:
            path.unlink(missing_ok=True)
    if not complete:
        raise ValueError(_("capture.failed"))
    return path
