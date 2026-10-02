"""Sampling a running core's memory and CPU while traffic flows.

The numbers that decide which core is cheaper are properties of a *process*, so
they are read from the OS rather than inferred from anything the core reports:

* resident set size, sampled;
* cumulative CPU time, differenced across the sample window;
* thread count, where the platform exposes it.

Two deliberate choices:

* **Peak is the maximum of the samples**, not `VmHWM`, so the number means the
  same thing on every platform this harness runs on. `VmHWM` is recorded
  separately on Linux because it is a better measurement, and the two are
  reported as different fields rather than silently merged.
* **CPU is a difference, not a total.** A process that was already busy before
  the sample started would otherwise be charged for work this benchmark did not
  ask for, which is exactly how a core with a busy background task looks
  faster than one without.

The server process is sampled too. It shares loopback CPU with the client even
though it is not the thing under test, and leaving that unstated is how a
loopback number ends up meaning "the pair, on this host".
"""

from __future__ import annotations

import os
import platform
import subprocess
import threading
import time
from dataclasses import dataclass

IS_LINUX = platform.system() == "Linux"
PAGE_KB = os.sysconf("SC_PAGE_SIZE") // 1024 if hasattr(os, "sysconf") else 4
CLOCK_TCK = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100

# Linux reports /proc/<pid>/stat times in clock ticks; macOS `ps time` is
# "D-HH:MM:SS.ss" or "MM:SS.ss". Sampling more finely than the tick would only
# produce repeated values.
DEFAULT_INTERVAL = 0.05 if IS_LINUX else 0.2


@dataclass
class Sample:
    at: float
    rss_kb: float
    cpu_s: float
    threads: int | None


def _read_linux(pid: int) -> tuple[float, float, int] | None:
    try:
        with open(f"/proc/{pid}/stat", "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    # The comm field can contain spaces and parentheses, so the fields after it
    # are located from the *last* ')'. Getting this wrong silently reports
    # another process's numbers.
    end = data.rfind(b")")
    if end < 0:
        return None
    fields = data[end + 2 :].split()
    if len(fields) < 19:
        return None
    utime = int(fields[11])
    stime = int(fields[12])
    threads = int(fields[17])
    return (utime + stime) / CLOCK_TCK, float(threads), threads


def _read_linux_rss(pid: int) -> float | None:
    try:
        with open(f"/proc/{pid}/statm", "rb") as fh:
            fields = fh.read().split()
    except OSError:
        return None
    if len(fields) < 2:
        return None
    return int(fields[1]) * PAGE_KB


def _read_linux_hwm(pid: int) -> float | None:
    try:
        with open(f"/proc/{pid}/status", "r") as fh:
            for line in fh:
                if line.startswith("VmHWM:"):
                    return float(line.split()[1])
    except OSError:
        pass
    return None


def _ps_time_to_seconds(text: str) -> float | None:
    """Parse `ps -o time=` into seconds.

    The format grows a day field once a process has been alive long enough, and
    a benchmark session can easily cross that boundary on a slow runner.
    """
    text = text.strip()
    if not text:
        return None
    days = 0
    if "-" in text:
        day_part, text = text.split("-", 1)
        try:
            days = int(day_part)
        except ValueError:
            return None
    parts = text.split(":")
    try:
        if len(parts) == 3:
            hours, minutes, seconds = parts
        elif len(parts) == 2:
            hours, minutes, seconds = "0", parts[0], parts[1]
        else:
            return None
        return days * 86400 + int(hours) * 3600 + int(minutes) * 60 + float(seconds)
    except ValueError:
        return None


def _read_darwin(pid: int) -> tuple[float, float, int | None] | None:
    try:
        proc = subprocess.run(
            ["ps", "-o", "rss=", "-o", "time=", "-p", str(pid)],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    parts = proc.stdout.split()
    if len(parts) < 2:
        return None
    try:
        rss = float(parts[0])
    except ValueError:
        return None
    cpu = _ps_time_to_seconds(parts[1])
    if cpu is None:
        return None
    return rss, cpu, 0


def read_once(pid: int) -> Sample | None:
    now = time.monotonic()
    if IS_LINUX:
        cpu = _read_linux(pid)
        if cpu is None:
            return None
        cpu_s, _threads_unused, threads = cpu
        rss = _read_linux_rss(pid)
        if rss is None:
            return None
    else:
        values = _read_darwin(pid)
        if values is None:
            return None
        rss, cpu_s, threads = values
        threads = None
    return Sample(at=now, rss_kb=rss, cpu_s=cpu_s, threads=threads)


def read_rss_kb(pid: int) -> float | None:
    sample = read_once(pid)
    return sample.rss_kb if sample else None


def read_hwm_kb(pid: int) -> float | None:
    return _read_linux_hwm(pid) if IS_LINUX else None


class Sampler:
    """Polls one pid until stopped, then reports what it saw.

    A `with` block, because the failure mode of getting this wrong is a sampling
    thread that outlives the measurement and keeps a dead pid in a loop.
    """

    def __init__(self, pid: int, interval: float | None = None):
        self.pid = pid
        self.interval = interval or DEFAULT_INTERVAL
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.samples: list[Sample] = []
        self.error: str | None = None

    def __enter__(self) -> "Sampler":
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_exc) -> None:
        self.stop()

    def _loop(self) -> None:
        while not self._stop.is_set():
            sample = read_once(self.pid)
            if sample is None:
                # The process is gone. That is information, not a crash: a core
                # that died mid-sample is a result the report must show.
                self.error = "process disappeared while sampling"
                return
            self.samples.append(sample)
            self._stop.wait(self.interval)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)


@dataclass
class Window:
    """A difference between two samples, which is the only honest form of CPU."""

    cpu_s: float
    rss_peak_kb: float
    rss_hwm_kb: float | None
    threads_peak: int | None
    samples: int
    missing: bool = False

    @property
    def rss_peak_mb(self) -> float:
        return self.rss_peak_kb / 1024.0

    def cpu_s_per_gb(self, bytes_moved: int) -> float | None:
        if bytes_moved <= 0:
            return None
        gib = bytes_moved / (1024**3)
        if gib <= 0:
            return None
        return self.cpu_s / gib


def summarise(samples: list[Sample], pid: int | None = None) -> Window:
    if not samples:
        return Window(0.0, 0.0, None, None, 0, missing=True)
    peak = max(s.rss_kb for s in samples)
    threads = [s.threads for s in samples if s.threads]
    return Window(
        # First and last cumulative CPU, in that order: a difference of a
        # cumulative counter is the window's cost and nothing else.
        cpu_s=max(0.0, samples[-1].cpu_s - samples[0].cpu_s),
        rss_peak_kb=peak,
        rss_hwm_kb=read_hwm_kb(pid) if pid else None,
        threads_peak=max(threads) if threads else None,
        samples=len(samples),
    )
