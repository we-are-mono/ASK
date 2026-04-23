"""Capture dmesg deltas between two points in time.

Strategy: the agent records the current dmesg cursor (last seen seq# from
/dev/kmsg, or the wall-clock timestamp if /dev/kmsg is unavailable) on
capture-start, and returns new lines on capture-stop/dmesg-delta.

Why not `dmesg --since`: that resolves to seconds, so two rapid-fire tests
will share the same time bucket and eat each other's lines. /dev/kmsg seq#
is per-message monotonic — the right primitive here.
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path

KMSG_PATH = Path("/dev/kmsg")

# KASAN/BUG/WARN signatures we treat as instant failure.
SPLAT_RE = re.compile(
    r"(BUG: KASAN|KFENCE: \w+|==============|UBSAN:|WARNING:|BUG: |"
    r"kernel BUG at|Oops:|Unable to handle|lockdep|"
    r"inconsistent.*usage|possible circular locking)"
)


def read_kmsg_seq() -> int | None:
    """Return the current last-written /dev/kmsg sequence number (None if N/A)."""
    if not KMSG_PATH.exists():
        return None
    # /dev/kmsg format: "priority,seq,time_us,flags[,...];message\n"
    # Seeking to EOF and back gets the tail; simpler: open nonblock, read all
    # pending, and remember the last seq.
    try:
        fd = os.open(str(KMSG_PATH), os.O_RDONLY | os.O_NONBLOCK)
    except OSError:
        return None
    last_seq = 0
    try:
        while True:
            try:
                chunk = os.read(fd, 8192)
            except BlockingIOError:
                break
            if not chunk:
                break
            for line in chunk.splitlines():
                try:
                    header = line.split(b";", 1)[0].decode("ascii", "replace")
                    parts = header.split(",")
                    if len(parts) >= 2:
                        last_seq = max(last_seq, int(parts[1]))
                except (ValueError, IndexError):
                    continue
    finally:
        os.close(fd)
    return last_seq


def read_since(cursor: int | None) -> tuple[int | None, list[str]]:
    """Return (new_cursor, list_of_new_lines) since the given cursor.

    cursor is a kmsg seq# (from read_kmsg_seq). If None, the full current
    buffer is returned.
    """
    if not KMSG_PATH.exists():
        return None, []
    try:
        fd = os.open(str(KMSG_PATH), os.O_RDONLY | os.O_NONBLOCK)
    except OSError:
        return None, []

    out_lines: list[str] = []
    new_cursor = cursor
    try:
        while True:
            try:
                chunk = os.read(fd, 8192)
            except BlockingIOError:
                break
            if not chunk:
                break
            for raw in chunk.splitlines():
                try:
                    header, msg = raw.split(b";", 1)
                    header_s = header.decode("ascii", "replace")
                    parts = header_s.split(",")
                    seq = int(parts[1])
                except (ValueError, IndexError):
                    continue
                if cursor is None or seq > cursor:
                    out_lines.append(msg.decode("utf-8", "replace"))
                    new_cursor = seq if new_cursor is None else max(new_cursor, seq)
    finally:
        os.close(fd)
    return new_cursor, out_lines


def has_splat(lines: list[str]) -> list[str]:
    """Return the subset of lines matching KASAN/BUG/UBSAN/lockdep signatures."""
    return [l for l in lines if SPLAT_RE.search(l)]
