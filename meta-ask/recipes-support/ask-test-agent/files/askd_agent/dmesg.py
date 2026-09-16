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

# Kernel-splat banner patterns. Match the *first line* of a kernel
# sanitiser/lockdep/BUG report; the agent reports the line as an
# instant-failure signal up to the orchestrator's splat_window.
SPLAT_RE = re.compile(
    r"(BUG: KASAN|"
    r"KFENCE: \w+|"
    r"==============|"          # KASAN/KFENCE/UBSAN banner separator
    r"UBSAN:|"
    r"WARNING:|"                # WARN_ON family + bad-unlock-balance etc.
    r"BUG: |"                   # generic kernel BUG()
    r"kernel BUG at|"           # BUG_ON
    r"Oops:|"                   # NULL deref / page fault
    r"Unable to handle|"        # arm64 page-fault banner
    r"INFO: possible (recursive locking|circular locking|"
    r"irq lock inversion)|"     # lockdep dependency reports
    r"INFO: trying to register non-static key|"
    r"inconsistent.*usage)"     # lockdep state-mismatch
)

def open_at_tail() -> int | None:
    """Open /dev/kmsg positioned after the last record, for a capture window.

    Every open of /dev/kmsg starts at the *oldest* surviving record, so
    learning "where we are now" by reading to the end costs a full parse of
    the ring -- 4 MiB on a log_buf_len=4M image, which is most of a second in
    Python and was being paid twice per test. SEEK_END is handled specially
    for this file: it positions after the last record, so a later read returns
    exactly what the window produced and nothing before it. Holding the
    descriptor open is what makes that position durable.

    Returns a descriptor the caller must close, or None if kmsg is absent.
    """
    if not KMSG_PATH.exists():
        return None
    try:
        fd = os.open(str(KMSG_PATH), os.O_RDONLY | os.O_NONBLOCK)
        os.lseek(fd, 0, os.SEEK_END)
    except OSError:
        return None
    return fd


def drain(fd: int | None) -> list[str]:
    """Read every record written since the descriptor was positioned."""
    lines: list[str] = []
    if fd is None:
        return lines
    while True:
        try:
            chunk = os.read(fd, 8192)
        except BlockingIOError:
            break
        except OSError:
            # EPIPE: records were overwritten while we held the position, so
            # the window is no longer complete. Keep what we have rather than
            # reporting a clean window we cannot vouch for.
            lines.append("askd-agent: kmsg overrun, window truncated")
            break
        if not chunk:
            break
        for raw in chunk.splitlines():
            _, _, msg = raw.partition(b";")
            lines.append(msg.decode("utf-8", "replace"))
    return lines


def close(fd: int | None) -> None:
    if fd is not None:
        try:
            os.close(fd)
        except OSError:
            pass


def read_kmsg_seq() -> int | None:
    """Return the current last-written /dev/kmsg sequence number (None if N/A).

    Walks the whole ring; used only by the cursor-based dmesg-delta endpoint,
    where the caller supplies its own cursor across separate requests and no
    descriptor can be held between them.
    """
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
    """Return the subset of lines that look like kernel splats.

    Policy lives client-side: orchestrator's splat_window fixture filters
    this raw list against tools/tests/golden/dmesg_allowlist.yaml. Keeping
    the agent simple means no rebuild/restage cycle to update suppressions.
    """
    return [l for l in lines if SPLAT_RE.search(l)]
