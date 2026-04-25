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

# Lines that pass SPLAT_RE on substring but are benign informational
# kernel banners — e.g. CONFIG_PROVE_RCU's boot announcement before any
# real lock has been taken. These are routine on every boot of a
# lockdep-enabled image and aren't splats. The pattern below is
# matched against the same lines BEFORE reporting; matches are
# excluded from the splat list.
#
# (Today this is belt-and-braces defence — the rcu line no longer
# matches SPLAT_RE itself once we tightened "lockdep" to specific
# splat patterns above. Kept so a future SPLAT_RE broadening doesn't
# silently re-introduce the false positive.)
_SPLAT_FALSE_POSITIVES_RE = re.compile(
    r"rcu: RCU lockdep checking is enabled"
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
    """Return the subset of lines that look like real kernel splats.

    Filters out informational lines that match SPLAT_RE on substring
    but aren't actual sanitiser/lockdep reports — see
    `_SPLAT_FALSE_POSITIVES_RE` for the deny-list. Centralising the
    filter here means every caller of /capture-stop and /dmesg-delta
    benefits, not just orchestrator fixtures with their own ad-hoc
    deny-list."""
    return [
        l for l in lines
        if SPLAT_RE.search(l) and not _SPLAT_FALSE_POSITIVES_RE.search(l)
    ]
