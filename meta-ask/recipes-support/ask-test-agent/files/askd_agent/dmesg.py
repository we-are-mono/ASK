"""Kernel-log capture with explicit completeness and sequence validation."""

from __future__ import annotations

import os
import re
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
    r"(?<!DE)BUG: |"            # generic kernel BUG(); not "ASK-DEBUG: " tracing
    r"kernel BUG at|"           # BUG_ON
    r"Oops:|"                   # NULL deref / page fault
    r"Unable to handle|"        # arm64 page-fault banner
    r"INFO: possible (recursive locking|circular locking|"
    r"irq lock inversion)|"     # lockdep dependency reports
    r"INFO: trying to register non-static key|"
    r"inconsistent.*usage)"     # lockdep state-mismatch
)

def open_at_tail() -> int:
    """Open a capture, or fail rather than create an unobservable window."""
    fd = os.open(KMSG_PATH, os.O_RDONLY | os.O_NONBLOCK)
    try:
        os.lseek(fd, 0, os.SEEK_END)
    except BaseException:
        os.close(fd)
        raise
    return fd


def drain(fd: int | None, *, cursor=None, boot=False) -> dict:
    """Retain partial evidence, but never label missing records complete."""
    result = {"complete": True, "error": None, "lines": [], "cursor": cursor}
    if fd is None:
        return {**result, "complete": False, "error": "kernel log is unavailable"}
    previous = None
    while True:
        try:
            chunk = os.read(fd, 65536)
        except BlockingIOError:
            break
        except OSError as error:
            result.update(complete=False, error=f"kernel log read failed: {error}")
            break
        if not chunk:
            break
        try:
            header, message = chunk.split(b";", 1)
            sequence = int(header.split(b",")[1])
        except (ValueError, IndexError):
            result.update(complete=False, error="malformed kernel log record")
            break
        if previous is None and boot and sequence > 1:
            result.update(complete=False, error="boot log has already been overwritten")
        if previous is not None and sequence != previous + 1:
            result.update(complete=False, error="kernel log sequence gap")
        if previous is None and cursor is not None and sequence > cursor + 1:
            result.update(complete=False, error="kernel log cursor has been overwritten")
        previous = sequence
        if cursor is None or sequence > cursor:
            result["lines"].extend(message.decode("utf-8", "replace").splitlines())
            result["cursor"] = sequence
    if boot and previous is None:
        result.update(complete=False, error="boot log is empty")
    return result


def close(fd: int | None) -> None:
    if fd is not None:
        os.close(fd)


def read_since(cursor: int | None) -> dict:
    """Read the retained boot log, or records following an explicit cursor."""
    try:
        fd = os.open(KMSG_PATH, os.O_RDONLY | os.O_NONBLOCK)
    except OSError as error:
        return {"complete": False, "error": str(error), "lines": [], "cursor": cursor}
    try:
        return drain(fd, cursor=cursor, boot=cursor is None)
    finally:
        close(fd)


def has_splat(lines: list[str]) -> list[str]:
    return [line for line in lines if SPLAT_RE.search(line)]
