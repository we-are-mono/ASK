"""Static lock-order net for the cmm daemon: `sa_lock` must stay a leaf.

cmm has one canonical lock chain — `itf_table.lock` -> `ctMutex` ->
`rtMutex` -> `neighMutex` — and the rtnl route/neighbor paths walk it
top-down before touching SA state, taking `sa_lock` innermost. Every
other `sa_lock` taker therefore has to agree: `sa_lock` is acquired
*after* any of those four, never before.

The regression this nets is a real deadlock. The CLI thread used to run
`cmmCtShow` holding `sa_lock` while blocking on `ctMutex` — and it holds
`sa_lock` across FCI round-trips, so the window is wide — while
`cmmCtThread` processed a route event holding `ctMutex`/`rtMutex`/
`neighMutex` and blocked on `sa_lock`. These are plain non-recursive
pthread mutexes (`__pthread_mutex_lock` is a straight alias for
`pthread_mutex_lock`), so both threads wedge permanently and all offload
event processing stops.

This parses the C sources on the host and never talks to the target
itself (the suite's standard target-reachability gate in conftest still
applies to the session). It is a coarse textual model of lock state — good enough because the offending
pattern is a literal ladder of `__pthread_mutex_lock(&x)` calls in a
single function — and the acquisition-site count below guards against
the parse silently degrading into a no-op pass.
"""

from __future__ import annotations

import re
from pathlib import Path

CMM_SRC = Path(__file__).resolve().parents[2] / "cmm" / "src"

# The canonical chain. `sa_lock` must never already be held when one of
# these is taken.
CANONICAL_LOCKS = frozenset({"itf_table.lock", "ctMutex", "rtMutex", "neighMutex"})

LEAF_LOCK = "sa_lock"

# A regression that broke the scan (renamed macro, moved sources) would
# otherwise turn this test into a green no-op. The tree currently has 10
# acquisition sites; require most of them to still be visible.
MIN_SA_LOCK_SITES = 8

LOCK_RE = re.compile(r"__pthread_mutex_lock\s*\(\s*&\s*([^)]+?)\s*\)")
UNLOCK_RE = re.compile(r"__pthread_mutex_unlock\s*\(\s*&\s*([^)]+?)\s*\)")

# Loose function-definition heuristic, used only to attribute a violation
# to a readable location: an identifier followed by '(' starting at
# column 0, not a declaration/call terminated by ';'.
FUNC_DEF_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_ \t\*]*?([A-Za-z_][A-Za-z0-9_]*)\s*\(")


class Violation:
    """One `sa_lock`-before-canonical-lock acquisition."""

    def __init__(
        self,
        path: Path,
        line_no: int,
        lock: str,
        func_name: str,
        func_line: int,
        held: list[str],
    ) -> None:
        self.path = path
        self.line_no = line_no
        self.lock = lock
        self.func_name = func_name
        self.func_line = func_line
        self.held = held

    def __str__(self) -> str:
        return (
            f"{self.path.name}:{self.line_no}: acquires {self.lock} while "
            f"holding {{{', '.join(self.held)}}} "
            f"(in {self.func_name}(), defined at line {self.func_line})"
        )


def _scan_file(path: Path) -> tuple[list[Violation], int]:
    """Return (violations, number of `sa_lock` acquisition sites) for one file."""
    violations: list[Violation] = []
    sa_sites = 0

    # Insertion-ordered so the reported held-set reads as an acquisition ladder.
    held: dict[str, int] = {}
    func_name = "<file scope>"
    func_line = 0

    for line_no, line in enumerate(path.read_text().splitlines(), start=1):
        # End of a top-level function: this codebase puts the closing
        # brace of a function body — and nothing else — at column 0.
        if line.startswith("}"):
            held.clear()
            continue

        if line[:1].isalpha() or line[:1] == "_":
            m = FUNC_DEF_RE.match(line)
            if m and not line.rstrip().endswith(";"):
                func_name = m.group(1)
                func_line = line_no

        m = LOCK_RE.search(line)
        if m:
            lock = m.group(1)
            if lock == LEAF_LOCK:
                sa_sites += 1
            elif lock in CANONICAL_LOCKS and LEAF_LOCK in held:
                violations.append(
                    Violation(
                        path, line_no, lock, func_name, func_line, list(held)
                    )
                )
            held.setdefault(lock, line_no)
            continue

        m = UNLOCK_RE.search(line)
        if m:
            held.pop(m.group(1), None)

    return violations, sa_sites


def _scan_tree() -> tuple[list[Violation], int]:
    violations: list[Violation] = []
    sa_sites = 0
    sources = sorted(CMM_SRC.glob("*.c"))
    assert sources, f"no cmm C sources found under {CMM_SRC}"
    for path in sources:
        file_violations, file_sites = _scan_file(path)
        violations.extend(file_violations)
        sa_sites += file_sites
    return violations, sa_sites


def test_cmm_sources_present() -> None:
    """Layout guard: the scan must be pointed at the real cmm sources."""
    assert CMM_SRC.is_dir(), (
        f"cmm source directory not found at {CMM_SRC} — repo layout changed "
        f"and this lock-order test is no longer scanning anything."
    )


def test_sa_lock_is_a_leaf_lock() -> None:
    """`sa_lock` is never held when a canonical-chain lock is acquired."""
    violations, sa_sites = _scan_tree()

    assert sa_sites >= MIN_SA_LOCK_SITES, (
        f"only {sa_sites} `{LEAF_LOCK}` acquisition site(s) found under "
        f"{CMM_SRC}, expected at least {MIN_SA_LOCK_SITES}. The scan has "
        f"gone blind (renamed lock macro, moved/renamed sources), so a "
        f"pass here would mean nothing."
    )

    assert not violations, (
        f"{len(violations)} lock-order violation(s): `{LEAF_LOCK}` is a leaf "
        f"lock and must be acquired AFTER "
        f"{'/'.join(sorted(CANONICAL_LOCKS))}, never before.\n  "
        + "\n  ".join(str(v) for v in violations)
        + f"\n\nThe rtnl route/neighbor paths hold the canonical chain and "
        f"take `{LEAF_LOCK}` innermost; a taker that inverts that order "
        f"deadlocks against them. Move the `{LEAF_LOCK}` acquisition to the "
        f"end of the ladder (and its release to the start of the LIFO "
        f"release ladder)."
    )
