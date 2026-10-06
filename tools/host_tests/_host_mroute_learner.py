"""Shared support for mroute learner."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _between(source, start, end):
    return source[source.index(start):source.index(end)]


def mr_structs(source):
    """The learner's state structs. The group and its plan are shared with the
    probes, so the private header holds them; the VIF and the event stay with
    the learner."""
    return (_between(source, "struct ft_mr_group {", "struct ft_mr_watch {")
            + _between(source, "struct ft_mr_vif {", "static LIST_HEAD(ft_mr_groups)"))


def _hunks(section):
    """A patch section's hunks, each with the function its header names."""
    parts = re.split(r"^@@ [^@]* @@ ?(.*)$", section, flags=re.M)
    return list(zip(parts[1::2], parts[2::2]))


def _hunk_in(section, function_head):
    """The one hunk of a section inside the function `function_head` begins."""
    found = [text for head, text in _hunks(section) if function_head in head]
    assert len(found) == 1, (function_head, len(found))
    return found[0]


def _ordered(text, *lines):
    """Each line in `text`, once, and in the order given."""
    at = []
    for line in lines:
        assert text.count(line) == 1, (line, text.count(line))
        at.append(text.index(line))
    assert at == sorted(at), lines


# ---------------------------------------------------------------- locking

def _held_regions(body, lock, unlock):
    """Offsets in `body` at which `lock` is held, as (start, end) pairs.

    Each acquisition runs to the next release after it, or to the end of the
    text when there is none. None of these locks is ever taken recursively, so
    that is exact; an early-return arm with a release of its own only makes the
    model wider than the truth, which is the safe direction for a test that
    asserts something is *not* inside.
    """
    releases = [m.start() for m in re.finditer(re.escape(unlock), body)]
    return [(m.start(), next((r for r in releases if r > m.start()), len(body)))
            for m in re.finditer(re.escape(lock), body)]


def _assert_not_inside(body, regions, needle, why):
    for m in re.finditer(re.escape(needle), body):
        for start, end in regions:
            assert not (start < m.start() < end), why
