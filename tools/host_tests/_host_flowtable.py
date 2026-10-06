"""Shared support for flowtable."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def flowtable_source():
    """The flowtable adapter as one text: its private header, then each of its
    objects, so a slice or an anchor finds what it names wherever it lives."""
    cdx = ROOT / "cdx"
    return "".join(path.read_text() for path in
                   [cdx / "ask_flowtable_internal.h", *sorted(cdx.glob("ask_flowtable_*.c"))])


def function(source, name):
    # The line has to begin with a word, the return type: a comment line that
    # names `foo()' would otherwise match and run on to the next definition.
    match = re.search(r"^(?:static )?\w[^\n]*\b" + name + r"\([^;]*?\)\s*\{", source, re.M)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"
