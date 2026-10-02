"""Shared support for pppoe hm."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HEADER = "drivers/net/ethernet/freescale/sdk_fman/inc/Peripherals/fm_ehash.h"


def declaration(source, name):
    """One struct as written, brace-matched rather than pattern-matched, so a
    field added inside it comes along instead of truncating the type."""
    start = source.index("struct " + name + " {")
    end, depth = source.index("{", start) + 1, 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:source.index(";", end) + 1] + "\n"


def typedef(source, tag):
    """A typedef'd struct, tag through to the name it is typedef'd to. The two
    IP headers are declared this way and the L3 description embeds both."""
    match = re.search(r"typedef struct\s+" + tag + r"\b.*?\}\s*\w+\s*;", source, re.S)
    assert match, tag
    return match.group() + "\n"


def display(source, name):
    body = source[source.index("static inline void *" + name + "("):]
    return body[:body.index("\n}") + 3]
