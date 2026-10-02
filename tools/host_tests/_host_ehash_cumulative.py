"""Shared support for ehash cumulative."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PCD = "drivers/net/ethernet/freescale/sdk_fman/Peripherals/FM/Pcd/fm_ehash.c"
HEADER = "drivers/net/ethernet/freescale/sdk_fman/inc/Peripherals/fm_ehash.h"


def declaration(source, name):
    """One struct as written, brace-matched, so a field added inside it comes
    along instead of truncating the type."""
    match = re.search(r"struct\s+" + name + r"\s*\{", source)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():source.index(";", end) + 1] + "\n"


def function(source, name):
    """A definition, whatever it returns: its parameter list is followed by a
    brace, which a call or a prototype never is. A comment that names the
    function is skipped: nothing in its prose need stop the search short of
    the brace that follows it."""
    match = re.search(r"^(?![ \t]*(?:/\*|\*|//))[^\n;{}]*\b" + name + r"\([^;{]*?\)\s*\{",
                      source, re.M)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"
