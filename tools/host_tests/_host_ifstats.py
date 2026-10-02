"""Shared support for ifstats."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HEADER = "drivers/net/ethernet/freescale/sdk_fman/inc/Peripherals/fm_ehash.h"


def declaration(source, kind, name):
    """One struct or enum as written, brace-matched rather than pattern-matched,
    so a field added inside it comes along instead of truncating the type. The
    opening brace is matched by regex rather than by literal text: the sources
    this reads from put it on the next line, on the same line, and directly
    against the name, all three."""
    match = re.search(rf"\b{kind}\s+{name}\s*\{{", source)
    assert match, (kind, name)
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():source.index(";", end) + 1] + "\n"


def stats_fields(source):
    """The statistics tail of `struct dpa_iface_info`, taken verbatim with the
    conditional it lives inside.

    The rest of that structure is a union of six device descriptions and drags
    in most of the driver's headers, none of which the allocator touches. What
    it does touch is these four fields, so these four are the real ones and the
    surrounding structure is not modelled at all -- a rename or a resize here
    still has to fail, which is the whole point of not restating them.
    """
    body = declaration(source, "struct", "dpa_iface_info")
    start = body.index("#ifdef INCLUDE_IFSTATS_SUPPORT")
    return "struct dpa_iface_info {\n" + body[start:body.index("#endif", start) + 6] + "\n};\n"
