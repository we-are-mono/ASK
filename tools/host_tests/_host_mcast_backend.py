"""Shared support for mcast backend."""

import re
from pathlib import Path

from _host_qos_lifecycle import function

ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT / "cdx/cdx_mcast_backend.h"
SOURCE = ROOT / "cdx/dpa_control_mc.c"


def declarations(source):
    """Source with its comments removed. The prose is allowed to name the
    legacy vocabulary -- explaining what this interface replaces is most of
    what it says -- but none of it may appear in a declaration. Every ordering
    assertion below goes through this too: a comment that mentions a call is
    not that call, and matching one silently inverts the check.
    """
    return re.sub(r"/\*.*?\*/", "", source, flags=re.S)


def code(name, source=None):
    """One function's body, comments stripped."""
    return declarations(function(source or SOURCE.read_text(), name))
