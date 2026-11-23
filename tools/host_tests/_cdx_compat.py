"""cdx/compat.h as the line under test resolves it, for harnesses that compile
cdx sources.

cdx's Kbuild force-includes compat.h ahead of every source; a harness compiles
those sources without the Kbuild, so it includes cdx_compat.inc instead: the
CDX_*/cdx_*/netif_* definitions the host preprocessor makes of compat.h at the
prepared tree's version. compat.h stays the one place a line difference is
decided. Its symbol-namespace shims are left out: harnesses stub the export
and module macros themselves.
"""

import os
from pathlib import Path
import re
import tempfile

from ask_orch.process import run_process
from _kernel_source import kernel_source

ROOT = Path(__file__).resolve().parents[2]
COMPAT = ROOT / "cdx/compat.h"
INC = "cdx_compat.inc"
NAMES = re.compile(r"^#define ((?:CDX_|cdx_|netif_)\w*)(\([^)]*\))?(?: (.*))?$")

# What a harness passes where compat.h's parameters are declared: the state's
# own device. Each is keyed on the parameters compat.h resolved to, so a
# change to compat.h that the harnesses do not model yet fails here rather
# than compiling into something else.
ARGUMENTS = {
    "CDX_XDO_DEV": ("CDX_XDO_DEV_ARG(dev)", {
        "": "",
        "struct net_device *dev,": "dev,"}),
}


def version(kernel):
    """(VERSION, PATCHLEVEL, SUBLEVEL) of the tree's top-level Makefile."""
    makefile = (kernel / "Makefile").read_text()
    return tuple(int(re.search(rf"^{name} = (\d+)$", makefile, re.M)[1])
                 for name in ("VERSION", "PATCHLEVEL", "SUBLEVEL"))


def definitions(kernel=None):
    """{name: (parameters, replacement)} of compat.h at the tree's version."""
    major, minor, sub = version(kernel or kernel_source())
    with tempfile.TemporaryDirectory() as include:
        # compat.h's own includes, empty: what it reads of them is the version.
        (Path(include) / "linux").mkdir()
        for header in ("version.h", "export.h", "module.h"):
            (Path(include) / "linux" / header).write_text("")
        out = run_process(
            [os.environ.get("HOSTCC", "cc"), "-E", "-dM", "-undef", "-nostdinc",
             "-I", include,
             "-DKERNEL_VERSION(a,b,c)=(((a) << 16) + ((b) << 8) + ((c) > 255 ? 255 : (c)))",
             f"-DLINUX_VERSION_CODE=KERNEL_VERSION({major},{minor},{sub})",
             str(COMPAT)],
            check=True, capture_output=True, text=True).stdout
    found = {}
    for line in out.splitlines():
        if (match := NAMES.match(line)) and match[1] != "CDX_COMPAT_H":
            found[match[1]] = (match[2] or "", match[3] or "")
    return found


def compat(directory, kernel=None):
    """Write cdx_compat.inc into `directory` for the line under test."""
    found = definitions(kernel)
    lines = [f"#define {name}{params} {body}".rstrip() for name, (params, body) in sorted(found.items())]
    for name, (argument, forms) in ARGUMENTS.items():
        resolved = found[name][1]
        assert resolved in forms, f"cdx/compat.h resolves {name} to {resolved!r}, which no harness models"
        lines.append(f"#define {argument} {forms[resolved]}".rstrip())
    (Path(directory) / INC).write_text(
        "/* cdx/compat.h as the line under test resolves it (_cdx_compat.py). */\n"
        + "\n".join(lines) + "\n")
    return found
