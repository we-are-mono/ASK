"""The kernel line a build or a test run is about.

One checkout builds every line it has a kernel recipe for, side by side
(meta-ask/conf/distro/ask.conf): each has its recipe, its patch series, its
SDK copy and its own build tree. ASK_LINE names the line a run is about, as
make's LINE does for the image build.
"""

import os
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
# The newest line, which meta-ask/.config.yaml and the Makefile default to too.
DEFAULT = "6.18"
RECIPES = "meta-ask/recipes-kernel/linux"
RECIPE = re.compile(r"^" + re.escape(RECIPES) + r"/linux-ask_(.+)\.bb$")


def lines(root=ROOT):
    """Every line the checkout has a kernel recipe for."""
    return sorted(path.stem.split("_", 1)[1]
                  for path in (Path(root) / RECIPES).glob("linux-ask_*.bb"))


def released(root=ROOT):
    """The lines a release tag from this checkout is released for:
    RELEASED_LINES, one per line, each one the checkout builds."""
    names = [entry for entry in (raw.split("#", 1)[0].strip()
                                 for raw in (Path(root) / "RELEASED_LINES").read_text().splitlines())
             if entry]
    if unknown := sorted(set(names) - set(lines(root))):
        raise ValueError(f"RELEASED_LINES names {', '.join(unknown)}, which this checkout "
                         f"has no kernel recipe for ({', '.join(lines(root))})")
    return names


def current(environ=None):
    """The line ASK_LINE names, the default when it names none."""
    line = (os.environ if environ is None else environ).get("ASK_LINE") or DEFAULT
    if line not in lines():
        raise ValueError(f"ASK_LINE={line} is none of this checkout's kernel lines "
                         f"({', '.join(lines())})")
    return line


def override(line=None):
    """The bitbake override recipes select a line on: 6.18 is ask618."""
    return "ask" + (line or current()).replace(".", "")


def recipe(line=None, root=ROOT):
    return Path(root) / RECIPES / f"linux-ask_{line or current()}.bb"


def patches(line=None, root=ROOT):
    return Path(root) / "patches/kernel" / (line or current())


def sdk(line=None, root=ROOT):
    """The line's copy of the NXP SDK drivers, laid out as in a kernel tree."""
    return Path(root) / "sdk" / (line or current())


def tmpdir(line=None, root=ROOT):
    """The line's bitbake TMPDIR: its work, work-shared and deploy trees."""
    return Path(root) / "meta-ask/build" / f"tmp-{line or current()}"


def kernel_source(line=None, root=ROOT):
    """The patched kernel tree the line's image build prepared."""
    return tmpdir(line, root) / "work-shared/ask-ls1046a/kernel-source"


def recorded(paths):
    """The line a kernel build record was built for, from the recipe it
    lists; None when it lists none."""
    for path in paths:
        if match := RECIPE.match(path):
            return match.group(1)
    return None
