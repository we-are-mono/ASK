"""The nxp-mwifiex driver as its recipe builds it for the kernel line ASK_LINE
names: NXP's release at the revision the recipe pins, with the line's local
fixes applied in the recipe's order."""

import io
import os
from pathlib import Path
import re
import subprocess
import tarfile

from ask_orch import kernel_line
from ask_orch.process import run_process

ROOT = Path(__file__).resolve().parents[2]
RECIPE = ROOT / "meta-ask/recipes-kernel/nxp-mwifiex/nxp-mwifiex_git.bb"


def revision(line=None):
    override = kernel_line.override(line)
    return re.search(rf'^SRCREV:{override} = "([0-9a-f]+)"$', RECIPE.read_text(), re.M)[1]


def patches(line=None):
    """The line's local fixes, in the order the recipe applies them."""
    line = line or kernel_line.current()
    listed = re.search(rf'^SRC_URI:append:{kernel_line.override(line)} = "(.*?)"$',
                       RECIPE.read_text(), re.M | re.S)[1]
    return [RECIPE.parent / "files" / line / name for name in re.findall(r"file://(\S+\.patch)", listed)]


def source(line=None):
    """bitbake's clone of the driver repository in the line's build tree, or
    the one ASK_MWIFIEX_SOURCE names."""
    return Path(os.environ.get("ASK_MWIFIEX_SOURCE")
                or kernel_line.tmpdir(line) / "work/ask_ls1046a-oe-linux/nxp-mwifiex/git/git")


def unpack(destination, line=None):
    """The patched driver tree in `destination`, independently of whether
    bitbake's working copy has rebuilt since the latest patch."""
    archive = subprocess.check_output(["git", "archive", revision(line)], cwd=source(line))
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(destination, filter="data")
    for patch in patches(line):
        run_process(["git", "apply", "--whitespace=error", str(patch)], cwd=destination, check=True)
