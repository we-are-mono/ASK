"""The daemon's own Makefile, which every consumer runs, builds -Werror-clean
both where the compiler hardens by default and where it does not. Ubuntu's gcc
predefines _FORTIFY_SOURCE, under which glibc declares write() and fgets()
warn_unused_result, and a (void) cast does not silence that in GCC."""

import os
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("fortify", [None, 2, 3], ids=["plain", "fortify2", "fortify3"])
def test_builds_warning_free(tmp_path, fortify):
    # A copy, so the build leaves nothing in the checkout, and without the
    # objects a kas build leaves in src/: make would take them as current.
    tree = tmp_path / "flowtable"
    shutil.copytree(ROOT / "flowtable", tree,
                    ignore=shutil.ignore_patterns("oe-*", "*.o", "ask-flowtable"))
    # Without the variables of a make this runs under: a CFLAGS= given to it
    # would override the Makefile's own, -Werror with them.
    env = {k: v for k, v in os.environ.items() if k not in ("MAKEFLAGS", "MAKELEVEL", "MFLAGS")}
    # Undefined first: a compiler that predefines it, as Ubuntu's does, would
    # otherwise warn that it is redefined.
    env["CFLAGS"] = "" if fortify is None else f"-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE={fortify}"
    result = subprocess.run(["make", "-C", str(tree), f"CC={os.environ.get('HOSTCC', 'cc')}", "all"],
                            env=env, capture_output=True, text=True, timeout=300)
    assert result.returncode == 0, result.stdout[-2000:] + result.stderr[-4000:]
    assert (tree / "src" / "ask-flowtable").exists()
