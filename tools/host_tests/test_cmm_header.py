"""The public CMM command header declares its own type dependencies."""

from pathlib import Path
import os
import subprocess

import pytest


@pytest.mark.parametrize("defines", [[], ["-DLS1043", "-DUSE_QOSCONNMARK"]],
                         ids=["generic", "ls1043"])
def test_cmm_header_standalone(defines):
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [os.environ.get("HOSTCC", "cc"), "-Werror", "-fsyntax-only", "-x", "c",
         "-I", str(root / "cmm/src"), *defines, "-"],
        input='#include "fpp.h"\n', text=True, capture_output=True,
    )
    assert result.returncode == 0, result.stderr
