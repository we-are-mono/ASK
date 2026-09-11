"""SA teardown must release hardware pins before deleting counted routes."""

import os
from pathlib import Path
import re
import subprocess

import pytest

from test_qos_lifecycle import function

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("ls1043", [False, True], ids=["generic", "ls1043"])
def test_cmm_sa_delete(tmp_path, ls1043):
    source = Path(os.environ.get("ASK_CMM_SOURCE", ROOT / "cmm/src"))
    ipsec = (source / "module_ipsec.c").read_text()
    key = (source / "keytrack.c").read_text()
    header = (source / "module_ipsec.h").read_text()
    (tmp_path / "cmm_sa_types.inc").write_text(
        header[header.index("#define SA_HASH_TABLE_SIZE"):header.index("int __cmmSATunnelRegister")]
        + "\n".join(re.findall(r"^#define SA_STATE_.*$", ipsec, re.M)) + "\n"
    )
    (tmp_path / "cmm_sa_delete.inc").write_text(
        function((source / "conntrack.c").read_text(), "__cmmFPPRouteDeregister")
        + function(key, "cmmKeyEnginetoIPSec")
        + "\n".join(function(ipsec, name) for name in [
            "__cmmSARemove", "cmmSADelete", "cmmSAFlush", "cmmSASetState"])
        + function(key, "cmmKeyCatch")
    )
    binary = tmp_path / "cmm_sa_delete"
    subprocess.run([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-O1", "-g",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        "-fno-pie", "-no-pie", "-Werror=implicit-function-declaration",
        *(["-DLS1043"] if ls1043 else []),
        "-I", str(source), "-I", str(tmp_path),
        str(Path(__file__).with_name("cmm_sa_delete.c")), "-o", str(binary),
    ], check=True)
    result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30,
                            env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
                                 "UBSAN_OPTIONS": "halt_on_error=1"})
    assert result.returncode == 0, result.stdout + result.stderr
    print(result.stdout.strip())
