"""Route-event retries must refresh rolled-back tunnel, socket and SA bindings."""

import os
from pathlib import Path
import re
import subprocess

import pytest

from test_qos_lifecycle import function

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("vlan", [False, True], ids=["plain", "vlan"])
def test_cmm_route_retry(tmp_path, vlan):
    source_root = Path(os.environ.get("ASK_CMM_SOURCE", ROOT / "cmm/src"))
    route = (source_root / "route_cache.c").read_text()
    conntrack = (source_root / "conntrack.c").read_text()
    ipsec = (source_root / "module_ipsec.c").read_text()
    (tmp_path / "cmm_route_retry.inc").write_text(
        function(conntrack, "__cmmFPPRouteRegister")
        + function(conntrack, "__cmmCheckFPPRouteIdUpdate")
        + function(conntrack, "__cmmFPPRouteDeregister")
        + function(route, "__cmmTunnelRouteUpdate")
        + function(route, "__cmmSocketRouteUpdate")
        + function(ipsec, "__cmmSARouteUpdate")
        + function(route, "__cmmRouteIsTnlItf")
        + function(ipsec, "__cmmRouteIsSA")
        + function(route, "__cmmRouteLocalNew")
        + function(route, "__cmmRouteNew")
    )
    header = (source_root / "conntrack.h").read_text()
    (tmp_path / "cmm_route_flags.inc").write_text("\n".join(
        line for line in header.splitlines()
        if re.match(r"\s*#define (?:FLOWFLAG_|ORIGINATOR|REPLIER)", line)
    ))
    binary = tmp_path / "cmm_route_retry"
    subprocess.run([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-O1", "-g",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        "-fno-pie", "-no-pie", "-Werror=implicit-function-declaration",
        "-DLS1043", *(["-DVLAN_FILTER"] if vlan else []),
        "-I", str(source_root), "-I", str(tmp_path),
        str(Path(__file__).with_name("cmm_route_retry.c")), "-o", str(binary),
    ], check=True)
    result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30,
                            env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
                                 "UBSAN_OPTIONS": "halt_on_error=1"})
    assert result.returncode == 0, result.stdout + result.stderr
    print(result.stdout.strip())
