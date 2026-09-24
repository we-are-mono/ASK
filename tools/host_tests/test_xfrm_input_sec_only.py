"""xfrm_input() receives a state the DPAA offload module holds through SEC and
nothing else, compiled from the patched tree.

SEC keeps such a state's anti-replay window, and xfrm's copy of it is only
refreshed from SEC, never written back; decrypting a frame in software would
check it against a second window, each accepting what the other had already
seen. So whatever SEC is not given -- the driver giving a frame back, and ESP
that GRO delivers past the driver -- is dropped and counted as
XfrmInStateMismatch, while every other state, another driver's packet-offloaded
one included, is received exactly as upstream receives it.
"""

import os
from pathlib import Path
import re
import subprocess

from test_qos_lifecycle import function

ROOT = Path(__file__).resolve().parents[2]


def test_xfrm_input_sec_only(tmp_path):
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    text = (kernel / "net/xfrm/xfrm_input.c").read_text()
    snmp = (kernel / "include/uapi/linux/snmp.h").read_text()
    (tmp_path / "xfrm_input_mib.inc").write_text(
        re.search(r"^enum\s*\{\s*LINUX_MIB_XFRMNUM = 0,.*?^\};", snmp, re.S | re.M).group()
        + "\n")
    (tmp_path / "xfrm_input_sec_only.inc").write_text(
        function(text, "xfrm_state_sec_only") + function(text, "xfrm_input"))
    binary = tmp_path / "xfrm_input_sec_only"
    subprocess.run([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
        "-Wno-unused-but-set-variable",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
        "-I", str(tmp_path), str(Path(__file__).with_name("xfrm_input_sec_only.c")),
        "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
