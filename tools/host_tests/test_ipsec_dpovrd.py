"""The DPOVRD value the DPAA driver gives SEC, compiled from the driver.

SEC takes the IP header length, the next-header offset and the next header
from DPOVRD instead of from the SA's PDB whenever the override bit is set, so
the value decides what a frame is encrypted as. A tunnel's names the inner
protocol; a transport SA's has to describe the frame's own IP header.
"""

import os
from pathlib import Path
import re
import subprocess

from test_qos_lifecycle import function

ROOT = Path(__file__).resolve().parents[2]


def test_ipsec_dpovrd(tmp_path):
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    source = (kernel / "drivers/net/ethernet/freescale/sdk_dpaa/dpaa_eth_sg.c").read_text()
    (tmp_path / "ipsec_dpovrd.inc").write_text(
        re.search(r"^#define DPOVRD_ENABLE\s.*$", source, re.M).group(0) + "\n"
        + function(source, "dpa_ipsec_dpovrd"))
    binary = tmp_path / "ipsec_dpovrd"
    subprocess.run([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
        "-I", str(tmp_path), str(Path(__file__).with_name("ipsec_dpovrd.c")),
        "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
