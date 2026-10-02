"""Compile the SEC input builder and completion paths with checked DMA ownership."""

from ask_orch.process import run_process

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_ipsec_sec_sg(tmp_path):
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    source = (kernel / "drivers/net/ethernet/freescale/sdk_dpaa/dpaa_eth_sg.c").read_text()
    (tmp_path / "ipsec_sec_sg.inc").write_text(
        source[source.index("static void dma_unmap_skb_sg_addrs"):
               source.index("int __hot skb_to_sg_fd(")])
    binary = tmp_path / "ipsec_sec_sg"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter", "-Wno-sign-compare",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
        "-I", str(tmp_path), str(Path(__file__).with_name("ipsec_sec_sg.c")),
        "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
