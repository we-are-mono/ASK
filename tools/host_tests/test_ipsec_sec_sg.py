"""Compile the SEC input builder and completion paths with checked DMA ownership."""

import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def test_ipsec_sec_sg(tmp_path):
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    source = (kernel / "drivers/net/ethernet/freescale/sdk_dpaa/dpaa_eth_sg.c").read_text()
    (tmp_path / "ipsec_sec_sg.inc").write_text(
        source[source.index("static void dma_unmap_skb_sg_addrs"):
               source.index("EXPORT_SYMBOL(skb_fraglist_to_sg_fd);")])
    binary = tmp_path / "ipsec_sec_sg"
    subprocess.run([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter", "-Wno-sign-compare",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
        "-I", str(tmp_path), str(Path(__file__).with_name("ipsec_sec_sg.c")),
        "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
