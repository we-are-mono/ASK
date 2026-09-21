"""Compile the kernel route builder at the bridge/IPsec boundary."""
import os
from pathlib import Path
import subprocess

from test_qos_lifecycle import function

ROOT = Path(__file__).resolve().parents[2]


def test_flowtable_ipsec_route(tmp_path):
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    source = (kernel / "net/netfilter/nft_flow_offload.c").read_text()
    (tmp_path / "route_production.inc").write_text(
        source[source.index("static enum flow_offload_xmit_type nft_xmit_type"):
               source.index("static bool nft_is_valid_ether_device")]
        + function(source, "nft_flow_route"))
    binary = tmp_path / "flowtable_route"
    subprocess.run([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra",
        "-Werror", "-Wno-unused-parameter", "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("flowtable_ipsec_route.c")), "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
