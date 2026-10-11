"""Compile the kernel route builder at the bridge/IPsec boundary."""

from ask_orch.process import run_process
import os
from pathlib import Path

from _host_qos_lifecycle import (function)
from _kernel_source import (kernel_source)


def test_flowtable_ipsec_route(tmp_path):
    kernel = kernel_source()
    source = (kernel / "net/netfilter/nft_flow_offload.c").read_text()
    (tmp_path / "route_production.inc").write_text(
        source[source.index("static enum flow_offload_xmit_type nft_xmit_type"):
               source.index("static bool nft_is_valid_ether_device")]
        + function(source, "nft_flow_route"))
    binary = tmp_path / "flowtable_route"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra",
        "-Werror", "-Wno-unused-parameter", "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("flowtable_ipsec_route.c")), "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
