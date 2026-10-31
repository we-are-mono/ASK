"""Compile the kernel route builder at the bridge/IPsec boundary, and the
forward-path walk under it."""

from ask_orch.process import run_process
import os
from pathlib import Path

from _host_qos_lifecycle import (function)
from _kernel_source import (kernel_source)


def _run(tmp_path, harness, includes, flags=()):
    for include, production in includes.items():
        (tmp_path / include).write_text(production)
    binary = tmp_path / Path(harness).stem
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra",
        "-Werror", "-Wno-unused-parameter", *flags, "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name(harness)), "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })


def _source(path="net/netfilter/nft_flow_offload.c"):
    return (kernel_source() / path).read_text()


def test_flowtable_ipsec_route(tmp_path):
    source = _source()
    _run(tmp_path, "flowtable_ipsec_route.c", {"route_production.inc":
         source[source.index("static enum flow_offload_xmit_type nft_xmit_type"):
                source.index("static bool nft_is_valid_ether_device")]
         + function(source, "nft_flow_route")})


def test_flowtable_forward_path_unresolved_hops(tmp_path):
    """A flow's first packet can meet a hop of its path not resolved yet: the
    client's neighbour on a VLAN or bridge just created again, a tunnel's
    outer next hop or outer route after the WAN link flapped, the client's FDB
    entry after it aged out. A table with neighbour output then caches no flow
    -- one cached on the logical device would never be walked again -- and
    asks for the neighbour where there is one to ask; a tunnel hop defers for
    every table. Ports, tables without neighbour output, PPPoE and a bridge
    port that is not forwarding keep their behaviour. A walk that reaches a
    port the table does not list falls back, and records the port when the
    fallback names a device above it, so that the port joining the table can
    retire the flow."""
    source = _source()
    dev = _source("net/core/dev.c")
    _run(tmp_path, "flowtable_forward_path.c", {
        "forward_path_devices.inc":
            function(dev, "dev_fwd_path") + function(dev, "dev_fill_forward_path")
            + function(_source("net/8021q/vlan_dev.c"), "vlan_dev_fill_forward_path")
            + function(_source("net/bridge/br_device.c"), "br_fill_forward_path")
            + function(_source("net/ipv6/sit.c"), "ipip6_fill_forward_path")
            + function(_source("net/ipv6/ip6_tunnel.c"), "ip6_tnl_fill_forward_path"),
        "forward_path_production.inc":
            source[source.index("static enum flow_offload_xmit_type nft_xmit_type"):
                   source.index("static bool nft_flow_offload_skip")],
    # The hooks compare an int count with ARRAY_SIZE(), as the kernel, which
    # builds without this warning, lets them.
    }, flags=("-Wno-sign-compare",))
