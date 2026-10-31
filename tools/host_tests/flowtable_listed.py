"""Compile a port joining a flowtable: nf_tables publishing the hook, the
flowtable retiring the flows that walked to the port while it was unlisted,
and the check a flow added after its walk makes against the list."""

import os
import re
from pathlib import Path

from ask_orch.process import run_process
from _host_qos_lifecycle import (function)
from _kernel_source import (kernel_source)


def _declaration(source, start):
    return re.search(r"^" + re.escape(start) + r".*?^\};\n", source, re.M | re.S).group()


def test_a_joining_port_retires_the_flows_that_walked_to_it(tmp_path):
    """A flow whose walk reached a port the flowtable did not list -- one that
    lost carrier, before a table following its ports adds it back -- is cached
    on the device above the port, which no hook matches, and records the
    port. The port joining the table retires exactly those flows: not one that
    recorded nothing, nor another port such as a bridged Wi-Fi interface, nor
    one of another namespace. nf_tables publishes an update's hooks where
    list_splice_rcu() put them, one at a time, each before a full barrier and
    the sweep for it, and a flow added after its walk looks at the list again
    behind a barrier of its own, so that a sweep run before the flow was in
    the table cannot miss it. A flow that recorded no port pays nothing. The
    port going down retires the flows that recorded it as well: one
    registered again comes back under another index, which nothing
    recorded."""
    kernel = kernel_source()
    header = (kernel / "include/net/netfilter/nf_flow_table.h").read_text()
    tables = (kernel / "include/net/netfilter/nf_tables.h").read_text()
    core = (kernel / "net/netfilter/nf_flow_table_core.c").read_text()
    offload = (kernel / "net/netfilter/nft_flow_offload.c").read_text()
    api = (kernel / "net/netfilter/nf_tables_api.c").read_text()
    inet = (kernel / "net/netfilter/nf_flow_table_inet.c").read_text()

    (tmp_path / "listed_types.inc").write_text(
        "".join(_declaration(header, start) for start in (
            "enum flow_offload_tuple_dir {", "enum flow_offload_xmit_type {",
            "enum nf_flow_flags {", "enum flow_offload_type {",
            "struct nf_flowtable_type {", "struct nf_flowtable {",
            "struct nf_flow_session {", "struct nf_flow_tunnel {",
            "struct flow_offload_tuple {", "struct flow_offload_tuple_rhash {",
            "struct flow_offload {", "struct nf_flow_route {"))
        + re.search(r"^#define NFT_HOOK_REMOVE\b.*\n", tables, re.M).group()
        + _declaration(tables, "struct nft_hook {")
        + _declaration(tables, "struct nft_flowtable {"))
    (tmp_path / "listed_production.inc").write_text(
        function(core, "nft_route_dst_fetch")
        + function(core, "flow_offload_fill_route")
        + function(core, "flow_offload_route_init")
        + function(core, "nf_flow_table_iterate")
        + function(core, "nf_flow_table_do_cleanup")
        + function(core, "nf_flow_table_do_listed")
        + function(core, "nf_flow_table_listed")
        + function(api, "nft_flowtable_hooks_publish")
        + function(offload, "nft_flowtable_find_ifindex")
        + function(offload, "nft_flow_offload_check_unlisted"))
    binary = tmp_path / "flowtable_listed"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra",
        "-Werror", "-Wno-unused-parameter", "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("flowtable_listed.c")), "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })

    # Where the compiled pieces are called from. The commit publishes an
    # update's hooks through the helper, and nothing splices them any more.
    commit = function(api, "nf_tables_commit")
    update = commit[commit.index("case NFT_MSG_NEWFLOWTABLE:"):
                    commit.index("case NFT_MSG_DELFLOWTABLE:")]
    assert re.search(r"if \(nft_trans_flowtable_update\(trans\)\) \{.*?"
                     r"nft_flowtable_hooks_publish\(nft_trans_flowtable\(trans\),\s*"
                     r"&nft_trans_flowtable_hooks\(trans\)\);\s*\} else \{", update, re.S)
    assert "list_splice_rcu" not in update
    # A flow checks the list once it is in the table, and only then.
    evaluate = function(offload, "nft_flow_offload_eval")
    assert re.search(r"ret = flow_offload_add\(flowtable, flow\);\s*if \(ret < 0\)\s*"
                     r"goto err_flow_add;\s*nft_flow_offload_check_unlisted\("
                     r"priv->flowtable, flow\);\s*return;", evaluate)
    assert evaluate.count("nft_flow_offload_check_unlisted(") == 1
    # Every nftables flowtable type has the op; nf_tables reaches the
    # flowtable only through it.
    for name in ("flowtable_inet", "flowtable_ipv4", "flowtable_ipv6"):
        assert re.search(r"\.listed\s*=\s*nf_flow_table_listed,",
                         _declaration(inet, f"static struct nf_flowtable_type {name} = {{"))
    assert not re.search(r"^\s*nf_flow_table_listed\(", api, re.M)
