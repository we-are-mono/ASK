"""Compile the production kernel handle, lookup and GC lifetime paths."""

from ask_orch.process import run_process
import os
from pathlib import Path
import re

from _host_qos_lifecycle import (function)
from _kernel_source import (kernel_source)


def test_lifecycle(tmp_path):
    kernel = kernel_source()
    source = (kernel / "net/netfilter/nf_flow_table_core.c").read_text()
    offload = (kernel / "net/netfilter/nf_flow_table_offload.c").read_text()
    header = (kernel / "include/net/netfilter/nf_flow_table.h").read_text()
    conntrack = (kernel / "include/net/netfilter/nf_conntrack.h").read_text()
    flags = re.search(r"^enum nf_flow_flags \{.*?^\};\n", header, re.M | re.S).group()
    # The flag queued work holds (NF_FLOW_HW_PENDING until 6.18 renamed it),
    # whether the collector leaves such a flow to that work, whether flows
    # close on a FIN or RST (NF_FLOW_CLOSING, 6.18), and whether
    # nf_ct_refresh() still takes the skb (dropped by 6.18).
    pending = re.search(r"if \(test_and_set_bit\((NF_FLOW_\w+), &flow->flags\)\)",
                        offload[offload.index("\nnf_flow_offload_work_alloc("):])
    assert pending, "the flag work_alloc claims"
    gc_step = function(source, "nf_flow_offload_gc_step")
    refresh = re.search(r"static inline void nf_ct_refresh\(([^)]*)\)", conntrack)
    assert refresh, "nf_ct_refresh"
    (tmp_path / "handle_types.inc").write_text(
        flags + f"#define FLOW_PENDING {pending[1]}\n"
        + ("#define GC_LEAVES_PENDING\n" if f"test_bit({pending[1]}, &flow->flags)" in gc_step else "")
        + ("#define HAVE_FLOW_CLOSING\n" if re.search(r"\bNF_FLOW_CLOSING,", flags) else "")
        + ("#define NF_CT_REFRESH_TAKES_SKB\n" if "const struct sk_buff *skb" in refresh[1] else ""))
    (tmp_path / "handle_production.inc").write_text(
        source[source.index("struct nf_flow_offload_handle {"):
               source.index("static void\nflow_offload_fill_dir")]
        + function(source, "flow_offload_free_rcu")
        + function(source, "flow_offload_free")
        + function(source, "flow_offload_add")
        + source[source.index("struct flow_offload_tuple_rhash *\nflow_offload_lookup"):
                 source.index("EXPORT_SYMBOL_GPL(flow_offload_lookup);")]
        # The collector judges expiry by the flowtable's clock, and applies
        # the driver's latest report first; a tree that applies it only
        # with the statistics has no helper for it.
        + function(header, "nf_flow_timeout_delta")
        + function(source, "nf_flow_has_expired")
        + (function(offload, "nf_flow_offload_refresh")
           if "nf_flow_offload_refresh(" in offload else "")
        + function(source, "nf_flow_offload_gc_step")
        + function(source, "nf_flow_table_gc_run")
        # A tree that predates the in-place free has no helper for it.
        + (function(source, "nf_flow_table_free_flow")
           if "nf_flow_table_free_flow(" in source else "")
        + function(source, "nf_flow_table_free")
        + function(offload, "nf_flow_offload_add"))
    binary = tmp_path / "flowtable_handle"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra",
        "-Werror", "-Wno-unused-parameter", "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
        "-I", str(tmp_path), str(Path(__file__).with_name("flowtable_handle.c")), "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
