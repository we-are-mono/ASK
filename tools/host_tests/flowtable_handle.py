"""Compile the production kernel handle, lookup and GC lifetime paths."""

from ask_orch.process import run_process
import os
from pathlib import Path

from _host_qos_lifecycle import (function)
from _kernel_source import (kernel_source)


def test_lifecycle(tmp_path):
    kernel = kernel_source()
    source = (kernel / "net/netfilter/nf_flow_table_core.c").read_text()
    offload = (kernel / "net/netfilter/nf_flow_table_offload.c").read_text()
    (tmp_path / "handle_production.inc").write_text(
        source[source.index("struct nf_flow_offload_handle {"):
               source.index("static void\nflow_offload_fill_dir")]
        + function(source, "flow_offload_free_rcu")
        + function(source, "flow_offload_free")
        + function(source, "flow_offload_add")
        + source[source.index("struct flow_offload_tuple_rhash *\nflow_offload_lookup"):
                 source.index("EXPORT_SYMBOL_GPL(flow_offload_lookup);")]
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
