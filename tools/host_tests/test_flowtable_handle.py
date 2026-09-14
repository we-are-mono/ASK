"""Compile the production kernel handle, lookup and GC lifetime paths."""
import os
from pathlib import Path
import subprocess

from test_qos_lifecycle import function

ROOT = Path(__file__).resolve().parents[2]


def test_flowtable_handle_lifecycle(tmp_path):
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    source = (kernel / "net/netfilter/nf_flow_table_core.c").read_text()
    (tmp_path / "handle_production.inc").write_text(
        source[source.index("struct nf_flow_offload_handle {"):
               source.index("static void\nflow_offload_fill_dir")]
        + function(source, "flow_offload_free")
        + function(source, "flow_offload_add")
        + source[source.index("struct flow_offload_tuple_rhash *\nflow_offload_lookup"):
                 source.index("EXPORT_SYMBOL_GPL(flow_offload_lookup);")]
        + function(source, "nf_flow_offload_gc_step"))
    binary = tmp_path / "flowtable_handle"
    subprocess.run([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra",
        "-Werror", "-Wno-unused-parameter", "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
        "-I", str(tmp_path), str(Path(__file__).with_name("flowtable_handle.c")), "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
