"""Exercise native admission allocation failures and their non-fault exits."""
import os
from pathlib import Path
import subprocess

from test_flowtable import function

ROOT = Path(__file__).resolve().parents[2]


def test_native_admission_allocation_recovery(tmp_path):
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    source = (kernel / "net/netfilter/nf_flow_table_offload.c").read_text()
    core = (kernel / "net/netfilter/nf_flow_table_core.c").read_text()
    # Normalize only the declaration line break for the shared extractor.
    source = source.replace("static struct nf_flow_rule *\n", "static struct nf_flow_rule *")
    source = source.replace("static struct flow_offload_work *\n", "static struct flow_offload_work *")
    (tmp_path / "allocations_production.inc").write_text(
        function(core, "nf_flow_offload_handle_invalidate")
        + function(source[source.index("static struct nf_flow_rule *nf_flow_offload_rule_alloc"):],
                   "nf_flow_offload_rule_alloc")
        + function(source[source.index("static struct flow_offload_work *nf_flow_offload_work_alloc"):],
                   "nf_flow_offload_work_alloc"))
    binary = tmp_path / "flowtable_allocations"
    subprocess.run([os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra",
                    "-Werror", "-Wno-unused-parameter", "-fsanitize=address,undefined",
                    "-fno-pie", "-no-pie", "-I", str(tmp_path),
                    str(Path(__file__).with_name("flowtable_allocations.c")), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=10, env={**os.environ,
                   "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1", "UBSAN_OPTIONS": "halt_on_error=1"})
