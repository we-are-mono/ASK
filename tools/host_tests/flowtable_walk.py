"""Compile the flowtable's walk, nf_flow_table_walk(), against a model of the
rhashtable walker, and check what holding softirqs off across a batch and
sleeping between batches must keep."""

import os
import re
from pathlib import Path

from ask_orch.process import run_process
from _host_qos_lifecycle import function
from _kernel_source import kernel_source


def test_walk_batches_softirqs_and_resumes_where_it_slept(tmp_path):
    """A walk is one RCU read-side section, which this kernel cannot preempt,
    and softirqs raised during it ran inside it: under receive load a GC pass
    retiring thousands of flows held its CPU for up to 23 s. The walk holds
    softirqs off across a batch of flows and lets them run between batches;
    a sweep beside the GC never sleeps, while the GC and the table's release
    sleep at a batch's end when the CPU is wanted, before a flow they have
    not handled, and find that flow again by address on waking -- removing
    what they handle, with flows added or a failed add's reply direction
    taken out meanwhile, they handle each flow once. Had the flow stopped
    before gone, the walk resumes at the next; had one ahead of it gone too,
    it would skip one, which is why a walk that the GC removes flows beside
    does not sleep. A resize, or a rehash met at the table's end, restarts
    it."""
    core = (kernel_source() / "net/netfilter/nf_flow_table_core.c").read_text()
    (tmp_path / "walk_production.inc").write_text(
        re.search(r"^#define NF_FLOW_TABLE_WALK_BATCH\b.*\n", core, re.M).group()
        + function(core, "nf_flow_table_walk"))
    binary = tmp_path / "flowtable_walk"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra",
        "-Werror", "-Wno-unused-parameter", "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("flowtable_walk.c")), "-o", str(binary),
    ], check=True)
    result = run_process([str(binary)], check=True, timeout=30, capture_output=True, text=True, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
    assert "flowtable walk checks passed" in result.stdout, result.stdout + result.stderr

    # Who sleeps: the periodic GC and the table's release, which nothing
    # removes flows beside; the sweeps beside the GC go through
    # nf_flow_table_iterate(), whose prototype trees that export it keep.
    assert re.search(r"\{\s*nf_flow_table_walk\(flow_table, nf_flow_offload_gc_step, NULL, true\);\s*\}",
                     function(core, "nf_flow_table_gc_run"))
    assert "nf_flow_table_gc_run(flow_table);" in function(core, "nf_flow_offload_work_gc")
    assert re.search(r"\{\s*return nf_flow_table_walk\(flow_table, iter, data, false\);\s*\}",
                     function(core, "nf_flow_table_iterate"))
    release = function(core, "nf_flow_table_free")
    assert release.count("nf_flow_table_walk(") == 2 and release.count(", NULL, true);") == 2
    assert "nf_flow_table_iterate(" not in release
    # nf_flow_table_gc_run() runs from the GC's work, the table's release and
    # the release's flush (nf_flow_table_offload_flush_cleanup()), only: no
    # other module can reach it.
    offload = (kernel_source() / "net/netfilter/nf_flow_table_offload.c").read_text()
    assert offload.count("nf_flow_table_gc_run(") == 1
    assert "nf_flow_table_gc_run(" in function(offload, "nf_flow_table_offload_flush_cleanup")
    assert core.count("nf_flow_table_gc_run(") == 3  # its definition, the work, the release
    assert "EXPORT_SYMBOL_GPL(nf_flow_table_gc_run)" not in core
    for sweep in ("nf_flow_table_gc_cleanup", "nf_flow_table_listed"):
        body = function(core, sweep)
        assert "nf_flow_table_iterate(" in body and "nf_flow_table_walk(" not in body
