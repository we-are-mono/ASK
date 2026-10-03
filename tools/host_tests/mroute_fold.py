"""`ip -s mroute` for an offloaded entry: the CPU's count plus the hardware's.

Run the adapter's own fold against an MFC entry that ipmr also counts into:
before the group reaches hardware, while a refusal keeps it in software, and
across a reinstall that starts a new hardware counter from zero.
"""

from ask_orch.process import run_process
import os
from pathlib import Path

from _host_qos_lifecycle import (function)

ROOT = Path(__file__).resolve().parents[2]


def test_mroute_fold(tmp_path):
    source = (ROOT / "cdx/ask_flowtable.c").read_text()
    start = source.index("enum ft_mr_state {")
    structs = source[source.index("struct ft_mr_vif {"):
                     source.index("static LIST_HEAD(ft_mr_groups)")]
    (tmp_path / "mroute_types.inc").write_text(
        source[start:source.index("};", start) + 3] + structs)
    (tmp_path / "mroute_fold.inc").write_text(
        function(source, "ft_mc_count_delta") + function(source, "ft_mr_fold")
        + function(source, "ft_mr_route_baseline"))
    binary = tmp_path / "fold"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
        "-I", str(tmp_path), str(Path(__file__).with_name("mroute_fold.c")),
        "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })


def test_a_fresh_hardware_group_folds_from_zero():
    """A hardware group's counters start at zero, and the worker is the one
    place that knows a group is new: it made it. A pointer comparison could
    not stand in -- the handle cdx_mc_group_del() frees is the next add's
    allocation often enough."""
    source = (ROOT / "cdx/ask_flowtable.c").read_text()
    work = function(source, "ft_mr_work_fn")
    add = work.index("cdx_mc_group_add(&plan.spec, &hw)")
    # The outcome is adopted by ft_mr_record(), inside the transaction the
    # fold takes too, so no fold sees the new entry against the old baseline.
    adopt = work.index("ft_mr_record(", add)
    assert work.index("added = true;", add) < adopt, "the add must be recorded as such"
    record = function(source, "ft_mr_record")
    assert "g->hw = hw;" in record
    assert "g->folded_packets = g->folded_bytes = 0;" in record, \
        "a group the worker has just added must be folded from zero"
    reset = record[record.index("g->folded_packets = g->folded_bytes = 0;"):]
    assert "g->fold_suspect = false;" in reset[:reset.index("}")], \
        "a doubt about the old baseline says nothing about the new one"


def test_both_learners_take_deltas_from_one_rule():
    """A sample below the baseline adds nothing; a second in a row moves the
    baseline there. The routed fold and the bridged refresh that feeds a
    route's count must agree, or the MFC's count depends on which learner
    carried the stream."""
    source = (ROOT / "cdx/ask_flowtable.c").read_text()
    assert "ft_mc_count_delta(&g->folded_packets, &g->folded_bytes," in function(source, "ft_mr_fold")
    assert "ft_mc_count_delta(&f->hw_packets, &f->hw_bytes," in function(source, "ft_mc_flow_counted")
    work = function(source, "ft_mc_work_fn")
    added = work[work.index("if (added) {"):]
    assert "target->count_suspect = false;" in added[:added.index("}")]
