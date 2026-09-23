"""`ip -s mroute` for an offloaded entry: the CPU's count plus the hardware's.

Run the adapter's own fold against an MFC entry that ipmr also counts into:
before the group reaches hardware, while a refusal keeps it in software, and
across a reinstall that starts a new hardware counter from zero.
"""
import os
from pathlib import Path
import subprocess

from test_qos_lifecycle import function

ROOT = Path(__file__).resolve().parents[2]


def test_mroute_fold(tmp_path):
    source = (ROOT / "cdx/ask_flowtable.c").read_text()
    start = source.index("enum ft_mr_state {")
    structs = source[source.index("struct ft_mr_vif {"):
                     source.index("static LIST_HEAD(ft_mr_groups)")]
    (tmp_path / "mroute_types.inc").write_text(
        source[start:source.index("};", start) + 3] + structs)
    (tmp_path / "mroute_fold.inc").write_text(function(source, "ft_mr_fold"))
    binary = tmp_path / "fold"
    subprocess.run([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
        "-I", str(tmp_path), str(Path(__file__).with_name("mroute_fold.c")),
        "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True, timeout=30, env={
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
    adopt = work.index("target->hw = hw;")
    assert work.index("added = true;", add) < adopt, "the add must be recorded as such"
    assert "target->folded_packets = target->folded_bytes = 0;" in work[adopt:], \
        "a group the worker has just added must be folded from zero"
