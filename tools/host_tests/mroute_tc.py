"""Run the routed learner's tc admission helpers against modelled devices.

A group is kept in software while tc runs anything in software where its
stream arrives or where a copy leaves, on the VIF devices and every device
below them: filters in a clsact block, on any class of an egress qdisc tree,
tcx BPF programs, and XDP on the way in. A block whose filters all skip
software, and a filter the hardware applies as it is, count for nothing. The
helpers are the adapter's own, extracted as written, and every chain and
classifier reference the iterators hand out has to be back by the end.
"""

from ask_orch.process import run_process
import os
from pathlib import Path

from _host_flowtable import (flowtable_source)
from _host_qos_lifecycle import (function)

ROOT = Path(__file__).resolve().parents[2]

HELPERS = [
    "ft_tc_filter", "ft_tc_block_soft", "ft_tc_class", "ft_qdisc_soft",
    "ft_qdisc_tree_soft", "ft_tc_xgress_block", "ft_dev_tc_soft", "ft_tc_lower",
    "ft_dev_stack_tc_soft",
    "ft_mr_tc_filtered",
]


def test_mroute_tc(tmp_path):
    source = flowtable_source()
    # The whole section, configuration guards and all, from the first walker
    # type to the predicate the admission asks: the guards are part of what
    # is tested, and nothing between them is left out.
    start = source.index("struct ft_tc_filters {")
    last = function(source, "ft_mr_tc_filtered")
    section = source[start:source.index(last) + len(last)]
    for name in HELPERS:
        function(section, name)
    for walker in ("struct ft_tc_filters {", "struct ft_tc_classes {",
                   "struct ft_tc_lowers {"):
        assert walker in section, walker
    (tmp_path / "mroute_tc.inc").write_text(section)
    binary = tmp_path / "tc"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
        "-I", str(tmp_path), str(Path(__file__).with_name("mroute_tc.c")),
        "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
