"""Run the routed learner's tc admission helpers against modelled devices.

A group is kept in software while tc runs anything in software where its
stream arrives or where a copy leaves, on the VIF devices and every device
below them: filters in a clsact block, on any class of an egress qdisc tree,
tcx BPF programs, and XDP on the way in. A block whose filters all skip
software, and a filter the hardware applies as it is, count for nothing. The
helpers are the adapter's own, extracted as written, and every chain and
classifier reference the iterators hand out has to be back by the end.
"""

import os
import re
from pathlib import Path

from _host_flowtable import flowtable_source
from _host_policer import after_includes
from _host_qos_lifecycle import function
from ask_orch.process import run_process

ROOT = Path(__file__).resolve().parents[2]

HELPERS = [
    "ft_tc_filter", "ft_tc_block_soft", "ft_tc_class", "ft_qdisc_soft",
    "ft_qdisc_schedules", "ft_qdisc_tree_soft", "ft_tc_xgress_block",
    "ft_dev_tc_soft_for", "ft_dev_tc_soft", "ft_dev_tc_soft_routed", "ft_tc_lower",
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
    # The kinds of routed direction the policer answers for, as defined.
    police = re.findall(r"^#define CDX_POLICE_\w+\s.*$",
                        (ROOT / "cdx/cdx_police.h").read_text(), re.MULTILINE)
    assert len(police) == 2, police
    (tmp_path / "mroute_tc.inc").write_text("\n".join(police) + "\n" + section)
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


def test_tc_is_never_asked_inside_the_transaction():
    """A step of a filter block's walk can put the last reference to a
    classifier a concurrent delete unlinked, and its destroy can drain the
    port's egress, which takes the backend transaction. So the walk asserts
    it is outside it, and what decides inside it -- routed admission and its
    rechecks, the bridged learner -- reads the sample a worker takes under
    RTNL, which walks tc under none of the transaction, ft_watch_lock,
    ft_mc_lock or any learner's lock."""
    source = flowtable_source()
    walk = function(source, "ft_dev_tc_soft_for")
    assert walk.index("cdx_ft_assert_not_held();") < walk.index("rtnl_dereference(")
    for name in ("ft_dev_tc_soft", "ft_dev_tc_soft_routed"):
        assert "return ft_dev_tc_soft_for(dev, " in function(source, name), name
    asks = ("ft_dev_tc_soft(", "ft_dev_stack_tc_soft(", "ft_dev_tc_soft_routed(")
    for name in ("ft_l2_resolve", "ft_l2_admit", "ft_l2_current", "ft_parse",
                 "ft_entry_bounded", "ft_rule_callback", "ft_rule_tc_soft",
                 "ft_tc_offer_refused"):
        body = function(source, name)
        for ask in asks:
            assert ask not in body, (name, ask)
    resolve = function(source, "ft_l2_resolve")
    assert "ft_l2_tc_soft(in, p->rule.in_vlan, p->rule.in_vlans, lower_in, FT_TC_RX)" in resolve
    assert "ft_l2_tc_soft(out, p->rule.out_vlan, p->rule.out_vlans, lower_out, FT_TC_TX)" in resolve
    # The worker walks tc under RTNL with no lock of the adapter's held: not
    # the transaction, ft_watch_lock, ft_mc_lock or any learner's lock. It
    # takes none itself there, and of what it calls there only the bridged
    # learner takes one -- ft_l2_lock, a leaf spinlock, let go before the
    # call returns, between one device's walk and the next -- and walks no
    # tc under it. A call added there has to be looked at for the same.
    # flowtable_tc_sample.c checks the same as the worker runs.
    worker = function(source, "ft_tc_workfn")
    asked = worker[worker.index("rtnl_lock();"):worker.rindex("rtnl_unlock();")]
    assert "ft_tc_ask(dev)" in asked and "rcu_assign_pointer(ft_tc_sample, new);" in asked
    locks = ("cdx_ft_begin", "cdx_ft_admission_begin", "spin_lock", "mutex_lock", "rtnl_lock")
    for lock in locks:
        assert lock not in asked.removeprefix("rtnl_lock();"), lock
    called = set(re.findall(r"\b(ft_\w+)\(", asked))
    reviewed = {"ft_tc_ask", "ft_tc_was", "ft_tc_report", "ft_l2_dev_changed"}
    assert called <= reviewed, called - reviewed
    for name in ("ft_tc_ask", "ft_tc_was", "ft_tc_report"):
        body = function(source, name)
        for lock in locks:
            assert lock not in body, (name, lock)
    for name in ("ft_l2_dev_changed", "ft_l2_mark", "ft_l2_names_dev", "ft_l2_refusals_clear"):
        body = function(source, name)
        for ask in asks:
            assert ask not in body, (name, ask)
        assert body.count("spin_lock_bh(&ft_l2_lock);") == \
            body.count("spin_unlock_bh(&ft_l2_lock);"), name
        assert "cdx_ft_begin" not in body and "mutex_lock" not in body, name
    assert "ft_l2_mark(ft_l2_names_dev, dev);" in function(source, "ft_l2_dev_changed")
    # It publishes before it retires anything by the new answer, or asks a
    # refusal again by it.
    assert worker.index("rcu_assign_pointer(") < worker.index("ft_tc_retire();")
    assert worker.index("rcu_assign_pointer(") < worker.index("ft_l2_refusals_reset();")
    assert "cdx_ft_begin" not in function(source, "ft_tc_retire")


def test_tc_sample_worker(tmp_path):
    """The worker that samples tc for the decisions taken inside the
    transaction, compiled from the adapter's source over stub devices: what it
    publishes and forgets, which installed directions a tighter answer
    retires, and what it tells the bridged learner -- a tighter answer
    retires every pair through the device, a looser one retires none and asks
    the refusals again, and one only routed directions meet does neither."""
    header = (ROOT / "cdx/ask_flowtable_internal.h").read_text()
    bits = re.findall(r"^#define FT_TC_(?:TX|RX\w*)\s.*$", header, re.MULTILINE)
    assert len(bits) == 4, bits
    police = re.findall(r"^#define CDX_POLICE_\w+\s.*$",
                        (ROOT / "cdx/cdx_police.h").read_text(), re.MULTILINE)
    assert len(police) == 2, police
    (tmp_path / "tc_sample_bits.inc").write_text("\n".join(bits + police) + "\n")
    (tmp_path / "tc_sample.inc").write_text(
        after_includes((ROOT / "cdx/ask_flowtable_tc.c").read_text()))
    binary = tmp_path / "tc_sample"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
        "-I", str(tmp_path), str(Path(__file__).with_name("flowtable_tc_sample.c")),
        "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
