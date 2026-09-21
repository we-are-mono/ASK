"""The routed multicast learner's decision logic and its locking discipline.

Two halves. The first compiles the contract -- every refusal, the oif walk and
what the FIB chain does to the group list -- against stubs, because a rig only
ever shows the one shape a routing daemon happens to write. The second reads
the source: the three ordering rules this learner lives under cannot be
observed from a passing test, only from code that never breaks them.
"""

import os
from pathlib import Path
import re
import subprocess

from test_qos_lifecycle import function

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "cdx/ask_flowtable.c"


def _between(source, start, end):
    return source[source.index(start):source.index(end)]


def test_mroute_learner(tmp_path):
    source = SOURCE.read_text()
    # The real state, not a restatement: a field added or resized on any of
    # these has to fail here rather than compile into a harness that no longer
    # matches what the adapter keeps.
    enum_start = source.index("enum ft_mr_state {")
    # The harness restates this one constant, so it must not drift.
    assert "#define FT_MR_OIF_TEXT\t\t(CDX_MC_MAX_LISTENERS * (IFNAMSIZ + 1))" \
        in source, "FT_MR_OIF_TEXT changed; mroute_learner.c repeats it"
    (tmp_path / "mroute_learner.inc").write_text(
        source[enum_start:source.index("};", enum_start) + 3]
        + _between(source, "struct ft_mr_vif {", "static LIST_HEAD(ft_mr_groups)")
        # The table the decision reads, declared between the struct it is an
        # array of and the functions that read it. The production definition
        # sits with the rest of the learner's state, which this harness owns.
        + "static struct ft_mr_vif ft_mr_vif[2][MAXVIFS];\n"
        + "\n".join(function(source, name) for name in [
            # Shared with the unicast path, and the routed oif walk is its
            # second caller -- so it is compiled here rather than stubbed.
            "ft_vlan_lower",
            "ft_bridge_vlan",
            "ft_mr_idx",
            "ft_mr_default_table",
            "ft_mr_state_text",
            "ft_mr_refusal",
            "ft_mr_specific",
            "ft_mr_scope_ok",
            "ft_mr_host_member",
            "ft_mr_ingress_port",
            "ft_mr_listener",
            "ft_mr_bridge_vid",
            "ft_mr_expand_bridge",
            "ft_mr_expand",
            "ft_mr_plan_put",
            "ft_mr_derive",
            "ft_mr_find",
            "ft_mr_dirty_family",
            "ft_mr_apply",
        ]))
    binary = tmp_path / "mroute_learner"
    subprocess.run([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
        "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("mroute_learner.c")), "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })


# ---------------------------------------------------------------- locking

def _held_regions(body, lock, unlock):
    """Offsets in `body` at which `lock` is held, as (start, end) pairs.

    Each acquisition runs to the next release after it, or to the end of the
    text when there is none. None of these locks is ever taken recursively, so
    that is exact; an early-return arm with a release of its own only makes the
    model wider than the truth, which is the safe direction for a test that
    asserts something is *not* inside.
    """
    releases = [m.start() for m in re.finditer(re.escape(unlock), body)]
    return [(m.start(), next((r for r in releases if r > m.start()), len(body)))
            for m in re.finditer(re.escape(lock), body)]


def _assert_not_inside(body, regions, needle, why):
    for m in re.finditer(re.escape(needle), body):
        for start, end in regions:
            assert not (start < m.start() < end), why


def test_the_fib_handler_only_queues():
    """The FIB chain is an atomic notifier chain and every mr_* caller asserts
    RTNL, so the handler runs in process context under RTNL and may not sleep
    or wait for the transaction. It holds what the worker will need, appends
    to a queue under a spinlock, and returns.
    """
    body = function(SOURCE.read_text(), "ft_mr_fib_event")
    for forbidden in ("cdx_ft_begin", "mutex_lock", "rtnl_lock",
                      "GFP_KERNEL", "cdx_mc_group_add", "cdx_mc_group_del",
                      "cdx_mc_group_replace", "cdx_mc_port_supported"):
        assert forbidden not in body, (
            f"{forbidden} cannot be reached from an atomic chain holding RTNL")
    assert "GFP_ATOMIC" in body, "the only allocation flag available here"
    assert "schedule_work(&ft_mr_work)" in body, "the worker does the rest"
    # And it holds what it queues, because by the time the worker runs the
    # entry may be deleted and the device unregistered.
    assert "mr_cache_hold" in body
    assert "dev_hold" in body


def test_the_worker_never_holds_a_lock_across_the_transaction():
    """/proc takes cdx_ft_begin() and then ft_mr_lock, so a worker that took
    the transaction while holding the lock would close a cycle with it. And
    cdx_ctrl_lock_with_rtnl() states the other one outright: never wait for
    RTNL or the control mutex while holding the other.
    """
    body = function(SOURCE.read_text(), "ft_mr_work_fn")
    assert "cdx_ft_begin();" in body, "the worker is where the hardware happens"
    for lock, unlock, why in (
        ("mutex_lock(&ft_mr_lock)", "mutex_unlock(&ft_mr_lock)",
         "ft_mr_lock must be released before the transaction is taken"),
        ("rtnl_lock()", "rtnl_unlock()",
         "RTNL must be released before the transaction is taken"),
    ):
        _assert_not_inside(body, _held_regions(body, lock, unlock),
                           "cdx_ft_begin()", why)


def test_the_two_learners_never_nest_their_locks():
    """One order, everywhere. The routed worker takes ft_mc_lock under RTNL
    with ft_mr_lock released, to copy a bridge's port set; the bridged side
    never reaches into the routed learner at all, it only kicks the worker.
    Nesting them in both directions is the deadlock this rules out.
    """
    source = SOURCE.read_text()
    regions = _held_regions(source, "mutex_lock(&ft_mc_lock)",
                            "mutex_unlock(&ft_mc_lock)")
    _assert_not_inside(source, regions, "mutex_lock(&ft_mr_lock)",
                       "ft_mr_lock must never be taken under ft_mc_lock")
    regions = _held_regions(source, "mutex_lock(&ft_mr_lock)",
                            "mutex_unlock(&ft_mr_lock)")
    _assert_not_inside(source, regions, "mutex_lock(&ft_mc_lock)",
                       "ft_mc_lock must never be taken under ft_mr_lock")
    # The bridged handler's only coupling to this learner.
    swdev = function(source, "ft_mc_swdev_obj")
    assert "ft_mr_kick()" in swdev, (
        "a membership change has to re-derive the routed groups that expand "
        "through that bridge")
    assert "ft_mr_lock" not in swdev


def test_the_derivation_touches_no_hardware_and_takes_no_rtnl():
    """It already holds RTNL, so taking it again would deadlock, and the
    transaction may not be taken under it at all. Everything it reads is
    netdev and bridge state.
    """
    body = function(SOURCE.read_text(), "ft_mr_derive")
    for forbidden in ("cdx_ft_begin", "rtnl_lock()", "ft_mr_offload_flag",
                      "mutex_lock(&ft_mr_lock)", "cdx_mc_group_add",
                      "cdx_mc_group_replace", "cdx_mc_group_del"):
        assert forbidden not in body, f"{forbidden} does not belong here"
    assert "ASSERT_RTNL();" in body, "the walk needs RTNL and should say so"


def test_the_contract_is_tested_in_the_order_it_is_written():
    """The backend refuses a link-local group and a wildcard source too, so
    without these tests up front /proc would report "refused-failed" four
    retries later and say nothing about why.
    """
    body = function(SOURCE.read_text(), "ft_mr_derive")
    order = [
        "FT_MR_REFUSED_TABLE",
        "FT_MR_REFUSED_POLICY",
        "FT_MR_REFUSED_WILDCARD",
        "FT_MR_REFUSED_SCOPE",
        "FT_MR_REFUSED_INGRESS",
        "FT_MR_REFUSED_HOST",
    ]
    at = [body.index(name) for name in order]
    assert at == sorted(at), f"the contract's order changed: {order}"
    # The thresholds and the listeners come last, because both walk the oif
    # list and the cheap tests have to be able to refuse before that.
    assert max(at) < body.index("FT_MR_REFUSED_THRESHOLD")


# ------------------------------------------------------------- references

def test_every_reference_the_learner_takes_is_released():
    """A group pins its ingress port and every listener for as long as the
    hardware entry names them -- the backend borrows exactly those pointers --
    and it holds the kernel's own cache entry for as long as it is keyed on
    it. One path releases all of them.
    """
    source = SOURCE.read_text()
    free = function(source, "ft_mr_group_free")
    assert "ft_mr_release_set(g)" in free
    assert "mr_cache_put(g->mfc)" in free
    release = function(source, "ft_mr_release_set")
    assert "dev_put(g->listener[i].dev)" in release
    assert "dev_put(g->in)" in release

    # mr_cache_put() can free the entry through RCU, so a flag written after
    # it is written into freed memory.
    assert free.index("ft_mr_offload_flag(g, false)") < \
        free.index("mr_cache_put(g->mfc)"), (
        "MFC_OFFLOAD must be cleared before the reference goes")

    # And nothing else frees a group, so there is one place to get it right.
    others = [n for n in ("ft_mr_apply", "ft_mr_work_fn", "ft_mr_exit")
              if "kfree(g)" in function(source, n)]
    assert not others, f"groups must be freed only by ft_mr_group_free: {others}"


def test_a_plan_is_adopted_whole_or_returned_whole():
    """The backend borrows the plan's device pointers, so a group that owned
    some of them would name one it did not. Either the group takes the lot or
    ft_mr_plan_put() gives the lot back.
    """
    source = SOURCE.read_text()
    put = function(source, "ft_mr_plan_put")
    assert "dev_put(plan->spec.listener[i].dev)" in put
    assert "dev_put(plan->spec.in)" in put
    assert "memset(plan, 0, sizeof(*plan))" in put, (
        "a returned plan must not be returned twice")
    worker = function(source, "ft_mr_work_fn")
    assert "ft_mr_plan_put(&plan);" in worker
    assert "memset(&plan, 0, sizeof(plan));" in worker, (
        "an adopted plan must be emptied before the unconditional put")


def test_the_learner_lets_go_of_a_device_that_went_away():
    """ipmr removes a VIF when its device unregisters, but not when the link
    merely goes down, and a reference still held when netdev_wait_allrefs()
    starts spinning is a device that never finishes unregistering.
    """
    source = SOURCE.read_text()
    netdev = function(source, "ft_netdev_event")
    assert netdev.count("ft_mr_device_gone(dev)") == 2, (
        "both the link going down and unregistration must reach the learner")
    gone = function(source, "ft_mr_device_gone")
    assert "ft_mr_release_set(g)" in gone, "released here, not by the worker"
    assert "g->in == dev" in gone, "as an ingress"
    assert "g->listener[i].dev == dev" in gone, "as a listener"
    # A port coming back has nothing else that would reconsider a group: the
    # MFC entry does not change and no frame re-offers it.
    assert "ft_mr_kick();" in netdev


def test_exit_drains_before_the_module_text_goes_away():
    """The worker and the delayed counter fold both hold pointers into this
    module. Unloading has to stop both and drain the groups, the queue and the
    VIF table, and it must do so after the FIB chain is unregistered so
    nothing can arrive while they drain.
    """
    source = SOURCE.read_text()
    exit_body = function(source, "ask_flowtable_exit")
    assert "ft_mr_exit();" in exit_body
    assert exit_body.index("unregister_fib_notifier") < \
        exit_body.index("ft_mr_exit();"), (
        "the chain must be gone before the groups drain")

    mr_exit = function(source, "ft_mr_exit")
    assert "WRITE_ONCE(ft_mr_stopping, true)" in mr_exit
    assert "cancel_work_sync(&ft_mr_work)" in mr_exit, (
        "the worker must be stopped, not merely asked to stop")
    assert "cancel_delayed_work_sync(&ft_mr_stats)" in mr_exit
    assert "ft_mr_group_free(g)" in mr_exit
    assert "dev_put(ft_mr_vif[idx][i].dev)" in mr_exit, (
        "the VIF table pins a device per entry")
    assert "mr_cache_put(ev->mfc)" in mr_exit, (
        "a queued event holds the cache entry it names")

    # A failed load has exactly the same debt, because registering the
    # notifier replays every VIF and MFC entry that already exists.
    init = function(source, "ask_flowtable_init")
    assert "ft_mr_exit();" in init


# ------------------------------------------------- the shared key register

def test_one_owner_per_hardware_key():
    """The classifier keeps one group id and one root entry per address pair,
    so the two learners share a namespace. Whoever takes the key installs;
    whoever cannot says so rather than spending a transaction to be told
    -EEXIST and then retrying three more times.
    """
    source = SOURCE.read_text()
    take = function(source, "ft_mc_claim_take")
    give = function(source, "ft_mc_claim_give")
    assert "-EEXIST" in take
    # Allocation before the lock, because the register is a leaf and taking it
    # must not be able to sleep.
    assert take.index("kzalloc") < take.index("spin_lock_bh(&ft_mc_claim_lock)")
    # Handing a key back stales the refusal it caused, and nothing else would
    # ever look again.
    assert "ft_mc_kick();" in give and "ft_mr_kick();" in give

    for worker, state in (("ft_mc_work_fn", "contested"),
                          ("ft_mr_work_fn", "FT_MR_REFUSED_CONTESTED")):
        body = function(source, worker)
        assert "ft_mc_claim_take(" in body, f"{worker} must take the key"
        assert "ft_mc_claim_give(" in body, f"{worker} must give it back"
        assert state in body, f"{worker} must report a contested key"
        # Taken before the transaction, so a contested key costs nothing.
        assert body.index("ft_mc_claim_take(") < body.rindex("cdx_ft_begin();")


def test_a_listener_is_its_whole_framing_not_its_port():
    """One port carries as many copies of a group as it has tag stacks, and
    the ingress is excluded on its framing rather than on its device.

    ft_parse() has applied that rule to a flow since the IPv6 increment --
    re-entering the ingress port is refused only when the two stacks match,
    because differing stacks are routing between VLANs on one link -- and the
    hardware enqueues back to the port a frame arrived on, measured as the
    hairpin double-NAT case. Multicast agreeing is the two paths saying the
    same thing.
    """
    source = SOURCE.read_text()
    body = function(source, "ft_mr_listener")
    assert "add.dev == ingress->dev && add.vlans == ingress->vlans" in body, (
        "the ingress test must compare the framing, not just the device")
    assert "port == ingress" not in body
    assert "out[i].vlans == add.vlans" in body, (
        "two copies on one port with different tags are two listeners")
    # And the ingress walk has to produce a stack for that comparison.
    walk = function(source, "ft_mr_ingress_port")
    assert "in->vlan[i] = inner[n - 1 - i]" in walk, (
        "outermost first, as a listener's are")


def test_the_counter_fold_restates_the_units():
    """The classifier counts the L2 frame it matched; ip_mr_forward() counts
    skb->len, which is the L3 packet. Folding one into the other without the
    correction would make `ip -s mroute` read high by the framing on every
    frame -- the same restatement ft_l2_overhead() makes for a flow.
    """
    body = function(SOURCE.read_text(), "ft_mr_fold")
    assert "ETH_HLEN + g->in_tags * VLAN_HLEN" in body
    assert "atomic_long_set(&g->mfc->mfc_un.res.pkt" in body
    assert "atomic_long_set(&g->mfc->mfc_un.res.bytes" in body
    assert "lastuse" in body, "ageing reads it and the CPU sees no packets"


def test_proc_reports_a_row_and_a_summary():
    """Statistics and state surface through standard tools, and /proc is the
    diagnostic beside them rather than the only door. Both have to be there:
    `ip mroute show` says offloaded, and this says why not.
    """
    source = SOURCE.read_text()
    show = function(source, "ft_show")
    assert "ft_mr_rows(seq);" in show
    for key in ("mroute_groups", "mroute_installed", "mroute_refused",
                "mroute_install_errors", "mroute_policy_rules"):
        assert key in show, f"{key} missing from the summary"
    rows = function(source, "ft_mr_rows")
    for field in ("family=", "table=", "group=", "src=", "in=", "oifs=",
                  "listeners=", "state=", "packets=", "bytes="):
        assert field in rows, f"{field} missing from the row"
    # A read is also a fold, so the two surfaces never disagree.
    assert "ft_mr_fold(g, &stats)" in rows
