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

from test_pppoe_hm import declaration
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
    header = (ROOT / "cdx/cdx_mcast_backend.h").read_text()
    (tmp_path / "mroute_learner.inc").write_text(
        declaration(header, "cdx_mc_listener")
        + declaration(header, "cdx_mc_group_spec")
        + source[enum_start:source.index("};", enum_start) + 3]
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
            # Both learners' MTU bound, shared with the bridged one.
            "ft_mc_link_mtu",
            "ft_mr_idx",
            "ft_mr_default_table",
            "ft_mr_state_text",
            "ft_mr_refusal",
            "ft_mr_specific",
            "ft_mr_scope_ok",
            "ft_mr_host_member",
            "ft_mr_ingress_port",
            "ft_mr_ingress_bridge",
            "ft_mr_listener",
            "ft_mr_bridge_vid",
            "ft_mr_expand_bridge",
            "ft_mr_expand",
            "ft_mr_plan_put",
            "ft_mr_vif_dev",
            "ft_mr_derive",
            "ft_mr_plan_same",
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
    source = SOURCE.read_text()
    body = function(source, "ft_mr_fib_event") + function(source, "ft_mr_event_alloc")
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
    RTNL or the control mutex while holding the other. The worker waits for
    RTNL, so it never holds the transaction then; the one caller that takes
    the transaction under RTNL is the drain, below.
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


def test_the_drain_takes_the_transaction_under_its_callers_rtnl_only():
    """The drain runs under the RTNL a tc command holds and takes the
    transaction there, the order the bind path already takes; it takes no
    RTNL of its own, never waits for the worker, and takes ft_mr_lock only
    inside the transaction. The worker, for its part, keeps the group's
    hardware until it is inside its own transaction and records before it
    leaves, so the drain never meets a group it cannot rebuild -- a group
    going over to a bridge's copies included, whose entry of its own is
    recorded gone before the transaction is let go.
    """
    source = SOURCE.read_text()
    drain = function(source, "ft_mr_egress_drain")
    for forbidden in ("rtnl_lock()", "flush_work", "cancel_work", "busy"):
        assert forbidden not in drain, forbidden
    assert drain.index("cdx_ft_begin();") < drain.index("mutex_lock(&ft_mr_lock)")
    assert drain.index("mutex_unlock(&ft_mr_lock)") < drain.index("cdx_ft_end();")
    # The installed spec, whole, as it was built: never one made up here
    # from the group's fields, which would leave the ingress tags out.
    assert "cdx_mc_group_replace(g->hw, &g->hw_spec)" in drain
    assert "memset(&spec" not in drain
    worker = function(source, "ft_mr_work_fn")
    taken = worker.index("hw = target->hw;")
    begin = worker.rindex("cdx_ft_begin();", 0, taken)
    end = worker.index("cdx_ft_end();", taken)
    assert begin < taken < worker.index("ft_mr_record(", taken) < end
    assert "cdx_ft_end();" not in worker[begin:taken]
    # Every place the worker takes the entry away from the group is inside
    # that transaction.
    at = worker.find("target->hw = NULL")
    while at != -1:
        assert begin < at < end, "the group's hardware stays the group's until the transaction"
        at = worker.find("target->hw = NULL", at + 1)
    record = function(source, "ft_mr_record")
    assert "g->hw_spec = plan->spec;" in record
    # The recorded spec borrows the listeners, so it goes with them: with the
    # copies half, which releasing the whole set releases too.
    assert "memset(&g->hw_spec, 0, sizeof(g->hw_spec));" in function(source, "ft_mr_release_copies")
    assert "ft_mr_release_copies(g);" in function(source, "ft_mr_release_set")


def test_the_two_learners_never_nest_their_locks():
    """One order, everywhere. The routed worker reads the kernel snapshot
    with ft_mr_lock released; the bridged side never reaches into the routed
    learner at all, it only kicks the worker.
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


def test_the_mtu_bound_is_rechecked_without_an_mfc_event():
    """Neither a device MTU change nor the IPv6 MTU sysctl touches the MFC, so
    the bound a group was admitted under would otherwise hold for its life.
    The device change kicks the worker; the sysctl, which no event reports, is
    found by the periodic refresh re-deriving every group, installed ones
    included, exactly as the unicast IPv6 bound is found by the stats pass.
    """
    source = SOURCE.read_text()
    derive = function(source, "ft_mr_derive")
    assert "return FT_MR_REFUSED_MTU;" in derive
    assert "ft_mc_link_mtu(vif_dev, g->family)" in derive
    # After the listeners, because only they say how narrow the copies are.
    assert derive.index("FT_MR_REFUSED_MTU") > derive.rindex("FT_MR_REFUSED_LISTENER")
    refresh = function(source, "ft_mr_stats_fn")
    assert "g->dirty = true;" in refresh
    link = function(source, "ft_mc_link_mtu")
    assert "idev->cnf.mtu6" in link, "IPv6 is bounded in its own units"


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
    # The listeners through the copies half, which a listener's own device
    # going releases on its own; the ingress here.
    assert "ft_mr_release_copies(g);" in release
    assert "dev_put(g->listener[i].dev)" in function(source, "ft_mr_release_copies")
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
    # The worker records through ft_mr_record(), which adopts the plan.
    assert worker.count("ft_mr_record(") == 2
    record = function(source, "ft_mr_record")
    assert "memset(plan, 0, sizeof(*plan));" in record, (
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
    # A listener's device only its copies: the ingress is still the key the
    # entry is swapped under.
    assert "ft_mr_release_copies(g)" in gone
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


# ------------------------------------------------- the learners' streams

def test_the_learners_share_streams_not_keys():
    """A routed root's port is never a bridge port and a bridged root's always
    is, in tables of their own, so neither learner can take a key from the
    other and there is no register between them. What they share is a stream
    that arrives on a bridge port and is also routed: the routed learner
    publishes its copies to the bridged group carrying it instead of
    installing a root of its own.
    """
    source = SOURCE.read_text()
    assert "ft_mc_claim" not in source, "the address-pair register is gone"
    worker = function(source, "ft_mr_work_fn")
    # A parent on a bridge installs nothing: its copies are published, and
    # anything else takes back what it once published.
    assert "ft_mr_publish(target, &plan)" in worker
    assert "ft_mc_route_withdraw(target->route)" in worker
    assert "(installed || (state == FT_MR_PENDING && !via))" in worker, (
        "a group routed through a bridge must never reach cdx_mc_group_add")
    # Each learner keeps its own collisions: two MFC entries on one port with
    # different tags are one key whose root validates one stack. Asked before
    # the transaction, so a contested key costs nothing.
    assert "ft_mr_key_taken(target, &plan.spec)" in worker
    assert worker.index("ft_mr_key_taken(") < worker.rindex("cdx_ft_begin();")
    assert "FT_MR_REFUSED_CONTESTED" in worker
    taken = function(source, "ft_mr_key_taken")
    assert "o->in == spec->in" in taken and "o->hw" in taken
    # And a key given up is offered again in the same pass.
    assert worker.count("ft_mr_key_freed = true;") >= 2
    assert "g->state == FT_MR_REFUSED_CONTESTED" in worker


def test_the_routed_learner_reaches_the_bridged_one_only_through_its_door():
    """Publishing takes ft_mc_lock, so it happens with ft_mr_lock released,
    and freeing a group's route happens only after it is off the bridged
    learner's list, which is what clears every pointer to it there.
    """
    source = SOURCE.read_text()
    publish = function(source, "ft_mr_publish")
    unlock = publish.index("mutex_unlock(&ft_mr_lock);")
    assert unlock < publish.index("ft_mc_route_publish(")
    taps = function(source, "ft_mr_publish_taps")
    assert taps.index("mutex_unlock(&ft_mr_lock);") < taps.index("ft_mc_taps_publish(")
    free = function(source, "ft_mr_group_free")
    assert free.index("ft_mc_route_withdraw(g->route)") < free.index("kfree(g->route)")
    for name in ("ft_mc_route_publish", "ft_mc_route_withdraw", "ft_mc_taps_publish"):
        body = function(source, name)
        assert "mutex_lock(&ft_mc_lock)" in body and "ft_mr_lock" not in body
    # What the bridged learner reports back is read under a leaf, so the
    # routed learner may read it holding its own lock.
    state = function(source, "ft_mc_route_state")
    assert "spin_lock_bh(&ft_mc_route_lock)" in state and "mutex_lock" not in state


def test_the_taps_say_so_whenever_they_cannot_be_trusted():
    """A group a VIF receives is carried only with its route, and the taps are
    how the bridged learner knows a VIF receives it. Wherever this learner
    cannot say where its VIFs are -- a mirror a lost event invalidated, a
    policy rule that can send a stream to a table it does not mirror, before
    its first word -- the taps say they may be anywhere. And a bridge that
    went down, whose taps the bridged learner dropped, is published again.
    """
    source = SOURCE.read_text()
    taps = function(source, "ft_mr_publish_taps")
    assert "ft_mr_resync_pending" in taps
    assert "ft_mr_policy[0] || ft_mr_policy[1]" in taps
    assert "static bool ft_mc_taps_overflow = true;" in source
    apply = function(source, "ft_mr_apply")
    rules = apply[apply.index("case FIB_EVENT_RULE_ADD:"):apply.index("case FIB_EVENT_VIF_ADD:")]
    assert "ft_mr_taps_stale = true;" in rules
    gone = function(source, "ft_mr_device_gone")
    assert "netif_is_bridge_master(dev)" in gone and "ft_mr_taps_stale = true;" in gone


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
    source = SOURCE.read_text()
    body = function(source, "ft_mr_fold")
    assert "ETH_HLEN + tags * VLAN_HLEN" in body
    # Added to what ipmr counted itself, never written over it: see
    # test_mroute_fold.py for what setting did to the count.
    assert "atomic_long_add(packets, &g->mfc->mfc_un.res.pkt" in body
    assert "atomic_long_add(bytes, &g->mfc->mfc_un.res.bytes" in body
    assert "atomic_long_set" not in body
    assert "lastuse" in body, "ageing reads it and the CPU sees no packets"
    # The framing is the entry's own ingress tags, or, for a group routed
    # through a bridge, what the bridged group carrying it reports: a daemon
    # ageing its routes by SIOCGETSGCNT must see a merged stream flow.
    counters = function(source, "ft_mr_counters")
    assert "*tags = g->in_tags;" in counters
    assert "ft_mc_route_state(g->route, c, tags)" in counters
    for caller in ("ft_mr_stats_fn", "ft_mr_rows"):
        assert "if (ft_mr_counters(g, &stats, &tags))" in function(source, caller)


def test_proc_reports_a_row_and_a_summary():
    """Statistics and state surface through standard tools, and /proc is the
    diagnostic beside them rather than the only door. Both have to be there:
    `ip mroute show` says offloaded, and this says why not.
    """
    source = SOURCE.read_text()
    show = function(source, "ft_show")
    assert "ft_mr_rows(seq);" in show
    for key in ("mroute_groups", "mroute_installed", "mroute_refused",
                "mroute_install_errors", "mroute_policy_rules",
                "mroute_ruleset_changes", "mroute_ruleset_settled",
                "mroute_confirm_errors"):
        assert key in show, f"{key} missing from the summary"
    rows = function(source, "ft_mr_rows")
    for field in ("family=", "table=", "group=", "src=", "in=", "oifs=",
                  "listeners=", "state=", "unconfirmed=", "packets=", "bytes="):
        assert field in rows, f"{field} missing from the row"
    # Every unseen oif is named, however many VIFs there are: written name
    # by name, never through a buffer that could cut the list short.
    assert "ft_mr_unconfirmed(seq, g);" in rows
    assert "scnprintf" not in function(source, "ft_mr_unconfirmed")
    # A read is also a fold, so the two surfaces never disagree.
    assert "ft_mr_fold(g, &stats, tags)" in rows


# ------------------------------------------------ what Linux itself forwarded

def test_a_group_is_carried_only_where_linux_forwards_it():
    """The MFC says where ipmr sends a stream, not whether the firewall lets
    it go, and a hardware entry replicates where no hook runs again. So a
    copy has to be seen leaving each oif at POST_ROUTING, after every filter
    and NAT hook, before the group is carried. What every packet pays at that
    hook is the multicast test; a forwarded copy of a group, one lookup.
    """
    source = SOURCE.read_text()
    hook = function(source, "ft_mr_confirm_hook")
    for family, test, mark in (
            ("AF_INET", "ipv4_is_multicast(iph->daddr)",
             "IPCB(skb)->flags & IPSKB_FORWARDED"),
            ("AF_INET6", "ipv6_addr_is_multicast(&ip6h->daddr)",
             "IP6CB(skb)->flags & IP6SKB_FORWARDED")):
        call = hook.index(f"ft_mr_confirm_seen({family},")
        assert hook.index(test) < hook.index(mark) < call
        # Where the copy came from: the device ipmr saw it arrive on.
        assert hook.index("skb->skb_iif", call) < hook.index(";", call)
    assert "state->out->ifindex" in hook
    assert hook.count("return NF_ACCEPT;") == 4 and "NF_DROP" not in hook
    ops = source[source.index("static struct nf_hook_ops ft_mr_confirm_ops[2]"):]
    ops = ops[:ops.index("};\n")]
    assert ops.count(".hooknum = NF_INET_POST_ROUTING") == 2
    assert ".priority = NF_IP_PRI_LAST" in ops and ".priority = NF_IP6_PRI_LAST" in ops

    # Confirmations are good for one ruleset: nftables' commit counter and
    # the cursor the rules are read through; and for one parent, which a
    # copy from any other confirms nothing for.
    read = function(source, "ft_mr_ruleset_read")
    assert "smp_load_acquire(&init_net.nft.base_seq)" in read
    assert "READ_ONCE(init_net.nft.gencursor)" in read
    seen = function(source, "ft_mr_confirm_seen")
    assert seen.index("READ_ONCE(ft_mr_gen_open)") < seen.index("ft_mr_ruleset_current()") < \
        seen.index("w->parent != iif") < seen.index("test_and_set_bit(i, &w->seen)")
    arm = function(source, "ft_mr_watch_arm")
    assert "old->parent == plan->parent" in arm and "w->parent = plan->parent;" in arm
    assert "old->parent == w->parent ? READ_ONCE(old->seen) : 0" in arm
    # Re-arming closes, waits out every copy in hand, clears, reads the
    # ruleset and starts timing it. Opening waits for it to have stood still
    # and for the commit behind it to be applied whole, waits out every copy
    # judged before that, and opens only if it still stands.
    sync = function(source, "ft_mr_ruleset_sync")
    close = sync[sync.index("WRITE_ONCE(ft_mr_gen_open, false);"):]
    steps = ["WRITE_ONCE(ft_mr_gen_open, false);", "synchronize_rcu();",
             "WRITE_ONCE(w->seen, 0);", "ft_mr_ruleset_read(&seq, &cursor);",
             "ft_mr_gen_since = jiffies;"]
    at = [close.index(s) for s in steps]
    assert at == sorted(at) and "WRITE_ONCE(ft_mr_gen_open, true);" not in close
    opening = sync[:sync.index("WRITE_ONCE(ft_mr_gen_open, false);")]
    steps = ["ft_mr_gen_armed && ft_mr_ruleset_current()",
             "time_before(jiffies, ft_mr_gen_since + FT_MR_RULESET_SETTLE)",
             "if (ft_mr_ruleset_applying())", "synchronize_rcu();",
             "if (ft_mr_ruleset_current())", "WRITE_ONCE(ft_mr_gen_open, true);"]
    at = [opening.index(s) for s in steps]
    assert at == sorted(at)
    # The commit's mark is the kernel's own reader, next to the pair in
    # struct net: no symbol from nf_tables, and read after the pair.
    assert "nft_commit_in_progress(&init_net)" in function(source, "ft_mr_ruleset_applying")

    # The worker follows the ruleset first, watches a group once its oifs
    # are known, and decides its state from the confirmations before it
    # decides whether the chain it has is the same.
    worker = function(source, "ft_mr_work_fn")
    assert "ft_mr_ruleset_sync()" in worker
    assert worker.index("ft_mr_derive(target, &plan)") < \
        worker.index("ft_mr_watch_arm(target, &plan)") < \
        worker.index("state = ft_mr_admit(target, &plan)") < worker.index("same = installed &&")
    admit = function(source, "ft_mr_admit")
    assert "ft_bridge_hooked(BIT(NF_BR_LOCAL_OUT) | BIT(NF_BR_POST_ROUTING))" in admit
    assert "if (ft_mr_observer_followed(g->family))" in admit
    assert "return FT_MR_UNCONFIRMED;" in admit and "ft_mr_watch_complete(g->watch)" in admit
    # A ruleset commit is looked for while any group exists, and a settling
    # ruleset when it will have settled.
    assert "schedule_delayed_work(&ft_mr_ruleset,\n\t\t\t\t\t      FT_MR_RULESET_INTERVAL)" in worker
    assert "mod_delayed_work(system_wq, &ft_mr_ruleset,\n\t\t\t\t\t ft_mr_ruleset_wait())" in worker
    poll = function(source, "ft_mr_ruleset_fn")
    assert "!READ_ONCE(ft_mr_gen_open)" in poll and "schedule_work(&ft_mr_work)" in poll

    # The watch goes with its group, and teardown takes the hook down before
    # the worker and the table go, and again after anything the worker did.
    assert "ft_mr_watch_drop(g);" in function(source, "ft_mr_group_free")
    exit_body = function(source, "ft_mr_exit")
    assert exit_body.index("ft_mr_confirm_sync();") < exit_body.index("cancel_work_sync(&ft_mr_work)") < \
        exit_body.rindex("ft_mr_confirm_sync();")
    assert exit_body.count("cancel_delayed_work_sync(&ft_mr_ruleset)") == 2
    sync_hook = function(source, "ft_mr_confirm_sync")
    assert "READ_ONCE(ft_mr_stopping)" in sync_hook and "synchronize_net();" in sync_hook


def test_the_kernel_marks_a_commit_until_it_is_applied():
    """A commit moves the generation, then goes on applying itself: chain
    policies, element timeouts, set backend updates. The learner may not
    take a ruleset as settled until that is over, and only nf_tables knows.
    So the kernel marks the commit from just before the generation is
    published -- ordered by the publishing release -- until the last set
    update is in, cleared with a release the learner's acquire pairs with;
    and the mark sits beside the pair in struct net, read inline."""
    patch = (ROOT / "patches/kernel/148-netfilter-nftables-commit-in-progress.patch").read_text()
    sections = dict(re.findall(r"\+\+\+ b/(\S+)\n(.*?)(?=\ndiff --git |\Z)", patch, re.S))
    commit = sections["net/netfilter/nf_tables_api.c"]
    assert commit.index("+\tWRITE_ONCE(net->nft.commit_applying, 1);") < \
        commit.index(" \tsmp_store_release(&net->nft.base_seq, base_seq);")
    assert commit.index(" \tnft_set_commit_update(&set_update_list);") < \
        commit.index("+\tsmp_store_release(&net->nft.commit_applying, 0);") < \
        commit.index(" \tnft_commit_notify(net, NETLINK_CB(skb).portid);")
    assert "+\treturn smp_load_acquire(&net->nft.commit_applying);" in \
        sections["include/net/netfilter/nf_tables.h"]
    assert "+\tu8\t\t\tcommit_applying;" in sections["include/net/netns/nftables.h"]
    # Every build applies it; meta-ask lists its patches one by one.
    recipe = (ROOT / "meta-ask/recipes-kernel/linux/linux-ask_6.12.bb").read_text()
    listed = re.findall(r"file://(\d+)-\S+\.patch", recipe)
    assert "148" in listed and listed == sorted(listed)


def test_nothing_that_can_drop_a_copy_runs_after_the_observer(tmp_path):
    """The observer is last by priority, but at an equal priority netfilter
    puts a later registration first, so an nftables chain that held the last
    priority when the observer registered runs after it and can still drop
    what it confirmed. Such a chain keeps the group in software; conntrack's
    confirmation, the kernel's own, does not. No BPF program can be there: a
    netfilter BPF link refuses the last priority."""
    source = SOURCE.read_text()
    (tmp_path / "mroute_confirm_order.inc").write_text(
        function(source, "ft_mr_observer_followed"))
    binary = tmp_path / "mroute_confirm_order"
    subprocess.run([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("mroute_confirm_order.c")), "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
