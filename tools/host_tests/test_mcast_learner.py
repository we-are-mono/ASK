"""The bridged multicast learner's decision logic."""

import os
from pathlib import Path
import re
import subprocess

from test_pppoe_hm import declaration
from test_qos_lifecycle import function

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "cdx/ask_flowtable.c"


def test_mcast_learner(tmp_path):
    source = SOURCE.read_text()
    backend = (ROOT / "cdx/cdx_mcast_backend.h").read_text()
    counters = (ROOT / "cdx/cdx_flowtable_backend.h").read_text()
    taps = source.index("#define FT_MC_TAPS")
    state = source.index("static LIST_HEAD(ft_mc_routes);")
    # The real membership, flow and route descriptions, not restatements: a
    # field added or resized on any has to fail here rather than compile into
    # a harness that no longer matches what the adapter keeps.
    (tmp_path / "mcast_learner.inc").write_text(
        # What a flow is installed from, and what a route contributes to
        # one, as the backend and the adapter declare them.
        declaration(backend, "cdx_mc_listener")
        + declaration(backend, "cdx_mc_group_spec")
        + declaration(counters, "cdx_ft_counters")
        + source[source.index("struct ft_mc_route {"):
                 source.index("\n", taps) + 1]
        # From the member bound rather than from the structs, so the harness
        # gets FT_MC_MAX_MEMBERS, the retry ceiling and the flow cap without
        # restating them.
        + source[source.index("#define FT_MC_MAX_MEMBERS"):
                 source.index("static LIST_HEAD(ft_mc_groups)")]
        # The published routes and taps, the state they are kept in.
        + source[state:source.index("\n", source.index(
            "static bool ft_mc_taps_overflow", state)) + 1]
        # The observation the hook records, declared further down with the
        # traffic half rather than with the flow it becomes.
        + source[source.index("struct ft_mc_seen {"):
                 source.index("};", source.index("struct ft_mc_seen {")) + 3]
        # The ring the hook records into, its dedup slots, and what forgets
        # them.
        + source[source.index("#define FT_MC_RING"):
                 source.index("static bool ft_mc_seen_eq(")]
        + "\n".join(function(source, name) for name in [
            "ft_mc_family",
            "ft_mc_link_local",
            "ft_mc_same_vlan_group",
            "ft_mc_touch",
            "ft_mc_same_group",
            "ft_mc_find",
            "ft_mc_carriable",
            "ft_mc_mtu_bounded",
            "ft_mc_port_eligible",
            "ft_mc_port_tags",
            "ft_mc_group_drop",
            "ft_mc_drop_port",
            "ft_mc_flow_drop_port",
            "ft_mc_drop_next",
            "ft_mc_group_free",
            "ft_mc_flow_release_ports",
            "ft_mc_flow_free",
            # The two learners' shared streams: what the routed learner
            # publishes, how a flow finds its route, what it is installed
            # as, when it is retired, and what the route is told back.
            "ft_mc_route_same",
            "ft_mc_route_clear",
            "ft_mc_route_publish",
            "ft_mc_route_withdraw",
            "ft_mc_route_state",
            "ft_mc_taps_publish",
            "ft_mc_via_receives",
            "ft_mc_route_reaches",
            "ft_mc_route_names",
            "ft_mc_tapped",
            "ft_mc_match_flow",
            "ft_mc_live_route",
            "ft_mc_match_routes",
            "ft_mc_host_wants",
            "ft_mc_installable",
            "ft_mc_flow_spec",
            "ft_mc_flow_named",
            "ft_mc_retire",
            "ft_mc_route_feedback",
            # Memberships, and the traffic that makes flows of them.
            "ft_mc_group_new",
            "ft_mc_membership",
            "ft_mc_seen_eq",
            "ft_mc_record",
            "ft_mc_seen_key",
            "ft_mc_same_shape",
            "ft_mc_flow_find",
            "ft_mc_route_learns",
            "ft_mc_namer",
            "ft_mc_source_named",
            "ft_mc_host_joined",
            "ft_mc_same_key",
            "ft_mc_observe",
            "ft_mc_adopt_next",
            # The bridge's answer, and what the flow makes of it.
            "ft_mc_shape_resolves",
            "ft_mc_listeners_same",
            "ft_mc_flow_derive",
            "ft_mc_flow_counted",
            "ft_mc_key_contested",
            "ft_mc_drain",
            "ft_mc_flow_names_dev",
            "ft_mc_device_gone",
            "ft_mc_bridge_changed",
            "ft_mc_port_moved",
            "ft_mc_egress_mark",
            "ft_mc_state",
            "ft_mc_member_src",
            "ft_mc_group_has_flow",
        ]))
    binary = tmp_path / "mcast_learner"
    subprocess.run([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
        "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("mcast_learner.c")), "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })


def test_the_handler_never_blocks_on_the_transaction():
    """The MDB handler runs holding RTNL -- switchdev_port_obj_add_deferred()
    asserts it -- and cdx_ctrl_lock_with_rtnl() states the rule those two live
    under: never wait for either lock while holding the other. So the handler
    may take ft_mc_lock and nothing else, and the hardware belongs to a worker
    that runs outside RTNL.
    """
    source = SOURCE.read_text()
    body = function(source, "ft_mc_swdev_obj")
    for forbidden in ("cdx_ft_begin", "cdx_mc_group_add", "cdx_mc_group_del",
                      "cdx_mc_group_replace", "cdx_mc_port_supported",
                      "br_multicast_list_ports"):
        assert forbidden not in body, (
            f"{forbidden} does not belong in the MDB handler")
    # The identity check it may use is the one that answers under its own lock.
    assert "cdx_mc_port_identity" in function(source, "ft_mc_port_eligible")
    # Link-local scope is never recorded: the bridge's own solicited-node
    # joins would keep the hook registered on every IPv6 LAN.
    assert body.index("ft_mc_link_local(&mdb->group)") < body.index("ft_mc_membership(")


def test_the_worker_never_holds_the_group_lock_across_the_transaction():
    """/proc reads the lists from inside the transaction, so a worker that took
    the transaction while holding ft_mc_lock would close a cycle with it. The
    worker snapshots under the lock, releases it, then does the hardware.
    """
    from test_mroute_learner import _assert_not_inside, _held_regions
    body = function(SOURCE.read_text(), "ft_mc_work_fn")
    assert "cdx_ft_begin();" in body, "the worker is where the hardware happens"
    _assert_not_inside(body, _held_regions(body, "mutex_lock(&ft_mc_lock)",
                                           "mutex_unlock(&ft_mc_lock)"),
                       "cdx_ft_begin()", "ft_mc_lock must be released before the transaction")


def test_the_bridge_is_asked_under_rtnl_and_never_across_hardware():
    """br_multicast_list_ports() asserts RTNL, and the switchdev handler holds
    it while it takes ft_mc_lock, so the worker takes them in that order too.
    RTNL is never held across the transaction -- cdx_ctrl_lock_with_rtnl()'s
    standing rule -- and the refresh takes the transaction in /proc's order.
    """
    from test_mroute_learner import _assert_not_inside, _held_regions
    source = SOURCE.read_text()
    worker = function(source, "ft_mc_work_fn")
    derive = worker[worker.index("rtnl_lock();"):]
    derive = derive[:derive.index("rtnl_unlock();")]
    assert derive.index("rtnl_lock();") < derive.index("mutex_lock(&ft_mc_lock);")
    assert "ft_mc_flow_derive(f)" in derive
    assert worker.count("rtnl_lock();") == 1, "one place the bridge is asked"
    _assert_not_inside(worker, _held_regions(worker, "rtnl_lock()", "rtnl_unlock()"),
                       "cdx_ft_begin()", "RTNL must be released before the transaction")

    flow = function(source, "ft_mc_flow_derive")
    assert "ASSERT_RTNL();" in flow
    # The snapshot is asked with the flow's own ingress, which is what makes
    # it the bridge's receive path rather than its transmit one, and with the
    # host's copy asked for.
    assert re.search(r"br_multicast_list_ports\(f->bridge, &f->addr, f->in, &local,", flow)
    # Nothing else in the learner asks it: every other path only marks.
    for name in ("ft_mc_swdev_obj", "ft_mc_membership", "ft_mc_bridge_changed",
                 "ft_mc_port_moved", "ft_mc_observe", "ft_mc_refresh_fn"):
        body = function(source, name)
        for forbidden in ("br_multicast_list_ports", "ft_mc_flow_derive",
                          "br_vlan_get_info(", "br_vlan_get_pvid("):
            assert forbidden not in body, (name, forbidden)
    # A port VLAN object is notified before the bridge applies it, so the
    # handler marks and the worker asks afterwards.
    assert "f->dirty = true;" in function(source, "ft_mc_bridge_changed")

    refresh = function(source, "ft_mc_refresh_fn")
    assert refresh.index("cdx_ft_begin();") < refresh.index("mutex_lock(&ft_mc_lock);")
    exit_body = function(source, "ft_mc_exit")
    assert exit_body.count("cancel_delayed_work_sync(&ft_mc_refresh)") == 2


def test_every_bridge_decision_asks_the_flows_again():
    """The bridge decides a flow's ports by its MDB, its VLANs, its ports'
    STP states and flags, its multicast router ports and state, and whether
    it snoops at all. Each change arrives as a switchdev object or attribute,
    and each has to reach the flows -- not only the routed learner's groups --
    or a flow keeps delivering to a port the bridge no longer does. A querier
    appearing or timing out is announced by nothing, so every flow is asked
    again at every refresh as well.
    """
    source = SOURCE.read_text()
    swdev = function(source, "ft_swdev_event")
    attrs = swdev[swdev.index("case SWITCHDEV_ATTR_ID_BRIDGE_MROUTER:"):]
    attrs = attrs[:attrs.index("return NOTIFY_DONE;")]
    for attr in ("PORT_MROUTER", "BRIDGE_MC_DISABLED", "PORT_BRIDGE_FLAGS",
                 "PORT_STP_STATE", "PORT_MST_STATE", "BRIDGE_MST", "VLAN_MSTI"):
        assert f"case SWITCHDEV_ATTR_ID_{attr}:" in attrs, attr
    assert "ft_mc_bridge_changed(dev);" in attrs and "ft_mr_kick();" in attrs
    # The VLAN objects and attributes further down.
    assert swdev.count("ft_mc_bridge_changed(dev);") == 2
    # A membership change asks every flow of the group, whatever its source:
    # a (S,G) port group blocked, a (*,G) switched to INCLUDE.
    membership = function(source, "ft_mc_membership")
    assert membership.index("ft_mc_touch(bridge, addr);") < membership.index("if (host)")
    assert "f->dirty = true;" in function(source, "ft_mc_touch")
    refresh = function(source, "ft_mc_refresh_fn")
    assert "f->dirty = true;" in refresh
    assert "schedule_work(&ft_mc_work);" in refresh
    # And the refresh runs while any flow exists, installed or not.
    assert "READ_ONCE(ft_mc_flow_count)" in refresh
    assert "READ_ONCE(ft_mc_flow_count)" in function(source, "ft_mc_work_fn")


def test_every_reference_the_learner_takes_is_released():
    """A membership pins its bridge and every port holding it; a flow pins its
    bridge, its ingress and every port it copies to -- the backend borrows
    them and the entry names ports that must not be unregistered underneath
    it. One free path each releases all of them.
    """
    source = SOURCE.read_text()
    free = function(source, "ft_mc_group_free")
    for field in ("g->port[i]", "g->bridge"):
        assert f"dev_put({field})" in free, f"{field} must be released"
    flow = function(source, "ft_mc_flow_free")
    assert "ft_mc_flow_release_ports(f);" in flow
    assert "dev_put(f->port[i].dev)" in function(source, "ft_mc_flow_release_ports")
    for field in ("f->in", "f->bridge"):
        assert f"dev_put({field})" in flow, f"{field} must be released"

    # And nothing else frees either, so there is one place to get it right.
    others = [n for n in ("ft_mc_membership", "ft_mc_work_fn", "ft_mc_exit",
                          "ft_mc_observe", "ft_mc_retire")
              if "kfree(" in function(source, n)]
    assert not others, f"frees belong to ft_mc_group_free/ft_mc_flow_free: {others}"


def test_exit_drains_before_the_module_text_goes_away():
    """The worker holds a pointer into this module. Unloading has to stop it
    and drain the memberships and flows, and it must do so after the switchdev
    chain is unregistered so nothing can add one while it drains.
    """
    source = SOURCE.read_text()
    exit_body = function(source, "ask_flowtable_exit")
    assert "ft_mc_exit();" in exit_body
    assert exit_body.index("unregister_switchdev_blocking_notifier") < \
        exit_body.index("ft_mc_exit();"), (
        "the chain must be gone before the lists drain")

    mc_exit = function(source, "ft_mc_exit")
    assert "cancel_work_sync(&ft_mc_work)" in mc_exit, (
        "the worker must be stopped, not merely asked to stop")
    assert "WRITE_ONCE(ft_mc_stopping, true)" in mc_exit
    for listed in ("ft_mc_groups", "ft_mc_flows"):
        assert f"list_splice_init(&{listed}," in mc_exit, listed

    # The hook is unregistered on both sides of the cancel. Registering sleeps,
    # so a worker part-way through planting one when the flag went up is only
    # actually stopped by the second call -- and a hook left on the bridge
    # chain after the module text is unmapped oopses on the next frame.
    assert mc_exit.count("ft_mc_hook_sync(false)") == 2, (
        "the hook must be unregistered before and after the work is cancelled")
    assert mc_exit.index("ft_mc_hook_sync(false)") < \
        mc_exit.index("cancel_work_sync(&ft_mc_work)") < \
        mc_exit.rindex("ft_mc_hook_sync(false)")

    sync = function(source, "ft_mc_hook_sync")
    assert "mutex_lock(&ft_mc_hook_lock)" in sync, (
        "the flag alone cannot serialize a registration that sleeps")
    assert "READ_ONCE(ft_mc_stopping)" in sync, (
        "teardown must win however the two interleave")
    # Unregistering frees the hook entries through call_rcu() and returns at
    # once, so a frame still inside the hook could write a dedup slot after
    # they are cleared, or queue the worker after exit cancelled it. One grace
    # period, after the unregister and before the slots are cleared, is every
    # such reader gone.
    off = sync[sync.index("nf_unregister_net_hook("):]
    assert off.index("synchronize_net();") < off.index("memset(ft_mc_last"), (
        "readers already inside the hook must be waited out")


def test_a_flow_the_hardware_cannot_serve_whole_is_not_served_at_all():
    """A matched frame never reaches the bridge, so a port the hardware did
    not take on does not fall back to software -- it stops receiving, with
    nothing anywhere to say why. A flow is refused whole over one such port,
    and every place that decides whether to install has to ask.
    """
    source = SOURCE.read_text()
    derive = function(source, "ft_mc_flow_derive")
    assert "ft_mc_port_eligible(chosen[i])" in derive
    assert "error = -EOPNOTSUPP;" in derive
    assert "if (f->error)\n\t\treturn false;" in function(source, "ft_mc_carriable")

    worker = function(source, "ft_mc_work_fn")
    pick = worker[:worker.index("target->stale = false;")]
    build = worker[worker.index("target->stale = false;"):]
    assert "ft_mc_installable(f)" in pick and "ft_mc_installable(target)" in build, (
        "both the pick and the spec build must ask")
    assert "ft_mc_carriable(f)" in function(source, "ft_mc_installable")
    assert "ft_mc_carriable(f)" in function(source, "ft_mc_state"), (
        "/proc must name the reason")

    # The routed learner reads the complete kernel snapshot independently,
    # as data the host sends through the bridge device.
    routed = function(source, "ft_mr_expand_bridge")
    assert "br_multicast_list_ports(bridge, &group, NULL, NULL," in routed
    assert "!cdx_mc_port_identity(chosen[i])" in routed


def test_a_flow_that_would_fragment_stays_in_software():
    """A bridge fragments nothing -- it drops a frame that does not fit the
    egress port -- while a listener's enqueue fragments anything over the
    port's MTU. So a flow is carried only while its ingress cannot deliver a
    frame larger than some copy's port MTU, and an MTU change, which changes
    no membership, has to reach installed flows as well.
    """
    source = SOURCE.read_text()
    assert "ft_mc_mtu_bounded(f)" in function(source, "ft_mc_installable")
    assert "ft_mc_mtu_bounded(f)" in function(source, "ft_mc_state")
    assert '"refused-mtu"' in function(source, "ft_mc_state")
    netdev = function(source, "ft_netdev_event")
    changemtu = netdev[netdev.index("case NETDEV_CHANGEMTU:"):]
    changemtu = changemtu[:changemtu.index("break;")]
    assert "ft_mc_kick_all();" in changemtu and "ft_mr_kick();" in changemtu
    # And the recheck it causes reaches installed flows too, which a
    # membership event never would.
    worker = function(source, "ft_mc_work_fn")
    recheck = worker[worker.index("if (READ_ONCE(ft_mc_recheck))"):]
    recheck = recheck[:recheck.index("mutex_unlock(&ft_mc_lock);")]
    assert "f->stale = true;" in recheck and "f->hw" not in recheck


def test_the_vid_follows_the_bridge_rather_than_the_port():
    """A bridge that does not filter resolves every frame to VLAN zero and
    reports every MDB entry with vid zero, but the port's PVID is not zero --
    nbp_vlan_init() installs the bridge's default_pvid on enslavement whatever
    the filtering setting. Asking the port unconditionally returns 1, no
    observation ever matches a membership, and the learner is inert on the
    commonest configuration there is.
    """
    source = SOURCE.read_text()
    body = function(source, "ft_mc_frame_vid")
    assert "br_vlan_enabled(bridge)" in body, (
        "a bridge that does not filter has no VLAN to resolve")
    assert body.index("br_vlan_enabled(bridge)") < \
        body.index("br_vlan_get_pvid_rcu"), (
        "the filtering test must come before the PVID lookup")
    # A tagged frame in a VLAN the port is not a member of is one the bridge
    # drops after this hook; learned, it would be retired and learned again
    # at the rate a host sends it.
    hook = function(source, "ft_mc_hook")
    assert hook.index("br_vlan_get_info_rcu(port, seen.addr.vid, &info)") < \
        hook.index("ft_mc_record(&seen);")
    # And an 802.1ad bridge takes an 802.1Q tag for payload.
    assert "br_vlan_get_proto(bridge, &bproto) || bproto != ETH_P_8021Q" in hook


def test_an_idle_entry_ages_on_the_bridges_clock():
    """An installed flow whose entry counts nothing for the bridge's group
    membership interval is a stream that stopped: it goes, so a new source can
    have its place, and a resumed one is learned again from traffic. The
    interval is the bridge's own for the flow's VLAN, read at every
    derivation, and the count is the one the refresh already reads."""
    source = SOURCE.read_text()
    derive = function(source, "ft_mc_flow_derive")
    assert "f->age = br_multicast_membership_interval(f->bridge, f->addr.vid);" in derive
    # Before the early return for an unchanged answer, so a changed
    # interval is followed without touching the hardware.
    assert derive.index("f->age =") < derive.index("if (f->derived && error == f->error")
    refresh = function(source, "ft_mc_refresh_fn")
    assert "ft_mc_flow_counted(f, &stats, jiffies);" in refresh
    counted = function(source, "ft_mc_flow_counted")
    assert "time_after(now, f->active + f->age)" in counted and "f->gone = true;" in counted
    worker = function(source, "ft_mc_work_fn")
    added = worker[worker.index("if (spec.listeners && !rc && !replace) {"):]
    assert "target->active = jiffies;" in added[:added.index("}")]
    patch = (ROOT / "patches/kernel/161-bridge-multicast-egress-snapshot.patch").read_text()
    assert "+EXPORT_SYMBOL_GPL(br_multicast_membership_interval);" in patch
    assert "+	interval = br_multicast_gmi(brmctx);" in patch


def test_a_failed_install_is_tried_again_an_interval_apart():
    """A failure is not permanent -- a port that lost carrier gets it back,
    another entry gives its room back -- but trying again straight away, in
    the same pass, only spends the ceiling before anything could change. The
    refresh is what tries again, one interval apart."""
    source = SOURCE.read_text()
    worker = function(source, "ft_mc_work_fn")
    failed = worker[worker.index("if (spec.listeners && rc) {"):]
    failed = failed[:failed.index("} else if (!rc) {")]
    assert "target->retries++;" in failed and "stale" not in failed.split("*/")[-1]
    refresh = function(source, "ft_mc_refresh_fn")
    assert "if (!f->hw && f->retries && f->retries < FT_MC_MAX_RETRIES)\n\t\t\tf->stale = true;" \
        in refresh


def test_a_blocked_source_is_the_bridges_answer_not_a_listener():
    """A blocked port group is one an IGMPv3 source filter excludes this source
    for; br_forward() skips it. The handler records it as the leave of its
    (S,G) membership and, like every membership change, asks every flow of
    the group again -- the bridge's answer then leaves the port out, whatever
    the (*,G) membership that still names the flow says.
    """
    source = SOURCE.read_text()
    body = function(source, "ft_mc_swdev_obj")
    assert "SWITCHDEV_OBJ_MDB_F_BLOCKED" in body
    blocked = body[body.index("SWITCHDEV_OBJ_MDB_F_BLOCKED"):]
    assert blocked.index("adding = false;") < blocked.index("ft_mc_membership(")
    # The link-local test on the hook shares the handler's rule.
    assert "ft_mc_link_local(&seen.addr)" in function(source, "ft_mc_hook")


def test_a_failed_chain_swap_takes_the_flow_out_of_hardware():
    """cdx_mc_group_replace() leaves the old chain in place when it fails, and
    the old chain can be missing a port that has just joined, or the routed
    copies the host now needs carried: a listener starved with nothing to say
    why, and a route reported carried that is not. So a failed swap takes
    the flow out, as a routed group's failed update does, and it retries
    from software.
    """
    worker = function(SOURCE.read_text(), "ft_mc_work_fn")
    swap = worker[worker.index("rc = cdx_mc_group_replace(hw, &spec);"):]
    swap = swap[:swap.index("} else {")]
    for step in ("cdx_mc_group_del(&hw);", "ft_mc_installed--;", "withdrew = true;"):
        assert step in swap, step
    # /proc and the refresh read the entry under the transaction and then
    # ft_mc_lock: it leaves the group under that lock before it is freed, or
    # the first of them to get the transaction reads freed memory.
    unhooked = swap.index("target->hw = NULL;")
    assert swap.index("mutex_lock(&ft_mc_lock);") < unhooked < \
        swap.index("mutex_unlock(&ft_mc_lock);") < swap.index("cdx_mc_group_del(&hw);")
    assert "if (!hw)\n\t\t\ttarget->carried_route = NULL;" in worker


def test_the_dedup_slots_are_forgotten_whenever_an_answer_may_change():
    """The hook records a frame once and then ignores its restatements until
    the slots are forgotten. A frame recorded while nothing named it -- the
    membership withdrawn, or its deferred MDB add not yet arrived, or the
    route not yet published -- would otherwise keep a flow from being learned
    for as long as the stream runs. So every event that can change the answer
    a recorded frame got forgets the slots, after the change is on the list;
    and the drain does not, because forgetting after every drain would record
    every frame of a stream that never installs.
    """
    source = SOURCE.read_text()
    forget = "ft_mc_forget_seen();"
    assert forget in function(source, "ft_mc_group_new"), "a membership created"
    assert forget in function(source, "ft_mc_route_publish"), "a route published"
    assert forget in function(source, "ft_mc_retire"), "a flow or membership retired"
    # A flow that took another shape: the old shape's frames are another
    # answer now.
    observe = function(source, "ft_mc_observe")
    assert observe.index("ft_mc_drop_next(f);") < observe.index(forget)
    worker = function(source, "ft_mc_work_fn")
    # An entry taken out of hardware and kept -- only one that was in it --
    # or replaced by the shape waiting to take over.
    withdraw = worker[worker.index("if (!spec.listeners) {"):]
    withdraw = withdraw[:withdraw.index("} else if (replace)")]
    assert withdraw.index("if (hw) {") < withdraw.index("withdrew = true;")
    assert "if (withdrew || stale)\n\t\t\tft_mc_forget_seen();" in worker
    # The retry goes through the helper, which asserts the group lock.
    assert "memset(ft_mc_last" not in worker
    assert "lockdep_assert_held(&ft_mc_lock)" in function(source, "ft_mc_forget_seen")
    assert forget not in function(source, "ft_mc_drain")
    assert "memset(ft_mc_last" in function(source, "ft_mc_hook_sync")
    assert "ft_mc_record(&seen);" in function(source, "ft_mc_hook")


def test_the_learner_lets_go_of_a_device_that_went_away():
    """Nothing reports a flow's ingress port, and a permanent MDB entry's
    delete arrives after the port has left the bridge -- del_nbp() flushes
    those from br_multicast_del_port(), after netdev_upper_dev_unlink(). Both
    would otherwise hold a reference that blocks unregistration for good. And
    a port leaving the bridge while it stays up is reported by nothing but
    its master changing.

    A link going down is not a device going away: the bridge keeps a
    permanent membership across it and never announces it again, so only
    unregistration lets go of the memberships; a link going down asks the
    bridge about the flows again.
    """
    source = SOURCE.read_text()
    netdev = function(source, "ft_netdev_event")
    down = netdev[netdev.index("case NETDEV_GOING_DOWN:"):]
    assert "ft_mc_device_gone(dev, false);" in down[:down.index("break;")]
    unregister = netdev[netdev.index("case NETDEV_UNREGISTER:"):]
    assert "ft_mc_device_gone(dev, true);" in unregister[:unregister.index("break;")]
    assert netdev.count("ft_mc_device_gone(") == 2
    upper = netdev[netdev.index("case NETDEV_CHANGEUPPER:"):]
    assert "ft_mc_port_moved(dev);" in upper[:upper.index("break;")]

    gone = function(source, "ft_mc_device_gone")
    assert gone.index("if (!unregistering) {") < gone.index("ft_mc_drop_port(dev)"), \
        "memberships are let go of only when the device goes"
    assert "ft_mc_drop_port(dev)" in gone, "as a membership's port"
    assert "ft_mc_flow_drop_port(f, dev)" in gone, "as a flow's copy"
    assert "f->in == dev" in gone and "dev_put(f->in);" in gone, "as an ingress"
    assert "f->bridge == dev" in gone, "as the bridge itself"
    # A port that left is answered by the bridge: -EINVAL for an ingress
    # that is no longer its port ends the flow.
    assert "if (n == -EINVAL) {" in function(source, "ft_mc_flow_derive")

    # And the delete that arrives too late falls back to dropping the port
    # wherever it is still listed.
    swdev = function(source, "ft_mc_swdev_obj")
    assert "ft_mc_drop_port(port)" in swdev, (
        "a delete with no master left must still release the port")


def test_a_changed_egress_rebuilds_every_group_copying_out_of_the_port():
    """Each listener entry names the frame queue its port had when it was
    built, and whether the port's DSCP map was on. CDX changing the port's
    queues -- an HTB tree switching it to or from CEETM, a class moving, the
    map changing -- leaves them enqueuing where nothing dequeues, so every
    installed group of either learner with a copy on the port is rebuilt.

    The caller may or may not hold RTNL and runs in process context, so the
    hook takes each learner's mutex in turn and never both, and nothing that
    needs RTNL or the transaction. A group being built while it runs may not
    be on its learner's list to mark; the generation, bumped before marking,
    is what both workers compare once they record a build.
    """
    source = SOURCE.read_text()
    assert "void ft_mc_egress_changed(const struct net_device *dev);" in source, (
        "the entry point is declared with the adapter's other multicast ones")
    body = function(source, "ft_mc_egress_changed")
    assert body.index("atomic_inc(&ft_mc_egress_gen)") < body.index("ft_mc_egress_mark(dev)")
    assert "ft_mr_egress_mark(dev)" in body
    assert "atomic64_add(rebuilt, &ft_mc_egress_rebuilds)" in body
    for forbidden in ("rtnl_lock", "ASSERT_RTNL", "cdx_ft_begin", "spin_lock",
                      "mutex_lock"):
        assert forbidden not in body, f"{forbidden} does not belong in the hook"
    for name, lock, other in (("ft_mc_egress_mark", "ft_mc_lock", "ft_mr_lock"),
                              ("ft_mr_egress_mark", "ft_mr_lock", "ft_mc_lock")):
        mark = function(source, name)
        assert f"mutex_lock(&{lock})" in mark and other not in mark, (
            f"{name} takes its own learner's lock and never the other's")
        for forbidden in ("rtnl", "cdx_ft_begin", "spin_lock"):
            assert forbidden not in mark
    # A rebuild is not skipped as an unchanged plan.
    assert "!rebuild" in function(source, "ft_mr_work_fn")
    for worker in ("ft_mc_work_fn", "ft_mr_work_fn"):
        assert "atomic_read(&ft_mc_egress_gen) != gen" in function(source, worker), (
            f"{worker} must rebuild a chain the queues moved under")
    assert "mcast_egress_rebuilds" in function(source, "ft_show")
