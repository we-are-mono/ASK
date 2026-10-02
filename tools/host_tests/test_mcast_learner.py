"""The bridged multicast learner's decision logic."""

from ask_orch.process import run_process

import os
from pathlib import Path
import re

from _host_pppoe_hm import (declaration)
from _host_qos_lifecycle import (function)

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
        # The refresh interval, which the shortest age is two of.
        + re.search(r"#define FT_MC_REFRESH_INTERVAL.*\n", source).group(0)
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
        # What runs in software on every bridge and bridge port, which the
        # derivation reads.
        + source[source.index("struct ft_mc_soft_dev {"):
                 source.index("static bool ft_mc_soft_bridged(")]
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
            "ft_mc_chain_forget",
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
            "ft_mc_discardable",
            "ft_mc_flow_key",
            "ft_mc_flow_spec",
            "ft_mc_discard_spec",
            "ft_mc_chain_record",
            "ft_mc_flow_named",
            "ft_mc_retire",
            "ft_mc_route_feedback",
            # Memberships, and the traffic that makes flows of them.
            "ft_mc_group_new",
            "ft_mc_membership",
            "ft_mc_seen_eq",
            "ft_mc_seen_set",
            "ft_mc_supersede",
            "ft_mc_flow_seen",
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
            # The bridge's answer, what runs in software on its ports beside
            # it, and what the flow makes of them.
            "ft_mc_shape_resolves",
            "ft_mc_listeners_same",
            "ft_mc_soft_bridged",
            "ft_mc_soft_bridge",
            "ft_mc_soft_ask",
            "ft_mc_soft_free",
            "ft_mc_soft_on",
            "ft_mc_netdev_dependent",
            "ft_mc_flow_derive",
            "ft_mc_count_delta",
            "ft_mc_flow_counted",
            "ft_mc_refresh_fn",
            "ft_mc_key_contested",
            "ft_mc_drain",
            # What gives a discard's group id to a stream somebody wants.
            "ft_mc_evict_discard",
            "ft_mc_flow_names_dev",
            "ft_mc_device_gone",
            "ft_mc_bridge_changed",
            "ft_mc_port_moved",
            "ft_mc_flow_hw_lists",
            "ft_mc_egress_mark",
            "ft_mc_egress_drain",
            # The worker itself, which builds, records inside its
            # transaction, and meets the drain there.
            "ft_mc_work_fn",
            "ft_mc_state",
            "ft_mc_member_src",
            "ft_mc_group_has_flow",
            # The switchdev MDB handler, and the filter a replay reaches it
            # through.
            "ft_mc_swdev_obj",
            "ft_mc_replay_event",
        ]))
    binary = tmp_path / "mcast_learner"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
        "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("mcast_learner.c")), "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=30, env={
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
    from _host_mroute_learner import (_assert_not_inside, _held_regions)
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
    from _host_mroute_learner import (_assert_not_inside, _held_regions)
    source = SOURCE.read_text()
    worker = function(source, "ft_mc_work_fn")
    derive = worker[worker.index("rtnl_lock();"):]
    derive = derive[:derive.index("rtnl_unlock();")]
    assert derive.index("rtnl_lock();") < derive.index("mutex_lock(&ft_mc_lock);")
    assert "ft_mc_flow_derive(f, &soft)" in derive
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


def test_a_reload_asks_the_bridge_for_standing_memberships():
    """Registering on the switchdev chain replays nothing, and a standing
    membership is never announced again -- a refreshing report only restarts
    a timer. So the adapter asks every bridge port for what it holds, after
    its own notifier is registered so nothing falls between, under the RTNL
    the replay asserts, through a notifier that takes only added MDB objects
    and reads nothing else as one."""
    source = SOURCE.read_text()
    init = function(source, "ask_flowtable_init")
    registered = init.index("register_switchdev_blocking_notifier(&ft_swdev_nb)")
    assert registered < init.index("ft_mc_replay();") < init.index("WRITE_ONCE(ft_ready, true);")
    replay = function(source, "ft_mc_replay")
    assert replay.index("rtnl_lock();") < replay.index("switchdev_bridge_port_replay(") < \
        replay.index("rtnl_unlock();")
    assert "for_each_netdev(&init_net, dev)" in replay and "netif_is_bridge_port(dev)" in replay
    assert "&ft_mc_replay_nb" in replay
    event = function(source, "ft_mc_replay_event")
    # An attribute event's ptr is not an object: the event is tested first.
    assert event.index("event != SWITCHDEV_PORT_OBJ_ADD") < event.index("info->obj")
    assert "ft_mc_swdev_obj(event, info);" in event
    # The VLAN arm of ft_swdev_event() would retire every unicast flow.
    assert "ft_swdev_event" not in event
    assert ".notifier_call = ft_mc_replay_event," in source


def test_patch_160_replays_what_it_notifies():
    """The replay built its objects from the MDB entry alone, so a blocked
    port group replayed as a member; and a replay was elided when a deferred
    event merely shared its MAC and VID -- which a group's (*,G) and (S,G)
    entries always do -- though that event restated something else."""
    patch = (ROOT / "patches/kernel/160-bridge-switchdev-mdb-group.patch").read_text()
    added = "\n".join(line[1:] for line in patch.splitlines()
                      if line.startswith("+") and not line.startswith("+++"))
    # One translation of a port group's flags, used by both paths.
    assert "static u8 br_switchdev_mdb_flags(const struct net_bridge_port_group *pg)" in added
    assert "mdb.flags = br_switchdev_mdb_flags(pg);" in added
    assert "\tif (pg)\n\t\tmdb.flags = br_switchdev_mdb_flags(pg);" in added
    assert "const struct net_bridge_port_group *pg," in added
    assert "mp, NULL, br_dev);" in added and "mp, p, dev);" in added
    # The deferred-event match compares what distinguishes two groups.
    eq = patch[patch.index("static bool switchdev_obj_eq"):]
    eq = eq[:eq.index("default:")]
    assert "+\t\t\tma->flags == mb->flags &&" in eq
    assert "+\t\t\t!memcmp(&ma->group, &mb->group, sizeof(ma->group));" in eq


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
    recheck = worker[worker.index("if (READ_ONCE(ft_mc_recheck) ||"):]
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
    assert derive.index("f->age =") < derive.index("if (same && error == f->error")
    refresh = function(source, "ft_mc_refresh_fn")
    assert "ft_mc_flow_counted(f, &stats, jiffies);" in refresh
    counted = function(source, "ft_mc_flow_counted")
    assert "time_after(now, f->active + f->age)" in counted and "f->gone = true;" in counted
    worker = function(source, "ft_mc_work_fn")
    added = worker[worker.index("if (added) {"):]
    assert "target->active = jiffies;" in added[:added.index("}")]
    patch = (ROOT / "patches/kernel/161-bridge-multicast-egress-snapshot.patch").read_text()
    assert "+EXPORT_SYMBOL_GPL(br_multicast_membership_interval);" in patch
    assert "+	interval = br_multicast_gmi(brmctx);" in patch


def test_a_stream_the_parser_never_classifies_is_not_learned():
    """The soft parser ends the parse of an IPv4 frame whose TTL is 0 or 1, and
    of an IPv6 one whose hop limit is, before any table is consulted. An entry
    learned from such a stream would count nothing, age out, and be learned
    again from the next frame for as long as the stream runs, so the hook
    records neither."""
    hook = function(SOURCE.read_text(), "ft_mc_hook")
    record = hook.index("ft_mc_record(&seen);")
    assert hook.index("if (iph->ttl <= 1)\n\t\t\treturn NF_ACCEPT;") < record
    assert hook.index("if (ip6h->hop_limit <= 1)\n\t\t\treturn NF_ACCEPT;") < record


def test_a_bridge_filter_hook_keeps_bridged_multicast_in_software(tmp_path):
    """An installed flow replicates at the classifier, where no bridge hook
    runs: an nftables bridge chain, ebtables, or br_netfilter handing bridged
    traffic to iptables would stop seeing the stream the moment it was
    carried. So while any hook but the learner's own is registered where a
    forwarded frame passes, every flow is refused, installed ones included,
    and the worker asks at every pass because nothing announces a hook."""
    source = SOURCE.read_text()
    (tmp_path / "mcast_bridge_filter.inc").write_text(
        function(source, "ft_bridge_hooked") + function(source, "ft_mc_bridge_filtered")
        + function(source, "ft_dev_nf_ingress_hooked"))
    binary = tmp_path / "mcast_bridge_filter"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("mcast_bridge_filter.c")), "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })

    worker = function(source, "ft_mc_work_fn")
    asked = worker.index("filtered = ft_mc_bridge_filtered();")
    assert asked < worker.index("ft_mc_drain();")
    changed = worker[asked:worker.index("ft_mc_drain();")]
    assert "filtered != READ_ONCE(ft_mc_filtered)" in changed
    assert "f->stale = true;" in changed and "f->retries = 0;" in changed
    assert "!ft_mc_filtered" in function(source, "ft_mc_installable")
    assert 'return "refused-filter";' in function(source, "ft_mc_state")
    # Nothing gives up a place for a source the filter would refuse too.
    assert "ft_mc_filtered" in function(source, "ft_mc_observe")


def test_tc_and_netdev_chains_keep_bridged_multicast_in_software():
    """tc and netfilter's netdev hooks run on every frame the bridge forwards
    in software and on none an installed entry replicates, and the entry's key
    stops at the addresses, so a filter dropping one port of the group would
    be bypassed for all of them. A flow stays in software while either runs
    anything where it arrives -- XDP included -- or where a bridged copy
    leaves: refused-tc by the routed learner's own predicate, refused-filter
    for a chain, as for a bridge hook. Both are asked under the RTNL the
    derivation holds, before the group lock, and every refresh asks again
    because nothing announces a filter or a chain."""
    from _host_mroute_learner import (_assert_not_inside, _held_regions)
    source = SOURCE.read_text()
    derive = function(source, "ft_mc_flow_derive")
    for asked in ("ft_mc_soft_on(soft, f->in, true, &tc_soft, &nf_hooked);",
                  "ft_mc_soft_on(soft, port[i].dev, false, &tc_soft, &nf_hooked);",
                  "ft_mc_soft_on(soft, f->bridge, true, &tc_soft, &nf_hooked);",
                  "ft_mc_netdev_dependent(f, port, ports, same)"):
        assert asked in derive, asked
    # The bridge device only for a copy it hands up that a carried flow
    # takes away: a host that joined, or flooding, refuses the flow anyway.
    hands_up = derive[:derive.index("ft_mc_soft_on(soft, f->bridge")]
    assert "if (local & (BR_MCAST_TO_HOST_ROUTER | BR_MCAST_TO_HOST_PROMISC))" in hands_up
    # A changed answer is one the install pass has to hear of.
    unchanged = derive[derive.index("if (same && error == f->error"):]
    unchanged = unchanged[:unchanged.index("return;")]
    assert "tc_soft == f->tc_soft" in unchanged and "nf_hooked == f->nf_hooked" in unchanged
    assert "same = f->derived && ports == f->ports &&" in derive
    assert derive.index("ft_mc_netdev_dependent(f, port, ports, same)") < \
        derive.index("if (same && error == f->error")
    assert "f->tc_soft = tc_soft;" in derive and "f->nf_hooked = nf_hooked;" in derive
    # Refused for one reason or several at once: one refusal.
    assert derive.count("ft_mc_refused++;") == 1
    for forbidden in ("ft_dev_stack_tc_soft", "ft_dev_tc_soft", "ft_dev_nf_ingress_hooked"):
        assert forbidden not in derive, forbidden
    # A port's chains are judged for what they do to a bridged stream, as
    # the routed learner judges its groups', and a walk a commit interrupted
    # keeps the answer the flow had -- or refuses one that had none.
    probe = function(source, "ft_mc_netdev_dependent")
    assert ".bridged = true," in probe and ".in = f->in," in probe and ".nout = ports," in probe
    assert "rc = nft_port_dependent(&init_net, &probe);" in probe
    assert probe.index("rcu_read_lock();") < probe.index("nft_port_dependent(") < \
        probe.index("rcu_read_unlock();")
    assert "if (rc == -EAGAIN || rc == -ENOMEM)\n\t\treturn !same || f->nf_hooked;" in probe
    assert "ft_mc_port_probe_errors++;" in probe
    assert "mcast_port_probe_errors" in function(source, "ft_show")
    # Asked under RTNL and before the group lock, never under it: a block
    # walk can destroy a classifier, whose destruction reaches the egress
    # mark, which takes the group lock.
    ask = function(source, "ft_mc_soft_ask")
    assert "ASSERT_RTNL();" in ask
    for asked in ("ft_dev_stack_tc_soft(dev, true)", "ft_dev_stack_tc_soft(dev, false)",
                  "ft_mc_soft_bridge(d, dev);"):
        assert asked in ask, asked
    assert "ft_mc_lock" not in ask
    # A bridge's hand-up copy crosses the bridge's LOCAL_IN hook, the bridge
    # device and every device above it, and nothing below it: every port of
    # the bridge is below it.
    bridge = function(source, "ft_mc_soft_bridge")
    assert "ft_dev_tc_soft(br, true)" in bridge and "ft_dev_nf_ingress_hooked(br)" in bridge
    assert "ft_bridge_hooked(BIT(NF_BR_LOCAL_IN))" in bridge
    assert "netdev_for_each_upper_dev_rcu(br, upper, iter)" in bridge
    assert "ft_dev_stack_tc_soft" not in bridge and "ASSERT_RTNL();" in bridge
    worker = function(source, "ft_mc_work_fn")
    derived = worker[worker.index("rtnl_lock();"):worker.index("rtnl_unlock();")]
    assert derived.index("if (ft_mc_soft_ask(&soft)) {") < derived.index("mutex_lock(&ft_mc_lock);")
    assert "ft_mc_flow_derive(f, &soft)" in derived
    code = re.sub(r"/\*.*?\*/", "", worker, flags=re.S)
    _assert_not_inside(code, _held_regions(code, "mutex_lock(&ft_mc_lock)",
                                           "mutex_unlock(&ft_mc_lock)"),
                       "ft_mc_soft_ask(", "tc must be asked outside ft_mc_lock")
    assert "ft_mc_soft_free(&soft);" in worker[worker.index("rtnl_unlock();"):]
    # A device the table does not name is one nothing can be said of.
    assert "*tc = *nf = true;" in function(source, "ft_mc_soft_on")
    # Declared ahead of the bridged learner, defined with the routed one.
    for name in ("ft_dev_tc_soft", "ft_dev_stack_tc_soft"):
        assert source.index(f"static bool {name}(struct net_device *dev, bool ingress);") < \
            source.index("static void ft_mc_flow_derive(")
    # A flowtable's hook is not a chain: chains and BPF programs are asked
    # for by type, which this kernel gives a flowtable none of.
    hooked = function(source, "ft_dev_nf_ingress_hooked")
    for kind in ("NF_HOOK_OP_NF_TABLES", "NF_HOOK_OP_BPF"):
        assert f"ops[i]->hook_ops_type == {kind}" in hooked, kind
    assert "NF_HOOK_OP_UNDEFINED" not in hooked and "!=" not in hooked
    for name in ("ft_mc_installable", "ft_mc_discardable"):
        body = function(source, name)
        assert "!f->tc_soft" in body and "!f->nf_hooked" in body, name
    # The flow's own ports after every refusal that would hold whatever
    # they ran, and before the discard.
    state = function(source, "ft_mc_state")
    assert state.index("if (ft_mc_filtered)\n\t\treturn \"refused-filter\";") < \
        state.index('return "refused-host";') < state.index('return "refused-routed";') < \
        state.index("if (f->nf_hooked)\n\t\treturn \"refused-filter\";") < \
        state.index('return "refused-tc";') < state.index("if (ft_mc_discardable(f))")
    # Patch 148's bridged probe: netdev hooks alone, no conntrack, no
    # x_tables, and a stream the bridge forwards nowhere still asked about.
    patch = (ROOT / "patches/kernel/148-netfilter-nftables-commit-in-progress.patch").read_text()
    sections = dict(re.findall(r"\+\+\+ b/(\S+)\n(.*?)(?=\ndiff --git |\Z)", patch, re.S))
    assert "+\tbool\t\t\t\tbridged;" in sections["include/net/netfilter/nf_port_probe.h"]
    walk = sections["net/netfilter/nf_tables_port_probe.c"]
    packet = walk[walk.index("+static u32 nft_probe_packet("):]
    packet = packet[:packet.index("\n+}\n")]
    assert packet.index("+\tif (!p->bridged) {\n+\t\tnft_probe_hook(ctx, NFT_PROBE_PRE,") > 0
    assert "+\t\tif (!p->bridged) {\n+\t\t\tnft_probe_hook(ctx, NFT_PROBE_FORWARD," in packet
    assert "+\t\tnft_probe_hook(ctx, NFT_PROBE_EGRESS, NULL, p->out[i], i);" in packet
    assert "+\t\tif (ctx->probe->bridged)\n+\t\t\treturn NFT_PROBE_CT_ABSENT;" in walk
    assert "+\t    (!probe->nout && !probe->bridged) ||" in walk
    assert "+\tif (probe->bridged)\n+\t\treturn 0;" in sections["net/netfilter/core.c"]
    # The bridge's own chains are the caller's: only some of its hooks see a
    # forwarded frame, which the learner asks itself.
    assert "+\t\tif (!ctx->steady && ctx->bridged && !ctx->probe->bridged) {" in walk
    # A netdev chain's hook a chain update adds is typed as the chain's
    # first ones are, so the learner's type check finds it.
    assert "+\t\t\t\th->ops.hook_ops_type = basechain->ops.hook_ops_type;" in \
        sections["net/netfilter/nf_tables_api.c"]
    assert "f->dirty = true;" in function(source, "ft_mc_refresh_fn")


def test_streams_the_worker_can_do_nothing_with_wake_it_once():
    """A stream nothing names, one turned away at the group's flow cap, a flow
    refused: each reaches the hook on every frame. The dedup slots keep one
    from being recorded again until something forgets them; a fact goes to one
    set of slots by a seeded hash of its stream, and pushes out only one that
    was recorded at least a refresh interval ago, so more streams than a set
    holds wait rather than each being news on every frame. Every pass of the
    worker takes the transaction, and /proc counts the passes and the facts
    that waited."""
    source = SOURCE.read_text()
    record = function(source, "ft_mc_record")
    assert "ft_mc_seen_set(seen)" in record
    assert "time_before(now, slot->at + FT_MC_REFRESH_INTERVAL)" in record
    assert "ft_mc_deferred++;" in record
    # The slot is claimed only once the fact is in the ring: a fact the full
    # ring dropped is asked again on its next frame.
    assert record.index("ft_mc_dropped++;") < record.index("slot->seen = *seen;")
    assert "ft_hash_seed" in function(source, "ft_mc_seen_set")
    worker = function(source, "ft_mc_work_fn")
    assert worker.index("WRITE_ONCE(ft_mc_passes, ft_mc_passes + 1);") < \
        worker.index("cdx_ft_begin();")
    show = function(source, "ft_show")
    assert "mcast_passes" in show and "mcast_deferred" in show
    # Seeded before the hook can be registered.
    init = function(source, "ask_flowtable_init")
    assert init.index("ft_hash_seed = get_random_u32();") < init.index("ft_mc_replay();")


def test_a_failed_install_is_tried_again_an_interval_apart():
    """A failure is not permanent -- a port that lost carrier gets it back,
    another entry gives its room back -- but trying again straight away, in
    the same pass, only spends the ceiling before anything could change. The
    refresh is what tries again, one interval apart."""
    source = SOURCE.read_text()
    worker = function(source, "ft_mc_work_fn")
    # A build is listeners or a discard, and either can fail.
    failed = worker[worker.index("if (build && rc) {"):]
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


def test_a_discard_gives_its_group_id_only_to_a_stream_somebody_wants():
    """Both learners' groups draw on one space of group ids per family, and a
    discard holds its id for as long as its stream arrives. An add that
    replicates and finds none takes one from a discard and is made again at
    once; nothing else asks -- not a discard's own add, not a failure of any
    other kind. The discard leaves the hardware the way the worker takes an
    entry out: off the books under ft_mc_lock inside the transaction, deleted
    with the transaction alone, and never the flow the worker holds."""
    source = SOURCE.read_text()
    evict = function(source, "ft_mc_evict_discard")
    assert "cdx_ft_assert_held();" in evict
    for guard in ("!f->hw_discard", "f->busy", "f->stale",
                  "ft_mc_family(&f->addr) != family", "if (!ft_mc_stopping)"):
        assert guard in evict, guard
    assert evict.count("mutex_lock(&ft_mc_lock)") == 1
    unlock = evict.rindex("mutex_unlock(&ft_mc_lock);")
    assert evict.index("victim->hw = NULL;") < unlock < evict.index("cdx_mc_group_del(&hw);")
    assert evict.index("dev_hold(in);") < unlock < evict.index("dev_put(in);")
    # The ingress is held until the delete that unsubscribes through it.
    assert evict.index("cdx_mc_group_del(&hw);") < evict.index("dev_put(in);")
    for worker, spec, guard in (("ft_mc_work_fn", "spec", "!spec.discard &&"),
                                ("ft_mr_work_fn", "plan.spec", "")):
        body = re.sub(r"/\*.*?\*/", "", function(source, worker), flags=re.S)
        add = f"rc = cdx_mc_group_add(&{spec}, &hw);"
        assert body.count(add) == 2 and body.count("ft_mc_evict_discard(") == 1, worker
        # Room is asked for in the add's own family.
        assert f"ft_mc_evict_discard({spec}.family)" in body, worker
        first = body.index(add)
        asked = body.index("ft_mc_evict_discard(")
        assert first < asked < body.index(add, first + 1), worker
        gate = " ".join(body[first + len(add):asked].split())
        assert gate == " ".join(f"if (rc == -ENOSPC && {guard}".split()), (worker, gate)
    # The worker's own target is its until it records, whichever way the
    # build went.
    worker = re.sub(r"/\*.*?\*/", "", function(source, "ft_mc_work_fn"), flags=re.S)
    held = worker[worker.index("target->busy = true;"):worker.index("target->busy = false;")]
    for leave in ("continue;", "break;", "return", "goto"):
        assert leave not in held, leave
    assert re.search(r"mutex_lock\(&ft_mc_lock\);\s+target->busy = false;", worker)
    # What a discard saves: every refresh's count over its interval, and none
    # yet for an entry just added.
    counted = function(source, "ft_mc_flow_counted")
    block = counted[counted.index("if (counted) {"):]
    assert "f->interval_packets = packets;" in block[:block.index("\n\t}\n")]
    added = worker[worker.index("if (added) {"):]
    assert "target->interval_packets = U64_MAX;" in added[:added.index("}")]
    assert "mcast_discards_evicted" in function(source, "ft_show")


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
    # /proc, the refresh and the egress drain read the entry under the
    # transaction: the hardware call and the record of what it did are made
    # in one transaction hold, so none of them can find the entry freed, or
    # built and not yet recorded. ft_mc_lock is taken for the record alone.
    build = worker[worker.index("Install or update whatever is now installable"):]
    build = build[build.index("cdx_ft_begin();"):]
    build = build[:build.index("cdx_ft_end();")]
    assert build.index("hw = target->hw;") < \
        build.index("rc = cdx_mc_group_replace(hw, &spec);") < \
        build.index("mutex_lock(&ft_mc_lock);") < build.index("target->hw = hw;") < \
        build.index("mutex_unlock(&ft_mc_lock);")
    assert "if (!hw)\n\t\t\ttarget->carried_route = NULL;" in worker


def test_no_worker_holds_its_learner_lock_across_the_hardware():
    """The MDB handler, the netdev events and the egress mark take the
    learners' locks holding RTNL. A worker that held one across a backend call
    -- which allocates entries and waits on the PCD -- would stall them, and
    every RTNL user behind them, for a whole build. The transaction is what
    keeps a half-built entry from being seen; the learner lock is only for
    the records."""
    from _host_mroute_learner import (_assert_not_inside, _held_regions)
    source = SOURCE.read_text()
    for worker, lock in (("ft_mc_work_fn", "ft_mc_lock"), ("ft_mr_work_fn", "ft_mr_lock")):
        # The code, not what its comments mention.
        body = re.sub(r"/\*.*?\*/", "", function(source, worker), flags=re.S)
        regions = _held_regions(body, f"mutex_lock(&{lock})", f"mutex_unlock(&{lock})")
        for call in ("cdx_mc_group_add(", "cdx_mc_group_replace(", "cdx_mc_group_del("):
            assert call in body, (worker, call)
        for call in ("cdx_mc_group_add(", "cdx_mc_group_replace(", "cdx_mc_group_del(",
                     "cdx_mc_group_stats("):
            _assert_not_inside(body, regions, call, f"{worker} holds {lock} across {call}")


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
    # A flow that took another shape: the old shape's frames, and the kept
    # one's, are another answer now -- their own slots lapse, and nothing
    # else is forgotten, or a stream arriving in two shapes would make every
    # stream news on every frame.
    observe = function(source, "ft_mc_observe")
    reshape = observe[observe.index("With nothing installed"):]
    reshape = reshape[:reshape.index("return;")]
    assert reshape.count("ft_mc_supersede(&other);") == 2
    assert reshape.index("ft_mc_supersede(&other);") < reshape.index("ft_mc_drop_next(f);")
    assert forget not in reshape
    supersede = function(source, "ft_mc_supersede")
    assert "set[i].superseded = true;" in supersede and "memset" not in supersede
    assert "lockdep_assert_held(&ft_mc_lock)" in supersede
    worker = function(source, "ft_mc_work_fn")
    # An entry taken out of hardware and kept -- only one that was in it,
    # with nothing left to build or the switch off -- or replaced by the
    # shape waiting to take over.
    withdraw = worker[worker.index("if (!build || paused) {"):]
    withdraw = withdraw[:withdraw.index("} else if (hw) {")]
    assert withdraw.index("if (hw) {") < withdraw.index("withdrew = true;")
    assert "if (withdrew || swapped)\n\t\t\tft_mc_forget_seen();" in worker
    # The shape taking over: its old entry is gone once deleted, so the
    # swap is remembered by a flag of its own rather than by the pointer.
    assert "swapped = true;" in worker
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
    upper = upper[:upper.index("break;")]
    # With the bridge it left, when it left one: the deferred deletes of its
    # memberships arrive once it may be another bridge's port.
    assert re.search(r"ft_mc_port_moved\(dev, upper->linking \? NULL :\s+upper->upper_dev\);",
                     upper)
    moved = function(source, "ft_mc_port_moved")
    assert "ft_mc_group_drop(g, dev)" in moved and "g->bridge == left" in moved

    gone = function(source, "ft_mc_device_gone")
    assert gone.index("if (!unregistering) {") < gone.index("ft_mc_drop_port(dev)"), \
        "memberships are let go of only when the device goes"
    assert "ft_mc_drop_port(dev)" in gone, "as a membership's port"
    assert "ft_mc_flow_drop_port(f, dev)" in gone, "as a flow's copy"
    assert "f->in == dev" in gone and "f->gone = true;" in gone, "as an ingress"
    # Whose reference outlives the entry naming it: the backend borrows the
    # ingress and unsubscribes the port's address through it on delete.
    assert "dev_put(f->in)" not in gone
    assert "dev_put(f->in);" in function(source, "ft_mc_flow_free")
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

    The adapter's egress hook counts the change and then marks: each learner's
    mutex in turn and never both, and nothing that needs RTNL or the
    transaction. A group being built while it runs may not be on its learner's
    list to mark; the count, taken before marking, is what both workers
    compare once they record a build, inside the transaction. The DSCP map
    may not leave the port before every marked group is rebuilt, and the
    caller holds RTNL, which both workers take: so each learner's drain
    rebuilds in place, from the chain recorded with the entry.
    """
    source = SOURCE.read_text()
    assert "static void ft_mc_egress_changed(const struct net_device *dev);" in source
    hook = function(source, "ft_egress_changed")
    assert hook.index("atomic64_inc_return(&ft_egress_changes);") < \
        hook.index("ft_mc_egress_changed(dev);")
    body = function(source, "ft_mc_egress_changed")
    assert body.index("ft_mc_egress_mark(dev)") < body.index("ft_mr_egress_mark(dev)")
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
        # Marked stale until a rebuild after the change, not merely picked.
        assert "->egress_stale = true;" in mark
    # The bridged mark asks the chain that was built, routed copies riding
    # it included, rather than what the bridge now says.
    assert "ft_mc_flow_hw_lists(f, dev)" in function(source, "ft_mc_egress_mark")
    # A marked chain is not skipped as an unchanged plan.
    assert "!target->egress_stale" in function(source, "ft_mr_work_fn")
    # Both workers compare the count across a build, inside the transaction.
    assert "atomic64_read(&ft_egress_changes) != changes" in function(source, "ft_mc_work_fn")
    assert "atomic64_read(&ft_egress_changes) != changes" in function(source, "ft_mr_record")
    for worker in ("ft_mc_work_fn", "ft_mr_work_fn"):
        assert "changes = atomic64_read_acquire(&ft_egress_changes);" in \
            function(source, worker)
    # The drains: under the caller's RTNL, so they wait for no worker and
    # take no RTNL; transaction then learner lock; the recorded chain.
    for name, lock, recorded in (("ft_mc_egress_drain", "ft_mc_lock", "&f->hw_spec"),
                                 ("ft_mr_egress_drain", "ft_mr_lock", "&g->hw_spec")):
        drain = function(source, name)
        for forbidden in ("rtnl_lock", "flush_work", "ft_mc_flow_spec(",
                          "ft_mr_derive("):
            assert forbidden not in drain, (name, forbidden)
        assert drain.index("cdx_ft_begin();") < drain.index(f"mutex_lock(&{lock});")
        assert f"cdx_mc_group_replace(" in drain and recorded in drain, name
    assert "mcast_egress_rebuilds" in function(source, "ft_show")
