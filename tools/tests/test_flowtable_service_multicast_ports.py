"""Routed multicast under a ruleset that tells a group's streams apart by port.

A routed group is carried under its source and group alone -- the classifier
key stops at L3 -- and only once Linux has been seen forwarding a copy of it
to every oif. A copy on one UDP port says nothing of a stream on another, so a
rule that treats the ports differently keeps the group in software
(refused-ports) where Linux judges every packet: the port it drops receives
nothing, the one it forwards receives everything. A rule that reads ports but
cannot change the stream's fate -- fw4's ISAKMP accept ahead of the group's
own -- keeps nothing out of hardware. The rule gone, the group is carried with
every port again.
"""
from __future__ import annotations

import pytest

from _mcast_windows import (COUNT, OTHER_PORT, PORT, delivered, in_hardware, in_software, learn,
                            members, moved, mroute_row, multicast_rig, stream,  # noqa: F401
                            streamed, summary)
from _topology import LAN_NIC, TARGET_LAN_IF, TARGET_WAN_IF, TopologyStack, dut_vlan_subif, lan_vlan_subif
from test_flowtable_offload import command
from test_mcast_e2e import wan_source_address
from test_mroute_capacity import _daemon

PORTS_GROUP = {4: "239.9.11.1", 6: "ff1e::9:11:1"}
PORTS_TABLE = "ask_ft_mr_ports"
# The second stream's port: the one the splitting rules single out.
OTHER = OTHER_PORT
# The second oif, tagged on the LAN port, which the oif case drops the other
# port toward; claimed in _topology.
PORTS_VID = 327
# What each case's rule does: which (port, oif) pairs Linux forwards.
KINDS = ["forward-drop", "prerouting-allow", "oif-drop", "control"]


def ruleset(family, group, kind, oif):
    match = "ip daddr" if family == 4 else "ip6 daddr"
    if kind == "forward-drop":
        chain = f'''chain forward {{ type filter hook forward priority filter; policy accept;
  {match} {group} udp dport {OTHER} drop
 }}'''
    elif kind == "prerouting-allow":
        chain = f'''chain prerouting {{ type filter hook prerouting priority filter; policy accept;
  {match} {group} udp dport {PORT} accept
  {match} {group} drop
 }}'''
    elif kind == "oif-drop":
        chain = f'''chain forward {{ type filter hook forward priority filter; policy accept;
  oifname "{oif}" {match} {group} udp dport {OTHER} drop
 }}'''
    else:
        # fw4's shape: established traffic first, a port rule for another
        # stream, the group's own accept, and every other multicast stream
        # dropped. Every path this group can take accepts, whatever its ports.
        chain = f'''chain forward {{ type filter hook forward priority filter; policy accept;
  ct state established,related accept
  meta l4proto udp udp dport 500 accept
  {match} {group} accept
  meta pkttype multicast drop
 }}'''
    return f"table inet {PORTS_TABLE} {{\n {chain}\n}}"


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("family", [4, 6])
async def test_flowtable_service_multicast_routed_follows_ports(multicast_rig, family, kind):
    """Two streams of one (S,G) on two ports, to two oifs, under a rule that may split them.

    Splitting rules: the group is confirmed by the port Linux forwards and
    then refused, so the whole group stays in software and every (port, oif)
    Linux drops receives nothing; the rule gone, both ports are carried to
    both oifs in hardware. The control: carried from the start, both ports
    delivered to both oifs by the classifier."""
    r = multicast_rig
    group, source = PORTS_GROUP[family], wan_source_address(family)
    untagged, tagged = f"{TARGET_LAN_IF}/0", f"{TARGET_LAN_IF}/{PORTS_VID}"
    splits = kind != "control"
    topology = TopologyStack()
    tabled = False

    def row(state):
        return mroute_row(state, group, source)

    def carried(state):
        current = row(state)
        return (bool(current) and current["state"] == "installed" and
                members(current, "listeners") == {untagged, tagged})

    def refused(state):
        current = row(state)
        return bool(current) and current["state"] == "refused-ports"

    def forwarded(port, iface):
        """Whether Linux forwards `port` to the oif `iface` observes."""
        if port == PORT or kind == "control":
            return True
        return kind == "oif-drop" and iface == LAN_NIC

    configs = [stream(family, group, hops=63), stream(family, group, hops=63, port=OTHER)]

    try:
        oif = await dut_vlan_subif(topology, r.target, r.session, parent=TARGET_LAN_IF,
                                   vid=PORTS_VID, ipv4="198.18.170.1/24", ipv6="fd00:170::1/64")
        peer = await lan_vlan_subif(topology, r.lan, parent=LAN_NIC, vid=PORTS_VID)
        observers = [(r.lan, {LAN_NIC: r.dut_lan_mac, peer: r.dut_lan_mac})]

        async def window(label, ruled):
            result = await r.window(configs, observers, ingress=TARGET_WAN_IF,
                                    label=f"ports-{kind}-v{family}-{label}")
            for port in (PORT, OTHER):
                config = streamed(result, group, port=port)
                for iface in (LAN_NIC, peer):
                    expected = forwarded(port, iface) if ruled else True
                    assert delivered(result, config, iface) == expected, (port, iface, label)
            return result

        async with _daemon(r.target, r.session, [TARGET_WAN_IF, TARGET_LAN_IF, oif]) as ctl:
            # Owned before it exists: a cancellation after the commit still
            # takes it down.
            tabled = True
            await command(r.target, r.session, "nft", ruleset(family, group, kind, oif))
            await ctl("add", TARGET_WAN_IF, source, group, TARGET_LAN_IF, oif)
            await learn(r, configs[:1], refused if splits else carried,
                        "refused for its ports" if splits else "carried whatever its ports")
            first = await window("ruled", ruled=True)
            if splits:
                in_software(first, streams=2)
                assert refused(first["after"]), summary(first["after"])
                assert first["after"]["mroute_installed"] == r.initial["mroute_installed"], \
                    summary(first["after"])
            else:
                in_hardware(first, streams=2)
                assert moved(first, row) == 2 * COUNT, summary(first["after"])

            before = await r.proc()
            await command(r.target, r.session, "nft", "delete", "table", "inet", PORTS_TABLE)
            tabled = False
            # A commit, which takes every confirmation back once the learner
            # has seen it: a group carried under the rule would otherwise
            # read as carried again before it was taken out.
            await r.settle(lambda s: s["mroute_ruleset_changes"] > before["mroute_ruleset_changes"],
                           "the rule's removal seen")
            await learn(r, configs[:1], carried, "carried once the rule is gone")
            second = await window("unruled", ruled=False)
            in_hardware(second, streams=2)
            assert moved(second, row) == 2 * COUNT, summary(second["after"])

            await ctl("remove", TARGET_WAN_IF, source, group)
            final = await r.settle(lambda s: row(s) is None and
                                   s["mroute_installed"] == r.initial["mroute_installed"],
                                   "the route removed")
        assert final["quarantine"] == 0, summary(final)
        assert final["mroute_install_errors"] == r.initial["mroute_install_errors"], summary(final)
        assert final["mroute_port_probe_errors"] == r.initial["mroute_port_probe_errors"], \
            summary(final)
    finally:
        if tabled:
            await command(r.target, r.session, "nft", "delete", "table", "inet", PORTS_TABLE,
                          check=False)
        await topology.teardown("routed ports")
