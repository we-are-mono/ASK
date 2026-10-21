"""IPTV through a stacked bridge, as OpenWrt bridges it (A412).

The WAN port's IPTV VLAN device and the LAN bridge's VLAN device for the same
VLAN are the ports of a bridge of their own, which snoops and queries; the LAN
bridge filters VLANs, carries the IPTV VLAN tagged to the set-top boxes, and
does not snoop. On router.zaman.io that is

    br-iptv = { eth4.3999, br-lan.3999 }    br-lan = { eth2, eth3 }, 3999 tagged

and the stream was forwarded in software, its membership `pending-source`: the
learner keyed a flow only on a bridge port that was itself a physical port, and
replicated only to one. The entry that carries it is an ordinary one -- the WAN
port keyed on the tag its VLAN device strips, a copy out of the LAN port tagged
as br-lan tags it -- and this case asserts that it is installed, that every
frame arrives exactly once, and that the CPU sees next to none of them.

The WAN VLAN has to reach the DUT's WAN port tagged, which on this bench only
the standing 3900 does (_topology.py); nothing is created or deleted on the
orchestrator's side of it, and ASK_IPTV_WAN_VID names another where the switch
trunks one. The LAN keeps the router's 3999, so the copies are also seen to
leave with br-lan's tag rather than the one the stream arrived with. The group
is a test one, so a stray frame is nobody's channel.
"""
from __future__ import annotations

from contextlib import AsyncExitStack
import os

import pytest

from _flowtable_rig import command
from _mcast_e2e import mdb_reports_offload, wan_source_address
from _mcast_windows import (COUNT, bridge_settings, delivered, host, in_hardware, learn,
                            mcast_rows, mdb_ports, moved, same, stream, streamed, summary)
from _topology import (LAN_NIC, OPENWRT_LAN_VID, TARGET_LAN_IF, TARGET_WAN_IF, VLAN_ID_PPPOE_WAN,
                       TopologyStack, dut_vlan_subif, lan_vlan_subif, openwrt_lan)

WAN_VID = int(os.environ.get("ASK_IPTV_WAN_VID", str(VLAN_ID_PPPOE_WAN)))
LAN_VID = 3999
BRIDGE = "br-iptv"
GROUP = "239.9.14.1"
# The set-top box's side: an address of its own, or rp_filter drops what the
# VLAN device receives from a source it has no route back to through it.
LAN_ADDRESS = "198.18.114.2/24"
# The router's own join, IGMPv2 for any source, and an SSM receiver's.
MECHANISMS = {
    "igmpv2": {"version": 2, "mode": "asm"},
    "igmpv3-ssm": {"version": 3, "mode": "ssm"},
}


@pytest.mark.rfc("4541")
@pytest.mark.parametrize("mechanism", MECHANISMS)
async def test_iptv_through_a_stacked_bridge(multicast_rig, mechanism):
    """The router's IPTV bridge, carried in hardware end to end."""
    r = multicast_rig
    spec = MECHANISMS[mechanism]
    source = wan_source_address(4)
    wan_port = f"{TARGET_WAN_IF}.{WAN_VID}"
    lan_if = f"vlan{LAN_VID}"

    async def dut(*argv, check=True):
        return await command(r.target, r.session, *argv, check=check)

    def carried(state):
        """The installed row replicating this stream, if there is one."""
        rows = [row for row in mcast_rows(state, GROUP)
                if row["state"] == "installed" and same(row["src"], source)]
        assert len(rows) <= 1, rows
        return rows[0] if rows else None

    stack = TopologyStack()
    try:
        # br-lan as the router has it: VLAN-aware, the router's address on
        # br-lan.1, the IPTV VLAN tagged on the set-top box's port and on the
        # bridge itself, which br-lan.<vid> sends through -- and no snooping.
        lan = await openwrt_lan(stack, r.target, r.session, vid=OPENWRT_LAN_VID, lan=r.lan)
        await dut("ip", "link", "set", lan["bridge"], "type", "bridge", "mcast_snooping", "0")
        await dut("bridge", "vlan", "add", "dev", TARGET_LAN_IF, "vid", str(LAN_VID))
        await dut("bridge", "vlan", "add", "dev", lan["bridge"], "vid", str(LAN_VID), "self")

        # br-iptv over the WAN port's VLAN device and br-lan's.
        await dut("ip", "link", "del", BRIDGE, check=False)
        await dut("ip", "link", "add", "name", BRIDGE, "type", "bridge", "mcast_snooping", "1",
                  "mcast_querier", "1", "mcast_igmp_version", str(spec["version"]))

        async def _drop_bridge():
            return await dut("ip", "link", "del", BRIDGE, check=False)
        stack.push(_drop_bridge)
        await dut_vlan_subif(stack, r.target, r.session, parent=TARGET_WAN_IF, vid=WAN_VID,
                             master=BRIDGE)
        lan_port = await dut_vlan_subif(stack, r.target, r.session, parent=lan["bridge"],
                                        vid=LAN_VID, master=BRIDGE)
        await dut("ip", "link", "set", BRIDGE, "up")
        await lan_vlan_subif(stack, r.lan, parent=LAN_NIC, vid=LAN_VID, name=lan_if,
                             ipv4=LAN_ADDRESS)

        config = stream(4, GROUP, hops=64, vlan=WAN_VID)
        async with AsyncExitStack() as scope:
            await scope.enter_async_context(bridge_settings(r, BRIDGE))
            await scope.enter_async_context(host(
                r.lan, family=4, group=GROUP, iface=lan_if, mode=spec["mode"],
                version=spec["version"]))
            learned = await learn(r, [config], lambda s: carried(s) is not None,
                                  f"{mechanism}: the stream through br-iptv")
            row = carried(learned)
            # Keyed where the stream arrives on br-iptv, copied out of the port
            # below br-lan.<vid>, tagged as br-lan tags it.
            assert row["br"] == BRIDGE and row["in"] == wan_port, row
            assert row["ports"] == f"{TARGET_LAN_IF}/{LAN_VID}", row
            # The membership is br-lan.<vid>'s, and the bridge is told the
            # hardware took it on.
            assert lan_port in await mdb_ports(r, BRIDGE, GROUP)
            assert await mdb_reports_offload(r.target, r.session, GROUP)

            window = await r.window([config], [(r.lan, {lan_if: None})], ingress=TARGET_WAN_IF,
                                    label=f"stacked-bridge-{mechanism}")
            assert delivered(window, streamed(window, GROUP), lan_if)
            assert moved(window, carried) == COUNT, summary(window["after"])
            in_hardware(window)
            assert window["after"]["mcast_install_errors"] == r.initial["mcast_install_errors"], \
                summary(window["after"])

        # The set-top box left: the flow goes with its membership.
        final = await r.settle(lambda s: not mcast_rows(s, GROUP),
                               f"{mechanism}: the group's flow retired")
        assert final["quarantine"] == 0, summary(final)
    finally:
        await stack.teardown("stacked-bridge")
