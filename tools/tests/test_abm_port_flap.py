"""Phase 2 item 4b: bridge port flap under load.

Stimulus-validity gate confirmed: br_stp_disable_port emits
BREVENT_PORT_DOWN under CONFIG_CPE_FAST_PATH (verified =y on the test
image), and is reached when a non-DISABLED bridge slave port goes
down via netif_running/oper_up flipping false. `ip link set <port>
down` on a slave port triggers exactly that path.

Bug class under test: the abm_br_event BREVENT_PORT_DOWN handler at
auto_bridge/auto_bridge.c:305-330 walks l2flow_table[] under
abm_lock, marks matching entries DYING, and queues a netlink DEL
message. Use-after-free or lockdep-class issues in that walk would
surface as splats during the flap; entries leaked on DYING transition
would surface as kmemleak hits filtered to abm symbols.

For the walk to do real work — not vacuously walk an empty table —
the test runs background L2 traffic across the bridge during the
flap. Topology: a LAN-side VLAN subif matching the primary bridge
port (eth4.231) blasts ARP requests at an unused IP in the bridge
subnet; the DUT's bridge floods the broadcasts to the second pseudo-
port (eth4.232), which populates l2flow_table[] entries that the
flap-driven BREVENT walk then sees.

KASAN-eligible per the Phase 2 plan — port-flap teardown is exactly
the kind of memory-class code KASAN catches.
"""

from __future__ import annotations

import asyncio

from _topology import (
    LAN_NIC,
    VLAN_IDS_BRIDGE,
    bridge_with_n_ports,  # noqa: F401  (fixture)
    lan_run,
)


# Filter to abm-only symbols. The broad ASK_KMEMLEAK_FILTER would
# incidentally flag DPAA bpool refills under [auto_bridge]; abm_-prefix
# function needles are the precise ones.
ABM_LEAK_FILTER = ["abm_", "[auto_bridge]"]

# Primary bridge VLAN — matches VLAN_IDS_BRIDGE[0] in the fixture.
PRIMARY_VID    = VLAN_IDS_BRIDGE[0]
LAN_BRIDGE_IF  = f"vlan{PRIMARY_VID}"
LAN_SUBNET     = f"10.99.{PRIMARY_VID}"
LAN_SELF_IP    = f"{LAN_SUBNET}.1"
LAN_TARGET_IP  = f"{LAN_SUBNET}.99"   # unused — ARP fails forever


async def test_abm_port_flap_no_splat_no_leak(
    aiohttp_session, target_agent, lan, splat_window, bridge_with_n_ports,
):
    """Flap each bridge port 3× while abm holds entries in flight.

    Background L2 traffic on a LAN-side VLAN matching one bridge port
    keeps l2flow_table[] populated so the BREVENT_PORT_DOWN walk does
    real work.

    Oracles:
      - splat_window: no KASAN/UBSAN/lockdep/WARN/BUG during the flap.
      - kmemleak filtered to abm symbols: zero new leaks.
    """
    bridge, ports = bridge_with_n_ports

    # Set up LAN-side vlan231 with an IP in the bridge subnet, so its
    # tagged egress ingresses on eth4.231 (a bridge port) on the DUT.
    await lan_run(lan, f"ip link del {LAN_BRIDGE_IF} 2>/dev/null", 5.0)
    r = await lan_run(
        lan,
        f"ip link add link {LAN_NIC} name {LAN_BRIDGE_IF} "
        f"type vlan id {PRIMARY_VID} && "
        f"ip addr add {LAN_SELF_IP}/24 dev {LAN_BRIDGE_IF} && "
        f"ip link set {LAN_BRIDGE_IF} up",
        10.0,
    )
    assert r.rc == 0, f"lan vlan setup failed: {r.stdout!r}"

    # Background ping at 100 Hz to an unused IP in the subnet. The
    # kernel sends ARP requests forever (broadcast on vlan231) — those
    # are exactly the frames the bridge floods, populating l2flow.
    # Foreground until the cleanup, killed via pkill.
    await lan_run(
        lan,
        f"nohup ping -I {LAN_BRIDGE_IF} -i 0.01 -W 0.1 -q "
        f"{LAN_TARGET_IP} > /tmp/abm_flap_ping.log 2>&1 & echo started",
        5.0,
    )

    try:
        # Let the bridge see + classify some traffic before clearing
        # the kmemleak baseline; we don't want the populate step's
        # frees to count against the post-flap scan.
        await asyncio.sleep(1.0)
        await target_agent.kmemleak_clear(aiohttp_session)

        for _ in range(3):
            for port in ports:
                r = await target_agent.exec_cmd(
                    aiohttp_session, ["ip", "link", "set", port, "down"],
                )
                assert r["rc"] == 0, f"set {port} down: {r}"
                # Brief pause so the bridge-stp state machine sees the
                # port-down event and abm_br_event runs to completion.
                await asyncio.sleep(0.3)
                r = await target_agent.exec_cmd(
                    aiohttp_session, ["ip", "link", "set", port, "up"],
                )
                assert r["rc"] == 0, f"set {port} up: {r}"
                await asyncio.sleep(0.3)

        # Let the abm workqueue drain any remaining DEL netlink sends
        # and any deferred frees before kmemleak walks the heap.
        await asyncio.sleep(2.0)

        report = await target_agent.kmemleak(
            aiohttp_session, filter_substrs=ABM_LEAK_FILTER,
        )
        assert report.get("leak_count", 0) == 0, (
            f"port-flap leaked {report['leak_count']} abm-tagged object(s):\n"
            + report.get("report", "")[:4000]
        )
    finally:
        await lan_run(
            lan, f"pkill -f 'ping -I {LAN_BRIDGE_IF}' 2>/dev/null", 5.0,
        )
        await lan_run(lan, f"ip link del {LAN_BRIDGE_IF} 2>/dev/null", 5.0)
