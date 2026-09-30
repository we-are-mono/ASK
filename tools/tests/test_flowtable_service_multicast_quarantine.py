"""A multicast delete whose hardware barrier fails parks what it unlinked.

Withdrawing a group unlinks its classifier key and its listener chain from
tables the FMan microcode may be walking at that moment. Only a successful
host-command barrier proves the walk has left them; until one does, the memory
stays allocated in CDX's quarantine and /proc's `quarantine` counts it. These
cases fail that barrier on purpose while a control group stands, and require:

  - the parked entries to be exactly the withdrawn group's: its root plus one
    per listener for a delete, the displaced chain for a listener swap;
  - the control group and the survivors to keep replicating exactly, in
    hardware, while those entries are parked;
  - the next good barrier to release every one of them, including one the
    flowtable backend issues itself when no multicast delete is left to.

Any completed barrier on the PCD releases the backlog, so parked counts are
read straight after the failure. The windows between stay exact because the
cases that watch them run no unicast offload: no admission or unicast delete
can sync there.

The image is KASAN, and the splat window fails a case whose CPU touches memory
the quarantine should have kept. A walker in the microcode is not something
KASAN can see, which is why the accounting is exact rather than eventual.

Two knobs, because a group delete and a listener swap end on different
barriers. /proc/fm_ehash_hcsync_fail fails the one inside the classifier key's
own delete; /proc/cdx_mc_hcsync_fail fails the one dpa_control_mc.c issues
after unlinking a listener chain. Both read back how many failures remain
armed, and both are disarmed on the way out whatever happened.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import json
import os
import time

import pytest

from _mcast_windows import (COUNT, MulticastRig, bridge_settings, delivered, dut_console, in_hardware,
                            in_software, learn, mcast_rows, mdb, members, moved, mroute_row,
                            multicast_rig, packets, stream, streamed, summary,  # noqa: F401
                            wire_interface)
from _topology import (LAN_NIC, TARGET_LAN_IF, TARGET_WAN_IF, TopologyStack, dut_vlan_subif,
                       lan_vlan_subif)
from test_flowtable_offload import (HEALTH_BASELINE, RX_PORTS_SCRIPT, command, console_command,  # noqa: F401
                                    console_python, hardware_proof, read, rig, status_text,
                                    stop_boot_daemon)
from test_mcast_e2e import _exec, dut_mac, mcast_bridge, wan_source_address  # noqa: F401
from test_mroute_capacity import _daemon

DELETE_BARRIER = "/proc/fm_ehash_hcsync_fail"
SPLICE_BARRIER = "/proc/cdx_mc_hcsync_fail"
# Withdrawn, and standing throughout.
GROUPS = {4: ("239.9.7.1", "239.9.7.2"), 6: ("ff1e::9:7:1", "ff1e::9:7:2")}
SWAP_GROUP = {4: "239.9.7.3", 6: "ff1e::9:7:3"}
SWAP_VID = 323


@asynccontextmanager
async def armed(r, knob, failures):
    present = await r.target.fs_read(r.session, knob)
    if present["errno"]:
        pytest.fail(f"{knob} is missing: this is not the fault-injection test image")
    result = await r.target.fs_write(r.session, knob, str(failures))
    assert result["errno"] == 0, (knob, result)
    try:
        yield
    finally:
        result = await r.target.fs_write(r.session, knob, "0")
        assert result["errno"] == 0, (knob, result)


async def remaining(r, knob):
    return (await read(r.target, r.session, knob)).split()[0]


class Routed:
    """smcroute's MFC: the WAN port in, the LAN port out, a routing hop."""
    kind, hops = "mroute", 63

    def __init__(self, r, ctl, family):
        self.r, self.ctl, self.family = r, ctl, family
        self.source = wan_source_address(family)
        self.observers = [(r.lan, {LAN_NIC: r.dut_lan_mac})]

    def row(self, state, group):
        return mroute_row(state, group, self.source)

    def installed(self, state, group):
        row = self.row(state, group)
        return bool(row) and row["state"] == "installed" and members(row, "listeners") == {f"{TARGET_LAN_IF}/0"}

    async def add(self, *groups):
        for group in groups:
            await self.ctl("add", TARGET_WAN_IF, self.source, group, TARGET_LAN_IF)
        # Carried once Linux has been seen forwarding each: frames first.
        return await learn(self.r, [stream(self.family, g, hops=63) for g in groups],
                           lambda s: all(self.installed(s, g) for g in groups),
                           f"routed {groups} installed")

    async def remove(self, group):
        await self.ctl("remove", TARGET_WAN_IF, self.source, group)

    def withdrawn(self, state, group):
        # Traffic for a withdrawn route can make smcrouted install a negative
        # entry. It has no listeners and stays in software.
        row = self.row(state, group)
        return row is None or (row["state"] == "refused-listener" and row["listeners"] == "-")


class Bridged:
    """A static membership on the snooping bridge; traffic supplies the key."""
    kind, hops = "mcast", 64

    def __init__(self, r, bridge, family):
        self.r, self.bridge, self.family = r, bridge, family
        self.source = wan_source_address(family)
        # The replica's source MAC belongs to the bridged-MAC work, which
        # asserts it on the wire; these cases count copies.
        self.observers = [(r.lan, {LAN_NIC: None})]

    def row(self, state, group):
        rows = mcast_rows(state, group)
        assert len(rows) <= 1, rows
        return rows[0] if rows else None

    def installed(self, state, group):
        row = self.row(state, group)
        return (bool(row) and row["state"] == "installed" and row["in"] == TARGET_WAN_IF and
                members(row, "ports") == {f"{TARGET_LAN_IF}/0"})

    async def add(self, *groups):
        for group in groups:
            await mdb(self.r, self.bridge, group, add=True)
        return await learn(self.r, [stream(self.family, g, hops=64) for g in groups],
                           lambda s: all(self.installed(s, g) for g in groups),
                           f"bridged {groups}")

    async def remove(self, group):
        await mdb(self.r, self.bridge, group, add=False)

    def withdrawn(self, state, group):
        return self.row(state, group) is None


async def withdrawal(r, learner, family):
    """The shared body: a failed delete parks, a good one releases."""
    target, control = GROUPS[family]
    installed = learner.kind + "_installed"

    def window(groups, label):
        return r.window([stream(family, g, hops=learner.hops) for g in groups], learner.observers,
                        ingress=TARGET_WAN_IF, label=f"quarantine-{learner.kind}-v{family}-{label}")

    def row(group):
        return lambda state: learner.row(state, group)

    await learner.add(target, control)
    both = await window([target, control], "baseline")
    for group in (target, control):
        assert delivered(both, streamed(both, group), LAN_NIC), group
        assert moved(both, row(group)) == COUNT, (group, summary(both["after"]))
    in_hardware(both, streams=2)

    before = await r.proc()
    assert before["quarantine"] == 0, summary(before)
    async with armed(r, DELETE_BARRIER, 1):
        await learner.remove(target)
        # The count drops after the delete returns, and /proc reads under the
        # same transaction, so whatever the delete parked is visible by then.
        parked = await r.settle(lambda s: s[installed] == before[installed] - 1,
                                f"{target} withdrawn from hardware")
        assert await remaining(r, DELETE_BARRIER) == "armed=0", "the delete never reached its barrier"
    assert learner.withdrawn(parked, target), summary(parked)
    # The classifier key and its one listener entry: unlinked, not freed.
    assert parked["quarantine"] == 2, summary(parked)
    assert learner.installed(parked, control), summary(parked)

    # The survivor replicates exactly while the withdrawn group's entries sit
    # parked; the withdrawn stream now reaches the CPU and nothing else.
    after = await window([target, control], "parked")
    assert not delivered(after, streamed(after, target), LAN_NIC)
    assert delivered(after, streamed(after, control), LAN_NIC)
    assert moved(after, row(control)) == COUNT, summary(after["after"])
    in_software(after)
    assert after["stream_cpu"] < COUNT * 1.1, (after["stream_cpu"], after["cpu"], after["idle"])
    # No barrier ran in that window, so nothing may have been released.
    assert after["after"]["quarantine"] == 2, summary(after["after"])
    assert learner.withdrawn(after["after"], target), summary(after["after"])

    # The next good barrier is the next delete that reaches one. It releases
    # everything parked before it, not only its own entries.
    await learner.remove(control)
    released = await r.settle(lambda s: s[installed] == r.initial[installed],
                              f"{control} withdrawn from hardware")
    assert released["quarantine"] == 0, summary(released)
    assert learner.withdrawn(released, control), summary(released)

    # The key the failed delete gave up installs again and carries traffic.
    await learner.add(target)
    again = await window([target], "reinstalled")
    assert delivered(again, streamed(again, target), LAN_NIC)
    assert moved(again, row(target)) == COUNT, summary(again["after"])
    in_hardware(again)
    await learner.remove(target)
    final = await r.settle(lambda s: s[installed] == r.initial[installed], f"{target} withdrawn")
    assert final["quarantine"] == 0, summary(final)
    for counter in ("mcast_install_errors", "mroute_install_errors"):
        assert final[counter] == r.initial[counter], (counter, summary(final))


@pytest.mark.parametrize("family", [4, 6])
async def test_flowtable_service_multicast_quarantine_routed(multicast_rig, family):
    r = multicast_rig
    async with _daemon(r.target, r.session, [TARGET_WAN_IF, TARGET_LAN_IF]) as ctl:
        await withdrawal(r, Routed(r, ctl, family), family)


@pytest.mark.parametrize("family", [4, 6])
async def test_flowtable_service_multicast_quarantine_bridged(multicast_rig, mcast_bridge, family):
    r = multicast_rig
    # A querier that counts in both families, so a withdrawn group is no
    # longer flooded to the port it left.
    async with bridge_settings(r, mcast_bridge):
        await withdrawal(r, Bridged(r, mcast_bridge, family), family)


@pytest.mark.parametrize("family", [4, 6])
async def test_flowtable_service_multicast_quarantine_listener_swap(multicast_rig, family):
    """One of two listeners goes and the swap's barrier fails.

    The group stays installed: the root entry now names the survivor's chain
    and has not left the table, so frames keep matching throughout. The
    displaced chain is what is parked, both of its entries, and the group's
    own delete is the good barrier that releases them."""
    r = multicast_rig
    group, source = SWAP_GROUP[family], wan_source_address(family)
    untagged, tagged = f"{TARGET_LAN_IF}/0", f"{TARGET_LAN_IF}/{SWAP_VID}"
    topology = TopologyStack()
    try:
        oif = await dut_vlan_subif(topology, r.target, r.session, parent=TARGET_LAN_IF, vid=SWAP_VID,
                                   ipv4="198.18.163.1/24", ipv6="fd00:163::1/64")
        peer = await lan_vlan_subif(topology, r.lan, parent=LAN_NIC, vid=SWAP_VID)
        observers = [(r.lan, {LAN_NIC: r.dut_lan_mac, peer: r.dut_lan_mac})]
        async with _daemon(r.target, r.session, [TARGET_WAN_IF, TARGET_LAN_IF, oif]) as ctl:
            await ctl("add", TARGET_WAN_IF, source, group, TARGET_LAN_IF, oif)

            def carried(state, listeners):
                row = mroute_row(state, group, source)
                return bool(row) and row["state"] == "installed" and members(row, "listeners") == listeners

            await learn(r, [stream(family, group, hops=63)],
                        lambda s: carried(s, {untagged, tagged}), "two listeners installed")
            both = await r.window([stream(family, group, hops=63)], observers,
                                  ingress=TARGET_WAN_IF, label=f"swap-{family}-both")
            # What the tail of the confirming burst left on the root.
            base = packets(mroute_row(both["before"], group, source))
            assert delivered(both, both["streams"][0], LAN_NIC)
            assert delivered(both, both["streams"][0], peer)
            in_hardware(both)

            before = await r.proc()
            assert before["quarantine"] == 0, summary(before)
            async with armed(r, SPLICE_BARRIER, 1):
                # The VIF goes with its device and the group is re-derived
                # onto the listener that is left: a chain swap, not a delete.
                await command(r.target, r.session, "ip", "link", "del", oif)
                swapped = await r.settle(lambda s: carried(s, {untagged}), "the swap to one listener")
                assert (await remaining(r, SPLICE_BARRIER)).startswith("armed=0"), \
                    "the swap never reached its barrier"
            assert swapped["mroute_installed"] == before["mroute_installed"], summary(swapped)
            # Never out of hardware on the way: a group taken out and put back
            # also ends on one listener with the count it had, but under an
            # entry added again, which its own row counts. The global refusal
            # count would not say so: it moves for any group, smcrouted's
            # listener-less entries for what the WAN VIF hears among them.
            now, then = mroute_row(swapped, group, source), mroute_row(before, group, source)
            assert now and then and now["adds"] == then["adds"], summary(swapped)
            assert swapped["mroute_install_errors"] == before["mroute_install_errors"], \
                summary(swapped)
            assert swapped["quarantine"] == 2, summary(swapped)

            survivor = await r.window([stream(family, group, hops=63)], observers,
                                      ingress=TARGET_WAN_IF, label=f"swap-{family}-survivor")
            assert delivered(survivor, survivor["streams"][0], LAN_NIC)
            assert not delivered(survivor, survivor["streams"][0], peer)
            in_hardware(survivor)
            # The same root counted both windows: it never left the table.
            assert packets(mroute_row(survivor["after"], group, source)) == base + 2 * COUNT, \
                summary(survivor["after"])
            assert survivor["after"]["quarantine"] == 2, summary(survivor["after"])

            await ctl("remove", TARGET_WAN_IF, source, group)
            released = await r.settle(lambda s: mroute_row(s, group, source) is None and
                                      s["mroute_installed"] == r.initial["mroute_installed"],
                                      "the group's own delete")
            assert released["quarantine"] == 0, summary(released)
    finally:
        await topology.teardown("listener swap quarantine")


async def test_flowtable_service_multicast_quarantine_released_without_multicast(multicast_rig, rig):
    """The only group is withdrawn and its barrier fails, so no multicast
    delete is left to release what it parked.

    The flowtable backend refuses every new unicast entry, and the adapter's
    load, while anything is parked, so it retries the barrier itself. A fresh
    unicast flow's admission releases the backlog and is admitted, with no
    multicast operation in between; parked a second time with nothing bound,
    the adapter's unload releases it and the adapter loads again. Both used to
    wait for an unrelated multicast or IPsec delete that might never come."""
    m, r = multicast_rig, rig
    group = GROUPS[4][0]
    async with _daemon(r.target, r.session, [TARGET_WAN_IF, TARGET_LAN_IF]) as ctl:
        learner = Routed(m, ctl, 4)

        async def park(label):
            await learner.add(group)
            before = await m.proc()
            assert before["quarantine"] == 0 and before["mroute_installed"] == 1, summary(before)
            async with armed(m, DELETE_BARRIER, 1):
                await learner.remove(group)
                parked = await m.settle(lambda s: s["mroute_installed"] == 0,
                                        f"{group} withdrawn from hardware before the {label}")
                assert await remaining(m, DELETE_BARRIER) == "armed=0", "the delete never reached its barrier"
            # The classifier key and its one listener entry, read before any
            # later barrier on the PCD could release them.
            assert learner.withdrawn(parked, group) and parked["quarantine"] == 2, summary(parked)
            return parked

        parked = await park("admission")
        await r.table()
        # Binding alone issues no barrier: the flow's admission has to.
        bound = await r.state()
        assert bound["quarantine"] == 2 and bound["entries"] == 0, bound
        # Admission retries at most once a second, so a flow it declined is
        # offered again on a later refresh: keep traffic flowing. An XFRM
        # policy anywhere in the namespace bypasses the software fast path and
        # defers that offer to the flow's 30-second expiry.
        deadline = time.monotonic() + 45
        while True:
            await r.exchange(32, promiscuous=False)
            admitted = await r.state()
            if admitted["entries"] == 2:
                break
            assert time.monotonic() < deadline, admitted
        assert admitted["quarantine"] == 0 and admitted["errors"] == parked["errors"], admitted
        for counter in ("mroute_groups", "mroute_installed", "mcast_groups", "mcast_installed",
                        "mroute_install_errors", "mcast_install_errors"):
            assert admitted[counter] == parked[counter], (counter, summary(parked), summary(admitted))
        admitted = await hardware_proof(r)
        drained = await r.delete_table()
        assert drained["quarantine"] == 0 and drained["errors"] == parked["errors"], drained

        await park("reload")
        # Nothing multicast is left installed for the unload to delete: that
        # delete's own barrier would release the backlog, and an unload that
        # never retries one would pass anyway.
        idle = await m.proc()
        assert idle["mcast_installed"] == idle["mroute_installed"] == 0, summary(idle)
        assert idle["quarantine"] == 2, summary(idle)
        console = await dut_console("quarantine-reload")
        try:
            await console_command(console, "rmmod", "ask_flowtable", timeout=30)
            try:
                # CDX's own read-back, the adapter's being gone with it.
                between = await console_command(console, "cat", "/proc/cdx_mc_hcsync_fail")
            finally:
                loaded = await console_command(console, "modprobe", "ask_flowtable", timeout=30, check=False)
        finally:
            console.close()
        assert "pending=0" in between["stdout"].split(), between
        assert loaded["rc"] == 0, loaded
        reloaded = await m.proc()
        assert reloaded["quarantine"] == reloaded["fatal"] == reloaded["bindings"] == 0, summary(reloaded)
        # The reload restarted the error count; health is measured from it.
        HEALTH_BASELINE["errors"] = reloaded["errors"]
        m.record("mcast-quarantine-released", {"parked": summary(parked), "admitted": summary(admitted),
                                               "unloaded": between["stdout"], "reloaded": summary(reloaded)})


UNLINK_FAULT = "/sys/module/cdx/parameters/ehash_fail_unlink"


@pytest.mark.skipif(os.environ.get("ASK_FLOWTABLE_TERMINAL") != "mcast-unlink",
                    reason="explicit terminal lifecycle test; fresh boot required")
async def test_flowtable_service_multicast_unproven_delete_is_terminal(target_agent, aiohttp_session, lan):
    """A group delete that cannot prove its unlink fail-stops the datapath.

    The cases above fail the barrier after the key has left the table, so its
    entries can be parked. This one fails the delete before the unlink
    (ehash_fail_unlink): the root may still resolve and replicate through a
    listener chain nothing owns any more -- the state a unicast -EIO latches --
    so it must latch the same way: terminal, with the ports stopped, rather
    than a leaked root replicating to a revoked listener while /proc calls the
    group gone.

    Terminal: the ports stop and take the management path with them, so every
    read after the withdrawal goes over the UART and nothing is restored; the
    reset the DUT then demands is the restoration. No fixture that tears down
    over the agent is used, and smcrouted is left to that reset."""
    await stop_boot_daemon()
    r = MulticastRig(target_agent, aiohttp_session, lan)
    r.initial = await r.proc()
    assert r.initial["fatal"] == r.initial["mroute_groups"] == 0, summary(r.initial)
    # No unicast binding either: its invalidation pass also drives recovery,
    # and would stop the ports even if the multicast latch never did.
    assert r.initial["bindings"] == r.initial["entries"] == 0, summary(r.initial)
    present = await r.target.fs_read(r.session, UNLINK_FAULT)
    if present["errno"]:
        pytest.fail(f"{UNLINK_FAULT} is missing: this is not the fault-injection test image")
    r.wire = wire_interface()
    r.dut_lan_mac = await dut_mac(target_agent, aiohttp_session, TARGET_LAN_IF)
    name = "ask-smcroute-terminal"
    config = f"/tmp/{name}.conf"
    result = await r.target.fs_write(r.session, config, "".join(
        f"phyint {dev} enable\n" for dev in (TARGET_WAN_IF, TARGET_LAN_IF)))
    assert result.get("errno", 0) == 0, result
    await _exec(r.target, r.session, "smcrouted", "-N", "-i", name, "-f", config, "-l", "notice")

    async def ctl(*args, check=True):
        return await _exec(r.target, r.session, "smcroutectl", "-i", name, *args, check=check)

    for _ in range(30):
        if (await ctl("show", "routes", check=False))["rc"] == 0:
            break
        await asyncio.sleep(0.1)
    else:
        raise AssertionError("smcrouted failed to own the default routing table")

    family = 4
    target, control = GROUPS[family]
    learner = Routed(r, ctl, family)
    live = await learner.add(target, control)
    assert learner.installed(live, target) and learner.installed(live, control), summary(live)
    # The ports stop from a work item, after the withdrawal returns, and its
    # printk would land inside whichever console read is running then. dmesg
    # keeps every line for the assertions below; the reset restores the level.
    await command(r.target, r.session, "sysctl", "-w", "kernel.printk=1 4 1 7")
    console = await dut_console("mcast-terminal")
    try:
        assert json.loads((await console_python(console, RX_PORTS_SCRIPT))["stdout"]) == {"6": 1, "7": 1}
        # Armed over the agent while it still reaches the DUT; the withdrawal
        # that consumes it is the last command the management path carries.
        result = await r.target.fs_write(r.session, UNLINK_FAULT, "1")
        assert result["errno"] == 0, result
        await learner.remove(target)
        deadline = time.monotonic() + 15
        while True:
            stopped = status_text((await console_command(console, "cat", "/proc/cdx_flowtable"))["stdout"].strip())
            ports = json.loads((await console_python(console, RX_PORTS_SCRIPT))["stdout"])
            if stopped["fatal"] == 1 and ports == {"6": 0, "7": 0}:
                break
            assert time.monotonic() < deadline, (summary(stopped), ports)
            await asyncio.sleep(0.2)
        # The adapter let the withdrawn group go; the hardware may not have,
        # which is why the stopped ports and not /proc are the proof.
        assert stopped["mroute_installed"] == live["mroute_installed"] - 1, summary(stopped)
        knob = (await console_command(console, "cat", UNLINK_FAULT))["stdout"].strip()
        assert knob == "0", knob
        log = (await console_command(console, "dmesg"))["stdout"]
        assert log.count("classifier delete failed pre-unlink") == 1, log
        assert "hardware stopped after unproven deletion; reboot required" in log, log
        assert "BUG: KASAN" not in log, log
        r.record("mcast-terminal", {"live": summary(live), "stopped": summary(stopped),
                                    "ports": ports, "dmesg": log})
    finally:
        console.close()
