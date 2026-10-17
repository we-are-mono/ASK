"""Re-admit current MTUs through an unchanged table and established TCP socket,
and carry every IPv4 UDP direction the microcode would have to fragment through
the offline-port detour, whose fragments are whole (A385)."""
from __future__ import annotations

from _flowtable_mtu import (SMALL_PATH, carried, current_mtus, detour_df, detour_fragments,
                            detour_handback, detour_overload, detour_ttl, fragmenter,
                            table_identity, udp_size, udp_warm)

import asyncio
import json
import os
import socket

import pytest

from ask_orch.client import Agent
from _topology import LAN_NIC, TARGET_LAN_IF, TARGET_WAN_IF, lan_run_python
from _flowtable_connections import (FLOWS, by_key, peer)
from _flowtable_rig import (DPORT, SPORT, WAN_IP, command, read)
from _flowtable_selective_neighbour import (hardware, keys, warm)
from _flowtable_tcp import (connection, hardware_transfer, installed, software_tx, tcp_table)


async def test_recovery(connections):
    r = connections
    flows = [{**f, "lan": r.lan_ip} for f in FLOWS[:2]]
    ids, sport = [0, 1], flows[0]["sport"]
    original = {dev: int((await read(r.target, r.session, f"/sys/class/net/{dev}/mtu")).strip())
                for dev in (TARGET_LAN_IF, TARGET_WAN_IF)}
    assert all(mtu == 1500 for mtu in original.values()), original
    mtus = dict(original)
    identity = await table_identity(r)
    boot_id = await read(r.target, r.session, "/proc/sys/kernel/random/boot_id")
    echo_socket = r.echo.transport.get_extra_info("socket")
    pmtu_option = getattr(socket, "IP_MTU_DISCOVER", 10)
    echo_pmtu = echo_socket.getsockopt(socket.SOL_IP, pmtu_option)
    try:
        async with peer(r, flows) as p:
            await warm(r, p, ids, "mtu-initial-admission", flows)
            initial = await hardware(r, p, "mtu-initial-hardware", flows)
            current_mtus(initial, mtus)
            # Exercise decrease and increase on each side. No conntrack flush,
            # flowtable recreation, adapter reload or socket reopen is allowed.
            # All four directions come back at the new MTUs; while a port is
            # below a full frame, the UDP one leaving by it -- the other port
            # can still deliver 1500 bytes -- through the detour.
            for dev in (TARGET_LAN_IF, TARGET_WAN_IF):
                for mtu in (1400, original[dev]):
                    before, tx_before = await r.state(), await software_tx(r)
                    await p.rpc("start", ids, count=0, interval=0.01)
                    await command(r.target, r.session, "ip", "link", "set", "dev", dev, "mtu", str(mtu))
                    mtus[dev] = mtu
                    expected = keys(ids, carried(flows, mtus))
                    after = await r.wait(lambda s: by_key(s).keys() == expected
                                         and s["deletes"] >= before["deletes"] + before["entries"]
                                         and all(int(f["mtu"]) == mtus[f["out"]] for f in s["flows"]))
                    reports = await p.rpc("stop", ids)
                    tx_after = await software_tx(r)
                    current_mtus(after, mtus)
                    # This case changes an MTU under RTNL while traffic is
                    # flowing, so an admission can lose rtnl_trylock and
                    # decline with -EAGAIN. With no IPsec policy configured
                    # that retires nothing -- the software path offers the
                    # flow again about a second later -- so whatever busy
                    # reads, the installs and deletes are exactly the
                    # directions this is counting.
                    assert after["installs"] == before["installs"] + len(expected), (before, after)
                    assert after["deletes"] == before["deletes"] + before["entries"], (before, after)
                    assert after["mtu_invalidations"] == before["mtu_invalidations"] + 2, (before, after)
                    assert after["rearms"] == initial["rearms"] and not after["invalidation_done"], after
                    assert all(report["count"] > 0 for report in reports.values()), reports
                    assert await table_identity(r) == identity
                    label = f"mtu-{dev}-{mtu}"
                    r.record(label, {"before": before, "after": after, "transfers": reports,
                                     "software_tx": {d: tx_after[d] - tx_before[d] for d in tx_before},
                                     "table": identity})
                    await hardware(r, p, label + "-hardware", carried(flows, mtus))

        # The TCP peer has closed cleanly.
        # Keep the same table and UDP tuple for the MTU boundary itself. The
        # WAN endpoint can retain PMTU from the earlier TCP transitions; make
        # its UDP replies probe the path too, rather than fragment there.
        wan = Agent("wan", f"http://{os.environ.get('ASK_WAN_IP', '127.0.0.1')}:9110")
        endpoint_route = await command(wan, r.session, "ip", "-j", "route", "get", r.lan_ip)
        r.record("mtu-endpoint-pmtu", {"route": json.loads(endpoint_route["stdout"]),
                                      "echo_pmtu_discover": echo_pmtu})
        echo_socket.setsockopt(socket.SOL_IP, pmtu_option, 3)  # IP_PMTUDISC_PROBE
        # Below a full frame on the WAN port, the upload's path no longer
        # carries what the LAN port can deliver, so it takes the detour: a
        # datagram exactly at the new MTU crosses it in hardware, one byte
        # more with DF gets Linux's own Fragmentation Needed, handed over by
        # the receive entry, and the download stays as it is throughout.
        await command(r.target, r.session, "ip", "link", "set", "dev", TARGET_WAN_IF, "mtu", "1400")
        mtus[TARGET_WAN_IF] = 1400
        detoured = await udp_warm(r, sport, mtus)
        assert [f["detour"] for f in sorted(detoured["flows"], key=lambda f: f["in"])] == ["1", "0"], detoured
        await udp_size(r, sport, 1372, "mtu-exact-boundary", mtus)
        probe = b"ASK-mtu-boundary".ljust(1373, b".")
        script = f'''
import json
from scapy.all import Ether, IP, UDP, ICMP, Raw, srp1
packet = Ether(dst={r.dut_lan_mac!r})/IP(src={r.lan_ip!r}, dst={WAN_IP!r}, flags='DF')/UDP(sport={sport}, dport={DPORT})/Raw({probe!r})
answer = srp1(packet, iface={LAN_NIC!r}, timeout=3, verbose=False)
assert answer is not None and ICMP in answer, answer
assert (answer[ICMP].type, answer[ICMP].code, answer[ICMP].nexthopmtu) == (3, 4, 1400), answer.show(dump=True)
print(json.dumps({{'type': answer[ICMP].type, 'code': answer[ICMP].code, 'mtu': answer[ICMP].nexthopmtu}}))
'''
        result = await lan_run_python(r.lan, script, timeout=15, label="flowtable_mtu_boundary")
        assert result.rc == 0, result.stdout
        assert not r.echo.received[probe], "oversized DF packet bypassed the new MTU"
        r.record("mtu-oversized-df", json.loads(result.stdout.strip()))
        await command(r.target, r.session, "ip", "link", "set", "dev", TARGET_WAN_IF, "mtu", "1500")
        mtus[TARGET_WAN_IF] = 1500
        await udp_warm(r, sport, mtus)
        await udp_size(r, sport, 1432, "mtu-raised-boundary-hardware", mtus)
        assert await table_identity(r) == identity
        assert await read(r.target, r.session, "/proc/sys/kernel/random/boot_id") == boot_id
        r.record("mtu-complete", {"state": await r.state(), "table": identity, "boot_id": boot_id})
    finally:
        echo_socket.setsockopt(socket.SOL_IP, pmtu_option, echo_pmtu)
        try:
            await r.delete_table()
        finally:
            failures = []
            for dev, mtu in original.items():
                result = await command(r.target, r.session, "ip", "link", "set", "dev", dev,
                                       "mtu", str(mtu), check=False)
                if result["rc"]:
                    failures.append(result)
            assert not failures, failures


@pytest.mark.rfc("791")
async def test_fragments_non_df_ipv4(rig):
    """An IPv4 datagram with DF clear that is larger than its path is
    fragmented in hardware, whole, through the offline-port detour (A385).

    The microcode fragments a non-DF IPv4 packet that exceeds its entry's MTU,
    and for a frame an Ethernet port received every payload byte of every
    fragment it builds is zero; of a frame an offline port took they are
    whole. So a UDP direction whose path is smaller than the largest frame its
    ingress port can deliver is installed in two entries: the LAN port's
    hands each frame untouched to the offline port, whose entry does the
    direction's work, fragmenting included. Here the host route to the WAN
    endpoint is lowered to 1200 for the test: the LAN-to-WAN direction takes
    the detour, while the reverse -- arriving on the WAN port and leaving by
    the LAN port at its full MTU -- is installed as it always was.

    The LAN sends 1250-byte payloads at its interface MTU with DF clear --
    whatever path MTU it learned from earlier tests -- and the WAN endpoint
    receives without answering. Every packet must leave the WAN port as exactly
    two fragments within 1200 bytes that carry the datagram's own bytes, the
    endpoint must reassemble each exactly once, the offline port's fragmenter
    must count every one, and Linux must send none of them. One with DF set is
    Linux's to answer (test_df_into_detour); TCP into the same path stays in
    hardware as it is, which test_tcp_into_smaller_path proves."""
    r = rig
    if (await r.state())["observe"]:
        pytest.skip("the detour is a hardware admission decision")
    route = [WAN_IP + "/32", "dev", TARGET_WAN_IF]
    await command(r.target, r.session, "ip", "route", "replace", *route, "mtu", str(SMALL_PATH))
    try:
        await detour_fragments(r)
    finally:
        # Back to the fixture's route, which carries no MTU of its own. Never
        # checked here: a failure above is the one worth reporting, and the
        # fixture removes the route either way.
        await command(r.target, r.session, "ip", "route", "replace", *route, check=False)


async def _detour_case(r, case):
    if (await r.state())["observe"]:
        pytest.skip("the detour is a hardware admission decision")
    route = [WAN_IP + "/32", "dev", TARGET_WAN_IF]
    await command(r.target, r.session, "ip", "route", "replace", *route, "mtu", str(SMALL_PATH))
    try:
        await case(r)
    finally:
        await command(r.target, r.session, "ip", "route", "replace", *route, check=False)


@pytest.mark.rfc("1191")
async def test_df_into_detour(rig):
    """A DF datagram larger than a detoured direction's path gets Linux's
    Fragmentation Needed, with the path's MTU, and goes no further; one that
    fits is carried whole by the hardware (detour_df())."""
    await _detour_case(rig, detour_df)


@pytest.mark.rfc("792")
async def test_ttl_expires_through_detour(rig):
    """A datagram whose TTL runs out on the DUT gets Linux's Time Exceeded on
    a detoured direction too, small or to be fragmented, and goes no further
    (detour_ttl())."""
    await _detour_case(rig, detour_ttl)


async def test_detour_hands_back(rig):
    """What the offline port does not forward reaches Linux on the port the
    frame arrived by, and Linux forwards it (detour_handback())."""
    await _detour_case(rig, detour_handback)


async def test_detour_under_overload(rig):
    """Offered more than its offline port forwards, a detoured direction loses
    the excess at the port's queue and no buffer with it, and carries the rest
    whole (detour_overload())."""
    await _detour_case(rig, detour_overload)


@pytest.mark.parametrize("rig", ["tcp"], indirect=True)
async def test_tcp_into_smaller_path(rig):
    """TCP into a path smaller than a full frame stays in hardware, and an
    oversized segment on its entry is still Linux's to answer.

    TCP sets DF, so nothing on such an entry is ever the microcode's to
    fragment: a segment larger than the entry's MTU is excepted to Linux,
    which answers Fragmentation Needed with the path's MTU, and the sender's
    next segments fit. Both host routes are lowered to 1200 here -- the path
    the non-DF UDP case keeps in Linux -- and both directions of one connection
    are installed with it and carry an upload in hardware.

    Then the WAN host sends one segment on the installed tuple, one byte over
    the entry's MTU and with DF set. It is the DF check in hardware, which is
    the same for every protocol: Linux must answer it with 1200, the
    microcode's fragmenter must not count it, and the entry must still be the
    one that was installed. The connection is idle while the probe crosses, so
    the entry's own hit counter -- which counts a frame before it is excepted
    -- moving by exactly one is what shows the probe met the entry in
    hardware rather than reaching Linux some other way."""
    r = rig
    if (await r.state())["observe"]:
        pytest.skip("the DF exception requires installed hardware")
    from scapy.all import Ether, ICMP, IP, TCP, Raw, srp1
    routes = [(r.lan_ip, TARGET_LAN_IF), (WAN_IP, TARGET_WAN_IF)]
    try:
        for address, dev in routes:
            await command(r.target, r.session, "ip", "route", "replace", address + "/32",
                          "dev", dev, "mtu", str(SMALL_PATH))
        await tcp_table(r)
        async with connection(r) as conn:
            admitted = await installed(r, conn)
            assert all(int(f["mtu"]) == SMALL_PATH for f in admitted["flows"]), admitted
            await hardware_transfer(r, conn, "upload", label="mtu-tcp-small-path-hardware")
            # The peer waits for its next command from here on; let the last
            # ACK of the transfer cross before the entries are read.
            await asyncio.sleep(0.5)
            before, counters_before = await r.state(), await fragmenter(r)
            # 20 bytes of IPv4 and 20 of TCP header, then one byte too many.
            probe = (Ether(src=r.wan_mac, dst=r.dut_wan_mac)
                     / IP(src=WAN_IP, dst=r.lan_ip, flags="DF")
                     / TCP(sport=DPORT, dport=SPORT, flags="A")
                     / Raw(b"M" * (SMALL_PATH - 39)))
            answer = await asyncio.to_thread(srp1, probe, iface=r.wan_if, timeout=3, verbose=False)
            after, counters_after = await r.state(), await fragmenter(r)
            moved = {label: counters_after[label] - counters_before[label] for label in counters_before}
            r.record("mtu-tcp-oversized-df", {"answer": answer.summary() if answer else None,
                                              "before": before, "after": after, "fragmenter": moved})
            assert answer is not None and ICMP in answer, "oversized DF segment was not answered"
            assert (answer[ICMP].type, answer[ICMP].code, answer[ICMP].nexthopmtu) == (3, 4, SMALL_PATH), \
                answer.show(dump=True)
            assert moved == {label: 0 for label in counters_before}, moved
            assert (after["installs"], after["deletes"]) == (before["installs"], before["deletes"]), (before, after)
            old, new = {f["in"]: f for f in before["flows"]}, {f["in"]: f for f in after["flows"]}
            assert {d: f["cookie"] for d, f in new.items()} == {d: f["cookie"] for d, f in old.items()}, \
                (before, after)
            hits = {d: int(new[d]["packets"]) - int(old[d]["packets"]) for d in old}
            assert hits == {TARGET_WAN_IF: 1, TARGET_LAN_IF: 0}, (hits, before, after)
            await conn.close("fin")
    finally:
        # Back to the fixture's routes, which carry no MTU of their own.
        for address, dev in routes:
            await command(r.target, r.session, "ip", "route", "replace", address + "/32", "dev", dev,
                          check=False)
