"""Re-admit current MTUs through an unchanged table and established TCP socket,
and fragment what the entry's MTU does not carry whole."""
from __future__ import annotations

import asyncio
import json
import os
import socket
import struct
import threading
import time

import pytest

from ask_orch.client import Agent
from _topology import LAN_NIC, TARGET_LAN_IF, TARGET_WAN_IF, lan_run_python
from test_flowtable_connections import FLOWS, by_key, connections, healthy, peer  # noqa: F401
from test_flowtable_offload import (ARTIFACTS, DPORT, SPORT, TABLE, WAN_IP, command, ct_listing,  # noqa: F401
                                    read, rig)
from test_flowtable_selective_neighbour import hardware, warm
from test_flowtable_tcp import software_tx


async def table_identity(r):
    result = await command(r.target, r.session, "nft", "-a", "-j", "list", "table", "inet", TABLE)
    tables = [item["flowtable"] for item in json.loads(result["stdout"])["nftables"] if "flowtable" in item]
    assert len(tables) == 1 and "handle" in tables[0], result
    return tables[0]


def current_mtus(state, mtus):
    healthy(state)
    assert state["handle_refs"] == state["entries"], state
    assert all(int(f["mtu"]) == mtus[f["out"]] for f in state["flows"]), (mtus, state)


async def udp_warm(r, sport, mtus):
    for _ in range(8):
        await r.exchange(64, sport=sport, promiscuous=False)
        state = await r.state()
        if state["entries"] == 2 and all(f["proto"] == "17" for f in state["flows"]):
            current_mtus(state, mtus)
            return state
    pytest.fail(f"UDP was not re-admitted: {state}")


async def udp_size(r, sport, size, label):
    before, tx_before = await r.state(), await software_tx(r)
    # PROBE bypasses a PMTU learned by this endpoint during earlier changes;
    # the packet must reach the DUT to test its current hardware MTU.
    reports = await r.exchange(256, payload_size=size, sport=sport,
                               ignore_pmtu=True, promiscuous=False)
    after, tx_after = await r.state(), await software_tx(r)
    healthy(after)
    assert before["installs"] == after["installs"] and before["deletes"] == after["deletes"]
    old, new = by_key(before), by_key(after)
    assert old.keys() == new.keys() and len(new) == 2, (before, after)
    for key in old:
        assert old[key]["cookie"] == new[key]["cookie"], (key, before, after)
        assert int(new[key]["packets"]) - int(old[key]["packets"]) == 256
        assert int(new[key]["bytes"]) - int(old[key]["bytes"]) == 256 * (size + 42)
    tx = {dev: tx_after[dev] - tx_before[dev] for dev in tx_before}
    assert 0 <= tx[TARGET_LAN_IF] <= 64 and 0 <= tx[TARGET_WAN_IF] <= 128, tx
    r.record(label, {"before": before, "after": after, "software_tx": tx, "transfers": reports})


async def test_flowtable_mtu_recovery(connections):
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
        # These /32 routes belong to the fixture. Remove its fixed 1200 MTU
        # before opening sockets, so admission must track actual port MTUs.
        for address, dev in [(r.lan_ip, TARGET_LAN_IF), (WAN_IP, TARGET_WAN_IF)]:
            await command(r.target, r.session, "ip", "route", "replace", address + "/32", "dev", dev)
        async with peer(r, flows) as p:
            await warm(r, p, ids, "mtu-initial-admission", flows)
            initial = await hardware(r, p, "mtu-initial-hardware", flows)
            current_mtus(initial, mtus)
            # Exercise decrease and increase on each side. No conntrack flush,
            # flowtable recreation, adapter reload or socket reopen is allowed.
            for dev in (TARGET_LAN_IF, TARGET_WAN_IF):
                for mtu in (1400, original[dev]):
                    before, tx_before = await r.state(), await software_tx(r)
                    await p.rpc("start", ids, count=0, interval=0.01)
                    await command(r.target, r.session, "ip", "link", "set", "dev", dev, "mtu", str(mtu))
                    mtus[dev] = mtu
                    after = await r.wait(lambda s: s["entries"] == 4 and s["deletes"] >= before["deletes"] + 4
                                         and all(int(f["mtu"]) == mtus[f["out"]] for f in s["flows"]))
                    reports = await p.rpc("stop", ids)
                    tx_after = await software_tx(r)
                    current_mtus(after, mtus)
                    # This case changes an MTU under RTNL while traffic is
                    # flowing, so an admission can lose rtnl_trylock, decline
                    # with -EAGAIN and retire its generation for a later retry.
                    # Each such retry reinstalls what it retired, which is one
                    # more install and one more delete than the four directions
                    # this is counting -- and busy is exactly how many.
                    retries = after["busy"] - before["busy"]
                    assert after["installs"] == before["installs"] + 4 + retries, (before, after)
                    assert after["deletes"] == before["deletes"] + 4 + retries, (before, after)
                    assert after["mtu_invalidations"] == before["mtu_invalidations"] + 2, (before, after)
                    assert after["rearms"] == initial["rearms"] and not after["invalidation_done"], after
                    assert all(report["count"] > 0 for report in reports.values()), reports
                    assert await table_identity(r) == identity
                    label = f"mtu-{dev}-{mtu}"
                    r.record(label, {"before": before, "after": after, "transfers": reports,
                                     "software_tx": {d: tx_after[d] - tx_before[d] for d in tx_before},
                                     "table": identity})
                    await hardware(r, p, label + "-hardware", flows)

        # The TCP peer has closed cleanly and released the sole LAN console.
        # Keep the same table and UDP tuple for actual firmware MTU boundaries.
        # The WAN endpoint can retain PMTU from the earlier TCP transitions;
        # make its UDP replies probe the path too, rather than fragment there.
        wan = Agent("wan", f"http://{os.environ.get('ASK_WAN_IP', '127.0.0.1')}:9110")
        endpoint_route = await command(wan, r.session, "ip", "-j", "route", "get", r.lan_ip)
        r.record("mtu-endpoint-pmtu", {"route": json.loads(endpoint_route["stdout"]),
                                      "echo_pmtu_discover": echo_pmtu})
        echo_socket.setsockopt(socket.SOL_IP, pmtu_option, 3)  # IP_PMTUDISC_PROBE
        await command(r.target, r.session, "ip", "link", "set", "dev", TARGET_WAN_IF, "mtu", "1400")
        mtus[TARGET_WAN_IF] = 1400
        await udp_warm(r, sport, mtus)
        await udp_size(r, sport, 1372, "mtu-exact-boundary-hardware")
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
        await udp_size(r, sport, 1432, "mtu-raised-boundary-hardware")
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


async def fragmenter(r):
    """The microcode fragmenter's cumulative counters, by their proc labels."""
    text = await read(r.target, r.session, "/proc/ucode_frag/stats")
    return {label.strip(): int(value) for label, value in
            (line.rsplit(":", 1) for line in text.splitlines() if ":" in line)}


async def test_flowtable_mtu_fragments_non_df_ipv4(rig):
    """An IPv4 packet with DF clear that exceeds its entry's MTU is fragmented
    by the microcode and never leaves hardware. A DF one goes to Linux for its
    Fragmentation Needed instead, which the exception tests cover.

    The rig's host routes carry MTU 1200, so both entries do. The LAN sends
    1250-byte payloads at its interface MTU with DF clear -- whatever path MTU
    it learned from earlier tests -- and the WAN endpoint receives without
    answering, so only the LAN-to-WAN direction fragments. Every packet must
    leave the WAN port as exactly two fragments within 1200 bytes, the
    endpoint must reassemble each exactly once, and the microcode must count
    one fragmented frame and two fragments per packet."""
    r = rig
    if (await r.state())["observe"]:
        pytest.skip("microcode fragmentation requires installed hardware")
    from scapy.all import AsyncSniffer, Ether, IP, wrpcap
    await r.table()
    await r.exchange()
    installed = await r.wait(lambda s: s["entries"] == 2)
    assert all(int(f["mtu"]) == 1200 for f in installed["flows"]), installed
    count, size = 64, 1250
    payloads = [struct.pack("!Q", n) + b"ASK-fragment".ljust(size - 8, b".") for n in range(count)]
    script = f'''
import json, socket, struct, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_IP, 10, 4)  # IP_MTU_DISCOVER: IP_PMTUDISC_INTERFACE, DF clear
s.bind(({r.lan_ip!r}, {SPORT}))
for n in range({count}):
    s.sendto(struct.pack('!Q', n) + b'ASK-fragment'.ljust({size - 8}, b'.'), ({WAN_IP!r}, {DPORT}))
    time.sleep(0.01)
s.close()
print(json.dumps({{'sent': {count}}}))
'''
    before, counters_before = await r.state(), await fragmenter(r)
    ready = threading.Event()
    sniffer = AsyncSniffer(iface=r.wan_if, filter=f"ip src {r.lan_ip} and ip dst {WAN_IP}",
                           store=True, started_callback=ready.set)
    sniffer.start()
    r.echo.reply = False
    try:
        assert await asyncio.to_thread(ready.wait, 5), "endpoint capture did not start"
        # Management traffic also leaves by the WAN port, so nothing but the
        # counter reads themselves sits between these two.
        tx_before = await software_tx(r)
        result = await lan_run_python(r.lan, script, timeout=20, label="flowtable_fragment")
        assert result.rc == 0, result.stdout
        deadline = time.monotonic() + 5
        while sum(r.echo.received[p] for p in payloads) < count and time.monotonic() < deadline:
            await asyncio.sleep(0.1)
        await asyncio.sleep(0.5)
        tx_after = await software_tx(r)
    finally:
        r.echo.reply = True
        frames = sniffer.stop()
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        wrpcap(str(ARTIFACTS / "fragments-non-df.pcap"), frames)
    after, counters_after = await r.state(), await fragmenter(r)
    listing = await ct_listing(r)
    moved = {label: counters_after[label] - counters_before[label] for label in counters_before}
    r.record("fragments-non-df", {"before": before, "after": after, "fragmenter": moved,
                                  "software_tx": {d: tx_after[d] - tx_before[d] for d in tx_before},
                                  "conntrack": listing, "frames": len(frames)})
    # The endpoint reassembled each packet, once.
    assert [r.echo.received[p] for p in payloads] == [1] * count, [r.echo.received[p] for p in payloads]
    assert moved == {"IPv4 frames received": count, "IPv6 frames received": 0,
                     "Number of IPv4 fragments sent": 2 * count, "Number of IPv6 fragments sent": 0,
                     "Failures in allocating buffers": 0}, moved
    # Still offloaded, the same generation, and carried by hardware alone.
    assert "[HW_OFFLOAD]" in listing, listing
    assert (after["installs"], after["deletes"], after["entries"]) == (
        before["installs"], before["deletes"], 2), (before, after)
    old, new = {f["in"]: f for f in before["flows"]}, {f["in"]: f for f in after["flows"]}
    assert {i: f["cookie"] for i, f in old.items()} == {i: f["cookie"] for i, f in new.items()}
    # A classifier hit counts the frame as it arrived, before fragmentation.
    assert int(new[TARGET_LAN_IF]["packets"]) - int(old[TARGET_LAN_IF]["packets"]) == count
    assert int(new[TARGET_LAN_IF]["bytes"]) - int(old[TARGET_LAN_IF]["bytes"]) == count * (14 + 20 + 8 + size)
    assert new[TARGET_WAN_IF]["packets"] == old[TARGET_WAN_IF]["packets"], (old, new)
    # Linux forwarding these would have transmitted all 2 * count fragments.
    assert tx_after[TARGET_WAN_IF] - tx_before[TARGET_WAN_IF] < count, (tx_before, tx_after)
    # The wire: two fragments per packet, each within the MTU, DF clear,
    # offsets contiguous, forwarded once with the DUT's own addressing.
    groups = {}
    for frame in frames:
        if IP in frame:
            groups.setdefault(frame[IP].id, []).append(frame)
    assert len(groups) == count, sorted(groups)
    for ident, fragments in groups.items():
        assert len(fragments) == 2, (ident, [f.summary() for f in fragments])
        first, last = sorted(fragments, key=lambda f: f[IP].frag)
        assert (first[IP].frag, int(first[IP].flags), int(last[IP].flags)) == (0, 1, 0), (first, last)
        assert last[IP].frag * 8 == first[IP].len - 4 * first[IP].ihl, (first, last)
        assert sum(f[IP].len - 4 * f[IP].ihl for f in fragments) == 8 + size, (first, last)
        for fragment in fragments:
            assert fragment[IP].len <= 1200 and fragment[IP].ttl == 63, fragment.summary()
            assert (fragment[Ether].src, fragment[Ether].dst) == (r.dut_wan_mac, r.wan_mac), fragment.summary()
            header = fragment[IP].copy()
            del header.chksum
            assert IP(bytes(header)).chksum == fragment[IP].chksum, fragment.summary()
