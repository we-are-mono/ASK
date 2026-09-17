"""Re-admit current MTUs through an unchanged table and established TCP socket."""
from __future__ import annotations

import json
import os
import socket

import pytest

from ask_orch.client import Agent
from _topology import LAN_NIC, TARGET_LAN_IF, TARGET_WAN_IF, lan_run_python
from test_flowtable_connections import FLOWS, by_key, connections, healthy, peer  # noqa: F401
from test_flowtable_offload import DPORT, TABLE, WAN_IP, command, read, rig  # noqa: F401
from test_flowtable_selective_neighbour import hardware, warm
from test_flowtable_tcp import software_tx

pytestmark = pytest.mark.skipif(os.environ.get("ASK_FLOWTABLE_TESTS") != "1",
                               reason="requires an explicit experimental boot")


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
