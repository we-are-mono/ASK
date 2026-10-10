"""Carry live GCM SAs and their replay history across WAN endpoint changes."""

import asyncio
import json
import secrets
from collections import Counter
from pathlib import Path

import pytest
from _flowtable_connections import by_key, peer
from _flowtable_rig import command
from _flowtable_selective_neighbour import keys, warm
from _flowtable_service_ipsec import (
    INNER, LAN_INNER, REQIDS, Wire, flows_for, hardware, ipsec_service, larval_state,
)
from _flowtable_service_ipsec_replay import (
    AEAD, READD_TIMEOUT_MS, Inbound, arrivals, delivered, getsa, lan_listener,
    peer_errors, xfrm_mib,
)
from _ipsec_helpers import iface_index, sa_add, sa_replay_state
from _topology import TARGET_LAN_IF, TARGET_WAN_IF


LOCAL, REMOTE = "198.18.112.1", "198.18.112.2"
REPLAY_FIELDS = ("oseq", "seq", "bitmap")


def identity(direction, spi, endpoints):
    local, remote = endpoints
    src, dst = (local, remote) if direction == "out" else (remote, local)
    return ["src", src, "dst", dst, "proto", "esp", "spi", hex(spi)]


async def aliases(r):
    for agent, iface, local, remote, mac in (
        (r.target, TARGET_WAN_IF, LOCAL, REMOTE, r.wan_mac),
        (r.ipsec.wan, r.wan_if, REMOTE, LOCAL, r.dut_wan_mac),
    ):
        addresses = json.loads((await command(agent, r.session, "ip", "-j", "-4", "addr"))["stdout"])
        assert not any(a.get("local") in (LOCAL, REMOTE) for link in addresses for a in link["addr_info"]), addresses
        for kind in ("route", "neigh"):
            tail = ["table", "all", "exact", remote + "/32"] if kind == "route" else ["to", remote, "dev", iface]
            assert not json.loads((await command(agent, r.session, "ip", "-j", kind, "show", *tail))["stdout"])
        for args, undo in (
            (["addr", "add", local + "/32", "dev", iface], ["addr", "del", local + "/32", "dev", iface]),
            (["route", "add", remote + "/32", "dev", iface, "src", local],
             ["route", "del", remote + "/32", "dev", iface]),
            (["neigh", "add", remote, "lladdr", mac, "dev", iface, "nud", "permanent"],
             ["neigh", "del", remote, "dev", iface]),
        ):
            await command(agent, r.session, "ip", *args)
            r.ipsec.cleanup.append((agent, ["ip", *undo]))


async def policy(r, agent, direction, endpoints, *, forward=False, block=False):
    src, dst = (LAN_INNER, INNER) if direction == "out" else (INNER, LAN_INNER)
    outer = identity(direction, 0, endpoints)
    which = "fwd" if forward else direction if agent is r.target else "in" if direction == "out" else "out"
    selector = ["src", src + "/32", "dst", dst + "/32"]
    if forward:
        selector += ["dev", TARGET_LAN_IF]
    args = ["action", "block"] if block else [
        "action", "allow", "tmpl", *outer[:6], "mode", "tunnel", "reqid", REQIDS[direction], "level", "required",
    ]
    if agent is r.target and not forward:
        args += ["offload", "packet", "dev", TARGET_WAN_IF]
    await command(agent, r.session, "ip", "xfrm", "policy", "update", *selector, "dir", which, *args)


async def checkpoint(r, agent, direction, spi, endpoints):
    ident = identity(direction, spi, endpoints)
    shown = await getsa(agent, r, ident)
    replay = await sa_replay_state(agent, r.session, dst=ident[3], spi=spi)
    assert replay["oseq"] >= shown["oseq"] and replay["seq"] >= shown["seq"], (shown, replay)
    return {**shown, **replay}


async def replace(r, agent, direction, spi, old, new, saved, ifindex):
    await command(agent, r.session, "ip", "xfrm", "state", "delete", *identity(direction, spi, old))
    ident = identity(direction, spi, new)
    algorithms = r.ipsec.transform.algorithms
    result = await sa_add(agent, r.session, src=ident[1], dst=ident[3], spi=spi,
                          reqid=int(REQIDS[direction]), ifindex=ifindex,
                          inbound=direction == "in", offload=agent is r.target,
                          aead=(algorithms[1], bytes.fromhex(algorithms[2][2:]), int(algorithms[3])),
                          replay_window=32, replay=tuple(saved[k] for k in REPLAY_FIELDS),
                          timeout_ms=READD_TIMEOUT_MS)
    # Own the exact identity even when an ACK is lost after a successful add.
    r.ipsec.cleanup.append((agent, ["ip", "xfrm", "state", "delete", *ident]))
    assert result.ok, result


async def probe(r, inbound, numbers, expected, *, destination=None):
    from scapy.all import Ether, sendp

    seen = await delivered(r)
    frames = []
    for seq in numbers:
        packet = inbound.packet(seq).copy()
        packet.src, packet.dst = r.ipsec.peer, destination or r.ipsec.outer
        del packet.chksum
        frames.append(Ether(src=r.wan_mac, dst=r.dut_wan_mac) / packet)
    await asyncio.to_thread(sendp, frames, iface=r.wan_if, inter=0.005, verbose=False)
    got = await arrivals(r, inbound.spi, seen, len(expected))
    assert got == Counter(expected), (numbers, expected, got)


def assert_wire_phases(packets, spi, endpoints, accepted):
    """Every accepted outbound ESP frame was captured, with fresh sequence/IV."""
    from scapy.all import ESP, IP

    rows = []
    for packet in packets:
        assert not (IP in packet and packet[IP].dst == INNER), "required policy leaked plaintext"
        if ESP not in packet:
            continue
        assert packet[ESP].spi == spi, packet.summary()
        payload = bytes(packet[ESP])
        assert len(payload) >= 16, packet.summary()
        rows.append(((packet[IP].src, packet[IP].dst), packet[ESP].seq, payload[8:16]))
    counts = Counter(row[0] for row in rows)
    assert counts == Counter(dict(zip(endpoints, accepted))), (counts, endpoints, accepted)
    assert all(count >= 256 for count in accepted), accepted
    assert len({row[1] for row in rows}) == len(rows), "ESP sequence reused across migration"
    assert len({row[2] for row in rows}) == len(rows), "GCM IV reused across migration"
    last = 0
    for endpoint in endpoints:
        numbers = [seq for pair, seq, _ in rows if pair == endpoint]
        assert numbers and min(numbers) > last, (endpoint, min(numbers, default=0), last)
        last = max(numbers)
    return {"packets": len(rows), "phases": [{"endpoints": pair, "packets": counts[pair]} for pair in endpoints],
            "last_sequence": last}


async def migrate(r, p, inbound, old, new, saved, ifindex, flows):
    label = "local" if old[0] != new[0] else "peer"
    # Re-add each DUT state immediately: retired replay history has a ten-second
    # lifetime, and NEWSA itself waits for the old hardware generation to retire.
    spis = r.ipsec.active
    for direction, spi in (("out", spis["out"]), ("in", inbound.spi), ("in", spis["in"])):
        await replace(r, r.target, direction, spi, old, new, saved[spi], ifindex)
    await r.wait(lambda s: not (keys([2, 3], flows) & by_key(s).keys()), timeout=5)
    blocked = False
    try:
        # The peer has no retired-state fold. Its active TCP socket can still
        # retransmit; block encryption while taking its final replay snapshot.
        await policy(r, r.ipsec.wan, "in", old, block=True)
        blocked = True
        previous, stable = None, 0
        for _ in range(20):
            latest = {direction: await checkpoint(r, r.ipsec.wan, direction, spi, old)
                      for direction, spi in spis.items()}
            stable = stable + 1 if latest == previous else 0
            if stable == 2:
                break
            previous = latest
            await asyncio.sleep(0.2)
        else:
            raise AssertionError(("peer replay state did not quiesce", previous, latest))
        for direction, spi in spis.items():
            await replace(r, r.ipsec.wan, direction, spi, old, new, latest[direction], ifindex)
        for direction in ("out", "in"):
            await policy(r, r.ipsec.wan, direction, new)
        blocked = False
        r.ipsec.outer, r.ipsec.peer = new
        for direction in ("out", "in"):
            await policy(r, r.target, direction, new)
        await policy(r, r.target, "in", new, forward=True)
    finally:
        if blocked:
            await policy(r, r.ipsec.wan, "in", new)
    report = (await p.rpc("stop", [3]))["3"]
    assert report["count"] > 0 and report["bytes"] == report["count"] * p.tcp_size, report
    await r.wait(lambda s: s["ipsec_sas"] == s["ipsec_sa_cache"] == 3, timeout=45)
    restored = await warm(r, p, [0, 1, 2, 3], f"migration-{label}-restored", flows)
    expected = {tuple(identity(direction, spi, new)[:4]) + (hex(spi),)
                for direction, spi in (("out", spis["out"]), ("in", spis["in"]), ("in", inbound.spi))}
    records = [record for record in await r.ipsec.states() if not larval_state(record)]
    actual = {tuple(record.split()[:4]) + (hex(int(record.split("spi ", 1)[1].split()[0], 16)),)
              for record in records}
    assert actual == expected, records
    r.record(f"endpoint-migration-{label}", {"old": old, "new": new, "dut_checkpoint": saved, "peer_checkpoint": latest,
                                            "tcp": report, "restored": restored})
    return latest["out"]["packets"]


@pytest.mark.parametrize("ipsec_service", [AEAD["rfc4106-icv16"]], indirect=True)
async def test_ipsec_live_endpoint_migration(ipsec_service):
    r = ipsec_service
    flows = flows_for(r)[:4]
    await aliases(r)
    ifindex = await iface_index(r.target, r.session, TARGET_WAN_IF)
    marker = secrets.token_bytes(16)
    inbound = Inbound(r, marker, r.ipsec.transform.algorithms, 32)
    await inbound.install()
    # The real reply SA must be newest when protected flows select their pair.
    spi = r.ipsec.active["in"]
    await command(r.target, r.session, "ip", "xfrm", "state", "delete", *r.ipsec.state("in", spi))
    await r.ipsec.install("in", spi)
    original = (r.ipsec.outer, r.ipsec.peer)
    endpoints = [original, (LOCAL, original[1]), (LOCAL, REMOTE)]
    accepted = []
    errors = xfrm_mib(Path("/proc/net/xfrm_stat").read_text())
    async with lan_listener(r, marker), peer(r, flows, initial_ids=[], lease=500, listen_addresses=[INNER]) as p:
        async with Wire(r, "ipsec-endpoint-migration") as wire:
            await p.rpc("open", [0, 1, 2, 3])
            await warm(r, p, [0, 1, 2, 3], "migration-initial", flows)
            await hardware(r, p, "migration-initial-hardware", flows)
            for cycle, (old, new) in enumerate(zip(endpoints, endpoints[1:])):
                base = cycle * 100
                await probe(r, inbound, range(base + 1, base + 21), range(base + 1, base + 21))
                saved = {owner: await checkpoint(r, r.target, direction, owner, old)
                         for direction, owner in (("out", r.ipsec.active["out"]),
                                                  ("in", inbound.spi), ("in", r.ipsec.active["in"]))}
                assert saved[inbound.spi]["seq"] == base + 20, saved
                await p.rpc("start", [3], count=0, interval=0.05)
                await probe(r, inbound, range(base + 21, base + 25), range(base + 21, base + 25))
                for _ in range(20):
                    late = {direction: await checkpoint(r, r.target, direction, owner, old)
                            for direction, owner in r.ipsec.active.items()}
                    if all(late[d]["oseq" if d == "out" else "seq"] >
                           saved[r.ipsec.active[d]]["oseq" if d == "out" else "seq"] for d in late):
                        break
                    await asyncio.sleep(0.2)
                else:
                    raise AssertionError(("DUT snapshots did not become stale", saved, late))
                accepted.append(await migrate(r, p, inbound, old, new, saved, ifindex, flows))
                before = (await r.state())["ipsec_sec_refused"]
                await probe(r, inbound, [base + 20, base + 23, base + 25], [base + 25])
                after = await r.wait(lambda s: s["ipsec_sec_refused"] >= before + 2, timeout=5)
                refused = after["ipsec_sec_refused"] - before
                assert refused == 2, (before, after)
                r.record(f"migration-{cycle}-replay", {"checkpoint": saved[inbound.spi],
                                                     "replayed": [base + 20, base + 23],
                                                     "fresh": base + 25, "sec_refusals": refused})
                if cycle == 0:
                    await probe(r, inbound, [base + 26], [], destination=old[0])
                    await probe(r, inbound, [base + 26], [base + 26])
                await hardware(r, p, f"migration-{cycle}-hardware", flows)
            await asyncio.sleep(0.5)
            final = await checkpoint(r, r.ipsec.wan, "out", r.ipsec.active["out"], endpoints[-1])
            accepted.append(final["packets"])
        assert not peer_errors(errors), peer_errors(errors)
        r.record("migration-wire", assert_wire_phases(wire.packets(), r.ipsec.active["out"], endpoints, accepted))
