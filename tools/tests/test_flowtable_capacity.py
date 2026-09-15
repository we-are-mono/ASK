"""Fill the production admission budget, overflow it, and reuse it under traffic."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import resource
import socket
import struct
import time

import pytest

from _topology import LAN_NIC, TARGET_LAN_IF, TARGET_WAN_IF
from test_flowtable_connections import by_key, healthy, peer
from test_flowtable_offload import DPORT, TABLE, WAN_IP, command, read, rig, status_text  # noqa: F401
from test_flowtable_tcp import cpu, cpu_delta, software_tx

pytestmark = pytest.mark.skipif(os.environ.get("ASK_FLOWTABLE_TESTS") != "1",
                               reason="requires an explicit experimental boot")
CAPACITY = 32768
CONNECTIONS = CAPACITY // 2
REPLACEMENTS = 256
# Keep explicit data sockets below the lab's ephemeral port range, so opening
# thousands of sockets cannot collide with the active control connection.
BASE = 20000


def socket_drops(sock):
    inode = str(os.fstat(sock.fileno()).st_ino)
    for line in Path("/proc/net/udp").read_text().splitlines()[1:]:
        fields = line.split()
        if fields[9] == inode:
            return int(fields[-1])
    raise AssertionError(("UDP socket missing", inode))


async def delete_udp(r, sport):
    # conntrack(8)'s filtered deletion dumps the entire table per invocation.
    # Use the existing agent's raw netlink transport for an exact original
    # tuple deletion (nfnetlink_conntrack.h), checking its kernel ACK.
    def attribute(kind, value):
        length = 4 + len(value)
        return struct.pack("=HH", length, kind) + value + bytes((-length) % 4)

    ip = attribute(1, socket.inet_aton(r.lan_ip)) + attribute(2, socket.inet_aton(WAN_IP))
    proto = (attribute(1, bytes([socket.IPPROTO_UDP])) + attribute(2, struct.pack("!H", sport))
             + attribute(3, struct.pack("!H", DPORT)))
    original = attribute(0x8001, ip) + attribute(0x8002, proto)
    body = struct.pack("!BBH", socket.AF_INET, 0, 0) + attribute(0x8001, original)
    result = await r.target.netlink_send(r.session, 12, body, nlmsg_type=0x102, nlmsg_flags=5)
    reply = bytes.fromhex(result["reply_hex"])
    assert len(reply) >= 20 and struct.unpack_from("=H", reply, 4)[0] == 2, result
    assert struct.unpack_from("=i", reply, 16)[0] == 0, (sport, result)


async def lan_counters(r):
    result = await r.run_peer(
        "import json,subprocess; print(json.dumps({k: subprocess.check_output(v,text=True) "
        f"for k,v in {{'link':['ethtool',{LAN_NIC!r}], 'stats':['ethtool','-S',{LAN_NIC!r}]}}.items()}}))",
        label="capacity_counters", timeout=15)
    assert result.rc == 0, result.stdout
    return json.loads(result.stdout.strip())


async def summary(r):
    result = await r.target.fs_read(r.session, "/proc/cdx_flowtable", max_bytes=4096)
    assert result["errno"] == 0, result
    return status_text(bytes.fromhex(result["content_hex"]).decode().split("flow ", 1)[0])


async def wait_entries(r, count, p, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        jobs = await p.rpc("status")
        assert not jobs["errors"], jobs
        state = await summary(r)
        assert not any(state[k] for k in ("errors", "fatal", "invalidated", "quarantine")), state
        if state["entries"] == count:
            return state
        await asyncio.sleep(1)
    r.record("capacity-unexpected", await r.state())
    pytest.fail(f"expected {count} directions: {state}")


def unchanged(before, after, *, excluded=()):
    healthy(after)
    old, new = by_key(before), by_key(after)
    excluded = set(excluded)
    for key, entry in old.items():
        if entry["cookie"] in excluded:
            continue
        assert key in new, key
        assert new[key]["cookie"] == entry["cookie"], key
        assert int(new[key]["packets"]) >= int(entry["packets"]), key


async def start(p, ids, *, count=0, interval=2):
    for proto in ("tcp", "udp"):
        selected = [i for i in ids if p.flows[i]["proto"] == proto]
        if selected:
            await p.rpc("start", selected, count=count, interval=interval,
                        allow_loss=proto == "udp", udp_timeout=5)


def delivery(p, reports):
    udp_sent = udp_lost = 0
    for ident, report in reports.items():
        proto = p.flows[int(ident)]["proto"]
        assert report["received"] > 0, (ident, report)
        size = p.tcp_size if proto == "tcp" else 256
        assert report["bytes"] == report["received"] * size, (ident, report)
        if proto == "tcp":
            assert report["received"] == report["count"] and not report["lost"], (ident, report)
        else:
            udp_sent += report["count"]
            udp_lost += report["lost"]
    # The lab has independently observed link errors. Bound and report isolated
    # UDP losses; do not turn a single bad frame into a capacity failure. Payload
    # corruption still fails in the peer, and every connection must deliver.
    assert udp_lost <= max(4, udp_sent // 1000), (udp_lost, udp_sent)
    return {"udp_sent": udp_sent, "udp_lost": udp_lost}


async def batch(p, ids, count, interval):
    await start(p, ids, count=count, interval=interval)
    reports = await p.rpc("wait", ids)
    assert set(map(int, reports)) == set(ids)
    assert all(report["count"] == count for report in reports.values())
    delivery(p, reports)
    return reports


def record_delivery(r, p, label, reports):
    # Preserve evidence even when the loss budget or delivery assertion fails.
    r.record(label, {"reports": reports})
    r.record(label, {"reports": reports, **delivery(p, reports)})


async def hardware_window(r, before, label):
    tx0, cpu0 = await software_tx(r), await cpu(r)
    await asyncio.sleep(10)
    cpu1, tx1 = await cpu(r), await software_tx(r)
    after = await r.state()
    unchanged(before, after)
    assert after["installs"] == before["installs"] and after["deletes"] == before["deletes"]
    old = by_key(before)
    assert all(int(f["packets"]) > int(old[k]["packets"]) for k, f in by_key(after).items())
    tx = {dev: tx1[dev] - tx0[dev] for dev in tx0}
    assert all(0 <= n <= 128 for n in tx.values()), tx
    r.record(label, {"state": after, "software_tx": tx, "cpu": cpu_delta(cpu0, cpu1)})
    return after


async def test_flowtable_capacity_overflow_and_reuse(rig):
    r = rig
    # Thousands of independent peers share one UDP receiver. Give this socket
    # a bounded buffer without changing host-wide networking sysctls.
    receiver = r.echo.transport.get_extra_info("socket")
    receiver.setsockopt(socket.SOL_SOCKET, 33, 4 << 20)  # Linux SO_RCVBUFFORCE
    assert receiver.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF) >= 4 << 20
    assert socket_drops(receiver) == 0
    initial = await r.state()
    assert initial["max_entries"] == CAPACITY and initial["entries"] == 0, initial
    assert BASE + (CONNECTIONS + REPLACEMENTS) // 2 < 65536
    address = json.loads((await command(r.target, r.session, "ip", "-j", "-4", "addr",
                                       "show", "dev", TARGET_WAN_IF))["stdout"])[0]
    public = next(a["local"] for a in address["addr_info"] if a["family"] == "inet")
    specs = [{"id": i, "proto": "tcp" if i & 1 else "udp", "sport": BASE + i // 2,
              "remote": [public, BASE + i // 2]} for i in range(CONNECTIONS + REPLACEMENTS)]
    full_ids = list(range(CONNECTIONS))
    extra_ids = list(range(CONNECTIONS, CONNECTIONS + REPLACEMENTS))
    retired_ids = full_ids[:REPLACEMENTS]
    survivors = full_ids[REPLACEMENTS:]
    cleanup = []
    r.record("capacity-lan-before", await lan_counters(r))
    limits = resource.getrlimit(resource.RLIMIT_NOFILE)
    required = 2 * len(specs) + 512
    assert required <= limits[1], (required, limits)
    resource.setrlimit(resource.RLIMIT_NOFILE, (max(limits[0], required), limits[1]))
    try:
        # Use the existing native MASQUERADE policy. The rig exempts only SPORT,
        # outside this workload. Longer idle timeouts allow deterministic bulk
        # setup; every admitted connection remains active during pressure.
        for proto in ("udp", "tcp"):
            name = f"net.netfilter.nf_flowtable_{proto}_timeout"
            value = (await read(r.target, r.session, "/proc/sys/" + name.replace(".", "/"))).strip()
            await command(r.target, r.session, "sysctl", "-w", f"{name}=120")
            cleanup.append(["sysctl", "-w", f"{name}={value}"])
            # This dedicated service tuple belongs entirely to the test.
            await command(r.target, r.session, "conntrack", "-D", "-p", proto,
                          "--orig-src", r.lan_ip, "--orig-dst", WAN_IP, "--dport", str(DPORT), check=False)
        await r.nft(f'''table inet {TABLE} {{
 flowtable fast {{ hook ingress priority 0; devices = {{ {TARGET_LAN_IF}, {TARGET_WAN_IF} }}; flags offload; }}
 chain forward {{ type filter hook forward priority 0; policy accept;
 ip saddr {r.lan_ip} ip daddr {WAN_IP} meta l4proto {{ tcp, udp }} th sport {BASE}-{BASE + len(specs)//2 - 1} th dport {DPORT} flow add @fast
 }}
}}''')
        memory_before = await read(r.target, r.session, "/proc/meminfo")
        async with peer(r, specs, initial_ids=[], lease=600, tcp_size=1024) as p:
            started = time.monotonic()
            warm_reports = {}
            # Bound the initial SYN/datagram burst, while previously opened
            # connections keep running. The admission cap itself is unchanged.
            for offset in range(0, len(full_ids), 256):
                group = full_ids[offset:offset + 256]
                await p.rpc("open", group)
                warm_reports.update(await batch(p, group, count=4, interval=0.025))
                await start(p, group)
            record_delivery(r, p, "capacity-warmup", warm_reports)
            await wait_entries(r, CAPACITY, p)
            full = await r.state()
            healthy(full)
            assert len(by_key(full)) == CAPACITY
            assert full["installs"] - full["deletes"] == CAPACITY
            assert full["handle_refs"] == CAPACITY
            assert all(f["new_src"].startswith(public + ":") for f in full["flows"] if f["in"] == TARGET_LAN_IF)
            r.record("capacity-full", {"state": full, "fill_seconds": time.monotonic() - started,
                                      "memory_before": memory_before,
                                      "memory_full": await read(r.target, r.session, "/proc/meminfo")})

            steady = await hardware_window(r, full, "capacity-steady")
            assert socket_drops(receiver) == 0, "generator UDP receive queue overflow"

            await p.rpc("open", extra_ids)
            tx0 = await software_tx(r)
            overflow_reports = await batch(p, extra_ids, count=8, interval=0.25)
            tx1, overflow = await software_tx(r), await r.state()
            unchanged(steady, overflow)
            assert overflow["entries"] == CAPACITY
            assert overflow["installs"] == steady["installs"] and overflow["deletes"] == steady["deletes"]
            assert overflow["rejects"] > steady["rejects"]
            tx = {dev: tx1[dev] - tx0[dev] for dev in tx0}
            assert all(n >= 8 * REPLACEMENTS for n in tx.values()), tx
            r.record("capacity-overflow", {"state": overflow, "software_tx": tx, "transfers": overflow_reports})

            record_delivery(r, p, "capacity-retired-transfers", await p.rpc("stop", retired_ids))
            await p.rpc("close", retired_ids)
            for ident in retired_ids[::2]:
                await delete_udp(r, specs[ident]["sport"])
                if ident % 32 == 0:
                    assert not (await p.rpc("status"))["errors"]
            await wait_entries(r, CAPACITY - 2 * REPLACEMENTS, p)
            freed = await r.state()
            freed_cookies = {f["cookie"] for f in freed["flows"]}
            removed = {f["cookie"] for f in full["flows"] if f["cookie"] not in freed_cookies}
            assert len(removed) == 2 * REPLACEMENTS
            unchanged(full, freed, excluded=removed)
            assert freed["installs"] == full["installs"]
            assert freed["deletes"] == full["deletes"] + 2 * REPLACEMENTS

            # Same overflow sockets and conntracks retry native hardware
            # admission when their software flow approaches its refresh window.
            await start(p, extra_ids, interval=0.25)
            await wait_entries(r, CAPACITY, p, timeout=150)
            reused = await r.state()
            r.record("capacity-reuse", reused)
            unchanged(full, reused, excluded=removed)
            # A new generation can lose RTNL between directional admissions.
            # Its shared handle then retires any provisional hardware before
            # Linux retries. Existing owners must survive unchanged; account
            # for this bounded, explicitly reported admission recovery.
            retries = reused["admission_invalidations"] - freed["admission_invalidations"]
            retired = reused["deletes"] - freed["deletes"]
            assert 0 <= retired <= 2 * retries, (retired, retries)
            assert reused["installs"] - freed["installs"] == 2 * REPLACEMENTS + retired
            after = await hardware_window(r, reused, "capacity-reused-steady")
            reports = await p.rpc("stop", survivors + extra_ids)
            record_delivery(r, p, "capacity-transfers", reports)
            # A committed route replacement affects every generation. This
            # exercises the full atomic dependency walk and worker retirement,
            # then repopulates the entire cap using the same live sockets.
            started = time.monotonic()
            await command(r.target, r.session, "ip", "route", "replace", f"{WAN_IP}/32",
                          "dev", TARGET_WAN_IF, "mtu", "1300")
            route_seconds = time.monotonic() - started
            drained = await wait_entries(r, 0, p)
            assert drained["route_invalidations"] - after["route_invalidations"] == CONNECTIONS
            assert drained["installs"] == drained["deletes"]
            r.record("capacity-route-drain", {"state": drained, "command_seconds": route_seconds,
                                             "retirement_seconds": time.monotonic() - started})
            # Reuse the initial admission pacing after bulk retirement too.
            # This verifies full occupancy/recovery without conflating it with
            # an unpaced simultaneous connection-admission stress test.
            recovering = survivors + extra_ids
            warm_reports = {}
            for offset in range(0, len(recovering), 256):
                group = recovering[offset:offset + 256]
                warm_reports.update(await batch(p, group, count=4, interval=0.025))
                await start(p, group)
            record_delivery(r, p, "capacity-recovery-warmup", warm_reports)
            await wait_entries(r, CAPACITY, p)
            regenerated = await r.state()
            healthy(regenerated)
            assert all(int(f["mtu"]) == (1300 if f["out"] == TARGET_WAN_IF else 1200)
                       for f in regenerated["flows"])
            assert regenerated["installs"] - regenerated["deletes"] == CAPACITY
            r.record("capacity-regenerated", regenerated)
            await hardware_window(r, regenerated, "capacity-regenerated-steady")
            reports = await p.rpc("stop", survivors + extra_ids)
            record_delivery(r, p, "capacity-regenerated-transfers", reports)
            # Exercise whole-table detachment while every socket is still open.
            started = time.monotonic()
            final = await r.delete_table()
            assert final["installs"] == final["deletes"]
            assert all(final[k] == 0 for k in ("entries", "handle_refs", "neighbour_refs", "quarantine", "errors"))
            assert socket_drops(receiver) == 0, "generator UDP receive queue overflow"
            r.record("capacity-drain", {"state": final, "seconds": time.monotonic() - started,
                                       "memory_drained": await read(r.target, r.session, "/proc/meminfo")})
    finally:
        try:
            records = {}
            for data, count in r.echo.received.items():
                ident, serial = struct.unpack("!IQ", data[:12])
                records.setdefault(ident, []).append([serial, count])
            r.record("capacity-receiver", {"drops": socket_drops(receiver), "records": records})
            r.record("capacity-lan-after", await lan_counters(r))
            r.record("capacity-final-state", await r.state())
            failures = []
            try:
                await r.delete_table()
            except Exception as error:
                failures.append(str(error))
            for proto in ("udp", "tcp"):
                await command(r.target, r.session, "conntrack", "-D", "-p", proto,
                              "--orig-src", r.lan_ip, "--orig-dst", WAN_IP, "--dport", str(DPORT), check=False)
            for argv in reversed(cleanup):
                result = await command(r.target, r.session, *argv, check=False)
                if result["rc"]:
                    failures.append(result)
            assert not failures, failures
        finally:
            resource.setrlimit(resource.RLIMIT_NOFILE, limits)
