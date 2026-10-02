"""Shared support for flowtable capacity."""

from __future__ import annotations

import asyncio
import errno
import json
import os
import socket
import struct
import time
from pathlib import Path

import pytest
from _flowtable_connections import by_key, healthy
from _flowtable_rig import DPORT, HEALTH_BASELINE, WAN_IP, status_text
from _flowtable_tcp import cpu, cpu_delta, software_tx
from _topology import LAN_NIC

CAPACITY = 32768
CONNECTIONS = CAPACITY // 2
REPLACEMENTS = 256
# Detaching a full table retires every hardware entry serially before nft
# returns: 13.7 s on 2026-09-21, 14.6 s isolated and over 15 s mid-suite on
# 2026-09-22 (KASAN). The wait is generous; the bound is what is asserted, at
# about twice the measured time.
DETACH_SECONDS = 60
DETACH_BOUND_SECONDS = 30
# Keep explicit data sockets below the lab's ephemeral port range, so opening
# thousands of sockets cannot collide with the active control connection.
BASE = 20000


def socket_drops(sock):
    inode = str(os.fstat(sock.fileno()).st_ino)
    table = "/proc/net/udp6" if sock.family == socket.AF_INET6 else "/proc/net/udp"
    for line in Path(table).read_text().splitlines()[1:]:
        fields = line.split()
        if fields[9] == inode:
            return int(fields[-1])
    raise AssertionError(("UDP socket missing", inode))


async def delete_udp(r, sport, *, allow_missing=False, source=None, destination=None):
    # conntrack(8)'s filtered deletion dumps the entire table per invocation.
    # Use the existing agent's raw netlink transport for an exact original
    # tuple deletion (nfnetlink_conntrack.h), checking its kernel ACK.
    def attribute(kind, value):
        length = 4 + len(value)
        return struct.pack("=HH", length, kind) + value + bytes((-length) % 4)

    source, destination = source or r.lan_ip, destination or WAN_IP
    family = socket.AF_INET6 if ":" in source else socket.AF_INET
    # CTA_IP_V4_SRC/DST are 1 and 2; CTA_IP_V6_SRC/DST are 3 and 4.
    kinds = (3, 4) if family == socket.AF_INET6 else (1, 2)
    ip = (attribute(kinds[0], socket.inet_pton(family, source))
          + attribute(kinds[1], socket.inet_pton(family, destination)))
    proto = (attribute(1, bytes([socket.IPPROTO_UDP])) + attribute(2, struct.pack("!H", sport))
             + attribute(3, struct.pack("!H", DPORT)))
    original = attribute(0x8001, ip) + attribute(0x8002, proto)
    body = struct.pack("!BBH", family, 0, 0) + attribute(0x8001, original)
    result = await r.target.netlink_send(r.session, 12, body, nlmsg_type=0x102, nlmsg_flags=5)
    reply = bytes.fromhex(result["reply_hex"])
    assert len(reply) >= 20 and struct.unpack_from("=H", reply, 4)[0] == 2, result
    error = struct.unpack_from("=i", reply, 16)[0]
    # A conntrack Linux has already reclaimed leaves the intended postcondition
    # in place. Callers that accept that must still count how often it happens;
    # silently tolerating it everywhere would hide a table that never filled.
    if allow_missing and error == -errno.ENOENT:
        return False
    assert error == 0, (sport, result)
    return True


async def lan_counters(r):
    result = await r.run_peer(
        "import json,subprocess; print(json.dumps({k: subprocess.check_output(v,text=True) "
        f"for k,v in {{'link':['ethtool',{LAN_NIC!r}], 'stats':['ethtool','-S',{LAN_NIC!r}]}}.items()}}))",
        label="capacity_counters", timeout=15)
    assert result.rc == 0, result.stdout
    return json.loads(result.stdout.strip())


async def summary(r):
    # The counters and status rows come before the first flow row, and a full
    # table runs to thousands of rows here, so only its head is read. The head
    # ends at the first line that is a flow row: a counter can end in "flow"
    # itself (ipsec_sec_refused_seq_overflow).
    limit = 16384
    result = await r.target.fs_read(r.session, "/proc/cdx_flowtable", max_bytes=limit)
    assert result["errno"] == 0, result
    head, row, _ = bytes.fromhex(result["content_hex"]).decode().partition("\nflow ")
    assert row or result["size"] < limit, ("the table's head outgrew the read", result["size"])
    return status_text(head)


async def wait_entries(r, count, p, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        jobs = await p.rpc("status")
        assert not jobs["errors"], jobs
        state = await summary(r)
        # Errors are cumulative for the boot; only this test's own count.
        assert state["errors"] == HEALTH_BASELINE["errors"], (state, HEALTH_BASELINE)
        assert not any(state[k] for k in ("fatal", "invalidated", "quarantine")), state
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


async def hardware_window(r, before, label, *, turnover=0):
    # Linux can retire and readmit a live flow on its own initiative; `turnover`
    # is how many directions this window tolerates doing so. It defaults to none,
    # so a caller that expects a completely static table still gets that.
    tx0, cpu0 = await software_tx(r), await cpu(r)
    await asyncio.sleep(10)
    cpu1, tx1 = await cpu(r), await software_tx(r)
    after = await r.state()
    old, new = by_key(before), by_key(after)
    # A recycled cookie cannot identify a new generation on its own; a restarted
    # packet count can. See the same reasoning in the churn proof.
    regenerated = {k for k in new.keys() & old.keys()
                   if new[k]["cookie"] != old[k]["cookie"]
                   or int(new[k]["packets"]) < int(old[k]["packets"])}
    tx = {dev: tx1[dev] - tx0[dev] for dev in tx0}
    # Record before asserting: a window that loses or turns over a flow is
    # exactly the one whose evidence is worth keeping.
    r.record(label, {"state": after, "software_tx": tx, "cpu": cpu_delta(cpu0, cpu1),
                     "regenerated": sorted(regenerated),
                     "missing": sorted(old.keys() - new.keys()),
                     "unexpected": sorted(new.keys() - old.keys()),
                     "installs": after["installs"] - before["installs"],
                     "deletes": after["deletes"] - before["deletes"]})
    assert new.keys() == old.keys(), sorted(set(new) ^ set(old))
    assert len(regenerated) <= turnover, sorted(regenerated)
    unchanged(before, after, excluded={old[k]["cookie"] for k in regenerated})
    assert after["installs"] - before["installs"] == len(regenerated), (before, after)
    assert after["deletes"] - before["deletes"] == len(regenerated), (before, after)
    assert all(int(f["packets"]) > int(old[k]["packets"])
               for k, f in new.items() if k not in regenerated)
    assert all(0 <= n <= 128 for n in tx.values()), tx
    return after
