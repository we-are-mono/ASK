"""Reopen offloaded TCP tuples as soon as their connections close.

A client that reconnects from the same source port reuses the closed
connection's tuple. Since 6.14 a FIN or RST leaves its flow in the table as
CLOSING while hardware lets the entry go, and the reopening SYN has to reach
the flowtable's state check, which retires that flow and hands conntrack a
closed connection, before conntrack sees it: otherwise conntrack takes the SYN
against the old connection's state, the new connection runs on a conntrack
stuck in CLOSE, and hardware never gets it back. The sustained churn on 6.18
lost dozens of reopened tuples so in every run. This closes CONNECTIONS
offloaded connections, half with FIN and half with RST, reopens each tuple the
moment hardware has let the old one go, and requires every one back in
hardware, CYCLES times.
"""
from __future__ import annotations

import json

from _flowtable_capacity import BASE, batch, start, wait_entries
from _flowtable_connections import peer
from _flowtable_rig import DPORT, TABLE, WAN_IP, command
from _topology import TARGET_LAN_IF, TARGET_WAN_IF

CONNECTIONS = 64
CYCLES = 3
# A reopened tuple is offered once its old flow has left the table: a GC tick
# or two, then the offer's own round trip.
READMIT_SECONDS = 30


async def test_reopened_tuples_return_to_hardware(rig):
    r = rig
    address = json.loads((await command(r.target, r.session, "ip", "-j", "-4", "addr",
                                       "show", "dev", TARGET_WAN_IF))["stdout"])[0]
    public = next(a["local"] for a in address["addr_info"] if a["family"] == "inet")
    specs = [{"id": i, "proto": "tcp", "sport": BASE + i, "abort": bool(i & 1),
              "remote": [public, BASE + i]} for i in range(CONNECTIONS)]
    ids = list(range(CONNECTIONS))
    await command(r.target, r.session, "conntrack", "-D", "-p", "tcp", "--orig-src", r.lan_ip,
                  "--orig-dst", WAN_IP, "--dport", str(DPORT), check=False, quiet=True)
    await r.nft(f'''table inet {TABLE} {{
 flowtable fast {{ hook ingress priority 0; devices = {{ {TARGET_LAN_IF}, {TARGET_WAN_IF} }}; flags offload; }}
 chain forward {{ type filter hook forward priority 0; policy accept;
 ip saddr {r.lan_ip} ip daddr {WAN_IP} tcp sport {BASE}-{BASE + CONNECTIONS - 1} tcp dport {DPORT} flow add @fast
 }}
}}''')
    try:
        async with peer(r, specs, initial_ids=[], lease=900, tcp_size=1024, reconnect=True) as p:
            await p.rpc("open", ids)
            await batch(p, ids, count=4, interval=0.025)
            await start(p, ids)
            await wait_entries(r, 2 * CONNECTIONS, p)
            cycles = []
            for cycle in range(CYCLES):
                await p.rpc("stop", ids)
                await p.rpc("close", ids)
                # Hardware has let every old flow go; Linux may still hold them.
                freed = await wait_entries(r, 0, p, timeout=60)
                await p.rpc("open", ids)
                await batch(p, ids, count=4, interval=0.025)
                await start(p, ids)
                try:
                    back = await wait_entries(r, 2 * CONNECTIONS, p, timeout=READMIT_SECONDS)
                except BaseException:
                    stuck = await command(r.target, r.session, "conntrack", "-L", "-p", "tcp",
                                          "--orig-src", r.lan_ip, "--dport", str(DPORT), check=False)
                    r.record(f"tcp-reopen-{cycle}-stuck", {"freed": freed, "conntrack": stuck["stdout"]})
                    raise
                cycles.append({"freed_installs": freed["installs"], "back_installs": back["installs"],
                               "wait_seconds": back.get("wait_seconds")})
            r.record("tcp-reopen", cycles)
            await p.rpc("stop", ids)
    finally:
        await r.delete_table(timeout=60)
