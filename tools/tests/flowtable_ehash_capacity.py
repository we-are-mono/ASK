"""A real full classifier bucket refuses one direction without disturbing its peers."""
from __future__ import annotations

import asyncio
import math
import time

from _ehash_bucket import CROWDED_DPORT_XORS, crowded_ipv4, bucket, ipv4_key
from _flowtable_connections import by_key, consistent, healthy, peer
from _flowtable_rig import DPORT, TABLE, WAN_IP, Echo, command, drive
from _flowtable_selective_neighbour import keys
from _flowtable_tcp import software_tx
from _topology import TARGET_LAN_IF, TARGET_WAN_IF

COUNT = 256


async def test_full_bucket_preserves_residents_and_recovers(rig):
    """32 resident forward keys, a refused 33rd, and an unrelated bucket.

    The refused direction still delivers in software while its reply and all
    residents keep their hardware identities. Deleting one resident makes
    room for the same live overflow connection, without resetting the table.
    """
    r = rig
    pairs = crowded_ipv4([DPORT ^ n for n in CROWDED_DPORT_XORS])
    def index(sport, dport):
        return bucket(ipv4_key(0, bytes(4), bytes(4), 17, sport, dport))
    crowded = index(*pairs[0])
    unrelated = next(s for s in range(1024, 32768)
                     if s not in {sport for sport, _ in pairs} and index(s, DPORT) != crowded)
    pairs.append((unrelated, DPORT))
    specs = [{"id": i, "proto": "udp", "lan": r.lan_ip, "sport": s, "connect_port": d}
             for i, (s, d) in enumerate(pairs)]
    residents, overflow, control = list(range(32)), 32, 33
    admitted = residents + [control]
    all_ids = list(range(len(specs)))
    overflow_forward = next(key for key in keys([overflow], specs) if key[0] == TARGET_LAN_IF)
    expected_full = keys(all_ids, specs) - {overflow_forward}
    servers = []
    nat = ["POSTROUTING", "-s", r.lan_ip, "-d", WAN_IP, "-p", "udp",
           "--sport", "1024:32767", "--dport", f"{min(d for _, d in pairs)}:{max(d for _, d in pairs)}",
           "-j", "ACCEPT"]
    nat_added = False
    initial = await r.state()

    async def forget(ids):
        for ident in ids:
            s, d = pairs[ident]
            await command(r.target, r.session, "conntrack", "-D", "-p", "udp",
                          "--orig-src", r.lan_ip, "--orig-dst", WAN_IP,
                          "--sport", str(s), "--dport", str(d), check=False)

    async def window(p, ids, expected, label, software=False):
        before, tx_before = await r.state(), await software_tx(r)
        started = time.monotonic()
        reports = await p.batch(ids, count=COUNT, interval=0.01)
        after, tx_after = await r.state(), await software_tx(r)
        elapsed = time.monotonic() - started
        r.record(label, {"pairs": pairs, "before": before, "after": after, "transfers": reports,
                         "tx_before": tx_before, "tx_after": tx_after, "seconds": elapsed})
        healthy(after)
        old, new = by_key(before), by_key(after)
        assert old.keys() == new.keys() == expected, (before, after)
        assert before["installs"] == after["installs"] and before["deletes"] == after["deletes"], (before, after)
        for key in expected:
            assert old[key]["cookie"] == new[key]["cookie"], (key, before, after)
            assert int(new[key]["packets"]) - int(old[key]["packets"]) == COUNT, (key, before, after)
        rejected = after["rejects"] - before["rejects"]
        tx = {dev: tx_after[dev] - tx_before[dev] for dev in tx_before}
        # A classifier hit can subsequently punt: only the refused forward
        # direction may account for a whole window of software transmits.
        assert 0 <= tx[TARGET_LAN_IF] <= 64, tx
        if software:
            # Linux retries a refused direction about once per second; a full
            # bucket must not turn each packet into a failed hardware insert.
            assert 1 <= rejected <= math.ceil(elapsed) + 2, (rejected, elapsed, before, after)
            assert COUNT <= tx[TARGET_WAN_IF] <= COUNT + 64, tx
        else:
            assert rejected == 0, (before, after)
            assert 0 <= tx[TARGET_WAN_IF] <= 64, tx
        return after

    try:
        loop = asyncio.get_running_loop()
        for port in sorted({d for _, d in pairs} - {DPORT}):
            server, _ = await loop.create_datagram_endpoint(Echo, local_addr=(WAN_IP, port))
            servers.append(server)
        await command(r.target, r.session, "iptables", "-t", "nat", "-I", *nat)
        nat_added = True
        await forget(all_ids)
        sports = ", ".join(str(s) for s, _ in pairs)
        dports = ", ".join(str(d) for d in sorted({d for _, d in pairs}))
        await r.nft(f'''table inet {TABLE} {{
 flowtable fast {{ hook ingress priority 0; devices = {{ {TARGET_LAN_IF}, {TARGET_WAN_IF} }}; flags offload; }}
 chain forward {{ type filter hook forward priority 0; policy accept;
 ip saddr {r.lan_ip} ip daddr {WAN_IP} udp sport {{ {sports} }} udp dport {{ {dports} }} flow add @fast
 }}
}}''')
        async with peer(r, specs, initial_ids=admitted) as p:
            await drive(r, lambda: p.batch(admitted),
                        lambda s: by_key(s).keys() == keys(admitted, specs), timeout=30)
            resident_state = await window(p, admitted, keys(admitted, specs), "bucket-residents")
            await p.rpc("open", [overflow])
            await drive(r, lambda: p.batch(all_ids),
                        lambda s: by_key(s).keys() == expected_full and s["rejects"] > resident_state["rejects"],
                        timeout=30)
            for number in range(2):
                full = await window(p, all_ids, expected_full, f"bucket-full-{number}", software=True)
                for key, row in by_key(resident_state).items():
                    assert by_key(full)[key]["cookie"] == row["cookie"], (key, resident_state, full)

            victim = residents[0]
            await p.rpc("close", [victim])
            await forget([victim])
            active = [i for i in all_ids if i != victim]
            vacant_keys = expected_full - keys([victim], specs)
            recovered_keys = keys(active, specs)
            # A retry already queued before deletion can claim the vacancy
            # before the first observation, without another packet from us.
            vacancy = await r.wait(lambda s: consistent(s) and by_key(s).keys() in (vacant_keys, recovered_keys))
            healthy(vacancy)
            assert vacancy["deletes"] == full["deletes"] + 2, (full, vacancy)
            assert vacancy["installs"] == full["installs"] + (overflow_forward in by_key(vacancy)), (full, vacancy)
            for key in vacant_keys:
                assert by_key(vacancy)[key]["cookie"] == by_key(full)[key]["cookie"], (key, full, vacancy)
            recovered = await drive(r, lambda: p.batch(active),
                                    lambda s: consistent(s) and by_key(s).keys() == recovered_keys, timeout=15)
            healthy(recovered)
            assert recovered["installs"] == full["installs"] + 1, (full, recovered)
            assert recovered["deletes"] == full["deletes"] + 2, (full, recovered)
            for key, row in by_key(vacancy).items():
                assert by_key(recovered)[key]["cookie"] == row["cookie"], (key, vacancy, recovered)
            await window(p, active, recovered_keys, "bucket-readmitted")
    finally:
        for server in servers:
            server.close()
        try:
            final = await r.delete_table(timeout=15)
            r.record("bucket-cleanup", final)
            assert all(final[k] == 0 for k in ("entries", "handle_refs", "neighbour_refs", "fatal", "quarantine")), final
            assert final["installs"] == final["deletes"] and final["errors"] == initial["errors"], (initial, final)
        finally:
            try:
                await forget(all_ids)
            finally:
                if nat_added:
                    await command(r.target, r.session, "iptables", "-t", "nat", "-D", *nat)
