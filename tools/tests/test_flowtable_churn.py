"""Sustained native NAT ownership turnover at the production admission budget."""
from __future__ import annotations

import asyncio
import json
import os
import resource
import socket
import statistics
import time

import pytest

from _topology import TARGET_LAN_IF, TARGET_WAN_IF
from test_flowtable_capacity import (BASE, CAPACITY, CONNECTIONS, batch, delete_udp,
                                     delivery, hardware_window, lan_counters,
                                     socket_drops, start, unchanged, wait_entries)
from test_flowtable_connections import by_key, healthy, peer
from test_flowtable_offload import DPORT, TABLE, WAN_IP, command, read, rig  # noqa: F401
from test_flowtable_tcp import cpu, cpu_delta, software_tx

pytestmark = pytest.mark.skipif(
    os.environ.get("ASK_FLOWTABLE_TESTS") != "1" or os.environ.get("ASK_FLOWTABLE_CHURN") != "1",
    reason="explicit sustained full-capacity churn proof")
GROUP = 256
SURVIVORS = GROUP
EGRESS_TABLE = "ask_churn_egress"
# Linux owns flow lifetime. A hardware-owned flow keeps its deadline only
# through a stats round trip, which the flowtable core queues in the last tenth
# of the flow timeout and skips entirely while any offload work for that flow is
# still pending. Every such read shares one hardware transaction with the
# installs and retirements of this workload, so a live flow can miss that window,
# be retired and then be readmitted on its next packet. Keep the offload timeout
# wide enough that the refresh is not routinely starved, and account for the
# turnover that remains instead of demanding a window the datapath cannot offer.
OFFLOAD_TIMEOUT = {"tcp": 120, "udp": 30}
# Directions one round may see readmitted without the group requesting it, and
# the average the whole run may sustain. A regression that retires live flows
# systematically exceeds these; a single starved refresh does not.
TURNOVER_ROUND = 64
TURNOVER_BUDGET = 16
# Forward-hook packets one readmitted direction may cost before hardware
# resumes. Software forwarding continues throughout, so this is latency, not loss.
SOFTWARE_PER_READMISSION = 8


def flow_keys(r, specs, ids):
    keys = set()
    for ident in ids:
        spec = specs[ident]
        proto = "6" if spec["proto"] == "tcp" else "17"
        src, dst = f"{r.lan_ip}:{spec['sport']}", f"{WAN_IP}:{DPORT}"
        translated = f"{spec['remote'][0]}:{spec['remote'][1]}"
        keys.update(((TARGET_LAN_IF, proto, src, dst), (TARGET_WAN_IF, proto, dst, translated)))
    return keys


async def flowtable_work(r):
    """Offload work the flowtable core still has queued: add, del and stats.

    A hardware-owned flow keeps its Linux deadline only through a stats round
    trip, so a stats backlog is what retires a live flow. Returns None on a
    kernel built without CONFIG_NF_FLOW_TABLE_PROCFS, where it cannot be seen.
    """
    result = await r.target.fs_read(r.session, "/proc/net/stat/nf_flowtable", max_bytes=8192)
    if result["errno"]:
        return None
    # Unlike /proc/net/stat/nf_conntrack alongside it, this file prints decimal.
    lines = bytes.fromhex(result["content_hex"]).decode().splitlines()
    fields = lines[0].split()
    queued = dict.fromkeys(fields, 0)
    for line in lines[1:]:
        for name, value in zip(fields, line.split()):
            queued[name] += int(value)
    return queued


async def work_peak(r, task):
    """Track the deepest offload backlog seen while `task` runs.

    Sampling once says nothing: the backlog builds and drains within a single
    retirement, so the peak is the only figure that describes the pressure.
    """
    peak = {}
    while not task.done():
        sample = await flowtable_work(r)
        if sample is None:
            return None
        peak = {name: max(peak.get(name, 0), value) for name, value in sample.items()}
        await asyncio.sleep(0.5)
    return peak


async def settled(r, p, expected, timeout=90):
    """Sample a whole table at full occupancy.

    Linux can retire a live flow between the occupancy check and the snapshot,
    so resample rather than reason about a torn view of ownership.
    """
    state, absences, reads = None, [], []
    for _ in range(5):
        await wait_entries(r, CAPACITY, p, timeout=timeout)
        # Time the dump. It reads every entry's counters from DDR under the
        # same hardware transaction as admission, retirement and the stats
        # refresh, so a slow one is itself a source of the pressure measured.
        begin = time.monotonic()
        state = await r.state()
        reads.append(round(time.monotonic() - begin, 3))
        present = by_key(state).keys()
        if state["entries"] == CAPACITY and present == expected:
            # Report what had to be retried. A resample that hides a flow
            # cycling through software is evidence, not noise.
            return state, {"absences": absences, "read_seconds": reads}
        absences.append(sorted(expected - present))
    header = {k: v for k, v in (state or {}).items() if k != "flows"}
    pytest.fail(f"table never settled at {CAPACITY} directions: {header} "
                f"absences={absences} read_seconds={reads}")


async def memory(r):
    meminfo = await read(r.target, r.session, "/proc/meminfo")
    slabinfo = await read(r.target, r.session, "/proc/slabinfo")
    return {"meminfo": meminfo, "slabinfo": slabinfo,
            "kib": {line.split()[0].rstrip(":"): int(line.split()[1])
                    for line in meminfo.splitlines()},
            "conntracks": int(await read(r.target, r.session,
                                         "/proc/sys/net/netfilter/nf_conntrack_count"))}


async def control_counters(r):
    result = await command(r.target, r.session, "nft", "-j", "list", "counters", "table", "inet", TABLE)
    return {obj["counter"]["name"]: obj["counter"]["packets"]
            for obj in json.loads(result["stdout"])["nftables"] if "counter" in obj}


async def egress_counters(r):
    result = await command(r.target, r.session, "nft", "-j", "list", "counters", "table", "netdev", EGRESS_TABLE)
    return {obj["counter"]["name"]: obj["counter"]["packets"]
            for obj in json.loads(result["stdout"])["nftables"] if "counter" in obj}


def transfer_summary(p, reports):
    result = delivery(p, reports)
    result["tcp_records"] = sum(v["count"] for i, v in reports.items() if p.flows[int(i)]["proto"] == "tcp")
    result["late"] = sum(v["late"] for v in reports.values())
    return result


async def test_flowtable_sustained_churn(rig):
    r = rig
    # A short run is useful while developing the generator, but the accepted
    # proof uses the default 900 seconds and visits every rotating tuple.
    duration = int(os.environ.get("ASK_FLOWTABLE_CHURN_SECONDS", "900"))
    # Round zero waits out idle UDP expiry, which alone takes the offload
    # timeout. A run shorter than this cannot reach the second round the
    # acceptance below requires.
    assert 3 * OFFLOAD_TIMEOUT["udp"] <= duration <= 3600
    receiver = r.echo.transport.get_extra_info("socket")
    receiver.setsockopt(socket.SOL_SOCKET, 33, 4 << 20)  # SO_RCVBUFFORCE
    assert receiver.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF) >= 4 << 20
    assert socket_drops(receiver) == 0
    # Payload validation remains at each peer. Do not retain millions of full
    # datagrams in the orchestrator merely to count a long-running workload.
    r.echo.record_payloads = False
    initial = await r.state()
    assert initial["max_entries"] == CAPACITY and initial["entries"] == 0
    address = json.loads((await command(r.target, r.session, "ip", "-j", "-4", "addr",
                                       "show", "dev", TARGET_WAN_IF))["stdout"])[0]
    public = next(a["local"] for a in address["addr_info"] if a["family"] == "inet")
    specs = [{"id": i, "proto": "tcp" if i & 1 else "udp", "sport": BASE + i // 2,
              "remote": [public, BASE + i // 2], "abort": i % 4 == 3}
             for i in range(CONNECTIONS)]
    ids = list(range(CONNECTIONS))
    groups = [ids[offset:offset + GROUP] for offset in range(SURVIVORS, CONNECTIONS, GROUP)]
    cleanup, samples = [], []
    totals = {"udp_sent": 0, "udp_lost": 0, "tcp_records": 0, "late": 0}
    retirements = {"fin": 0, "rst": 0, "udp_delete": 0, "udp_expiry": 0}
    # Directions Linux retired and readmitted on its own, the forward-hook
    # packets that entitles a survivor to, and conntracks Linux had already
    # reclaimed when this test went to delete them. All three describe the same
    # reclamation pressure, and all three are bounded rather than assumed absent.
    turnover = software_budget = absent = 0
    limits = resource.getrlimit(resource.RLIMIT_NOFILE)
    needed = 2 * CONNECTIONS + 512
    assert needed <= limits[1]
    resource.setrlimit(resource.RLIMIT_NOFILE, (max(limits[0], needed), limits[1]))

    def transfers(p, label, reports):
        r.record(label, {"reports": reports})
        result = transfer_summary(p, reports)
        for key in totals:
            totals[key] += result[key]
        return result

    try:
        r.record("churn-lan-before", await lan_counters(r))
        r.record("churn-memory-before", await memory(r))
        r.record("churn-kmemleak-baseline", await r.target.kmemleak_clear(r.session))
        for proto, timeout in OFFLOAD_TIMEOUT.items():
            name = f"net.netfilter.nf_flowtable_{proto}_timeout"
            value = (await read(r.target, r.session, "/proc/sys/" + name.replace(".", "/"))).strip()
            cleanup.append(["sysctl", "-w", f"{name}={value}"])
            await command(r.target, r.session, "sysctl", "-w", f"{name}={timeout}")
            await command(r.target, r.session, "conntrack", "-D", "-p", proto,
                          "--orig-src", r.lan_ip, "--orig-dst", WAN_IP, "--dport", str(DPORT), check=False)
        existing = await command(r.target, r.session, "nft", "list", "table", "netdev", EGRESS_TABLE, check=False)
        assert existing["rc"] != 0, "churn egress table already exists"
        await r.nft(f'''table netdev {EGRESS_TABLE} {{
 counter lan {{ }}
 counter wan {{ }}
 chain lan {{ type filter hook egress device {TARGET_LAN_IF} priority 0; policy accept;
 ip saddr {WAN_IP} ip daddr {r.lan_ip} meta l4proto {{ tcp, udp }} th sport {DPORT} th dport {BASE}-{BASE + SURVIVORS//2 - 1} counter name lan
 }}
 chain wan {{ type filter hook egress device {TARGET_WAN_IF} priority 0; policy accept;
 ip saddr {public} ip daddr {WAN_IP} meta l4proto {{ tcp, udp }} th sport {BASE}-{BASE + SURVIVORS//2 - 1} th dport {DPORT} counter name wan
 }}
}}''')
        cleanup.append(["nft", "delete", "table", "netdev", EGRESS_TABLE])
        await r.nft(f'''table inet {TABLE} {{
 flowtable fast {{ hook ingress priority 0; devices = {{ {TARGET_LAN_IF}, {TARGET_WAN_IF} }}; flags offload; }}
 counter fin {{ }}
 counter rst {{ }}
 counter survivor_forward {{ }}
 chain forward {{ type filter hook forward priority 0; policy accept;
 ip saddr {r.lan_ip} ip daddr {WAN_IP} meta l4proto {{ tcp, udp }} th sport {BASE}-{BASE + SURVIVORS//2 - 1} th dport {DPORT} counter name survivor_forward
 ip saddr {WAN_IP} ip daddr {r.lan_ip} meta l4proto {{ tcp, udp }} th sport {DPORT} th dport {BASE}-{BASE + SURVIVORS//2 - 1} counter name survivor_forward
 ip saddr {r.lan_ip} ip daddr {WAN_IP} tcp sport {BASE}-{BASE + CONNECTIONS//2 - 1} tcp dport {DPORT} tcp flags & fin == fin counter name fin
 ip saddr {r.lan_ip} ip daddr {WAN_IP} tcp sport {BASE}-{BASE + CONNECTIONS//2 - 1} tcp dport {DPORT} tcp flags & rst == rst counter name rst
 ip saddr {r.lan_ip} ip daddr {WAN_IP} meta l4proto {{ tcp, udp }} th sport {BASE}-{BASE + CONNECTIONS//2 - 1} th dport {DPORT} flow add @fast
 }}
}}''')
        async with peer(r, specs, initial_ids=[], lease=duration + 600, tcp_size=1024, reconnect=True) as p:
            warmup = {}
            for offset in range(0, CONNECTIONS, GROUP):
                group = ids[offset:offset + GROUP]
                await p.rpc("open", group)
                warmup.update(await batch(p, group, count=4, interval=0.025))
                await start(p, group)
            transfers(p, "churn-warmup", warmup)
            await wait_entries(r, CAPACITY, p)
            before = await hardware_window(r, await r.state(), "churn-initial-hardware")
            assert by_key(before).keys() == flow_keys(r, specs, ids)
            survivor_keys = flow_keys(r, specs, ids[:SURVIVORS])
            survivor_initial = {k: f for k, f in by_key(before).items() if k in survivor_keys}
            counts0 = await control_counters(r)
            egress0 = await egress_counters(r)
            # Initial software exchanges must actually hit each observation
            # hook; a misplaced or incorrectly translated match is not proof.
            assert all(value > 0 for value in egress0.values()), egress0
            started = time.monotonic()
            round_id = 0
            visited = set()
            while time.monotonic() - started < duration:
                group = groups[round_id % len(groups)]
                keys = flow_keys(r, specs, group)
                old = by_key(before)
                removed = {old[k]["cookie"] for k in keys}
                cpu0, tx0 = await cpu(r), await software_tx(r)
                begin = time.monotonic()
                reports = await p.rpc("stop", group)
                transferred = transfers(p, f"churn-{round_id:04d}-transfers", reports)
                await p.rpc("close", group)
                expire = round_id % 8 == 0
                for ident in group:
                    if specs[ident]["proto"] == "udp":
                        # Linux may already have reclaimed the conntrack of a
                        # flow it retired. That reaches the same postcondition,
                        # so count it rather than failing the exact deletion.
                        if not expire and not await delete_udp(r, specs[ident]["sport"],
                                                               allow_missing=True):
                            absent += 1
                        retirements["udp_expiry" if expire else "udp_delete"] += 1
                    else:
                        retirements["rst" if specs[ident]["abort"] else "fin"] += 1
                # Follow the offload backlog while this round's retirements
                # drain; once the table has settled it says nothing.
                draining = asyncio.create_task(
                    wait_entries(r, CAPACITY - 2 * GROUP, p, timeout=OFFLOAD_TIMEOUT["udp"] + 45))
                work = await work_peak(r, draining)
                freed = await draining
                # Retirement must free precisely this group's ownership. An
                # install here belongs to a flow Linux retired and readmitted by
                # itself; it is balanced by its own delete and is attributed to a
                # surviving tuple once the table is whole again. The adapter must
                # not have retired anything on its own initiative, so every
                # counter describing an adapter-driven retirement stays put, and
                # the three independently maintained occupancy counters agree.
                readmitted = freed["installs"] - before["installs"]
                if readmitted:
                    r.record(f"churn-{round_id:04d}-readmitted",
                             {"before": {k: v for k, v in before.items() if k != "flows"},
                              "freed": freed, "group": group})
                assert 0 <= readmitted <= TURNOVER_ROUND, (before, freed)
                assert (freed["entries"] == freed["neighbour_refs"] == freed["handle_refs"]
                        == CAPACITY - 2 * GROUP), freed
                assert freed["installs"] - freed["deletes"] == freed["entries"], freed
                assert all(freed[k] == before[k] for k in (
                    "errors", "invalidated", "quarantine", "rearms",
                    "neighbour_invalidations", "route_invalidations", "mtu_invalidations",
                    "link_invalidations", "mac_invalidations")), (before, freed)
                # Reopen the exact tuples with continuing payload serials. This
                # catches stale packets crossing a hardware generation boundary.
                await p.rpc("open", group)
                transferred_warm = transfers(p, f"churn-{round_id:04d}-warmup",
                                              await batch(p, group, count=4, interval=0.025))
                await start(p, group)
                await wait_entries(r, CAPACITY, p)
                # Keep admission paced even on machines with very fast control
                # RPCs. This increment does not revisit simultaneous burst loss.
                while time.monotonic() - begin < 4:
                    assert not (await p.rpc("status"))["errors"]
                    await asyncio.sleep(0.5)
                after, settle = await settled(r, p, old.keys())
                healthy(after)
                current = by_key(after)
                # The group's own change of identity is requested and excluded;
                # anything else that changed is turnover, and it has to account
                # for the installs this round did not ask for. The cookie alone
                # cannot identify that: Linux derives it from the flow tuple's
                # address (`nf_flow_table_offload.c`), so a readmitted flow can
                # reappear under a recycled one. A restarted packet count cannot
                # alias, and the adapter's own -ESTALE guard exists for the same
                # reason, so treat either as a new hardware generation.
                regenerated = {k for k in current if k not in keys
                               and (current[k]["cookie"] != old[k]["cookie"]
                                    or int(current[k]["packets"]) < int(old[k]["packets"]))}
                assert readmitted <= len(regenerated) <= TURNOVER_ROUND, (readmitted, sorted(regenerated))
                unchanged(before, after, excluded=removed | {old[k]["cookie"] for k in regenerated})
                # Readmitting the group is the only ownership this round asked
                # for. Anything deleted alongside it is a contended admission
                # rolled back, or a further flow Linux turned over; both publish
                # and retire in pairs, so the surplus installs must match them.
                retries = after["admission_invalidations"] - freed["admission_invalidations"]
                surplus = after["deletes"] - freed["deletes"]
                assert after["installs"] - freed["installs"] == 2 * GROUP + surplus, (freed, after)
                assert 0 <= surplus <= 2 * retries + TURNOVER_ROUND, (freed, after, retries)
                assert after["installs"] - after["deletes"] == CAPACITY
                survivors_regenerated = regenerated & survivor_keys
                turnover += len(regenerated)
                software_budget += SOFTWARE_PER_READMISSION * len(survivors_regenerated)
                for key in survivor_keys:
                    if key in survivors_regenerated:
                        # Linux gave this survivor a new hardware generation.
                        # Rebase it; the next round holds it to the new cookie.
                        survivor_initial[key] = current[key]
                        continue
                    assert current[key]["cookie"] == survivor_initial[key]["cookie"]
                    assert int(current[key]["packets"]) > int(old[key]["packets"]), key
                cpu1, tx1 = await cpu(r), await software_tx(r)
                # The gc_* columns are cumulative retirement causes, so a peak
                # says nothing about them; take an exact snapshot for the delta.
                work_now = await flowtable_work(r)
                counters = await control_counters(r)
                egress = await egress_counters(r)
                # A survivor leaves hardware only when Linux readmits it, and
                # only for as long as that readmission takes. Software forwarding
                # covers the gap, so this budget bounds latency, not loss: with
                # no readmitted survivor it is zero and these stay exact.
                assert 0 <= counters["survivor_forward"] - counts0["survivor_forward"] <= software_budget, (
                    counts0, counters, software_budget)
                assert all(0 <= egress[dev] - egress0[dev] <= software_budget for dev in egress), (
                    "survivor software transmission", egress0, egress, software_budget)
                assert absent <= TURNOVER_BUDGET * (round_id + 1), (absent, round_id)
                mem = await memory(r)
                assert mem["conntracks"] <= CONNECTIONS + 1024, mem["conntracks"]
                assert socket_drops(receiver) == 0, "generator UDP receive queue overflow"
                sample = {"round": round_id, "seconds": time.monotonic() - started,
                          "round_seconds": time.monotonic() - begin, "expiry": expire,
                          "group": group, "state": {k: v for k, v in after.items() if k != "flows"},
                          "memory": mem, "cpu": cpu_delta(cpu0, cpu1),
                          "forward_counters": counters,
                          "survivor_software_tx": {dev: egress[dev] - egress0[dev] for dev in egress},
                          "software_tx": {dev: tx1[dev] - tx0[dev] for dev in tx0},
                          "transfers": transferred, "warmup": transferred_warm,
                          "readmitted": readmitted, "regenerated": sorted(regenerated),
                          "survivors_regenerated": sorted(survivors_regenerated),
                          "turnover": turnover, "software_budget": software_budget,
                          "absent_conntracks": absent, "offload_work": work,
                          "offload_totals": work_now,
                          "settle": settle,
                          "retirements": dict(retirements), "totals": dict(totals)}
                r.record(f"churn-{round_id:04d}", sample)
                samples.append(sample)
                visited.update(group)
                before = after
                round_id += 1
            assert round_id >= 2 and all(retirements.values()), retirements
            # One starved refresh can turn a round's worth of directions over.
            # A run that sustains that rate is retiring live flows systematically
            # and is the regression this budget exists to catch.
            assert turnover <= TURNOVER_BUDGET * round_id, (turnover, round_id)
            if duration >= 900:
                assert len(visited) == CONNECTIONS - SURVIVORS, (round_id, len(visited))
            counts1 = await control_counters(r)
            controls = {key: counts1[key] - counts0[key] for key in counts0}
            assert 0 <= controls["survivor_forward"] <= software_budget, (controls, software_budget)
            egress1 = await egress_counters(r)
            assert all(0 <= egress1[dev] - egress0[dev] <= software_budget for dev in egress1), (
                egress0, egress1, software_budget)
            assert controls["fin"] >= retirements["fin"] and controls["rst"] >= retirements["rst"], controls
            # Bracket the quiet window. Nothing is asked of the table here, so
            # any retirement inside it is unprompted, and these columns say
            # which condition caused it.
            quiet_before = await flowtable_work(r)
            try:
                final_hardware = await hardware_window(r, before, "churn-final-hardware",
                                                       turnover=TURNOVER_ROUND)
            finally:
                r.record("churn-quiet-window",
                         {"before": quiet_before, "after": await flowtable_work(r)})
            transfers(p, "churn-final-transfers", await p.rpc("stop", ids))
            final = await r.delete_table()
            assert final["installs"] == final["deletes"]
            assert all(final[k] == 0 for k in ("entries", "bindings", "handle_refs", "neighbour_refs",
                                              "quarantine", "errors", "fatal", "invalidated"))
            # Unreclaimable slab is a coarse platform guard, not an ownership
            # counter. Compare settled full-occupancy samples and retain all
            # raw allocator data for review; allocator caches may stay warm.
            width = max(1, len(samples) // 4)
            head = samples[width:2 * width] or samples[:width]
            growth = statistics.median(s["memory"]["kib"]["SUnreclaim"] for s in samples[-width:]) - statistics.median(
                s["memory"]["kib"]["SUnreclaim"] for s in head)
            r.record("churn-result", {"requested_seconds": duration, "rounds": round_id,
                                     "churn_seconds": samples[-1]["seconds"], "visited": len(visited),
                                     "retirements": retirements, "totals": totals, "tcp_control": controls,
                                     "turnover": turnover, "software_budget": software_budget,
                                     "absent_conntracks": absent,
                                     "unreclaimable_growth_kib": growth, "generator_drops": socket_drops(receiver),
                                     "udp_received": r.echo.packets, "state": final,
                                     "last_full_state": {k: v for k, v in final_hardware.items() if k != "flows"}})
            # 32 MiB is a coarse sustained-growth tripwire, not a claim that
            # smaller leaks are acceptable. Exact backend ownership must drain.
            assert growth <= 32 * 1024, ("unreclaimable slab growth", growth)
    finally:
        failures = []

        async def restore(label, operation, *, record=False, allowed_rc=(0,)):
            try:
                result = await operation
                if record:
                    r.record(label, result)
                elif result["rc"] not in allowed_rc:
                    failures.append((label, result))
            except Exception as error:
                failures.append((label, repr(error)))

        try:
            try:
                r.record("churn-receiver", {"packets": r.echo.packets, "drops": socket_drops(receiver)})
            except Exception as error:
                failures.append(("receiver diagnostics", repr(error)))
            await restore("churn-lan-after", lan_counters(r), record=True)
            await restore("churn-drained", r.delete_table(), record=True)
            for proto in ("udp", "tcp"):
                await restore("delete " + proto, command(
                    r.target, r.session, "conntrack", "-D", "-p", proto, "--orig-src", r.lan_ip,
                    "--orig-dst", WAN_IP, "--dport", str(DPORT), check=False), allowed_rc=(0, 1))
            for argv in reversed(cleanup):
                await restore(" ".join(argv), command(r.target, r.session, *argv, check=False))
            await restore("churn-memory-drained", memory(r), record=True)
            assert not failures, failures
        finally:
            resource.setrlimit(resource.RLIMIT_NOFILE, limits)
    # Scan after closing all peers, deleting test conntracks and allowing
    # deferred reclamation. Scope includes native flow storage and its CDX
    # classifier allocations, without unrelated hardware-owned DPAA pools.
    await asyncio.sleep(5)
    leaks = await r.target.kmemleak(r.session, filter_substrs=[
        "[ask_flowtable]", "[cdx]", "ask_ft_", "cdx_flowtable_",
        "flow_offload_", "nf_flow_", "ExternalHashTable"])
    r.record("churn-kmemleak", leaks)
    assert leaks["leak_count"] == 0, leaks
