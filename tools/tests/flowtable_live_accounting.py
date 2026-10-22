"""Offloaded traffic reaches conntrack at the adapter's pace, once."""
from __future__ import annotations

import asyncio
import json
import time

import pytest

from _topology import lan_run_python
from _flowtable_rig import (WAN_IP, command, read)
import flowtable_burst_accounting as burst

FLOWS = 16
RATE = 20
STATS_MS = "/sys/module/ask_flowtable/parameters/stats_ms"


@pytest.mark.parametrize("stats_ms", [1000, 10000, 0])
async def test_live_accounting(rig, stats_ms):
    """With the adapter's passes on, an offloaded flow's conntrack counts
    trail what crossed it by about a pass -- under two seconds at one a second,
    under twelve at one every ten, which half the default timeout still covers
    -- and Netfilter asks for no flow's counters; off, Netfilter asks for each
    flow's instead, every tenth of its timeout (the lag is recorded, not
    bounded). Either way every datagram is counted once, both ways."""
    r = rig
    base = 43800
    loop = asyncio.get_running_loop()
    transport, echo = await loop.create_datagram_endpoint(burst.FlowEcho,
                                                          local_addr=(WAN_IP, burst.PORT))
    nat = ["POSTROUTING", "-s", r.lan_ip, "-d", WAN_IP, "-p", "udp", "--dport", str(burst.PORT),
           "-j", "ACCEPT"]
    previous = (await read(r.target, r.session, STATS_MS)).strip()
    written = await r.target.fs_write(r.session, STATS_MS, str(stats_ms))
    assert written["errno"] == 0, written
    await command(r.target, r.session, "iptables", "-t", "nat", "-I", *nat)
    try:
        await burst.forget(r)
        echo.echoed = [0] * FLOWS
        await r.nft(burst.table(r, base, FLOWS))
        await r.wait(lambda s: s["bindings"] == 2)
        peer = asyncio.create_task(lan_run_python(r.lan, burst.stream(r.lan_ip, base, FLOWS, RATE),
                                                  label="live-accounting",
                                                  timeout=burst.SECONDS + 30))
        try:
            await r.wait(lambda s: s["entries"] == 2 * FLOWS, timeout=burst.SECONDS / 2)
            # Until a pass has reported them, Netfilter keeps the new flows
            # alive by asking, as for any flow: one period on, one has.
            await asyncio.sleep(stats_ms / 1000 + 1)
            start = await r.state()
            samples = []
            window = 6 if stats_ms > 1000 else 12
            began = time.monotonic()
            while time.monotonic() - began < window:
                echoed = sum(echo.echoed)
                counts = await burst.conntrack(r, base, FLOWS)
                samples.append({"t": round(time.monotonic() - began, 2), "echoed": echoed,
                                "counted": sum(orig for orig, _ in counts.values())})
                await asyncio.sleep(0.25)
            end = await r.state()
        finally:
            result = await peer
        assert result.rc == 0, result.stdout
        report = json.loads(result.stdout.strip().splitlines()[-1])
        counts = await burst.settled(r, base, FLOWS)
        # How far behind what crossed the counts were, in seconds of traffic.
        lags = [(s["echoed"] - s["counted"]) / (FLOWS * RATE) for s in samples]
        requests = end["stats_requests"] - start["stats_requests"]
        wrong = {i: {"ct": counts.get(i), "sent": report["sent"][i], "echoed": echo.echoed[i],
                     "received": report["received"][i]}
                 for i in range(FLOWS)
                 if i not in counts or
                 not echo.echoed[i] <= counts[i][0] <= report["sent"][i] or
                 not report["received"][i] <= counts[i][1] <= echo.echoed[i]}
        r.record(f"live-accounting-{stats_ms}", {
            "start": start, "end": end, "samples": samples, "lags": lags,
            "requests": requests, "report": report, "conntrack": counts, "wrong": wrong})
        assert not wrong, wrong
        assert end["errors"] == start["errors"], (start, end)
        if stats_ms:
            assert end["stats_passes"] - start["stats_passes"] >= window * 1000 // stats_ms - 1, (start, end)
            assert requests == 0, requests
            # A pass a period, its read, and the sampling's own read.
            assert max(lags) < stats_ms / 1000 + 1.5, lags
        else:
            assert end["stats_passes"] == start["stats_passes"], (start, end)
            assert requests > 0, requests
    finally:
        transport.close()
        await r.delete_table(timeout=30)
        await command(r.target, r.session, "iptables", "-t", "nat", "-D", *nat, check=False)
        await burst.forget(r)
        await r.target.fs_write(r.session, STATS_MS, previous)
