"""TCP rate floors through the offloaded path, with the classifier proved to
carry every stream while the rate is measured.

A floor is a capability gate. The CPU forwards a small fraction of these
rates (97.9 Mbit/s of routed IPv6 on the KASAN image, docs/flowtable/ipv6.md),
so a sample at a floor set near the path's ceiling was carried in hardware.
A path that keeps its entries but loses its ceiling -- an MTU that excepts
every segment to the CPU, a queue that holds the acknowledgements -- passes
every functional test and misses the floor (docs/flowtable/ipsec.md, "The MTU
the classifier is told is the outer one").

The hardware proof is taken inside the measured interval: every data stream
and its acknowledgements on a hardware entry, each entry's cookie unchanged
across WINDOW seconds and its counters moving, and the DUT's software
transmit on both ports next to nothing. The rate is the receiver's own count
over its per-second intervals from RAMP on, by which time a slow start that
overshot has recovered. iperf3's omit period is not used: its first interval
after the omit can claim two seconds for one second's bytes.

The WAN host terminates every path here, and its share of one core makes
single samples vary with the DUT unchanged, so a floor is met by the best of
up to SAMPLES runs. The hardware proof must hold in every run.
"""
from __future__ import annotations

import asyncio
import json

from _flowtable_tcp import cpu, cpu_delta, software_tx
from _topology import TARGET_LAN_IF, TARGET_WAN_IF, lan_run_python

STREAMS = 4
SECONDS, RAMP, WINDOW = 10, 3, 3
SAMPLES = 3
# Staging the client script through the guest agent before iperf3 starts.
STAGING = 1.5
# Nothing else crosses the DUT during a sample, so what its kernel transmits
# on a port in the window is a punted segment or two, never a stream's bulk.
SOFTWARE_TX = 512
# What each entry moves in the window at the lowest floor here, by a wide
# margin: a stream at a quarter of 1 Gbit/s sends ~60,000 segments in 3 s.
MOVED = 1000


def endpoint(address, port):
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


def settled(report, ramp=RAMP):
    """The receiver's bits per second over its intervals from `ramp` on."""
    intervals = [i["sum"] for i in report["intervals"]
                 if not i["sum"]["sender"] and i["sum"]["start"] >= ramp - 0.01]
    assert intervals, report["intervals"]
    seconds = sum(i["seconds"] for i in intervals)
    return {"bits_per_second": sum(i["bytes"] for i in intervals) * 8 / seconds,
            "seconds": seconds}


def _bulk(state, server, data_in, stale):
    """The data directions: to or from the server's port, arriving on
    `data_in`, carrying full segments rather than acknowledgements, and not
    among the `stale` cookies."""
    return [f for f in state["flows"] if f["proto"] == "6" and f["in"] == data_in
            and server in (f["src"], f["dst"]) and f["cookie"] not in stale
            and int(f["bytes"]) > max(1_000_000, 512 * int(f["packets"]))]


def _acks(state, data):
    """Each data direction's acknowledgements: the entry arriving where the
    data leaves, addressed back to where the data's translated tuple came
    from."""
    rows = {(f["in"], f["src"], f["dst"]): f for f in state["flows"] if f["proto"] == "6"}
    acks = []
    for row in data:
        key = (row["out"], row["new_dst"], row["new_src"])
        assert key in rows, ("acknowledgements not in hardware", row, state)
        acks.append(rows[key])
    return acks


async def _reports(record, task, server_side):
    """Both ends' iperf3 reports into `record`, once the run has ended."""
    result = await task
    record["client_console"] = {"rc": result.rc, "stdout": result.stdout}
    if server_side.returncode is None:
        try:
            stdout, stderr = await asyncio.wait_for(server_side.communicate(), 15)
        except TimeoutError:
            server_side.terminate()
            stdout, stderr = await asyncio.wait_for(server_side.communicate(), 10)
    else:
        stdout, stderr = await server_side.communicate()
    record["server_rc"] = server_side.returncode
    record["server_stderr"] = stderr.decode()
    record["server"] = json.loads(stdout) if stdout.strip() else {}
    if result.rc == 0:
        report = json.loads(result.stdout.strip().splitlines()[-1])
        record["client_rc"], record["client_stderr"] = report["rc"], report["stderr"]
        record["client"] = json.loads(report["stdout"]) if report["stdout"].strip() else {}


async def _sample(r, record, *, server, client, port, upload, family, streams, run, label,
                  admission, check, each, counters, within):
    """One run into `record`, which keeps what it collected when it fails."""
    server_side = await asyncio.create_subprocess_exec(
        "iperf3", "-s", "-1", "-B", server, "-p", str(port), "-J",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    task = None
    try:
        await asyncio.sleep(0.3)
        assert server_side.returncode is None, "the endpoint iperf3 did not start"
        record["argv"] = argv = [
            "iperf3", "-c", server, "-B", client, "-p", str(port), "-P", str(streams),
            "-t", str(SECONDS), "-Z", "-J", *(["-6"] if family == 6 else []),
            *([] if upload else ["-R"])]
        script = f'''
import json, subprocess
result = subprocess.run({argv!r}, capture_output=True, text=True, timeout={SECONDS + 20})
print(json.dumps({{'rc': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}}))
'''
        # A previous sample's entries outlive its streams by a second or so;
        # none of them is this sample's.
        stale = {f["cookie"] for f in (await r.state())["flows"]}
        loop = asyncio.get_running_loop()
        launched = loop.time()
        task = asyncio.create_task(run(script, label=label, timeout=SECONDS + 40))
        data_in = TARGET_LAN_IF if upload else TARGET_WAN_IF
        target = endpoint(server, port)
        while True:
            record["admission"] = state = await r.state()
            data = _bulk(state, target, data_in, stale)
            if len(data) == streams:
                break
            assert not task.done(), "iperf3 ended before every stream was in hardware"
            assert loop.time() < launched + admission, \
                f"not every stream was in hardware {admission} s after launch"
            await asyncio.sleep(0.25)
        record["admitted_after"] = round(loop.time() - launched, 2)
        # Inside the settled part of the run, which the rate is taken from,
        # and over before the run is.
        start = max(loop.time(), launched + STAGING + RAMP)
        assert start + WINDOW < launched + STAGING + SECONDS - 0.5, \
            "the streams entered hardware too late in the run to measure them there"
        await asyncio.sleep(start - loop.time())
        record["before"] = before = await r.state()
        data = _bulk(before, target, data_in, stale)
        assert len(data) == streams, "a stream left hardware before the window"
        acks = _acks(before, data)
        if check:
            check(data, acks)
        keys = {(f["in"], f["src"], f["dst"]) for f in data + acks}
        data_keys = {(f["in"], f["src"], f["dst"]) for f in data}
        extra_before = await counters() if counters else {}
        tx_before, cpu_before = await software_tx(r), await cpu(r)
        await asyncio.sleep(WINDOW)
        cpu_after, tx_after = await cpu(r), await software_tx(r)
        extra_after = await counters() if counters else {}
        record["after"] = after = await r.state()
        record["cpu"] = cpu_delta(cpu_before, cpu_after)
        record["software_tx"] = tx = {dev: tx_after[dev] - tx_before[dev] for dev in tx_before}
        record["counters"] = extra = {name: extra_after[name] - extra_before[name]
                                      for name in extra_before}
        assert not task.done(), "the run ended inside the window"
        old = {(f["in"], f["src"], f["dst"]): f for f in before["flows"]}
        new = {(f["in"], f["src"], f["dst"]): f for f in after["flows"]}
        record["hardware"] = hardware = [
            {"key": key, "cookie_kept": key in new and new[key]["cookie"] == old[key]["cookie"],
             "packets": int(new[key]["packets"]) - int(old[key]["packets"]) if key in new else 0,
             "bytes": int(new[key]["bytes"]) - int(old[key]["bytes"]) if key in new else 0}
            for key in sorted(keys)]
        assert all(m["cookie_kept"] for m in hardware), "an entry was replaced inside the window"
        if each:
            assert all(m["packets"] > MOVED for m in hardware), "an entry stalled in the window"
        else:
            for group in (data_keys, keys - data_keys):
                total = sum(m["packets"] for m in hardware if m["key"] in group)
                assert total > MOVED * len(group), "the entries stalled in the window"
        if within:
            within(extra)
        assert all(0 <= count <= SOFTWARE_TX for count in tx.values()), \
            "the DUT's kernel transmitted the streams' traffic"
        for state in (before, after):
            assert state["invalidated"] == state["fatal"] == state["quarantine"] == 0, state
        assert after["errors"] == before["errors"], "the adapter counted an error"
        pending, task = task, None
        await _reports(record, pending, server_side)
        assert record["client_console"]["rc"] == 0 and record["client_rc"] == 0, record["client_console"]
        assert record["server_rc"] == 0, record["server_stderr"]
        assert "error" not in record["client"] and "error" not in record["server"]
        record["settled"] = settled(record["server"] if upload else record["client"])
    finally:
        if task:
            # Evidence for the failure already in flight; never a new one.
            try:
                await _reports(record, task, server_side)
            except Exception as error:
                record["reports_error"] = repr(error)
        if server_side.returncode is None:
            server_side.terminate()
            await asyncio.wait_for(server_side.communicate(), 10)


async def tcp_floor(r, *, server, client, port, upload, floor, label, family=4,
                    streams=STREAMS, run=None, admission=8, check=None, each=True,
                    counters=None, within=None):
    """iperf3 between `client` on the LAN side and `server` on this host, the
    data going `upload` (LAN to WAN) or the other way. Returns the samples;
    the best of them meets `floor` bits per second.

    `check(data, acks)` asserts what the path's entries must describe, on
    each sample's rows. `each` requires every entry to move in the window;
    without it the data entries and the acknowledgement entries must move
    together, for a path whose far end can stall one stream on its own.
    `counters()` reads named DUT counters at the window's edges and
    `within(delta)` bounds what they moved."""
    if run is None:
        async def run(script, *, label, timeout):
            return await lan_run_python(r.lan, script, label=label, timeout=timeout)
    samples = []
    for attempt in range(SAMPLES):
        record = {}
        try:
            await _sample(r, record, server=server, client=client, port=port, upload=upload,
                          family=family, streams=streams, run=run, admission=admission,
                          check=check, each=each, counters=counters, within=within,
                          label=f"{label}_{attempt}")
        finally:
            r.record(f"{label}-{attempt}", record)
        samples.append(record["settled"])
        if samples[-1]["bits_per_second"] >= floor:
            break
    r.record(label, {"floor": floor, "samples": samples})
    assert max(s["bits_per_second"] for s in samples) >= floor, (samples, floor)
    return samples
