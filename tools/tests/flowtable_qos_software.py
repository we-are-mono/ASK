"""Software shaping on a flow's path keeps that direction of the flow in software.

The classifier forwards an offloaded flow from the port it arrives on straight
to the queues of the port it leaves by, so nothing Linux runs on the way -- no
qdisc, no tc filter -- ever sees it. A shaper is where that matters. OpenWrt's
SQM puts `cake` at the root of the WAN device for the upload, and for the
download an `ingress` qdisc whose one u32 filter redirects every frame the WAN
device receives to an ifb carrying another `cake`. Against an offloaded flow
both shape the handful of packets Linux forwarded before admission and nothing
after it, and `tc -s` reads as a shaper with nothing to do.

So a direction whose path runs tc in software stays there. On the way out that
is a filter, a tcx program, or a root qdisc that schedules: anything but a tree
the hardware runs itself (`htb offload`) or a work-conserving qdisc of the kinds
Linux attaches by default -- fq_codel, pfifo_fast and the FIFOs however they
came there, fq and the default kind only as the kernel attached them. On the
way in it is a filter, tcx or XDP. Each direction is judged on its own path,
so cake on the WAN port holds the upload back and leaves the download, which
leaves by the LAN port, in hardware. A shaper that arrives under an installed
direction retires it, and once the shaper is gone the software path offers
the flow again. The adapter counts
both in /proc/ask_flowtable/stats: `tc_refused` for an admission refused,
`tc_invalidations` for an installed direction retired.

The cap, SQM_MBIT, is below what one core forwards in software on the test
image, so a direction in software is held at it by cake rather than by the
CPU; the offered load is five times the cap, which a direction in hardware
carries whole and cake does not. Three oracles, then: the rate the receiver
counts, the shaper's own `tc -s` count, which has to cover what arrived, and
the adapter's rows.

Uploads run as reversed transfers this host opens: the LAN VM's iperf3 server
sends, this host receives, and the upload is the reply direction of a flow
that arrived on the WAN port, routed rather than translated. The session cases
use the PPPoE rig, whose WAN is a session over a tag. Needs sch_cake, ifb and
act_mirred on the DUT, which the test image ships, and iperf3 on the LAN VM
and here.
"""
from __future__ import annotations

import asyncio
import os
import statistics
import time

import pytest
from _flowtable_pppoe import INNER_LOCAL
from _flowtable_qos import (
    COUNT,
    DATAGRAM,
    PORT_SQM_DEFAULT,
    PORT_SQM_DOWNLOAD,
    PORT_SQM_FQ,
    PORT_SQM_LIVE,
    PORT_SQM_UPLOAD,
    SETTLE,
    UDP_HEADERS,
    WINDOW,
    admit,
    directions,
    inbound,
    iperf,
    lan_start,
    lockstep,
    offload,
    read_intervals,
    received_bps,
    receiver_intervals,
)
from _flowtable_rig import (
    DPORT,
    SPORT,
    WAN_IP,
    command,
    console_command,
    console_json,
    drive,
)
from _topology import TARGET_LAN_IF, TARGET_WAN_IF

from ask_orch.commands import remove_qdisc
from ask_orch.counters import kernel_tx_packets
from ask_orch.lifecycle import CleanupStack

# The shaper's rate: about 1,700 full-size frames a second, well below what one
# core forwards in software on the test image (KASAN, lockdep) -- the PPPoE QoS
# case finds a core saturating near 6,000 a second through a session, the
# costlier path -- so a direction in software is held here by cake, not by the
# CPU. 50 Mbit/s sat too close: an upload retired under it once fell to 30 as
# the CPU took the whole offered load, where reruns held 48.5. The offered
# load, five times this, must fit through that core with cake in the path as
# well: at 30 Mbit/s its 150 overflowed the LAN port's CPU queue, FMan
# discarded ~29% of the upload ahead of cake, and iperf3's control connection
# beside it lost the state change that ends a run, so a third of the runs
# never finished. At 20, the 100 Mbit/s offered was discarded nowhere.
SQM_MBIT = int(os.environ.get("ASK_FLOWTABLE_SQM_MBIT", "20"))
# What a direction in hardware carries whole, and more than the CPU forwards.
SQM_OFFERED_MBIT = 5 * SQM_MBIT
# Payload bits a second through cake at the cap. With no overhead configured
# it charges each frame its length from the Ethernet header on: on the WAN
# port's egress, and on the ifb, where mirred pushed that header back.
def cap_goodput(mbit):
    """Payload bits a second through cake at `mbit`."""
    return mbit * 1e6 * DATAGRAM / (DATAGRAM + UDP_HEADERS)


SQM_GOODPUT = cap_goodput(SQM_MBIT)
# The download shaper's rate, lower: a frame the ifb hands back is marked to
# skip classification, which skips the port's netfilter ingress hook with tc,
# so the download takes Linux's whole forward path rather than the flowtable's
# fast one. On the test image that held 50 Mbit/s at 29 under five times the
# load, every datagram through cake, and 20 at 19.4.
SQM_IFB_MBIT = int(os.environ.get("ASK_FLOWTABLE_SQM_IFB_MBIT", "20"))
SQM_IFB_GOODPUT = cap_goodput(SQM_IFB_MBIT)
# A rate held at the cap, as fractions of SQM_GOODPUT. The ceiling is the
# shaper's; the floor only says the CPU kept up with it.
HELD = (0.8, 1.1)
# Most of the offered load: what a direction no shaper holds delivers. Not
# proof of hardware -- Linux's fast path carried an unshaped upload at all of
# 150 Mbit/s on the test image -- which the WAN port's software transmit
# count is instead (HARDWARE_SHARE).
UNSHAPED_BPS = 0.8 * SQM_OFFERED_MBIT * 1e6
# The most of a phase's datagrams the WAN port may count as sent by software
# while the upload is in hardware: what Linux forwarded before admission, and
# none after.
HARDWARE_SHARE = 0.1
# How long a shaper arriving under an installed direction has to retire it,
# and its going to have the direction back. Software offers a flow again
# about once a second while it carries traffic.
RETIRED_WITHIN, READMITTED_WITHIN = 5, 10
# The handle every root qdisc here is given, so its counters can be found.
ROOT = "1:"


# ---- the DUT's tc -----------------------------------------------------------

async def tc(console, *argv, check=True):
    """`tc` is not in the agent's argv allowlist, so it runs on the console
    the fixture holds."""
    return await console_command(console, "tc", *argv, check=check, timeout=30)


async def qdiscs(console, dev):
    """Every qdisc on `dev`, with its statistics, as `tc -s -j` reports them."""
    return console_json((await tc(console, "-s", "-j", "qdisc", "show", "dev", dev))["stdout"])


async def sent(console, dev, handle=ROOT):
    """The packets one qdisc on `dev`, found by handle, has sent."""
    shown = await qdiscs(console, dev)
    found = [q for q in shown if q.get("handle") == handle]
    assert len(found) == 1, (dev, handle, shown)
    return found[0]["packets"]


async def root_kind(console, dev):
    roots = [q for q in await qdiscs(console, dev) if q.get("root")]
    assert len(roots) == 1, (dev, roots)
    return roots[0]["kind"]


async def restore_root(console, dev, kind):
    """Delete `dev`'s root, which gives the device the kernel's default again,
    and require that to be the kind it had before the case."""
    await tc(console, "qdisc", "del", "dev", dev, "root")
    restored = await root_kind(console, dev)
    assert restored == kind, (dev, kind, restored)


async def shaper(r, cleanup, dev, mbit=SQM_MBIT):
    """cake at `dev`'s root at the cap, as SQM puts it there, until `cleanup`
    takes it away. A replace, so a tree a killed run left is taken over."""
    await tc(r.console, "qdisc", "replace", "dev", dev, "root", "handle", ROOT,
             "cake", "bandwidth", f"{mbit}mbit")
    cleanup.push(lambda: remove_qdisc(r.console, dev, "root", "cake"))


async def load(r, module, *parameters):
    """A module the case's tc needs, loaded up front, so an image without it
    fails here by name rather than as a tc error later."""
    await command(r.target, r.session, "modprobe", module, *parameters)


# ---- the adapter ------------------------------------------------------------

def outbound(r, port):
    """A rule offering a reversed transfer's flow from the LAN VM's side: the
    datagrams its iperf3 server sends this host. The flow is this host's, so
    its first packets came the other way."""
    return f"ip saddr {r.lan_ip} ip daddr {WAN_IP} udp sport {port} flow add @fast"


def uploads(state, r, port):
    """The installed directions from the LAN VM's `port` to this host."""
    return directions(state, ingress=TARGET_LAN_IF, proto=17, src=f"{r.lan_ip}:{port}")


def downloads(state, r, port):
    """The installed directions from this host to the LAN VM's `port`."""
    return directions(state, ingress=TARGET_WAN_IF, proto=17, dst=f"{r.lan_ip}:{port}")


async def within(r, predicate, seconds):
    """Poll the adapter until `predicate` holds or `seconds` pass: the state
    that answered and when it was read, or the last state read and None."""
    deadline = time.monotonic() + seconds
    while True:
        state = await r.state()
        now = time.monotonic()
        if predicate(state):
            return state, now
        if now >= deadline:
            return state, None
        await asyncio.sleep(0.2)


def assert_counted(before, after, counter):
    """One of the adapter's counters moved between two states. They only ever
    grow, so the case's own baseline is what it is judged against."""
    assert counter in after, f"/proc/ask_flowtable/stats reports no {counter}"
    assert after[counter] > before.get(counter, 0), (counter, before.get(counter), after[counter])


# ---- the transfers ----------------------------------------------------------

def offered_bps(report, after=SETTLE):
    """What the sender put on the wire per second once settled, as the
    receiver reads it from the datagrams' sequence numbers: every one that
    arrived, and every one a later arrival showed was lost."""
    intervals = [i["sum"] for i in receiver_intervals(report)
                 if i["sum"]["start"] >= after - 0.01]
    assert intervals, receiver_intervals(report)
    return sum(i["packets"] for i in intervals) * DATAGRAM * 8 / sum(i["seconds"] for i in intervals)


def arrived(report):
    """Every datagram the receiver took in, over the whole transfer."""
    return sum(i["sum"]["bytes"] for i in receiver_intervals(report)) // DATAGRAM


def delivered(intervals, start, end):
    """The datagrams a streamed transfer delivered between two instants, from
    the rate of each one-second interval it reported wholly within them."""
    return sum(bps for at, bps in intervals if at - 1.0 >= start and at <= end) / (8 * DATAGRAM)


def median_bps(intervals, start, end):
    """The median rate a streamed transfer reported between two instants. An
    interval is reported as it ends, so it covers the second before."""
    rates = [bps for at, bps in intervals if at - 1.0 >= start and at <= end]
    assert len(rates) >= 2, (start, end, intervals)
    return statistics.median(rates)


async def measured(r, port, dev, *, reverse, mbit=SQM_MBIT):
    """One transfer at five times the cap `mbit` through the cake on `dev`:
    the adapter's state before it, once it has settled and after it, the
    receiver's report, and how many packets cake sent meanwhile."""
    before = await r.state()
    shaped = await sent(r.console, dev)
    client = asyncio.create_task(iperf(r, port, udp_mbit=5 * mbit, reverse=reverse))
    try:
        await asyncio.sleep(SETTLE)
        during = await r.state()
        report = await client
    finally:
        if not client.done():
            client.cancel()
            await asyncio.gather(client, return_exceptions=True)
    # What cake still holds drains at the cap before it is counted.
    await asyncio.sleep(0.5)
    shaped = await sent(r.console, dev) - shaped
    return {"before": before, "during": during, "after": await r.state(), "report": report,
            "shaped": shaped}


# ---- the upload -------------------------------------------------------------

async def test_cake_keeps_the_upload_in_software(qos):
    """cake at the WAN port's root, as SQM's upload shaper: the direction that
    leaves by the WAN port stays in software, held at the cap, and cake sends
    every datagram of it that arrives. The download half leaves by the LAN
    port, which shapes nothing, and stays in hardware.

    Before, the upload was offloaded with the rest of the flow and ran at the
    offered rate past a cake that sent the few packets Linux forwarded ahead
    of admission.
    """
    r = qos
    wan, port = TARGET_WAN_IF, PORT_SQM_UPLOAD
    await load(r, "sch_cake")
    cleanup = CleanupStack()
    try:
        await shaper(r, cleanup, wan)
        await offload(r, outbound(r, port))
        await lan_start(r, iperf=[port])
        run = await measured(r, port, wan, reverse=True)
    finally:
        await cleanup.teardown("software qdisc")
    report = run["report"]
    goodput, offered, delivered = received_bps(report), offered_bps(report), arrived(report)
    upload = uploads(run["during"], r, port) + uploads(run["after"], r, port)
    download = downloads(run["after"], r, port)
    r.record("sqm-upload", {**run, "goodput_bps": goodput, "offered_bps": offered,
                            "arrived": delivered, "cap_goodput_bps": SQM_GOODPUT})

    low, high = HELD
    assert offered >= 3 * SQM_MBIT * 1e6, ("the LAN VM did not offer enough to test a cap", offered)
    assert goodput <= high * SQM_GOODPUT, (
        "the upload ran past the cake at the WAN port's root", goodput, SQM_GOODPUT)
    assert run["shaped"] >= 0.9 * delivered, (
        "cake sent fewer packets than the upload delivered", run["shaped"], delivered)
    assert not upload, ("the upload was offloaded past cake", upload)
    assert goodput >= low * SQM_GOODPUT, ("the upload fell short of the cap", goodput, SQM_GOODPUT)
    assert len(download) == 1, ("the download half, on no shaped path, was not in hardware",
                                run["after"]["flows"])
    assert_counted(run["before"], run["after"], "tc_refused")


async def test_cake_under_a_live_upload_retires_it(qos):
    """A shaper that arrives under an upload already in hardware takes it out:
    within RETIRED_WITHIN seconds of cake taking the WAN port's root the
    upload's direction is gone from the adapter and the transfer runs at the
    cap. Once cake goes, the software path offers the flow again and the
    upload is back in hardware. Either side of the shaper, the WAN port's
    software transmit count barely moves while the upload delivers: the
    hardware carried it, which no rate tells apart from Linux's fast path.

    One reversed transfer runs through all of it, this host streaming the
    rate it receives, so each phase's rate is read off the same flow. Before,
    the upload stayed in hardware under cake and ran at the offered rate
    throughout.
    """
    r = qos
    wan, port = TARGET_WAN_IF, PORT_SQM_LIVE
    await load(r, "sch_cake")
    await offload(r, outbound(r, port))
    await lan_start(r, iperf=[port])
    # Stopped once the last phase has been sampled, which ends the sender too.
    client = await asyncio.create_subprocess_exec(
        "iperf3", "-c", r.lan_ip, "-B", WAN_IP, "-p", str(port), "-t", "60", "-R",
        "-u", "-b", f"{SQM_OFFERED_MBIT}M", "-l", str(DATAGRAM), "--json-stream",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    intervals = []
    reader = asyncio.create_task(read_intervals(client.stdout, intervals))
    shaping = CleanupStack()
    try:
        installed, admitted = await within(r, lambda s: uploads(s, r, port), 10)
        if admitted is None:
            pytest.fail(f"the upload was never in hardware before the shaper: {installed}")
        software = [await kernel_tx_packets(r.target, r.session, wan)]
        counted = time.monotonic()
        await asyncio.sleep(1.0 + WINDOW)
        before = await r.state()
        software.append(await kernel_tx_packets(r.target, r.session, wan))
        shaped = time.monotonic()
        await shaper(r, shaping, wan)
        held, left = await within(r, lambda s: not uploads(s, r, port), RETIRED_WITHIN)
        await asyncio.sleep(1.0 + WINDOW)
        during = await r.state()
        unshaped = time.monotonic()
        await shaping.teardown("cake")
        back, readmitted = await within(r, lambda s: uploads(s, r, port), READMITTED_WITHIN)
        software.append(await kernel_tx_packets(r.target, r.session, wan))
        recounted = time.monotonic()
        await asyncio.sleep(1.0 + WINDOW)
        software.append(await kernel_tx_packets(r.target, r.session, wan))
        ended = time.monotonic()
    finally:
        await shaping.teardown("cake")
        if client.returncode is None:
            client.terminate()
        await asyncio.wait_for(client.wait(), 10)
        await asyncio.gather(reader, return_exceptions=True)
    stderr = (await client.stderr.read()).decode(errors="replace")[-400:]
    r.record("sqm-live", {"intervals": intervals, "admitted": admitted, "shaped": shaped,
                          "left": left, "unshaped": unshaped, "readmitted": readmitted,
                          "ended": ended, "installed": installed, "before": before,
                          "held": held, "during": during, "back": back, "stderr": stderr,
                          "software": software, "counted": counted,
                          "recounted": recounted})

    low, high = HELD
    hardware = median_bps(intervals, admitted, shaped)
    assert hardware >= UNSHAPED_BPS, (
        "the upload ran below what an unshaped direction delivers", hardware, intervals)
    alone = delivered(intervals, counted, shaped)
    assert software[1] - software[0] <= HARDWARE_SHARE * alone, (
        "the WAN port sent the upload in software while it was in hardware",
        software[1] - software[0], alone)
    assert left is not None, (
        f"the upload stayed in hardware {RETIRED_WITHIN} s after cake took the WAN port's root",
        uploads(held, r, port))
    limited = median_bps(intervals, left + 1.0, unshaped)
    assert low * SQM_GOODPUT <= limited <= high * SQM_GOODPUT, (
        "the upload out of hardware was not held at the cap", limited, SQM_GOODPUT)
    assert readmitted is not None, (
        f"the upload was not back in hardware {READMITTED_WITHIN} s after cake went", back)
    freed = median_bps(intervals, readmitted + 1.0, ended)
    assert freed >= UNSHAPED_BPS, (
        "the readmitted upload ran below what an unshaped direction delivers", freed)
    again = delivered(intervals, recounted, ended)
    assert software[3] - software[2] <= HARDWARE_SHARE * again, (
        "the WAN port sent the readmitted upload in software", software[3] - software[2], again)
    assert_counted(before, during, "tc_invalidations")


# ---- the download -----------------------------------------------------------

async def test_sqm_ingress_keeps_the_download_in_software(qos):
    """SQM's download shaper as sqm-scripts builds it: an ifb with cake at its
    root, and an `ingress` qdisc on the WAN port whose one u32 filter
    redirects every frame the port receives to it. tc runs that filter on
    every frame Linux receives there and on none the classifier forwards, so
    the download stays in software, held at the cap, every datagram of it
    that arrives sent by the ifb's cake. The upload half arrives on the LAN
    port, which runs nothing, and leaves by a WAN root that shapes nothing:
    it stays in hardware.

    Before, the download was offloaded and the ifb's cake shaped only the
    packets ahead of admission.
    """
    r = qos
    wan, port = TARGET_WAN_IF, PORT_SQM_DOWNLOAD
    # sqm-scripts' name for it, within IFNAMSIZ.
    ifb = f"ifb4{wan}"[:15]
    await load(r, "sch_cake")
    await load(r, "act_mirred")
    # As OpenWrt loads it: no ifb0 and ifb1 of the module's own.
    await load(r, "ifb", "numifbs=0")
    cleanup = CleanupStack()
    try:
        # A run killed before its teardown leaves both behind.
        await tc(r.console, "qdisc", "del", "dev", wan, "ingress", check=False)
        await command(r.target, r.session, "ip", "link", "del", ifb, check=False)
        await command(r.target, r.session, "ip", "link", "add", "name", ifb, "type", "ifb")
        cleanup.push(lambda: command(r.target, r.session, "ip", "link", "del", ifb))
        await command(r.target, r.session, "ip", "link", "set", ifb, "up")
        await shaper(r, cleanup, ifb, SQM_IFB_MBIT)
        await tc(r.console, "qdisc", "add", "dev", wan, "handle", "ffff:", "ingress")
        cleanup.push(lambda: remove_qdisc(r.console, wan, "ingress", "ingress"))
        await tc(r.console, "filter", "add", "dev", wan, "parent", "ffff:", "protocol", "all",
                 "prio", "10", "u32", "match", "u32", "0", "0", "flowid", "1:1",
                 "action", "mirred", "egress", "redirect", "dev", ifb)
        await offload(r, inbound(r, "udp", port))
        await lan_start(r, iperf=[port])
        run = await measured(r, port, ifb, reverse=False, mbit=SQM_IFB_MBIT)
    finally:
        await cleanup.teardown("software qdisc")
    report = run["report"]
    goodput, offered, delivered = received_bps(report), offered_bps(report), arrived(report)
    download = downloads(run["during"], r, port) + downloads(run["after"], r, port)
    upload = uploads(run["after"], r, port)
    r.record("sqm-download", {**run, "goodput_bps": goodput, "offered_bps": offered,
                              "arrived": delivered, "cap_goodput_bps": SQM_IFB_GOODPUT})

    low, high = HELD
    assert offered >= 3 * SQM_IFB_MBIT * 1e6, (
        "this host did not offer enough to test a cap", offered)
    assert goodput <= high * SQM_IFB_GOODPUT, (
        "the download ran past the ifb's cake", goodput, SQM_IFB_GOODPUT)
    assert run["shaped"] >= 0.9 * delivered, (
        "the ifb's cake sent fewer packets than the download delivered", run["shaped"], delivered)
    assert not download, ("the download was offloaded past the WAN port's ingress filter",
                          download)
    assert goodput >= low * SQM_IFB_GOODPUT, ("the download fell short of the cap", goodput,
                                              SQM_IFB_GOODPUT)
    assert len(upload) == 1, ("the upload half, on no filtered path, was not in hardware",
                              run["after"]["flows"])
    assert_counted(run["before"], run["after"], "tc_refused")


# ---- what does not shape ----------------------------------------------------

@pytest.mark.parametrize("kind", ["fq_codel", "pfifo_fast"])
async def test_default_root_keeps_the_flow_in_hardware(qos, kind):
    """A root qdisc of a kind Linux attaches by default and that never shapes
    only orders what it is given and holds nothing back, so a flow the
    classifier forwards past it loses nothing by it: both directions stay in
    hardware, even with the root created by tc as here.

    Every port has a root qdisc -- mq over default children unless something
    replaced it, fq_codel at the root wherever OpenWrt's default puts it -- so
    a refusal that counted these would keep every flow on every port in
    software. The echo's replies leave by the WAN port: both directions
    installed, the replies counted by their entry, the root sending next to
    none of them, and no refusal for tc. This held before the refusal existed;
    it is what keeps that refusal to qdiscs that shape. fq, the other default
    kind, is let through only as the kernel attaches it
    (test_explicit_fq_keeps_the_upload_in_software).
    """
    r = qos
    wan, port = TARGET_WAN_IF, PORT_SQM_DEFAULT
    original = await root_kind(r.console, wan)
    cleanup = CleanupStack()
    try:
        await tc(r.console, "qdisc", "replace", "dev", wan, "root", "handle", ROOT, kind)
        cleanup.push(lambda: restore_root(r.console, wan, original))
        await offload(r, inbound(r, "udp", port))
        await lan_start(r, echo=[port])
        before = await r.state()
        _, reverse = await admit(r, port)
        queued = await sent(r.console, wan)
        echoed = await asyncio.to_thread(lockstep, r.lan_ip, port, COUNT)
        queued = await sent(r.console, wan) - queued
        after = await r.state()
    finally:
        await cleanup.teardown("root qdisc")
    rows = uploads(after, r, port)
    r.record(f"sqm-default-{kind}", {"original": original, "before": before, "reverse": reverse,
                                     "after": after, "echoed": echoed, "queued": queued})

    assert echoed == COUNT, echoed
    assert len(rows) == 1 and rows[0]["cookie"] == reverse["cookie"], (reverse, rows)
    assert int(rows[0]["packets"]) - int(reverse["packets"]) == COUNT, (reverse, rows)
    assert queued <= COUNT // 4, (f"the {kind} root sent the replies the hardware carries", queued)
    assert after.get("tc_refused", 0) == before.get("tc_refused", 0), (
        "a default root was taken for a shaper", before.get("tc_refused"), after.get("tc_refused"))


async def test_explicit_fq_keeps_the_upload_in_software(qos):
    """An fq the operator put at the WAN port's root keeps the upload in
    software, as cake does there, and leaves the download, which leaves by
    the LAN port, in hardware.

    fq is a kind Linux attaches by default, and as the kernel attaches it --
    mq's children, or the root of a single-queue device, with
    net.core.default_qdisc=fq -- it counts for nothing. One tc created is
    there for a reason the adapter cannot read: fq paces every flow through
    it to its `maxrate`, which the port's queues do not, and tc's dump is the
    only place that says whether one was given. So an explicit fq counts,
    whatever its parameters. This one is given none and shapes nothing, so
    the rate says nothing either way; the adapter's rows and `tc_refused`
    are the oracle, and fq's own count shows the upload went through it.

    Before, fq was let through by its kind alone, and the upload was
    offloaded past whatever pacing it was given.
    """
    r = qos
    wan, port = TARGET_WAN_IF, PORT_SQM_FQ
    original = await root_kind(r.console, wan)
    cleanup = CleanupStack()
    try:
        await tc(r.console, "qdisc", "replace", "dev", wan, "root", "handle", ROOT, "fq")
        cleanup.push(lambda: restore_root(r.console, wan, original))
        await offload(r, outbound(r, port))
        await lan_start(r, iperf=[port])
        run = await measured(r, port, wan, reverse=True)
    finally:
        await cleanup.teardown("root qdisc")
    delivered = arrived(run["report"])
    upload = uploads(run["during"], r, port) + uploads(run["after"], r, port)
    download = downloads(run["after"], r, port)
    r.record("sqm-explicit-fq", {**run, "original": original, "arrived": delivered})

    assert not upload, ("the upload was offloaded past an fq tc created", upload)
    assert len(download) == 1, ("the download half, on no paced path, was not in hardware",
                                run["after"]["flows"])
    assert_counted(run["before"], run["after"], "tc_refused")
    assert run["shaped"] >= 0.9 * delivered, (
        "fq sent fewer packets than the upload delivered", run["shaped"], delivered)


# ---- a PPPoE WAN ------------------------------------------------------------

@pytest.mark.parametrize("on", ["ppp_if", "ppp_lower"], ids=["session", "tag"])
async def test_cake_on_the_session_keeps_the_upload_in_software(pppoe_rig, on):
    """SQM on a PPPoE WAN shapes the session's own device, where the line's
    rate applies, or the tag under it: devices the upload crosses above the
    WAN port, which no hardware entry passes through. With cake on either,
    the upload stays in software, where the flowtable sends it down the
    session device and every datagram of it through cake; the download,
    which arrives inside the session and leaves by the LAN port, stays in
    hardware.

    Before, the upload was offloaded through the offline-port detour and cake
    on the session sent next to none of it.
    """
    r = pppoe_rig
    dev = getattr(r, on)
    upload = {"ingress": TARGET_LAN_IF, "proto": 17, "src": f"{r.lan_ip}:{SPORT}",
              "dst": f"{INNER_LOCAL}:{DPORT}"}
    download = {"ingress": TARGET_WAN_IF, "proto": 17, "src": f"{INNER_LOCAL}:{DPORT}",
                "dst": f"{r.lan_ip}:{SPORT}"}
    await load(r, "sch_cake")
    cleanup = CleanupStack()
    try:
        # Before the flowtable binds, so nothing it holds sees the change.
        await shaper(r, cleanup, dev)
        before = await r.state()
        await r.table()
        # Both directions are offered together, so the download's admission
        # says the upload's was decided too. A refused direction is offered
        # again about once a second while it carries traffic, so a few more
        # rounds give a late admission every chance to land.
        await drive(r, lambda: r.exchange(16), lambda s: directions(s, **download), timeout=15)
        for _ in range(3):
            await r.exchange(64)
        shaped = await sent(r.console, dev)
        await r.exchange(COUNT)
        shaped = await sent(r.console, dev) - shaped
        after = await r.state()
    finally:
        await cleanup.teardown("software qdisc")
    r.record(f"sqm-pppoe-{on}", {"dev": dev, "before": before, "after": after, "shaped": shaped})

    assert shaped >= COUNT, (
        f"cake on {dev} sent {shaped} packets while the LAN VM sent {COUNT} datagrams up it",
        directions(after, **upload))
    assert not directions(after, **upload), ("the upload was offloaded past cake", after["flows"])
    assert len(directions(after, **download)) == 1, (
        "the download, on no shaped path, was not in hardware", after["flows"])
    assert_counted(before, after, "tc_refused")


async def xfrm_configured(r):
    """Whether the DUT has an xfrm policy, or a default other than accept:
    what sends every packet of the rig's table up Linux's slow path
    (nf_flow_offload_ip_hook())."""
    policies = await command(r.target, r.session, "ip", "xfrm", "policy", "list")
    defaults = await command(r.target, r.session, "ip", "xfrm", "policy", "getdefault")
    return bool(policies["stdout"].strip()) or "block" in defaults["stdout"].lower()


async def test_sqm_on_the_session_follows_linux(pppoe_rig):
    """SQM's download shaper where most consumers put it: on the PPPoE
    session's own device, `pppoe-wan`, an `ingress` qdisc whose one u32
    filter redirects every frame the device receives to an ifb carrying cake.
    The hardware has to do what Linux's own path would, no more and no less,
    and what that path crosses on the way in depends on which path it is: the
    software fast path takes the frame at the flowtable hook on the WAN port,
    before the tag's device and the session's receive it, so with no xfrm
    policy configured the ifb shapes no download Linux forwards either
    (ft_fast_path()).

    Linux is asked first. A software filter on what the LAN port sends --
    nothing to do with the session -- keeps the download out of hardware, and
    a burst of it is forwarded in software: whether the ifb's cake counts it
    is what Linux's own path crosses. Then the filter goes, and the adapter's
    decision has to match: the download in hardware where Linux's path passed
    the ifb by, kept out of it and shaped where it crossed it. The kernel
    analysis says which it is from the DUT's xfrm configuration; a burst that
    disagrees with it fails as such, and so does an adapter that disagrees
    with Linux.
    """
    r = pppoe_rig
    lan, ppp = r.dut_lan_if, r.ppp_if
    # sqm-scripts' name for it, within IFNAMSIZ.
    ifb = f"ifb4{ppp}"[:15]
    upload = {"ingress": TARGET_LAN_IF, "proto": 17, "src": f"{r.lan_ip}:{SPORT}",
              "dst": f"{INNER_LOCAL}:{DPORT}"}
    download = {"ingress": TARGET_WAN_IF, "proto": 17, "src": f"{INNER_LOCAL}:{DPORT}",
                "dst": f"{r.lan_ip}:{SPORT}"}
    await load(r, "sch_cake")
    await load(r, "act_mirred")
    await load(r, "ifb", "numifbs=0")
    slow = await xfrm_configured(r)
    cleanup, lan_filter = CleanupStack(), CleanupStack()
    try:
        # A run killed before its teardown leaves these behind.
        await tc(r.console, "qdisc", "del", "dev", ppp, "ingress", check=False)
        await tc(r.console, "qdisc", "del", "dev", lan, "clsact", check=False)
        await command(r.target, r.session, "ip", "link", "del", ifb, check=False)
        await command(r.target, r.session, "ip", "link", "add", "name", ifb, "type", "ifb")
        cleanup.push(lambda: command(r.target, r.session, "ip", "link", "del", ifb))
        await command(r.target, r.session, "ip", "link", "set", ifb, "up")
        await shaper(r, cleanup, ifb)
        await tc(r.console, "qdisc", "add", "dev", ppp, "handle", "ffff:", "ingress")
        cleanup.push(lambda: remove_qdisc(r.console, ppp, "ingress", "ingress"))
        await tc(r.console, "filter", "add", "dev", ppp, "parent", "ffff:", "protocol", "all",
                 "prio", "10", "u32", "match", "u32", "0", "0", "flowid", "1:1",
                 "action", "mirred", "egress", "redirect", "dev", ifb)
        # The unrelated way into software: a filter on what the LAN port
        # sends, which the download leaves through and the upload does not.
        await tc(r.console, "qdisc", "add", "dev", lan, "clsact")
        lan_filter.push(lambda: remove_qdisc(r.console, lan, "clsact", "clsact"))
        await tc(r.console, "filter", "add", "dev", lan, "egress", "protocol", "all",
                 "prio", "10", "u32", "match", "u32", "0", "0", "action", "pass")
        before = await r.state()
        await r.table()
        # Both directions are offered together: the upload in says the
        # download was decided too.
        await drive(r, lambda: r.exchange(16), lambda s: directions(s, **upload), timeout=15)
        for _ in range(3):
            await r.exchange(64)
        soft = await sent(r.console, ifb)
        await r.exchange(COUNT)
        soft = await sent(r.console, ifb) - soft
        in_software = await r.state()
        # Linux has answered. Now the filter goes, and the adapter answers.
        await lan_filter.teardown("LAN filter")
        deadline = time.monotonic() + 15
        while True:
            await r.exchange(16)
            settled = await r.state()
            if directions(settled, **download) or time.monotonic() >= deadline:
                break
        for _ in range(3):
            await r.exchange(64)
        hard = await sent(r.console, ifb)
        await r.exchange(COUNT)
        hard = await sent(r.console, ifb) - hard
        after = await r.state()
    finally:
        await lan_filter.teardown("LAN filter")
        await cleanup.teardown("software qdisc")
    crossed, passed = soft >= 0.9 * COUNT, soft <= COUNT // 10
    r.record("sqm-pppoe-ingress", {"ppp": ppp, "slow": slow, "soft": soft, "hard": hard,
                                   "before": before, "in_software": in_software,
                                   "after": after})

    # Linux's own path, which the burst forwarded in software shows.
    assert crossed or passed, (
        f"the ifb's cake counted {soft} of {COUNT} datagrams Linux forwarded: neither path", soft)
    assert not directions(in_software, **download), (
        "the download was in hardware past the LAN port's egress filter", in_software["flows"])
    # The adapter's decision, which has to be Linux's.
    downloaded = directions(after, **download)
    if crossed:
        assert not downloaded and hard >= 0.9 * COUNT, (
            (f"Linux's path crosses the ifb on {ppp}, and the adapter carried the download "
             f"past it ({hard} of {COUNT} counted)"), downloaded)
    else:
        assert len(downloaded) == 1, (
            (f"Linux's path passes the ifb on {ppp} by, and the adapter kept the download "
             "out of hardware anyway"), after["flows"])
        assert hard <= COUNT // 10, (hard, COUNT)
    # And the kernel analysis behind ft_fast_path(): the slow path, and so
    # the ifb, exactly while an xfrm policy or a blocking default is set.
    assert crossed == slow, (
        (f"Linux's path {'crossed' if crossed else 'passed'} the ifb on {ppp} with xfrm "
         f"{'configured' if slow else 'unconfigured'}, where ft_fast_path() expects it to "
         f"{'cross' if slow else 'pass'}: the receive-side rule is wrong for this topology"),
        soft)
    assert_counted(before, in_software, "tc_refused")
