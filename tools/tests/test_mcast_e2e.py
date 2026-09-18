"""End-to-end multicast offload: a real consumer joins, a real source sends.

Everything else that touches multicast in this suite programs a group by hand
over FCI and then checks the hardware replicated it. That proves the encoder.
It cannot prove the thing this increment is actually about, which is that
nobody has to program anything: the LAN VM sends an IGMP or MLD report, the
bridge's own snooping learns the group, and the offload follows from that.

Topology. vision (the orchestrator, this host) is the source, on the DUT's WAN
port. loki (the LAN VM) is the consumer, behind the DUT and reachable only over
the libvirt UART. The DUT bridges the two.

**The assertion that matters is not that loki receives the stream.** The Linux
bridge floods multicast perfectly well in software, so arrival proves
forwarding and says nothing about offload. Each case therefore carries three
oracles, and the third is the one that discriminates:

  1. `bridge mdb show` reports `offload` against the port group. Read this as
     "the adapter took responsibility for the group", not "the hardware is
     carrying it": the switchdev handler runs under RTNL and cannot take the
     transaction an install needs, so it decides and a work item installs.
     See docs/flowtable-multicast.md, "The handler cannot install".
  2. The group is present in the hardware table, read from /proc. THIS is
     "actually installed", and it is where a disagreement with (1) surfaces.
  3. **The DUT's CPU does not see the stream.** A hardware-replicated frame is
     matched and transmitted by the FMAN and never reaches the host, so a
     capture on the DUT's bridge device counts ~0 while loki counts thousands.
     Software flooding cannot produce that, and neither can a group that is
     merely present in a table but not matching.

The three deliberately mean different things — accepted, installed, and
matching — so a case that passes all three has been checked at three
independent points rather than three times at one.

IGMPv2 and IGMPv3 are both covered and the split is not incidental. The
classifier key is an exact (S,G), so a v3 INCLUDE report — which carries a
source — is installable from the membership alone, while a v2 report or a v3
EXCLUDE{} gives a (*,G) the membership cannot key, and the group only appears
once traffic has taught the adapter its source and ingress port. Those are two
different halves of the learner, and a suite that used whatever `ip maddr`
happened to emit would exercise one of them.
"""

from __future__ import annotations

import asyncio
import os

import pytest
import pytest_asyncio

from _mcast_helpers import (  # noqa: F401  (fixture imported for resolution)
    capture_parallel_window,
    pcap_cleanup_lan,
)
from _topology import (
    LAN_NIC,
    TARGET_LAN_IF,
    TARGET_WAN_IF,
    TopologyStack,
    lan_run,
    lan_run_python,
)

pytestmark = pytest.mark.asyncio


# The bridge the DUT puts its two test ports into. Not `br-lan`: the shipping
# configuration is not ours to disturb, and a test that reused it could not
# tell its own groups from the product's.
BRIDGE = "br_mcast_e2e"
# `fwd` and `lt` are nft keywords and a chain named either fails with a syntax
# error that reads like console corruption; the same caution is worth keeping
# for bridge names that shell out.

MCAST_PORT = int(os.environ.get("ASK_MCAST_E2E_PORT", "47300"))
# Above 1, always. See send_stream_from_vision() and the TTL section of
# docs/flowtable-multicast.md: the parser refuses to classify TTL 0 or 1.
MCAST_TTL = int(os.environ.get("ASK_MCAST_E2E_TTL", "64"))
# Distinct group per case so a stale entry from one cannot satisfy another.
GROUPS_V4 = {
    "v3_include": "239.8.1.1",
    "v2": "239.8.1.2",
    "vlan": "239.8.1.3",
    "rejoin": "239.8.1.4",
    "routed": "239.8.1.5",
}
GROUPS_V6 = {
    "mldv2_include": "ff1e::8:1:1",
    "mldv1": "ff1e::8:1:2",
    "routed": "ff1e::8:1:5",
}
# The ISP's IPTV VLAN in the deployment this increment exists for.
IPTV_VID = int(os.environ.get("ASK_MCAST_E2E_VID", "3999"))

# How long a case lets the stream run. Long enough that a software-forwarded
# stream would put thousands of frames through the DUT's CPU, which is what
# the negative oracle measures against.
STREAM_S = 3.0
STREAM_PPS = 500


# ---------------------------------------------------------------- fixtures

@pytest_asyncio.fixture
async def mcast_bridge(aiohttp_session, target_agent):
    """The DUT bridging its WAN and LAN ports, with IGMP/MLD snooping on and a
    querier of its own.

    The querier is not optional. Without one nothing on the segment elicits
    membership reports, the MDB stays empty, and the bridge floods every group
    to every port — which looks exactly like a working test and proves nothing.
    """
    stack = TopologyStack()

    async def _exec(*argv: str):
        return await target_agent.exec_cmd(aiohttp_session, list(argv))

    try:
        await _exec("ip", "link", "del", BRIDGE)  # idempotent
        r = await _exec("ip", "link", "add", "name", BRIDGE, "type", "bridge",
                        "mcast_snooping", "1", "mcast_querier", "1")
        assert r["rc"] == 0, f"bridge add {BRIDGE}: {r}"

        async def _cleanup():
            for port in (TARGET_WAN_IF, TARGET_LAN_IF):
                await _exec("ip", "link", "set", port, "nomaster")
            await _exec("ip", "link", "del", BRIDGE)
        stack.push(_cleanup)

        for port in (TARGET_WAN_IF, TARGET_LAN_IF):
            r = await _exec("ip", "link", "set", port, "master", BRIDGE)
            assert r["rc"] == 0, f"enslave {port}: {r}"
            r = await _exec("ip", "link", "set", port, "up")
            assert r["rc"] == 0, f"up {port}: {r}"
        r = await _exec("ip", "link", "set", BRIDGE, "up")
        assert r["rc"] == 0, f"bridge up: {r}"

        # The querier's startup queries are spaced by
        # multicast_startup_query_interval; without waiting them out the first
        # join can land before snooping is querying and be missed.
        await asyncio.sleep(3.0)
        yield BRIDGE
    finally:
        await stack.teardown("mcast_bridge")


# ---------------------------------------------------------------- oracles

async def mdb_reports_offload(target_agent, session, group: str) -> bool:
    """Whether the bridge says a driver took this group's port group on.

    br_switchdev_mdb_complete() sets MDB_PG_FLAGS_OFFLOAD only when the
    switchdev object was handled without error, and `bridge mdb show` prints
    it. Nothing else in the bridge consults that flag, so it is purely a
    report — which is what makes it a clean oracle rather than a mechanism the
    test could accidentally be driving.
    """
    r = await target_agent.exec_cmd(session, ["bridge", "mdb", "show"])
    for line in (r.get("stdout") or "").splitlines():
        if group in line:
            return "offload" in line
    return False


async def hardware_has_group(target_agent, session, group: str) -> bool:
    """Whether the adapter's own table holds the group."""
    r = await target_agent.fs_read(session, "/proc/cdx_flowtable")
    return group in (r.get("content") or "")


async def dut_cpu_frame_count(target_agent, session, bridge: str,
                              group: str, window_s: float) -> int:
    """How many frames of the stream reached the DUT's CPU.

    The discriminating oracle. A hardware-replicated frame is matched and
    transmitted by the FMAN without ever being enqueued to the host, so this
    is ~0 when the offload is carrying the stream and approximately the whole
    stream when the bridge is flooding it in software.
    """
    cap = await target_agent.capture_start(session, ifaces=[bridge])
    await asyncio.sleep(window_s)
    r = await target_agent.capture_stop(session, cap["cap_id"])
    return sum(
        1 for ln in (r.get("stdout") or "").splitlines() if group in ln
    )


# ------------------------------------------------------------ LAN VM side

def _join_script(group: str, port: int, source: str | None,
                 family: int, seconds: float, igmp_version: int | None) -> str:
    """A consumer that joins and then counts what arrives.

    Joining with a real socket rather than `ip maddr` is deliberate: the socket
    option decides which report the kernel emits, and that is the whole
    v2-versus-v3 distinction these cases turn on. IP_ADD_SOURCE_MEMBERSHIP
    produces an INCLUDE report naming the source; IP_ADD_MEMBERSHIP with
    force_igmp_version=2 produces a v2 report with none.
    """
    return f"""
import socket, struct, time, sys

GROUP = {group!r}
PORT = {port}
SOURCE = {source!r}
FAMILY = socket.AF_INET6 if {family} == 6 else socket.AF_INET
SECONDS = {seconds}

if {igmp_version!r} is not None:
    with open('/proc/sys/net/ipv4/conf/{LAN_NIC}/force_igmp_version', 'w') as f:
        f.write(str({igmp_version!r}))

s = socket.socket(FAMILY, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('', PORT))

ifindex = socket.if_nametoindex({LAN_NIC!r})
if FAMILY == socket.AF_INET6:
    mreq = socket.inet_pton(socket.AF_INET6, GROUP) + struct.pack('@I', ifindex)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
elif SOURCE is not None:
    # IP_ADD_SOURCE_MEMBERSHIP: imr_multiaddr, imr_interface, imr_sourceaddr.
    mreq = (socket.inet_aton(GROUP) + socket.inet_aton('0.0.0.0')
            + socket.inet_aton(SOURCE))
    s.setsockopt(socket.IPPROTO_IP, 39, mreq)   # IP_ADD_SOURCE_MEMBERSHIP
else:
    mreq = socket.inet_aton(GROUP) + socket.inet_aton('0.0.0.0')
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

print('JOINED', flush=True)
s.settimeout(0.5)
seen = 0
deadline = time.monotonic() + SECONDS
while time.monotonic() < deadline:
    try:
        s.recv(2048)
        seen += 1
    except socket.timeout:
        pass
print('RECEIVED', seen, flush=True)
"""


async def lan_join_and_count(lan, *, group: str, source: str | None,
                             family: int, seconds: float,
                             igmp_version: int | None, label: str) -> int:
    script = _join_script(group, MCAST_PORT, source, family, seconds,
                          igmp_version)
    r = await lan_run_python(lan, script, label=label, timeout=seconds + 30)
    assert "JOINED" in r.stdout, f"LAN join failed: {r.stdout!r}"
    for line in r.stdout.splitlines():
        if line.startswith("RECEIVED"):
            return int(line.split()[1])
    raise AssertionError(f"no RECEIVED line from LAN: {r.stdout!r}")


# ------------------------------------------------------------- WAN source

def send_stream_from_vision(group: str, family: int, seconds: float,
                            pps: int) -> None:
    """Send a multicast UDP stream from this host onto the DUT-facing wire.

    L2 sendp with an explicit iface, because a multicast destination has no
    host route and scapy's L3 send() would pick whatever default outbound NIC
    the kernel finds — which on this orchestrator is not the DUT-facing one.
    Pinning the source address matters just as much: the classifier key is an
    exact (S,G), so a source scapy chose for itself would miss the entry and
    the frame would punt unreplicated. That cost a debugging session once
    already; see commit 73144ff.
    """
    import time
    from scapy.all import (  # type: ignore[import]
        IP, IPv6, UDP, Raw, Ether, sendp,
    )

    iface = os.environ.get("ASK_WAN_INJECT_IF", "br0")
    src = wan_source_address(family)
    # Explicitly, and never inherited. The FMC soft parser ends the parse
    # before classification for TTL 0 or 1, so a TTL-1 stream is never matched
    # in hardware however correct the entry is -- and a plain UDP multicast
    # socket sends TTL 1 by default. Getting this wrong makes a working
    # offload look completely dead; it cost a rig session once.
    if family == 6:
        # IPv6 multicast MAC: 33:33:<low 32 bits of the group>.
        import socket as _socket
        raw = _socket.inet_pton(_socket.AF_INET6, group)
        mac = "33:33:" + ":".join(f"{b:02x}" for b in raw[12:16])
        layer = IPv6(src=src, dst=group, hlim=MCAST_TTL)
    else:
        o = [int(b) for b in group.split(".")]
        mac = "01:00:5e:%02x:%02x:%02x" % (o[1] & 0x7F, o[2], o[3])
        layer = IP(src=src, dst=group, ttl=MCAST_TTL)

    frame = (Ether(dst=mac) / layer / UDP(sport=MCAST_PORT, dport=MCAST_PORT)
             / Raw(b"x" * 512))
    total = int(seconds * pps)
    sendp(frame, iface=iface, count=total, inter=1.0 / pps, verbose=False)


def wan_source_address(family: int) -> str:
    if family == 6:
        return os.environ.get("ASK_WAN_IPV6", "fc00:beef::99")
    # Derived from br0 on THIS host; the conftest default is stale.
    return os.environ.get("ASK_WAN_IPERF_IP", "10.0.0.141")


# ------------------------------------------------------------------- cases

async def run_bridged_case(aiohttp_session, target_agent, lan, *, group: str,
                           family: int, source: str | None,
                           igmp_version: int | None, label: str):
    """One bridged case, end to end, with all three oracles."""
    bridge = BRIDGE

    # A pre-test drain: background multicast on a shared segment must not be
    # counted as this group's.
    await asyncio.sleep(2.0)

    baseline_hw = await hardware_has_group(target_agent, aiohttp_session, group)
    assert not baseline_hw, (
        f"{group} already in the hardware table before the test joined it — "
        f"a stale entry from an earlier run would satisfy every oracle here"
    )

    joiner = asyncio.create_task(lan_join_and_count(
        lan, group=group, source=source, family=family,
        seconds=STREAM_S + 4.0, igmp_version=igmp_version, label=label,
    ))
    # Let the report reach the bridge and the learner act on it.
    await asyncio.sleep(2.0)

    cpu_frames = asyncio.create_task(dut_cpu_frame_count(
        target_agent, aiohttp_session, bridge, group, STREAM_S,
    ))
    await asyncio.to_thread(
        send_stream_from_vision, group, family, STREAM_S, STREAM_PPS,
    )

    received = await joiner
    cpu_seen = await cpu_frames
    offloaded = await mdb_reports_offload(target_agent, aiohttp_session, group)
    in_hw = await hardware_has_group(target_agent, aiohttp_session, group)

    sent = int(STREAM_S * STREAM_PPS)
    # Forwarding first: without it the rest is describing a broken path.
    assert received > sent * 0.5, (
        f"{group}: consumer received {received} of {sent} — the stream is not "
        f"reaching the LAN VM at all, so nothing below is meaningful"
    )
    assert in_hw, f"{group}: forwarded, but no hardware entry — software path"
    assert offloaded, (
        f"{group}: installed in hardware, but `bridge mdb show` does not "
        f"report offload. The flag is set when the adapter accepts the "
        f"switchdev object, which is strictly earlier than the install, so "
        f"an entry present without it means the group reached hardware by "
        f"some path other than the membership it was supposed to come from"
    )
    # The discriminating one.
    assert cpu_seen < sent * 0.05, (
        f"{group}: {cpu_seen} of {sent} frames reached the DUT's CPU. A "
        f"hardware-replicated frame never does, so the bridge is still "
        f"flooding this group in software whatever the table says"
    )


@pytest.mark.parametrize("case,source_kind,igmp_version", [
    ("v3_include", "explicit", 3),
    ("v2", None, 2),
])
async def test_bridged_ipv4(aiohttp_session, target_agent, lan, mcast_bridge,
                            case, source_kind, igmp_version):
    """IPv4, both report versions.

    v3 INCLUDE gives the MDB a source, so the membership alone composes a key.
    v2 gives a (*,G), and the group can only appear once traffic has supplied
    the source and the ingress port — the two halves of the learner.
    """
    source = wan_source_address(4) if source_kind == "explicit" else None
    await run_bridged_case(
        aiohttp_session, target_agent, lan,
        group=GROUPS_V4[case], family=4, source=source,
        igmp_version=igmp_version, label=f"mcast_e2e_v4_{case}",
    )


@pytest.mark.parametrize("case,source_kind", [
    ("mldv2_include", "explicit"),
    ("mldv1", None),
])
async def test_bridged_ipv6(aiohttp_session, target_agent, lan, mcast_bridge,
                            case, source_kind):
    """IPv6, both report versions, against the mc6 side of the encoder."""
    source = wan_source_address(6) if source_kind == "explicit" else None
    await run_bridged_case(
        aiohttp_session, target_agent, lan,
        group=GROUPS_V6[case], family=6, source=source,
        igmp_version=None, label=f"mcast_e2e_v6_{case}",
    )


async def test_bridged_ipv4_on_the_iptv_vlan(aiohttp_session, target_agent,
                                             lan, mcast_bridge):
    """The shape the product actually runs: the ISP delivers IPTV on a VLAN
    the box simply bridges, so the group's frames carry a tag on the way in
    and the listener port's membership decides whether they carry one out.
    """
    pytest.skip("VLAN-aware bridge fixture lands with the membership learner")


async def test_a_leave_does_not_interrupt_the_others(aiohttp_session,
                                                     target_agent, lan,
                                                     mcast_bridge):
    """Two consumers, one leaves mid-stream, the other must not notice.

    This is the chain swap's reason for existing. Replacing a listener set by
    deleting the group and re-adding it would take the key out of the
    classifier between the two, so every remaining listener would lose frames
    because a different listener left — and in an IPTV deployment membership
    changes whenever anyone changes channel.
    """
    pytest.skip("needs the second LAN consumer the topology does not yet have")


@pytest.mark.parametrize("family", [4, 6])
async def test_routed(aiohttp_session, target_agent, lan, family):
    """Routed multicast, programmed through ipmr's MFC by smcroute.

    A second learner against the same encoder: mfc_cache already carries an
    (S,G) and a replication list in ttls[], so it needs none of the traffic
    learning the bridged (*,G) case does, and ft_fib_event() is already on the
    RTNL_FAMILY_IPMR chain — it drops those events at its family filter today.

    Deliberately failing rather than skipping: this is the acceptance gate for
    an increment that has not been built, and a skip would let it be forgotten.
    """
    pytest.fail(
        "routed multicast learner not implemented — reads ipmr's MFC via "
        "call_ipmr_mfc_entry_notifiers() on RTNL_FAMILY_IPMR, which "
        "ft_fib_event() currently filters out. See docs/flowtable-multicast.md "
        "'Open questions'."
    )
