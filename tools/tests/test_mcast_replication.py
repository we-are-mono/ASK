"""Phase 2 item 3b/3c: multicast data-plane replication correctness.

Asserts that for a multicast group with 3 listeners, *exactly one*
replicated frame arrives on each listener interface when one
multicast UDP frame is injected. Tripwire shape: count == 1
discriminates loudly between drop (0), correct replication (1), and
double-replication (>=2).

Bug class under test (per the Phase 2 plan): the listeners[]
iteration loop at cdx/dpa_control_mc.c:443-453 and the uiListenerCnt
accounting around it. Not asserting multi-physical-port HW
replication semantics — that's an FMAN/PCD topic outside Phase 2
scope. VLAN-pseudo-ports exercise the listener loop because each
(target_iface, lan_iface) pair is a distinct entry in
pMcastGrpInfo->members[].

Two variants — each registers its OWN mcast group with the right
ingress for its injection direction:

  3b WAN-side injection (dst=239.7.2.1, ingress=eth3) — orchestrator's
     local scapy sends an untagged mcast frame onto the WAN wire; it
     ingresses on the DUT's eth3 and matches the group's ingress.
     All 3 listeners must receive exactly 1 frame.

  3c LAN-side VLAN-tagged injection (dst=239.7.2.2, ingress=eth4.241)
     — LAN VM scapy sends a VLAN-tagged mcast frame out vlan241; it
     ingresses on eth4.241 (a member port matching the group's
     ingress). The other 2 listeners must receive exactly 1; the
     source listener's self-echo is recorded as a tripwire constant.

Capture mechanism: tcpdump -G 2 -W 1 -w pcap on each listener subif
runs in parallel on the LAN VM. The LAN VM is reachable only over
the libvirt UART (it's behind the DUT NAT, no IP path from the
orchestrator), so we launch the parallel tcpdumps via a single
backgrounded shell command on the UART, sleep through the capture
window, then read each pcap back sequentially via tcpdump -r.

Noise floor: 2-second pre-test drain (background mcast on shared
subnets must not pollute the count); per-listener subif (cross-group
multicast filtered out by VLAN membership); tight UDP-port match.
"""

from __future__ import annotations

import asyncio
import os
import struct

import pytest
import pytest_asyncio

from _topology import (
    lan_run_python,
    multi_listener_subifs,  # noqa: F401  (fixture, imported for resolution)
)


# Mcast group + payload conventions
MCAST_DST_3B = os.environ.get("ASK_MCAST_REPL_DST_3B", "239.7.2.1")
MCAST_DST_3C = os.environ.get("ASK_MCAST_REPL_DST_3C", "239.7.2.2")
MCAST_SRC    = os.environ.get("ASK_WAN_IPERF_IP",      "10.0.0.141")
MCAST_PORT   = int(os.environ.get("ASK_MCAST_REPL_PORT", "47200"))
INGRESS_3B   = os.environ.get("ASK_MCAST_INGRESS_WAN", "eth3")
# 3c's ingress is the source LAN VLAN subif on the DUT — set per
# fixture below since it depends on the listener fixture's vid choice.

# FCI codes/wire layout — same as test_mcast_pagination
CMD_MC4_MULTICAST     = 0x0701
CDX_MC_ACTION_ADD     = 0
CDX_MC_ACTION_REMOVE  = 1
NO_ERR                = 0
ERR_MC_CONFIG         = 707
IF_NAME_SIZE          = 16
MC4_MIN_COMMAND_SIZE  = 44


def _ip_be_bytes(addr: str) -> bytes:
    return bytes(int(o) for o in addr.split("."))


def _pack_mc4_output(iface: str) -> bytes:
    name = iface.encode().ljust(IF_NAME_SIZE, b"\x00")[:IF_NAME_SIZE]
    return (
        b"\x00\x00\x00\x00"   # timer
        + name                # output_device_str[16]
        + b"\x00"             # shaper_mask
        + b"\x00"             # bitfield
        + b"\x00" * 6         # uc_mac
        + b"\x00"             # queue
        + b"\x00" * 16        # new_output_device_str
        + b"\x00"             # bitfield
        + b"\x00\x00"         # padding[2]
    )


def _pack_mc4_command(
    action: int, listeners: list[str], *,
    dst: str, src: str = MCAST_SRC, ingress: str,
) -> bytes:
    n = len(listeners)
    header = (
        struct.pack("<HBB", action, 0, 0)
        + _ip_be_bytes(src)
        + _ip_be_bytes(dst)
        + struct.pack("<I", n)
    )
    ingress_field = ingress.encode().ljust(IF_NAME_SIZE, b"\x00")[:IF_NAME_SIZE]
    outputs = b"".join(_pack_mc4_output(i) for i in listeners)
    wire = header + ingress_field + outputs
    if len(wire) < MC4_MIN_COMMAND_SIZE:
        wire += b"\x00" * (MC4_MIN_COMMAND_SIZE - len(wire))
    return wire


# ---- mcast group lifecycle fixtures --------------------------------------

async def _assert_mc4_has_group(
    target_agent, session, *, dst: str,
) -> None:
    """Query the FCI mc4 table and assert `dst` appears among registered
    groups. Catches the silent-ADD-failure case where fci_send returned
    NO_ERR but the group never persisted into the FCI table.
    """
    r = await target_agent.cmm_query(session, "mc4")
    out = (r.get("stdout") or "") + (r.get("stderr") or "")
    if "table empty" in out or dst not in out:
        raise AssertionError(
            f"FCI ADD reported NO_ERR but group {dst} is missing from "
            f"mc4 table — silent registration failure. cmm output:\n"
            f"  stdout: {(r.get('stdout') or '')[:400]!r}\n"
            f"  stderr: {(r.get('stderr') or '')[:400]!r}"
        )


@pytest_asyncio.fixture
async def mcast_group_wan_ingress(
    aiohttp_session, target_agent, multi_listener_subifs,
):
    """3b group: ingress=eth3 (WAN), all 3 listeners as members."""
    listeners = multi_listener_subifs
    target_ifaces = [t for t, _, _ in listeners]

    add = _pack_mc4_command(
        CDX_MC_ACTION_ADD, target_ifaces,
        dst=MCAST_DST_3B, ingress=INGRESS_3B,
    )
    r = await target_agent.fci_send(
        aiohttp_session, fcode=CMD_MC4_MULTICAST,
        length=len(add), payload=add, timeout_ms=2000,
    )
    assert r.get("reply_rc") == NO_ERR, f"3b mcast ADD failed: {r}"
    await _assert_mc4_has_group(
        target_agent, aiohttp_session, dst=MCAST_DST_3B,
    )

    try:
        yield listeners
    finally:
        rem = _pack_mc4_command(
            CDX_MC_ACTION_REMOVE, target_ifaces,
            dst=MCAST_DST_3B, ingress=INGRESS_3B,
        )
        r = await target_agent.fci_send(
            aiohttp_session, fcode=CMD_MC4_MULTICAST,
            length=len(rem), payload=rem, timeout_ms=2000,
        )
        rc = r.get("reply_rc")
        if rc not in (NO_ERR, ERR_MC_CONFIG):
            import warnings
            warnings.warn(f"3b teardown REMOVE returned reply_rc={rc}: {r}")


@pytest_asyncio.fixture
async def mcast_group_lan_vlan_ingress(
    aiohttp_session, target_agent, multi_listener_subifs,
):
    """3c group: ingress=<source VLAN subif>, all 3 listeners as members.
    Source iface is listeners[0][0] (the first DUT-side VLAN subif)."""
    listeners = multi_listener_subifs
    target_ifaces = [t for t, _, _ in listeners]
    ingress_iface = listeners[0][0]   # e.g. eth4.241

    add = _pack_mc4_command(
        CDX_MC_ACTION_ADD, target_ifaces,
        dst=MCAST_DST_3C, ingress=ingress_iface,
    )
    r = await target_agent.fci_send(
        aiohttp_session, fcode=CMD_MC4_MULTICAST,
        length=len(add), payload=add, timeout_ms=2000,
    )
    assert r.get("reply_rc") == NO_ERR, (
        f"3c mcast ADD (ingress={ingress_iface}) failed: {r}"
    )
    await _assert_mc4_has_group(
        target_agent, aiohttp_session, dst=MCAST_DST_3C,
    )

    try:
        yield listeners, ingress_iface
    finally:
        rem = _pack_mc4_command(
            CDX_MC_ACTION_REMOVE, target_ifaces,
            dst=MCAST_DST_3C, ingress=ingress_iface,
        )
        r = await target_agent.fci_send(
            aiohttp_session, fcode=CMD_MC4_MULTICAST,
            length=len(rem), payload=rem, timeout_ms=2000,
        )
        rc = r.get("reply_rc")
        if rc not in (NO_ERR, ERR_MC_CONFIG):
            import warnings
            warnings.warn(f"3c teardown REMOVE returned reply_rc={rc}: {r}")


@pytest_asyncio.fixture
async def pcap_cleanup_lan(lan):
    """Tracks pcap paths created during a test; rm them on teardown so
    /tmp on the LAN VM doesn't accumulate over many parametrize runs.
    UART has direct shell access — single rm call suffices.
    """
    paths: list[str] = []
    yield paths
    if paths:
        try:
            lan.run("rm -f " + " ".join(paths), timeout=5)
        except Exception:
            pass


# ---- capture helpers (UART-driven, no LAN agent required) ----------------

_TCPDUMP_PIDFILE_PREFIX = "/tmp/ask_mcast_tcpdump"


def _spawn_parallel_tcpdumps(
    lan, ifaces: list[str], capfiles: list[str], port: int, window_s: float,
) -> None:
    """Launch one backgrounded tcpdump per (iface, capfile) on the LAN VM.

    Plain `tcpdump -w file &` (no -G/-W) so behaviour is portable across
    tcpdump/libpcap versions; `pkill` after the window terminates them
    cleanly. We capture each tcpdump's PID into a sidecar file so the
    later kill is precise instead of `pkill -f tcpdump`-broad.

    Single UART command chains all spawns so the UART round-trip is
    one shot regardless of N.
    """
    bpf = f"udp port {port}"
    # `&` terminates a command, then `echo $!` captures the pid into a
    # sidecar. Background processes need stdin/stdout/stderr redirection
    # so they detach cleanly from the controlling shell.
    chain = ""
    for iface, capfile in zip(ifaces, capfiles):
        pidfile = f"{_TCPDUMP_PIDFILE_PREFIX}_{iface}.pid"
        # `-Q in` records inbound only — excludes the local sendp's
        # egress copy that AF_PACKET would otherwise capture, so the
        # frame count reflects just what arrives at the listener
        # (replicated by the DUT, plus any FMAN self-echo to the
        # ingress port).
        chain += (
            f"nohup tcpdump -i {iface} -Q in -w {capfile} '{bpf}' "
            f"</dev/null >/dev/null 2>&1 & "
            f"echo $! > {pidfile}; "
        )
    chain += "echo SPAWNED"
    r = lan.run(chain, timeout=10)
    assert "SPAWNED" in r.stdout, (
        f"failed to spawn tcpdumps via UART: rc={r.rc}, out={r.stdout!r}"
    )


def _kill_parallel_tcpdumps(lan, ifaces: list[str]) -> None:
    """SIGTERM the previously-spawned tcpdumps via their pid sidecars."""
    chain = ""
    for iface in ifaces:
        pidfile = f"{_TCPDUMP_PIDFILE_PREFIX}_{iface}.pid"
        # `kill -TERM $(cat <pidfile>) 2>/dev/null || true` so a
        # missing pidfile or already-dead pid doesn't fail the chain.
        chain += (
            f"[ -f {pidfile} ] && kill -TERM $(cat {pidfile}) "
            f"2>/dev/null; rm -f {pidfile}; "
        )
    chain += "echo KILLED"
    r = lan.run(chain, timeout=10)
    assert "KILLED" in r.stdout, (
        f"failed to kill tcpdumps: rc={r.rc}, out={r.stdout!r}"
    )


def _read_pcap_count(lan, capfile: str) -> int:
    """Parse a saved pcap via `tcpdump -r`; count UDP summary lines."""
    r = lan.run(f"tcpdump -r {capfile} -nn 2>&1", timeout=10)
    if r.rc != 0:
        raise AssertionError(
            f"tcpdump -r {capfile} failed: rc={r.rc}, out={r.stdout!r}"
        )
    return sum(
        1 for ln in r.stdout.splitlines()
        if " IP " in ln and "UDP" in ln
    )


async def _capture_parallel_window(
    lan, *, ifaces: list[str], capfiles: list[str], port: int,
    window_s: float = 2.0,
) -> dict[str, int]:
    """Spawn parallel tcpdumps, sleep through the window, kill them,
    read the pcaps, return per-iface counts. Pure UART — no LAN agent
    needed (LAN VM is behind the DUT NAT).
    """
    _spawn_parallel_tcpdumps(lan, ifaces, capfiles, port, window_s)
    # Tiny grace so tcpdumps are listening before any traffic arrives.
    # Caller is expected to inject AFTER this returns.
    await asyncio.sleep(0.4)
    await asyncio.sleep(window_s)
    _kill_parallel_tcpdumps(lan, ifaces)
    # Tiny pause for the pcap writer to flush on TERM.
    await asyncio.sleep(0.2)
    return {
        iface: _read_pcap_count(lan, cf)
        for iface, cf in zip(ifaces, capfiles)
    }


# ---- 3b: WAN-side injection -----------------------------------------------

def _send_mcast_from_orchestrator(dst: str, port: int, payload: bytes) -> None:
    """Send one IPv4 mcast UDP frame from the orchestrator host onto the
    DUT-facing bridge. Uses L2 sendp with explicit `iface` because
    multicast destinations have no host route, so scapy's L3 send()
    would pick whatever default outbound NIC the kernel finds (often
    not the DUT-facing one).
    """
    import os as _os
    import struct
    from scapy.all import IP, UDP, Raw, Ether, sendp  # type: ignore[import]
    iface = _os.environ.get("ASK_WAN_INJECT_IF", "br0")
    # IPv4 mcast MAC = 01:00:5E:<low 23 bits of dst>.
    o = [int(b) for b in dst.split(".")]
    mac = "01:00:5e:{:02x}:{:02x}:{:02x}".format(o[1] & 0x7f, o[2], o[3])
    # src must match the (S,G) key the MC4 fixture programs (MCAST_SRC).
    # Left to scapy's auto-pick it depends on the orchestrator's address
    # plan — the entry misses and the DUT punts the frame unreplicated.
    pkt = (Ether(dst=mac)
           / IP(src=MCAST_SRC, dst=dst, ttl=4)
           / UDP(dport=port, sport=47201)
           / Raw(payload))
    sendp(pkt, iface=iface, count=1, verbose=0)


async def test_mcast_replication_one_per_listener_wan_injection(
    aiohttp_session, target_agent, lan, splat_window,
    mcast_group_wan_ingress, pcap_cleanup_lan,
):
    """Single mcast frame from WAN, each listener receives exactly one."""
    listeners = mcast_group_wan_ingress
    lan_ifaces = [li for _, li, _ in listeners]
    vids       = [vid for _, _, vid in listeners]

    # Pre-test drain — assert no stray multicast on listeners.
    drain_capfiles = [f"/tmp/ask_mcast_drain_{vid}.pcap" for vid in vids]
    pcap_cleanup_lan.extend(drain_capfiles)
    drain_counts = await _capture_parallel_window(
        lan, ifaces=lan_ifaces, capfiles=drain_capfiles,
        port=MCAST_PORT, window_s=2.0,
    )
    for iface, n in drain_counts.items():
        assert n == 0, (
            f"pre-test drain on {iface} saw {n} stray mcast frames; "
            f"port {MCAST_PORT} is contaminated"
        )

    # Capture window: spawn tcpdumps, then inject after a small grace.
    capfiles = [f"/tmp/ask_mcast_wan_{vid}.pcap" for vid in vids]
    pcap_cleanup_lan.extend(capfiles)

    _spawn_parallel_tcpdumps(
        lan, lan_ifaces, capfiles, port=MCAST_PORT, window_s=2.0,
    )
    try:
        # Small grace so tcpdumps are listening before the mcast hits.
        await asyncio.sleep(0.4)
        await asyncio.to_thread(
            _send_mcast_from_orchestrator,
            MCAST_DST_3B, MCAST_PORT, b"mcast_wan",
        )
        # Wait the rest of the capture window before terminating.
        await asyncio.sleep(2.0)
    finally:
        _kill_parallel_tcpdumps(lan, lan_ifaces)
    # Brief pause for the pcap writer to flush on TERM.
    await asyncio.sleep(0.2)

    counts = {
        iface: _read_pcap_count(lan, cf)
        for iface, cf in zip(lan_ifaces, capfiles)
    }
    for iface, n in counts.items():
        assert n == 1, (
            f"replication count mismatch on {iface}: expected exactly 1 "
            f"frame, got {n}. Drop=0 (HW didn't replicate), >=2 means "
            f"double-replication. listeners={listeners}"
        )


# ---- 3c: LAN-side VLAN-tagged injection -----------------------------------

_LAN_INJECT_TEMPLATE = """
from scapy.all import IP, UDP, Raw, sendp, Ether
# Spoof src to match the MC4 ADD's registered source — the FMAN ehash
# lookup is exact-match on (src, dst, ingress) and the LAN VM's
# DHCP-assigned vlan241 IP would otherwise diverge from the canonical
# WAN-side source the test fixtures register.
pkt = (Ether()
       / IP(src="{src}", dst="{dst}", ttl=4)
       / UDP(dport={port}, sport=47202)
       / Raw(b"mcast_vlan"))
sendp(pkt, iface="{lan_if}", count=1, verbose=0)
print("INJECTED")
"""


async def test_mcast_replication_lan_vlan_tagged_injection(
    aiohttp_session, target_agent, lan, splat_window,
    mcast_group_lan_vlan_ingress, pcap_cleanup_lan,
):
    """Mcast injected from LAN through one VLAN subif. The group's
    ingress field is set to that VLAN subif, so the LAN-tagged frame
    matches the (S, G, ingress) lookup. Replication should hit *the
    other two* listeners; the source listener's self-echo is asserted
    against a tripwire constant.
    """
    listeners, ingress_iface = mcast_group_lan_vlan_ingress
    src_target_if, src_lan_if, src_vid = listeners[0]
    other = listeners[1:]
    assert src_target_if == ingress_iface, (
        f"3c fixture wired wrong: ingress={ingress_iface} "
        f"!= src_target_if={src_target_if}"
    )

    script = _LAN_INJECT_TEMPLATE.format(
        src=MCAST_SRC, dst=MCAST_DST_3C, port=MCAST_PORT, lan_if=src_lan_if,
    )

    await asyncio.sleep(0.3)

    lan_ifaces = [li for _, li, _ in listeners]
    vids       = [vid for _, _, vid in listeners]
    capfiles   = [f"/tmp/ask_mcast_vlan_{vid}.pcap" for vid in vids]
    pcap_cleanup_lan.extend(capfiles)

    _spawn_parallel_tcpdumps(
        lan, lan_ifaces, capfiles, port=MCAST_PORT, window_s=2.0,
    )
    try:
        # Grace before injection so tcpdumps are listening.
        await asyncio.sleep(0.4)
        r = await lan_run_python(lan, script, label="mcast_vlan_inject", timeout=15.0)
        assert r.rc == 0, f"injection failed: {r.stdout!r}"
        # Drain window for replicated frames.
        await asyncio.sleep(2.0)
    finally:
        _kill_parallel_tcpdumps(lan, lan_ifaces)
    # tcpdump only flushes the pcap on TERM; a stray read while the
    # writer is still alive yields a truncated/empty file.
    await asyncio.sleep(0.2)

    counts = {
        iface: _read_pcap_count(lan, cf)
        for iface, cf in zip(lan_ifaces, capfiles)
    }

    # The two non-source listeners must each receive exactly one frame.
    for _, lan_if, _ in other:
        n = counts[lan_if]
        assert n == 1, (
            f"VLAN-tagged mcast: non-source listener {lan_if} got "
            f"{n} frames, expected exactly 1. counts={counts}"
        )

    # Source-listener self-echo: FMAN replicates to ALL listeners in
    # the MC4 group, including the ingress port itself when it's also
    # registered as a listener. With tcpdump filtered to inbound only
    # (`-Q in`), the local sendp egress isn't counted — so the source
    # listener should see exactly 1 frame (the FMAN-replicated copy).
    SRC_SELF_ECHO_EXPECTED = 1
    assert counts[src_lan_if] == SRC_SELF_ECHO_EXPECTED, (
        f"VLAN-tagged mcast: source listener {src_lan_if} got "
        f"{counts[src_lan_if]} frames; expected {SRC_SELF_ECHO_EXPECTED} "
        f"(self-echo tripwire). If this is intended new behaviour, "
        f"update SRC_SELF_ECHO_EXPECTED in this file."
    )
