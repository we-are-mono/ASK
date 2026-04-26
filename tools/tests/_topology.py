"""Phase 2 topology + counter helpers shared across data-plane edge tests.

Three concerns colocated here, in order of increasing scope:

  1. Counter signatures + golden-file tripwires. Items 1a / 1d / 2a / 2d
     don't know in advance whether HW silently drops, punts to the
     kernel slow path, or fast-paths the edge-case packet — so they
     record the observed delta of /proc/fqid_stats `frame count` (and
     ethtool stats) on first run and assert byte-for-byte equality on
     subsequent runs. Drift in either direction (HW behaviour shift,
     PCD config change) fails the test loudly.

  2. ICMP-egress observation. Items 1b / 1c / 2b / 2c assert "the
     kernel emitted an ICMP error" by tcpdumping the DUT's egress
     interface and grep'ing the summary line. tcpdump is already in
     the exec_cmd allowlist; -c 1 + the agent's per-call timeout
     bound the wait without needing a new endpoint.

  3. Multi-listener + multi-port-bridge fixtures. Items 3 and 4 need
     N parallel VLAN subifs (item 3) and a Linux bridge with N
     VLAN-pseudo-port members (item 4). Built on the same
     finalizer-stack discipline as test_vlan_data_plane.py — partial
     setup tears down whatever did come up.

Per the Phase 2 plan: no new agent endpoints, no new exec_cmd allowlist
entries, no /pkt/inject, no pcap storage. Everything here runs on
existing primitives.
"""

from __future__ import annotations

import asyncio
import json
import os
import pathlib
import re
import warnings
from typing import Any, Awaitable, Callable

import aiohttp
import pytest_asyncio


# ---- VLAN ID conventions -------------------------------------------------
#
# Kept out of collision with Phase 1 conventions:
#   test_vlan_data_plane.py        100  (from ASK_VLAN_ID)
#   test_vlan_failslab.py          251  (from ASK_VLAN_FAILSLAB_VID)
#   test_mcast_concurrent.py       241+ (from ASK_MCAST_CONCURRENT_VID)
#   test_mcast_pagination.py       201..208
#
# Phase 2 uses 241/242/243 (mcast replication — overlaps the concurrent
# test, but the two never run at the same time and both teardown in
# their finalizers) and 231/232 (bridge) — both exclusive to this module.
VLAN_IDS_MCAST: tuple[int, int, int]  = (241, 242, 243)
VLAN_IDS_BRIDGE: tuple[int, int]      = (231, 232)

TARGET_LAN_IF = os.environ.get("ASK_TARGET_LAN_IF", "eth4")
LAN_NIC       = os.environ.get("ASK_LAN_NIC",       "enp4s0")


# ---- 1. counter signatures ------------------------------------------------

# /proc/fqid_stats/<class>/<iface>/<file> contents:
#   ::fqid 1700(5888)
#   fqctrl   1
#   ...
#   byte count    0
#   frame count   42
# Multiple ::fqid stanzas per file. Only "frame count" is the per-FQ
# numeric signal worth comparing; "byte count" varies with payload size
# and would make goldens fragile.
_FQID_LINE = re.compile(r"^::fqid\s+(\S+)")
_FRAME_COUNT_LINE = re.compile(r"^frame count\s+(-?\d+)\s*$")


def _parse_fq_file(content: str) -> dict[str, int]:
    """Extract {fqid: frame_count} from one /proc/fqid_stats file's text.

    Tolerant: malformed stanzas are skipped, not raised on. Returns an
    empty dict for content with no ::fqid markers (some files are
    empty under no-traffic conditions)."""
    out: dict[str, int] = {}
    current: str | None = None
    for line in content.splitlines():
        m = _FQID_LINE.match(line)
        if m:
            current = m.group(1)
            continue
        if current is not None:
            mm = _FRAME_COUNT_LINE.match(line)
            if mm:
                try:
                    out[current] = int(mm.group(1))
                except ValueError:
                    pass
                current = None
    return out


def flatten_counters(snap: dict[str, Any]) -> dict[str, int]:
    """Flatten Agent.counters() output into a single {key: int} dict.

    Keys are slash-joined paths so a regex selector can pick subsets
    without walking nested dicts. Three classes of keys are emitted:

      fqid_stats/<class>/<iface>/<file>/<fqid>/frame_count
      ethtool/<iface>/<stat_name>
      (ask_proc/ — text-only on this kernel, no numeric leaves; skipped)
    """
    out: dict[str, int] = {}

    for relpath, content in (snap.get("fqid_stats") or {}).items():
        if not isinstance(content, str):
            continue
        for fqid, frames in _parse_fq_file(content).items():
            out[f"fqid_stats/{relpath}/{fqid}/frame_count"] = frames

    for iface, stats in (snap.get("ethtool") or {}).items():
        if not isinstance(stats, dict):
            continue
        for k, v in stats.items():
            if isinstance(v, int):
                out[f"ethtool/{iface}/{k}"] = v

    return out


def counter_signature(
    before: dict[str, Any],
    after: dict[str, Any],
    *,
    key_regex: str | None = None,
) -> dict[str, int]:
    """Return {key: delta} for keys whose value changed between snapshots.

    `key_regex` filters to a subset (e.g. r"^fqid_stats/.*frame_count$"
    to keep only per-FQ frame counters and drop ethtool noise from
    BMC/link-state ticks). Keys present only in one snapshot are
    treated as having a baseline of 0.
    """
    flat_b = flatten_counters(before)
    flat_a = flatten_counters(after)
    pat = re.compile(key_regex) if key_regex else None
    sig: dict[str, int] = {}
    keys = set(flat_a) | set(flat_b)
    for k in keys:
        if pat and not pat.search(k):
            continue
        delta = flat_a.get(k, 0) - flat_b.get(k, 0)
        if delta != 0:
            sig[k] = delta
    return sig


def assert_counter_signature(
    observed: dict[str, int],
    *,
    golden_path: pathlib.Path,
    label: str,
) -> None:
    """Compare observed signature to golden[label]; assert byte-equality.

    Set ASK_REGEN_GOLDEN=1 to record observed as the new golden
    and pass — used on first run and after an intentional behaviour
    change. Never pass this flag in CI: a regression would be silently
    overwritten.
    """
    regen = os.environ.get("ASK_REGEN_GOLDEN") == "1"

    golden: dict[str, dict[str, int]] = {}
    if golden_path.exists():
        try:
            golden = json.loads(golden_path.read_text())
        except json.JSONDecodeError as e:
            raise AssertionError(
                f"golden file {golden_path} is malformed: {e}"
            )

    if regen:
        golden[label] = observed
        golden_path.parent.mkdir(parents=True, exist_ok=True)
        golden_path.write_text(
            json.dumps(golden, indent=2, sort_keys=True) + "\n"
        )
        return

    expected = golden.get(label)
    if expected is None:
        raise AssertionError(
            f"no golden entry for label={label!r} in {golden_path}; "
            f"first run? regenerate with ASK_REGEN_GOLDEN=1"
        )
    assert observed == expected, (
        f"counter signature for label={label!r} drifted from golden "
        f"({golden_path.name}):\n"
        f"  expected: {expected}\n"
        f"  observed: {observed}\n"
        f"  diff (observed - expected):\n"
        + "\n".join(
            f"    {k}: {observed.get(k, 0) - expected.get(k, 0):+d}"
            for k in sorted(set(observed) | set(expected))
            if observed.get(k, 0) != expected.get(k, 0)
        )
    )


# ---- 2. ICMP-egress observation ------------------------------------------

# Substring needles for tcpdump summary output. Used as belt-and-braces
# verification that the BPF-matched frame really is the ICMP we expected
# (a stray same-type-different-code frame would otherwise satisfy the
# BPF and confuse the test).
ICMP4_FRAG_NEEDED       = "unreachable - need to frag"   # type=3 code=4
ICMP4_TIME_EXCEEDED     = "time exceeded"                # type=11
ICMP6_PACKET_TOO_BIG    = "packet too big"               # type=2
ICMP6_TIME_EXCEEDED     = "time exceeded"                # type=3
ICMP6_HBH_PARAM_PROBLEM = "parameter problem"            # type=4


def _build_icmp_bpf(ip_ver: int, icmp_type: int, icmp_code: int | None) -> str:
    """Construct a tight BPF filter for the specific ICMP type/code so
    a stray ICMP frame (echo request, RA, unrelated unreachable) can't
    win the tcpdump -c 1 race.

    IPv4 uses raw byte offsets icmp[0]/icmp[1] for portability across
    tcpdump versions (the 'icmptype'/'icmpcode' name macros were added
    later and aren't universal). IPv6 uses ip6[40] which is reliable
    when the response itself has no extension headers — true for
    DUT-emitted ICMPv6 errors but not for arbitrary IPv6 traffic.
    """
    if ip_ver == 6:
        bpf = f"icmp6 and ip6[40] = {icmp_type}"
        if icmp_code is not None:
            bpf += f" and ip6[41] = {icmp_code}"
        return bpf
    bpf = f"icmp and icmp[0] = {icmp_type}"
    if icmp_code is not None:
        bpf += f" and icmp[1] = {icmp_code}"
    return bpf


async def expect_icmp_egress(
    target,                  # ask_orch.client.Agent
    session: aiohttp.ClientSession,
    *,
    iface: str,
    icmp_type: int,
    icmp_code: int | None = None,
    expect_substr: str | None = None,
    ip_ver: int = 4,
    timeout_s: float = 2.0,
) -> str:
    """Run `tcpdump -c 1 -nn -i <iface> '<tight icmp filter>'` on the DUT.

    BPF filter is constructed to match the specific (ip_ver, icmp_type,
    icmp_code) tuple — no stray ICMP frame can satisfy `-c 1` ahead of
    the one we actually want. `expect_substr` is an optional secondary
    check on tcpdump's summary line (e.g. "need to frag" for IPv4
    type=3 code=4) that catches mis-tcpdumps where the BPF passes but
    the parsed output reports something unexpected.

    NOTE: signature deviates from the plan's locked
    expect_icmp_egress(..., icmp_type, icmp_code, ...) form by adding
    expect_substr alongside (not replacing) the type/code BPF — both
    layers run for defense-in-depth. See the Phase 2 plan addendum.

    Returns tcpdump's summary line on success. Raises AssertionError
    if no matching frame is captured within `timeout_s`. The agent-side
    subprocess timeout bounds the wait without needing a new endpoint.
    """
    bpf = _build_icmp_bpf(ip_ver, icmp_type, icmp_code)
    timeout_ms = int(timeout_s * 1000) + 500
    try:
        r = await target.exec_cmd(
            session,
            ["tcpdump", "-c", "1", "-nn", "-i", iface, bpf],
            timeout_ms=timeout_ms,
        )
    except aiohttp.ClientResponseError as e:
        if e.status == 504:
            raise AssertionError(
                f"no ICMP{'v6' if ip_ver == 6 else ''} type={icmp_type}"
                + (f" code={icmp_code}" if icmp_code is not None else "")
                + f" frame captured on {iface} within {timeout_s}s"
            )
        raise

    rc = r.get("rc", -1)
    stdout = r.get("stdout", "") or ""
    stderr = r.get("stderr", "") or ""

    if rc != 0:
        raise AssertionError(
            f"tcpdump on {iface} exited rc={rc}; stderr={stderr.strip()!r}"
        )

    if not stdout.strip():
        raise AssertionError(
            f"tcpdump on {iface} matched filter but produced no output: "
            f"stderr={stderr!r}"
        )

    # Pick the first non-header line as the captured frame's summary.
    summary_lines = [
        ln for ln in stdout.splitlines()
        if ln.strip() and not ln.startswith("listening on")
    ]
    if not summary_lines:
        raise AssertionError(
            f"tcpdump output had no summary line; stdout={stdout!r}"
        )
    summary = summary_lines[0]

    if expect_substr is not None and expect_substr not in summary:
        raise AssertionError(
            f"tcpdump on {iface} captured an ICMP frame matching the "
            f"BPF (type={icmp_type}, code={icmp_code}) but the summary "
            f"didn't contain {expect_substr!r}: {summary!r}"
        )
    return summary


# ---- 3. fixtures ----------------------------------------------------------

@pytest_asyncio.fixture
async def dut_egress_mtu(target_agent, aiohttp_session):
    """Yields a callable `await set(iface, mtu)`. Restores all touched
    interfaces' MTUs at teardown via addfinalizer-equivalent cleanup, so
    a SIGKILL between setup and the test body doesn't leave the DUT with
    a half-applied MTU change.

    Reads the original MTU at first call per interface so multiple
    set()s on the same iface within one test still restore correctly.
    """
    saved: dict[str, int] = {}

    async def _read_mtu(iface: str) -> int:
        r = await target_agent.exec_cmd(
            aiohttp_session, ["ip", "-o", "link", "show", iface],
        )
        # `ip -o link show eth4` line contains "mtu 1500".
        m = re.search(r"\bmtu\s+(\d+)", r.get("stdout", ""))
        if not m:
            raise RuntimeError(
                f"couldn't read MTU of {iface}: rc={r.get('rc')}, "
                f"out={r.get('stdout', '')[:200]!r}"
            )
        return int(m.group(1))

    async def set_mtu(iface: str, mtu: int) -> None:
        if iface not in saved:
            saved[iface] = await _read_mtu(iface)
        r = await target_agent.exec_cmd(
            aiohttp_session, ["ip", "link", "set", iface, "mtu", str(mtu)],
        )
        assert r.get("rc") == 0, (
            f"ip link set {iface} mtu {mtu} failed: rc={r.get('rc')}, "
            f"stderr={r.get('stderr', '')!r}"
        )

    try:
        yield set_mtu
    finally:
        for iface, original in saved.items():
            try:
                await target_agent.exec_cmd(
                    aiohttp_session,
                    ["ip", "link", "set", iface, "mtu", str(original)],
                )
            except Exception as e:
                warnings.warn(f"failed to restore MTU on {iface}: {e}")


def _lan_run(lan, cmd: str, timeout: float = 10.0):
    """Synchronous LAN console call wrapped for asyncio. Console.run is
    blocking on serial I/O — bounce through to_thread so we don't stall
    the event loop."""
    return asyncio.to_thread(lan.run, cmd, timeout)


# DUT and LAN IPv6 addresses for the Phase 2 IPv6 tests. Two ULA /64s
# (fc00::/7 documentation/private space) — keeps routing self-contained
# without needing real upstream IPv6 connectivity. ASK_WAN_IPV6 should
# point into the WAN /64; a destination there has no listener, but the
# DUT's IPv6 input path (TTL/HBH/PTB checks, classifier) runs before
# the next-hop ND attempt, which is what these tests exercise.
DUT_IPV6_LAN  = "fc00:dead::1"
DUT_IPV6_WAN  = "fc00:beef::1"
LAN_IPV6      = "fc00:dead::2"
TARGET_WAN_IF = os.environ.get("ASK_TARGET_WAN_IF", "eth3")


@pytest_asyncio.fixture
async def ipv6_topology(aiohttp_session, target_agent, lan):
    """Bring up a minimal IPv6 LAN→DUT→WAN topology for Phase 2 item 2
    tests. Tears down all assigned addresses + forwarding flags + routes
    on exit, in reverse order of setup, so partial-setup failures clean
    only what came up.

    DUT eth4  ULA  fc00:dead::1/64  (LAN-facing)
    DUT eth3  ULA  fc00:beef::1/64  (WAN-facing)
    LAN NIC   ULA  fc00:dead::2/64
    LAN default v6 route via fc00:dead::1

    ASK_WAN_IPV6 (default fc00:beef::99) lives in the WAN /64 — the
    DUT routes to it but no listener exists; ND for the next-hop fails.
    That's expected: 2b/2c assert ICMPv6 errors emitted *before* the
    next-hop attempt, and 2a/2d/2e tripwire on counter deltas
    irrespective of forward outcome.
    """
    cleanups: list[Callable[[], Awaitable[None]]] = []

    async def _exec(*argv: str):
        return await target_agent.exec_cmd(aiohttp_session, list(argv))

    async def _lan(cmd: str, timeout_s: float = 5.0):
        return await asyncio.to_thread(lan.run, cmd, timeout_s)

    try:
        # ---- DUT sysctl: enable IPv6 forwarding ----
        # Save current values so teardown restores them.
        r = await _exec("sysctl", "-n", "net.ipv6.conf.all.forwarding")
        prev_all_fwd = r.get("stdout", "0").strip() or "0"

        async def _restore_all_fwd(v=prev_all_fwd):
            await _exec("sysctl", "-w", f"net.ipv6.conf.all.forwarding={v}")
        cleanups.append(_restore_all_fwd)

        r = await _exec("sysctl", "-w", "net.ipv6.conf.all.forwarding=1")
        assert r["rc"] == 0, f"enable v6 forwarding: {r}"

        # ---- DUT addresses ----
        # Idempotent: del before add so a re-run after a botched teardown
        # doesn't trip "already exists".
        await _exec("ip", "-6", "addr", "del",
                    f"{DUT_IPV6_LAN}/64", "dev", TARGET_LAN_IF)
        r = await _exec("ip", "-6", "addr", "add",
                        f"{DUT_IPV6_LAN}/64", "dev", TARGET_LAN_IF)
        assert r["rc"] == 0, f"DUT eth4 v6 addr: {r}"

        async def _del_dut_lan():
            await _exec("ip", "-6", "addr", "del",
                        f"{DUT_IPV6_LAN}/64", "dev", TARGET_LAN_IF)
        cleanups.append(_del_dut_lan)

        await _exec("ip", "-6", "addr", "del",
                    f"{DUT_IPV6_WAN}/64", "dev", TARGET_WAN_IF)
        r = await _exec("ip", "-6", "addr", "add",
                        f"{DUT_IPV6_WAN}/64", "dev", TARGET_WAN_IF)
        assert r["rc"] == 0, f"DUT eth3 v6 addr: {r}"

        async def _del_dut_wan():
            await _exec("ip", "-6", "addr", "del",
                        f"{DUT_IPV6_WAN}/64", "dev", TARGET_WAN_IF)
        cleanups.append(_del_dut_wan)

        # ---- LAN address + default route ----
        await _lan(f"ip -6 addr del {LAN_IPV6}/64 dev {LAN_NIC} 2>/dev/null")
        r = await _lan(f"ip -6 addr add {LAN_IPV6}/64 dev {LAN_NIC}")
        assert r.rc == 0, f"LAN v6 addr: {r.stdout!r}"

        async def _del_lan_addr():
            await _lan(f"ip -6 addr del {LAN_IPV6}/64 dev {LAN_NIC} 2>/dev/null")
        cleanups.append(_del_lan_addr)

        await _lan(f"ip -6 route del default via {DUT_IPV6_LAN} 2>/dev/null")
        r = await _lan(
            f"ip -6 route add default via {DUT_IPV6_LAN} dev {LAN_NIC}"
        )
        assert r.rc == 0, f"LAN v6 default route: {r.stdout!r}"

        async def _del_lan_route():
            await _lan(f"ip -6 route del default via {DUT_IPV6_LAN} 2>/dev/null")
        cleanups.append(_del_lan_route)

        # Populate the LAN's IPv6 neighbor cache for the DUT. Without
        # this, scapy's first send falls back to broadcast L2 MAC
        # ("MAC address to reach destination not found") which the
        # DUT may drop at L2 input, and the entire IPv6 test path
        # turns into a vacuous "no signal" pass. ping6 -c 1 forces
        # the LAN kernel to do ND once; subsequent scapy sends in
        # the same test see the cached neighbor.
        await _lan(
            f"ping -6 -c 1 -W 2 {DUT_IPV6_LAN} > /dev/null 2>&1 || true",
            10.0,
        )
        await asyncio.sleep(0.5)
        yield {
            "dut_lan_v6": DUT_IPV6_LAN,
            "dut_wan_v6": DUT_IPV6_WAN,
            "lan_v6":     LAN_IPV6,
        }
    finally:
        for cleanup in reversed(cleanups):
            try:
                await cleanup()
            except Exception as e:
                warnings.warn(f"ipv6_topology cleanup failed: {e}")


@pytest_asyncio.fixture
async def multi_listener_subifs(aiohttp_session, target_agent, lan):
    """N=3 VLAN subifs on DUT eth4 + matching subifs on the LAN VM.

    Yields list of (target_iface, lan_iface, vlan_id) tuples. CMM picks
    up the target-side NEWLINK netlink events and registers each VLAN
    in the FMAN onif table — prerequisite for mcast ADD's
    get_onif_by_name(listener) resolution.

    Cleanup discipline: each successfully-brought-up interface registers
    its own teardown closure into a stack; the finally block walks the
    stack in reverse so a partial setup tears down only what actually
    came up.
    """
    cleanups: list[Callable[[], Awaitable[None]]] = []

    async def _push_target_cleanup(iface: str) -> None:
        async def _cleanup():
            await target_agent.exec_cmd(
                aiohttp_session, ["ip", "link", "del", iface],
            )
        cleanups.append(_cleanup)

    async def _push_lan_cleanup(iface: str) -> None:
        async def _cleanup():
            await _lan_run(lan, f"ip link del {iface} 2>/dev/null", 5.0)
        cleanups.append(_cleanup)

    listeners: list[tuple[str, str, int]] = []
    try:
        for vid in VLAN_IDS_MCAST:
            target_if = f"{TARGET_LAN_IF}.{vid}"
            lan_if    = f"vlan{vid}"

            # Idempotent nuke before setup
            await target_agent.exec_cmd(
                aiohttp_session, ["ip", "link", "del", target_if],
            )
            await _lan_run(lan, f"ip link del {lan_if} 2>/dev/null", 5.0)

            # Target side
            r = await target_agent.exec_cmd(aiohttp_session, [
                "ip", "link", "add", "link", TARGET_LAN_IF,
                "name", target_if, "type", "vlan", "id", str(vid),
            ])
            assert r["rc"] == 0, f"target vlan add {target_if}: {r}"
            await _push_target_cleanup(target_if)

            r = await target_agent.exec_cmd(
                aiohttp_session, ["ip", "link", "set", target_if, "up"],
            )
            assert r["rc"] == 0, f"target vlan up {target_if}: {r}"

            # LAN side
            res = await _lan_run(
                lan,
                f"ip link add link {LAN_NIC} name {lan_if} "
                f"type vlan id {vid} && ip link set {lan_if} up",
                10.0,
            )
            assert res.rc == 0, (
                f"lan vlan add {lan_if} (id {vid}) on {LAN_NIC}: "
                f"rc={res.rc}, out={res.stdout!r}"
            )
            await _push_lan_cleanup(lan_if)

            listeners.append((target_if, lan_if, vid))

        # Let CMM/netlink propagate the NEWLINKs.
        await asyncio.sleep(1.0)
        yield listeners

    finally:
        for cleanup in reversed(cleanups):
            try:
                await cleanup()
            except Exception as e:
                warnings.warn(f"multi_listener_subifs cleanup failed: {e}")


@pytest_asyncio.fixture
async def bridge_with_n_ports(aiohttp_session, target_agent):
    """Linux bridge `br_test_abm` on the DUT with N=2 VLAN-pseudo-port
    members on TARGET_LAN_IF. Yields (bridge_name, [port_iface, ...]).

    Same finalizer-stack discipline as multi_listener_subifs: every
    successful setup step registers its teardown immediately, so a
    partial setup tears down only what came up.

    Single-physical-link constraint applies — see §Item 4 in the plan
    for the stimulus-validity gate that must run before this fixture
    is used to assert anything about BREVENT_PORT_DOWN behaviour.
    """
    bridge = "br_test_abm"
    cleanups: list[Callable[[], Awaitable[None]]] = []

    async def _exec(*argv: str):
        return await target_agent.exec_cmd(aiohttp_session, list(argv))

    ports: list[str] = []
    try:
        # Idempotent nuke
        await _exec("ip", "link", "del", bridge)

        r = await _exec("ip", "link", "add", "name", bridge, "type", "bridge")
        assert r["rc"] == 0, f"bridge add {bridge}: {r}"

        async def _cleanup_bridge():
            await _exec("ip", "link", "del", bridge)
        cleanups.append(_cleanup_bridge)

        r = await _exec("ip", "link", "set", bridge, "up")
        assert r["rc"] == 0, f"bridge up {bridge}: {r}"

        for vid in VLAN_IDS_BRIDGE:
            port = f"{TARGET_LAN_IF}.{vid}"
            await _exec("ip", "link", "del", port)
            r = await _exec(
                "ip", "link", "add", "link", TARGET_LAN_IF,
                "name", port, "type", "vlan", "id", str(vid),
            )
            assert r["rc"] == 0, f"port add {port}: {r}"

            async def _cleanup_port(_port=port):
                await _exec("ip", "link", "del", _port)
            cleanups.append(_cleanup_port)

            r = await _exec("ip", "link", "set", port, "master", bridge)
            assert r["rc"] == 0, f"port enslave {port}: {r}"
            r = await _exec("ip", "link", "set", port, "up")
            assert r["rc"] == 0, f"port up {port}: {r}"
            ports.append(port)

        await asyncio.sleep(0.5)
        yield bridge, ports
    finally:
        for cleanup in reversed(cleanups):
            try:
                await cleanup()
            except Exception as e:
                warnings.warn(f"bridge_with_n_ports cleanup failed: {e}")


# ---- helpers for golden-file paths ----------------------------------------

GOLDEN_DIR = pathlib.Path(__file__).parent / "golden"


def golden_for(label_file: str) -> pathlib.Path:
    """Construct the standard golden path for a Phase 2 test file.

    e.g. golden_for('ipv4_edge_options.json') -> tools/tests/golden/ipv4_edge_options.json
    """
    return GOLDEN_DIR / label_file
