"""Topology + counter helpers shared across data-plane edge tests.

Three concerns colocated here, in order of increasing scope:

  1. RX-path classification + golden-file tripwires. The edge-case
     tests don't know in advance whether HW silently drops, punts to
     the kernel slow path, or fast-paths the edge-case packet — so
     they classify what *did* happen (via the ingress netdev's kernel
     RX counter: FMAN-handled frames never tick it, punted frames tick
     it 1:1), pin the classification in a golden on first run, and
     assert equality on subsequent runs. A behaviour shift (PCD config
     change, ucode change) fails the test loudly.

  2. ICMP-egress observation. The ICMP edge-case tests assert "the
     kernel emitted an ICMP error" by tcpdumping the DUT's egress
     interface and grep'ing the summary line. tcpdump is already in
     the exec_cmd allowlist; -c 1 + the agent's per-call timeout
     bound the wait without needing a new endpoint.

  3. Multi-listener + multi-port-bridge fixtures. These need
     N parallel VLAN subifs (multi-listener) and a Linux bridge with N
     VLAN-pseudo-port members (multi-port-bridge). Built on the same
     finalizer-stack discipline as test_vlan_data_plane.py — partial
     setup tears down whatever did come up.

By design: no new agent endpoints, no new exec_cmd allowlist
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
# Every test that creates VLAN subinterfaces on the LAN segment claims its
# IDs here so they don't collide. pytest runs serially, but teardown races
# and shared-segment capture still make overlap worth tracking. Claims:
#   test_vlan_data_plane.py     100          (ASK_VLAN_ID)
#   test_mcast_pagination.py    201..208     (ASK_MCAST_BASE_VID) + 300 transient
#   test_mcast_failslab.py      231/232      (ASK_MCAST_FAILSLAB_VID)
#   test_mcast_concurrent.py    241+         (ASK_MCAST_CONCURRENT_VID)
#   test_mcast_replication.py   241/242/243  (VLAN_IDS_MCAST)
#   test_vlan_failslab.py       251          (ASK_VLAN_FAILSLAB_VID)
#   bridge helpers              231/232      (VLAN_IDS_BRIDGE)
#
# Overlaps that are safe only because the pairs never run concurrently and
# both sides tear down in finalizers: bridge 231/232 vs mcast_failslab
# 231/232; mcast_replication 241/242/243 vs mcast_concurrent 241+.
VLAN_IDS_MCAST: tuple[int, int, int]  = (241, 242, 243)
VLAN_IDS_BRIDGE: tuple[int, int]      = (231, 232)

# Bench wiring: the DUT's eth3 faces the LAN client VM, eth4 faces the
# WAN/orchestrator segment. Every test that needs a role-scoped DUT port
# imports these two symbols rather than hardcoding a netdev name, so a
# re-cable is a one-line change here (or an env override at run time).
TARGET_LAN_IF = os.environ.get("ASK_TARGET_LAN_IF", "eth3")
LAN_NIC       = os.environ.get("ASK_LAN_NIC",       "enp4s0")


# ---- 1. RX-path classification -------------------------------------------
#
# Earlier revisions built golden signatures from /proc/fqid_stats
# "frame count" deltas. That counter is *instantaneous queue occupancy*,
# not cumulative: queues drain between the before/after snapshots, every
# delta was zero, and all recorded goldens were vacuous {} — the
# tripwire could never fire. The DPAA ethtool stats are no alternative
# tripwire source either: they are kernel-side per-CPU counters, i.e.
# they tick only for frames that reached the kernel, and their names
# ("rx packets [TOTAL]") don't survive the agent's stat-name parser.
#
# The question the tripwire actually needs answered — did the DUT
# handle this packet shape in hardware, or punt it to the kernel? — is
# answered by the ingress netdev's kernel RX packet counter alone:
# FMAN-handled frames (fast-pathed or dropped) never tick it, punted
# frames tick it 1:1. classify_rx_path() reduces the delta to a stable
# label the goldens can pin. Injection counts must be large enough to
# dominate background chatter on the segment (ND, mDNS): use >= 20.

async def kernel_rx_packets(target_agent, session, iface: str) -> int:
    """Cumulative kernel-side RX packet count for `iface` on the DUT."""
    r = await target_agent.exec_cmd(
        session, ["ip", "-s", "-j", "link", "show", iface])
    assert r["rc"] == 0, f"ip -s link show {iface}: {r}"
    return json.loads(r["stdout"])[0]["stats64"]["rx"]["packets"]


def classify_rx_path(kernel_rx_delta: int, injected: int) -> str:
    """Classify where injected frames went: 'kernel' if ~all reached
    the kernel (punt / slow path), 'hardware' if ~none did (FMAN drop
    or fast-path). An in-between delta is asserted on rather than
    returned — pinning a noise-dependent value in a golden would make
    the tripwire flaky in both directions."""
    if kernel_rx_delta >= injected:
        return "kernel"
    if kernel_rx_delta <= injected // 4:
        return "hardware"
    raise AssertionError(
        f"ambiguous RX path: kernel rx +{kernel_rx_delta} for "
        f"{injected} injected frames — neither ~all (punt) nor ~none "
        f"(hardware); rerun on a quieter segment or raise the count"
    )


def assert_counter_signature(
    observed: dict[str, Any],
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
        f"  changed keys:\n"
        + "\n".join(
            f"    {k}: {expected.get(k)!r} -> {observed.get(k)!r}"
            for k in sorted(set(observed) | set(expected))
            if observed.get(k) != expected.get(k)
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

    NOTE: expect_substr runs alongside (not replacing) the
    icmp_type/icmp_code BPF — both layers run for defense-in-depth.

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
        # `ip -o link show <iface>` line contains "mtu 1500".
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


# ---- 3. composable topology primitives ----------------------------------

class TopologyStack:
    """Per-fixture LIFO of teardown callables.

    Pushes happen as each setup step succeeds; the matching `teardown()`
    walks the stack in reverse so a partial setup tears down only what
    actually came up. Failures during teardown emit a warning rather
    than raising — one cleanup failure shouldn't mask the rest.
    """

    def __init__(self) -> None:
        self._cleanups: list[Callable[[], Awaitable[None]]] = []

    def push(self, cleanup: Callable[[], Awaitable[None]]) -> None:
        self._cleanups.append(cleanup)

    async def teardown(self, label: str = "topology") -> None:
        for c in reversed(self._cleanups):
            try:
                await c()
            except Exception as e:
                warnings.warn(f"{label} cleanup failed: {e}")


async def dut_vlan_subif(
    stack: TopologyStack,
    target_agent,
    session: aiohttp.ClientSession,
    *,
    parent: str,
    vid: int,
    name: str | None = None,
    ipv4: str | None = None,
    ipv6: str | None = None,
    master: str | None = None,
) -> str:
    """Create a VLAN subif on the DUT, push its cleanup onto `stack`,
    return the iface name.

    `name` defaults to `f"{parent}.{vid}"`. `ipv4`/`ipv6` are CIDR
    strings (e.g. "192.168.100.1/24"). `master` enslaves to a bridge.
    The subif is brought up at the end. Idempotent: a stale iface
    with the same name is deleted before re-add.
    """
    iface = name or f"{parent}.{vid}"

    async def _exec(*argv: str):
        return await target_agent.exec_cmd(session, list(argv))

    await _exec("ip", "link", "del", iface)  # idempotent

    r = await _exec(
        "ip", "link", "add", "link", parent,
        "name", iface, "type", "vlan", "id", str(vid),
    )
    assert r["rc"] == 0, f"DUT vlan add {iface} (vid {vid}): {r}"

    async def _cleanup():
        await _exec("ip", "link", "del", iface)
    stack.push(_cleanup)

    if ipv4:
        r = await _exec("ip", "addr", "add", ipv4, "dev", iface)
        assert r["rc"] == 0, f"DUT ipv4 {ipv4} on {iface}: {r}"
    if ipv6:
        r = await _exec("ip", "-6", "addr", "add", ipv6, "dev", iface)
        assert r["rc"] == 0, f"DUT ipv6 {ipv6} on {iface}: {r}"
    if master:
        r = await _exec("ip", "link", "set", iface, "master", master)
        assert r["rc"] == 0, f"DUT enslave {iface} → {master}: {r}"

    r = await _exec("ip", "link", "set", iface, "up")
    assert r["rc"] == 0, f"DUT vlan up {iface}: {r}"
    return iface


async def lan_vlan_subif(
    stack: TopologyStack,
    lan,
    *,
    parent: str,
    vid: int,
    name: str | None = None,
    ipv4: str | None = None,
    ipv6: str | None = None,
    routes: list[str] | None = None,
) -> str:
    """LAN-side counterpart to `dut_vlan_subif`. Same shape, driven via
    UART. `routes` is a list of `ip route add ARGS` argument strings;
    each is added with a matching `ip route del FIRST_TOKEN` cleanup
    pushed onto `stack`.
    """
    iface = name or f"vlan{vid}"

    await lan_run(lan, f"ip link del {iface} 2>/dev/null", 5.0)

    r = await lan_run(
        lan,
        f"ip link add link {parent} name {iface} type vlan id {vid}",
        10.0,
    )
    assert r.rc == 0, f"LAN vlan add {iface} (vid {vid}): {r.stdout!r}"

    async def _cleanup():
        await lan_run(lan, f"ip link del {iface} 2>/dev/null", 5.0)
    stack.push(_cleanup)

    if ipv4:
        r = await lan_run(lan, f"ip addr add {ipv4} dev {iface}", 5.0)
        assert r.rc == 0, f"LAN ipv4 {ipv4} on {iface}: {r.stdout!r}"
    if ipv6:
        r = await lan_run(lan, f"ip -6 addr add {ipv6} dev {iface}", 5.0)
        assert r.rc == 0, f"LAN ipv6 {ipv6} on {iface}: {r.stdout!r}"

    r = await lan_run(lan, f"ip link set {iface} up", 5.0)
    assert r.rc == 0, f"LAN vlan up {iface}: {r.stdout!r}"

    for spec in (routes or []):
        await lan_run(lan, f"ip route add {spec}", 5.0)
        async def _del_route(_first=spec.split()[0]):
            await lan_run(lan, f"ip route del {_first} 2>/dev/null", 5.0)
        stack.push(_del_route)

    return iface


# ---- 4. low-level helpers -----------------------------------------------

async def lan_run(lan, cmd: str, timeout: float = 10.0):
    """Async wrapper around `Console.lan().run(...)`.

    `Console.run` is blocking on serial I/O — bounce through
    `asyncio.to_thread` so concurrent async work isn't stalled while
    the UART round-trip is in flight. Use this from any async test
    body or fixture; sync-only helpers can call `lan.run` directly.
    """
    return await asyncio.to_thread(lan.run, cmd, timeout)


async def lan_run_python(
    lan,
    script: str,
    *,
    timeout: float = 30.0,
    label: str = "script",
):
    """Stage a Python script on the LAN VM via base64-over-UART, run it,
    return the RunResult.

    The script is written to a unique /tmp path so concurrent invocations
    (or reruns within the same minute) don't collide. `label` is folded
    into the path for debuggability — e.g. label="ipv4_options" produces
    something like "/tmp/ask_lan_ipv4_options_<pid>_<usec>.py".

    Single staging pattern across all LAN-injection tests so callers
    don't reimplement the base64 boilerplate.
    """
    import base64
    import time

    path = f"/tmp/ask_lan_{label}_{os.getpid()}_{int(time.monotonic() * 1e6)}.py"
    b64 = base64.b64encode(script.encode()).decode()

    stage = lan.run(
        f"echo {b64} | base64 -d > {path} && echo STAGED",
        timeout=10,
    )
    if stage.rc != 0 or "STAGED" not in stage.stdout:
        raise AssertionError(
            f"failed to stage Python script on LAN at {path}: "
            f"rc={stage.rc}, stdout={stage.stdout!r}"
        )
    return await lan_run(lan, f"python3 {path}", timeout)


# DUT and LAN IPv6 addresses for the IPv6 tests. Two ULA /64s
# (fc00::/7 documentation/private space) — keeps routing self-contained
# without needing real upstream IPv6 connectivity. ASK_WAN_IPV6 should
# point into the WAN /64; a destination there has no listener, but the
# DUT's IPv6 input path (TTL/HBH/PTB checks, classifier) runs before
# the next-hop ND attempt, which is what these tests exercise.
DUT_IPV6_LAN  = "fc00:dead::1"
DUT_IPV6_WAN  = "fc00:beef::1"
LAN_IPV6      = "fc00:dead::2"
TARGET_WAN_IF = os.environ.get("ASK_TARGET_WAN_IF", "eth4")


@pytest_asyncio.fixture
async def ipv6_topology(aiohttp_session, target_agent, lan):
    """Bring up a minimal IPv6 LAN→DUT→WAN topology for the IPv6
    tests. Tears down all assigned addresses + forwarding flags + routes
    on exit, in reverse order of setup, so partial-setup failures clean
    only what came up.

    DUT eth3  ULA  fc00:dead::1/64  (LAN-facing, TARGET_LAN_IF)
    DUT eth4  ULA  fc00:beef::1/64  (WAN-facing, TARGET_WAN_IF)
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
        return await lan_run(lan, cmd, timeout_s)

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
                        f"{DUT_IPV6_LAN}/64", "dev", TARGET_LAN_IF, "nodad")
        assert r["rc"] == 0, f"DUT {TARGET_LAN_IF} v6 addr: {r}"

        async def _del_dut_lan():
            await _exec("ip", "-6", "addr", "del",
                        f"{DUT_IPV6_LAN}/64", "dev", TARGET_LAN_IF)
        cleanups.append(_del_dut_lan)

        await _exec("ip", "-6", "addr", "del",
                    f"{DUT_IPV6_WAN}/64", "dev", TARGET_WAN_IF)
        r = await _exec("ip", "-6", "addr", "add",
                        f"{DUT_IPV6_WAN}/64", "dev", TARGET_WAN_IF, "nodad")
        assert r["rc"] == 0, f"DUT {TARGET_WAN_IF} v6 addr: {r}"

        async def _del_dut_wan():
            await _exec("ip", "-6", "addr", "del",
                        f"{DUT_IPV6_WAN}/64", "dev", TARGET_WAN_IF)
        cleanups.append(_del_dut_wan)

        # ---- LAN address + default route ----
        await _lan(f"ip -6 addr del {LAN_IPV6}/64 dev {LAN_NIC} 2>/dev/null")
        # nodad: static ULA on a point-to-point test segment — DAD would
        # leave the address tentative ~1.5 s and the first test flow of
        # the session silently fails to come up.
        r = await _lan(f"ip -6 addr add {LAN_IPV6}/64 dev {LAN_NIC} nodad")
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
    """N=3 VLAN subifs on the DUT's LAN-facing port (TARGET_LAN_IF,
    eth3 by default) + matching subifs on the LAN VM.

    Yields list of (target_iface, lan_iface, vlan_id) tuples. CMM picks
    up the target-side NEWLINK netlink events and registers each VLAN
    in the FMAN onif table — prerequisite for mcast ADD's
    get_onif_by_name(listener) resolution.
    """
    stack = TopologyStack()
    listeners: list[tuple[str, str, int]] = []
    try:
        for vid in VLAN_IDS_MCAST:
            t = await dut_vlan_subif(
                stack, target_agent, aiohttp_session,
                parent=TARGET_LAN_IF, vid=vid,
            )
            l = await lan_vlan_subif(
                stack, lan, parent=LAN_NIC, vid=vid,
            )
            listeners.append((t, l, vid))

        # Let CMM/netlink propagate the NEWLINKs.
        await asyncio.sleep(1.0)
        yield listeners
    finally:
        await stack.teardown("multi_listener_subifs")


@pytest_asyncio.fixture
async def bridge_with_n_ports(aiohttp_session, target_agent):
    """Linux bridge `br_test_abm` on the DUT with N=2 VLAN-pseudo-port
    members on TARGET_LAN_IF. Yields (bridge_name, [port_iface, ...]).

    Single-physical-link constraint applies — a stimulus-validity gate
    must run before this fixture is used to assert anything about
    BREVENT_PORT_DOWN behaviour.
    """
    bridge = "br_test_abm"
    stack = TopologyStack()

    async def _exec(*argv: str):
        return await target_agent.exec_cmd(aiohttp_session, list(argv))

    ports: list[str] = []
    try:
        await _exec("ip", "link", "del", bridge)  # idempotent
        r = await _exec("ip", "link", "add", "name", bridge, "type", "bridge")
        assert r["rc"] == 0, f"bridge add {bridge}: {r}"

        async def _cleanup_bridge():
            await _exec("ip", "link", "del", bridge)
        stack.push(_cleanup_bridge)

        r = await _exec("ip", "link", "set", bridge, "up")
        assert r["rc"] == 0, f"bridge up {bridge}: {r}"

        for vid in VLAN_IDS_BRIDGE:
            port = await dut_vlan_subif(
                stack, target_agent, aiohttp_session,
                parent=TARGET_LAN_IF, vid=vid, master=bridge,
            )
            ports.append(port)

        await asyncio.sleep(0.5)
        yield bridge, ports
    finally:
        await stack.teardown("bridge_with_n_ports")


# ---- helpers for golden-file paths ----------------------------------------

GOLDEN_DIR = pathlib.Path(__file__).parent / "golden"


def golden_for(label_file: str) -> pathlib.Path:
    """Construct the standard golden path for a test file.

    e.g. golden_for('ipv4_edge_options.json') -> tools/tests/golden/ipv4_edge_options.json
    """
    return GOLDEN_DIR / label_file
