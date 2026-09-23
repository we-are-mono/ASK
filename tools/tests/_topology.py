"""Topology helpers shared across data-plane tests.

Bench port roles, VLAN ID claims, LAN-VM scripting and composable
topology fixtures: VLAN subifs on either side and the IPv6 topology,
built on a finalizer stack so a partial setup tears down whatever did
come up.

By design: no new agent endpoints, no new exec_cmd allowlist
entries, no /pkt/inject, no pcap storage. Everything here runs on
existing primitives.
"""

from __future__ import annotations

import asyncio
import os
import warnings
from typing import Awaitable, Callable

import aiohttp
import pytest_asyncio

from ask_orch.counters import kernel_rx_packets  # noqa: F401 (shared helper)


# ---- VLAN ID conventions -------------------------------------------------
#
# Every test that creates VLAN subinterfaces on the LAN segment claims its
# IDs here so they don't collide. pytest runs serially, but teardown races
# and shared-segment capture still make overlap worth tracking. Claims:
#   test_flowtable_vlan.py      271/272      (ASK_FLOWTABLE_VLAN_ID, +1 inner)
#   test_flowtable_bridge.py    273/274/275  (ASK_FLOWTABLE_BRIDGE_VID, +1, +2)
#   test_flowtable_pppoe.py     276          (ASK_FLOWTABLE_PPPOE_LAN_VID)
#   test_flowtable_service_vlan.py 284      (service VLAN recovery)
#   test_flowtable_service_bridge.py 285/286 (trusted/guest bridge membership,
#                                            port and VLAN forwarding state)
#   test_mcast_e2e.py           244          (VLAN_ID_MROUTE, routed oif)
#   test_mroute_capacity.py     311..319     (nine LAN listeners)
#   test_flowtable_service_multicast_leave.py      321/322 (routed via a snooping bridge)
#   test_flowtable_service_multicast_quarantine.py 323     (listener swap)
#
# 3900 is not a claim on that segment but a standing bench VLAN: the
# orchestrator carries a permanent `wan3900` device on br0 and the PPPoE access
# concentrator binds to it, so test_flowtable_pppoe.py builds eth4.3900 on the
# DUT to meet it and never creates or deletes anything on the orchestrator
# side. Do not reuse 3900 for a test that does.
# test_mroute_capacity.py also receives a tagged WAN replica on that existing
# device using a temporary packet-socket membership, without reconfiguring it,
# and test_flowtable_service_multicast_edges.py does the same.
VLAN_ID_MROUTE: int                   = 244
VLAN_IDS_MROUTE_LIMIT: tuple[int, ...] = tuple(range(311, 320))
VLAN_ID_PPPOE_WAN: int                = 3900

# Bench wiring: the DUT's eth3 faces the LAN client VM, eth4 faces the
# WAN/orchestrator segment. Every test that needs a role-scoped DUT port
# imports these two symbols rather than hardcoding a netdev name, so a
# re-cable is a one-line change here (or an env override at run time).
TARGET_LAN_IF = os.environ.get("ASK_TARGET_LAN_IF", "eth3")
LAN_NIC       = os.environ.get("ASK_LAN_NIC",       "enp4s0")


# ---- composable topology primitives --------------------------------------

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
        # `replace`, not `add`: a leftover route from a crashed prior run
        # (same prefix, stale nexthop) would make `add` fail "File exists"
        # and keep the stale route; replace keeps setup idempotent.
        await lan_run(lan, f"ip route replace {spec}", 5.0)
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
# The offload tests give the WAN host this address for real bidirectional
# traffic, so their endpoint answers rather than only provoking an ICMPv6
# error. VIRT_IPV6 is an unassigned address in the same /64, used as the
# pre-translation destination of a DNAT flow.
WAN_IPV6      = os.environ.get("ASK_WAN_IPV6", "fc00:beef::99")
VIRT_IPV6     = os.environ.get("ASK_VIRT_IPV6", "fc00:beef::dd")
TARGET_WAN_IF = os.environ.get("ASK_TARGET_WAN_IF", "eth4")

# A third ULA /64, claimed by test_flowtable_pppoe.py for the addresses a PPPoE
# session carries inside itself. It is deliberately neither of the two above:
# the session's endpoints are not on the LAN or the WAN segment, they are on
# the point-to-point link between the two ppp devices, and giving them an
# address out of a segment /64 would make a routing mistake look like a
# working path. The concentrator takes ::1 and the DUT ::2, matching the
# INNER_LOCAL/INNER_REMOTE convention the IPv4 side of that session uses.
# ("babe" rather than a spelling like "ppp" because p is not a hex digit and
# the address would not parse.)
#
# Only the session's own /64 is new. Its LAN side reuses DUT_IPV6_LAN and
# LAN_IPV6 above, which it configures itself rather than through
# ipv6_topology -- that fixture also addresses the WAN port, which is where
# the session stands. Sharing those two with test_flowtable_ipv6.py is safe
# only because pytest runs serially and both tear down in finalizers, the same
# basis as the VLAN id overlaps recorded above.
PPPOE_IPV6_LOCAL  = os.environ.get("ASK_PPPOE_INNER_LOCAL6", "fc00:babe::1")
PPPOE_IPV6_REMOTE = os.environ.get("ASK_PPPOE_INNER_REMOTE6", "fc00:babe::2")


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

        # `replace`, not `add`: loki may already carry a v6 default route
        # from the DUT's router advertisements (via a link-local next-hop),
        # so a plain `add` fails with "File exists". replace is idempotent —
        # it adds when absent and overwrites any existing default regardless
        # of its next-hop.
        r = await _lan(
            f"ip -6 route replace default via {DUT_IPV6_LAN} dev {LAN_NIC}"
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
