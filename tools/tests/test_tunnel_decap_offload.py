"""Tunnel RX-decap offload — real-path tests for 6o4 (sit) and 4o6 (ipip6).

Design: kernel tunnel netdevs on both ends, cmm auto-registers them on
NEWLINK, real conntrack forms from real traffic, and cmm programs the
FMAN entries two-phase (originator at CONFIRMED, both directions once
the flow is ASSURED — allow a few seconds of programming latency).

Oracle: the DUT's kernel tunnel-netdev RX counter. Decapped-in-hardware
frames never touch the kernel tunnel, so once the flow is programmed
the counter goes flat while echoes keep flowing end-to-end. The first
few packets of any flow legitimately take the kernel path.

The old synthetic-FCI variant of this test installed an outer-keyed
proto-41 conntrack, which cdx rightly rejects — the design keys decap
on the *inner* tuple (PCD dists parse to the innermost L3 header).
See ISSUES.md A9 for the full evidence chain. TX-encap offload is
blocked inside FMAN ucode 210.10.1 (INSERT_L3_HDR punts), so these
tests assert nothing about the encap direction.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import threading

import pytest_asyncio

from _topology import lan_run, ipv6_topology  # noqa: F401  (fixture re-export)

DUT_WAN_IPV4 = os.environ.get("ASK_TARGET_IP", "10.0.0.62")
ORCH_IPV4    = os.environ.get("ASK_WAN_IP", "10.0.0.141")
LAN_NIC      = os.environ.get("ASK_LAN_NIC", "enp4s0")
# Orchestrator-side NIC that shares the DUT's WAN L2 segment; carries the
# fc00:beef:: outer for the 4o6 test.
WAN_V6_NIC   = os.environ.get("ASK_WAN_V6_NIC", "br0")

LAN_V6      = "fc00:dead::2"
DUT_TUN_V6  = "fc00:cafe::2"
ORCH_TUN_V6 = "fc00:cafe::1"

ECHO_PORT_6O4 = 5411
ECHO_PORT_4O6 = 5412

# Programming latency budget (conntrack ASSURED + cmm push) before the
# measurement window opens.
PROGRAM_S = 5.0
WINDOW_S  = 6.0


def _sh(cmd: str) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


async def _tun_rx(target_agent, session, ifname: str) -> int:
    r = await target_agent.exec_cmd(
        session, ["ip", "-s", "-j", "link", "show", ifname])
    return json.loads(r["stdout"])[0]["stats64"]["rx"]["packets"]


async def _await_path(dst: str, port: int, deadline_s: float = 12.0) -> int:
    """Poll the echo path until it comes up, absorbing DAD-tentative
    latency on the LAN address and cmm's tunnel registration. Returns
    the echo count of the first good burst (>=8), else the last count."""
    import time as _t
    end = _t.monotonic() + deadline_s
    got = 0
    while _t.monotonic() < end:
        got = await asyncio.to_thread(_udp_echo_burst, dst, port, 10, 0.05)
        if got >= 8:
            return got
        await asyncio.sleep(1.0)
    return got


async def _start_lan_udp_echo(lan, port: int, family: str) -> None:
    """Backgrounded UDP echo server on the LAN VM (:: binds dual-stack)."""
    src = (
        "import socket\\n"
        "s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)\\n"
        f's.bind((\"::\", {port}))\\n'
        "while True:\\n"
        "    d, a = s.recvfrom(2048)\\n"
        "    s.sendto(d, a)\\n"
    )
    await lan_run(
        lan,
        f"pkill -f 'udp_echo_{port}' 2>/dev/null; "
        f"printf '{src}' > /tmp/udp_echo_{port}.py; "
        f"nohup python3 /tmp/udp_echo_{port}.py >/dev/null 2>&1 & echo ok",
    )


def _udp_echo_burst(dst: str, port: int, n: int, gap_s: float) -> int:
    """Paced UDP echo exchange from the orchestrator; returns echoes."""
    fam = socket.AF_INET6 if ":" in dst else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_DGRAM)
    s.settimeout(0.5)
    got = 0
    for _ in range(n):
        try:
            s.sendto(b"d" * 64, (dst, port))
            s.recv(2048)
            got += 1
        except OSError:
            pass
        if gap_s:
            import time
            time.sleep(gap_s)
    s.close()
    return got


# ---------------------------------------------------------------------------
# 6o4: IPv6-in-IPv4 (sit). Outer v4 lab addresses, inner cafe/dead ULAs.
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def sit_decap_tunnel(aiohttp_session, target_agent, lan, ipv6_topology):
    tun = "sit_dcap"
    _sh(f"sudo ip link del {tun} 2>/dev/null")
    await target_agent.exec_cmd(aiohttp_session, ["ip", "link", "del", tun])

    _sh("sudo modprobe sit")
    for cmd in (
        f"sudo ip tunnel add {tun} mode sit local {ORCH_IPV4} remote {DUT_WAN_IPV4} ttl 64",
        f"sudo ip link set {tun} mtu 1480 up",
        f"sudo ip -6 addr add {ORCH_TUN_V6}/64 dev {tun}",
        f"sudo ip -6 route replace fc00:dead::/64 dev {tun}",
    ):
        r = _sh(cmd)
        assert r.returncode == 0 or "exists" in r.stderr, f"{cmd}: {r.stderr}"

    for argv in (
        ["modprobe", "sit"],
        ["ip", "tunnel", "add", tun, "mode", "sit",
         "local", DUT_WAN_IPV4, "remote", ORCH_IPV4, "ttl", "64"],
        ["ip", "link", "set", tun, "mtu", "1480", "up"],
        ["ip", "-6", "addr", "add", f"{DUT_TUN_V6}/64", "dev", tun],
    ):
        await target_agent.exec_cmd(aiohttp_session, argv)

    await _start_lan_udp_echo(lan, ECHO_PORT_6O4, "v6")
    await asyncio.sleep(2.0)  # cmm registers the tunnel
    try:
        yield tun
    finally:
        await target_agent.exec_cmd(aiohttp_session, ["ip", "link", "del", tun])
        _sh(f"sudo ip -6 route del fc00:dead::/64 dev {tun} 2>/dev/null")
        _sh(f"sudo ip link del {tun} 2>/dev/null")


async def test_tunnel_6o4_decap_offloaded(
    aiohttp_session, target_agent, lan, splat_window, sit_decap_tunnel,
):
    tun = sit_decap_tunnel

    # Warm-up: wait for the path (DAD-tentative LAN addr + cmm tunnel
    # registration), then a bidirectional flow so conntrack reaches
    # ASSURED and cmm programs both directions.
    warm = await _await_path(LAN_V6, ECHO_PORT_6O4)
    assert warm >= 8, f"6o4 path never came up: {warm}/10 echoes"
    await asyncio.to_thread(_udp_echo_burst, LAN_V6, ECHO_PORT_6O4, 40, 0.05)
    await asyncio.sleep(PROGRAM_S)

    rx0 = await _tun_rx(target_agent, aiohttp_session, tun)
    got = await asyncio.to_thread(
        _udp_echo_burst, LAN_V6, ECHO_PORT_6O4, int(WINDOW_S / 0.02), 0.02)
    rx1 = await _tun_rx(target_agent, aiohttp_session, tun)

    kernel_rx = rx1 - rx0
    assert got >= 100, f"echo flow collapsed during measurement: {got}"
    assert kernel_rx <= got * 0.1, (
        f"6o4 decap not offloaded: kernel sit rx +{kernel_rx} for {got} "
        f"delivered echoes (expected ~0 once cmm programs the flow). "
        f"See ISSUES.md A9."
    )


# ---------------------------------------------------------------------------
# 4o6: IPv4-in-IPv6 (ipip6). Outer fc00:beef:: ULAs, inner 10.77.0.0/24;
# the LAN VM initiates so the decap direction is the conntrack reply.
# Exercises the ip6_tunnel.c underlying_iif stamp (patch 030).
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def tnl4o6(aiohttp_session, target_agent, lan, ipv6_topology):
    tun = "tnl4o6t"
    _sh(f"sudo ip link del {tun} 2>/dev/null")
    await target_agent.exec_cmd(aiohttp_session, ["ip", "link", "del", tun])

    _sh("sudo modprobe ip6_tunnel")
    _sh(f"sudo ip -6 addr add fc00:beef::2/64 dev {WAN_V6_NIC} nodad 2>/dev/null")
    for cmd in (
        f"sudo ip -6 tunnel add {tun} mode ipip6 local fc00:beef::2 remote fc00:beef::1 ttl 64",
        f"sudo ip link set {tun} up mtu 1440",
        f"sudo ip addr add 10.77.0.1/24 dev {tun}",
        f"sudo ip route replace 192.168.1.0/24 dev {tun}",
    ):
        r = _sh(cmd)
        assert r.returncode == 0 or "exists" in r.stderr, f"{cmd}: {r.stderr}"

    for argv in (
        ["modprobe", "ip6_tunnel"],
        ["ip", "-6", "tunnel", "add", tun, "mode", "ipip6",
         "local", "fc00:beef::1", "remote", "fc00:beef::2", "ttl", "64"],
        ["ip", "link", "set", tun, "up", "mtu", "1440"],
        ["ip", "addr", "add", "10.77.0.2/24", "dev", tun],
    ):
        await target_agent.exec_cmd(aiohttp_session, argv)

    await asyncio.sleep(2.0)  # cmm registers the tunnel
    try:
        yield tun
    finally:
        await target_agent.exec_cmd(aiohttp_session, ["ip", "link", "del", tun])
        _sh(f"sudo ip route del 192.168.1.0/24 dev {tun} 2>/dev/null")
        _sh(f"sudo ip link del {tun} 2>/dev/null")


async def test_tunnel_4o6_decap_offloaded(
    aiohttp_session, target_agent, lan, splat_window, tnl4o6,
):
    tun = tnl4o6

    # Orchestrator-side v4 echo server on the tunnel address.
    stop = threading.Event()

    def serve():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("10.77.0.1", ECHO_PORT_4O6))
        s.settimeout(0.5)
        while not stop.is_set():
            try:
                d, a = s.recvfrom(2048)
                s.sendto(d, a)
            except OSError:
                pass
        s.close()

    th = threading.Thread(target=serve, daemon=True)
    th.start()

    try:
        # LAN VM initiates: backgrounded paced client for warm-up plus the
        # whole measurement span.
        total_s = int(3 + PROGRAM_S + WINDOW_S + 4)
        cli = (
            "import socket, time\\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\\n"
            "s.settimeout(0.5)\\n"
            "n = 0\\n"
            f"end = time.time() + {total_s}\\n"
            "while time.time() < end:\\n"
            "    try:\\n"
            f"        s.sendto(b'g' * 64, ('10.77.0.1', {ECHO_PORT_4O6}))\\n"
            "        s.recv(2048)\\n"
            "        n += 1\\n"
            "    except OSError:\\n"
            "        pass\\n"
            "    time.sleep(0.02)\\n"
            "print('echoed', n)\\n"
        )
        await lan_run(
            lan,
            f"pkill -f 'cli_{ECHO_PORT_4O6}' 2>/dev/null; "
            f"printf \"{cli}\" > /tmp/cli_{ECHO_PORT_4O6}.py; "
            f"nohup python3 /tmp/cli_{ECHO_PORT_4O6}.py "
            f"> /tmp/cli_{ECHO_PORT_4O6}.log 2>&1 & echo ok",
        )

        await asyncio.sleep(3 + PROGRAM_S)
        rx0 = await _tun_rx(target_agent, aiohttp_session, tun)
        await asyncio.sleep(WINDOW_S)
        rx1 = await _tun_rx(target_agent, aiohttp_session, tun)
        await asyncio.sleep(5)

        r = await lan_run(lan, f"tail -1 /tmp/cli_{ECHO_PORT_4O6}.log")
        echoed = int(r.stdout.strip().rsplit(" ", 1)[-1])
        kernel_rx = rx1 - rx0
        window_rate = echoed / total_s   # ~echoes per second
        expected_in_window = window_rate * WINDOW_S

        assert echoed >= 200, f"4o6 path broken: only {echoed} echoes total"
        assert kernel_rx <= expected_in_window * 0.1, (
            f"4o6 decap not offloaded: kernel {tun} rx +{kernel_rx} during a "
            f"{WINDOW_S:.0f}s window with ~{expected_in_window:.0f} frames "
            f"flowing (expected ~0). The ip6_tunnel.c underlying_iif stamp "
            f"(kernel patch 030) may have regressed. See ISSUES.md A9."
        )
    finally:
        stop.set()
        th.join(timeout=2)
