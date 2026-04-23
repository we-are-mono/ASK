"""VLAN data-plane: verify 802.1Q-tagged traffic actually offloads.

Topology during this test:

    lan (vlan100 = 192.168.100.2/24, tag 100)
        │  VID 100 frames
        ▼
    target eth4.100 (192.168.100.1/24)
        │  stripped, routed, NAT'd out eth3
        ▼
    wan (10.0.0.141) iperf3 server

The test creates the VLAN subinterface on both ends, adds a /32 route
on lan forcing iperf3 traffic to egress via vlan100, drives iperf3,
then:
  * queries CMM to prove the 5-tuple installed as an offloaded flow,
  * asserts line-rate throughput (only FMAN can sustain 9 Gbps here),
  * tears everything down cleanly even on failure.

Overridable via env:
    ASK_LAN_NIC             parent NIC on the lan host (default enp4s0)
    ASK_TARGET_LAN_IF       parent NIC on the target (default eth4)
    ASK_VLAN_ID             VID used for the test (default 100)
    ASK_WAN_IPERF_IP        iperf3 server addr (default 10.0.0.141)
    ASK_IPERF_DURATION      seconds (default 5)
"""

from __future__ import annotations

import asyncio
import os
import re

import pytest
import pytest_asyncio


LAN_NIC           = os.environ.get("ASK_LAN_NIC",       "enp4s0")
TARGET_LAN_IF     = os.environ.get("ASK_TARGET_LAN_IF", "eth4")
VLAN_ID           = int(os.environ.get("ASK_VLAN_ID",   "100"))
WAN_IPERF_IP      = os.environ.get("ASK_WAN_IPERF_IP",  "10.0.0.141")
IPERF_DURATION_S  = int(os.environ.get("ASK_IPERF_DURATION", "5"))

OFFLOAD_MIN_GBPS = 1.0

TARGET_VLAN_IF   = f"{TARGET_LAN_IF}.{VLAN_ID}"
TARGET_VLAN_CIDR = f"192.168.{VLAN_ID}.1/24"
LAN_VLAN_IF      = f"vlan{VLAN_ID}"
LAN_VLAN_CIDR    = f"192.168.{VLAN_ID}.2/24"
LAN_VLAN_ADDR    = f"192.168.{VLAN_ID}.2"
TARGET_VLAN_ADDR = f"192.168.{VLAN_ID}.1"


_IPERF_RX_RE = re.compile(
    r"^\[\s*\d+\]\s+[\d.]+-[\d.]+\s+sec\s+[\d.]+\s[KMGT]?Bytes\s+([\d.]+)\s+([KMG]?)bits/sec",
    re.M,
)
_CT_TOTAL_RE = re.compile(r"Total Connection Entries:\s*(\d+)")


def _flow_count(cmm: dict) -> int:
    m = _CT_TOTAL_RE.search(cmm.get("stdout", ""))
    return int(m.group(1)) if m else 0


def _iperf_receiver_gbps(log: str) -> float | None:
    matches = _IPERF_RX_RE.findall(log)
    if not matches:
        return None
    val, unit = matches[-1]
    scale = {"": 1e-9, "K": 1e-6, "M": 1e-3, "G": 1.0}.get(unit, 0.0)
    return float(val) * scale


# ---- setup / teardown ---------------------------------------------------

async def _target_ip(session, target_agent, argv_tail: list[str]) -> None:
    """Run an `ip` subcommand on the target, tolerating pre-existing state
    during cleanup (exit code 2 from `ip link del` on a missing iface is
    fine to ignore)."""
    r = await target_agent.exec_cmd(session, ["ip"] + argv_tail)
    return r


def _lan_ip(lan_console, argv_tail: str) -> int:
    """Run `ip <args>` on the lan host via UART, return exit code."""
    return lan_console.run(f"ip {argv_tail}", timeout=5.0).rc


@pytest_asyncio.fixture
async def vlan_100_setup(aiohttp_session, target_agent, lan):
    """Create eth4.100 on target and vlan100 on lan; tear both down."""
    # Idempotent: nuke any stale state from a previous aborted run.
    await _target_ip(aiohttp_session, target_agent,
                     ["link", "del", TARGET_VLAN_IF])
    _lan_ip(lan, f"link del {LAN_VLAN_IF} 2>/dev/null")

    # Target side
    r = await target_agent.exec_cmd(aiohttp_session, [
        "ip", "link", "add", "link", TARGET_LAN_IF,
        "name", TARGET_VLAN_IF, "type", "vlan", "id", str(VLAN_ID),
    ])
    assert r["rc"] == 0, f"target vlan link add failed: {r}"
    await target_agent.exec_cmd(aiohttp_session, [
        "ip", "addr", "add", TARGET_VLAN_CIDR, "dev", TARGET_VLAN_IF,
    ])
    await target_agent.exec_cmd(aiohttp_session, [
        "ip", "link", "set", TARGET_VLAN_IF, "up",
    ])

    # Lan side (UART)
    assert _lan_ip(lan,
        f"link add link {LAN_NIC} name {LAN_VLAN_IF} type vlan id {VLAN_ID}"
    ) == 0, "lan vlan link add failed"
    _lan_ip(lan, f"addr add {LAN_VLAN_CIDR} dev {LAN_VLAN_IF}")
    _lan_ip(lan, f"link set {LAN_VLAN_IF} up")
    # /32 to wan via target's vlan100 address. Forces this flow's traffic
    # to egress vlan100 instead of the default route on the LAN native
    # interface — i.e. guarantees frames are VLAN-tagged.
    _lan_ip(lan, f"route add {WAN_IPERF_IP}/32 via {TARGET_VLAN_ADDR} dev {LAN_VLAN_IF}")

    # Give the subsystems a moment to see the new interface / cmm to
    # observe the netlink IFLA event and install VLAN entries.
    await asyncio.sleep(0.5)

    yield

    # --- teardown (best-effort; ignore errors) --------------------
    _lan_ip(lan, f"route del {WAN_IPERF_IP}/32 2>/dev/null")
    _lan_ip(lan, f"link del {LAN_VLAN_IF} 2>/dev/null")
    await _target_ip(aiohttp_session, target_agent,
                     ["link", "del", TARGET_VLAN_IF])


# ---- the test ----------------------------------------------------------

async def test_vlan_tagged_flow_offloaded(
    aiohttp_session, target_agent, lan, splat_window, vlan_100_setup,
):
    """iperf3 over a VLAN 100 subif; CMM sees the flow, throughput ≥ 1 Gbps."""
    baseline = await target_agent.cmm_query(aiohttp_session, "connections")
    baseline_count = _flow_count(baseline)

    # iperf3 picks up our /32 route automatically — no -B needed.
    await asyncio.to_thread(
        lan.run,
        f"nohup iperf3 -c {WAN_IPERF_IP} -t {IPERF_DURATION_S} "
        f"> /tmp/iperf-vlan.log 2>&1 & echo started",
    )

    await asyncio.sleep(2.0)
    during = await target_agent.cmm_query(aiohttp_session, "connections")
    during_count = _flow_count(during)
    assert during_count > baseline_count, (
        f"CMM saw no new flows through VLAN {VLAN_ID}: "
        f"baseline={baseline_count}, during={during_count}; "
        f"stderr={during.get('stderr','').strip()!r}"
    )

    await asyncio.sleep(IPERF_DURATION_S + 1)
    log_result = await asyncio.to_thread(lan.run, "cat /tmp/iperf-vlan.log")
    gbps = _iperf_receiver_gbps(log_result.stdout)
    assert gbps is not None, (
        f"iperf3 summary missing from log:\n{log_result.stdout}"
    )
    assert gbps >= OFFLOAD_MIN_GBPS, (
        f"throughput {gbps:.2f} Gbps below {OFFLOAD_MIN_GBPS} Gbps "
        f"over VLAN {VLAN_ID} — offload likely not engaged"
    )
