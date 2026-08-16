"""End-to-end TX-side tunnel offload test: LAN → DUT → tunnel → WAN.

Verifies the FMAN data plane accelerates the encap direction of an
IPv6-in-IPv4 (sit) tunnel. The path:

  LAN VM (fc00:dead::2) ──ipv6──> DUT eth4 (fc00:dead::1)
  DUT routes inner IPv6 via sit_test (kernel sit netdev)
  CMM observes the netdev's NEWLINK + conntrack flow, pushes
    CMD_TNL_CREATE + CMD_IPV6_CONNTRACK to FCI
  FCI installs an ehash entry with INSERT_L3_HDR action chain
  FMAN ucode prepends IPv4(proto=41) outer at line rate
  DUT eth3 ──ipv4(proto=41)/ipv6──> orchestrator sit_test → iperf3 -s

NOTE: TX-encap offload is currently blocked in FMAN ucode 210.10.1
(INSERT_L3_HDR punts every matched packet — ISSUES.md A9), so encap
runs in the kernel sit path (~9 Gbit/s on the A72s). This is a
THROUGHPUT + path-truth test, not an offload proof.

Oracles:
  (i)  iperf3 throughput ≥ OFFLOAD_MIN_GBPS — measures the kernel
       sit-encap path; a kernel-tx tripwire (below) asserts the
       software path explicitly, so if a future ucode fixes
       INSERT_L3_HDR this test fails loudly rather than silently
       changing meaning.
  (ii) The kernel grew at least one IPv6 conntrack entry during the
       run — proves the firewall rules engaged tracking, which is
       the prerequisite for CMM to mirror the flow to FCI.

Both oracles are required: (i) without (ii) could mean the LAN-side
link is itself the bottleneck (some test harnesses sit on a 10G
LAN-VM bridge); (ii) without (i) means we tracked but FMAN didn't
take the work.

Out of scope: RX-side decap. The CDX kernel module has no installer
for outer-keyed ehash entries (proto=41/4/47); decap falls through
to Linux's sit module in software. See ISSUES.md A9.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess

import pytest
import pytest_asyncio

from _topology import lan_run, ipv6_topology  # noqa: F401  (fixture re-export)


# Topology constants — defaults match the primary dev site.
DUT_WAN_IPV4 = os.environ.get("ASK_TARGET_IP",       "10.0.0.62")
ORCH_IPV4    = os.environ.get("ASK_WAN_IP",          "10.0.0.141")
LAN_NIC      = os.environ.get("ASK_LAN_NIC",         "enp4s0")

# Inner-tunnel ULA pair — kept distinct from the LAN/WAN ULAs so the
# test is identifiable in routing tables and not collide with any
# Phase 2 ipv6_topology fixture state.
DUT_TUN_V6   = "fc00:cafe::2"
ORCH_TUN_V6  = "fc00:cafe::1"
LAN_V6       = "fc00:dead::2"
DUT_LAN_V6   = "fc00:dead::1"

TUNNEL_IF    = "sit_test"
TUNNEL_MTU   = 1480       # 1500 (eth) - 20 (IPv4 outer)

# Kernel sit-encap on the A72 sustains ~9 Gbit/s (ISSUES.md A9); the
# >1 Gbps floor asserts the software path is healthy, not that FMAN
# offloaded (TX-encap offload is currently blocked in ucode).
OFFLOAD_MIN_GBPS = float(os.environ.get("ASK_TUNNEL_TX_MIN_GBPS", "1.0"))
IPERF_DURATION_S = int(os.environ.get("ASK_TUNNEL_TX_DURATION", "8"))

# Non-default port — 5201 is typically held by a system iperf3 service
# for ad-hoc client connects, and `iperf3 -s -D` on default would fail
# to bind silently (stderr is discarded under -D).
IPERF_PORT       = int(os.environ.get("ASK_TUNNEL_TX_IPERF_PORT", "5333"))

# CMM's tunnel-aware conntrack offload programs both directions only
# after seeing packets in both — TCP's SYN+SYNACK provides that
# (cmm/src/conntrack.c:2537 comment). Stick to TCP.
_IPERF_RX_RE = re.compile(
    r"^\[\s*\d+\]\s+[\d.]+-[\d.]+\s+sec\s+[\d.]+\s[KMGT]?Bytes\s+"
    r"([\d.]+)\s+([KMG]?)bits/sec.*receiver",
    re.M,
)


def _iperf_receiver_gbps(log: str) -> float | None:
    m = _IPERF_RX_RE.search(log)
    if not m:
        return None
    value, unit = m.groups()
    scale = {"": 1e-9, "K": 1e-6, "M": 1e-3, "G": 1.0}.get(unit, 0.0)
    return float(value) * scale


def _sh(cmd: str, check: bool = False) -> subprocess.CompletedProcess:
    """Shell command on the orchestrator (this host)."""
    return subprocess.run(
        cmd, shell=True, capture_output=True, text=True, check=check,
    )


# ---- fixture: bring up sit tunnel on orchestrator + DUT + LAN VM ----------

@pytest_asyncio.fixture
async def sit_tunnel(aiohttp_session, target_agent, lan, ipv6_topology):
    """Create a kernel-sit tunnel on DUT and orchestrator, plus inner-
    subnet IPv6 routes on LAN VM. Yields nothing (the test references
    constants directly). Cleans up on teardown.

    The sit netdev is what CMM watches and registers with FCI as an
    ASK tunnel — that's how the FMAN encap path becomes engaged.

    Depends on `ipv6_topology` for the underlying LAN→DUT v6 plumbing
    (fc00:dead::1/64 on DUT eth4, fc00:dead::2/64 on the LAN NIC,
    default v6 route on the LAN VM via fc00:dead::1, IPv6 forwarding
    on DUT). Without that, ND for the inner default-route next-hop
    fails and iperf3 reports `No route to host` immediately.
    """
    # Idempotent cleanup — prior test runs may have left state.
    _sh(f"ip link del {TUNNEL_IF} 2>/dev/null")
    _sh("pkill -f 'iperf3 -s' 2>/dev/null")
    await target_agent.exec_cmd(
        aiohttp_session, ["ip", "link", "del", TUNNEL_IF],
    )

    # ---- Orchestrator side ----
    _sh("modprobe sit")
    r = _sh(
        f"ip tunnel add {TUNNEL_IF} mode sit "
        f"local {ORCH_IPV4} remote {DUT_WAN_IPV4} ttl 64"
    )
    if r.returncode != 0:
        raise RuntimeError(f"orch sit add: {r.stderr}")
    _sh(f"ip link set {TUNNEL_IF} mtu {TUNNEL_MTU} up")
    _sh(f"ip -6 addr add {ORCH_TUN_V6}/64 dev {TUNNEL_IF}")
    _sh(f"ip -6 route add fc00:dead::/64 dev {TUNNEL_IF}")
    _sh("sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null")

    # iperf3 server on orchestrator (one-shot, exit after first client).
    # Pinned to IPERF_PORT to avoid colliding with a system iperf3 on 5201.
    iperf_proc = subprocess.Popen(
        ["iperf3", "-s", "-D", "-1", "-p", str(IPERF_PORT)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    # Give iperf3 a moment to bind.
    await asyncio.sleep(0.8)

    # ---- DUT side (via agent exec_cmd) ----
    for argv in [
        ["modprobe", "sit"],
        ["ip", "tunnel", "add", TUNNEL_IF, "mode", "sit",
         "local", DUT_WAN_IPV4, "remote", ORCH_IPV4, "ttl", "64"],
        ["ip", "link", "set", TUNNEL_IF, "mtu", str(TUNNEL_MTU), "up"],
        ["ip", "-6", "addr", "add", f"{DUT_TUN_V6}/64", "dev", TUNNEL_IF],
        # Default v6 route via the tunnel — anything LAN sends with
        # an IPv6 dst outside fc00:dead::/64 egresses via sit_test.
        ["ip", "-6", "route", "add", "fc00::/16", "dev", TUNNEL_IF],
    ]:
        r = await target_agent.exec_cmd(aiohttp_session, argv)
        # `ip link del` -> add can race; ignore "exists" errors.
        if r.get("rc") != 0 and "exists" not in (r.get("stderr") or ""):
            pass  # best-effort; downstream commands will fail loudly

    # ---- LAN VM side ----
    await lan_run(
        lan,
        f"ip -6 addr add {LAN_V6}/64 dev {LAN_NIC} 2>/dev/null; "
        f"ip -6 route add default via {DUT_LAN_V6} dev {LAN_NIC} 2>/dev/null",
    )

    # Give CMM time to observe the new sit netdev's NEWLINK and push
    # CMD_TNL_CREATE to FCI before any data plane traffic starts.
    await asyncio.sleep(2.0)

    try:
        yield
    finally:
        # Orchestrator
        _sh("pkill -f 'iperf3 -s' 2>/dev/null")
        _sh(f"ip -6 route del fc00:dead::/64 dev {TUNNEL_IF} 2>/dev/null")
        _sh(f"ip link del {TUNNEL_IF} 2>/dev/null")
        # DUT
        await target_agent.exec_cmd(
            aiohttp_session,
            ["ip", "-6", "route", "del", "fc00::/16", "dev", TUNNEL_IF],
        )
        await target_agent.exec_cmd(
            aiohttp_session, ["ip", "link", "del", TUNNEL_IF],
        )
        # LAN — leave the addr in place; cheap, harmless.
        try:
            iperf_proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            iperf_proc.kill()


# ---- the test --------------------------------------------------------------

async def test_tunnel_tx_ipv6_in_ipv4_offload(
    aiohttp_session, target_agent, lan, splat_window, sit_tunnel,
):
    """LAN→WAN IPv6 iperf3 over a sit tunnel — throughput + path truth.

    This is a THROUGHPUT test, not an offload proof: TX-encap offload is
    blocked inside FMAN ucode 210.10.1 (INSERT_L3_HDR punts every matched
    packet — ISSUES.md A9), and modern kernel sit encap sustains ~9 Gbit/s
    on the A72s, which is what the >1 Gbps floor actually measures. A
    kernel-tx counter tripwire below asserts the software path explicitly,
    so if a future ucode fixes INSERT_L3_HDR and encap starts offloading,
    this test fails loudly and gets rewritten rather than silently
    changing meaning.
    """
    # Conntrack baseline (we want at least ONE new IPv6 entry to appear,
    # which proves the kernel netfilter conntrack engaged on the
    # forwarded v6 path — prerequisite for CMM→FCI mirroring).
    r = await target_agent.exec_cmd(
        aiohttp_session,
        ["sysctl", "-n", "net.netfilter.nf_conntrack_count"],
    )
    ct_before = int((r.get("stdout") or "0").strip() or "0")

    r = await target_agent.exec_cmd(
        aiohttp_session, ["ip", "-s", "-j", "link", "show", TUNNEL_IF])
    sit_tx_before = json.loads(r["stdout"])[0]["stats64"]["tx"]["packets"]

    # iperf3 client on LAN VM, target = orchestrator's tunnel-side v6.
    # TCP so SYN+SYNACK marks the flow assured-equivalent enough for
    # the IPIP/SIT path (cmm/src/conntrack.c:2537 — IPIP never reaches
    # ASSURED, programmed when packets are seen in both directions).
    r = await lan_run(
        lan,
        f"iperf3 -c {ORCH_TUN_V6} -p {IPERF_PORT} -t {IPERF_DURATION_S} 2>&1",
        timeout=IPERF_DURATION_S + 15,
    )
    log = r.stdout
    gbps = _iperf_receiver_gbps(log)
    if gbps is None:
        # Path-trace on failure: tunnel state on DUT/Vision + LAN
        # routing. Quickest discriminator between "tunnel not up", "v6
        # forwarding off", "iperf3 didn't bind", and "FMAN dropped".
        vision_a  = _sh(f"ip a show {TUNNEL_IF}").stdout
        vision_rt = _sh("ip -6 route show").stdout
        vision_ls = _sh(f"ss -ltnp 'sport = :{IPERF_PORT}'").stdout
        vision_state = (
            f"ip a {TUNNEL_IF}:\n{vision_a}\n"
            f"ip -6 route:\n{vision_rt}\n"
            f"listen on :{IPERF_PORT}:\n{vision_ls}"
        )
        dut_a   = await target_agent.exec_cmd(
            aiohttp_session, ["ip", "a", "show", TUNNEL_IF],
        )
        dut_rt  = await target_agent.exec_cmd(
            aiohttp_session, ["ip", "-6", "route", "show"],
        )
        dut_fwd = await target_agent.exec_cmd(
            aiohttp_session, ["sysctl", "-n", "net.ipv6.conf.all.forwarding"],
        )
        dut_text = (
            f"ip a {TUNNEL_IF}:\n{dut_a.get('stdout','')}\n"
            f"ip -6 route:\n{dut_rt.get('stdout','')}\n"
            f"v6 forwarding: {dut_fwd.get('stdout','').strip()}"
        )
        lan_state = await lan_run(
            lan,
            f"ip a show {LAN_NIC}; ip -6 route show; "
            f"ping -6 -c 2 -W 2 {ORCH_TUN_V6} 2>&1; "
            f"ping -6 -c 2 -W 2 {DUT_LAN_V6} 2>&1",
            timeout=15.0,
        )
        pytest.fail(
            f"iperf3 didn't report a receiver throughput line.\n"
            f"--- iperf3 output ---\n{log[-800:]}\n"
            f"--- Vision tunnel + ipv6 routes + listen ---\n{vision_state}\n"
            f"--- DUT tunnel + ipv6 routes + forwarding ---\n{dut_text}\n"
            f"--- LAN VM ipv6 + ping(orch_tun_v6) + ping(dut_lan_v6) ---\n"
            f"{lan_state.stdout}"
        )

    # Counter snapshot: did the kernel grow any IPv6 conntrack entries?
    r = await target_agent.exec_cmd(
        aiohttp_session,
        ["sysctl", "-n", "net.netfilter.nf_conntrack_count"],
    )
    ct_after = int((r.get("stdout") or "0").strip() or "0")
    ct_delta = ct_after - ct_before

    # Oracle (i): throughput must exceed the SW-fallback ceiling.
    assert gbps >= OFFLOAD_MIN_GBPS, (
        f"tunneled iperf3 throughput {gbps:.2f} Gbps below "
        f"{OFFLOAD_MIN_GBPS} Gbps — kernel sit-encap path unhealthy "
        f"(normally ~9 Gbit/s). CT delta: {ct_delta}. iperf3 tail:\n"
        f"{log[-600:]}"
    )

    # Oracle (ii): conntrack must have grown. If this fires while (i)
    # passes, the LAN-side link is the bottleneck and the throughput
    # number is misleading — investigate before treating as a real
    # offload pass.
    assert ct_delta >= 1, (
        f"throughput {gbps:.2f} Gbps but conntrack count didn't grow "
        f"(before={ct_before}, after={ct_after}). Either ip6tables "
        f"FORWARD rule isn't engaging conntrack, or traffic bypassed "
        f"the kernel forward path entirely (LAN-side bottleneck)."
    )

    # Oracle (iii): software-encap tripwire. Kernel sit tx must have
    # carried the bulk of the run; if it stays near zero the encap
    # direction started hardware-offloading (ucode INSERT_L3_HDR fixed?)
    # and this test's premise changed — rewrite it as a real offload
    # test with counter oracles (see ISSUES.md A9).
    r = await target_agent.exec_cmd(
        aiohttp_session, ["ip", "-s", "-j", "link", "show", TUNNEL_IF])
    sit_tx_after = json.loads(r["stdout"])[0]["stats64"]["tx"]["packets"]
    sit_tx_delta = sit_tx_after - sit_tx_before
    assert sit_tx_delta > 1000, (
        f"kernel sit tx only +{sit_tx_delta} during a {gbps:.2f} Gbps "
        f"run — encap appears hardware-offloaded now, which contradicts "
        f"the known ucode 210.10.1 INSERT_L3_HDR limitation. Re-verify "
        f"and rewrite this test; see ISSUES.md A9."
    )
