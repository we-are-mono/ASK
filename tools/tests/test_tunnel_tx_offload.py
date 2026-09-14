"""End-to-end TX-side tunnel offload test: LAN → DUT → tunnel → WAN.

Verifies the FMAN data plane accelerates the encap direction of an
IPv6-in-IPv4 (sit) tunnel. The path:

  LAN VM (fc00:dead::2) ──ipv6──> DUT eth3 (fc00:dead::1)
  DUT routes inner IPv6 via sit_test (kernel sit netdev)
  CMM observes the netdev's NEWLINK + conntrack flow, pushes
    CMD_TNL_CREATE + CMD_IPV6_CONNTRACK to FCI
  FCI installs an ehash entry with INSERT_L3_HDR action chain
  FMAN ucode prepends IPv4(proto=41) outer at line rate
  DUT eth4 ──ipv4(proto=41)/ipv6──> orchestrator sit_test → iperf3 -s

Oracles:
  (i)  iperf3 throughput ≥ OFFLOAD_MIN_GBPS — the path carries traffic
       at all. Not an offload signal on its own: the software path also
       clears this floor easily.
  (ii) conntrack holds an entry for THIS tunnel flow after the run —
       the outer proto-41 sit encapsulation between the tunnel
       endpoints (or the inner v6 flow) — proving the kernel forward
       path engaged tracking, the prerequisite for CMM→FCI mirroring.
       A global conntrack-count delta is deliberately not used: entries
       left by earlier tests age out mid-run and made it flaky late in
       the suite.
  (iii) the physical LAN port's software RX count (SDK DPAA ethtool)
        stays below 10% of received frames. This distinguishes hardware
        forwarding from the Linux tunnel path even when CPUs are idle.
  (iv) WAN egress frames average IPV4_HDR_LEN bytes more than LAN
       ingress frames, confirming the expected encapsulation. CPU busy
       time is reported as a diagnostic, not used as an offload proof.

Do NOT re-introduce a tunnel-netdev counter oracle here. ASK folds the
FMAN per-interface stats into the netdev counters (ISSUES.md A136), so
`ip -s link show sit_test` cannot distinguish a hardware encap from a
kernel one — an earlier revision of this test asserted the opposite
conclusion off that counter and was wrong for months.

Out of scope: RX-side decap — covered by test_tunnel_decap_offload.py.
"""
from __future__ import annotations

import asyncio
import os
import re
import subprocess

import pytest
import pytest_asyncio

from _topology import (  # noqa: F401  (fixture re-export)
    lan_run, ipv6_topology, TARGET_LAN_IF, TARGET_WAN_IF, kernel_rx_packets,
)


# Topology constants — defaults match the primary dev site.
DUT_WAN_IPV4 = os.environ.get("ASK_TARGET_IP",       "10.0.0.62")
ORCH_IPV4    = os.environ.get("ASK_WAN_IPERF_IP",    "10.0.0.141")
LAN_NIC      = os.environ.get("ASK_LAN_NIC",         "enp4s0")

# Inner-tunnel ULA pair — kept distinct from the LAN/WAN ULAs so the
# test is identifiable in routing tables and not collide with any
# ipv6_topology fixture state.
DUT_TUN_V6   = "fc00:cafe::2"
ORCH_TUN_V6  = "fc00:cafe::1"
LAN_V6       = "fc00:dead::2"
DUT_LAN_V6   = "fc00:dead::1"

TUNNEL_IF    = "sit_test"
TUNNEL_MTU   = 1480       # 1500 (eth) - 20 (IPv4 outer)

# Offloaded 6o4 encap runs the LAN link out at ~9 Gbit/s. The floor stays
# well under that so link-speed variation between benches doesn't flake it;
# the separate software RX counter determines whether Linux forwarded it.
OFFLOAD_MIN_GBPS = float(os.environ.get("ASK_TUNNEL_TX_MIN_GBPS", "1.0"))
IPERF_DURATION_S = int(os.environ.get("ASK_TUNNEL_TX_DURATION", "8"))

# At most 10% of received frames may enter software, including flow setup.
MAX_SOFTWARE_RX_FRAC = 0.1

# A 6o4 outer header is 20 bytes. Tolerance absorbs the few unencapsulated
# frames (ARP/ND, the iperf control socket) mixed into the port counters.
IPV4_HDR_LEN          = 20
ENCAP_OVERHEAD_TOL    = 3.0

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


async def _proc_read(target_agent, session, path: str) -> str:
    """Read a /proc file via the agent's fs/read (cat is not allowlisted)."""
    r = await target_agent.fs_read(session, path)
    assert r.get("errno", 0) == 0, f"read {path} failed: {r!r}"
    return bytes.fromhex(r["content_hex"]).decode("utf-8", "replace")


async def _port_counters(target_agent, session, ifname: str) -> dict:
    """RX/TX bytes+packets for one DUT port, from /proc/net/dev.

    These totals include software and hardware forwarding. Use them for
    traffic volume and packet lengths; ethtool supplies software RX alone.
    """
    for line in (await _proc_read(
            target_agent, session, "/proc/net/dev")).splitlines():
        name, _, rest = line.partition(":")
        if name.strip() != ifname:
            continue
        f = rest.split()
        return {"rx_bytes": int(f[0]), "rx_packets": int(f[1]),
                "tx_bytes": int(f[8]), "tx_packets": int(f[9])}
    raise AssertionError(f"{ifname} not found in DUT /proc/net/dev")


async def _cpu_jiffies(target_agent, session) -> tuple[int, int]:
    """(idle_jiffies, total_jiffies) from the aggregate /proc/stat line."""
    head = (await _proc_read(
        target_agent, session, "/proc/stat")).splitlines()[0]
    f = head.split()
    assert f and f[0] == "cpu", f"unexpected /proc/stat head: {head!r}"
    vals = [int(x) for x in f[1:11]]
    # user nice system idle iowait irq softirq steal guest guest_nice
    idle = vals[3] + vals[4]
    # guest and guest_nice are already included in user and nice.
    return idle, sum(vals[:8])


def _busy_fraction(before: tuple[int, int], after: tuple[int, int]) -> float:
    idle_d  = after[0] - before[0]
    total_d = after[1] - before[1]
    assert total_d > 0, f"no CPU time elapsed: {before} -> {after}"
    return 1.0 - (idle_d / total_d)


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
    (fc00:dead::1/64 on DUT eth3, fc00:dead::2/64 on the LAN NIC,
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
    """LAN→WAN IPv6 iperf3 over a sit tunnel — proves FMAN does the encap.

    End-to-end delivery with few software ingress packets proves offload.
    Port byte/packet totals verify encapsulation and CPU time is diagnostic.
    Tunnel-netdev totals alone cannot distinguish the two paths (A136).
    """
    # Baselines for the offload oracles: per-port byte/packet counters and
    # the CPU jiffie vector. Both are read again after the run.
    lan_before = await _port_counters(
        target_agent, aiohttp_session, TARGET_LAN_IF)
    wan_before = await _port_counters(
        target_agent, aiohttp_session, TARGET_WAN_IF)
    cpu_before = await _cpu_jiffies(target_agent, aiohttp_session)
    sw_before = await kernel_rx_packets(target_agent, aiohttp_session, TARGET_LAN_IF)

    # iperf3 client on LAN VM, target = orchestrator's tunnel-side v6.
    # TCP so SYN+SYNACK marks the flow assured-equivalent enough for
    # the IPIP/SIT path (cmm/src/conntrack.c:2537 — IPIP never reaches
    # ASSURED, programmed when packets are seen in both directions).
    r = await lan_run(
        lan,
        f"iperf3 -c {ORCH_TUN_V6} -p {IPERF_PORT} -t {IPERF_DURATION_S} 2>&1",
        timeout=IPERF_DURATION_S + 15,
    )
    # End all measurement windows before querying conntrack or diagnostics.
    sw_after = await kernel_rx_packets(target_agent, aiohttp_session, TARGET_LAN_IF)
    cpu_after = await _cpu_jiffies(target_agent, aiohttp_session)
    wan_after = await _port_counters(target_agent, aiohttp_session, TARGET_WAN_IF)
    lan_after = await _port_counters(target_agent, aiohttp_session, TARGET_LAN_IF)
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

    # Oracle (i): enough delivered traffic for the path measurement.
    assert gbps >= OFFLOAD_MIN_GBPS, (
        f"tunneled iperf3 throughput {gbps:.2f} Gbps below "
        f"{OFFLOAD_MIN_GBPS} Gbps — tunnel path throughput too low. iperf3 tail:\n"
        f"{log[-600:]}"
    )

    # Oracle (ii): the kernel forward path must have tracked THIS flow.
    # A global nf_conntrack_count delta is unreliable — background entries
    # left by earlier tests age out during the run and can mask the flow's
    # own entry (a late-in-suite false negative). Query conntrack for the
    # tunnel's own flow instead: the outer sit encap appears as a proto-41
    # entry between the two tunnel endpoints (long timeout, stable), with
    # the inner v6 TCP flow as a secondary signal that expires sooner.
    r = await target_agent.exec_cmd(
        aiohttp_session, ["conntrack", "-L"], timeout_ms=8000)
    ct_dump = r.get("stdout", "") or ""

    def _is_outer_sit(line):
        # conntrack row for proto 41: "unknown  41 <timeout> src=.. dst=.."
        fields = line.split()
        return (len(fields) > 2 and fields[1] == "41"
                and DUT_WAN_IPV4 in line and ORCH_IPV4 in line)

    outer_tracked = any(_is_outer_sit(ln) for ln in ct_dump.splitlines())
    inner_tracked = any(
        f"dport={IPERF_PORT}" in ln and ORCH_TUN_V6 in ln
        for ln in ct_dump.splitlines()
    )
    assert outer_tracked or inner_tracked, (
        f"throughput {gbps:.2f} Gbps but no conntrack entry for the tunnel "
        f"flow (outer proto-41 {DUT_WAN_IPV4}<->{ORCH_IPV4}, or inner v6 "
        f"dport={IPERF_PORT} to {ORCH_TUN_V6}). Either the ip6tables FORWARD "
        f"rule isn't engaging conntrack, or traffic bypassed the kernel "
        f"forward path (LAN-side bottleneck).\nconntrack -L:\n{ct_dump[:1500]}"
    )

    busy_frac = _busy_fraction(cpu_before, cpu_after)

    # The software counter excludes hardware RX; the totals below include it.
    lan_pkts  = lan_after["rx_packets"] - lan_before["rx_packets"]
    wan_pkts  = wan_after["tx_packets"] - wan_before["tx_packets"]
    lan_bytes = lan_after["rx_bytes"] - lan_before["rx_bytes"]
    wan_bytes = wan_after["tx_bytes"] - wan_before["tx_bytes"]
    assert lan_pkts > 10_000 and wan_pkts > 10_000, (
        f"too little traffic to measure: {TARGET_LAN_IF} rx +{lan_pkts} pkt, "
        f"{TARGET_WAN_IF} tx +{wan_pkts} pkt during a {gbps:.2f} Gbps run"
    )
    software_rx = sw_after - sw_before
    assert 0 <= software_rx <= lan_pkts * MAX_SOFTWARE_RX_FRAC, (
        f"{TARGET_LAN_IF} software RX +{software_rx} of {lan_pkts} received "
        f"frames: too much tunnel traffic entered Linux (limit "
        f"{MAX_SOFTWARE_RX_FRAC:.0%}). CPU busy {busy_frac:.1%}, "
        f"throughput {gbps:.2f} Gbps."
    )
    # Packet lengths establish encapsulation, independently of which path ran.
    encap_overhead = (wan_bytes / wan_pkts) - (lan_bytes / lan_pkts)
    print(f"tunnel TX: {gbps:.2f} Gbps, software RX {software_rx}/{lan_pkts}, "
          f"CPU busy {busy_frac:.1%}, overhead {encap_overhead:.2f} B/packet")
    assert abs(encap_overhead - IPV4_HDR_LEN) <= ENCAP_OVERHEAD_TOL, (
        f"egress frames are {encap_overhead:.2f} B/pkt larger than ingress, "
        f"expected {IPV4_HDR_LEN} ± {ENCAP_OVERHEAD_TOL} for a 6o4 outer "
        f"header. {TARGET_LAN_IF} rx {lan_bytes}B/{lan_pkts}pkt, "
        f"{TARGET_WAN_IF} tx {wan_bytes}B/{wan_pkts}pkt."
    )
