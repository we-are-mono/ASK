"""Shared fixtures for the ASK test harness.

Design notes:
  - aiohttp session is function-scoped (ClientSession is bound to the
    loop that created it; pytest-asyncio's default test loop is
    function-scoped).
  - The LAN-side UART console is session-scoped. Logging in over serial
    takes ~0.5s, which is not worth paying again for every test.
    Trade-off: tests share the shell — they must
    leave it at a clean prompt (Console.run() already does).
  - `splat_window` is per-test: opens a dmesg/counters capture on entry,
    asserts no new KASAN/BUG/UBSAN/lockdep splats on exit, including
    function fixture setup and teardown.
  - `_target_reachable` is autouse: fail-fast if the target agent is
    down, rather than every test flailing against 5s HTTP timeouts.

Bench settings come from the environment (or Make's ignored .ask-test.mk):

    ASK_TARGET_IP       agent HTTP host
    ASK_TARGET_DEV      target serial device
    ASK_LAN_VM          libvirt domain for LAN UART
    ASK_LAN_USER        LAN VM serial login user (default root)
    ASK_LAN_PASSWORD    LAN VM serial login password (optional)
    ASK_WAN_IP          WAN-side agent HTTP host (default 127.0.0.1)
    ASK_WAN_IPERF_IP    iperf3 server on the WAN side

The LAN VM is reached only via libvirt PTY (Console.lan()) — it sits
behind the DUT's NAT and has no IP path from the orchestrator, by
design. Tests drive LAN-side work through the UART; parallel-shape
work uses backgrounded shell processes coordinated via filesystem
state (see _mcast_helpers.py for the pattern).
"""

from __future__ import annotations

import os

from ask_orch.artifacts import artifact_dir, record
from ask_orch.capture import capture_window, verify_capture

import aiohttp
import pytest
import pytest_asyncio

from ask_orch import client
from ask_orch.uart import Console


from _dmesg_allowlist import load_allowlist


LAN_USER     = os.environ.get("ASK_LAN_USER",     "root")
LAN_PASSWORD = os.environ.get("ASK_LAN_PASSWORD", "")


# ---- per-test aiohttp ---------------------------------------------------

# Function-scoped: pytest-asyncio's default test loop is function-scoped,
# and aiohttp.ClientSession is bound to the loop it was created under.
# Session-scoping the ClientSession would span multiple loops and raise
# "Timeout context manager should be used inside a task". ClientSession
# creation cost is ~1ms, negligible compared to the HTTP round-trips
# each test does.
@pytest_asyncio.fixture
async def aiohttp_session():
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as s:
        yield s


@pytest.fixture(scope="session")
def target_agent(bench_health):
    return client.TARGET


# Loaded once per session. An expired entry raises here, failing the suite
# before hardware setup rather than letting a stale suppressor mask a regression.
@pytest.fixture(scope="session")
def dmesg_allowlist():
    return load_allowlist()


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def bench_health(request, hardware_bench, dmesg_allowlist):
    """Check firmware, logging and selected release capabilities before mutations."""
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
        health = await client.TARGET.health(session)
        record("dut", health, nodeid="session")
        assert health.get("ok") and health.get("capture_protocol") == 2, (
            "DUT needs the current test agent with reliable kernel capture", health)
        boot = await client.TARGET.boot_log(session)
        record("boot-kernel", boot, nodeid="session")
        verify_capture(boot, "boot", dmesg_allowlist)
        if request.config.getoption("--release"):
            required = {"ip", "nft", "conntrack"}
            for item in request.session.items:
                for marker in item.iter_markers("requires"):
                    required.update(marker.args)
            missing = required - set(health.get("binaries", []))
            assert not missing, f"release firmware lacks required tools: {sorted(missing)}"
        return {"health": health, "boot": boot}


@pytest_asyncio.fixture(autouse=True)
async def _target_reachable(aiohttp_session, target_agent):
    """Fail-fast per-test if the target agent is unreachable. Cheaper
    than every test flailing against 5s HTTP timeouts."""
    try:
        h = await target_agent.health(aiohttp_session)
    except Exception as e:
        pytest.exit(f"target agent unreachable: {e}", returncode=2)
    if not h.get("ok"):
        pytest.exit(f"target /health returned ok=False: {h!r}", returncode=2)


@pytest.fixture(scope="session")
def lan(hardware_bench):
    """Pre-logged-in UART console to the LAN-side traffic-generator VM.

    Session-scoped to amortize the login cost across all tests. Tests
    should leave the shell at a clean prompt (the Console.run() path
    already handles that).
    """
    with Console.lan(log_path=str(artifact_dir("session") / "lan-uart.log")) as con:
        con.login(LAN_USER, LAN_PASSWORD)
        con.send("stty cols 1000 rows 200\r")
        con.sync_prompt()
        yield con


# ---- per-test ------------------------------------------------------------

@pytest_asyncio.fixture(autouse=True)
async def splat_window(request, aiohttp_session, target_agent, dmesg_allowlist):
    """Wrap a test in a capture window; fail if new kernel splats appear.

    Even if the test's main assertion failed, run the splat check — a
    sanitizer report is independently important and surfacing both
    signals beats hiding one.

    Splat filtering is two-stage: the agent emits everything matching
    SPLAT_RE; this fixture then drops anything in the checked-in
    allowlist (golden/dmesg_allowlist.yaml). Test authors should *not*
    add inline filters here — extend the YAML.
    """
    async with capture_window(target_agent, aiohttp_session, request.node.nodeid, dmesg_allowlist) as cap_id:
        yield cap_id


# Shared fixtures are registered here; test modules declare dependencies by name.
from _flowtable_connections import connections  # noqa: F401
from _flowtable_ipv6 import hairpin6, ipv6_rig  # noqa: F401
from _flowtable_pppoe import pppoe_rig  # noqa: F401
from _flowtable_qos import qos  # noqa: F401
from _flowtable_rig import rig  # noqa: F401
from _flowtable_selective_neighbour import selective  # noqa: F401
from _flowtable_service import service  # noqa: F401
from _flowtable_service_bridge import bridge_service, bridge_software  # noqa: F401
from _flowtable_service_ipsec import ipsec_service  # noqa: F401
from _flowtable_service_multicast import multicast_service  # noqa: F401
from _flowtable_service_multicast_leave import listener_bridge  # noqa: F401
from _flowtable_service_vlan import vlan_service  # noqa: F401
from _flowtable_tcp_snat import tcp_snat  # noqa: F401
from _flowtable_tunnel import tunnel_rig  # noqa: F401
from _flowtable_vlan import vlan_rig  # noqa: F401
from _mcast_e2e import mcast_bridge, mroute_lan_bridge, smcrouted, stream_cpu  # noqa: F401
from _mcast_helpers import pcap_cleanup_lan  # noqa: F401
from _mcast_windows import multicast_rig  # noqa: F401
from _topology import ipv6_topology  # noqa: F401
