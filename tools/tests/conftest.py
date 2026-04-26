"""Shared fixtures for the ASK test harness.

Design notes:
  - aiohttp session is function-scoped (ClientSession is bound to the
    loop that created it; pytest-asyncio's default test loop is
    function-scoped).
  - The LAN-side UART console is session-scoped. Logging in over serial
    takes ~0.5s; with ~720 fuzz cases coming up we can't afford to
    re-login per test. Trade-off: tests share the shell — they must
    leave it at a clean prompt (Console.run() already does).
  - `splat_window` is per-test: opens a dmesg/counters capture on entry,
    asserts no new KASAN/BUG/UBSAN/lockdep splats on exit. Any test
    that uses it gets free sanitizer gating.
  - `_target_reachable` is autouse: fail-fast if the target agent is
    down, rather than every test flailing against 5s HTTP timeouts.

Environment variables (all with sensible defaults for the primary dev
site; override for other deployments):

    ASK_TARGET_IP       agent HTTP host (default 10.0.0.62)
    ASK_TARGET_DEV      target serial device (default /dev/ttyUSB0)
    ASK_LAN_IP          LAN-side agent HTTP host (default 172.30.0.10)
    ASK_LAN_VM          libvirt domain for LAN UART (default "loki")
    ASK_LAN_USER        LAN VM serial login user (default root)
    ASK_LAN_PASSWORD    LAN VM serial login password (default password)
    ASK_WAN_IP          WAN-side agent HTTP host (default 127.0.0.1)
    ASK_WAN_IPERF_IP    iperf3 server on the WAN side (default 10.0.0.141)
"""

from __future__ import annotations

import os

import aiohttp
import pytest
import pytest_asyncio

from ask_orch import client
from ask_orch.uart import Console

from _dmesg_allowlist import filter_splats, load_allowlist


LAN_USER     = os.environ.get("ASK_LAN_USER",     "root")
LAN_PASSWORD = os.environ.get("ASK_LAN_PASSWORD", "password")


# ---- per-test aiohttp ---------------------------------------------------

# Function-scoped: pytest-asyncio's default test loop is function-scoped,
# and aiohttp.ClientSession is bound to the loop it was created under.
# Session-scoping the ClientSession would span multiple loops and raise
# "Timeout context manager should be used inside a task". ClientSession
# creation cost is ~1ms, negligible compared to the HTTP round-trips
# each test does.
@pytest_asyncio.fixture
async def aiohttp_session():
    async with aiohttp.ClientSession() as s:
        yield s


@pytest.fixture(scope="session")
def target_agent():
    return client.TARGET


@pytest.fixture(scope="session")
def lan_agent():
    """LAN-side askd-agent. Same Agent class as target_agent, just
    pointed at $ASK_LAN_IP. Used by Phase 2 mcast replication tests
    that need parallel tcpdump captures across N listener subifs —
    the UART console is a single serial channel and can't run
    concurrent commands."""
    return client.LAN


# Loaded once per session. An expired entry raises here, failing the suite
# at collection rather than letting a stale suppressor mask a regression.
@pytest.fixture(scope="session")
def dmesg_allowlist():
    return load_allowlist()


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
def lan():
    """Pre-logged-in UART console to the LAN-side traffic-generator VM.

    Session-scoped to amortize the login cost across all tests. Tests
    should leave the shell at a clean prompt (the Console.run() path
    already handles that).
    """
    con = Console.lan()
    con.login(LAN_USER, LAN_PASSWORD)
    yield con
    con.close()


# ---- per-test ------------------------------------------------------------

@pytest_asyncio.fixture
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
    cap_id = await target_agent.capture_start(aiohttp_session, ifaces=["eth3", "eth4"])
    yield cap_id
    result = await target_agent.capture_stop(aiohttp_session, cap_id)
    raw = result.get("splats", [])
    splats = filter_splats(raw, request.node.nodeid, dmesg_allowlist)
    assert not splats, (
        f"kernel splats during test ({len(splats)}): "
        + "; ".join(s.strip() for s in splats[:3])
    )
