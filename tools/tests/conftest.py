"""Shared fixtures: session-owned DUT UART, LAN QGA, and WAN HTTP clients.

Function-scoped aiohttp sessions follow pytest-asyncio's event loops. Kernel
capture windows include fixture setup and teardown, retaining bulk evidence
only on failures. Bench settings come from .ask-test.mk or ASK_* variables.
"""

from __future__ import annotations

import gzip
import asyncio
import json
import os
from pathlib import Path
import warnings

from ask_orch.artifacts import artifact_dir, record
from ask_orch.capture import capture_window, verify_capture

import aiohttp
import pytest
import pytest_asyncio

from ask_orch import client, manifest
from ask_orch.uart import Console, set_target_session
from ask_orch.serial import SerialSession
from askd_agent.wire import VERSION as SERIAL_PROTOCOL
from ask_orch.guest import Guest
from ask_orch.provenance import agent_sources, firmware_script


from _dmesg_allowlist import load_allowlist
from _topology import LAN_NIC, TARGET_WAN_IF, wire_interface
import _wire_loss as wire_loss

# Written on the DUT by a case that ends its boot, before it starts. The
# rootfs is an initramfs, so only a new boot clears it.
BOOT_SPENT = "/run/ask-test-boot-spent"


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


@pytest.fixture(scope="session")
def dut_uart(hardware_bench):
    """One physical reader for both agent operations and console helpers.

    ASK_TARGET_AGENT_DEV names the DUT's USB serial port (its ttyGS0) to
    carry them instead of the UART: the same protocol, without the UART's
    line rate or its need to pace writes. The UART then stays free for raw
    console use -- boot, reboot and recovery."""
    agent_dev = os.environ.get("ASK_TARGET_AGENT_DEV")
    log_path = str(artifact_dir("session") / "dut-uart.log")
    opened = (Console(port=agent_dev, log_path=log_path) if agent_dev
              else Console.target(raw=True, log_path=log_path))
    with opened as console:
        session = SerialSession(console)
        set_target_session(session)
        try:
            yield session
        finally:
            try:
                session.close()
            finally:
                set_target_session(None)


# Loaded once per session. An expired entry raises here, failing the suite
# before hardware setup rather than letting a stale suppressor mask a regression.
@pytest.fixture(scope="session")
def dmesg_allowlist():
    return load_allowlist()


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def bench_health(request, hardware_bench, dmesg_allowlist, dut_uart):
    """Check firmware, logging and selected release capabilities before
    mutations. A release also needs the image this checkout builds: every
    component and the device tree (ask_orch.manifest)."""
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
        health = await client.TARGET.health(session)
        record("dut", health, nodeid="session")
        assert health.get("ok") and health.get("capture_protocol") == 2 and health.get("serial_protocol") == SERIAL_PROTOCOL, (
            "DUT needs the current test agent with reliable kernel capture", health)
        spent = await client.TARGET.fs_read(session, BOOT_SPENT)
        assert spent["errno"], (
            f"{bytes.fromhex(spent['content_hex']).decode()} ended this boot; "
            "boot the staged image again before testing")
        required = {"ip", "nft", "conntrack", "python3"}
        for item in request.session.items:
            for marker in item.iter_markers("requires"):
                required.update(marker.args)
        result = await asyncio.to_thread(dut_uart.python, firmware_script(required))
        assert result["rc"] == 0, result
        firmware = json.loads(result["stdout"])
        expected = agent_sources(Path(__file__).resolve().parents[1] / "askd_agent")
        firmware["agent_matches_checkout"] = firmware["agent_sources"] == expected
        firmware["build_problems"] = manifest.verify(Path(__file__).resolve().parents[2], firmware["image"])
        record("firmware", firmware, nodeid="session")
        config = await client.TARGET.fs_read(session, "/proc/config.gz")
        assert config["errno"] == 0, config
        kernel_config = gzip.decompress(bytes.fromhex(config["content_hex"])).decode()
        assert "CONFIG_KASAN=y" in kernel_config.splitlines(), (
            "DUT tests require KASAN; rebuild with make ask-image, stage and boot it")
        boot = await client.TARGET.boot_log(session)
        record("boot-kernel", boot, nodeid="session")
        try:
            verify_capture(boot, "boot", dmesg_allowlist)
        except BaseException:
            if boot.get("artifact"):
                data = await client.TARGET.artifact(session, boot["artifact"]["id"])
                (artifact_dir("session") / "boot-kernel-log.json").write_bytes(data)
            raise
        finally:
            if boot.get("artifact"):
                await client.TARGET.request(session, "artifact/release", {"id": boot["artifact"]["id"]})
        # A frame the wire loses before the DUT fails a zero-loss case as a
        # forwarding loss would. Measured once, so such a failure can be told.
        wire = wire_interface()
        lossy = None
        if wire:
            loss = await wire_loss.measure(client.TARGET, session, wire, TARGET_WAN_IF)
            record("wan-wire-loss", loss, nodeid="session")
            if loss["lost"]:
                lossy = (f"the WAN wire lost {loss['lost']} of {loss['sent']} frames between {wire} "
                         f"and the DUT's {TARGET_WAN_IF} MAC; zero-loss cases fed from the WAN can "
                         "fail for it (session artifact wan-wire-loss.json)")
        if request.config.getoption("--release"):
            assert not lossy, lossy
            assert not firmware["missing_binaries"], (
                "release firmware lacks required tools", firmware["missing_binaries"])
            assert firmware["agent_matches_checkout"], (
                "DUT agent differs from this checkout; rebuild, stage and boot the current image")
            assert not firmware["build_problems"], (
                "DUT image was not built from this checkout ("
                + "; ".join(firmware["build_problems"]) + "); " + manifest.REMEDY)
        elif firmware["build_problems"]:
            # Testing an older image on purpose is legitimate outside a release.
            warnings.warn("DUT image was not built from this checkout: "
                          + "; ".join(firmware["build_problems"]))
        if lossy and not request.config.getoption("--release"):
            warnings.warn(lossy)
        return {"health": health, "boot": boot}


@pytest_asyncio.fixture(autouse=True)
async def _boot_ending(request, _target_reachable, aiohttp_session, target_agent):
    """A destructive case ends its boot whatever its outcome, so it says so on
    the DUT before anything else of it runs, and the next session refuses
    that boot."""
    if request.node.get_closest_marker("destructive"):
        result = await target_agent.fs_write(aiohttp_session, BOOT_SPENT, request.node.nodeid)
        assert result["errno"] == 0, result


@pytest_asyncio.fixture(autouse=True)
async def _target_reachable(aiohttp_session, target_agent):
    """Fail-fast per-test if the target agent is unreachable. Cheaper
    than repeating commands against a lost UART session."""
    try:
        h = await target_agent.health(aiohttp_session)
    except Exception as e:
        pytest.exit(f"target agent unreachable: {e}", returncode=2)
    if not h.get("ok"):
        pytest.exit(f"target /health returned ok=False: {h!r}", returncode=2)


@pytest.fixture(autouse=True)
def _lan_learned_state_forgotten(lan):
    """The LAN VM reaches everything beyond its subnet through the DUT's LAN
    address, at the MAC it last learned for it. A case that bridges the LAN
    port has the DUT answer for that address with the bridge's MAC, and the
    VM keeps that MAC once the port is on its own again: the next case's
    first datagrams go to a MAC the port no longer takes, and stay dark --
    some nine seconds -- until the VM's unicast probes fail and a broadcast
    finds the port's own. A peer that waits five seconds for an echo fails
    on it. The bridge also carries the WAN segment's router advertisements
    to the VM, which takes a default route, an address and an on-link
    prefix from them. So every case starts with the VM's LAN NIC holding
    none of what it learned: it resolves the DUT afresh, its first packet
    queued a millisecond for it."""
    result = lan.run(f"ip neigh flush dev {LAN_NIC} && "
                     f"ip -6 route flush dev {LAN_NIC} proto ra && "
                     f"ip -6 addr flush dev {LAN_NIC} scope global dynamic && "
                     f"ip -6 route show dev {LAN_NIC} | awk '/ expires /{{print $1}}' | "
                     f"while read -r prefix; do ip -6 route del \"$prefix\" dev {LAN_NIC} || exit 1; done",
                     timeout=10)
    assert result.rc == 0, ("forgetting what the LAN VM learned", result.stdout)


@pytest.fixture(scope="session")
def lan(hardware_bench):
    """Out-of-band LAN control through the VM's virtio guest-agent channel."""
    guest = Guest(os.environ["ASK_LAN_VM"])
    record("lan-agent", {"version": guest.check()}, nodeid="session")
    return guest


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
    async with capture_window(target_agent, aiohttp_session, request.node.nodeid, dmesg_allowlist,
                              failed_check=lambda: getattr(request.node, "_ask_failed", False)) as cap_id:
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
