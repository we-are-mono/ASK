"""The xfrmdev_ops control plane: a packet-offload SA reaches the hardware.

  test_esp_hw_offload_advertised
      The CDX physical ports carry NETIF_F_HW_ESP. This is not cosmetic:
      strongSwan resolves the position of the `esp-hw-offload` feature once
      at startup and then tests it per interface before it will ask the
      kernel for offload at all. A port that does not advertise it is never
      offered an SA, and the tunnel runs in software with nothing saying so.

  test_packet_offload_sa_install
      `ip xfrm state add ... offload packet dev <wan> dir out` is accepted,
      and `ip -d xfrm state` reports the offload back. Without xfrmdev_ops
      on the device, xfrm_dev_state_add() refuses a packet-offload request
      with -EINVAL before any driver runs, so this is the first end-to-end
      assertion that the control plane exists.

Neither test sends traffic. The datapath is the next increment; what is
being pinned here is that an SA can be described, accepted and withdrawn.
"""

from __future__ import annotations

import asyncio
import json
import os
import time

import pytest

from ask_orch.uart import Console
from _ipsec_helpers import endpoints_up, iface_index, sa_add
from _topology import TARGET_WAN_IF
from test_flowtable_offload import (ARTIFACTS, RX_PORTS_SCRIPT, command, console_command, console_python,
                                    read, status_text, stop_boot_daemon)

# Documentation-range addresses (RFC 2544 benchmarking block), distinct from
# every other IPsec file's so the tests can run in any order.
LOCAL = "198.18.86.1"
PEER = "198.18.86.2"
SPI = "0x4d6f6e6f"
REQID = "48601"
# AES-128-GCM: sixteen key bytes then the four-byte salt, which is why the
# key material is twenty bytes for a "128-bit" cipher. ICV 128 selects
# SADB_X_EALG_AES_GCM_ICV16, the combination A24a measured as the fast one.
AEAD_KEY = "0x" + "a5" * 20
AEAD = ["aead", "rfc4106(gcm(aes))", AEAD_KEY, "128"]


async def _run(session, agent, *argv, expect_rc=0):
    result = await agent.exec_cmd(session, list(argv))
    if expect_rc is not None:
        assert result["rc"] == expect_rc, (argv, result)
    return result


async def test_esp_hw_offload_advertised(aiohttp_session, target_agent):
    result = await _run(aiohttp_session, target_agent,
                        "ethtool", "-k", TARGET_WAN_IF)
    features = {
        line.split(":")[0].strip(): line.split(":")[1].strip()
        for line in result["stdout"].splitlines() if ":" in line
    }
    assert "esp-hw-offload" in features, (
        f"{TARGET_WAN_IF} does not list esp-hw-offload; strongSwan will never "
        f"offer it an SA. Features seen: {sorted(features)}")
    assert features["esp-hw-offload"].startswith("on"), features["esp-hw-offload"]


@pytest.mark.usefixtures("splat_window")
async def test_packet_offload_sa_install(aiohttp_session, target_agent):
    # An outbound SA is not describable without egress framing, so the bench
    # has to supply what a real tunnel would have had from its IKE exchange:
    #
    #   - the local endpoint as an address on the CDX port, because that is
    #     what resolves the SA to an interface (dpa_get_iface_info_by_ipaddress
    #     matches sa->id.saddr for an outbound SA), and
    #   - a route and a resolved neighbour for the peer, because what leaves
    #     SEC is a finished frame and the destination MAC is written into the
    #     SA at install time rather than per packet.
    #
    # The neighbour is permanent and the peer does not exist: nothing is sent
    # here, and inventing a lladdr keeps this a control-plane test rather than
    # a two-host one.
    setup = [
        ["ip", "address", "replace", f"{LOCAL}/32", "dev", TARGET_WAN_IF],
        ["ip", "route", "replace", f"{PEER}/32", "dev", TARGET_WAN_IF],
        ["ip", "neigh", "replace", PEER, "lladdr", "02:00:00:00:86:02",
         "dev", TARGET_WAN_IF, "nud", "permanent"],
    ]
    teardown = [
        ["ip", "neigh", "del", PEER, "dev", TARGET_WAN_IF],
        ["ip", "route", "del", f"{PEER}/32", "dev", TARGET_WAN_IF],
        ["ip", "address", "del", f"{LOCAL}/32", "dev", TARGET_WAN_IF],
    ]
    add = [
        "ip", "xfrm", "state", "add",
        "src", LOCAL, "dst", PEER,
        "proto", "esp", "spi", SPI, "reqid", REQID, "mode", "tunnel",
        *AEAD,
        "offload", "packet", "dev", TARGET_WAN_IF, "dir", "out",
    ]
    delete = [
        "ip", "xfrm", "state", "delete",
        "src", LOCAL, "dst", PEER, "proto", "esp", "spi", SPI,
    ]
    # Leave nothing behind for the next test even if an assertion below trips.
    await _run(aiohttp_session, target_agent, *delete, expect_rc=None)
    for argv in setup:
        await _run(aiohttp_session, target_agent, *argv)
    try:
        result = await _run(aiohttp_session, target_agent, *add, expect_rc=None)
        # Two gates gave -EINVAL before this increment, and the order matters
        # when reading a failure here. "Type doesn't support offload" is
        # x->type_offload being NULL, which means the ESP offload module is
        # not built in; anything else is xfrm_dev_state_add() finding no
        # xfrmdev_ops on the device. Both are refusals before the driver runs.
        assert result["rc"] == 0, (
            f"packet-offload SA refused: {result}")

        shown = await _run(aiohttp_session, target_agent,
                           "ip", "-d", "xfrm", "state", "get",
                           "src", LOCAL, "dst", PEER, "proto", "esp", "spi", SPI)
        out = shown["stdout"]
        assert "crypto offload parameters" in out, out
        assert TARGET_WAN_IF in out, out
        assert "packet" in out, out
    finally:
        await _run(aiohttp_session, target_agent, *delete, expect_rc=None)
        for argv in teardown:
            await _run(aiohttp_session, target_agent, *argv, expect_rc=None)


UNLINK_FAULT = "/sys/module/cdx/parameters/ehash_fail_unlink"
# Which inbound SA's classifier delete fails before its unlink, by the value of
# ASK_FLOWTABLE_TERMINAL: bare ESP keys its entry on the SPI; NAT-T keys it on
# the UDP pair and picks the SA by SPI inside it.
TERMINAL = {"ipsec-unlink": None, "ipsec-natt-unlink": (4500, 4500)}
TERMINAL_LOCAL = "198.18.91.1"
TERMINAL_PEER = "198.18.91.2"
TERMINAL_PEER_MAC = "02:00:00:00:91:02"
TERMINAL_SPI = 0x4d6f6e70
TERMINAL_REQID = 49101


@pytest.mark.skipif(os.environ.get("ASK_FLOWTABLE_TERMINAL") not in TERMINAL,
                    reason="explicit terminal lifecycle test; fresh boot required")
async def test_packet_offload_sa_unproven_delete_is_terminal(aiohttp_session, target_agent):
    """An SA delete that cannot prove its entry unlinked fail-stops the
    datapath and keeps the SA's FQIDs.

    The entry enqueues to the SA's TO_SEC FQID. If it may still be linked, the
    queues can go -- an out-of-service FQ rejects the enqueue -- but the FQIDs
    cannot: a later SA or any other queue given them would be fed frames it
    was never admitted for. So the delete must latch terminal failure, stop
    the ports, and the release that follows must hold the FQIDs rather than
    return them.

    Terminal: the ports stop and take the management path with them, so the
    delete and every read after it go over the UART and nothing is restored;
    the reset the DUT then demands is the restoration."""
    natt = TERMINAL[os.environ["ASK_FLOWTABLE_TERMINAL"]]
    await stop_boot_daemon()
    initial = status_text(await read(target_agent, aiohttp_session, "/proc/cdx_flowtable"))
    assert initial["fatal"] == 0, initial
    # No unicast binding: its invalidation pass also drives recovery, and would
    # stop the ports even if the IPsec latch never did.
    assert initial["bindings"] == initial["entries"] == 0, initial
    present = await target_agent.fs_read(aiohttp_session, UNLINK_FAULT)
    if present["errno"]:
        pytest.fail(f"{UNLINK_FAULT} is missing: this is not the fault-injection test image")

    ifindex = await iface_index(target_agent, aiohttp_session, TARGET_WAN_IF)
    await endpoints_up(target_agent, aiohttp_session, iface=TARGET_WAN_IF,
                       local=TERMINAL_LOCAL, peer=TERMINAL_PEER, lladdr=TERMINAL_PEER_MAC)
    reply = await sa_add(target_agent, aiohttp_session, src=TERMINAL_PEER, dst=TERMINAL_LOCAL,
                         spi=TERMINAL_SPI, reqid=TERMINAL_REQID, ifindex=ifindex, inbound=True,
                         natt=natt)
    assert reply.ok, reply
    installed = status_text(await read(target_agent, aiohttp_session, "/proc/cdx_flowtable"))
    assert installed["ipsec_sas"] == initial["ipsec_sas"] + 1, installed

    # The release's printk lands after the delete returns, inside whichever
    # console read runs then. dmesg keeps every line for the assertions below.
    await command(target_agent, aiohttp_session, "sysctl", "-w", "kernel.printk=1 4 1 7")
    con = Console.target(log_path=str(ARTIFACTS / "ipsec-terminal-uart.log"))
    try:
        await asyncio.to_thread(con.login, "root", None)
        assert json.loads((await console_python(con, RX_PORTS_SCRIPT))["stdout"]) == {"6": 1, "7": 1}
        # Armed over the agent while it still reaches the DUT; the delete that
        # consumes it goes over the console, since the ports may stop before
        # an agent reply could leave.
        result = await target_agent.fs_write(aiohttp_session, UNLINK_FAULT, "1")
        assert result["errno"] == 0, result
        await console_command(con, "ip", "xfrm", "state", "delete", "src", TERMINAL_PEER,
                              "dst", TERMINAL_LOCAL, "proto", "esp", "spi", hex(TERMINAL_SPI))
        deadline = time.monotonic() + 15
        while True:
            stopped = status_text((await console_command(con, "cat", "/proc/cdx_flowtable"))["stdout"].strip())
            ports = json.loads((await console_python(con, RX_PORTS_SCRIPT))["stdout"])
            if stopped["fatal"] == 1 and ports == {"6": 0, "7": 0}:
                break
            assert time.monotonic() < deadline, (stopped, ports)
            await asyncio.sleep(0.2)
        assert stopped["ipsec_sas"] == initial["ipsec_sas"], stopped
        knob = (await console_command(con, "cat", UNLINK_FAULT))["stdout"].strip()
        assert knob == "0", knob
        # The queues retire on a one-second timer before the release that
        # would return the FQIDs; it has to have run to have held them.
        # Counted on the DUT: the whole KASAN boot log is slow at 115200 baud.
        held = "held until reset: a classifier entry may still name them"
        deadline = time.monotonic() + 45
        while True:
            count = (await console_command(con, "sh", "-c", f"dmesg | grep -c '{held}' || true"))["stdout"]
            if count.strip() != "0":
                break
            assert time.monotonic() < deadline, "the SA's release never ran"
            await asyncio.sleep(1)
        log = (await console_command(con, "dmesg"))["stdout"]
        assert log.count("unable to remove entry from hash table") == 1, log
        assert log.count(held) == 1, log
        assert "hardware stopped after unproven deletion; reboot required" in log, log
        assert "BUG: KASAN" not in log, log
    finally:
        con.close()
