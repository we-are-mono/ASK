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

import os

import pytest

from _topology import TARGET_WAN_IF

# Ownership is exclusive and fixed for the boot: in a CMM boot the adapter is
# never loaded, so the ports advertise no esp-hw-offload and there is no
# /proc/cdx_flowtable to read. These assert the flowtable owner's behaviour and
# have nothing to talk to otherwise, so they take the same opt-in gate the
# test_flowtable_* files do rather than failing a legacy run.
pytestmark = pytest.mark.skipif(os.environ.get("ASK_FLOWTABLE_TESTS") != "1",
                                reason="requires an explicit flowtable boot")

# Documentation-range addresses (RFC 2544 benchmarking block), distinct from
# the ones test_ipsec_esp_traffic.py uses so the two can run in either order.
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
