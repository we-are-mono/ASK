"""TCP through an offloaded SA at the rate the WAN host's software IPsec
sustains, uploads encrypted by SEC and downloads decrypted by it, for both
transform families the adapter offloads.

The WAN host is the ceiling here, not the DUT: four streams through one SA
moved 2.46 Gbit/s with AES-GCM and 2.34-2.44 with AES-CBC and HMAC-SHA256
(docs/flowtable/ipsec.md), and this case's samples ranged 2.29-2.54 Gbit/s
over both families and directions. An offload that installs but excepts every
frame to the CPU ran at 0.07 Gb/s on the same bench, so the floor separates
the two by a wide margin. Every stream and its acknowledgements are on a hardware
entry naming the SA during the measured window, and the software path hands
SEC next to nothing (`tx toenc`, `tx todec`). The far end's async crypto can
reorder its ESP past the SA's replay window, and SEC refuses those frames as
late, which can stall one stream for a while (A342); the streams' entries
must therefore move together rather than each on its own.
"""
import asyncio
import os
import re
from pathlib import Path

import pytest

from _flowtable_rig import WAN_IP, command, console_command, read
from _flowtable_service import CONF, INIT, service_status, wait_service
from _flowtable_service_ipsec import INNER, LAN_INNER, Transform
from _flowtable_service_ipsec_replay import AEAD, peer_errors, xfrm_mib
from _ipsec_inbound_flow_offload import sec_counter
from _throughput import tcp_floor
from _topology import TARGET_LAN_IF, TARGET_WAN_IF

PORT = 48994
MIN_RATE = float(os.environ.get("ASK_IPSEC_MIN_GBPS", "2")) * 1e9
# The frames the software path gives SEC in a window: a stream's segment
# that reaches Linux before its entry does, never its bulk.
SOFTWARE_SEC = 64


@pytest.mark.parametrize("upload", [True, False], ids=["upload", "download"])
@pytest.mark.parametrize("ipsec_service", [Transform(), AEAD["rfc4106-icv16"]],
                         ids=["cbc-sha256", "gcm-128"], indirect=True)
async def test_rate(ipsec_service, upload):
    r = ipsec_service
    # The normal 1500-byte links rather than the fixture's 1200/1400-byte
    # exception routes, which the fixture deletes.
    for address, gateway, dev in ((INNER, WAN_IP, TARGET_WAN_IF), (LAN_INNER, r.lan_ip, TARGET_LAN_IF)):
        await command(r.target, r.session, "ip", "route", "replace", address + "/32",
                      "via", gateway, "dev", dev, "mtu", "1500")
    nat = ["POSTROUTING", "-s", LAN_INNER, "-d", INNER, "-p", "tcp",
           "--dport", str(PORT), "-j", "ACCEPT"]
    await command(r.target, r.session, "iptables", "-t", "nat", "-I", *nat)
    try:
        config = await read(r.target, r.session, CONF)
        result = await r.target.fs_write(r.session, CONF, config +
                                         f"scope saddr {LAN_INNER} daddr {INNER} dport {PORT}\n")
        assert result["errno"] == 0, result
        previous = (await service_status(r))["policy_hash"]
        await console_command(r.service_console, INIT, "reload", timeout=45)
        # The reload replaces the table; streams launched before the new one
        # is bound would start in software.
        for _ in range(100):
            status = await service_status(r)
            if status["policy_hash"] != previous:
                break
            await asyncio.sleep(0.2)
        assert status["policy_hash"] != previous, status
        await wait_service(r, policy_hash=status["policy_hash"])

        def through_sa(data, acks):
            # Encrypted on the way out of the WAN port, decrypted on the way
            # in, for the data and its acknowledgements alike.
            for row in data + acks:
                field = "sa" if row["in"] == TARGET_LAN_IF else "in_sa"
                assert row[field] != "0", row

        async def software_sec():
            return {name: await sec_counter(r.session, r.target, TARGET_WAN_IF, name)
                    for name in ("tx toenc", "tx todec")}

        def offloaded(delta):
            assert 0 <= delta["tx toenc"] <= SOFTWARE_SEC and delta["tx todec"] == 0, delta

        peer_before = xfrm_mib(Path("/proc/net/xfrm_stat").read_text())
        await tcp_floor(r, server=INNER, client=LAN_INNER, port=PORT, upload=upload,
                        floor=MIN_RATE, check=through_sa, each=False,
                        counters=software_sec, within=offloaded,
                        label=f"ipsec-rate-{'upload' if upload else 'download'}")
        # The peer's own SA says whether the DUT's ESP was good: no integrity
        # failure, no replay. Its MIB also counts its software crypto
        # shedding load at this rate, which is the peer's limit.
        peer_sa = (await command(r.ipsec.wan, r.session, "ip", "-s", "xfrm", "state", "get",
                                 *r.ipsec.state("out", r.ipsec.active["out"])))["stdout"]
        errors = peer_errors(peer_before)
        r.record("ipsec-rate-peer", {"sa": peer_sa, "errors": errors})
        stats = re.search(r"stats:\s*replay-window \d+ replay (\d+) failed (\d+)", peer_sa)
        assert stats and stats.groups() == ("0", "0"), peer_sa
        shed = {"XfrmInStateProtoError", "XfrmInError", "XfrmOutStateProtoError"}
        assert not {k: v for k, v in errors.items() if k not in shed}, errors
    finally:
        await command(r.target, r.session, "conntrack", "-D", "-p", "tcp",
                      "--orig-src", LAN_INNER, "--orig-dst", INNER, "--dport", str(PORT),
                      check=False)
        await command(r.target, r.session, "iptables", "-t", "nat", "-D", *nat)
