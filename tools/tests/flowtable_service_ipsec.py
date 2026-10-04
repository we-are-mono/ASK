"""IPsec prerequisite and allocation recovery through the shipping service.

XFRM owns SAs; restoring a withdrawn SA models the configuration/IKE owner.
The flowtable service must recover existing sockets without any flow repair.
All policies remain required while an SA is absent, including on the peer.
"""
from __future__ import annotations

from _flowtable_service_ipsec import (INNER, LAN_INNER, Wire, flows_for, hardware, ipsec_shared_sequence, negative, plaintext_probe)

import asyncio
import time

import pytest

from _topology import TARGET_WAN_IF
from _flowtable_connections import (by_key, consistent, peer)
from _flowtable_failslab import (same_service, slab_fault)
from _flowtable_rig import (DPORT, command, read)
from _flowtable_selective_neighbour import (keys, unchanged, warm)
from _flowtable_service import FIRST, supervision_status
from _flowtable_service_vlan import attempts, balanced, received

# Linux's UDP_ENCAP socket option and its ESP-in-UDP mode (linux/udp.h).


# What the fixture lowers the DUT's net.core.xfrm_acq_expires to while it
# runs, so a placeholder a test's traffic left is gone within seconds rather
# than lingering into the next module's setup.


@pytest.mark.parametrize("direction", ["out", "in"])
@pytest.mark.parametrize("allocation_failure", [False, True], ids=["withdrawal", "failslab"])
async def test_sa_recovery(ipsec_service, direction, allocation_failure):
    r, flows = ipsec_service, flows_for(ipsec_service)
    service, policies = await supervision_status(r), await r.ipsec.policies()
    capture = Wire(r, "ipsec-sa-wire")
    capture.filter = "ip proto 50"
    # Observe before opening sockets so capture setup cannot hide an
    # admission race by delaying their first exchanges.
    async with capture, peer(r, flows, initial_ids=[0, 1, 2, 3, 5, 6], lease=400,
                             listen_addresses=[INNER]) as p:
        try:
            await warm(r, p, [0, 1, 2, 3], "ipsec-baseline", flows[:4])
        except BaseException:
            r.record("ipsec-baseline-failure", {
                "backend": await r.state(), "states": await r.ipsec.states(),
                "policies": await r.ipsec.policies(),
                "xfrm_stats": await read(r.target, r.session, "/proc/net/xfrm_stat"),
                "sec_stats": (await command(r.target, r.session, "ethtool", "-S", TARGET_WAN_IF))["stdout"],
            })
            raise
        initial = await hardware(r, p, "ipsec-baseline-hardware", flows[:4])
        await plaintext_probe(r, p, 'ipsec-baseline-plaintext')
        initial_attempts = await attempts(r)
        for cycle in range(1 if allocation_failure else 2):
            label = f"ipsec-{direction}-{'slab' if allocation_failure else 'withdraw'}-{cycle}"
            await negative(r, p)
            before = await r.state()
            # New SPI avoids resetting the anti-replay sequence on a reused SA.
            spi = await r.ipsec.prepare_peer(direction)
            await p.rpc("start", [2], count=0, interval=0.05, allow_loss=True)
            await p.rpc("start", [3], count=0, interval=0.05)
            started = time.monotonic()
            old_spi = await r.ipsec.remove(direction)
            try:
                retired = await r.wait(lambda s: by_key(s).keys() == keys([0, 1], flows), timeout=5)
                retire_seconds = time.monotonic() - started
                assert retire_seconds < 5
                unchanged(initial, retired, [0, 1], flows)
                assert retired["ipsec_invalidations"] == before["ipsec_invalidations"] + 2, (before, retired)
                await asyncio.sleep(0.2)
                stopped, wan_before = await p.rpc("status"), received(r, 2)
                await plaintext_probe(r, p, label + '-plaintext')
                async with Wire(r, label + "-unavailable") as wire:
                    held = time.monotonic()
                    while time.monotonic() - held < 6:
                        await p.batch([0, 1], count=32, interval=0.01)
                        progress = await p.rpc("status")
                        assert not progress["errors"], progress
                        assert all(progress["received"][str(i)] == stopped["received"][str(i)] for i in (2, 3)), progress
                        state = await r.state()
                        r.record(label + '-held', {'state': state, 'progress': progress})
                        unchanged(initial, state, [0, 1], flows)
                        assert by_key(state).keys() == keys([0, 1], flows), state
                assert await r.ipsec.policies() == policies
                assert len(await r.ipsec.states()) == 1
                assert await attempts(r) == initial_attempts
                if direction == "out":
                    assert received(r, 2) == wan_before, "required outbound policy failed open"
                r.record(label + "-absent", {"state": retired, "seconds": retire_seconds, "wire": wire.check()})
                if allocation_failure:
                    async with slab_fault(r, "ipsec-context", label,
                                          keep_alive=(p, [0, 1])) as fault:
                        refused = await r.ipsec.install(direction, spi, check=False)
                        assert refused["rc"] != 0, refused
                        hit = await fault.hit()
                        assert len(await r.ipsec.states()) == 1
                        await p.batch([0, 1], count=32, interval=0.01)
                        r.record(label + "-refused", {"result": refused, "hit": hit})
            finally:
                await r.ipsec.install(direction, spi)
                await command(r.ipsec.wan, r.session, "ip", "xfrm", "state", "delete", *r.ipsec.state(direction, old_spi))
            restored = time.monotonic()
            while True:
                await p.batch([0, 1], count=32, interval=0.01)
                progress = await p.rpc("status")
                assert not progress["errors"], progress
                if progress["received"]["2"] >= stopped["received"]["2"] + 16 and progress["received"]["3"] > stopped["received"]["3"]:
                    break
                assert time.monotonic() - restored < 25, progress
            transfers = await p.rpc("stop", [2, 3])
            assert transfers["2"]["lost"] > 0 and transfers["3"]["lost"] == 0, transfers
            await warm(r, p, [0, 1, 2, 3], label + "-readmitted", flows[:4])
            ready_seconds = time.monotonic() - restored
            assert ready_seconds < 25
            after = await hardware(r, p, label + "-hardware", flows[:4])
            hardware_seconds = time.monotonic() - restored
            assert hardware_seconds < 45
            balanced(after, initial["errors"])
            unchanged(initial, after, [0, 1], flows)
            assert after["rearms"] == initial["rearms"]
            assert (after["installs"], after["deletes"]) == (before["installs"] + 4, before["deletes"] + 4)
            # The hardware proof's identities held for its whole burst, longer
            # than a health-check period: nothing reapplied the policy since.
            assert await attempts(r) == initial_attempts
            await same_service(r, service)
            r.record(label + "-recovery", {"ready_seconds": ready_seconds, "hardware_seconds": hardware_seconds,
                "before": before, "after": after, "transfers": transfers})
        await p.rpc("open", [4])
        await warm(r, p, [0, 1, 2, 3, 4], "ipsec-new-connection", flows[:5])
        await hardware(r, p, "ipsec-new-hardware", flows[:5])
        await negative(r, p)


async def test_admission_churn(ipsec_service):
    """Repeatedly cross software/SEC and hardware admission with exact delivery."""
    r, flows = ipsec_service, flows_for(ipsec_service)
    service, initial_attempts = await supervision_status(r), await attempts(r)
    capture = Wire(r, "ipsec-admission-churn")
    capture.filter = "ip proto 50"
    # Start capture before opening sockets so observation adds no settling
    # delay between the first connections and their initial exchanges.
    async with capture, peer(r, flows, initial_ids=[0, 1, 2, 3, 5, 6], lease=400,
                             listen_addresses=[INNER]) as p:
        try:
            await warm(r, p, [0, 1, 2, 3], "admission-churn-baseline", flows[:4])
            initial = await hardware(r, p, "admission-churn-baseline-hardware", flows[:4])
            for cycle in range(24):
                before = await r.state()
                await p.rpc("close", [2])
                await command(r.target, r.session, "conntrack", "-D", "-f", "ipv4", "-p", "udp",
                              "--orig-src", LAN_INNER, "--orig-dst", INNER,
                              "--sport", str(FIRST), "--dport", str(DPORT))
                retired = await r.wait(lambda s: consistent(s) and not (by_key(s).keys() & keys([2], flows)),
                                       timeout=5)
                unchanged(initial, retired, [0, 1, 3], flows)
                await p.rpc("open", [2])
                await warm(r, p, [0, 1, 2, 3], f"admission-churn-{cycle}", flows[:4])
                admitted = await r.state()
                reports = await p.batch([0, 1, 2, 3], count=32, interval=0.01)
                after = await r.state()
                unchanged(admitted, after, [0, 1, 2, 3], flows)
                unchanged(initial, after, [0, 1, 3], flows)
                old, new = by_key(admitted), by_key(after)
                for key in keys([2], flows):
                    assert int(new[key]["packets"]) - int(old[key]["packets"]) >= 32, (key, old[key], new[key])
                assert (after["installs"], after["deletes"]) == (before["installs"] + 2, before["deletes"] + 2)
                balanced(after, initial["errors"])
                assert after["rearms"] == initial["rearms"]
                r.record(f"admission-churn-{cycle}-verified", {"before": before, "after": after,
                                                             "reports": reports})
            await hardware(r, p, "admission-churn-final-hardware", flows[:4])
            await plaintext_probe(r, p, "admission-churn-plaintext")
            await negative(r, p)
            assert await attempts(r) == initial_attempts
            await same_service(r, service)
        except BaseException:
            r.record("admission-churn-failure", {
                "backend": await r.state(), "states": await r.ipsec.states(),
                "policies": await r.ipsec.policies(), "wan_udp_received": received(r, 2),
                "xfrm_stats": await read(r.target, r.session, "/proc/net/xfrm_stat"),
                "sec_stats": (await command(r.target, r.session, "ethtool", "-S", TARGET_WAN_IF))["stdout"],
            })
            raise


async def test_shared_sequence(ipsec_service):
    await ipsec_shared_sequence(ipsec_service)
