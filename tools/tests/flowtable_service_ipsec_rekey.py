"""SA provenance across legitimate inbound and outbound rekey overlap."""
from __future__ import annotations

import asyncio
import hashlib
import secrets

import pytest

from _flowtable_connections import (by_key, healthy, peer)
from _flowtable_rig import (command, none_missed)
from _flowtable_selective_neighbour import (warm)
from _flowtable_service_ipsec import (INNER, Transform, flows_for, hardware, offline_port_discards)
from _flowtable_service_ipsec_provenance import (COUNT, KEY, inject)
from _flowtable_service_ipsec_replay import (AEAD, sa_state)

NATT = (4500, 31000)


@pytest.mark.parametrize("ipsec_service", [Transform(), AEAD["rfc4106-icv16"]],
                         ids=["cbc", "gcm"], indirect=True)
async def test_ipsec_inbound_rekey_collision(ipsec_service):
    """Both authorized SAs deliver the identical tuple; only the bound SA
    uses hardware, and the other must pass Linux's own policy check."""
    r, flows = ipsec_service, flows_for(ipsec_service)
    async with peer(r, flows, initial_ids=[0, 1, 2, 3], lease=300,
                    listen_addresses=[INNER]) as p:
        await warm(r, p, [0, 1, 2, 3], "overlap-baseline", flows[:4])
        await hardware(r, p, "overlap-baseline-hardware", flows[:4])
        await p.rpc("close", [1, 3])
        old_spi = r.ipsec.active["in"]
        new_spi = 0xB2800000 | secrets.randbits(16)
        await r.ipsec.install("in", new_spi)
        baseline = by_key(await r.state())[KEY]
        marker = b"ASK-SA-OVERLAP-" + secrets.token_bytes(8)
        old = await inject(r, p, old_spi, marker + b"old")
        assert old["wire"]["received"] == COUNT and old["software_forwarded"] == 0, old
        new = await inject(r, p, new_spi, marker + b"new")
        assert new["wire"]["received"] == COUNT, new
        assert new["software_forwarded"] == COUNT, new
        first, last = by_key(new["before"])[KEY], by_key(new["after"])[KEY]
        assert first["cookie"] == last["cookie"] == baseline["cookie"], new
        # FMan counts tuple hits before VLAN validation, including exceptions.
        # Linux's forwarding counter proves all new-SA frames took its check.
        healthy(new["after"])
        # Deleting the bound SA retires its flow, while the overlapping SA
        # remains able to deliver its next packet through the CPU.
        await command(r.target, r.session, "ip", "xfrm", "state", "delete",
                      *r.ipsec.state("in", old_spi))
        await r.wait(lambda s: KEY not in by_key(s))
        alive = await inject(r, p, new_spi, marker + b"survivor", seq=100000 + COUNT)
        assert alive["wire"]["received"] == COUNT, alive
        healthy(alive["after"])


@pytest.mark.parametrize("ipsec_service", [Transform(encap=(4500, 31000)),
                         Transform(AEAD["rfc4106-icv16"].algorithms, (4500, 31000))],
                         ids=["cbc", "gcm"], indirect=True)
async def test_ipsec_outbound_natt_rekey_root(ipsec_service):
    """Old and new SEC descriptors share one UDP output root. Retiring the
    first descriptor must keep that root's tag valid for the surviving SA."""
    r, flows = ipsec_service, flows_for(ipsec_service)
    async with peer(r, flows, initial_ids=[0, 1, 2, 3], lease=300,
                    listen_addresses=[INNER]) as p:
        await warm(r, p, [0, 1, 2, 3], "natt-overlap-baseline", flows[:4])
        await hardware(r, p, "natt-overlap-baseline-hardware", flows[:4])
        old_spi = r.ipsec.active["out"]
        new_spi = await r.ipsec.prepare_peer("out")
        await r.ipsec.install("out", new_spi)
        # Existing flows keep the old SA. A fresh socket resolves the new
        # one, so traffic exercises both descriptors while the root is shared.
        await p.rpc("open", [4])
        await warm(r, p, [0, 1, 2, 3, 4], "natt-overlap-both", flows[:5])
        before = {spi: await sa_state(r, spi) for spi in (old_spi, new_spi)}
        await p.batch([2, 3, 4], count=256, interval=0.03125)
        await asyncio.sleep(1.5)
        after = {spi: await sa_state(r, spi) for spi in (old_spi, new_spi)}
        r.record("natt-overlap-sas", {"before": before, "after": after, "state": await r.state()})
        assert all(after[spi]["packets"] > before[spi]["packets"] for spi in before), (before, after)
        await command(r.target, r.session, "ip", "xfrm", "state", "delete",
                      *r.ipsec.state("out", old_spi))
        # Wait for the old descriptor's deferred queue/tag release too.
        await asyncio.sleep(2)
        await warm(r, p, [0, 1, 2, 3, 4], "natt-overlap-survivor", flows[:5])
        await hardware(r, p, "natt-overlap-survivor-hardware", flows[:5])
        healthy(await r.state())


def key(name, size):
    """A key of `size` bytes no other transform here shares, derived so a
    failure reruns with the same keys (and a 3DES key whose thirds differ)."""
    return "0x" + hashlib.shake_256(name.encode()).hexdigest(size)


# What a decrypted frame's last output word holds depends on the cipher's
# block and the ICV that trail the payload, so each family SEC runs is
# loaded here: AES-CBC with the HMAC lengths it pairs with, the counter
# modes, and 3DES's 8-byte block.
OVERLAP_TRANSFORMS = {
    "cbc-sha256": Transform(encap=NATT),
    "gcm": Transform(AEAD["rfc4106-icv16"].algorithms, NATT),
    "cbc-sha1": Transform(("enc", "cbc(aes)", key("cbc-sha1/enc", 16),
                           "auth-trunc", "hmac(sha1)", key("cbc-sha1/auth", 20), "96"), NATT),
    "cbc-sha512": Transform(("enc", "cbc(aes)", key("cbc-sha512/enc", 32),
                             "auth-trunc", "hmac(sha512)", key("cbc-sha512/auth", 64), "256"), NATT),
    "ctr-sha256": Transform(("enc", "rfc3686(ctr(aes))", key("ctr/enc", 20),
                             "auth-trunc", "hmac(sha256)", key("ctr/auth", 32), "128"), NATT),
    "ccm-icv16": Transform(("aead", "rfc4309(ccm(aes))", key("ccm", 19), "128"), NATT),
    "3des-sha1": Transform(("enc", "cbc(des3_ede)", key("3des/enc", 24),
                            "auth-trunc", "hmac(sha1)", key("3des/auth", 20), "96"), NATT),
}


@pytest.mark.parametrize("ipsec_service", list(OVERLAP_TRANSFORMS.values()),
                         ids=list(OVERLAP_TRANSFORMS), indirect=True)
async def test_ipsec_decrypted_frames_intact_under_overlap(ipsec_service):
    """SEC writes every decrypted frame whole while both rekey descriptors
    encrypt; SEC's own refusals are the only discards the offline port may
    make (offline_port_discards()). The records arrive back to back at line
    rate on both ports, which neither MAC may drop for want of room in its
    FIFO (none_missed())."""
    r, flows = ipsec_service, flows_for(ipsec_service)
    async with peer(r, flows, initial_ids=[0, 1, 2, 3], lease=400, listen_addresses=[INNER],
                    tcp_size=131072) as p, none_missed(r, "overlap-intact-missed"):
        await warm(r, p, [0, 1, 2, 3], "overlap-intact-baseline", flows[:4])
        await r.ipsec.install("out", await r.ipsec.prepare_peer("out"))
        await p.rpc("open", [4])
        await warm(r, p, [0, 1, 2, 3, 4], "overlap-intact-both", flows[:5])
        async with offline_port_discards(r, "overlap-intact-discards"):
            # Two streams of 128 KB records beside a UDP flow: the decrypted
            # ACKs keep both outbound descriptors and the inbound one busy.
            for _ in range(8):
                await p.batch([2, 3, 4], count=256, interval=0.01)
