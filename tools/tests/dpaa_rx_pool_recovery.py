"""An empty receive pool fills again by itself, on the same boot (A454).

Every private DPAA port receives into one BMan pool, and only the CPU's own
receive refilled it, once its per-CPU count of what it had taken out ran low.
A buffer the hardware loses leaves that count high (A453), so a pool run dry
by losses stayed dry: every port discarded every frame for want of a buffer
(port_rx_out_of_buffers_discard), no frame reached a CPU to refill it, and
nothing was logged. A gateway stopped receiving that way, and only a reboot
brought it back.

CDX's test knob takes every buffer the pool holds and frees it, unseen by the
driver's count, as a loss does. The driver's pool watch must see the pool dry
while the ports discard, say so once, and fill it again: the DUT answers pings
again within seconds, `ethtool -S` counts the episode and the buffers added,
and at idle the pool holds what the driver counts again.
"""
import asyncio
import re
import time

from _flowtable_rig import command, pings_answered, read
from _topology import TARGET_LAN_IF
from flowtable_wireguard_detour import POOLS, SLACK, ethernet_pool

LEAK = "/sys/module/cdx/parameters/pool_leak"
# The DK's two rig receive ports, eth3 (LAN) and eth4 (WAN), by register block.
RX_DISCARDS = tuple(f"/sys/devices/platform/soc/1a00000.fman/{port}.port/statistics/"
                    "port_rx_out_of_buffers_discard" for port in ("1a90000", "1a91000"))
DRY = "receive pool {} ran dry"
AGAIN = "receive pool {} is receiving again"
# The watch reads the pool once a second and acts on the second dry reading in
# a row; refilling a whole pool of jumbo buffers on the KASAN image takes a
# few seconds more. Far longer than that is a pool nothing refills.
RECOVERY_S = 30


async def discards(r):
    """The rig ports' out-of-buffer discards, summed."""
    total = 0
    for path in RX_DISCARDS:
        total += int(re.findall(r"\d+", await read(r.target, r.session, path))[-1])
    return total


async def pool_stats(r):
    """`ethtool -S`'s pool-wide episode counts, or None where the driver has
    none."""
    out = (await command(r.target, r.session, "ethtool", "-S", TARGET_LAN_IF))["stdout"]
    stats = {}
    for name in ("bp dry episodes", "bp buffers reseeded"):
        found = re.search(rf"^\s*{re.escape(name)}:\s*(\d+)", out, re.M)
        stats[name] = int(found.group(1)) if found else None
    return stats


async def kernel_log(r):
    return (await command(r.target, r.session, "dmesg"))["stdout"]


def count(log, text):
    return sum(text in line for line in log.splitlines())


async def eventually(probe, done, timeout=RECOVERY_S):
    """probe()'s value once done() holds of it, or its last before the
    deadline."""
    deadline = time.monotonic() + timeout
    while True:
        value = await probe()
        if done(value) or time.monotonic() > deadline:
            return value
        await asyncio.sleep(0.5)


async def test_an_empty_receive_pool_fills_again(rig):
    r = rig
    assert await pings_answered(r.dut_wan_ip, 10) >= 9, "the DUT does not answer pings to begin with"
    bpid, lost = await ethernet_pool(r)
    stats = await pool_stats(r)
    log = await kernel_log(r)
    before = await discards(r)

    # The knob reads back what it has taken in all, this boot.
    taken = -int((await read(r.target, r.session, LEAK)).strip())
    result = await r.target.fs_write(r.session, LEAK, "all")
    assert result["errno"] == 0, result
    taken += int((await read(r.target, r.session, LEAK)).strip())
    left = int((await read(r.target, r.session, f"{POOLS}/{bpid}")).strip())
    r.record("leak", {"bpid": bpid, "lost_before": lost, "taken": taken, "left": left, "stats": stats})
    assert taken > 4096, ("the knob took too little to empty the pool", taken, left)

    # Pings to the DUT are what arrives meanwhile: discarded while the pool is
    # dry, answered once it holds buffers again.
    start = time.monotonic()
    answered = 0
    while not answered and time.monotonic() - start < RECOVERY_S:
        answered = await pings_answered(r.dut_wan_ip, 5)
    elapsed = time.monotonic() - start
    state = {"elapsed_s": round(elapsed, 1), "answered": answered,
             "free": int((await read(r.target, r.session, f"{POOLS}/{bpid}")).strip()),
             "discards": await discards(r) - before, "stats": await pool_stats(r)}
    r.record("recovery", state)
    assert answered, f"receive did not come back within {RECOVERY_S} s on the same boot: {state}"
    # The knob had emptied it: the ports discarded for want of a buffer.
    assert state["discards"] > 0, state

    # Said once as the pool ran dry, and once as it received again. Pings
    # come back with the first buffers in; the episode ends at the reading
    # after the whole reseed is, and only then are its counts final.
    said = {text: count(log, text.format(bpid)) for text in (DRY, AGAIN)}

    async def episode_lines():
        now = await kernel_log(r)
        return {text: [line for line in now.splitlines() if text.format(bpid) in line]
                for text in (DRY, AGAIN)}

    lines = await eventually(episode_lines,
                             lambda found: all(len(found[text]) > said[text] for text in found))
    r.record("episode-log", lines)
    for text, found in lines.items():
        assert len(found) == said[text] + 1, lines

    _, lost_after = await ethernet_pool(r, bpid)
    after = await pool_stats(r)
    r.record("settled", {"lost_after": lost_after, "stats": after})
    assert after["bp dry episodes"] == stats["bp dry episodes"] + 1, (stats, after)
    reseeded = after["bp buffers reseeded"] - stats["bp buffers reseeded"]
    assert abs(reseeded - taken) <= SLACK, (taken, reseeded)
    # At idle the pool holds what the driver counts, as it did before.
    assert abs(lost_after - lost) <= SLACK, (lost, lost_after)
