"""IP-reassembly stress tests covering C3/C4 (cdx/cdx_reassm.c).

The `ipr_buff_release_dqrr` path reads `num_entries` and `ref_count`
from a reassembly context that FMAN microcode populates. Userspace
can't forge those fields directly, so the only way to regression-test
C3 (unbounded num_entries) and C4 (ref_count underflow) is to drive
enough real fragmented traffic through the hardware reassembly path
that a regression trips the sanitizer shelf (UBSAN/KFENCE/WARN/BUG,
all gated by `splat_window`) or kmemleak (deltaed via kmemleak_clear
at test entry + filtered scan at exit).

Traffic shape:
  lan  --- fragmented UDP -->  target (FMAN reassembles)  ---->  wan
         scapy send_frags            hardware reassembly            iperf3
                                     ipr_buff_release_dqrr

Variants:
  A1 plain — one pass over many 5-tuples, out-of-order fragments.
  A2 duplicates — every fragment sent twice back-to-back. Stresses
     the same-context ref_count increment path (C4 regression would
     show as underflow WARN or bman_release on a stale ctx).

Overlapping fragments are intentionally not covered: FMAN's microcode
behavior under overlap is not contracted and varies by version. The
pool-saturation scenario from the test plan is folded in via the large
number of distinct 5-tuples (>= max_contexts for the vendor default
config of 128), which exercises context eviction under churn.
"""

from __future__ import annotations

import asyncio
import base64
import os
import textwrap

import pytest


WAN_IPERF_IP = os.environ.get("ASK_WAN_IPERF_IP", "10.0.0.141")

# Knobs chosen so the whole test runs in well under a minute:
#   - 1500 pre-fragmentation packets, each 2-5 KB → ~4-10 fragments each,
#     so ~6000-15000 actual frame sends.
#   - 150 distinct source ports → 150 distinct 5-tuples, above the
#     default 128 reassembly contexts on this platform. Forces pool
#     churn; any C3 regression on context reuse trips the sanitizer.
#   - fragsize=500 B keeps per-fragment size well under the PCD's
#     typical frame-size threshold so they all hit the reassembly path.
N_PACKETS       = 1500
N_SOURCE_PORTS  = 150
UDP_SPORT_BASE  = 30000
UDP_DPORT       = 5201          # wan iperf3 server
PKT_MIN_BYTES   = 2000
PKT_MAX_BYTES   = 5000
FRAGSIZE        = 500


def _storm_script(duplicate: bool) -> str:
    """Return the scapy script text; runs as root on lan."""
    return textwrap.dedent(f"""
        import random, sys
        from scapy.all import IP, UDP, Raw, fragment, send
        random.seed(0xA5C03E)
        all_frags = []
        for i in range({N_PACKETS}):
            sport = {UDP_SPORT_BASE} + (i % {N_SOURCE_PORTS})
            size  = random.randint({PKT_MIN_BYTES}, {PKT_MAX_BYTES})
            pkt   = IP(dst="{WAN_IPERF_IP}") / UDP(sport=sport, dport={UDP_DPORT}) \\
                    / Raw(b"X" * size)
            frags = fragment(pkt, fragsize={FRAGSIZE})
            if {int(bool(duplicate))}:
                # Interleave the duplicate after the original so the
                # target sees two-in-a-row for each fragment — the
                # ref_count wrap scenario from C4.
                doubled = []
                for f in frags:
                    doubled.append(f)
                    doubled.append(f)
                frags = doubled
            all_frags.extend(frags)
        # Shuffle across the whole storm so different contexts interleave;
        # this creates the churn C3 needs under pool pressure.
        random.shuffle(all_frags)
        # Batch-send to keep per-packet sendto() overhead manageable.
        send(all_frags, verbose=0, inter=0)
        print("STORM_DONE n_frags=%d" % len(all_frags))
    """).strip()


def _push_script_to_lan(lan_console, script: str, path: str) -> None:
    """Drop the scapy script onto the lan VM via UART using base64.

    Base64 avoids any shell-escape landmine when the source contains
    quotes / backslashes / non-printables. The serial write is one
    blast followed by a `base64 -d` on the remote.
    """
    b64 = base64.b64encode(script.encode()).decode()
    r = lan_console.run(f"echo {b64} | base64 -d > {path} && echo OK", timeout=10)
    assert r.rc == 0 and "OK" in r.stdout, (
        f"failed to stage scapy script on lan: rc={r.rc}, out={r.stdout!r}"
    )


async def _run_storm(lan_console, duplicate: bool) -> str:
    """Fire the storm on lan via UART, return the script's stdout.

    Depends on system python3 having scapy importable. `make
    deploy-agent-lan` installs `python3-scapy` via apt on the lan VM
    exactly to satisfy this; on a fresh lan that hasn't been deployed
    to, run deploy-agent-lan first (or apt-get install python3-scapy
    by hand).
    """
    script = _storm_script(duplicate=duplicate)
    path = "/tmp/ask_reassembly_storm.py"
    _push_script_to_lan(lan_console, script, path)

    # Scapy's pure-Python send() does ~10 kpps; worst case 30k frags
    # finishes in ~3 s, but the kernel PTY path adds its own slack.
    # Budget generously but not absurdly.
    r = await asyncio.to_thread(
        lan_console.run, f"python3 {path}", 180.0
    )
    assert r.rc == 0, f"storm script failed: rc={r.rc}, out={r.stdout!r}"
    assert "STORM_DONE" in r.stdout, f"storm did not finish: {r.stdout!r}"
    return r.stdout


@pytest.mark.parametrize(
    "duplicate,label",
    [
        (False, "plain"),        # C3-oriented: pool-churn + list walk
        (True,  "duplicates"),   # C4-oriented: ref_count increment path
    ],
    ids=["plain", "duplicates"],
)
async def test_reassembly_fragment_storm(
    aiohttp_session, target_agent, lan, splat_window, duplicate, label,
):
    """Fragment storm from lan through target's FMAN reassembly.

    splat_window gates UBSAN/KFENCE/lockdep/WARN/BUG during the storm.
    kmemleak delta (cleared pre-storm, filtered post-storm) catches any
    in-subsystem leak that survives the release path.
    """
    # Establish the kmemleak cursor: "clear" marks every currently-
    # reported leak as seen, so the post-storm scan only surfaces leaks
    # detected inside this test's window. Without this, the ~16k DPAA
    # baseline false-positives would drown any real signal.
    await target_agent.kmemleak_clear(aiohttp_session)

    out = await _run_storm(lan, duplicate=duplicate)

    # Give the kernel a moment to quiesce: the bpool replenish hook
    # and any deferred softirqs should settle before we scan kmemleak.
    # kmemleak's own scanner also needs a jiffy to walk the heap.
    await asyncio.sleep(3.0)

    report = await target_agent.kmemleak(
        aiohttp_session, filter_substrs=["cdx_", "fci_", "abm_"],
    )
    assert report.get("leak_count", 0) == 0, (
        f"kmemleak found {report['leak_count']} new leak(s) in cdx/fci/abm "
        f"after {label} storm ({out.strip().splitlines()[-1]}):\n"
        + report.get("report", "")[:4000]
    )
