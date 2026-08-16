"""L2-flow table flush correctness.

Toggling /proc/sys/net/abm/abm_l3_filtering between 0 and 1 calls
abm_l2flow_table_flush() (auto_bridge/auto_bridge.c:1532-1540) which
walks every l2flow_table[] bucket and unlinks all entries. This is
the cleanest userspace-driven flush trigger; alternative paths
(BREVENT_PORT_DOWN, abm_max_entries shrink) flush
selectively, not whole-table.

Asserts:
  - the toggle returns successfully (sysctl write must not error)
  - no splat during the flush walk (the bug class — bucket iteration
    with locks dropped between rows historically the worst lifecycle
    stress in this code)
  - kmemleak filtered to abm symbols: zero new leaks from the flush
    or the netlink reset that follows it (abm_nl_send_rst_msg)

KASAN-eligible (memory-class teardown).
"""

from __future__ import annotations

import asyncio

from _topology import (
    bridge_with_n_ports,  # noqa: F401  (fixture)
)


# abm_-prefix only; the [auto_bridge] bracket annotation is too noisy
# under soft-IRQ stack unwinding and incidentally tags DPAA bpool
# refills as abm leaks. See test_abm_port_flap.py for the rationale.
ABM_LEAK_FILTER = ["abm_"]


async def _read_l3_filtering(target_agent, session) -> int:
    """sysctl is plain text "0\n" or "1\n"."""
    r = await target_agent.exec_cmd(
        session, ["sysctl", "-n", "net.abm.abm_l3_filtering"],
    )
    assert r["rc"] == 0, f"sysctl read failed: {r}"
    return int(r["stdout"].strip())


async def _write_l3_filtering(target_agent, session, value: int) -> None:
    r = await target_agent.exec_cmd(
        session, ["sysctl", "-w", f"net.abm.abm_l3_filtering={value}"],
    )
    assert r["rc"] == 0, f"sysctl write to {value} failed: {r}"


async def test_abm_table_flush_via_sysctl(
    aiohttp_session, target_agent, splat_window, bridge_with_n_ports,
):
    """Flip abm_l3_filtering to its inverse value and back; the toggle
    triggers abm_l2flow_table_flush() each time.
    """
    await target_agent.kmemleak_clear(aiohttp_session)

    initial = await _read_l3_filtering(target_agent, aiohttp_session)
    inverse = 1 - initial

    try:
        # First flip: triggers flush + abm_nl_send_rst_msg
        await _write_l3_filtering(target_agent, aiohttp_session, inverse)
        await asyncio.sleep(0.5)
        cur = await _read_l3_filtering(target_agent, aiohttp_session)
        assert cur == inverse, (
            f"abm_l3_filtering didn't take effect: wrote {inverse}, read {cur}"
        )

        # Second flip back: triggers another flush
        await _write_l3_filtering(target_agent, aiohttp_session, initial)
        await asyncio.sleep(0.5)
        cur = await _read_l3_filtering(target_agent, aiohttp_session)
        assert cur == initial, (
            f"abm_l3_filtering didn't revert: wrote {initial}, read {cur}"
        )
    finally:
        # Best-effort restore in case an assertion failed mid-flip.
        try:
            await _write_l3_filtering(target_agent, aiohttp_session, initial)
        except Exception:
            pass

    await asyncio.sleep(2.0)

    report = await target_agent.kmemleak(
        aiohttp_session, filter_substrs=ABM_LEAK_FILTER,
    )
    assert report.get("leak_count", 0) == 0, (
        f"table flush leaked {report['leak_count']} abm-tagged object(s):\n"
        + report.get("report", "")[:4000]
    )
