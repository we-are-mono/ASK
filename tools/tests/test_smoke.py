"""Smoke tests — run first, gate everything else via fixtures.

The session-scoped _target_reachable fixture in conftest already kills
the run if the target isn't responsive, so test_health is mostly a
named TAP/JUnit line confirming the agent responded. test_no_boot_splats
uses the splat_window fixture as its only assertion — it's a positive
confirmation that the kernel booted clean.
"""

from __future__ import annotations


async def test_target_health(aiohttp_session, target_agent):
    h = await target_agent.health(aiohttp_session)
    assert h["ok"]
    assert "version" in h
    assert h.get("uptime_s", 0) > 0


async def test_no_boot_splats(splat_window):
    """Pass if no KASAN/BUG/UBSAN/lockdep fires between capture-start
    and capture-stop. For this test the window is ~0 seconds, so it
    really asserts "nothing new has happened since the last capture" —
    a cheap liveness check that the splat detector isn't broken."""
    pass
