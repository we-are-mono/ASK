"""Agent health and retained boot-log verification."""


async def test_target_health(aiohttp_session, target_agent):
    h = await target_agent.health(aiohttp_session)
    assert h["ok"]
    assert "version" in h
    assert h.get("uptime_s", 0) > 0


async def test_no_boot_splats(bench_health):
    # The session preflight reads and verifies boot history before mutations.
    assert bench_health["boot"]["complete"] is True
