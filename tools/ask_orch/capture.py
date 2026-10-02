"""Kernel-log checks shared by test and profile fixture lifecycles."""

from contextlib import asynccontextmanager

from ask_orch.artifacts import record


def verify_capture(result, nodeid, allowlist):
    from _dmesg_allowlist import filter_splats

    assert result.get("complete") is True, ("incomplete kernel log capture", result)
    assert "splats" in result, ("missing kernel log verdict", result)
    splats = filter_splats(result["splats"], nodeid, allowlist)
    assert not splats, f"kernel splats during {nodeid}: " + "; ".join(splats[:3])


@asynccontextmanager
async def capture_window(agent, session, nodeid, allowlist, *, name="kernel"):
    cap_id = await agent.capture_start(session)
    try:
        yield cap_id
    finally:
        result = await agent.capture_stop(session, cap_id)
        record(name, result, nodeid=nodeid)
        verify_capture(result, nodeid, allowlist)
