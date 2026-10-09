"""release_latch() against a model of the adapter: the flowtable it binds to
clear a leftover invalidation goes again whatever happens while it is bound,
and one an interrupted attempt left behind is cleared before anything else."""

import asyncio

import pytest

import _flowtable_rig
from _flowtable_rig import LATCH_TABLE, release_latch


class Adapter:
    """The counters release_latch() reads, and the bind that clears a latch
    the adapter can rearm on."""

    def __init__(self, invalidated=1, bindings=0, fatal=0, rearm_ready=1):
        self.state = {"invalidated": invalidated, "bindings": bindings, "fatal": fatal,
                      "rearm_ready": rearm_ready, "entries": 0}
        self.table = bindings == 2
        self.binds = self.deletes = 0
        self.fail_wait = None

    def bind(self):
        assert not self.table, "bound a second latch table"
        self.table, self.binds = True, self.binds + 1
        self.state["bindings"] = 2
        if self.state["rearm_ready"] and not self.state["fatal"]:
            self.state["invalidated"] = 0

    def delete(self):
        self.deletes += 1
        if not self.table:
            return {"rc": 1, "stdout": "", "stderr": "No such file or directory"}
        self.table = False
        self.state["bindings"] = 0
        return {"rc": 0, "stdout": "", "stderr": ""}


class Rig:
    def __init__(self, adapter):
        self.adapter, self.target, self.session = adapter, object(), object()

    async def state(self):
        return dict(self.adapter.state)

    async def nft(self, text):
        assert f"table inet {LATCH_TABLE}" in text and "flags offload" in text, text
        self.adapter.bind()

    async def wait(self, predicate, timeout=10):
        if self.adapter.fail_wait:
            raise self.adapter.fail_wait
        state = await self.state()
        assert predicate(state), state
        return state


@pytest.fixture
def adapter(monkeypatch):
    model = Adapter()
    patient = _flowtable_rig.rearm_ready

    async def command(agent, session, *argv, check=True, **kwargs):
        assert argv == ("nft", "delete", "table", "inet", LATCH_TABLE) and not check, argv
        return model.delete()

    async def rearm_ready(r, timeout=10):
        # The same poll, without its ten seconds of patience.
        return await patient(r, timeout=0.3)

    monkeypatch.setattr(_flowtable_rig, "command", command)
    monkeypatch.setattr(_flowtable_rig, "rearm_ready", rearm_ready)
    return model


def test_releases_a_latch_left_with_nothing_bound(adapter):
    state = asyncio.run(release_latch(Rig(adapter)))
    assert state["invalidated"] == state["bindings"] == 0 and adapter.binds == 1
    assert not adapter.table


@pytest.mark.parametrize("failure", [ConnectionError("agent went away"), asyncio.CancelledError()])
def test_gives_the_table_back_when_interrupted(adapter, failure):
    """An observation that fails, or a case cancelled, while the table is
    bound still deletes it: the next fixture would otherwise find two
    bindings and refuse to start."""
    adapter.fail_wait = failure
    with pytest.raises(type(failure)):
        asyncio.run(release_latch(Rig(adapter)))
    assert not adapter.table and adapter.state["bindings"] == 0


def test_clears_a_table_an_interrupted_attempt_left(adapter):
    adapter.table, adapter.state["bindings"] = True, 2
    with pytest.warns(UserWarning, match="interrupted latch release"):
        state = asyncio.run(release_latch(Rig(adapter)))
    assert state["bindings"] == state["invalidated"] == 0 and not adapter.table


def test_a_failed_release_is_reported(adapter, monkeypatch):
    """A table that would not go after the rearm fails the release there,
    with nft's answer, rather than as a wait that never converges."""
    deletes = []

    async def command(agent, session, *argv, check=True, **kwargs):
        deletes.append(argv)
        if len(deletes) == 1:
            return adapter.delete()
        return {"rc": 1, "stdout": "", "stderr": "Device or resource busy"}

    monkeypatch.setattr(_flowtable_rig, "command", command)
    with pytest.raises(AssertionError, match="resource busy"):
        asyncio.run(release_latch(Rig(adapter)))


@pytest.mark.parametrize("left", [{"invalidated": 0}, {"fatal": 1}, {"rearm_ready": 0}])
def test_leaves_what_a_bind_would_not_clear(adapter, left):
    """Nothing latched, or a latch a bind cannot clear: no table, and the
    state goes to the case as it is."""
    adapter.state.update(left)
    state = asyncio.run(release_latch(Rig(adapter)))
    assert adapter.binds == 0 and not adapter.table
    assert {k: state[k] for k in left} == left
