"""Retry transient partial admission without replacing the table or sockets."""
from __future__ import annotations

import os

import pytest

from test_flowtable_connections import SPORT, connections, peer  # noqa: F401
from test_flowtable_mtu import table_identity
from test_flowtable_offload import read, rig  # noqa: F401
from test_flowtable_selective_neighbour import hardware, warm

pytestmark = pytest.mark.skipif(os.environ.get("ASK_FLOWTABLE_TESTS") != "1",
                               reason="requires an explicit experimental boot")


@pytest.mark.parametrize("protocol", ["udp", "tcp"])
async def test_flowtable_transient_admission(connections, protocol):
    r = connections
    flows = [{"id": 0, "proto": protocol, "sport": SPORT + (protocol == "tcp"), "lan": r.lan_ip}]
    before, identity = await r.state(), await table_identity(r)
    assert before["entries"] == 0, before
    knob = "/sys/module/ask_flowtable/parameters/flowtable_fail_stage"
    # This fault is consumed only by a matching second directional request
    # after its peer already owns a hardware entry. It uses the same path as
    # failure to acquire RTNL, without actually blocking a kernel lock.
    assert (await r.target.fs_write(r.session, knob, "4"))["errno"] == 0
    try:
        async with peer(r, flows) as p:
            admitted = await warm(r, p, [0], protocol + "-busy-readmitted", flows)
            assert (await read(r.target, r.session, knob)).strip() == "0"
            assert admitted["busy"] >= before["busy"] + 1
            assert admitted["admission_invalidations"] >= before["admission_invalidations"] + 1
            assert admitted["deletes"] >= before["deletes"] + 1
            assert admitted["installs"] - before["installs"] == admitted["deletes"] - before["deletes"] + 2
            assert admitted["rearms"] == before["rearms"] and not admitted["invalidation_done"]
            assert admitted["handle_refs"] == admitted["neighbour_refs"] == 2
            assert await table_identity(r) == identity
            after = await hardware(r, p, protocol + "-busy-hardware", flows)
            assert after["admission_invalidations"] == admitted["admission_invalidations"]
            r.record(protocol + "-busy-complete", {"before": before, "admitted": admitted,
                                                   "after": after, "table": identity})
    finally:
        assert (await r.target.fs_write(r.session, knob, "0"))["errno"] == 0
