"""Ignore unrelated netdev events while retaining safe bound-port retirement."""
from __future__ import annotations

import json
import os

import pytest

from _topology import TARGET_LAN_IF, TARGET_WAN_IF
from test_flowtable_connections import FLOWS, by_key, connections, peer  # noqa: F401
from test_flowtable_module import table
from test_flowtable_offload import command, rename_roundtrip, rig  # noqa: F401
from test_flowtable_selective_neighbour import hardware, unchanged, warm
from test_flowtable_tcp import software_tx

pytestmark = pytest.mark.skipif(os.environ.get("ASK_FLOWTABLE_TESTS") != "1",
                               reason="requires an explicit experimental boot")
DUMMY, RENAMED, BRIDGE = "askftdev0", "askftdev1", "askftdevbr"


async def test_flowtable_device_dependencies(connections):
    r = connections
    flows = [{**f, "lan": r.lan_ip} for f in FLOWS[:2]]
    ids = [0, 1]
    links = json.loads((await command(r.target, r.session, "ip", "-j", "link", "show"))["stdout"])
    assert not {DUMMY, RENAMED, BRIDGE} & {i["ifname"] for i in links}, links
    await command(r.target, r.session, "modprobe", "dummy", "numdummies=0")
    try:
        async with peer(r, flows) as p:
            await warm(r, p, ids, "devices-initial-admission", flows)
            initial = await hardware(r, p, "devices-initial-hardware", flows)
            await p.rpc("start", ids, count=0, interval=0.01)
            changes = [
                ("create", ["add", "name", DUMMY, "type", "dummy"]),
                ("up", ["set", "dev", DUMMY, "up"]),
                ("mtu", ["set", "dev", DUMMY, "mtu", "1400"]),
                ("mac", ["set", "dev", DUMMY, "address", "02:00:00:ab:cd:01"]),
                ("bridge", ["add", "name", BRIDGE, "type", "bridge"]),
                ("upper-add", ["set", "dev", DUMMY, "master", BRIDGE]),
                ("upper-remove", ["set", "dev", DUMMY, "nomaster"]),
                ("down", ["set", "dev", DUMMY, "down"]),
                ("rename", ["set", "dev", DUMMY, "name", RENAMED]),
                ("renamed-up", ["set", "dev", RENAMED, "up"]),
                ("unregister", ["del", "dev", RENAMED]),
                ("bridge-unregister", ["del", "dev", BRIDGE]),
            ]
            for label, args in changes:
                before = await r.state()
                old = by_key(before)
                result = await command(r.target, r.session, "ip", "link", *args)

                def progressed(state):
                    if state["invalidated"] or state["entries"] != 4:
                        return True  # Fail immediately below with the actual state.
                    now = by_key(state)
                    return now.keys() == old.keys() and all(
                        int(now[k]["packets"]) > int(old[k]["packets"]) for k in old)

                after = await r.wait(progressed)
                unchanged(initial, after, ids, flows)
                for field in ("installs", "deletes", "rearms"):
                    assert after[field] == initial[field], (field, initial, after)
                r.record("devices-unrelated-" + label, {"command": args, "result": result,
                                                       "before": before, "after": after})
            reports = await p.rpc("stop", ids)
            assert all(v["count"] > 0 for v in reports.values()), reports
            r.record("devices-unrelated-transfers", reports)
            await hardware(r, p, "devices-unrelated-hardware", flows)

            # Rename remains a conservative event on either real port. MTU
            # changes have a separate automatic recovery proof.
            for dev in (TARGET_LAN_IF, TARGET_WAN_IF):
                before = await r.state()
                await p.rpc("start", ids, count=0, interval=0.01)
                await rename_roundtrip(r, dev)
                retired = await r.wait(lambda s: s["invalidation_done"] == 1 and not s["entries"])
                assert retired["invalidated"] == 1 and retired["bindings"] == 2, retired
                assert retired["handle_refs"] == retired["neighbour_refs"] == retired["quarantine"] == 0, retired
                assert retired["fatal"] == retired["errors"] == 0, retired
                assert retired["installs"] == before["installs"] and retired["deletes"] == before["deletes"] + 4
                assert retired["rearms"] == before["rearms"], retired
                transition = await p.rpc("stop", ids)
                tx_before = await software_tx(r)
                reports = await p.batch(ids, count=128, interval=0.01)
                tx_after = await software_tx(r)
                tx = {d: tx_after[d] - tx_before[d] for d in tx_before}
                assert all(tx[d] >= 128 for d in (TARGET_LAN_IF, TARGET_WAN_IF)), tx
                blocked = await r.state()
                assert blocked["entries"] == 0 and blocked["installs"] == before["installs"], blocked
                await r.delete_table()
                await table(r)
                await warm(r, p, ids, "devices-" + dev + "-readmitted", flows)
                after = await hardware(r, p, "devices-" + dev + "-hardware", flows)
                assert after["rearms"] == before["rearms"] + 1, after
                r.record("devices-" + dev, {"before": before, "retired": retired,
                                           "transition": transition, "software_transfers": reports,
                                           "software_tx": tx, "after": after})
    finally:
        # Remove only names checked absent before the test.
        try:
            await r.delete_table()
        finally:
            failures = []
            links = json.loads((await command(r.target, r.session, "ip", "-j", "link", "show"))["stdout"])
            names = {i["ifname"] for i in links}
            for name in (RENAMED, DUMMY, BRIDGE):
                if name in names:
                    result = await command(r.target, r.session, "ip", "link", "del", "dev", name, check=False)
                    if result["rc"]:
                        failures.append(result)
            assert not failures, failures
