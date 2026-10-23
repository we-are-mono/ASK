"""Ignore unrelated netdev events while retaining safe bound-port retirement."""
from __future__ import annotations

import json

from _topology import TARGET_LAN_IF, TARGET_WAN_IF
from _flowtable_connections import (FLOWS, by_key, peer)
from _flowtable_rig import (HEALTH_BASELINE, command, upper_roundtrip)
from _flowtable_selective_neighbour import (hardware, unchanged, warm)

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

            # An upper-device change on either real port retires every flow
            # through it, and Linux readmits each on its next packets: the
            # table, its bindings and admission stay up throughout (A415).
            # MTU, MAC and link recovery have separate proofs.
            for dev in (TARGET_LAN_IF, TARGET_WAN_IF):
                before = await r.state()
                # Enslaving the port temporarily removes its routed path.
                await p.rpc("start", [0], count=0, interval=0.01, allow_loss=True)
                await p.rpc("start", [1], count=0, interval=0.01)
                await upper_roundtrip(r, dev)
                transition = await p.rpc("stop", ids)
                # Traffic ran throughout, so a flow may be back already.
                retired = await r.state()
                assert retired["link_invalidations"] > before["link_invalidations"], (before, retired)
                assert retired["deletes"] >= before["deletes"] + 4, (before, retired)
                assert retired["invalidated"] == 0 and retired["bindings"] == 2, retired
                assert retired["fatal"] == retired["quarantine"] == 0, retired
                assert retired["errors"] == HEALTH_BASELINE["errors"], retired
                assert retired["rearms"] == before["rearms"], retired
                await warm(r, p, ids, "devices-" + dev + "-readmitted", flows)
                after = await hardware(r, p, "devices-" + dev + "-hardware", flows)
                assert after["installs"] >= before["installs"] + 4, (before, after)
                assert after["rearms"] == before["rearms"] and after["invalidated"] == 0, after
                r.record("devices-" + dev, {"before": before, "retired": retired,
                                           "transition": transition, "after": after})
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
