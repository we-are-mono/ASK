"""Conntrack marks that only select a route.

mwan3, pbr and a VPN client's policy routing mark connections to choose a
route, and nothing after that reads the mark: Linux resolved the route when it
created the flow, and the flow keeps it whichever fast path forwards it. The
adapter refuses any mark it cannot honour, so those bits are named to it at
load -- `ask_flowtable.route_mark_mask`, boot-immutable like the class mask --
before such a connection is admitted.
"""
from __future__ import annotations

import asyncio

from ask_orch.uart import Console
from _flowtable_qos import reload_adapter
from _flowtable_rig import artifact_dir, hardware_proof

# mwan3's default mmx_mask.
MWAN3_BITS = 0x3f00


async def test_route_bits_are_admitted(rig):
    """With mwan3's bits named, a connection marked inside them is admitted in
    both directions and forwarded by hardware; a bit outside them and the
    class's still refuses. The image's own options come back afterwards."""
    r = rig
    r.console = Console.target(log_path=str(artifact_dir() / "marks-uart.log"))
    try:
        await asyncio.to_thread(r.console.login, "root", None)
        initial = await r.state()
        qos = int(initial["qos_mark_mask"])
        route = MWAN3_BITS & ~qos
        assert route, qos
        await reload_adapter(r, f"route_mark_mask={route:#x}")
        try:
            assert int((await r.state())["route_mark_mask"]) == route
            await r.table(mark=route & -route)
            await r.admit()
            proof = await hardware_proof(r, 64)
            r.record("marks-route-admitted", {"mask": route, "proof": proof})
            await r.delete_table()
            await r.clear_ct()

            outside = ~(route | qos) & 0xffffffff
            refused_from = await r.state()
            await r.table(mark=outside & -outside)
            await r.exchange(count=32)
            declined = await r.wait(lambda s: s["rejects"] > refused_from["rejects"])
            assert not declined["entries"], declined
            r.record("marks-outside-refused", {"declined": declined})
        finally:
            try:
                await r.delete_table()
            finally:
                await reload_adapter(r, idle=False)
        restored = await r.state()
        assert int(restored.get("route_mark_mask", 0)) == int(initial.get("route_mark_mask", 0))
        assert int(restored["qos_mark_mask"]) == qos
    finally:
        r.console.close()
