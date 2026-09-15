"""Boot and forward through CDX without starting CMM or loading FCI."""
import asyncio
import json
import os

import pytest

from ask_orch.uart import Console
from test_flowtable_connections import FLOWS, connections, peer  # noqa: F401
from test_flowtable_module import table
from test_flowtable_offload import ARTIFACTS, console_command, read, rig  # noqa: F401
from test_flowtable_selective_neighbour import hardware, warm

pytestmark = pytest.mark.skipif(os.environ.get("ASK_FLOWTABLE_TESTS") != "1",
                               reason="requires an explicit experimental boot")


async def test_flowtable_startup_without_cmm_or_fci(connections):
    r = connections

    async def independent():
        modules = await read(r.target, r.session, "/proc/modules")
        names = {line.split()[0] for line in modules.splitlines()}
        assert {"cdx", "ask_flowtable"} <= names and not {"fci", "auto_bridge"} & names, modules
        assert (await r.target.fs_read(r.session, "/var/run/cmm.pid"))["errno"] != 0
        assert (await read(r.target, r.session, "/sys/module/cdx/parameters/offload_owner")).strip() == "flowtable"

    await independent()
    await r.delete_table()
    with Console.target(log_path=str(ARTIFACTS / "startup-independence-uart.log")) as con:
        await asyncio.to_thread(con.login, "root", None)
        cmm = await console_command(con, "/etc/init.d/cmm", "start")
        assert "CMM disabled" in cmm["stdout"], cmm
        default = json.loads(await read(r.target, r.session, "/etc/ask/flowtable.json"))
        assert not default["enabled"], "test expects the shipped disabled policy"
        result = await console_command(con, "/etc/init.d/ask-flowtable", "start")
        applied = json.loads(result["stdout"])
        assert not applied["enabled"] and applied["drained"]["bindings"] == 0, applied
        await independent()
    await table(r)
    flows = [{**f, "lan": r.lan_ip} for f in FLOWS[:2]]
    async with peer(r, flows) as p:
        await warm(r, p, [0, 1], "startup-independent-admission", flows)
        state = await hardware(r, p, "startup-independent-hardware", flows)
        await independent()
        r.record("startup-independent", {"default_policy": applied, "cmm_start": cmm, "state": state})
