"""The offload service is default-on: a normal boot installs the catch-all
policy across the CDX physical ports with no configuration, the way CMM "just
worked". This is the parity guarantee of the C ask-flowtable daemon.

Order-independent: it (re)starts the boot service itself, so it does not depend
on running before the controlled tests that stop the daemon for their own
policies. It restarts the service at teardown so the image is left in its
normal default-on state.
"""
from __future__ import annotations

import asyncio
import json
import os

import pytest

from ask_orch.uart import Console
from test_flowtable_offload import ARTIFACTS, console_command, read, rig  # noqa: F401

pytestmark = pytest.mark.skipif(os.environ.get("ASK_FLOWTABLE_TESTS") != "1",
                               reason="requires an explicit experimental boot")

INIT = "/etc/init.d/ask-flowtable"
DAEMON = "/usr/sbin/ask-flowtable"
DEFAULT_CONF = "/etc/ask/offload.conf"


async def _status(con):
    result = await console_command(con, DAEMON, "status")
    return json.loads(result["stdout"])


async def test_boot_service_offloads_by_default(target_agent, aiohttp_session):
    with Console.target(log_path=str(ARTIFACTS / "default-on-uart.log")) as con:
        await asyncio.to_thread(con.login, "root", None)

        owner = (await read(target_agent, aiohttp_session,
                            "/sys/module/cdx/parameters/offload_owner")).strip()
        assert owner == "flowtable", "boot ask.offload=flowtable first"

        # Zero-config: the shipped default parses and is the catch-all. (Its
        # `check` hash covers the unresolved "devices auto"; the installed
        # table's marker is the resolved-device hash, so the two differ by
        # design and are not compared here.)
        shipped = await console_command(con, DAEMON, "check", "--config", DEFAULT_CONF)
        assert json.loads(shipped["stdout"])["policy_hash"], shipped

        # (Re)start the boot service — idempotent, and the point of the test is
        # that starting it is the *whole* configuration.
        await console_command(con, INIT, "restart", check=False, timeout=45)
        # Prior one-shot tests can retain manual ownership across restart.
        await console_command(con, DAEMON, "resume")

        # It installs its table and binds every up CDX physical port with no
        # further action.
        for _ in range(40):
            status = await _status(con)
            if status["policy_installed"] and status["admission_ready"]:
                break
            await asyncio.sleep(0.5)
        else:
            pytest.fail(f"default-on service did not bind the backend: {status}")

        # The installed table carries our ownership marker (a 64-hex hash), and
        # every up CDX physical port is bound — with no configuration.
        assert status["policy_hash"] and len(status["policy_hash"]) == 64, status
        assert status["backend"]["bindings"] >= 2, status
        assert status["backend"]["owner"] == "flowtable", status
        assert not status["backend"]["fatal"] and not status["backend"]["invalidated"], status
