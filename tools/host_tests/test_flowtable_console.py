"""UART acknowledgement loss must retry staging, never a test operation."""
import ast
import asyncio
import base64
import hashlib
from pathlib import Path
import re
import shlex
import time
from types import SimpleNamespace

import pytest


def helpers():
    source = Path(__file__).resolve().parents[1] / "tests/test_flowtable_offload.py"
    parsed = ast.parse(source.read_text())
    selected = [node for node in parsed.body if isinstance(node, ast.AsyncFunctionDef)
                and node.name in {"console_command", "console_python"}]
    namespace = {name: value for name, value in globals().items() if not name.startswith("__")}
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(source), "exec"), namespace)
    return namespace


class Staging:
    def __init__(self, lost_ack=None, execution_error=False, corrupt=False):
        self.lost_ack, self.execution_error, self.corrupt = lost_ack, execution_error, corrupt
        self.encoded = ""
        self.decoded = b""
        self.executed, self.resets = [], 0

    async def command(self, console, *argv, **kwargs):
        result = {"rc": 0, "stdout": ""}
        if argv[0] == "rm":
            self.encoded, self.decoded = "", b""
            self.resets += 1
        elif argv[:2] == ("sh", "-c"):
            words = shlex.split(argv[2])
            if words[0] == "printf":
                self.encoded += words[2]
                if self.lost_ack:
                    error, self.lost_ack = self.lost_ack, None
                    raise error("kernel log split the acknowledgement after the write")
            else:
                assert words[:2] == ["base64", "-d"]
                self.decoded = base64.b64decode(self.encoded, validate=True)
        elif argv[0] == "sha256sum":
            result["stdout"] = ("0" * 64 if self.corrupt else hashlib.sha256(self.decoded).hexdigest())
        elif argv[0] == "python3":
            self.executed.append(self.decoded)
            if self.execution_error:
                raise TimeoutError("operation executed but its acknowledgement was lost")
        else:
            raise AssertionError(argv)
        return result


@pytest.mark.parametrize("lost_ack", [TimeoutError, AssertionError])
async def test_lost_staging_ack_restarts_before_execution(lost_ack):
    namespace, staging, synced = helpers(), Staging(lost_ack=lost_ack), []
    namespace["console_command"] = staging.command
    script = "print('one operation')\n" * 20  # multiple staging chunks
    result = await namespace["console_python"](SimpleNamespace(sync_prompt=lambda: synced.append(True)), script)
    assert result["rc"] == 0
    assert staging.executed == [script.encode()]
    assert staging.resets == 3  # failed attempt, fresh attempt, final cleanup
    assert synced == [True]


async def test_unknown_execution_is_not_retried():
    namespace, staging = helpers(), Staging(execution_error=True)
    namespace["console_command"] = staging.command
    with pytest.raises(TimeoutError, match="operation executed"):
        await namespace["console_python"](object(), "print('one operation')")
    assert staging.executed == [b"print('one operation')"]
    assert staging.resets == 2


async def test_staging_digest_must_match_before_execution():
    namespace, staging = helpers(), Staging(corrupt=True)
    namespace["console_command"] = staging.command
    with pytest.raises(pytest.fail.Exception, match="staging failed 3 times"):
        await namespace["console_python"](object(), "print('one operation')")
    assert not staging.executed
    assert staging.resets == 4


@pytest.mark.parametrize("resync", [False, True])
async def test_timeout_resync_requires_explicit_idempotent_call(resync):
    synced = []

    def run(*args):
        raise TimeoutError("split marker")

    console = SimpleNamespace(run=run, sync_prompt=lambda: synced.append(True))
    call = helpers()["console_command"](console, "true", resync=resync)
    if resync:
        assert await call == {"rc": None, "stdout": "split marker"}
        assert synced == [True]
    else:
        with pytest.raises(TimeoutError, match="split marker"):
            await call
        assert not synced
