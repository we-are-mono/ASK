"""Real slab failures in binding and asynchronous admission, with service recovery."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import gzip
import json
import os
from pathlib import Path
import time

import pytest

from test_flowtable_connections import peer
from test_flowtable_offload import console_command, console_python, read, rig  # noqa: F401
from test_flowtable_selective_neighbour import hardware, unchanged, warm
from test_flowtable_service import (FAULT_DIR, FLOWS, blocked_probe,
                                    service, service_status, supervision_status, wait_service)  # noqa: F401

pytestmark = pytest.mark.skipif(os.environ.get("ASK_FLOWTABLE_TESTS") != "1",
                               reason="requires an explicit flowtable boot")


async def wait_json(r, path, timeout=25):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = await r.target.fs_read(r.session, path)
        if result["errno"] == 0:
            return json.loads(bytes.fromhex(result["content_hex"]))
        assert result["errno"] == 2, result
        await asyncio.sleep(0.05)
    pytest.fail(f"failslab guard did not publish {path}")


class Fault:
    def __init__(self, r, target, label, root, continuous=False):
        self.r, self.target, self.label, self.root = r, target, label, root
        self.result = None
        self.continuous = continuous

    async def hit(self):
        if self.result is None:
            self.result = await wait_json(self.r, self.root + "/result.json")
            self.r.record(self.label + "-injection", self.result)
        result = self.result
        assert result["consumed"] and "error" not in result, result
        assert not result["restore_errors"] and result["restored"] == result["original"], result
        if self.continuous:
            # __GFP_NOWARN sites suppress even failslab's stack diagnostic.
            # The scoped injector's finite budget records every consumed hit.
            assert result["failures"] > 0, result
            return result
        log = "".join(result["kernel_records"])
        assert "FAULT_INJECTION: forcing a failure" in log and "name failslab" in log, log
        # times=1 is a limit, not an atomic reservation across CPUs. Prove
        # that this run consumed exactly one failure in the selected path.
        failures = log.count("name failslab,")
        assert failures >= 1, log
        assert failures == 1, log
        assert result["selected"]["name"] + "+" in log, log
        if self.target == "callback":
            assert "ft_block_setup" in log, "fault missed the flowtable binding path"
        if self.target == "actions":
            assert "flow_offload_work" in log, "fault missed native flow admission"
        return result


@asynccontextmanager
async def slab_fault(r, target, label, *, continuous=False):
    config = await r.target.fs_read(r.session, "/proc/config.gz")
    assert config["errno"] == 0, config
    config = gzip.decompress(bytes.fromhex(config["content_hex"])).decode()
    for option in ("CONFIG_KASAN=y", "CONFIG_FAILSLAB=y", "CONFIG_FAULT_INJECTION_STACKTRACE_FILTER=y"):
        assert option in config.splitlines(), f"rebuild/stage a KASAN image with {option}"
    script = Path(__file__).with_name("_flowtable_failslab_guard.py").read_text()
    root = FAULT_DIR + "/failslab-" + target
    # Stage while management is healthy. A long paced-UART upload here would
    # outlive the traffic peer's idle lease; fault cleanup still uses UART.
    await console_command(r.service_console, "mkdir", root)
    staged = await r.target.fs_write(r.session, root + "/guard.py", script)
    assert staged["errno"] == 0, staged
    assert await read(r.target, r.session, root + "/guard.py") == script
    fault = Fault(r, target, label, root, continuous)
    try:
        # Launch can succeed even when its UART acknowledgement is lost.
        # Keep cancellation protected from the moment the child may exist.
        await console_python(r.service_console, f'''
from pathlib import Path
import subprocess
root = Path({root!r})
script = root / 'guard.py'
with (root / 'guard.log').open('w') as log:
    child = subprocess.Popen(['/usr/bin/python3', str(script), str(root), {target!r},
                              {'continuous' if continuous else 'once'!r}],
                             stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                             close_fds=True, start_new_session=True)
(root / 'pid').write_text(str(child.pid))
''')
        armed = await wait_json(r, root + "/armed.json", timeout=5)
        r.record(label + "-armed", armed)
        yield fault
    finally:
        # Only remove our fault. A missing result is a failed guard, never
        # permission to repair flowtables or discard the failed observation.
        try:
            cancelled = await r.target.fs_write(r.session, root + "/cancel", "")
            assert cancelled["errno"] == 0, cancelled
        except Exception:
            # UART remains the fallback when the fault disrupts management;
            # HTTP avoids a lost command boundary amid kernel diagnostics.
            await console_command(r.service_console, "touch", root + "/cancel")
        try:
            result = await wait_json(r, root + "/result.json", timeout=5)
            r.record(label + "-guard-final", result)
            assert not result["restore_errors"] and result.get("restored") == result.get("original"), result
        except BaseException:
            await console_python(r.service_console, f'''
from pathlib import Path
import json
root = Path({root!r})
saved = root / 'original.json'
if saved.exists():
    knobs = Path('/sys/kernel/debug/failslab')
    (knobs / 'probability').write_text('0')
    for name, value in json.loads(saved.read_text()).items():
        if name != 'probability': (knobs / name).write_text(value)
''')
            raise


async def same_service(r, before):
    assert await supervision_status(r) == before
    assert (await read(r.target, r.session, "/proc/sys/kernel/random/boot_id")).strip() == r.service_boot
    status = await service_status(r)
    assert status["admission_ready"] and not status["reconciliation_paused"], status


@pytest.mark.parametrize("target", ["binding", "callback"])
async def test_flowtable_failslab_binding_recovery(service, target):
    r = service
    flows = [{**f, "lan": r.lan_ip} for f in FLOWS]
    before_service = await supervision_status(r)
    async with peer(r, flows, initial_ids=[0, 1, 3]) as p:
        await warm(r, p, [0, 1], target + "-baseline", flows[:2])
        before = await hardware(r, p, target + "-before", flows[:2])
        await blocked_probe(r, p)
        async with slab_fault(r, target, target) as fault:
            started = time.monotonic()
            # The actual service recreates the missing table. No apply or
            # restart occurs after the injected deletion/allocation failure.
            await console_command(r.service_console, "nft", "delete", "table", "inet", "ask_flowtable")
            hit = await fault.hit()
            await p.batch([0, 1], count=32, interval=0.01)
            await blocked_probe(r, p)
            samples = await wait_service(r, timeout=20, policy_hash=r.service_hash)
            ready_seconds = time.monotonic() - started
            assert ready_seconds < 20, (ready_seconds, samples)
            await warm(r, p, [0, 1], target + "-readmitted", flows[:2])
            after = await hardware(r, p, target + "-after", flows[:2])
            assert time.monotonic() - started < 40
            assert after["errors"] == before["errors"]
            await p.rpc("open", [2])
            await warm(r, p, [0, 1, 2], target + "-new-flow", flows[:3])
            await hardware(r, p, target + "-new-hardware", flows[:3])
            await blocked_probe(r, p)
            await same_service(r, before_service)
            r.record(target + "-recovery", {"controller_seconds": ready_seconds, "before": before,
                                           "after": after, "hit": hit, "samples": samples})


@pytest.mark.parametrize("target", ["work", "rule", "actions", "entry", "hardware"])
@pytest.mark.parametrize("protocol", ["udp", "tcp"])
async def test_flowtable_failslab_admission_recovery(service, target, protocol):
    r = service
    label = target + "-" + protocol
    flows = [{**f, "lan": r.lan_ip} for f in FLOWS]
    flows[2]["proto"] = protocol
    before_service = await supervision_status(r)
    async with peer(r, flows, initial_ids=[0, 1, 3]) as p:
        await warm(r, p, [0, 1], label + "-baseline", flows[:2])
        before = await hardware(r, p, label + "-before", flows[:2])
        await blocked_probe(r, p)
        async with slab_fault(r, target, label) as fault:
            started = time.monotonic()
            await p.rpc("open", [2])
            await p.batch([2], count=32, interval=0.01)
            hit = await fault.hit()
            # The original new socket must recover by traffic alone. Keeping
            # controls active also proves selective retirement/clean unwind.
            admitted = await warm(r, p, [0, 1, 2], label + "-readmitted", flows[:3])
            ready_seconds = time.monotonic() - started
            assert ready_seconds < 20, (ready_seconds, admitted)
            after = await hardware(r, p, label + "-hardware", flows[:3])
            assert time.monotonic() - started < 40
            unchanged(before, after, [0, 1], flows)
            assert after["errors"] == before["errors"] and after["rearms"] == before["rearms"]
            assert (await service_status(r))["policy_hash"] == r.service_hash
            await blocked_probe(r, p)
            await same_service(r, before_service)
            r.record(label + "-recovery", {"admission_seconds": ready_seconds, "before": before,
                                         "after": after, "hit": hit})
