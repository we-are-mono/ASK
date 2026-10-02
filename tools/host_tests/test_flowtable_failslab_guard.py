"""The independent fault lease restores configuration even without a runner."""
import importlib.util
import gzip
import json
import os
from pathlib import Path
import re
from types import SimpleNamespace

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "tests/_flowtable_failslab_guard.py"
spec = importlib.util.spec_from_file_location("slab_guard", SOURCE)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


@pytest.fixture
def knobs(tmp_path):
    debugfs = tmp_path / "debugfs"
    debugfs.mkdir()
    for name in guard.KNOBS:
        (debugfs / name).write_text("0" if name == "probability" else "1")
    symbols = tmp_path / "symbols"
    symbols.write_text("1000 t ft_replace [ask_flowtable]\n2000 t next [ask_flowtable]\n"
                       "3000 t handle_softirqs\n4000 t after\n")
    backend, kmsg = tmp_path / "backend", tmp_path / "kmsg"
    backend.write_text("entries 0\n")
    kmsg.touch()
    return {"debugfs": debugfs, "kallsyms": symbols, "backend": backend,
            "lock_path": tmp_path / "lock", "kmsg": kmsg}


@pytest.mark.parametrize("finish", ["consumed", "expired", "cancelled", "setup-error"])
def test_fault_lease_restores_every_knob(tmp_path, knobs, monkeypatch, finish):
    root = tmp_path / "result"
    before = {name: (knobs["debugfs"] / name).read_text() for name in guard.KNOBS}
    original = Path.write_text
    failed = False

    def write(path, value, *args, **kwargs):
        nonlocal failed
        if finish == "setup-error" and path == knobs["debugfs"] / "require-end" and not failed:
            failed = True
            raise OSError("injected setup write error")
        result = original(path, value, *args, **kwargs)
        if path == knobs["debugfs"] / "probability" and value == "100":
            if finish == "consumed":
                original(knobs["debugfs"] / "times", "0")
            elif finish == "cancelled":
                (root / "cancel").touch()
        return result

    monkeypatch.setattr(Path, "write_text", write)
    guard.run(root, "entry", lease=0.02, **knobs)
    result = json.loads((root / "result.json").read_text())
    assert result["consumed"] == (finish == "consumed")
    assert ("error" in result) == (finish == "setup-error")
    assert not result["restore_errors"] and result["restored"] == before
    assert {name: (knobs["debugfs"] / name).read_text() for name in guard.KNOBS} == before


def test_refuses_another_active_injector(tmp_path, knobs):
    (knobs["debugfs"] / "probability").write_text("100")
    before = {name: (knobs["debugfs"] / name).read_text() for name in guard.KNOBS}
    root = tmp_path / "result"
    guard.run(root, "entry", **knobs)
    result = json.loads((root / "result.json").read_text())
    assert "another failslab user" in result["error"] and not (root / "armed.json").exists()
    assert {name: (knobs["debugfs"] / name).read_text() for name in guard.KNOBS} == before


@pytest.mark.parametrize("cancel", [False, True])
def test_continuous_fault_keeps_lease_after_a_hit(tmp_path, knobs, monkeypatch, cancel):
    root = tmp_path / "result"
    before = {name: (knobs["debugfs"] / name).read_text() for name in guard.KNOBS}
    polls = 0

    def drain(fd):
        nonlocal polls
        polls += 1
        if polls == 1:
            assert int((knobs["debugfs"] / "times").read_text()) == guard.CONTINUOUS_BUDGET
            (knobs["debugfs"] / "times").write_text(str(guard.CONTINUOUS_BUDGET - 3))
            assert (knobs["debugfs"] / "verbose_ratelimit_interval_ms").read_text() == "1000"
            assert (knobs["debugfs"] / "verbose_ratelimit_burst").read_text() == "1"
            # __GFP_NOWARN allocations still decrement the kernel counter.
            return []
        if polls == 2:
            assert (knobs["debugfs"] / "probability").read_text() == "100"
            if cancel:
                (root / "cancel").touch()
        return []

    monkeypatch.setattr(guard, "drain_kmsg", drain)
    guard.run(root, "entry", lease=0.04, continuous=True, **knobs)
    result = json.loads((root / "result.json").read_text())
    assert result["consumed"] and result["continuous"] and polls >= 3
    assert result["failures"] == 3
    assert not result["restore_errors"] and result["restored"] == before


@pytest.mark.parametrize("target", sorted(guard.TARGETS))
def test_task_context_faults_exclude_softirq_stacks(tmp_path, knobs, target):
    name, module, _ = guard.TARGETS[target]
    owner = f" [{module}]" if module else ""
    knobs["kallsyms"].write_text(
        f"1000 t {name}{owner}\n2000 t next{owner}\n"
        "3000 t handle_softirqs\n4000 t after\n")
    root = tmp_path / "result"
    guard.run(root, target, lease=0.02, **knobs)
    result = json.loads((root / "armed.json").read_text())
    assert result["selected"]["start"] == 0x1000
    # These two run inside a softirq themselves; rejecting softirq stacks
    # would stop them ever firing.
    if target in ("work", "ipsec-receive"):
        assert result["excluded"] is None
    else:
        assert (result["excluded"]["start"], result["excluded"]["end"]) == (0x3000, 0x4000)


# Where each target's owner keeps its source: the ASK modules in cdx/, the
# kernel's own in the tree ASK_KERNEL_SOURCE names.
KERNEL_DIRS = {None: ("net/core", "drivers/net/ethernet/freescale/sdk_fman/Peripherals/FM/Pcd"),
               "nf_flow_table": ("net/netfilter",)}


@pytest.mark.parametrize("target", sorted(guard.TARGETS))
def test_every_target_names_a_function_its_module_defines(target):
    """A target whose function was renamed or removed never arms, and the
    rig case that relies on it fails at setup instead of injecting."""
    name, module, _ = guard.TARGETS[target]
    if module in ("cdx", "ask_flowtable"):
        files = sorted((SOURCE.parents[2] / "cdx").glob("*.c"))
    else:
        kernel = os.environ.get("ASK_KERNEL_SOURCE")
        if not kernel:
            pytest.skip("ASK_KERNEL_SOURCE names no kernel tree")
        files = sorted(path for directory in KERNEL_DIRS[module]
                       for path in (Path(kernel) / directory).glob("*.c"))
    definition = re.compile(rf"(?m)^(?:[A-Za-z_][\w \t*]*[\s*])?{re.escape(name)}\([^;{{]*\)\s*\{{")
    assert any(definition.search(path.read_text(errors="replace")) for path in files), (target, name)


def test_symbol_selection_requires_unique_visible_module_function():
    text = ("1000 t ft_block_setup.constprop.0 [ask_flowtable]\n"
            "1000 t alias [ask_flowtable]\n2000 t next [ask_flowtable]\n"
            "3000 t ft_block_setup [unrelated]\n4000 t next [unrelated]\n")
    selected = guard.symbol_range(text, "ft_block_setup", "ask_flowtable")
    assert selected["start"] == 0x1000 and selected["end"] == 0x2000
    with pytest.raises(AssertionError):
        guard.symbol_range(text.replace("1000", "0000"), "ft_block_setup", "ask_flowtable")
    with pytest.raises(AssertionError):
        guard.symbol_range(text + "1500 t ft_block_setup [ask_flowtable]\n", "ft_block_setup", "ask_flowtable")


@pytest.mark.parametrize("cancel_transport", ["http", "uart"])
async def test_lost_launch_acknowledgement_still_cancels_guard(monkeypatch, cancel_transport):
    monkeypatch.syspath_prepend(str(SOURCE.parent))
    import _flowtable_failslab as suite

    active = False
    cancelled = False
    script = None
    records = {}

    class Target:
        async def fs_read(self, session, path):
            assert path == "/proc/config.gz"
            config = ("CONFIG_KASAN=y\nCONFIG_FAILSLAB=y\n"
                      "CONFIG_FAULT_INJECTION_STACKTRACE_FILTER=y\n")
            return {"errno": 0, "content_hex": gzip.compress(config.encode()).hex()}

        async def fs_write(self, session, path, content):
            nonlocal script, cancelled
            if path.endswith("/cancel"):
                if cancel_transport == "uart":
                    raise OSError("management disrupted by fault")
                cancelled = True
            else:
                script = content
            return {"errno": 0}

    async def read(*args):
        return script

    async def command(console, *args):
        nonlocal cancelled
        if args[0] == "touch":
            assert args[1].endswith("/cancel")
            cancelled = True
        else:
            assert args[0] in ("mkdir", "rm")

    async def launch(*args):
        nonlocal active
        active = True
        raise EOFError("guard launched, UART acknowledgement lost")

    async def result(r, path, timeout):
        nonlocal active
        assert cancelled and path.endswith("/result.json")
        active = False
        return {"restore_errors": [], "original": {"probability": "0"},
                "restored": {"probability": "0"}}

    monkeypatch.setattr(suite, "read", read)
    monkeypatch.setattr(suite, "console_command", command)
    monkeypatch.setattr(suite, "console_python", launch)
    monkeypatch.setattr(suite, "wait_json", result)
    r = SimpleNamespace(target=Target(), session=None, service_console=None,
                        record=lambda name, value: records.update({name: value}))
    with pytest.raises(EOFError, match="acknowledgement lost"):
        async with suite.slab_fault(r, "entry", "lost-launch"):
            pytest.fail("an unacknowledged launch must not run the test body")
    assert not active and cancelled
    assert "lost-launch-guard-final" in records
