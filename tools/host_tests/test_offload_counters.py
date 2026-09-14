"""Prevent combined netdev totals from becoming software-path evidence."""

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


counter = load("offload_counters", "tools/ask_orch/counters.py")
capture = load("capture_counters", "meta-ask/recipes-support/ask-test-agent/files/askd_agent/counters.py")


class Agent:
    def __init__(self, output, rc=0):
        self.output, self.rc = output, rc

    async def exec_cmd(self, session, argv):
        if argv == ["ethtool", "-S", "eth4"]:
            return {"rc": self.rc, "stdout": self.output}
        # A136: netdev counts grow even when the software count stays flat.
        assert argv == ["ip", "-s", "-j", "link", "show", "eth4"]
        return {"rc": 0, "stdout": json.dumps([
            {"stats64": {"rx": {"packets": 1000000}}},
        ])}


async def test_software_count_excludes_hardware_and_percpu_duplicates():
    agent = Agent("""NIC statistics:
     rx packets [CPU 0]: 3
     rx packets [CPU 1]: 4
     rx packets [TOTAL]: 7
     tx packets [TOTAL]: 2000000
""")
    assert await counter.kernel_rx_packets(agent, None, "eth4") == 7


@pytest.mark.parametrize("output,rc", [
    ("rx_packets: 7\n", 0),
    ("rx packets [CPU 0]: 7\n", 0),
    ("rx packets [TOTAL]: -1\n", 0),
    ("rx packets [TOTAL]: 7\nrx packets [TOTAL]: 8\n", 0),
    ("rx packets [TOTAL]: 7\n", 1),
    ("", 0),
])
async def test_missing_or_ambiguous_software_counter_fails(output, rc):
    with pytest.raises(AssertionError):
        await counter.kernel_rx_packets(Agent(output, rc), None, "eth4")


def test_capture_keeps_sdk_counter_names(monkeypatch):
    monkeypatch.setattr(capture.subprocess, "run", lambda *args, **kw: SimpleNamespace(
        stdout="""NIC statistics:
     rx packets [CPU 0]: 3
     rx packets [TOTAL]: 7
     tx S/G [TOTAL]: 11
     congestion time (ms): 0
     rx_errors: 2
"""))
    assert capture._ethtool_stats("eth4") == {
        "rx packets [CPU 0]": 3, "rx packets [TOTAL]": 7,
        "tx S/G [TOTAL]": 11, "congestion time (ms)": 0, "rx_errors": 2,
    }
