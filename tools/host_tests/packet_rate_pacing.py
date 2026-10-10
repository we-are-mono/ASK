"""The paced pktgen script caps its NIC queue before sending any frames."""
import ast
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


SOURCE = Path(__file__).parents[1] / "tests" / "flowtable_nat_throughput.py"
NIC = "testnic"


@pytest.mark.parametrize("frame,ratep,cap", [(64, 2000000, 1344), (128, 2000000, 2368),
                                           (64, 2000001, 1345), (64, None, None)])
def test_pktgen_queue_cap(tmp_path, monkeypatch, frame, ratep, cap):
    root = tmp_path / "proc/net/pktgen"
    root.mkdir(parents=True)
    queue = tmp_path / f"sys/class/net/{NIC}/queues/tx-0/tx_maxrate"
    queue.parent.mkdir(parents=True)
    queue.write_text("0")
    writes = []
    started = False
    original_write = Path.write_text

    def write(path, value, *args, **kwargs):
        nonlocal started
        if path == queue:
            assert not started
            writes.append(int(value))
        elif path.parent == root and path.name == "pgctrl":
            assert int(queue.read_text()) == (cap or 0), "pktgen ran without its hardware cap"
            started = True
            original_write(root / f"{NIC}@0", "Result: OK: completed\n")
        return original_write(path, value, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", write)
    tree = ast.parse(SOURCE.read_text())
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_pktgen")
    namespace = dict(LAN_NIC=NIC, WAN_IP="192.0.2.1", PACKET_PORT=42000, PACKET_SPORT=41000)
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(SOURCE), "exec"), namespace)
    rig = SimpleNamespace(dut_lan_mac="02:00:00:00:00:01", lan_ip="198.51.100.2")
    script = ast.parse(namespace["_pktgen"](rig, frame, 1, 6000000, ratep))
    # Replace system imports, retaining the complete generated script.
    script.body = [node for node in script.body if not isinstance(node, (ast.Import, ast.ImportFrom))]

    def counters(*args, **kwargs):
        assert int(queue.read_text()) == (cap or 0)
        return "NIC statistics:\n tx_pkts_nic: 6000000\n tx_packets: 6000000\n tx_dropped: 0\n"

    exec(compile(script, "<guest-script-model>", "exec"),
         dict(json=json, Path=lambda path: tmp_path / path.lstrip("/"),
              subprocess=SimpleNamespace(run=lambda *a, **k: None, check_output=counters),
              time=SimpleNamespace(monotonic=lambda: 1)))
    assert started
    assert writes == ([cap] if cap else [])
