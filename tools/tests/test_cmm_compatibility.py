"""Paced legacy-mode proof using hardware entries and software packet counts."""
import asyncio
import json
import os
from pathlib import Path
import re
from types import SimpleNamespace

import pytest

from ask_orch.counters import kernel_rx_packets
from ask_orch.uart import Console
from _topology import LAN_NIC, TARGET_LAN_IF, lan_run_python
from test_flowtable_offload import console_command, read
from test_flowtable_tcp import cpu, cpu_delta

pytestmark = pytest.mark.skipif(os.environ.get("ASK_CMM_COMPAT") != "1",
                               reason="requires an explicit default CMM boot")


def count(table):
    assert table["rc"] == 0, table
    match = re.search(r"Total Connection Entries:\s*(\d+)", table["stdout"])
    if match:
        return int(match.group(1))
    assert not table["stdout"] and table["stderr"].strip() == "ERROR: FPP IPV4 CONNTRACK table empty", table
    return 0


async def test_cmm_paced_tcp_compatibility(aiohttp_session, target_agent, lan, splat_window):
    r = SimpleNamespace(target=target_agent, session=aiohttp_session)
    wan = os.environ.get("ASK_WAN_IPERF_IP", "10.0.0.141")
    port = 5251
    artifacts = Path(os.environ.get("ASK_CMM_ARTIFACTS", "/tmp/ask-cmm-compatibility"))
    artifacts.mkdir(parents=True, exist_ok=True)
    assert (await read(r.target, r.session, "/sys/module/cdx/parameters/offload_owner")).strip() == "cmm"
    names = {s.split()[0] for s in (await read(r.target, r.session, "/proc/modules")).splitlines()}
    assert {"cdx", "fci", "auto_bridge"} <= names and "ask_flowtable" not in names, names
    pid = int((await read(r.target, r.session, "/var/run/cmm.pid")).strip())
    assert (await read(r.target, r.session, f"/proc/{pid}/cmdline")).startswith("/usr/bin/cmm\0")
    with Console.target(log_path=str(artifacts / "cmm-policy-hook-uart.log")) as con:
        await asyncio.to_thread(con.login, "root", None)
        await console_command(con, "/etc/init.d/ask-flowtable", "start")
        # The experimental hook cannot start a second flow owner in CMM mode.
        absent = await console_command(con, "test", "-e", "/sys/module/ask_flowtable", check=False)
        assert absent["rc"] == 1

    server = await asyncio.create_subprocess_exec("iperf3", "-s", "-1", "-B", wan, "-p", str(port), "-J",
                                                 stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    result = {}
    try:
        before = await cpu(r)
        await asyncio.sleep(4)
        assert server.returncode is None, "dedicated iperf server failed to start"
        result["idle_cpu"] = cpu_delta(before, await cpu(r))
        result["before"] = await r.target.cmm_query(r.session, "connections")
        rx_before = await kernel_rx_packets(r.target, r.session, TARGET_LAN_IF)
        cpu_before = await cpu(r)
        script = f'''
import json, subprocess
link = subprocess.check_output(['ethtool', {LAN_NIC!r}], text=True)
assert 'Link detected: yes' in link, link
argv = ['iperf3', '-c', {wan!r}, '-p', {str(port)!r}, '-b', '800M', '-t', '5', '-J']
r = subprocess.run(argv, capture_output=True, text=True, timeout=20)
print(json.dumps(dict(link=link, argv=argv, rc=r.returncode, stdout=r.stdout, stderr=r.stderr)))
'''
        traffic = asyncio.create_task(lan_run_python(lan, script, timeout=25, label="cmm_compatibility"))
        try:
            await asyncio.sleep(2)
            result["during"] = await r.target.cmm_query(r.session, "connections")
            output = await traffic
        finally:
            await traffic
        assert output.rc == 0, output.stdout
        result["client"] = json.loads(output.stdout)
        assert result["client"]["rc"] == 0, result["client"]
        result["cpu"] = cpu_delta(cpu_before, await cpu(r))
        result["software_rx"] = await kernel_rx_packets(r.target, r.session, TARGET_LAN_IF) - rx_before
        out, err = await asyncio.wait_for(server.communicate(), 5)
        assert server.returncode == 0, err
        result["server"] = json.loads(out)
        report = json.loads(result["client"]["stdout"])
        result["received_bytes"] = report["end"]["sum_received"]["bytes"]
        assert result["received_bytes"] == result["server"]["end"]["sum_received"]["bytes"]
        result["data_frame_lower_bound"] = result["received_bytes"] // 1500
        assert count(result["during"]) > count(result["before"]), result
        assert result["data_frame_lower_bound"] > 1000
        assert 0 <= result["software_rx"] < result["data_frame_lower_bound"] // 10, result
    finally:
        if server.returncode is None:
            server.kill()
        await server.wait()
        (artifacts / "cmm-paced-tcp.json").write_text(json.dumps(result, indent=2) + "\n")
