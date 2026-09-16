"""Policy replacement must revoke existing hardware without closing sockets."""
from __future__ import annotations

import asyncio
import copy
import json
import os

import pytest

from ask_orch.uart import Console
from _topology import TARGET_LAN_IF, TARGET_WAN_IF
from ask_flowtable import DRAIN_FIELDS, policy_hash
from test_flowtable_connections import FLOWS, SPORT, by_key, connections, peer  # noqa: F401
from test_flowtable_offload import ARTIFACTS, DPORT, WAN_IP, console_command, console_python, rig  # noqa: F401
from test_flowtable_selective_neighbour import hardware, keys, warm
from test_flowtable_tcp import software_tx

pytestmark = pytest.mark.skipif(os.environ.get("ASK_FLOWTABLE_TESTS") != "1",
                               reason="requires an explicit experimental boot")
CONFIG = "/tmp/ask-flowtable-test.json"


def candidate(r):
    return {"version": 1, "enabled": True, "devices": [TARGET_LAN_IF, TARGET_WAN_IF],
            "scope": [{"source": r.lan_ip, "destination": WAN_IP,
                       "source_port": {"min": SPORT, "max": SPORT + 15}, "destination_port": DPORT}],
            "exclude": []}


async def apply(con, policy, *, check=True):
    await console_python(con, f"from pathlib import Path\nPath({CONFIG!r}).write_text({json.dumps(policy)!r})\n")
    result = await console_command(con, "/usr/sbin/ask-flowtable", "apply", "--config", CONFIG,
                                   check=check, timeout=40)
    if check:
        result = json.loads(result["stdout"])
        assert all(result["drained"][k] == 0 for k in DRAIN_FIELDS), result
    return result


async def stop(con):
    result = await console_command(con, "/usr/sbin/ask-flowtable", "stop", timeout=40)
    state = json.loads(result["stdout"])["drained"]
    assert all(state[k] == 0 for k in DRAIN_FIELDS), state


async def installed(con):
    result = await console_command(con, "/usr/sbin/ask-flowtable", "status")
    return json.loads(result["stdout"])


async def test_flowtable_policy_revokes_live_connections(connections):
    r = connections
    flows = [{**flow, "lan": r.lan_ip} for flow in FLOWS[:2]]
    policy = candidate(r)
    await r.delete_table()
    with Console.target(log_path=str(ARTIFACTS / "policy-uart.log")) as con:
        await asyncio.to_thread(con.login, "root", None)
        try:
            await apply(con, policy)
            async with peer(r, flows) as p:
                await warm(r, p, [0, 1], "policy-initial-admission", flows)
                initial = await hardware(r, p, "policy-initial-hardware", flows)
                excluded = copy.deepcopy(policy)
                # 'port' matches either direction's tuple endpoints.
                excluded["exclude"] = [{"protocol": "udp", "port": SPORT}]
                result = await apply(con, excluded)
                assert result["drained"]["deletes"] == initial["deletes"] + 4, result
                for _ in range(8):
                    await p.batch([0, 1], 128, 0.01)
                    state = await r.state()
                    if state["entries"] == 2:
                        break
                assert by_key(state).keys() == keys([1], flows), state
                # Count software forwarding independently of the TCP stream.
                before_tx = await software_tx(r)
                udp = await p.batch([0], 256, 0.005)
                after_tx = await software_tx(r)
                tx = {d: after_tx[d] - before_tx[d] for d in before_tx}
                assert all(value >= 256 for value in tx.values()), tx
                state = await r.state()
                assert by_key(state).keys() == keys([1], flows), state
                before_tcp = await software_tx(r)
                tcp = await p.batch([1], 256, 0.015625)
                after_tcp, accelerated = await software_tx(r), await r.state()
                tcp_tx = {d: after_tcp[d] - before_tcp[d] for d in before_tcp}
                assert tcp_tx[TARGET_LAN_IF] <= 64 and tcp_tx[TARGET_WAN_IF] <= 512, tcp_tx
                for key in keys([1], flows):
                    old, new = by_key(state)[key], by_key(accelerated)[key]
                    assert old["cookie"] == new["cookie"]
                    assert int(new["packets"]) - int(old["packets"]) >= tcp[1]["bytes"] // 1500
                assert (await installed(con))["policy_hash"] == policy_hash(excluded)
                r.record("policy-exclusion-revoked-existing-udp", {"apply": result, "state": accelerated,
                         "udp": udp, "tcp": tcp, "udp_software_tx": tx, "tcp_software_tx": tcp_tx})

                # Schema errors leave the installed generation untouched.
                rejected = await apply(con, {**policy, "enabled": "yes"}, check=False)
                assert rejected["rc"] != 0 and "expected boolean" in rejected["stdout"], rejected
                held = await r.state()
                assert held["installs"] == accelerated["installs"] and held["deletes"] == accelerated["deletes"]
                assert (await installed(con))["policy_hash"] == policy_hash(excluded)
                await apply(con, policy)
                await warm(r, p, [0, 1], "policy-exclusion-removed", flows)
                await hardware(r, p, "policy-restored-hardware", flows)

                # A valid configuration with unsupported hardware ports is
                # rejected after retiring the old policy. Both sockets survive.
                unsupported = {**policy, "devices": [TARGET_LAN_IF, "lo"]}
                rejected = await apply(con, unsupported, check=False)
                assert rejected["rc"] != 0 and "acceleration disabled" in rejected["stdout"], rejected
                status = await installed(con)
                assert not status["policy_installed"] and not status["admission_ready"], status
                assert all(status["backend"][k] == 0 for k in DRAIN_FIELDS), status
                before_tx = await software_tx(r)
                reports = await p.batch([0, 1], 128, 0.01)
                after_tx = await software_tx(r)
                tx = {d: after_tx[d] - before_tx[d] for d in before_tx}
                assert all(value >= 128 for value in tx.values()), tx
                r.record("policy-failed-candidate-software", {"rejection": rejected, "status": status,
                                                            "transfers": reports, "software_tx": tx})
        finally:
            await stop(con)
            await console_command(con, "rm", "-f", CONFIG)


async def test_flowtable_policy_preserves_foreign_table(connections):
    r = connections
    with Console.target(log_path=str(ARTIFACTS / "policy-foreign-uart.log")) as con:
        await asyncio.to_thread(con.login, "root", None)
        try:
            # The fixture's differently named flowtable owns the backend.
            before = await r.state()
            result = await apply(con, candidate(r), check=False)
            assert result["rc"] != 0 and "another flowtable" in result["stdout"], result
            after = await r.state()
            assert after["bindings"] == 2 and after["rearms"] == before["rearms"]
            await r.delete_table()
            await r.nft("table inet ask_flowtable { comment \"foreign\"; }")
            try:
                result = await apply(con, candidate(r), check=False)
                assert result["rc"] != 0 and "ownership marker" in result["stdout"], result
                listed = await console_command(con, "nft", "-j", "list", "table", "inet", "ask_flowtable")
                assert any(t.get("table", {}).get("comment") == "foreign" for t in json.loads(listed["stdout"])["nftables"])
                r.record("policy-foreign-ownership-preserved", result)
            finally:
                await console_command(con, "nft", "delete", "table", "inet", "ask_flowtable")
        finally:
            await console_command(con, "rm", "-f", CONFIG)
