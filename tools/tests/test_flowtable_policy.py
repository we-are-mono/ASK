"""Policy replacement must revoke existing hardware without closing sockets."""
from __future__ import annotations

import asyncio
import copy
import json
import os

import pytest

from ask_orch.uart import Console
from _topology import TARGET_LAN_IF, TARGET_WAN_IF
from test_flowtable_connections import FLOWS, SPORT, by_key, connections, peer  # noqa: F401
from test_flowtable_offload import ARTIFACTS, DPORT, WAN_IP, console_command, console_python, rig  # noqa: F401
from test_flowtable_selective_neighbour import hardware, keys, warm
from test_flowtable_tcp import software_tx

pytestmark = pytest.mark.skipif(os.environ.get("ASK_FLOWTABLE_TESTS") != "1",
                               reason="requires an explicit experimental boot")
CONFIG = "/tmp/ask-flowtable-test.conf"

# The offload engine is the C ask-flowtable daemon; the hardware-drain fields it
# reports match the adapter's /proc header (see flowtable/src, cdx_flowtable).
DRAIN_FIELDS = ("bindings", "entries", "handle_refs", "neighbour_refs", "quarantine")


def candidate(r):
    """A policy dict in the historical schema. policy_to_conf() renders it to the
    daemon's native /etc/ask/offload.conf format; the dict form keeps the tests
    readable and lets a case mutate one field."""
    return {"version": 1, "enabled": True, "devices": [TARGET_LAN_IF, TARGET_WAN_IF],
            "scope": [{"source": r.lan_ip, "destination": WAN_IP,
                       "source_port": {"min": SPORT, "max": SPORT + 15}, "destination_port": DPORT}],
            "exclude": []}


def _portspec(value):
    return f"{value['min']}-{value['max']}" if isinstance(value, dict) else str(value)


def _match_to_tokens(m):
    """A scope/exclude dict -> a conf match line's tokens. Empty dict -> 'any'."""
    fields = {"protocol": "proto", "source": "saddr", "destination": "daddr",
              "reply_source": "reply-saddr", "reply_destination": "reply-daddr"}
    ports = {"source_port": "sport", "destination_port": "dport",
             "reply_source_port": "reply-sport", "reply_destination_port": "reply-dport"}
    parts = []
    for k, tok in fields.items():
        if k in m:
            parts.append(f"{tok} {m[k]}")
    for k, tok in ports.items():
        if k in m:
            parts.append(f"{tok} {_portspec(m[k])}")
    if "port" in m:
        parts.append(f"port {_portspec(m['port'])}")
    if "mark" in m:
        parts.append(f"mark {m['mark']['value']:#x}/{m['mark']['mask']:#x}")
    if "name" in m:
        parts.append(f"name {m['name']}")
    return " ".join(parts) if parts else "any"


def policy_to_conf(policy):
    """Render the dict policy to the daemon's line-based conf. Non-schema values
    (e.g. enabled as a string) pass through verbatim so a case can still probe a
    rejection; the daemon validates."""
    lines = [f"version {policy.get('version', 1)}"]
    enabled = policy.get("enabled", True)
    lines.append("enabled " + ("yes" if enabled is True else "no" if enabled is False else str(enabled)))
    lines.append("devices " + " ".join(policy["devices"]))
    for m in policy.get("scope", []):
        lines.append("scope " + _match_to_tokens(m))
    for m in policy.get("exclude", []):
        lines.append("exclude " + _match_to_tokens(m))
    return "\n".join(lines) + "\n"


async def expected_hash(con, policy):
    """The daemon's own fingerprint for a policy, from `check` — the tests no
    longer import a Python hash implementation to mirror. Written to a scratch
    path so it does not disturb whatever CONFIG currently holds."""
    scratch = "/tmp/ask-flowtable-hash.conf"
    await console_python(con, f"from pathlib import Path\nPath({scratch!r}).write_text({policy_to_conf(policy)!r})\n")
    result = await console_command(con, "/usr/sbin/ask-flowtable", "check", "--config", scratch)
    return json.loads(result["stdout"])["policy_hash"]


async def apply(con, policy, *, check=True, r=None):
    """Install a policy. Pass `r` to write the config over the agent instead of
    the console: the write is setup, never inside a measurement window, and the
    agent egresses on the WAN port where the software-TX bounds are loose --
    the tight ones are all on the LAN port, which agent traffic never touches.
    The CLI run stays on the console either way, because apply drains the
    datapath and an HTTP reply in flight across that drain can be lost."""
    text = policy_to_conf(policy)
    if r is not None:
        written = await r.target.fs_write(r.session, CONFIG, text)
        assert written["errno"] == 0, written
    else:
        await console_python(con, f"from pathlib import Path\nPath({CONFIG!r}).write_text({text!r})\n")
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
            await apply(con, policy, r=r)
            async with peer(r, flows) as p:
                await warm(r, p, [0, 1], "policy-initial-admission", flows)
                initial = await hardware(r, p, "policy-initial-hardware", flows)
                excluded = copy.deepcopy(policy)
                # 'port' matches either direction's tuple endpoints.
                excluded["exclude"] = [{"protocol": "udp", "port": SPORT}]
                result = await apply(con, excluded, r=r)
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
                assert (await installed(con))["policy_hash"] == await expected_hash(con, excluded)
                r.record("policy-exclusion-revoked-existing-udp", {"apply": result, "state": accelerated,
                         "udp": udp, "tcp": tcp, "udp_software_tx": tx, "tcp_software_tx": tcp_tx})

                # Schema errors leave the installed generation untouched.
                rejected = await apply(con, {**policy, "enabled": "maybe"}, check=False, r=r)
                assert rejected["rc"] != 0 and "yes or no" in rejected["stdout"], rejected
                held = await r.state()
                assert held["installs"] == accelerated["installs"] and held["deletes"] == accelerated["deletes"]
                assert (await installed(con))["policy_hash"] == await expected_hash(con, excluded)
                await apply(con, policy, r=r)
                await warm(r, p, [0, 1], "policy-exclusion-removed", flows)
                await hardware(r, p, "policy-restored-hardware", flows)

                # A valid configuration with unsupported hardware ports is
                # rejected after retiring the old policy. Both sockets survive.
                unsupported = {**policy, "devices": [TARGET_LAN_IF, "lo"]}
                rejected = await apply(con, unsupported, check=False, r=r)
                assert rejected["rc"] != 0, rejected
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
            result = await apply(con, candidate(r), check=False, r=r)
            assert result["rc"] != 0 and "another flowtable" in result["stdout"], result
            after = await r.state()
            assert after["bindings"] == 2 and after["rearms"] == before["rearms"]
            await r.delete_table()
            await r.nft("table inet ask_flowtable { comment \"foreign\"; }")
            try:
                result = await apply(con, candidate(r), check=False, r=r)
                assert result["rc"] != 0 and "ownership marker" in result["stdout"], result
                listed = await console_command(con, "nft", "-j", "list", "table", "inet", "ask_flowtable")
                assert any(t.get("table", {}).get("comment") == "foreign" for t in json.loads(listed["stdout"])["nftables"])
                r.record("policy-foreign-ownership-preserved", result)
            finally:
                await console_command(con, "nft", "delete", "table", "inet", "ask_flowtable")
        finally:
            await console_command(con, "rm", "-f", CONFIG)
