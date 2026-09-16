"""Run the TCP lifetime proofs with a forced native SNAT address and port."""
import asyncio
import json
import os

import pytest
import pytest_asyncio

from ask_orch.uart import Console
from _topology import TARGET_LAN_IF, TARGET_WAN_IF
from test_flowtable_offload import ARTIFACTS, DPORT, SPORT, TABLE, WAN_IP, command, console_command, rig  # noqa: F401
from test_flowtable_policy import CONFIG, apply, stop
from test_flowtable_tcp import (
    test_flowtable_tcp_transfer_expiry_fin as _fin,
    test_flowtable_tcp_retransmit_withdraw_rst as _rst,
)

pytestmark = [
    pytest.mark.skipif(os.environ.get("ASK_FLOWTABLE_TESTS") != "1",
                       reason="requires an explicit experimental boot"),
    pytest.mark.parametrize("rig", ["tcp"], indirect=True),
]


@pytest_asyncio.fixture
async def tcp_snat(rig, request):
    r = rig
    addresses = json.loads((await command(r.target, r.session, "ip", "-j", "-4", "addr", "show",
                                         "dev", TARGET_WAN_IF))["stdout"])
    external = next(a["local"] for a in addresses[0]["addr_info"] if a["family"] == "inet")
    port = SPORT + 1024
    r.tcp_remote = (external, port)
    policy = {"version": 1, "enabled": True, "devices": [TARGET_LAN_IF, TARGET_WAN_IF],
              "scope": [{"protocol": "tcp", "source": r.lan_ip, "destination": WAN_IP,
                         "source_port": SPORT, "destination_port": DPORT}], "exclude": []}
    nat_table = "ask_tcp_snat_test"
    kind = getattr(request, "param", "snat")
    assert kind in {"snat", "masquerade"}
    translation = f"snat to {external}:{port}" if kind == "snat" else f"masquerade to :{port}"
    nat = (f"table ip {nat_table} {{ chain postrouting {{ type nat hook postrouting priority 90; "
           f"ip saddr {r.lan_ip} ip daddr {WAN_IP} tcp sport {SPORT} tcp dport {DPORT} "
           f"{translation}; }}; }}")
    table, delete_table, state = r.table, r.delete_table, r.state
    with Console.target(log_path=str(ARTIFACTS / "tcp-snat-uart.log")) as con:
        await asyncio.to_thread(con.login, "root", None)
        existing = await console_command(con, "nft", "list", "table", "ip", nat_table, check=False)
        assert existing["rc"] != 0, existing
        await console_command(con, "nft", nat)

        async def create():
            # Flag counters remain at the forward hook. The production policy
            # owns the flowtable, including stop/reapply during the same socket.
            await r.nft(f"table inet {TABLE} {{ chain forward {{ type filter hook forward priority 0; policy accept; }}; }}")
            await apply(con, policy)

        async def remove():
            await stop(con)
            return await delete_table()

        # The adapter's error count is cumulative for the boot and never reset,
        # so this fixture's floor is whatever earlier tests already accounted
        # for. Only the three current-state fields are absolute.
        baseline = (await state())["errors"]

        async def checked_state():
            result = await state()
            assert result["fatal"] == result["quarantine"] == result["invalidated"] == 0, result
            assert result["errors"] == baseline, (result, baseline)
            local, remote, mapped = f"{r.lan_ip}:{SPORT}", f"{WAN_IP}:{DPORT}", f"{external}:{port}"
            expected = {TARGET_LAN_IF: (local, remote, mapped, remote, WAN_IP),
                        TARGET_WAN_IF: (remote, mapped, remote, local, r.lan_ip)}
            for row in result["flows"]:
                assert row["proto"] == "6" and row["mtu"] == "1200", result
                assert tuple(row[k] for k in ("src", "dst", "new_src", "new_dst", "nexthop")) == expected[row["in"]], result
            return result

        r.table, r.delete_table, r.state = create, remove, checked_state
        try:
            yield r
        finally:
            r.table, r.delete_table, r.state = table, delete_table, state
            try:
                await stop(con)
            finally:
                try:
                    await console_command(con, "nft", "delete", "table", "ip", nat_table)
                finally:
                    await console_command(con, "rm", "-f", CONFIG)


async def test_flowtable_tcp_snat_expiry_fin(tcp_snat):
    await _fin(tcp_snat)


async def test_flowtable_tcp_snat_retransmit_withdraw_rst(tcp_snat):
    await _rst(tcp_snat)
