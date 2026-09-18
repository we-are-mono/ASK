"""Both halves of a tunnel are carried by the classifier, not by the CPU.

Step 5 proved the outbound half: a forwarded flow whose policy encrypts it is
installed with its SA named, and the frames reach SEC without the driver's
transmit function. It proved it against a bench whose *return* direction was
plain, and that turned out to be load-bearing in a way nothing intended --
see below. This is the bidirectional case, which is what a tunnel actually is.

Inbound is not the mirror of outbound, and the asymmetry is the whole subject:

  - an arriving ESP frame's 5-tuple is the tunnel's, so it cannot match a flow
    entry at all. The inbound SA's own classifier entry steers it to SEC on the
    SPI, which already worked before this test existed;
  - what SEC hands back is the decrypted inner frame, and it re-enters
    classification on the **offline port**, not on the physical port it
    arrived by. An entry keyed on the physical port is therefore dead: it is
    installed, it is counted, and it never matches a single frame.

So the oracle is the reverse direction's own packet counter. Before this
increment it read zero for the whole transfer while the echo still worked,
because every decrypted frame crossed the CPU and was forwarded in software.

Two further things this asserts, each of which was a separate defect:

  - **the flow is offered to the driver at all.** A transformed destination
    reaches the flowtable as FLOW_OFFLOAD_XMIT_XFRM, and upstream's
    flow_offload_eth_src()/_dst() refuse that transmit type outright, which
    fails nf_flow_offload_alloc() before any driver callback runs. In a
    one-way-tunnelled bench the flow is created from the plain reply packet,
    both tuples come out NEIGH and nothing notices. In a real tunnel the reply
    carries a sec_path, nft_flow_offload_skip() declines it, and the only
    packet left to create the flow is the encrypted one -- so the whole
    connection silently fell back to software, both directions.
  - **`tx todec` stays at zero.** That counter tracks frames the *software*
    path handed to SEC. Inbound decryption is done by the classifier, so it
    must not move at all; if it tracks the transfer, the ESP is being punted
    to the CPU and decrypted from `xfrm_input()`.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import socket
import textwrap
import time

import pytest

from _topology import LAN_NIC, TARGET_LAN_IF, TARGET_WAN_IF

# Ownership is exclusive and fixed for the boot: in a CMM boot the adapter is
# never loaded, so the ports advertise no esp-hw-offload and there is no
# /proc/cdx_flowtable to read. These assert the flowtable owner's behaviour and
# have nothing to talk to otherwise, so they take the same opt-in gate the
# test_flowtable_* files do rather than failing a legacy run.
pytestmark = pytest.mark.skipif(os.environ.get("ASK_FLOWTABLE_TESTS") != "1",
                                reason="requires an explicit flowtable boot")

LAN_INNER = "198.18.96.2"
PORT = 48901
REQID_OUT, REQID_IN = "48901", "48902"
COUNT = 60
# Packets that legitimately travel in software before the entries exist.
# A bidirectional tunnel needs more of these than a plain flow: conntrack must
# confirm, and only an original-direction packet can create the flow at all --
# every reply carries a sec_path and nft_flow_offload_skip() declines it. What
# separates the fast path from the slow one is that the software counter stops
# after this handful rather than tracking the whole transfer, not its exact
# value, so the bound is generous and the assertions below lean on "stopped".
SETUP = 5
CIPHER = "0x" + "a5" * 16
AUTH = "0x" + "5a" * 32
TABLE = "ask_ipsec_inbound"


def quoted(*argv):
    """Shell-safe join: algorithm names carry parentheses."""
    import shlex
    return " ".join(shlex.quote(str(word)) for word in argv)


def crypto(reqid):
    return ["mode", "tunnel", "reqid", reqid,
            "enc", "cbc(aes)", CIPHER,
            "auth-trunc", "hmac(sha256)", AUTH, "128"]


async def sec_counter(session, agent, iface, name):
    """`tx toenc`/`tx todec` across CPUs: frames the software path gave SEC."""
    result = await agent.exec_cmd(session, ["ethtool", "-S", iface])
    assert result["rc"] == 0, result
    return sum(int(line.split(":")[1])
               for line in result["stdout"].splitlines()
               if line.strip().startswith(f"{name} [CPU"))


async def flows(session, agent):
    """The adapter's installed directions, as dicts of its own key=value row."""
    result = await agent.fs_read(session, "/proc/cdx_flowtable")
    text = binascii.unhexlify(result.get("content_hex") or b"").decode(errors="replace")
    return [dict(field.split("=", 1) for field in line.split()[1:] if "=" in field)
            for line in text.splitlines() if line.startswith("flow ")]


@pytest.mark.usefixtures("splat_window")
async def test_tunnel_carries_both_directions_in_hardware(
    aiohttp_session, target_agent, lan, record_property,
):
    session = aiohttp_session
    spi_out = 0x0A960000 | (int.from_bytes(os.urandom(2), "big") or 1)
    spi_in = spi_out ^ 0x8000

    async def dut(*argv, check=True):
        result = await target_agent.exec_cmd(session, list(argv))
        if check:
            assert result["rc"] == 0, (argv, result)
        return result

    lan_outer = next(
        field.split("/")[0]
        for field in lan.run(f"ip -o -4 addr show dev {LAN_NIC}", timeout=20).stdout.split()
        if field.count(".") == 3 and "/" in field)
    dut_lan = next(
        address["local"]
        for interface in json.loads(
            (await dut("ip", "-j", "-4", "addr", "show", "dev", TARGET_LAN_IF))["stdout"])
        for address in interface["addr_info"] if address["family"] == "inet")
    here = os.environ["ASK_WAN_IPERF_IP"]
    record_property("tunnel", f"{dut_lan} <-> {lan_outer}, inner {here} <-> {LAN_INNER}")

    # The outbound SA carries here -> LAN_INNER; the inbound one carries the
    # replies. They are separate states with separate SPIs, exactly as an IKE
    # exchange installs them, and only the DUT's pair is offloaded.
    out_state = ("src", dut_lan, "dst", lan_outer, "proto", "esp", "spi", hex(spi_out))
    in_state = ("src", lan_outer, "dst", dut_lan, "proto", "esp", "spi", hex(spi_in))
    fwd_sel = ("src", here + "/32", "dst", LAN_INNER + "/32")
    rev_sel = ("src", LAN_INNER + "/32", "dst", here + "/32")
    fwd_tmpl = ("tmpl", "src", dut_lan, "dst", lan_outer, "proto", "esp",
                "mode", "tunnel", "reqid", REQID_OUT, "level", "required")
    rev_tmpl = ("tmpl", "src", lan_outer, "dst", dut_lan, "proto", "esp",
                "mode", "tunnel", "reqid", REQID_IN, "level", "required")

    echo = f"/tmp/ask_ipsec_inbound_echo_{os.getpid()}.py"
    cleanup = []
    try:
        # --- the LAN VM: both halves of the tunnel in software, and the echo
        lan.run("ip xfrm state flush; ip xfrm policy flush", timeout=25)
        lan.run(f"ip address add {LAN_INNER}/32 dev lo 2>/dev/null; true", timeout=20)
        lan.run("ip xfrm state add "
                + quoted(*out_state, *crypto(REQID_OUT), "replay-window", "32"), timeout=25)
        lan.run("ip xfrm state add "
                + quoted(*in_state, *crypto(REQID_IN), "replay-window", "32"), timeout=25)
        lan.run("ip xfrm policy add " + quoted(*fwd_sel, "dir", "in", *fwd_tmpl), timeout=25)
        lan.run("ip xfrm policy add " + quoted(*rev_sel, "dir", "out", *rev_tmpl), timeout=25)
        cleanup.append(lambda: lan.run(
            "ip xfrm state flush; ip xfrm policy flush; "
            f"ip address del {LAN_INNER}/32 dev lo 2>/dev/null; "
            f"pkill -f {echo}; rm -f {echo}; true", timeout=25))
        script = textwrap.dedent(f"""
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(({LAN_INNER!r}, {PORT}))
            while True:
                data, peer = sock.recvfrom(2048)
                sock.sendto(data, peer)
        """)
        lan.run("echo " + base64.b64encode(script.encode()).decode()
                + f" | base64 -d > {echo}", timeout=20)
        lan.run(f"setsid python3 {echo} >/dev/null 2>&1 & sleep 1", timeout=25)

        # --- the DUT: flowtable, route, both SAs offloaded, all three policies
        await dut("nft", "delete", "table", "inet", TABLE, check=False)
        await dut("nft", "delete", "table", "inet", "ask", check=False)
        await dut("ip", "xfrm", "policy", "flush")
        await dut("ip", "xfrm", "state", "flush")
        await dut("nft", f'''table inet {TABLE} {{
 flowtable fast {{ hook ingress priority 0; devices = {{ {TARGET_LAN_IF}, {TARGET_WAN_IF} }};
 flags offload; }}
 chain forward {{ type filter hook forward priority 0; policy accept;
 ip protocol udp flow add @fast
 }}
}}''')
        cleanup.append(lambda: dut("nft", "delete", "table", "inet", TABLE, check=False))
        await dut("ip", "route", "replace", LAN_INNER + "/32", "via", lan_outer)
        cleanup.append(lambda: dut("ip", "route", "del", LAN_INNER + "/32", check=False))
        await dut("ip", "xfrm", "state", "add", *out_state, *crypto(REQID_OUT),
                  "offload", "packet", "dev", TARGET_LAN_IF, "dir", "out")
        await dut("ip", "xfrm", "state", "add", *in_state, *crypto(REQID_IN),
                  "offload", "packet", "dev", TARGET_LAN_IF, "dir", "in")
        await dut("ip", "xfrm", "policy", "add", *fwd_sel, "dir", "out", *fwd_tmpl,
                  "offload", "packet", "dev", TARGET_LAN_IF)
        await dut("ip", "xfrm", "policy", "add", *rev_sel, "dir", "in", *rev_tmpl,
                  "offload", "packet", "dev", TARGET_LAN_IF)
        # A decrypted packet that is *forwarded* is checked against the forward
        # policy, not the inbound one, and a tunnel-mode sec_path with no
        # matching fwd policy is rejected outright. This is ordinary
        # IPsec-gateway configuration rather than anything about the offload,
        # but without it the replies never reach the forward chain at all.
        await dut("ip", "xfrm", "policy", "add", *rev_sel, "dir", "fwd", *rev_tmpl)
        cleanup.append(lambda: dut("ip", "xfrm", "policy", "flush", check=False))
        cleanup.append(lambda: dut("ip", "xfrm", "state", "flush", check=False))
        # A conntrack entry surviving an earlier run carries IPS_OFFLOAD and is
        # never offered to the flowtable again, so the flow would be judged on
        # the previous scenario's decision rather than on this one's.
        await dut("conntrack", "-F", check=False)

        os.system(f"ip route replace {LAN_INNER}/32 via "
                  + os.environ.get("ASK_TARGET_IP", "10.0.0.62") + " >/dev/null 2>&1")

        toenc_before = await sec_counter(session, target_agent, TARGET_LAN_IF, "tx toenc")
        todec_before = await sec_counter(session, target_agent, TARGET_LAN_IF, "tx todec")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        echoed = 0
        for _ in range(COUNT):
            sock.sendto(b"y" * 512, (LAN_INNER, PORT))
            try:
                sock.recv(2048)
                echoed += 1
            except OSError:
                pass
            time.sleep(0.02)
        sock.close()
        toenc_after = await sec_counter(session, target_agent, TARGET_LAN_IF, "tx toenc")
        todec_after = await sec_counter(session, target_agent, TARGET_LAN_IF, "tx todec")
        rows = await flows(session, target_agent)

        forward = [row for row in rows if row.get("out") == TARGET_LAN_IF]
        reverse = [row for row in rows if row.get("out") == TARGET_WAN_IF]
        record_property("echoed", echoed)
        record_property("toenc_delta", toenc_after - toenc_before)
        record_property("todec_delta", todec_after - todec_before)
        record_property("flows", "; ".join(
            f"{r.get('in')}->{r.get('out')} sa={r.get('sa')} in_sa={r.get('in_sa')} "
            f"packets={r.get('packets')}" for r in rows))

        assert echoed >= COUNT - 2, f"only {echoed} of {COUNT} echoed: the tunnel did not carry"
        # Both directions installed. Before the transformed destination was
        # admitted this list was empty: the rule allocation failed upstream and
        # the driver was never asked, so neither half was offloaded.
        assert forward, (
            "the encrypted direction was not offloaded, so nothing was offered "
            f"to the driver for this flow at all: {rows}")
        assert forward[0]["sa"] != "0", (
            "the encrypted direction was offloaded with no SA, which forwards in "
            f"hardware what the policy says to encrypt: {forward[0]}")
        assert reverse, f"the decrypted direction was not offloaded: {rows}"
        assert reverse[0]["in_sa"] != "0", (
            "the decrypted direction names no inbound SA, so its entry was keyed "
            "on the physical port and cannot match a frame that SEC re-classifies "
            f"on the offline port: {reverse[0]}")

        # The counter that separates a live entry from a dead one. This read
        # zero for the whole transfer while the echo still worked.
        assert int(reverse[0]["packets"]) >= COUNT - SETUP, (
            f"the decrypted direction matched {reverse[0]['packets']} of {COUNT} "
            "frames; its entry exists but the hardware is not reaching it")
        assert int(forward[0]["packets"]) >= COUNT - SETUP, (
            f"the encrypted direction matched {forward[0]['packets']} of {COUNT}")

        # A handful, not COUNT: the packets that travelled before the entry
        # existed. The distinction this makes is qualitative -- on the slow
        # path this counter tracks the transfer one for one.
        assert toenc_after - toenc_before <= SETUP, (
            f"{toenc_after - toenc_before} frames reached SEC through the software "
            "path; the classifier should have steered all but the first")
        # Zero, not one: inbound steering is on the SPI and needs no first
        # packet through the stack, because the SA's own classifier entry is
        # installed before any frame arrives.
        assert todec_after - todec_before == 0, (
            f"{todec_after - todec_before} ESP frames were decrypted from the "
            "software path; the classifier should have steered every one")
    finally:
        for undo in reversed(cleanup):
            try:
                result = undo()
                if hasattr(result, "__await__"):
                    await result
            except Exception:
                pass
