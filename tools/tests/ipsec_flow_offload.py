"""A tunnelled flow is steered to SEC by the classifier, not by the stack.

Step 4 proved SEC can encrypt: every packet crossed the CPU, was handed to the
engine, and came back. This is the fast path, where the classifier entry itself
names the SA and the frames never reach the driver's transmit function at all.

The oracle that separates the two is `tx toenc`, which counts frames the
*software* path handed to SEC. On the slow path it advances once per packet. On
the fast path it advances exactly **once** -- for the packet that travelled
before the hardware entry existed -- and then stops while the rest of the
transfer goes through. Throughput cannot tell the two apart; this can.

The tunnel runs between the DUT and the LAN VM, and the traffic is *forwarded*
by the DUT rather than generated on it, which is the shape a gateway actually
has. The test host is the far end of the forwarded flow, not of the tunnel.

The connection is offered to hardware by its first reply, which is also the
first packet the DUT sends the test host, so the DUT's neighbour entry for the
host decides whether that offer can be built at all. `resolved` warms the entry
first. `resolving` holds the DUT's ARP requests back until the first offer has
failed: while a policy is configured no software refresh offers the flow again,
so only the generation's retirement (kernel patch 140) brings the connection
into hardware before its flow expires.

Also asserted here, because it is what this increment exists to prevent: a flow
whose policy resolves to no usable SA must be refused, never installed in the
clear. Admission used to ask the *destination* whether it was transformed
(`dst_xfrm`), which is never true for a forwarded flow -- those are routed
plainly and transformed later at POSTROUTING -- so a flow under a `level
required` policy was offloaded and forwarded unencrypted.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import textwrap
import time

import pytest

from ask_orch.artifacts import record
from ask_orch.commands import read
from _topology import LAN_NIC, TARGET_LAN_IF, TARGET_WAN_IF

LAN_INNER = "198.18.88.2"
PORT = 48801
REQID = 48801
COUNT = 60
CIPHER = b"\xa5" * 16
AUTH = b"\x5a" * 32
TABLE = "ask_ipsec_flow"
ARP_TABLE = "ask_ipsec_arp"
# Well inside the 30 s a UDP flow lives without a refresh: an offer that is
# never made again leaves the connection in software that long.
ADMISSION_S = 10


def quoted(*argv):
    """Shell-safe join: algorithm names carry parentheses."""
    import shlex
    return " ".join(shlex.quote(str(word)) for word in argv)


async def toenc(session, agent, iface):
    result = await agent.exec_cmd(session, ["ethtool", "-S", iface])
    assert result["rc"] == 0, result
    return sum(int(line.split(":")[1])
               for line in result["stdout"].splitlines()
               if line.strip().startswith("tx toenc [CPU"))


async def flows(session, agent):
    """The adapter's installed directions, as dicts of its own key=value row."""
    text = await read(agent, session, "/proc/ask_flowtable/flows")
    rows = []
    for line in text.splitlines():
        if not line.startswith("flow "):
            continue
        rows.append(dict(field.split("=", 1)
                         for field in line.split()[1:] if "=" in field))
    return rows


async def hw_invalid_retired(session, agent):
    """Flows GC has retired for an invalid hardware handle, on every CPU."""
    result = await agent.fs_read(session, "/proc/net/stat/nf_flowtable", max_bytes=8192)
    lines = bytes.fromhex(result.get("content_hex", "")).decode().splitlines()
    column = lines[0].split().index("gc_hw_invalid")
    return sum(int(line.split()[column]) for line in lines[1:] if line.strip())


def exchange(sock, count):
    """Datagrams the echo answered, of `count` sent one at a time."""
    echoed = 0
    for _ in range(count):
        sock.sendto(b"y" * 512, (LAN_INNER, PORT))
        try:
            sock.recv(2048)
            echoed += 1
        except OSError:
            pass
        time.sleep(0.02)
    return echoed


@pytest.mark.usefixtures("splat_window")
@pytest.mark.parametrize("neighbour", ["resolved", "resolving"])
async def test_tunnelled_flow_is_steered_to_sec(
    aiohttp_session, target_agent, lan, neighbour,
):
    session = aiohttp_session
    spi = 0x0A880000 | (int.from_bytes(os.urandom(2), "big") or 1)
    properties = {}

    def note(key, value):
        # The run's figures, kept in its artifacts: the suite's xunit2
        # report has no per-test properties.
        properties[key] = value
        record("properties", properties)

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
    note("tunnel", f"{dut_lan} <-> {lan_outer}, inner {here} -> {LAN_INNER}")

    state = ("src", dut_lan, "dst", lan_outer, "proto", "esp", "spi", hex(spi))
    crypto = ("mode", "tunnel", "reqid", str(REQID),
              "enc", "cbc(aes)", "0x" + CIPHER.hex(),
              "auth-trunc", "hmac(sha256)", "0x" + AUTH.hex(), "128")
    selector = ("src", here + "/32", "dst", LAN_INNER + "/32")
    tmpl = ("tmpl", "src", dut_lan, "dst", lan_outer, "proto", "esp",
            "mode", "tunnel", "reqid", str(REQID), "level", "required")

    results = f"/tmp/ask_ipsec_flow_{os.getpid()}.json"
    echo = f"/tmp/ask_ipsec_echo_{os.getpid()}.py"
    cleanup = []
    try:
        # --- the LAN VM: tunnel far end, and the echo the flow talks to
        lan.run("ip xfrm state flush; ip xfrm policy flush", timeout=25)
        lan.run(f"ip address add {LAN_INNER}/32 dev lo 2>/dev/null; true", timeout=20)
        lan.run("ip xfrm state add " + quoted(*state, *crypto, "replay-window", "32"),
                timeout=25)
        lan.run("ip xfrm policy add " + quoted(*selector, "dir", "in", *tmpl), timeout=25)
        cleanup.append(lambda: lan.run(
            "ip xfrm state flush; ip xfrm policy flush; "
            f"ip address del {LAN_INNER}/32 dev lo 2>/dev/null; "
            f"pkill -f '^python3 {echo}$'; rm -f {echo} {echo}.log {results}; true", timeout=25))
        script = textwrap.dedent(f"""
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(({LAN_INNER!r}, {PORT}))
            sock.settimeout(120)
            print('READY', flush=True)
            while True:
                data, peer = sock.recvfrom(2048)
                sock.sendto(data, peer)
        """)
        compile(script, echo, "exec")
        staged = lan.run("echo " + base64.b64encode(script.encode()).decode()
                         + f" | base64 -d > {echo}", timeout=20)
        assert staged.rc == 0, staged.stdout
        started = lan.run(f"setsid python3 {echo} >{echo}.log 2>&1 & sleep 1; cat {echo}.log", timeout=25)
        assert started.rc == 0 and started.stdout.strip() == "READY", started.stdout

        # --- the DUT: offload the flowtable, then the SA and its policy
        # A flowtable binds its devices exclusively, so any table left behind
        # by another run would refuse this one's bind rather than fail loudly.
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
        await dut("ip", "xfrm", "state", "add", *state, *crypto,
                  "offload", "packet", "dev", TARGET_LAN_IF, "dir", "out")
        await dut("ip", "xfrm", "policy", "add", *selector, "dir", "out", *tmpl,
                  "offload", "packet", "dev", TARGET_LAN_IF)
        cleanup.append(lambda: dut("ip", "xfrm", "policy", "flush", check=False))
        cleanup.append(lambda: dut("ip", "xfrm", "state", "flush", check=False))

        host_route = [LAN_INNER + "/32", "via", os.environ["ASK_TARGET_IP"]]
        existing = json.loads(subprocess.check_output(["ip", "-j", "route", "show", "exact", host_route[0]]))
        if existing:
            assert len(existing) == 1 and existing[0].get("gateway") == host_route[2], existing
        else:
            subprocess.run(["ip", "route", "add", *host_route], check=True, capture_output=True)
            cleanup.append(lambda: subprocess.run(["ip", "route", "del", *host_route],
                                                   check=True, capture_output=True))

        await dut("nft", "delete", "table", "arp", ARP_TABLE, check=False)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        before = await toenc(session, target_agent, TARGET_LAN_IF)
        retired = await hw_invalid_retired(session, target_agent)
        # Answering the host's ping resolves the DUT's entry for the host,
        # and confirms the host's for the DUT: it sends the DUT no ARP request
        # for a while, which would hand the DUT the entry the resolving case
        # takes away.
        subprocess.run(["ping", "-c1", "-W2", os.environ["ASK_TARGET_IP"]],
                       check=True, capture_output=True)
        if neighbour == "resolving":
            # The first reply is forwarded, offered and queued behind an ARP
            # request that never leaves, so its offer cannot be built. ARP
            # retries every second; the next one after the drop goes resolves.
            await dut("ip", "neigh", "flush", "dev", TARGET_WAN_IF)
            await dut("nft", f'''table arp {ARP_TABLE} {{
 chain out {{ type filter hook output priority 0; policy accept;
 oifname "{TARGET_WAN_IF}" arp operation request drop
 }}
}}''')
            cleanup.append(lambda: dut("nft", "delete", "table", "arp", ARP_TABLE, check=False))
            assert exchange(sock, 1) == 0, (
                "the first reply reached the host, so its neighbour was not "
                "resolving when the connection was offered")
            await dut("nft", "delete", "table", "arp", ARP_TABLE)

        def admitted(rows):
            return ({row.get("out") for row in rows} >= {TARGET_LAN_IF, TARGET_WAN_IF})

        start = time.monotonic()
        rows = []
        while not admitted(rows) and time.monotonic() - start < ADMISSION_S:
            exchange(sock, 5)
            rows = await flows(session, target_agent)
        note("admission_s", round(time.monotonic() - start, 2))
        middle = await toenc(session, target_agent, TARGET_LAN_IF)
        echoed = exchange(sock, COUNT)
        sock.close()
        after = await toenc(session, target_agent, TARGET_LAN_IF)
        rows = await flows(session, target_agent)
        retired = await hw_invalid_retired(session, target_agent) - retired

        forward = [row for row in rows if row.get("out") == TARGET_LAN_IF]
        reverse = [row for row in rows if row.get("out") == TARGET_WAN_IF]
        note("echoed", echoed)
        note("toenc_admission", middle - before)
        note("toenc_delta", after - middle)
        note("hw_invalid_retired", retired)
        note("flows", "; ".join(
            f"{r.get('in')}->{r.get('out')} sa={r.get('sa')} packets={r.get('packets')}"
            for r in rows))

        assert forward, f"the tunnelled direction was not offloaded: {rows}"
        assert forward[0]["sa"] != "0", (
            "the tunnelled direction was offloaded with no SA, which forwards in "
            f"hardware what the policy says to encrypt: {forward[0]}")
        assert reverse and reverse[0]["sa"] == "0", (
            f"the return direction has no policy and must carry no SA: {reverse}")
        assert echoed >= COUNT - 2, f"only {echoed} of {COUNT} echoed"
        if neighbour == "resolved":
            # One, not all: the packet that travelled before the entry
            # existed. More means the first offer did not install.
            assert middle - before <= 2, (
                f"{middle - before} frames reached SEC through the software path "
                f"before admission; the first offer should have installed")
        else:
            assert retired >= 1, (
                "no generation was retired for an invalid handle: the first offer "
                "did not fail, so this run did not exercise its re-offer")
        # None once both directions are in: the classifier steers them all.
        assert after == middle, (
            f"{after - middle} frames reached SEC through the software path with "
            f"the entry installed; the classifier should have steered them all")
    finally:
        for undo in reversed(cleanup):
            try:
                result = undo()
                if hasattr(result, "__await__"):
                    await result
            except Exception:
                pass
