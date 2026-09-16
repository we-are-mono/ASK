"""PPPoE flowtable offload: the WAN sits behind a session, the LAN does not.

The asymmetry is the point, as it is for a tag. One direction arrives inside a
session and leaves bare, the other the reverse, so a single connection
exercises both the ingress strip and the egress insert and neither can be
mistaken for the other.

Two things make a session unlike a tag, and both are what these cases are for.
Netfilter describes an ingress session with *nothing* -- there is no pop action
and no dissector key, so the reverse direction's rule is byte-for-byte the rule
an unencapsulated flow produces, and only the devices say otherwise. And a ppp
device resolves no Ethernet destination at all: it is NOARP with no address, so
the four Ethernet mangles Netfilter writes are zeros and the real destination
is the concentrator the session named. Every case therefore asserts the session
the adapter recorded against `/proc/net/pppoe`, which is where the kernel's own
view of the negotiated session can be read back independently, and then sends a
second burst and requires the classifier's own packet counters to account for
all of it.

The session runs over a tag, because the bench's access concentrator lives on a
standing VLAN. That is not incidental: `ppp0` over `eth4.3900` over `eth4` puts
a session and a tag on one path, which is both encapsulation slots a direction
has, and it is the shape every case here runs in.

The bench side that pre-exists is used, never built: the orchestrator's
`wan3900` device and the LAN VM's route to the inner address are standing
state, so this file creates neither and removes neither.
"""
from __future__ import annotations

import asyncio
import json
import os
import pathlib
import re
import subprocess

import pytest
import pytest_asyncio

from ask_orch.client import Agent
from ask_orch.uart import Console
from _topology import (LAN_NIC, TARGET_LAN_IF, TARGET_WAN_IF, VLAN_ID_PPPOE_WAN,
                       TopologyStack, dut_vlan_subif, lan_run, lan_vlan_subif)
import test_flowtable_offload as ft
from test_flowtable_offload import (ARTIFACTS, DPORT, Echo, SPORT, Rig, command,
                                    console_command, console_python, read)

pytestmark = pytest.mark.skipif(os.environ.get("ASK_FLOWTABLE_TESTS") != "1",
                                reason="requires an explicit experimental boot")

# The orchestrator's standing tagged device, and the tag the DUT has to put on
# eth4 to meet it. Claimed in _topology.py: 3900 is bench furniture, not this
# file's to create or delete.
SERVER_IF = os.environ.get("ASK_PPPOE_SERVER_IF", "wan3900")
WAN_VID = int(os.environ.get("ASK_FLOWTABLE_PPPOE_VID", str(VLAN_ID_PPPOE_WAN)))
# Claimed in _topology.py's VLAN ID conventions block.
LAN_VID = int(os.environ.get("ASK_FLOWTABLE_PPPOE_LAN_VID", "276"))

# The inner addresses the session negotiates. 10.98.0.x deliberately avoids
# 10.99.0.x, where the IPsec bench puts an address on the orchestrator's lo.
INNER_LOCAL = os.environ.get("ASK_PPPOE_INNER_LOCAL", "10.98.0.1")
INNER_REMOTE = os.environ.get("ASK_PPPOE_INNER_REMOTE", "10.98.0.2")
PPPOE_USER, PPPOE_SECRET = "ask-test", "ask-test-secret"

# Not derived from either VLAN id: an id can exceed an octet, and a subnet
# built out of one silently aliases as soon as it does.
TAGGED_SUBNET, DUT_TAGGED_ADDR, LAN_TAGGED_ADDR = "172.29.76.0/24", "172.29.76.1", "172.29.76.2"
# Reachable only because the orchestrator routes it down the session, so it
# cannot be confused with any address the bench carries of its own.
SNAT_ADDR = "172.29.76.9"
NAT_TABLE = "ask_pppoe_nat"

# The session's own MTU, which pppd negotiates as the underlying device's less
# the eight bytes a PPPoE header costs. Nothing here sets it; that it arrives
# at 1492 on its own is part of what the MTU case proves.
SESSION_MTU = 1492

SERVER_OPTS = "/tmp/ask-flowtable-pppoe-server.opt"
SERVER_SECRETS = "/tmp/ask-flowtable-pppoe-secrets"
DUT_PEER = "/tmp/ask-flowtable-pppoe-peer"
DUT_SECRETS = "/tmp/ask-flowtable-pppoe-secrets"
DUT_LOG = "/tmp/ask-flowtable-pppoe-pppd.log"
DUT_PID = "/tmp/ask-flowtable-pppoe-pppd.pid"


class SourceEcho(Echo):
    """Echo that also records where each datagram came from. Under SNAT that is
    the translated endpoint, which is the wire-level proof of the rewrite."""

    def __init__(self):
        super().__init__()
        self.sources = set()

    def datagram_received(self, data, addr):
        self.sources.add((addr[0], addr[1]))
        super().datagram_received(data, addr)


async def _flows(r):
    return (await r.state())["flows"]


def _direction(flows, source, destination):
    """One installed direction, named by the endpoints of its match."""
    matching = [f for f in flows if f["src"].startswith(source + ":")
                and f["dst"].startswith(destination + ":")]
    assert len(matching) == 1, (source, destination, flows)
    return matching[0]


# ---- the session ---------------------------------------------------------

def _server_start():
    """The access concentrator, on the orchestrator's standing tagged device.

    Run as a plain subprocess rather than through the WAN agent: pppoe-server
    is deliberately not in the agent's exec allowlist, and the orchestrator is
    the machine this test already runs on.
    """
    server = "/usr/sbin/pppoe-server"
    if not os.access(server, os.X_OK):
        pytest.skip(f"{server} not installed on the orchestrator")
    pathlib.Path(SERVER_SECRETS).write_text(
        f'"{PPPOE_USER}"   *   "{PPPOE_SECRET}"   *\n')
    os.chmod(SERVER_SECRETS, 0o600)
    pathlib.Path(SERVER_OPTS).write_text(
        # require-pap: the DUT authenticates to us, so a session that comes up
        # has completed discovery and authentication rather than merely LCP.
        "require-pap\n"
        f"pap-secrets {SERVER_SECRETS}\n"
        f"chap-secrets {SERVER_SECRETS}\n"
        f"mtu {SESSION_MTU}\n"
        f"mru {SESSION_MTU}\n"
        "nodefaultroute\n"
        "lcp-echo-interval 5\n"
        "lcp-echo-failure 3\n"
        "noipdefault\n")
    proc = subprocess.Popen(
        # -k: kernel-mode PPPoE. -F: stay in the foreground, so this handle is
        # the server rather than a wrapper that has already exited, which is
        # what makes teardown PID-targeted -- a pkill pattern broad enough to
        # find a daemonized one also matches the shell running it.
        [server, "-I", SERVER_IF, "-L", INNER_LOCAL, "-R", INNER_REMOTE,
         "-N", "4", "-O", SERVER_OPTS, "-k", "-F"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return proc


def _server_stop(proc):
    """By PID. A bare pkill pattern matches the shell running it."""
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    for path in (SERVER_OPTS, SERVER_SECRETS):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


async def _dial(console, lower):
    """Start pppd on the DUT over `lower` and wait for the session.

    pppd is not in the agent's exec allowlist, so the whole of it goes over the
    console. The config files are staged through console_python rather than a
    heredoc: the staging is checksum-verified, which a heredoc over a
    115200-baud line is not.
    """
    peer = (
        # plugin pppoe.so is the in-kernel PPPoE channel; the device named on
        # the next line is the one it dials over, which here is the tagged
        # device the concentrator sits behind.
        "plugin pppoe.so\n"
        f"{lower}\n"
        f"name {PPPOE_USER}\n"
        # noauth: we do not demand the concentrator authenticate back.
        # nodefaultroute: the DUT keeps reaching the agent over its own
        # default route, so the control channel never moves into the session.
        # nodetach: the process we start is the process we later signal.
        # No persist: a redial has to be this test's doing rather than pppd's,
        # or the dependency case races an automatic reconnection.
        "noauth\n"
        "nodefaultroute\n"
        "nodetach\n"
        "maxfail 3\n"
        "holdoff 2\n"
        f"mtu {SESSION_MTU}\n"
        f"mru {SESSION_MTU}\n"
        "lcp-echo-interval 5\n"
        "lcp-echo-failure 3\n"
        f"pap-secrets {DUT_SECRETS}\n"
        f"chap-secrets {DUT_SECRETS}\n")
    secrets = f'"{PPPOE_USER}"   *   "{PPPOE_SECRET}"   *\n'
    # Built here and staged as literals rather than assembled on the DUT: the
    # script that carries them is checksum-verified over the line, which a
    # heredoc at 115200 baud is not.
    stage = (
        "import json, pathlib, subprocess\n"
        f"pathlib.Path({DUT_SECRETS!r}).write_text({secrets!r})\n"
        f"pathlib.Path({DUT_SECRETS!r}).chmod(0o600)\n"
        f"pathlib.Path({DUT_PEER!r}).write_text({peer!r})\n"
        f"pathlib.Path({DUT_LOG!r}).unlink(missing_ok=True)\n"
        f"log = open({DUT_LOG!r}, 'wb')\n"
        f"proc = subprocess.Popen(['pppd', 'file', {DUT_PEER!r}],\n"
        "                        stdin=subprocess.DEVNULL, stdout=log, stderr=log,\n"
        "                        start_new_session=True)\n"
        f"pathlib.Path({DUT_PID!r}).write_text(str(proc.pid))\n"
        "print(json.dumps({'pid': proc.pid}))\n")
    result = await console_python(console, stage, timeout=30)
    assert result["rc"] == 0, result["stdout"]
    reported = [line for line in result["stdout"].splitlines() if line.startswith("{")]
    assert reported, result["stdout"]
    pid = json.loads(reported[-1])["pid"]
    # One long shell loop rather than Python-side polling: a single console
    # round-trip is robust against kernel log noise arriving mid-stream, and
    # the ppp_generic lockdep warning fires on the first PPPIOCNEWUNIT of a
    # boot (ISSUES.md A13) right where a tight polling loop would read.
    poll = ("found=; for i in $(seq 1 60); do "
            "  iface=$(ip -br link show | awk '/^ppp[0-9]/ {print $1; exit}'); "
            "  if [ -n \"$iface\" ] && ip -4 addr show $iface | grep -q 'inet '; then "
            "    found=$iface; break; fi; sleep 0.5; done; "
            "if [ -n \"$found\" ]; then echo PPPIFACE=$found; else echo PPPIFACE_TIMEOUT; fi")
    probe = await asyncio.to_thread(console.run, poll, 45.0)
    match = re.search(r"PPPIFACE=(ppp\d+)", probe.stdout)
    if not match:
        log = await console_command(console, "sh", "-c", f"tail -60 {DUT_LOG}", check=False)
        await _hangup(console)
        pytest.fail("the PPPoE session did not come up within 30s. pppd log:\n"
                    + (log["stdout"] or "<empty: pppd never started>"))
    return match.group(1), pid


async def _hangup(console):
    """Stop pppd by the PID we started, and wait for the device to go.

    By PID, never by pattern: a pkill broad enough to find pppd also matches
    the shell that is running it.
    """
    await console_command(console, "sh", "-c",
                          f"[ -f {DUT_PID} ] && kill -TERM $(cat {DUT_PID}) 2>/dev/null; "
                          f"for i in 1 2 3 4 5 6 7 8 9 10; do "
                          f"  ip -br link show | grep -q '^ppp' || break; sleep 0.5; done; "
                          f"[ -f {DUT_PID} ] && kill -KILL $(cat {DUT_PID}) 2>/dev/null; "
                          f"rm -f {DUT_PID}; true", check=False, timeout=25)


async def _session_identity(r):
    """The session as the kernel itself describes it: (id, concentrator MAC).

    /proc/net/pppoe is the independent view. The adapter derives its own copy
    from the forwarding-path walk, so requiring the two to agree is what says
    the hardware carries the session that was actually negotiated -- and, after
    a redial, that it carries the new one rather than the old.
    """
    text = await read(r.target, r.session, "/proc/net/pppoe")
    rows = [line.split() for line in text.splitlines()[1:] if line.strip()]
    assert len(rows) == 1, (text, "expected exactly one PPPoE session")
    sid, mac, lower, ppp = rows[0][0], rows[0][1], rows[0][2], rows[0][3]
    # Which devices the session really stands on, rather than which ones the
    # fixture asked for: the tag under the session is half of what makes this
    # path spend both encapsulation slots.
    assert (lower, ppp) == (r.ppp_lower, r.ppp_if), (rows, r.ppp_lower, r.ppp_if)
    return int(sid, 16), mac.lower()


def _session_text(identity):
    """How the adapter prints one: the id in decimal and the concentrator."""
    return f"{identity[0]}@{identity[1]}"


async def _wait_reachable(r, attempts=10):
    """Prove the path across the session before measuring anything on it.

    The first packet after a bring-up can lose a race with the peer route and
    with the concentrator's own ARP for the LAN, and `exchange` treats a single
    lost datagram as a failure -- correctly, since that is what it is there to
    catch. Absorb the bring-up here instead of in whichever case happens to
    run first.
    """
    for _ in range(attempts):
        probe = await lan_run(r.lan, f"ping -c 1 -W 2 -I {r.peer_if} {INNER_LOCAL} "
                                     f">/dev/null 2>&1; echo rc=$?", 12.0)
        if "rc=0" in probe.stdout:
            return
        await asyncio.sleep(1.0)
    pytest.fail(f"the LAN VM could not reach {INNER_LOCAL} across the session after "
                f"{attempts} attempts: {probe.stdout!r}")


# ---- topology ------------------------------------------------------------

async def _lan_segment(r, stack, tagged):
    """The LAN side, tagged or not, and the LAN VM's route to the inner peer.

    The route is restated rather than created: the bench already carries it,
    which is why nothing here removes it.
    """
    if tagged:
        dut_if = await dut_vlan_subif(stack, r.target, r.session, parent=TARGET_LAN_IF,
                                      vid=LAN_VID, ipv4=f"{DUT_TAGGED_ADDR}/24")
        lan_if = await lan_vlan_subif(
            stack, r.lan, parent=LAN_NIC, vid=LAN_VID, ipv4=f"{LAN_TAGGED_ADDR}/24",
            routes=[f"{INNER_LOCAL}/32 via {DUT_TAGGED_ADDR} dev vlan{LAN_VID}"])
        r.lan_ip, reachable = LAN_TAGGED_ADDR, TAGGED_SUBNET
    else:
        dut_if, lan_if = TARGET_LAN_IF, LAN_NIC
        addr = json.loads((await lan_run(r.lan, f"ip -j -4 addr show dev {LAN_NIC}")).stdout)
        r.lan_ip = next(a["local"] for a in addr[0]["addr_info"] if a["family"] == "inet")
        reachable = f"{r.lan_ip}/32"
        gateway = json.loads((await command(r.target, r.session, "ip", "-j", "-4", "addr",
                                            "show", "dev", TARGET_LAN_IF))["stdout"])[0]
        via = next(a["local"] for a in gateway["addr_info"] if a["family"] == "inet")
        # Restating a route the bench already carries, which is why nothing
        # removes it again: the LAN VM reaches the inner peer through the DUT
        # exactly as it reaches everything else.
        await lan_run(r.lan, f"ip route replace {INNER_LOCAL}/32 via {via} dev {LAN_NIC}")
    r.dut_lan_if, r.peer_if, r.peer_link = dut_if, lan_if, LAN_NIC
    link = json.loads((await lan_run(r.lan, f"ip -j link show dev {lan_if}")).stdout)[0]
    r.peer_mac = r.lan_mac = link["address"]
    r.peer_gateway_mac = r.dut_lan_mac = (
        await read(r.target, r.session, f"/sys/class/net/{dut_if}/address")).strip()
    return reachable


@pytest_asyncio.fixture
async def pppoe_rig(target_agent, aiohttp_session, lan, splat_window, request, monkeypatch):
    """LAN VM -> DUT -> PPPoE session -> orchestrator.

    The parameter selects the shape: "udp" (default), "tcp", or "tagged" for a
    tagged LAN behind the session. Teardown reverses only what came up.

    The far endpoint is the session's own inner address, not the orchestrator's
    ordinary WAN address. It has to be: a host route for the WAN address down
    the session would send the agent's own replies through the tunnel and take
    the control channel with it. Rig reads that endpoint from its own module,
    so it is rebound there for this fixture rather than restated in a fork of
    every Rig method; monkeypatch puts it back.
    """
    shape = getattr(request, "param", "udp")
    assert shape in {"udp", "tcp", "tagged"}
    monkeypatch.setattr(ft, "WAN_IP", INNER_LOCAL)
    r = Rig()
    r.proto = "tcp" if shape == "tcp" else "udp"
    r.target, r.session, r.lan, r.sequence = target_agent, aiohttp_session, lan, 1
    r.recovery_console = None
    initial = await r.state()
    assert initial["owner"] == "flowtable", "boot ask.offload=flowtable first"
    assert initial["entries"] == initial["bindings"] == initial["invalidated"] == 0, initial
    r.wan = Agent("wan", f"http://{os.environ.get('ASK_WAN_IP', '127.0.0.1')}:9110")
    stack = TopologyStack()
    cleanup = []
    transport = server = None
    console = Console.target(log_path=str(ARTIFACTS / "pppoe-uart.log"))
    try:
        await command(r.target, r.session, "modprobe", "xt_tcpudp")
        await asyncio.to_thread(console.login, "root", None)
        # Probe for pppd before anything is built: skipping here costs nothing,
        # where skipping after the concentrator is up costs a spin-up and a
        # teardown, and skipping after the dial costs a 30-second timeout.
        await console_command(console, "modprobe", "pppoe")
        probe = await console_command(console, "sh", "-c", "command -v pppd", check=False)
        if probe["rc"] != 0:
            pytest.skip("pppd is not in the DUT image; add `ppp` to IMAGE_INSTALL")
        # Every device the session stands on exists before the flowtable binds.
        # Adding an upper to a bound port is a configuration change the adapter
        # answers with full invalidation, which would retire flows for a reason
        # that has nothing to do with the session.
        r.ppp_lower = await dut_vlan_subif(stack, r.target, r.session,
                                           parent=TARGET_WAN_IF, vid=WAN_VID)
        server = _server_start()
        # ~0.5s to bind. A bad interface or a port already in use exits fast;
        # catching that here beats a bring-up timeout half a minute later.
        await asyncio.sleep(0.5)
        if server.poll() is not None:
            _, err = server.communicate(timeout=2)
            pytest.fail(f"pppoe-server exited rc={server.returncode} on {SERVER_IF}: "
                        f"{err.decode('utf-8', 'replace')[:1000]!r}")
        r.ppp_if, r.ppp_pid = await _dial(console, r.ppp_lower)
        stack.push(lambda: _hangup(console))
        r.console = console
        r.reachable = await _lan_segment(r, stack, shape == "tagged")
        r.session_identity = await _session_identity(r)
        # pppd installs the peer host route itself; what it does not install is
        # the way back, and the concentrator has no route to the LAN at all.
        # Point-to-point, so no nexthop: the session is the only way there.
        for prefix in (r.reachable, f"{SNAT_ADDR}/32"):
            await command(r.wan, r.session, "ip", "route", "replace", prefix,
                          "dev", r.ppp_if)
            cleanup.append((r.wan, ["ip", "route", "del", prefix, "dev", r.ppp_if]))
        # Only the LAN neighbour is pinned. There is deliberately none to pin
        # on the session: a ppp device is NOARP and carries no address, so the
        # concentrator is named by the session and by nothing else.
        await command(r.target, r.session, "ip", "neigh", "replace", r.lan_ip,
                      "lladdr", r.lan_mac, "nud", "permanent", "dev", r.dut_lan_if)
        cleanup.append((r.target, ["ip", "neigh", "del", r.lan_ip, "dev", r.dut_lan_if]))
        # Without this the image's own masquerade rule would translate the
        # routed case and it would silently stop being a routed case.
        accept = ["POSTROUTING", "-s", r.lan_ip, "-d", INNER_LOCAL, "-p", r.proto,
                  "--sport", str(SPORT), "--dport", str(DPORT), "-j", "ACCEPT"]
        await command(r.target, r.session, "iptables", "-t", "nat", "-I", *accept)
        cleanup.append((r.target, ["iptables", "-t", "nat", "-D", *accept]))
        old_acct = (await read(r.target, r.session,
                               "/proc/sys/net/netfilter/nf_conntrack_acct")).strip()
        await command(r.target, r.session, "sysctl", "-w", "net.netfilter.nf_conntrack_acct=1")
        cleanup.append((r.target, ["sysctl", "-w",
                                   f"net.netfilter.nf_conntrack_acct={old_acct}"]))
        await _wait_reachable(r)
        await r.clear_ct()
        if r.proto == "udp":
            transport, r.echo = await asyncio.get_running_loop().create_datagram_endpoint(
                SourceEcho, local_addr=(INNER_LOCAL, DPORT))
        r.record("pppoe-fixture", {"lan": r.lan_ip, "inner": INNER_LOCAL, "shape": shape,
                                   "ppp": r.ppp_if, "lower": r.ppp_lower,
                                   "pppd_pid": r.ppp_pid, "reachable": r.reachable,
                                   "session": _session_text(r.session_identity),
                                   "dut_if": r.dut_lan_if, "lan_mac": r.lan_mac,
                                   "initial": initial})
        yield r
    finally:
        if transport:
            transport.close()
        failures = []
        steps = [r.delete_table] + ([r.clear_ct] if hasattr(r, "lan_ip") else [])
        for step in steps:
            try:
                await step()
            except Exception as error:
                failures.append(str(error))
        await command(r.target, r.session, "nft", "delete", "table", "ip", NAT_TABLE,
                      check=False)
        for agent, argv in reversed(cleanup):
            await command(agent, r.session, *argv, check=False)
        await stack.teardown("flowtable-pppoe")
        if server:
            _server_stop(server)
        try:
            await console_command(console, "sh", "-c",
                                  f"rm -f {DUT_PEER} {DUT_SECRETS} {DUT_LOG}; true",
                                  check=False)
        finally:
            console.close()
        assert not failures, failures


async def _both_directions(r):
    """Admission is directional, so one direction refused leaves the other
    accelerated and the difference is invisible in a throughput number. An
    ingress session is the likeliest half to be refused and the hardest to
    notice, because its rule looks exactly like an unencapsulated one."""
    state = await r.state()
    if len(state["flows"]) != 2:
        conntrack = await command(r.target, r.session, "conntrack", "-L", "-o", "extended",
                                  check=False)
        r.record("pppoe-partial-admission", {"state": state, "conntrack": conntrack})
        pytest.fail(f"{len(state['flows'])} of 2 directions admitted: "
                    f"validated={state['validated']} rejects={state['rejects']} "
                    f"busy={state['busy']} errors={state['errors']}\n"
                    f"flows={state['flows']}\nconntrack={conntrack['stdout']}")
    return state["flows"]


async def _established(r, count=64):
    """Install the flow, then measure a second burst against the hardware.

    The counters are cumulative for the boot, so every measurement here is a
    delta against a baseline taken once the flow is already installed.
    """
    await r.table()
    await r.exchange(count=4)
    flows = await _both_directions(r)
    before = {f["cookie"]: int(f["packets"]) for f in flows}
    await r.exchange(count=count)
    state = await r.state()
    after = {f["cookie"]: int(f["packets"]) for f in state["flows"]}
    if set(before) != set(after):
        r.record("pppoe-readmitted", {"before": before, "state": state})
        pytest.fail("a direction was readmitted mid-measurement: "
                    f"before={before} after={after}\n" +
                    " ".join(f"{k}={state[k]}" for k in sorted(state)
                             if k.endswith("invalidations") or
                             k in ("invalidated", "invalidation_done", "rearms",
                                   "errors", "rejects", "busy", "installs", "deletes")))
    return flows, {c: after[c] - before[c] for c in before}


def _assert_session(r, forward, reverse, session=None):
    """The session is named on the direction that carries it and nowhere else.

    Both directions still name the physical ports: a ppp device never becomes
    one, and neither does the tagged device the session stands on.
    """
    expected = _session_text(session or r.session_identity)
    assert forward["out_ppp"] == expected and forward["in_ppp"] == "-", forward
    assert reverse["in_ppp"] == expected and reverse["out_ppp"] == "-", reverse
    assert forward["in"] == TARGET_LAN_IF and forward["out"] == TARGET_WAN_IF, forward
    assert reverse["in"] == TARGET_WAN_IF and reverse["out"] == TARGET_LAN_IF, reverse
    # The session stands on a tag, so the WAN side of each direction carries
    # both -- which is every encapsulation slot a direction has.
    assert forward["out_vlan"] == str(WAN_VID), forward
    assert reverse["in_vlan"] == str(WAN_VID), reverse


async def test_flowtable_pppoe_routed(pppoe_rig):
    """A session on the WAN side and a bare LAN, routed, with no translation.

    The session id and the concentrator the adapter recorded have to be the
    ones the kernel negotiated, on the direction that inserts the header and on
    the direction that strips it, and on neither of the LAN-side halves.
    """
    r = pppoe_rig
    flows, delta = await _established(r)
    forward = _direction(flows, r.lan_ip, INNER_LOCAL)
    reverse = _direction(flows, INNER_LOCAL, r.lan_ip)
    _assert_session(r, forward, reverse)
    # Nothing on the LAN side is encapsulated, which is what makes the session
    # assertions above about the session rather than about the path.
    assert forward["in_vlan"] == "-" and reverse["out_vlan"] == "-", (forward, reverse)
    assert forward["in_br"] == reverse["out_br"] == "-", (forward, reverse)
    # The forward direction leaves by the session, so it carries the session's
    # MTU; nothing in this test set it, and the eight bytes are already in it.
    assert int(forward["mtu"]) == SESSION_MTU, forward
    assert all(d == 64 for d in delta.values()), delta
    r.record("pppoe-routed", {"flows": flows, "delta": delta,
                              "session": _session_text(r.session_identity)})


async def test_flowtable_pppoe_snat(pppoe_rig):
    """Source NAT across the session, proved at the far endpoint.

    The concentrator observing the translated source is what separates a
    rewrite that reached the wire from one that only reached the rule -- and
    the wire here is inside a session, so it also says the translation and the
    encapsulation were applied to the same frame in the right order.
    """
    r = pppoe_rig
    # nft rather than an iptables SNAT target, which this image has no module
    # for, and at priority 90 so it runs ahead of the fixture's own
    # priority-100 exemption rather than behind it.
    nat = (f"table ip {NAT_TABLE} {{ chain postrouting {{ "
           f"type nat hook postrouting priority 90; "
           f"ip saddr {r.lan_ip} ip daddr {INNER_LOCAL} "
           f"udp sport {SPORT} udp dport {DPORT} snat to {SNAT_ADDR}; }}; }}")
    await command(r.target, r.session, "nft", nat)
    try:
        flows, delta = await _established(r)
        forward = _direction(flows, r.lan_ip, INNER_LOCAL)
        assert forward["new_src"].startswith(SNAT_ADDR + ":"), forward
        reverse = _direction(flows, INNER_LOCAL, SNAT_ADDR)
        assert reverse["new_dst"].startswith(r.lan_ip + ":"), reverse
        _assert_session(r, forward, reverse)
        assert all(d == 64 for d in delta.values()), delta
        # What the wire carried, not what the rule said it would.
        assert r.echo.sources == {(SNAT_ADDR, SPORT)}, r.echo.sources
        r.record("pppoe-snat", {"flows": flows, "delta": delta,
                                "observed": sorted(r.echo.sources)})
    finally:
        await command(r.target, r.session, "nft", "delete", "table", "ip", NAT_TABLE,
                      check=False)


@pytest.mark.parametrize("pppoe_rig", ["tagged"], indirect=True)
async def test_flowtable_pppoe_tagged_lan(pppoe_rig):
    """A tag on the LAN and a session on the WAN, so every slot is spent.

    The WAN path already costs a tag and a session, which is both
    encapsulation slots that direction has. Adding a tag on the LAN gives each
    direction something to describe on each side at once: the forward rule pops
    the LAN tag, pushes the WAN tag and pushes the session, and the reverse one
    is the mirror. A derivation that counted the session against the wrong
    direction's budget, or emitted its push in the wrong place, produces an
    action list of the right length for the wrong reason -- so the tags are
    asserted per direction, not as a set.
    """
    r = pppoe_rig
    flows, delta = await _established(r)
    forward = _direction(flows, r.lan_ip, INNER_LOCAL)
    reverse = _direction(flows, INNER_LOCAL, r.lan_ip)
    _assert_session(r, forward, reverse)
    assert forward["in_vlan"] == str(LAN_VID), forward
    assert reverse["out_vlan"] == str(LAN_VID), reverse
    assert all(d == 64 for d in delta.values()), delta
    r.record("pppoe-tagged-lan", {"flows": flows, "delta": delta,
                                  "lan_vid": LAN_VID, "wan_vid": WAN_VID})


async def test_flowtable_pppoe_full_mtu_datagram(pppoe_rig):
    """A datagram filling the session MTU still crosses it.

    The frame the session produces is twelve bytes longer than the datagram
    inside it: eight for the PPPoE and PPP headers and four for the tag the
    session stands on. If the hardware's own size check counted any of them,
    this is the payload that would be dropped or punted while a shorter one was
    forwarded, so the counters have to account for it exactly as for any other
    burst. 1492 is the path MTU rather than a number chosen here, which is what
    makes the reply the same size as the request.
    """
    r = pppoe_rig
    await r.table()
    await r.exchange(count=4)
    before = {f["cookie"]: int(f["packets"]) for f in await _both_directions(r)}
    # The session MTU less the IPv4 and UDP headers: the largest datagram the
    # path takes without fragmenting, and exactly the one the eight bytes of
    # PPPoE would push over if they were counted twice.
    await r.exchange(count=16, payload_size=SESSION_MTU - 28)
    after = {f["cookie"]: int(f["packets"]) for f in await _flows(r)}
    delta = {c: after[c] - before[c] for c in before}
    assert all(d == 16 for d in delta.values()), delta
    r.record("pppoe-full-mtu", {"delta": delta, "payload": SESSION_MTU - 28})


@pytest.mark.parametrize("pppoe_rig", ["tcp"], indirect=True)
async def test_flowtable_pppoe_tcp(pppoe_rig):
    """An established TCP connection across the session.

    The classifier punts SYN, FIN and RST before its own lookup, so what the
    hardware actually carries is the bulk transfer in the middle. The cookies
    staying put is what proves the connection was never readmitted underneath
    it -- and with a session that matters more than elsewhere, because a
    readmission against a changed session would still forward, just to a
    header the concentrator no longer answers.
    """
    r = pppoe_rig
    await r.table()
    peer = f'''
import json, socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(({r.lan_ip!r}, {SPORT}))
s.settimeout(20)
s.connect(({INNER_LOCAL!r}, {DPORT}))
block = bytes(range(256)) * 16
sent = 0
for _ in range(128):
    s.sendall(block)
    sent += len(block)
    remaining = len(block)
    while remaining:
        chunk = s.recv(remaining)
        assert chunk, 'peer closed mid-transfer'
        remaining -= len(chunk)
    time.sleep(0.002)
s.close()
print(json.dumps({{'sent': sent}}))
'''
    server = await asyncio.start_server(_echo_stream, INNER_LOCAL, DPORT)
    try:
        async with server:
            # The echo server is an endpoint in this process; the peer has to
            # run off the event loop or every reply misses its deadline.
            result = await r.run_peer(peer, timeout=120, label="flowtable_pppoe_tcp")
        assert result.rc == 0, result.stdout
        report = json.loads(result.stdout.strip())
        flows = await _both_directions(r)
        forward = _direction(flows, r.lan_ip, INNER_LOCAL)
        reverse = _direction(flows, INNER_LOCAL, r.lan_ip)
        _assert_session(r, forward, reverse)
        assert int(forward["packets"]) > 100 and int(reverse["packets"]) > 100, flows
        r.record("pppoe-tcp", {"flows": flows, "report": report,
                               "session": _session_text(r.session_identity)})
    finally:
        server.close()
        await server.wait_closed()


async def test_flowtable_pppoe_mtu_retires(pppoe_rig):
    """The ppp device carries its own MTU, and a flow through it depends on it.

    Each direction carries the MTU of the interface it leaves by, so lowering
    the session moves only the direction leaving by it and the other keeps the
    LAN port's. Both directions share one invalidation handle, so retiring the
    connection is a single increment rather than two. The starting values are
    themselves an assertion: 1492 on the session side without anyone setting
    it is where the eight bytes of overhead already are.
    """
    r = pppoe_rig
    await r.table()

    async def settled(expected):
        """`expected` maps egress port to the MTU the direction leaving by it
        should describe. Readmission needs traffic, so each attempt sends
        before it looks; nothing re-offers a retired flow on its own."""
        for _ in range(10):
            await r.exchange(count=4)
            state = await r.state()
            if state["entries"] == 2 and all(
                    int(f["mtu"]) == expected[f["out"]] for f in state["flows"]):
                return state
        pytest.fail(f"flow did not settle at {expected}: {state}")

    before = await settled({TARGET_LAN_IF: 1500, TARGET_WAN_IF: SESSION_MTU})
    await command(r.target, r.session, "ip", "link", "set", r.ppp_if, "mtu", "1400")
    try:
        invalidated = await r.wait(
            lambda s: s["mtu_invalidations"] >= before["mtu_invalidations"] + 1)
        reduced = await settled({TARGET_LAN_IF: 1500, TARGET_WAN_IF: 1400})
        assert reduced["errors"] == before["errors"], reduced
        # The session survived the MTU change, so the flow came back describing
        # the same session rather than a different one.
        assert await _session_identity(r) == r.session_identity
        r.record("pppoe-mtu", {"before": before, "invalidated": invalidated,
                               "reduced": reduced})
    finally:
        await command(r.target, r.session, "ip", "link", "set", r.ppp_if,
                      "mtu", str(SESSION_MTU), check=False)


async def test_flowtable_pppoe_session_retires_and_redials(pppoe_rig):
    """The session going away retires the flow, and a redial readmits it.

    This is the dependency proof. The session is what the hardware inserts and
    strips, and nothing about it reaches the rule that could be revalidated
    later: the id is in an action the flow was built from once, and the
    concentrator's address is in no action at all. So hanging the session up
    has to retire the flow -- otherwise the hardware keeps inserting a session
    header the concentrator has already forgotten, and the frames vanish with
    every counter looking healthy.

    What notices is the route. pppd's peer route dies with the device, and the
    flow borrowed that destination, so the route watch retires both directions
    before the device is even unregistered. By the time it is, nothing
    references it and it was never a binding, so the netdev watch has nothing
    left to do. That makes a session drop *selective*: the retirement costs
    the two directions it should and nothing else, the bindings stay up, and
    admission is never disabled. A drop is therefore self-healing -- the table
    is not touched, nothing re-arms, and the next packet re-offers the flow
    against whatever session exists then, which is the assertion that matters
    and the one a stale entry would fail.
    """
    r = pppoe_rig
    flows, delta = await _established(r)
    forward = _direction(flows, r.lan_ip, INNER_LOCAL)
    reverse = _direction(flows, INNER_LOCAL, r.lan_ip)
    _assert_session(r, forward, reverse)
    assert all(d == 64 for d in delta.values()), delta
    before = await r.state()
    first = r.session_identity

    await _hangup(r.console)
    # The route is what goes first, so that is what the convergence waits on.
    retired = await r.wait(
        lambda s: not s["entries"] and
        s["route_invalidations"] >= before["route_invalidations"] + 1, timeout=30)
    # Selective, and that is the result: the table is untouched, so admission
    # was never disabled and nothing has to be rebuilt to get it back.
    assert retired["bindings"] == 2, retired
    assert retired["invalidated"] == 0 and retired["invalidation_done"] == 0, retired
    assert retired["rearms"] == before["rearms"], retired
    assert retired["handle_refs"] == retired["neighbour_refs"] == 0, retired
    assert retired["fatal"] == retired["quarantine"] == 0, retired
    assert retired["errors"] == before["errors"], retired
    # The device is gone, so /proc/net/pppoe has nothing left to describe.
    assert not (await read(r.target, r.session, "/proc/net/pppoe")).splitlines()[1:]

    r.ppp_if, r.ppp_pid = await _dial(r.console, r.ppp_lower)
    # The device went and took its routes with it; the concentrator still has
    # no other way back to the LAN.
    for prefix in (r.reachable, f"{SNAT_ADDR}/32"):
        await command(r.wan, r.session, "ip", "route", "replace", prefix,
                      "dev", r.ppp_if)
    second = await _session_identity(r)
    r.session_identity = second
    # The path went down and came back, so let the bring-up settle before any
    # measurement rather than charging a lost first datagram to the adapter.
    await _wait_reachable(r)

    # Nothing re-offers a retired flow on its own, so each attempt sends before
    # it looks. What it does not need is the table: the retirement was
    # selective, so the bindings that were there before are the ones admitting
    # this flow again.
    for _ in range(10):
        await r.exchange(count=4)
        state = await r.state()
        if state["entries"] == 2:
            break
    else:
        pytest.fail(f"the flow was not readmitted after the redial: {state}")
    readmitted = await _both_directions(r)
    forward = _direction(readmitted, r.lan_ip, INNER_LOCAL)
    reverse = _direction(readmitted, INNER_LOCAL, r.lan_ip)
    # Against the session that exists now. A flow that had survived the hangup,
    # or been readmitted from anything cached, would name the old one -- which
    # is exactly the failure that forwards happily and delivers nothing.
    _assert_session(r, forward, reverse, session=second)
    after = await r.state()
    # Readmitted through the bindings that were never disturbed: no global
    # invalidation to clear, and nothing to re-arm.
    assert after["bindings"] == 2 and after["rearms"] == before["rearms"], after
    assert after["invalidated"] == after["invalidation_done"] == 0, after
    assert after["errors"] == before["errors"], after
    # And the readmitted flow forwards, measured the same way as any other.
    counts = {f["cookie"]: int(f["packets"]) for f in readmitted}
    await r.exchange(count=32)
    final = {f["cookie"]: int(f["packets"]) for f in await _flows(r)}
    assert all(final[c] - counts[c] == 32 for c in counts), (counts, final)
    r.record("pppoe-redial", {"first": _session_text(first),
                              "second": _session_text(second),
                              "before": before, "retired": retired, "after": after})


async def _echo_stream(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()
