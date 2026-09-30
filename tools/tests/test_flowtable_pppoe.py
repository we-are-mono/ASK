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

An IPv4 UDP upload into the session stays in Linux, which is the shipping
behaviour rather than a bench limitation. It arrives on the LAN port, which can
deliver a full 1500-byte frame whatever MTU the port is given, and the session
carries 1492: the microcode would have to fragment it, and the fragments it
builds from a frame an Ethernet port received carry no payload. So the UDP
cases assert that refusal and prove the download -- the strip -- in hardware,
and every property of the upload -- the insert, the session MTU it describes,
the translation in front of it, the LAN tag it pops -- is proved on TCP, which
sets DF and is never the microcode's to fragment.
"""
from __future__ import annotations

import asyncio
import json
import math
import os
import pathlib
import re
import socket
import subprocess
import time

import pytest
import pytest_asyncio

from ask_orch.client import Agent
from ask_orch.counters import kernel_tx_packets
from ask_orch.uart import Console
from _gated_tcp import GatedTcp
from _topology import (DUT_IPV6_LAN, LAN_IPV6, LAN_NIC, PPPOE_IPV6_LOCAL,
                       PPPOE_IPV6_REMOTE, TARGET_LAN_IF, TARGET_WAN_IF,
                       VLAN_ID_PPPOE_WAN, TopologyStack, dut_vlan_subif, lan_run,
                       lan_vlan_subif)
import test_flowtable_offload as ft
from test_flowtable_offload import (ARTIFACTS, DPORT, Echo, SPORT, Rig, assert_undisturbed,
                                    command, console_command, console_python, read)

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

# The same two ends of the session in IPv6, claimed in _topology.py. IPV6CP
# negotiates interface identifiers and forms link-local addresses from them; a
# global address it does not assign, so the fixture puts one on each end.
INNER_LOCAL6 = PPPOE_IPV6_LOCAL
INNER_REMOTE6 = PPPOE_IPV6_REMOTE
# Distinct from the IPv4 cases' ports. The fixture's conntrack clear is
# IPv4-shaped by construction, so a v6 connection left behind by an earlier run
# would otherwise be readmitted into this one's measurement.
SPORT6 = int(os.environ.get("ASK_FLOWTABLE_PPPOE_SPORT6", "48280"))
DPORT6 = int(os.environ.get("ASK_FLOWTABLE_PPPOE_DPORT6", "48281"))

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

# Seconds between the LCP echo requests each end of the session sends. Both
# ends are configured from this, and it bounds what the session exchanges on
# its own while a case measures around it.
LCP_ECHO_INTERVAL = 5

# The untagged flow the session-record case runs beside the session: the LAN
# VM to the WAN host's own address on the bare WAN port, crossing neither the
# session nor the tag it stands on. Ports of its own, so its conntrack is never
# the session flow's.
UNTAGGED_SPORT = int(os.environ.get("ASK_FLOWTABLE_PPPOE_UNTAGGED_SPORT", "48284"))
UNTAGGED_DPORT = UNTAGGED_SPORT + 1
UNTAGGED_COUNT = 10000
# That host's address, read at import: pppoe_rig rebinds the offload module's
# endpoint to the session's inner address for the length of each case.
WAN_ENDPOINT = ft.WAN_IP

# The QoS case's two flows: one marked into a class, which the port has to find
# again after the session scrubbed its conntrack, and one unmarked, which
# saturates the shaped channel beside it. The channel is slow enough that the
# CPU forwards several times its rate through the session; the class the mark
# names is the prio 1 leaf's, class queue 6.
PORT_QOS_VOICE = int(os.environ.get("ASK_FLOWTABLE_PPPOE_QOS_PORT", "48290"))
PORT_QOS_BULK = PORT_QOS_VOICE + 1
QOS_TABLE = "ask_pppoe_qos"
# The QoS case forwards everything in software -- no flowtable is bound --
# and on the test image (KASAN, lockdep) one core saturates near 6,000
# frames a second: at 20 and 60 it pegged, delaying the marked flow's echoes
# past their timeout although every one of them had left on its leaf. Three
# times the channel still fills the unclassified queue.
QOS_RATE_MBIT, QOS_BULK_MBIT = 5, 15
QOS_VOICE_PRIO, QOS_VOICE_CQ = 1, 6
QOS_DATAGRAM, QOS_COUNT = 1200, 200
QOS_BULK_SCRIPT = "/tmp/ask_pppoe_qos_bulk.py"
QOS_BULK_PID = "/tmp/ask_pppoe_qos_bulk.pid"

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


def _session_row(state, identity):
    """The statistics record the adapter holds for one session.

    Keyed on the same `id@concentrator` string the flow rows carry, which is
    what lets the two be joined. A session always has a row once a direction
    naming it is admitted; whether it has a firmware record is what `slot`
    says, because the pool is four deep and shared and running out has to be
    visible rather than silent.
    """
    wanted = _session_text(identity)
    matching = [s for s in state["sessions"] if s["pppoe"] == wanted]
    assert len(matching) == 1, (wanted, state["sessions"])
    return matching[0]


def _direction(flows, source, destination):
    """One installed direction, named by the endpoints of its match."""
    matching = [f for f in flows if f["src"].startswith(source + ":")
                and f["dst"].startswith(destination + ":")]
    assert len(matching) == 1, (source, destination, flows)
    return matching[0]


# ---- the session ---------------------------------------------------------

def _server_start(ipv6=False):
    """The access concentrator, on the orchestrator's standing tagged device.

    Run as a plain subprocess rather than through the WAN agent: pppoe-server
    is deliberately not in the agent's exec allowlist, and the orchestrator is
    the machine this test already runs on.

    `ipv6` enables IPV6CP on this end. It is enabled on both ends or neither:
    the peer that is not asked for it rejects the protocol, and the side that
    wanted it gives up rather than failing, so a session would come up carrying
    IPv4 only and the case that needs v6 would fail as a routing problem.
    """
    server = "/usr/sbin/pppoe-server"
    if not os.access(server, os.X_OK):
        pytest.skip(f"{server} not installed on the orchestrator")
    _server_clear(server)
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
        f"lcp-echo-interval {LCP_ECHO_INTERVAL}\n"
        "lcp-echo-failure 3\n"
        "noipdefault\n"
        + ("+ipv6\n" if ipv6 else ""))
    proc = subprocess.Popen(
        # -k: kernel-mode PPPoE. -F: stay in the foreground, so this handle is
        # the server rather than a wrapper that has already exited, which is
        # what makes teardown PID-targeted -- a pkill pattern broad enough to
        # find a daemonized one also matches the shell running it.
        [server, "-I", SERVER_IF, "-L", INNER_LOCAL, "-R", INNER_REMOTE,
         "-N", "4", "-O", SERVER_OPTS, "-k", "-F"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return proc


def _server_clear(server):
    """Stop any concentrator a run that never reached its teardown left on
    SERVER_IF. Every one there answers the DUT's discovery, so the session
    could otherwise come up on a stale server started with other options --
    one without IPv6CP, say. Matched by exact argv from /proc, not a pkill
    pattern, which would also match the shell running it."""
    for entry in pathlib.Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            argv = (entry / "cmdline").read_bytes().split(b"\0")
        except OSError:
            continue
        argv = [a.decode(errors="replace") for a in argv if a]
        if argv[:1] == [server] and argv[1:3] == ["-I", SERVER_IF]:
            pid = int(entry.name)
            os.kill(pid, 15)
            deadline = time.monotonic() + 5
            while pathlib.Path(f"/proc/{pid}").exists() and time.monotonic() < deadline:
                time.sleep(0.1)


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


async def _dial(console, lower, ipv6=False):
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
        f"lcp-echo-interval {LCP_ECHO_INTERVAL}\n"
        "lcp-echo-failure 3\n"
        f"pap-secrets {DUT_SECRETS}\n"
        f"chap-secrets {DUT_SECRETS}\n"
        # IPV6CP, which brings up the v6 network protocol on the session and
        # forms a link-local address from the negotiated interface identifiers.
        # The global addresses are the fixture's to add; this is what makes the
        # device carry v6 at all.
        + ("+ipv6\n" if ipv6 else ""))
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


async def _wait_reachable(r, attempts=25):
    """Prove the path across the session before measuring anything on it.

    The first packet after a bring-up can lose a race with the peer route and
    with the concentrator's own ARP for the LAN, and `exchange` treats a single
    lost datagram as a failure -- correctly, since that is what it is there to
    catch. Absorb the bring-up here instead of in whichever case happens to
    run first.
    """
    # Three probes per attempt, not one: the first datagram after a cold boot
    # is the one that resolves the neighbour rather than the one that crosses,
    # so a single-packet probe reports failure for a path that is one packet
    # away from working. Observed on a freshly booted DUT, where ten
    # single-packet attempts were not enough and every later case passed.
    for _ in range(attempts):
        probe = await lan_run(r.lan, f"ping -c 3 -W 2 -I {r.peer_if} {INNER_LOCAL} "
                                     f">/dev/null 2>&1; echo rc=$?", 20.0)
        if "rc=0" in probe.stdout:
            return
        await asyncio.sleep(1.0)
    await _unreachable(r, INNER_LOCAL, attempts, probe)


async def _unreachable(r, target, attempts, probe):
    """Fail with the state of every hop, not just the verdict.

    "Could not reach" names the symptom and nothing else, and the path has
    four places to break: the session itself, the DUT's route across it, the
    concentrator's route back to the LAN, and the LAN VM's route to the inner
    address. Report all four so the next failure is diagnosed from the log
    rather than from a re-run.
    """
    dut = await command(r.target, r.session, "ip", "-br", "addr", "show", "ppp0",
                        check=False)
    dut_route = await command(r.target, r.session, "ip", "route", "get", target,
                              check=False)
    lan_route = await lan_run(r.lan, f"ip route get {target} 2>&1", 10.0)
    wan_route = await command(r.wan, r.session, "ip", "route", "get", r.lan_ip,
                              check=False)
    pytest.fail(
        f"the LAN VM could not reach {target} across the session after "
        f"{attempts} attempts: {probe.stdout!r}\n"
        f"  DUT ppp0:        {dut.get('stdout', dut)!r}\n"
        f"  DUT route:       {dut_route.get('stdout', dut_route)!r}\n"
        f"  LAN route:       {lan_route.stdout!r}\n"
        f"  concentrator ->  {wan_route.get('stdout', wan_route)!r}")


async def _wait_reachable6(r, attempts=25):
    """The same bring-up absorption for the v6 path across the session.

    Sourced from the LAN address the offload rule matches on rather than from
    an interface: the LAN VM carries more than one v6 address, and a probe that
    left from a different one would prove a path the flow never takes.
    """
    for _ in range(attempts):
        probe = await lan_run(r.lan, f"ping -6 -c 3 -W 2 -I {LAN_IPV6} {INNER_LOCAL6} "
                                     f">/dev/null 2>&1; echo rc=$?", 20.0)
        if "rc=0" in probe.stdout:
            return
        await asyncio.sleep(1.0)
    pytest.fail(f"the LAN VM could not reach {INNER_LOCAL6} across the session after "
                f"{attempts} attempts: {probe.stdout!r}")


async def _offload_table6(r):
    """The offload table for a v6 flow across the session.

    `Rig.table()` writes an IPv4 match by construction and the family is part
    of the adapter's key, so this direction needs a table of its own. The
    devices are the same two physical ports: a ppp device is never one, which
    is as true for v6 as for v4.
    """
    await r.nft(f'''table inet {ft.TABLE} {{
 flowtable fast {{ hook ingress priority 0; devices = {{ {TARGET_LAN_IF}, {TARGET_WAN_IF} }};
 flags offload; }}
 chain forward {{ type filter hook forward priority 0; policy accept;
 ip6 saddr {LAN_IPV6} udp sport {SPORT6} udp dport {DPORT6} flow add @fast
 }}
}}''')
    await r.wait(lambda s: s["bindings"] == 2)


async def _exchange6(r, count):
    """Echo `count` v6 datagrams from the LAN VM across the session.

    A reply from the wrong endpoint or with the wrong payload is fatal; a
    timeout is only counted, so the caller can tolerate loss while the flow is
    still being admitted and forbid it once it is installed.
    """
    script = f'''
import json, socket, struct, time
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.settimeout(2)
s.bind(({LAN_IPV6!r}, {SPORT6}))
echoed = lost = 0
for n in range({count}):
    payload = struct.pack('!Q', n) + b'ASK-flowtable-pppoe-v6'.ljust(48, b'.')
    s.sendto(payload, ({INNER_LOCAL6!r}, {DPORT6}))
    try:
        data, addr = s.recvfrom(2048)
    except TimeoutError:
        lost += 1
        continue
    assert data == payload, (n, data)
    assert (addr[0], addr[1]) == ({INNER_LOCAL6!r}, {DPORT6}), (n, addr)
    echoed += 1
    time.sleep(0.01)
s.close()
print(json.dumps({{'echoed': echoed, 'lost': lost}}))
'''
    result = await r.run_peer(script, timeout=count * 0.3 + 40, label="flowtable_pppoe_v6")
    assert result.rc == 0, result.stdout
    return json.loads(result.stdout.strip().splitlines()[-1])


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


async def _ipv6_session(r, stack, cleanup):
    """Global IPv6 on both ends of the session, and a LAN that can reach it.

    Three /64s meet here and only one of them is new. The LAN segment reuses
    the addresses the IPv6 offload tests already put on the DUT's LAN port and
    the LAN VM, so that half of the path is the one those tests proved. The
    session's own two endpoints get a /64 of their own, because they are on
    neither segment: they are the ends of the point-to-point link between the
    two ppp devices, and taking an address out of a segment's prefix would make
    a routing mistake look like a working path.

    What IPV6CP brings up is the protocol and a link-local address formed from
    the negotiated interface identifiers. A global address it does not assign,
    so each end gets one here -- as a /64 on a point-to-point device, which
    makes the far end on-link and needs no next hop, exactly as the IPv4 side
    of this session needs none.
    """
    async def target(*argv, check=True):
        return await command(r.target, r.session, *argv, check=check)

    # The concentrator's own ppp device, named by the address pppoe-server put
    # on it rather than assumed to be the DUT's name: both ends are usually
    # ppp0, which is a coincidence between two machines rather than a fact
    # about either.
    addresses = json.loads((await command(r.wan, r.session, "ip", "-j", "-4", "addr"))["stdout"])
    r.server_ppp_if = next(i["ifname"] for i in addresses
                           if any(a.get("local") == INNER_LOCAL for a in i["addr_info"]))

    previous = (await target("sysctl", "-n", "net.ipv6.conf.all.forwarding"))["stdout"].strip()
    cleanup.append((r.target, ["sysctl", "-w",
                               f"net.ipv6.conf.all.forwarding={previous}"]))
    await target("sysctl", "-w", "net.ipv6.conf.all.forwarding=1")
    # The LAN tells its hosts the session's MTU, the configuration a PPPoE LAN
    # needs for its IPv6 upload to be offloaded at all: the microcode would
    # fragment a larger packet instead of letting Linux send Packet Too Big
    # (see test_flowtable_ipv6_mtu_bound).
    key = f"net.ipv6.conf.{TARGET_LAN_IF}.mtu"
    previous = (await target("sysctl", "-n", key))["stdout"].strip()
    cleanup.append((r.target, ["sysctl", "-w", f"{key}={previous}"]))
    await target("sysctl", "-w", f"{key}={SESSION_MTU}")

    # nodad throughout: duplicate address detection leaves an address tentative
    # for about a second and a half, and the first flow would silently not come
    # up. A ppp device is NOARP and skips it anyway; the LAN port does not.
    for address, interface in ((INNER_REMOTE6, r.ppp_if), (DUT_IPV6_LAN, TARGET_LAN_IF)):
        await target("ip", "-6", "addr", "del", f"{address}/64", "dev", interface,
                     check=False)
        await target("ip", "-6", "addr", "add", f"{address}/64", "dev", interface, "nodad")
        cleanup.append((r.target, ["ip", "-6", "addr", "del", f"{address}/64",
                                   "dev", interface]))
    await target("ip", "-6", "neigh", "replace", LAN_IPV6, "lladdr", r.lan_mac,
                 "nud", "permanent", "dev", TARGET_LAN_IF)
    cleanup.append((r.target, ["ip", "-6", "neigh", "del", LAN_IPV6,
                               "dev", TARGET_LAN_IF]))

    await command(r.wan, r.session, "ip", "-6", "addr", "del", f"{INNER_LOCAL6}/64",
                  "dev", r.server_ppp_if, check=False)
    await command(r.wan, r.session, "ip", "-6", "addr", "add", f"{INNER_LOCAL6}/64",
                  "dev", r.server_ppp_if, "nodad")
    cleanup.append((r.wan, ["ip", "-6", "addr", "del", f"{INNER_LOCAL6}/64",
                            "dev", r.server_ppp_if]))
    # The concentrator has no route to the LAN at all, in either family. Point
    # to point, so no next hop: the session is the only way there.
    await command(r.wan, r.session, "ip", "-6", "route", "replace", f"{LAN_IPV6}/128",
                  "dev", r.server_ppp_if)
    cleanup.append((r.wan, ["ip", "-6", "route", "del", f"{LAN_IPV6}/128",
                            "dev", r.server_ppp_if]))

    await lan_run(r.lan, f"ip -6 addr del {LAN_IPV6}/64 dev {LAN_NIC} 2>/dev/null; true")
    result = await lan_run(r.lan, f"ip -6 addr add {LAN_IPV6}/64 dev {LAN_NIC} nodad")
    assert result.rc == 0, result.stdout
    await lan_run(r.lan, f"ip -6 neigh replace {DUT_IPV6_LAN} lladdr {r.dut_lan_mac} "
                         f"nud permanent dev {LAN_NIC}")
    # A host route rather than a default: the LAN VM keeps whatever v6 default
    # it already had, so nothing else it does moves onto this path.
    await lan_run(r.lan, f"ip -6 route replace {INNER_LOCAL6}/128 via {DUT_IPV6_LAN} "
                         f"dev {LAN_NIC}")

    async def _lan_restore():
        await lan_run(r.lan, f"ip -6 route del {INNER_LOCAL6}/128 dev {LAN_NIC} "
                             f"2>/dev/null; true")
        await lan_run(r.lan, f"ip -6 neigh del {DUT_IPV6_LAN} dev {LAN_NIC} "
                             f"2>/dev/null; true")
        await lan_run(r.lan, f"ip -6 addr del {LAN_IPV6}/64 dev {LAN_NIC} "
                             f"2>/dev/null; true")
    stack.push(_lan_restore)
    await _wait_reachable6(r)


@pytest_asyncio.fixture
async def pppoe_rig(target_agent, aiohttp_session, lan, splat_window, request, monkeypatch):
    """LAN VM -> DUT -> PPPoE session -> orchestrator.

    The parameter selects the shape: "udp" (default), "tcp", "tagged" for a
    tagged LAN behind the session, "tagged-tcp" for the same carrying TCP, or
    "ipv6" for a session carrying v6 as well. Teardown reverses only what came
    up.

    The far endpoint is the session's own inner address, not the orchestrator's
    ordinary WAN address. It has to be: a host route for the WAN address down
    the session would send the agent's own replies through the tunnel and take
    the control channel with it. Rig reads that endpoint from its own module,
    so it is rebound there for this fixture rather than restated in a fork of
    every Rig method; monkeypatch puts it back.
    """
    shape = getattr(request, "param", "udp")
    assert shape in {"udp", "tcp", "tagged", "tagged-tcp", "ipv6"}
    monkeypatch.setattr(ft, "WAN_IP", INNER_LOCAL)
    r = Rig()
    r.proto = "tcp" if shape.endswith("tcp") else "udp"
    # The v6 shape is v4 plus a second family on the same session, never
    # instead of it: the v4 path is what the bring-up waits on and what the
    # control channel and the session's own addressing already run over.
    r.session_ipv6 = shape == "ipv6"
    r.target, r.session, r.lan, r.sequence = target_agent, aiohttp_session, lan, 1
    r.recovery_console = None
    initial = await r.state()
    assert initial["entries"] == initial["bindings"] == initial["invalidated"] == 0, initial
    r.wan = Agent("wan", f"http://{os.environ.get('ASK_WAN_IP', '127.0.0.1')}:9110")
    stack = TopologyStack()
    cleanup = []
    transport = transport6 = server = None
    console = Console.target(log_path=str(ARTIFACTS / "pppoe-uart.log"))
    try:
        await command(r.target, r.session, "modprobe", "xt_tcpudp")
        # Quiet the kernel's own console before driving it. Every command here
        # is framed by a marker the reader matches on, and a printk landing
        # mid-marker truncates it -- observed as "missing console output
        # boundary" with the leading bytes of the token gone, and as a dial
        # that silently did not happen, which then surfaces one step later as
        # an unreachable peer. Restored in teardown.
        printk = (await read(r.target, r.session, "/proc/sys/kernel/printk")).split()
        await command(r.target, r.session, "sysctl", "-w", "kernel.printk=1 4 1 7")
        cleanup.append((r.target, ["sysctl", "-w",
                                   "kernel.printk=" + " ".join(printk[:4])]))
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
        server = _server_start(ipv6=r.session_ipv6)
        # ~0.5s to bind. A bad interface or a port already in use exits fast;
        # catching that here beats a bring-up timeout half a minute later.
        await asyncio.sleep(0.5)
        if server.poll() is not None:
            _, err = server.communicate(timeout=2)
            pytest.fail(f"pppoe-server exited rc={server.returncode} on {SERVER_IF}: "
                        f"{err.decode('utf-8', 'replace')[:1000]!r}")
        r.ppp_if, r.ppp_pid = await _dial(console, r.ppp_lower, ipv6=r.session_ipv6)
        stack.push(lambda: _hangup(console))
        r.console = console
        r.reachable = await _lan_segment(r, stack, shape.startswith("tagged"))
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
        if r.session_ipv6:
            # After the v4 path is proven, so a v6 failure is about v6 rather
            # than about a session that never came up.
            await _ipv6_session(r, stack, cleanup)
            transport6, r.echo6 = await asyncio.get_running_loop().create_datagram_endpoint(
                SourceEcho, local_addr=(INNER_LOCAL6, DPORT6), family=socket.AF_INET6)
        r.record("pppoe-fixture", {"lan": r.lan_ip, "inner": INNER_LOCAL, "shape": shape,
                                   "ppp": r.ppp_if, "lower": r.ppp_lower,
                                   "pppd_pid": r.ppp_pid, "reachable": r.reachable,
                                   "session": _session_text(r.session_identity),
                                   "dut_if": r.dut_lan_if, "lan_mac": r.lan_mac,
                                   "initial": initial})
        yield r
    finally:
        for endpoint in (transport, transport6):
            if endpoint:
                endpoint.close()
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


async def _both_directions(r, state=None):
    """Admission is directional, so one direction refused leaves the other
    accelerated and the difference is invisible in a throughput number. An
    ingress session is the likeliest half to be refused and the hardest to
    notice, because its rule looks exactly like an unencapsulated one. Reads
    the state unless handed one."""
    state = state or await r.state()
    if len(state["flows"]) != 2:
        conntrack = await command(r.target, r.session, "conntrack", "-L", "-o", "extended",
                                  check=False)
        r.record("pppoe-partial-admission", {"state": state, "conntrack": conntrack})
        pytest.fail(f"{len(state['flows'])} of 2 directions admitted: "
                    f"validated={state['validated']} rejects={state['rejects']} "
                    f"busy={state['busy']} errors={state['errors']}\n"
                    f"flows={state['flows']}\nconntrack={conntrack['stdout']}")
    return state["flows"]


async def _download_only(r, since):
    """The one direction of an IPv4 UDP connection hardware holds: the
    download, which arrives inside the session and leaves by the LAN port at
    its full MTU. The upload's path is the session's 1492 bytes and its LAN
    port can deliver 1500, so it is refused to Linux (see the module
    docstring) -- counted as a reject since the state `since` was read, and
    absent rather than merely late."""
    state = await r.state()
    flows = state["flows"]
    if (len(flows) != 1 or flows[0]["in"] != TARGET_WAN_IF
            or state["rejects"] <= since["rejects"]):
        conntrack = await command(r.target, r.session, "conntrack", "-L", "-o", "extended",
                                  check=False)
        r.record("pppoe-unexpected-admission", {"since": since, "state": state,
                                                "conntrack": conntrack})
        pytest.fail(f"expected the download alone, the upload refused: "
                    f"validated={state['validated']} rejects={state['rejects']} "
                    f"(from {since['rejects']}) busy={state['busy']} "
                    f"errors={state['errors']}\nflows={flows}\nconntrack={conntrack['stdout']}")
    return flows


async def _established(r, count=64):
    """Install the flow, then measure a second burst against the hardware.

    What is installed is the download alone; see _download_only. The counters
    are cumulative for the boot, so every measurement here is a delta against
    a baseline taken once the flow is already installed.
    """
    initial = await r.state()
    await r.table()
    await r.exchange(count=4)
    flows = await _download_only(r, initial)
    installed = await r.state()
    before = {f["cookie"]: int(f["packets"]) for f in flows}
    await r.exchange(count=count)
    state = await r.state()
    after = {f["cookie"]: int(f["packets"]) for f in state["flows"]}
    _assert_undisturbed(r, installed, state, set(before) == set(after))
    return flows, {c: after[c] - before[c] for c in before}


def _assert_undisturbed(r, before, after, same=True):
    assert_undisturbed(r, before, after, same, label="pppoe-readmitted")


def _assert_session(r, forward, reverse, session=None):
    """The session is named on the direction that carries it and nowhere else.

    Both directions still name the physical ports: a ppp device never becomes
    one, and neither does the tagged device the session stands on. `forward`
    is None where the upload is Linux's.
    """
    expected = _session_text(session or r.session_identity)
    assert reverse["in_ppp"] == expected and reverse["out_ppp"] == "-", reverse
    assert reverse["in"] == TARGET_WAN_IF and reverse["out"] == TARGET_LAN_IF, reverse
    # The session stands on a tag, so the WAN side of each direction carries
    # both -- which is every encapsulation slot a direction has.
    assert reverse["in_vlan"] == str(WAN_VID), reverse
    if forward is None:
        return
    assert forward["out_ppp"] == expected and forward["in_ppp"] == "-", forward
    assert forward["in"] == TARGET_LAN_IF and forward["out"] == TARGET_WAN_IF, forward
    assert forward["out_vlan"] == str(WAN_VID), forward


# What the session's record counts per frame and the ppp device does not. The
# device counts the payload alone; the insert counts the frame with the
# Ethernet and session headers on and no tag yet, the strip the frame as it
# arrived less the session header, so the tag the session runs over is in.
# The adapter restates by the same amounts (FT_PPP_TX_OVERHEAD and
# ft_ppp_rx_overhead in ask_flowtable.c).
PPP_TX_OVERHEAD = 14 + 8
PPP_RX_OVERHEAD = 14 + 4


def _session_halves(state, identity):
    row = _session_row(state, identity)
    return {k: int(row[k]) for k in ("rx_packets", "rx_bytes", "tx_packets", "tx_bytes")}


async def _tcp_carried(r, label):
    """One TCP connection from the LAN across the session, read back while it
    is open and idle (see _gated_tcp): a first phase admits it, a second is
    measured. Returns the installed flows, both states, and what moved over the
    measured phase -- the ppp device's record, its `ip -s link` counters and
    the WAN port's software transmit count -- with the endpoint the
    concentrator's end saw connect from.

    The concentrator advertises the MSS its ppp device allows, so every full
    data segment of the upload comes within its TCP options of the session's
    MTU. A size check that counted the session or tag header against that MTU
    would except each one to Linux, which would then send it out of the WAN
    port itself; the software count is what shows it did not."""
    async with GatedTcp(r.run_peer, source=r.lan_ip, sport=SPORT, peer=INNER_LOCAL,
                        dport=DPORT, label=label) as transfer:
        await transfer.warmed()
        # Admission is asynchronous (rtnl_trylock, deferred a second or two
        # under RTNL contention), so warmed()'s brief settle can miss a late
        # direction; wait both in before reading the baseline the record and
        # the direction check share.
        before = await r.wait(lambda s: len(s["flows"]) == 2)
        flows = await _both_directions(r, before)
        record = _session_halves(before, r.session_identity)
        link = await _ppp_link(r)
        sent = await kernel_tx_packets(r.target, r.session, TARGET_WAN_IF)
        await transfer.measure()
        sent = await kernel_tx_packets(r.target, r.session, TARGET_WAN_IF) - sent
        after = await r.state()
        record_after = _session_halves(after, r.session_identity)
        link_after = await _ppp_link(r)
    return {"flows": flows, "before": before, "after": after, "software_wan_tx": sent,
            "record": {k: record_after[k] - record[k] for k in record},
            "link": {k: link_after[k] - link[k] for k in link},
            "peer": transfer.peername, "report": transfer.report}


def _assert_carried(r, measured):
    """The measured phase was hardware's, and the ppp device says so in the
    units it counts itself.

    The same two entries carried it, each at least a hundred packets, with
    nothing installed, retired or declined meanwhile. The session record's
    halves are those same frames: the insert's the upload's, the strip's the
    download's. And `ip -s link` on the ppp device moved by the record,
    restated into payload bytes, plus only what the session itself exchanged
    in software meanwhile (LCP echoes), each at most one frame -- which is the
    transmit fold for frames the hardware inserted, the half a UDP upload can
    no longer show."""
    before, after = measured["before"], measured["after"]
    old = {f["cookie"]: f for f in measured["flows"]}
    new = {f["cookie"]: f for f in after["flows"]}
    _assert_undisturbed(r, before, after, new.keys() == old.keys()
                        and (after["installs"], after["deletes"]) == (before["installs"], before["deletes"]))
    moved = {c: int(new[c]["packets"]) - int(old[c]["packets"]) for c in old}
    upload = moved[next(c for c, f in old.items() if f["out_ppp"] != "-")]
    download = moved[next(c for c, f in old.items() if f["in_ppp"] != "-")]
    assert upload > 100 and download > 100, moved
    record, link = measured["record"], measured["link"]
    assert (record["tx_packets"], record["rx_packets"]) == (upload, download), (record, moved)
    for half, overhead in (("tx", PPP_TX_OVERHEAD), ("rx", PPP_RX_OVERHEAD)):
        stray = link[half + "_packets"] - record[half + "_packets"]
        assert 0 <= stray <= 8, (half, record, link)
        payload = record[half + "_bytes"] - overhead * record[half + "_packets"]
        assert payload <= link[half + "_bytes"] <= payload + stray * 1518, (half, record, link)
    # Only the handful of frames the reads above cost, and the session's own.
    assert measured["software_wan_tx"] < upload // 4, (measured["software_wan_tx"], upload)


async def test_flowtable_pppoe_routed(pppoe_rig):
    """A session on the WAN side and a bare LAN, routed, with no translation.

    The session id and the concentrator the adapter recorded have to be the
    ones the kernel negotiated, on the direction that strips the header, and
    on neither of the LAN-side halves. The UDP upload is Linux's; the
    direction that inserts the header is proved by test_flowtable_pppoe_tcp.
    """
    r = pppoe_rig
    flows, delta = await _established(r)
    reverse = _direction(flows, INNER_LOCAL, r.lan_ip)
    _assert_session(r, None, reverse)
    # Nothing on the LAN side is encapsulated, which is what makes the session
    # assertions above about the session rather than about the path.
    assert reverse["out_vlan"] == "-" and reverse["out_br"] == "-", reverse
    # The download leaves by the LAN port, whose full MTU it carries.
    assert int(reverse["mtu"]) == 1500, reverse
    assert all(d == 64 for d in delta.values()), delta
    r.record("pppoe-routed", {"flows": flows, "delta": delta,
                              "session": _session_text(r.session_identity)})


@pytest.mark.parametrize("pppoe_rig", ["ipv6"], indirect=True)
async def test_flowtable_pppoe_ipv6_routed(pppoe_rig):
    """IPv6 across the session, which was the one thing a session excluded.

    The exclusion was about the firmware rather than the adapter.
    `en_ehash_insert_pppoe_hdr` carries a version, a type, a code and a session
    id, and no PPP protocol id at all, so the microcode chooses between 0x0021
    and 0x0057 itself and nothing had shown which it picks for an IPv6 frame. A
    wrong choice is a header the concentrator discards, which is silent loss
    rather than a refusal, so it stayed out until measured.

    This is the measurement. A complete v6 exchange across the session is the
    evidence: every datagram was answered, so the peer parsed every frame the
    hardware inserted a header onto, which a wrong protocol id would not
    survive. The counters then say the hardware carried it rather than software
    quietly doing the work.

    One routed case is the whole of it, deliberately. Nothing about the family
    reaches the session decode -- the walk, the concentrator and the id are
    identical either way -- so what the other shapes would re-prove is the
    adapter's handling of a session, which the IPv4 cases already cover, and
    what is new here belongs to the firmware.
    """
    r = pppoe_rig
    # Errors accumulate for the life of the module, and the fault-injection
    # cases in test_flowtable_offload.py raise some on purpose, so what this
    # case can claim is that it added none of its own.
    baseline = (await r.state())["errors"]
    await _offload_table6(r)
    # Nothing re-offers a flow on its own, so each attempt sends before it
    # looks; admission needs traffic and the reverse direction needs a reply.
    for _ in range(10):
        await _exchange6(r, 4)
        if (await r.state())["entries"] == 2:
            break
    flows = await _both_directions(r)
    forward = _direction(flows, f"[{LAN_IPV6}]", f"[{INNER_LOCAL6}]")
    reverse = _direction(flows, f"[{INNER_LOCAL6}]", f"[{LAN_IPV6}]")
    assert forward["family"] == reverse["family"] == "6", flows
    # The session, asserted exactly as the v4 routed case asserts it: the id
    # and the concentrator the kernel negotiated, on the direction that inserts
    # the header and on the direction that strips it, and on neither LAN half.
    _assert_session(r, forward, reverse)
    assert forward["in_vlan"] == "-" and reverse["out_vlan"] == "-", (forward, reverse)
    assert forward["in_br"] == reverse["out_br"] == "-", (forward, reverse)
    # The forward direction leaves by the session, so it carries the session's
    # MTU -- which is above the IPv6 minimum link MTU, the one extra thing v6
    # requires of a path.
    assert int(forward["mtu"]) == SESSION_MTU, forward

    before = {f["cookie"]: int(f["packets"]) for f in flows}
    report = await _exchange6(r, 64)
    assert report == {"echoed": 64, "lost": 0}, report
    state = await r.state()
    after = {f["cookie"]: int(f["packets"]) for f in state["flows"]}
    assert set(before) == set(after), (before, state)
    delta = {c: after[c] - before[c] for c in before}
    assert all(d == 64 for d in delta.values()), (delta, state)
    assert state["errors"] == baseline, (baseline, state)
    # And what the far end observed, which is where the protocol id was really
    # decided: the concentrator's stack had to parse the PPP frame before this
    # datagram could reach a socket at all.
    assert r.echo6.sources == {(LAN_IPV6, SPORT6)}, r.echo6.sources
    r.record("pppoe-ipv6-routed", {"flows": flows, "delta": delta,
                                   "session": _session_text(r.session_identity),
                                   "observed": sorted(r.echo6.sources)})


async def _ppp_link(r):
    link = json.loads((await command(r.target, r.session, "ip", "-s", "-j", "link", "show",
                                     "dev", r.ppp_if))["stdout"])[0]["stats64"]
    return {"rx_packets": link["rx"]["packets"], "rx_bytes": link["rx"]["bytes"],
            "tx_packets": link["tx"]["packets"], "tx_bytes": link["tx"]["bytes"]}


async def test_flowtable_pppoe_session_counters(pppoe_rig):
    """The session's own byte counters, which the firmware keeps for it, and
    where an operator reads them: on the ppp device.

    One record per ppp device, not per flow and not per direction: every
    direction of a connection that crosses the device in hardware holds a
    reference, and counts into the half of the record it uses. Sending a
    measured burst and requiring the record to have moved by it is what
    separates counters the firmware is really maintaining from an index that
    was merely written into an opcode; requiring `ip -s link` on the device to
    have moved by the same burst, restated into the payload the device itself
    counts, is what makes the record an operator's number rather than a
    diagnostic.

    The UDP upload is Linux's, so here the download alone holds the record
    and moves its receive half, while the device's transmit counter moves by
    the upload Linux sent through it. The insert's half of the record is
    counted by test_flowtable_pppoe_tcp.
    """
    r = pppoe_rig
    initial = await r.state()
    await r.table()
    await r.exchange(count=4)
    await _download_only(r, initial)
    state = await r.state()
    row = _session_row(state, r.session_identity)
    # Held by the one direction in hardware, and holding a record: the pool
    # is empty only after four sessions, and this bench has one. The record is
    # the device's, and says which device.
    assert row["refs"] == "1", row
    assert row["slot"] == "yes", row
    assert row["dev"] == r.ppp_if, row
    assert state["session_records"] == 1 and state["session_slots"] == 1, state
    before = {k: int(row[k]) for k in
              ("rx_packets", "rx_bytes", "tx_packets", "tx_bytes")}
    link_before = await _ppp_link(r)

    payload = 256
    ip_len = 20 + 8 + payload
    await r.exchange(count=64, payload_size=payload)
    burst = await r.state()
    _assert_undisturbed(r, state, burst, [f["cookie"] for f in burst["flows"]]
                        == [f["cookie"] for f in state["flows"]])
    row = _session_row(burst, r.session_identity)
    link_after = await _ppp_link(r)
    after = {k: int(row[k]) for k in before}
    delta = {k: after[k] - before[k] for k in before}
    link = {k: link_after[k] - link_before[k] for k in before}
    # Received frames are the ones the download stripped the header from; the
    # record's transmit half counts only headers hardware inserted, and the
    # upload inserted none.
    assert delta["rx_packets"] == 64 and delta["tx_packets"] == delta["tx_bytes"] == 0, (before, after)
    # The firmware's session record, measured on this bench and pinned here:
    # the strip counts the frame as it arrived less the session header alone,
    # so the WAN tag the session runs over is still in.
    assert delta["rx_bytes"] == 64 * (ip_len + 14 + 4), delta
    # The device counts the payload alone, both ways -- the download folded in
    # from the record, the upload counted by Linux as it sent it -- and its
    # counters now include the burst restated to exactly that, plus the few
    # frames the session itself exchanges meanwhile (LCP echoes), each at most
    # one frame.
    for half in ("rx", "tx"):
        stray = link[f"{half}_packets"] - 64
        assert 0 <= stray <= 8, (half, link)
        assert 64 * ip_len <= link[f"{half}_bytes"] <= 64 * ip_len + stray * 1518, (half, link)
    r.record("pppoe-session-counters", {"before": before, "after": after, "delta": delta,
                                        "row": row, "link": link})
    # The record belongs to the device rather than to the flows: retiring the
    # connection returns the references and keeps the record and its totals,
    # so the device's counters survive the connection going idle.
    await r.delete_table()
    state = await r.state()
    row = _session_row(state, r.session_identity)
    assert row["refs"] == "0" and row["slot"] == "yes", row
    assert state["session_records"] == 1 and state["session_slots"] == 1, state
    assert {k: int(row[k]) for k in after} == after, (row, after)


async def _untagged_path(r, cleanup):
    """The WAN host's own address across the two bare ports, beside the
    session: the path test_flowtable_offload's rig builds, restated here
    because that fixture and this one cannot share a case -- each owns the
    offload module's endpoint.

    Built before anything is admitted, since a host route added under an
    installed flow is a routing change the adapter answers. The concentrator's
    route back to the LAN is left pointing into the session; the case moves it
    for its window alone. Returns what that move needs: the WAN host's device
    and the DUT's own address on the WAN port.
    """
    addresses = json.loads((await command(r.wan, r.session, "ip", "-j", "-4", "addr"))["stdout"])
    wan_if = next((i["ifname"] for i in addresses
                   if any(a.get("local") == WAN_ENDPOINT for a in i["addr_info"])), None)
    assert wan_if, (f"ASK_WAN_IPERF_IP={WAN_ENDPOINT} is none of the WAN host's addresses",
                    addresses)
    wan_mac = json.loads((await command(r.wan, r.session, "ip", "-j", "link", "show",
                                        "dev", wan_if))["stdout"])[0]["address"]
    dut = json.loads((await command(r.target, r.session, "ip", "-j", "-4", "addr", "show",
                                    "dev", TARGET_WAN_IF))["stdout"])[0]
    dut_wan_ip = next(a["local"] for a in dut["addr_info"] if a["family"] == "inet")
    # Pinned, as the rig pins it, and put back as it was found: a neighbour
    # resolving mid-measurement is a change the adapter would answer inside
    # the window.
    old = json.loads((await command(r.target, r.session, "ip", "-j", "neigh", "show", "to",
                                    WAN_ENDPOINT, "dev", TARGET_WAN_IF))["stdout"])
    restore = ["ip", "neigh", "del", WAN_ENDPOINT, "dev", TARGET_WAN_IF]
    if old and old[0].get("lladdr"):
        state = "permanent" if "PERMANENT" in old[0]["state"] else "stale"
        restore = ["ip", "neigh", "replace", WAN_ENDPOINT, "lladdr", old[0]["lladdr"],
                   "nud", state, "dev", TARGET_WAN_IF]
    await command(r.target, r.session, "ip", "neigh", "replace", WAN_ENDPOINT, "lladdr",
                  wan_mac, "nud", "permanent", "dev", TARGET_WAN_IF)
    cleanup.append((r.target, restore))
    routes = json.loads((await command(r.target, r.session, "ip", "-j", "route", "show",
                                       "exact", f"{WAN_ENDPOINT}/32"))["stdout"])
    assert not routes, ("a host route to the WAN host was left behind", routes)
    await command(r.target, r.session, "ip", "route", "add", f"{WAN_ENDPOINT}/32",
                  "dev", TARGET_WAN_IF)
    cleanup.append((r.target, ["ip", "route", "del", f"{WAN_ENDPOINT}/32",
                               "dev", TARGET_WAN_IF]))
    # Routed, not translated: the image's own masquerade would rewrite it.
    accept = ["POSTROUTING", "-s", r.lan_ip, "-d", WAN_ENDPOINT, "-p", "udp",
              "--sport", str(UNTAGGED_SPORT), "--dport", str(UNTAGGED_DPORT), "-j", "ACCEPT"]
    await command(r.target, r.session, "iptables", "-t", "nat", "-I", *accept)
    cleanup.append((r.target, ["iptables", "-t", "nat", "-D", *accept]))
    clear = ["conntrack", "-D", "-p", "udp", "--orig-src", r.lan_ip, "--orig-dst", WAN_ENDPOINT,
             "--sport", str(UNTAGGED_SPORT), "--dport", str(UNTAGGED_DPORT)]
    await command(r.target, r.session, *clear, check=False)
    cleanup.append((r.target, clear))
    return wan_if, dut_wan_ip


async def _untagged_exchange(r, count):
    """Echo `count` datagrams from the LAN VM to the WAN host over the bare
    ports, one at a time, so each is one frame each way and the entries'
    counters can be held to exactly `count`. A lost reply is counted, not
    fatal, so the caller decides what loss means."""
    script = f'''
import json, socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.bind(({r.lan_ip!r}, {UNTAGGED_SPORT}))
echoed = lost = 0
for n in range({count}):
    payload = struct.pack('!Q', n) + b'ASK-pppoe-untagged'.ljust(56, b'.')
    s.sendto(payload, ({WAN_ENDPOINT!r}, {UNTAGGED_DPORT}))
    try:
        while True:
            data, addr = s.recvfrom(2048)
            if data == payload:
                break
    except TimeoutError:
        lost += 1
        continue
    assert addr == ({WAN_ENDPOINT!r}, {UNTAGGED_DPORT}), (n, addr)
    echoed += 1
s.close()
print(json.dumps({{'echoed': echoed, 'lost': lost}}))
'''
    result = await r.run_peer(script, timeout=count * 0.01 + 40, label="flowtable_pppoe_untagged")
    assert result.rc == 0, result.stdout
    return json.loads(result.stdout.strip().splitlines()[-1])


def _untagged_directions(r, flows):
    """The untagged flow's two installed directions, forward first, or None
    until hardware holds both."""
    lan, wan = f"{r.lan_ip}:{UNTAGGED_SPORT}", f"{WAN_ENDPOINT}:{UNTAGGED_DPORT}"
    forward = [f for f in flows if (f["src"], f["dst"]) == (lan, wan)]
    reverse = [f for f in flows if (f["src"], f["dst"]) == (wan, lan)]
    if len(forward) == len(reverse) == 1:
        return forward[0], reverse[0]
    return None


async def _untagged_window(r, echo):
    """Admit the untagged flow, then run UNTAGGED_COUNT round trips over it
    between two readings of everything the session keeps: its record, its
    ppp device's counters, and its download's entry in the adapter state."""
    for _ in range(10):
        await _untagged_exchange(r, 4)
        state = await r.state()
        if _untagged_directions(r, state["flows"]):
            break
    else:
        pytest.fail(f"the untagged flow was not admitted beside the session: {state}")
    before = await r.state()
    assert _untagged_directions(r, before["flows"]), before["flows"]
    record = _session_halves(before, r.session_identity)
    opened = time.monotonic()
    link = await _ppp_link(r)
    answered = echo.packets
    report = await _untagged_exchange(r, UNTAGGED_COUNT)
    answered = echo.packets - answered
    link_after = await _ppp_link(r)
    window = time.monotonic() - opened
    after = await r.state()
    return {"before": before, "after": after, "report": report, "answered": answered,
            "window": window, "record": record,
            "record_after": _session_halves(after, r.session_identity),
            "link": link, "link_after": link_after}


async def test_flowtable_pppoe_session_record_ignores_untagged_flows(pppoe_rig):
    """A session's hardware record ignores untagged flows that do not cross it.

    An entry whose ingress names no tag and no session still carries the strip
    that validates it arrived untagged, and that strip's statistics word is a
    count of zero at a pointer to the base of the statistics carve
    (insert_remove_vlan_hm()). The carve opens with the session pool, so the
    pointer is the receive half of the first session record -- the very
    address the download of a session holding that record counts into. Only
    the count tells the two apart. A microcode that followed the pointer
    whatever the count would put every untagged frame into that session's
    record, and through the fold into its ppp device's `ip -s link`; with the
    record free, into the free list's link, which occupies the same bytes.

    So a plain routed flow runs both ways between the bare ports while the
    session holds a record, and the record must not move at all. That is sharp
    while the session holds the first record, and here it does by
    construction: the pool is a stack laid down in carve order, taken from and
    returned to its head, so it hands out the first record every time until
    two sessions hold records at once -- and no case on this bench ever holds
    two, since each dials the only session (_session_identity). What of that
    can be read back is checked: no record held before the admission, exactly
    one after.

    The control is the session's own download: 64 frames through it still
    move the same record by exactly 64. A record that counted nothing at all
    would pass everything else here too.
    """
    r = pppoe_rig
    initial = await r.state()
    assert initial["session_records"] == 0, (
        "a session record outlived its device, so the one this case takes would "
        "not come off the head of the pool", initial["sessions"])
    cleanup = []
    transport = None
    try:
        wan_if, dut_wan_ip = await _untagged_path(r, cleanup)
        await r.table()
        await r.nft(f"add rule inet {ft.TABLE} forward ip saddr {r.lan_ip} "
                    f"ip daddr {WAN_ENDPOINT} udp sport {UNTAGGED_SPORT} "
                    f"udp dport {UNTAGGED_DPORT} flow add @fast")
        await r.exchange(count=4)
        await _download_only(r, initial)
        held = await r.state()
        row = _session_row(held, r.session_identity)
        assert row["slot"] == "yes" and row["dev"] == r.ppp_if, row
        assert held["session_records"] == held["session_slots"] == 1, held
        transport, echo = await asyncio.get_running_loop().create_datagram_endpoint(
            Echo, local_addr=(WAN_ENDPOINT, UNTAGGED_DPORT))
        echo.record_payloads = False
        # The concentrator reaches the LAN VM through the session, so the WAN
        # host's echoes would come back inside it. For the window its route to
        # the LAN VM goes by the DUT's WAN address instead, which leaves both
        # halves of the flow bare; the session's route is back before the
        # control, which needs it.
        await command(r.wan, r.session, "ip", "route", "replace", r.reachable,
                      "via", dut_wan_ip, "dev", wan_if)
        try:
            measured = await _untagged_window(r, echo)
        finally:
            await command(r.wan, r.session, "ip", "route", "replace", r.reachable,
                          "dev", r.ppp_if, check=False)
        r.record("pppoe-untagged-beside-session",
                 {**measured, "session": _session_text(r.session_identity)})

        before, after = measured["before"], measured["after"]
        old = _untagged_directions(r, before["flows"])
        new = _untagged_directions(r, after["flows"])
        _assert_undisturbed(r, before, after, new is not None and
                            [f["cookie"] for f in new] == [f["cookie"] for f in old])
        # Bare both ways: nothing described on either side of either
        # direction, so each entry's strip is the one that names no record.
        for flow, ingress, egress in ((old[0], TARGET_LAN_IF, TARGET_WAN_IF),
                                      (old[1], TARGET_WAN_IF, TARGET_LAN_IF)):
            assert (flow["in"], flow["out"]) == (ingress, egress), flow
            assert all(flow[k] == "-" for k in ("in_vlan", "out_vlan", "in_br", "out_br",
                                                "in_ppp", "out_ppp", "in_tnl", "out_tnl")), flow
        # Every round trip crossed in hardware, both ways.
        assert measured["report"] == {"echoed": UNTAGGED_COUNT, "lost": 0}, measured["report"]
        assert measured["answered"] == UNTAGGED_COUNT, measured["answered"]
        moved = [int(n["packets"]) - int(o["packets"]) for o, n in zip(old, new)]
        assert moved == [UNTAGGED_COUNT, UNTAGGED_COUNT], (moved, old, new)
        # Nothing crossed the session's download in hardware meanwhile, where
        # it is still installed -- it can go idle and expire in the window,
        # which retires the entry and keeps the record. So any movement below
        # is the pointer's and not traffic's.
        download = {f["cookie"]: int(f["packets"]) for f in before["flows"] if f["in_ppp"] != "-"}
        crossed = {f["cookie"]: int(f["packets"]) - download[f["cookie"]]
                   for f in after["flows"] if f["cookie"] in download}
        assert not any(crossed.values()), (crossed, before["flows"], after["flows"])
        record = {k: measured["record_after"][k] - measured["record"][k]
                  for k in measured["record"]}
        assert record == dict.fromkeys(record, 0), (
            f"{2 * UNTAGGED_COUNT} untagged frames moved the session's record",
            measured["record"], measured["record_after"])
        # What the session exchanges on its own meanwhile: each end sends an
        # LCP echo request every LCP_ECHO_INTERVAL seconds and answers the
        # other's, so the DUT receives at most two frames per interval, and a
        # window of w seconds overlaps at most ceil(w / interval) + 1 of them;
        # each is at most a full frame. A record counting the untagged flows
        # would fold thousands in here.
        allowance = 2 * (math.ceil(measured["window"] / LCP_ECHO_INTERVAL) + 1)
        link = {k: measured["link_after"][k] - measured["link"][k] for k in measured["link"]}
        assert 0 <= link["rx_packets"] <= allowance, (
            allowance, measured["window"], measured["link"], measured["link_after"])
        assert link["rx_bytes"] <= link["rx_packets"] * 1518, (
            measured["link"], measured["link_after"])
        assert after["errors"] == initial["errors"], (initial["errors"], after)
        row = _session_row(after, r.session_identity)
        assert row["slot"] == "yes", row
        assert after["session_records"] == after["session_slots"] == 1, after

        # The control. The download may have expired over the window, so it
        # is offered until hardware holds it again, then measured as
        # test_flowtable_pppoe_session_counters measures it.
        for _ in range(10):
            await r.exchange(count=4)
            state = await r.state()
            if any(f["in_ppp"] != "-" for f in state["flows"]):
                break
        else:
            pytest.fail(f"the session's download was not readmitted: {state}")
        download = _direction(state["flows"], INNER_LOCAL, r.lan_ip)
        halves = _session_halves(state, r.session_identity)
        payload = 256
        await r.exchange(count=64, payload_size=payload)
        burst = await r.state()
        counted = _direction(burst["flows"], INNER_LOCAL, r.lan_ip)
        _assert_undisturbed(r, state, burst, counted["cookie"] == download["cookie"])
        control = {k: v - halves[k] for k, v in _session_halves(burst, r.session_identity).items()}
        r.record("pppoe-untagged-control", {"before": halves, "delta": control,
                                            "download": [download, counted]})
        assert int(counted["packets"]) - int(download["packets"]) == 64, (download, counted)
        assert control == {"rx_packets": 64,
                           "rx_bytes": 64 * (20 + 8 + payload + PPP_RX_OVERHEAD),
                           "tx_packets": 0, "tx_bytes": 0}, (halves, control)
    finally:
        if transport:
            transport.close()
        # The table first, so its entries retire by unbinding rather than by
        # the routes below going out from under them.
        await command(r.target, r.session, "nft", "delete", "table", "inet", ft.TABLE,
                      check=False)
        for agent, argv in reversed(cleanup):
            await command(agent, r.session, *argv, check=False)


@pytest.mark.parametrize("target", ["dev-stats", "hardware"])
async def test_flowtable_pppoe_admission_failslab(pppoe_rig, target):
    """A session direction's admission takes a reference on the ppp device's
    statistics record before its hardware entry exists. A hardware failure
    after that has to hand the reference back, and the connection recovers by
    traffic alone. A failure creating the record itself is not an admission
    failure: that direction forwards in hardware and counts nowhere, which the
    record's references and counters both show.

    The UDP upload is Linux's and refused before it asks for any record, so
    the download is the one direction the fault can meet. Without a record
    from the download, the device has none at all."""
    from test_flowtable_failslab import slab_fault
    from test_flowtable_service import FAULT_DIR

    r = pppoe_rig
    # The guard is staged and cancelled over the DUT console; no service
    # fixture runs here to own the directory it lives in.
    r.service_console = r.console
    await console_command(r.console, "rm", "-rf", FAULT_DIR)
    await console_command(r.console, "mkdir", FAULT_DIR)
    try:
        initial = await r.state()
        await r.table()
        async with slab_fault(r, target, "pppoe-" + target) as fault:
            await r.exchange(count=4)
            hit = await fault.hit()
        deadline = time.monotonic() + 20
        while True:
            await r.exchange(count=4)
            state = await r.state()
            if len(state["flows"]) == 1:
                break
            assert time.monotonic() < deadline, state
    finally:
        await console_command(r.console, "rm", "-rf", FAULT_DIR, check=False)
    flows = await _download_only(r, initial)
    _assert_session(r, None, _direction(flows, INNER_LOCAL, r.lan_ip))
    state = await r.state()
    assert state["errors"] == initial["errors"] and state["fatal"] == state["quarantine"] == 0, state
    assert state["installs"] - state["deletes"] == state["entries"] == 1, state
    session = _session_text(r.session_identity)
    if target == "dev-stats":
        assert state["session_records"] == initial["session_records"], (initial, state)
        assert not [s for s in state["sessions"] if s["pppoe"] == session], state["sessions"]
        counted = None
    else:
        assert state["session_records"] == initial["session_records"] + 1, (initial, state)
        counted = _session_row(state, r.session_identity)
        assert counted["slot"] == "yes", counted
    before = {f["cookie"]: int(f["packets"]) for f in flows}
    installed = state
    await r.exchange(count=64)
    state = await r.state()
    _assert_undisturbed(r, installed, state, {f["cookie"] for f in state["flows"]} == set(before))
    assert {f["cookie"]: int(f["packets"]) - before[f["cookie"]]
            for f in state["flows"]} == {c: 64 for c in before}, (before, state["flows"])
    # The download strips the session header and the burst moved it by 64,
    # into the record's receive half where there is a record at all.
    if counted is None:
        row = None
        assert not [s for s in state["sessions"] if s["pppoe"] == session], state["sessions"]
    else:
        row = _session_row(state, r.session_identity)
        moved = {half: int(row[half + "_packets"]) - int(counted[half + "_packets"])
                 for half in ("rx", "tx")}
        assert row["refs"] == "1" and moved == {"rx": 64, "tx": 0}, (counted, row)
    r.record("pppoe-" + target + "-recovery", {"initial": initial, "state": state,
                                               "hit": hit, "row": row})
    # Retiring the connection returns exactly the references it took.
    await r.delete_table()
    if row is not None:
        row = _session_row(await r.state(), r.session_identity)
        assert row["refs"] == "0", row


def _snat_table(r):
    # nft rather than an iptables SNAT target, which this image has no module
    # for, and at priority 90 so it runs ahead of the fixture's own
    # priority-100 exemption rather than behind it.
    return (f"table ip {NAT_TABLE} {{ chain postrouting {{ "
            f"type nat hook postrouting priority 90; "
            f"ip saddr {r.lan_ip} ip daddr {INNER_LOCAL} "
            f"{r.proto} sport {SPORT} {r.proto} dport {DPORT} snat to {SNAT_ADDR}; }}; }}")


async def test_flowtable_pppoe_snat(pppoe_rig):
    """Source NAT across the session, proved at the far endpoint.

    The concentrator observing the translated source is what separates a
    rewrite that reached the wire from one that only reached the rule. The UDP
    upload is Linux's, so here the translation on the way out is software's
    and the hardware's half is the download's: the reverse translation, after
    the strip. The upload's translation in front of the insert is
    test_flowtable_pppoe_snat_tcp's.
    """
    r = pppoe_rig
    await command(r.target, r.session, "nft", _snat_table(r))
    try:
        flows, delta = await _established(r)
        reverse = _direction(flows, INNER_LOCAL, SNAT_ADDR)
        assert reverse["new_dst"].startswith(r.lan_ip + ":"), reverse
        _assert_session(r, None, reverse)
        assert all(d == 64 for d in delta.values()), delta
        # What the wire carried, not what the rule said it would.
        assert r.echo.sources == {(SNAT_ADDR, SPORT)}, r.echo.sources
        r.record("pppoe-snat", {"flows": flows, "delta": delta,
                                "observed": sorted(r.echo.sources)})
    finally:
        await command(r.target, r.session, "nft", "delete", "table", "ip", NAT_TABLE,
                      check=False)


@pytest.mark.parametrize("pppoe_rig", ["tcp"], indirect=True)
async def test_flowtable_pppoe_snat_tcp(pppoe_rig):
    """Source NAT in front of the insert, in hardware.

    The concentrator seeing the translated source connect, while the upload
    that carried the connection was in hardware, says the translation and the
    encapsulation were applied to the same frame in the right order: the
    rewrite before the session header went on, and the reverse translation
    after it came off.
    """
    r = pppoe_rig
    await command(r.target, r.session, "nft", _snat_table(r))
    try:
        await r.table()
        measured = await _tcp_carried(r, "flowtable_pppoe_snat_tcp")
        flows = measured["flows"]
        r.record("pppoe-snat-tcp", measured)
        forward = _direction(flows, r.lan_ip, INNER_LOCAL)
        assert forward["new_src"].startswith(SNAT_ADDR + ":"), forward
        reverse = _direction(flows, INNER_LOCAL, SNAT_ADDR)
        assert reverse["new_dst"].startswith(r.lan_ip + ":"), reverse
        _assert_session(r, forward, reverse)
        _assert_carried(r, measured)
        assert measured["peer"] == (SNAT_ADDR, SPORT), measured["peer"]
    finally:
        await command(r.target, r.session, "nft", "delete", "table", "ip", NAT_TABLE,
                      check=False)


@pytest.mark.parametrize("pppoe_rig", ["tagged", "tagged-tcp"], indirect=True)
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

    Over UDP the upload is Linux's and the mirror is what is proved; over TCP
    both directions are.
    """
    r = pppoe_rig
    if r.proto == "tcp":
        await r.table()
        delta = await _tcp_carried(r, "flowtable_pppoe_tagged_tcp")
        flows = delta["flows"]
        forward = _direction(flows, r.lan_ip, INNER_LOCAL)
        assert forward["in_vlan"] == str(LAN_VID), forward
        _assert_carried(r, delta)
    else:
        flows, delta = await _established(r)
        forward = None
        assert all(d == 64 for d in delta.values()), delta
    reverse = _direction(flows, INNER_LOCAL, r.lan_ip)
    _assert_session(r, forward, reverse)
    assert reverse["out_vlan"] == str(LAN_VID), reverse
    r.record("pppoe-tagged-lan-" + r.proto, {"flows": flows, "delta": delta,
                                             "lan_vid": LAN_VID, "wan_vid": WAN_VID})


async def test_flowtable_pppoe_full_mtu_datagram(pppoe_rig):
    """A datagram filling the session MTU still crosses it.

    The frame the session carries is twelve bytes longer than the datagram
    inside it: eight for the PPPoE and PPP headers and four for the tag the
    session stands on. If the hardware's own size check counted any of them,
    this is the payload that would be dropped or punted while a shorter one was
    forwarded, so the counters have to account for it exactly as for any other
    burst. 1492 is the path MTU rather than a number chosen here, which is what
    makes the reply the same size as the request.

    The UDP upload is Linux's, so the hardware's datagram here is the reply,
    stripped of all twelve; the insert's large segments are
    test_flowtable_pppoe_tcp's.
    """
    r = pppoe_rig
    initial = await r.state()
    await r.table()
    await r.exchange(count=4)
    before = {f["cookie"]: int(f["packets"]) for f in await _download_only(r, initial)}
    installed = await r.state()
    # The session MTU less the IPv4 and UDP headers: the largest datagram the
    # path takes without fragmenting, and exactly the one the eight bytes of
    # PPPoE would push over if they were counted twice.
    await r.exchange(count=16, payload_size=SESSION_MTU - 28)
    state = await r.state()
    after = {f["cookie"]: int(f["packets"]) for f in state["flows"]}
    _assert_undisturbed(r, installed, state, set(before) == set(after))
    delta = {c: after[c] - before[c] for c in before}
    assert all(d == 16 for d in delta.values()), delta
    r.record("pppoe-full-mtu", {"delta": delta, "payload": SESSION_MTU - 28})


async def _qos_bulk(r, seconds):
    """Start the unmarked flow on the LAN VM, detached, paced at QOS_BULK_MBIT
    towards a port on the far end that nothing reads. It is its own session
    under `timeout`, so a run that dies without its teardown leaves nothing
    sending for longer than that."""
    blaster = f'''
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(({r.lan_ip!r}, {PORT_QOS_BULK}))
payload = b'ASK-pppoe-qos-bulk'.ljust({QOS_DATAGRAM}, b'.')
per_second = {QOS_BULK_MBIT} * 1e6 / 8 / {QOS_DATAGRAM}
start = time.monotonic()
sent = 0
while time.monotonic() - start < {seconds}:
    s.sendto(payload, ({INNER_LOCAL!r}, {PORT_QOS_BULK}))
    sent += 1
    ahead = sent / per_second - (time.monotonic() - start)
    if ahead > 0.002:
        time.sleep(ahead)
'''
    script = f'''
import pathlib, subprocess
pathlib.Path({QOS_BULK_SCRIPT!r}).write_text({blaster!r})
proc = subprocess.Popen(['timeout', {str(seconds + 30)!r}, 'python3', {QOS_BULK_SCRIPT!r}],
                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL, start_new_session=True)
pathlib.Path({QOS_BULK_PID!r}).write_text(str(proc.pid))
print('BULK-UP')
'''
    result = await r.run_peer(script, label="pppoe_qos_bulk", timeout=30)
    assert result.rc == 0 and "BULK-UP" in result.stdout, result.stdout


async def _qos_bulk_stop(r):
    script = f'''
import os, pathlib, signal
pid = pathlib.Path({QOS_BULK_PID!r})
if pid.exists():
    try:
        os.killpg(int(pid.read_text()), signal.SIGTERM)
    except ProcessLookupError:
        pass
    pid.unlink()
print('BULK-DOWN')
'''
    result = await r.run_peer(script, label="pppoe_qos_bulk_stop", timeout=30)
    assert result.rc == 0 and "BULK-DOWN" in result.stdout, result.stdout


async def test_flowtable_pppoe_qos_upload_keeps_its_class(pppoe_rig):
    """A marked upload through the session lands on its class, and unmarked
    bulk through the same session cannot starve it.

    Every frame the CPU sends into a PPPoE session loses its conntrack and its
    ingress index before it reaches the port: ppp_start_xmit() scrubs both. The
    port's queue selection used to take such a frame for the gateway's own,
    which put every upload over the session -- marked or not -- on class queue
    7, above every class in the tree. The marked flow lost its class, and an
    unmarked one could take the whole channel from every leaf. Now the port
    reads the frame through the tag and the session header and finds the
    connection again by the translated packet's tuple.

    The tree is on the WAN port: one channel at QOS_RATE_MBIT and one prio 1
    leaf. The marked flow is translated, as a subscriber's is, and echoed one
    datagram at a time while the unmarked one offers three times the channel.
    Nothing is offloaded -- no flowtable is bound -- so this is the software
    path alone. The oracles are the port's CEETM counters: every marked frame
    on the leaf, the unmarked flow holding the unclassified queue full, and
    the control queue carrying only control traffic.
    """
    from test_flowtable_qos import OAL, egress, leaf_delta, timing_slack

    r = pppoe_rig
    mask = int((await read(r.target, r.session,
                           "/sys/module/ask_flowtable/parameters/qos_mark_mask")).strip())
    if not mask:
        pytest.skip("classification is off in this boot; the QoS case needs "
                    "ask_flowtable.qos_mark_mask=0xf0, which the test image ships")
    mark = QOS_VOICE_CQ << ((mask & -mask).bit_length() - 1)
    dev = TARGET_WAN_IF
    rate = f"{QOS_RATE_MBIT}mbit"

    async def tc(*argv, check=True):
        """`tc` is not in the agent's argv allowlist, so the tree is built on
        the console the fixture holds."""
        return await console_command(r.console, "tc", *argv, check=check, timeout=30)

    async def clear_ct():
        for port in (PORT_QOS_VOICE, PORT_QOS_BULK):
            await command(r.target, r.session, "conntrack", "-D", "-p", "udp",
                          "--orig-src", r.lan_ip, "--dport", str(port), check=False)

    # A port nothing reads: the far end queues what arrives until its buffer
    # is full and drops the rest, rather than answering every datagram with an
    # ICMP error back down the session.
    sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sink.bind((INNER_LOCAL, PORT_QOS_BULK))
    transport, echo = await asyncio.get_running_loop().create_datagram_endpoint(
        SourceEcho, local_addr=(INNER_LOCAL, PORT_QOS_VOICE))
    bulk = False
    try:
        await clear_ct()
        # A run killed before its teardown leaves its tree behind.
        await tc("qdisc", "del", "dev", dev, "root", check=False)
        await tc("qdisc", "add", "dev", dev, "root", "handle", "1:", "htb", "offload")
        await tc("class", "add", "dev", dev, "parent", "1:", "classid", "1:1",
                 "htb", "rate", rate, "ceil", rate)
        await tc("class", "add", "dev", dev, "parent", "1:1", "classid", "1:10",
                 "htb", "rate", rate, "ceil", rate, "prio", str(QOS_VOICE_PRIO))
        # The mark at forward/mangle, and the translation at the priority the
        # SNAT case uses, ahead of the image's own masquerade.
        await command(r.target, r.session, "nft", f"""table ip {QOS_TABLE} {{
 chain forward {{ type filter hook forward priority -150; policy accept;
 ip saddr {r.lan_ip} udp dport {PORT_QOS_VOICE} ct mark set {mark:#x}; }}
 chain postrouting {{ type nat hook postrouting priority 90; policy accept;
 ip saddr {r.lan_ip} ip daddr {INNER_LOCAL} udp dport {PORT_QOS_VOICE} snat to {SNAT_ADDR}; }}
}}""")
        await _qos_bulk(r, seconds=30)
        bulk = True
        await asyncio.sleep(3)
        first = await egress(r, dev)
        voice = f'''
import json, socket, struct, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(({r.lan_ip!r}, {PORT_QOS_VOICE}))
s.settimeout(1)
echoed = lost = 0
for n in range({QOS_COUNT}):
    payload = struct.pack('!Q', n) + b'ASK-pppoe-qos'.ljust(120, b'.')
    s.sendto(payload, ({INNER_LOCAL!r}, {PORT_QOS_VOICE}))
    try:
        while s.recv(2048) != payload:
            pass
        echoed += 1
    except TimeoutError:
        lost += 1
    time.sleep(0.02)
print(json.dumps({{'echoed': echoed, 'lost': lost}}))
'''
        result = await r.run_peer(voice, label="pppoe_qos_voice", timeout=QOS_COUNT * 1.1 + 30)
        assert result.rc == 0, result.stdout
        report = json.loads(result.stdout.strip().splitlines()[-1])
        second = await egress(r, dev)
        conntrack = await command(r.target, r.session, "conntrack", "-L", "-p", "udp",
                                  "--dport", str(PORT_QOS_VOICE), "-o", "extended", check=False)
    finally:
        if bulk:
            await _qos_bulk_stop(r)
        transport.close()
        sink.close()
        await tc("qdisc", "del", "dev", dev, "root", check=False)
        await command(r.target, r.session, "nft", "delete", "table", "ip", QOS_TABLE,
                      check=False)
        await clear_ct()
    voice_leaf = leaf_delta(first, second, 0)
    unclassified = leaf_delta(first, second, "default")
    control = leaf_delta(first, second, "control")
    window = second["at"] - first["at"]
    shaped = sum((q["bytes"] + OAL * q["frames"]) * 8
                 for q in (voice_leaf, unclassified, control)) / window
    r.record("pppoe-qos", {"report": report, "voice_leaf": voice_leaf,
                           "unclassified": unclassified, "control": control,
                           "shaped_bps": shaped, "window": window,
                           "sources": sorted(echo.sources),
                           "conntrack": conntrack["stdout"]})

    # Translated on the way, so the connection was found by the inverse of a
    # tuple the table does not hold.
    assert echo.sources == {(SNAT_ADDR, PORT_QOS_VOICE)}, echo.sources
    # Every marked frame on the leaf its mark names, and it lost nothing to
    # the unmarked flow beside it: the leaf is above the queue that flow is on.
    assert report["echoed"] + report["lost"] == QOS_COUNT, report
    assert report["lost"] <= QOS_COUNT // 100, report
    assert QOS_COUNT - report["lost"] <= voice_leaf["frames"] <= QOS_COUNT, (voice_leaf, report)
    assert voice_leaf["rejected"] == 0, voice_leaf
    # The unmarked flow held the unclassified queue full -- the queue refused
    # what the channel could not carry -- and the channel carried what it was
    # shaped to.
    assert unclassified["rejected"] > 0 and unclassified["frames"] > 0, unclassified
    slack = timing_slack(first, second)
    assert shaped >= (0.85 - slack) * QOS_RATE_MBIT * 1e6, (shaped, slack)
    # None of it rode the control queue, which now carries only control
    # traffic: the session's LCP, the gateway's own sessions.
    assert control["frames"] * 20 < unclassified["frames"], (control, unclassified)


@pytest.mark.parametrize("pppoe_rig", ["tcp"], indirect=True)
async def test_flowtable_pppoe_tcp(pppoe_rig):
    """An established TCP connection across the session.

    The classifier punts SYN, FIN and RST before its own lookup, so what the
    hardware actually carries is the bulk transfer in the middle. The cookies
    staying put is what proves the connection was never readmitted underneath
    it -- and with a session that matters more than elsewhere, because a
    readmission against a changed session would still forward, just to a
    header the concentrator no longer answers.

    It is also the upload in hardware, which UDP cannot be: the insert, the
    session MTU it carries, its large segments crossing whole, and the
    record's transmit half counting them into the ppp device's own counters.
    """
    r = pppoe_rig
    await r.table()
    measured = await _tcp_carried(r, "flowtable_pppoe_tcp")
    flows = measured["flows"]
    r.record("pppoe-tcp", {**measured, "session": _session_text(r.session_identity)})
    forward = _direction(flows, r.lan_ip, INNER_LOCAL)
    reverse = _direction(flows, INNER_LOCAL, r.lan_ip)
    _assert_session(r, forward, reverse)
    # The forward direction leaves by the session, so it carries the session's
    # MTU; nothing in this test set it, and the eight bytes are already in it.
    assert int(forward["mtu"]) == SESSION_MTU, forward
    _assert_carried(r, measured)


async def test_flowtable_pppoe_mtu_retires(pppoe_rig):
    """The ppp device carries its own MTU, and a flow through it depends on it.

    Each direction carries the MTU of the interface it leaves by. The UDP
    upload is Linux's at any session MTU below a full frame, so the direction
    in hardware is the download, which arrives by the session and leaves by
    the LAN port at the port's MTU. It still depends on the ppp device it
    arrives on: lowering the session retires the connection -- one increment,
    for the one invalidation handle both directions share -- and the download
    comes back as it was, the upload still refused. That the session direction
    describes the session's MTU is test_flowtable_pppoe_tcp's to show.
    """
    r = pppoe_rig
    await r.table()

    async def settled(expected, since=None):
        """`expected` maps the egress port of each direction hardware should
        hold to the MTU it should describe; `since`, a state the directions
        must have been installed after. Readmission needs traffic, so each
        attempt sends before it looks; nothing re-offers a retired flow on its
        own."""
        for _ in range(10):
            await r.exchange(count=4)
            state = await r.state()
            if (sorted(f["out"] for f in state["flows"]) == sorted(expected)
                    and all(int(f["mtu"]) == expected[f["out"]] for f in state["flows"])
                    and (since is None or state["installs"] > since["installs"])):
                return state
        pytest.fail(f"flow did not settle at {expected}: {state}")

    before = await settled({TARGET_LAN_IF: 1500})
    await command(r.target, r.session, "ip", "link", "set", r.ppp_if, "mtu", "1400")
    try:
        invalidated = await r.wait(
            lambda s: s["mtu_invalidations"] >= before["mtu_invalidations"] + 1)
        # The same shape as before, so what tells the readmitted download from
        # the retired one is that it was installed since.
        reduced = await settled({TARGET_LAN_IF: 1500}, since=before)
        assert reduced["errors"] == before["errors"], reduced
        assert reduced["rejects"] > invalidated["rejects"], (invalidated, reduced)
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
    flow borrowed that destination, so the route watch retires its directions,
    normally before the device is even unregistered. Should the unregistration
    arrive while the entries are still being taken out, it retires them too
    rather than stopping admission: a ppp device is neither bound nor a port.
    That makes a session drop *selective*: the retirement costs
    the directions it should and nothing else, the bindings stay up, and
    admission is never disabled. A drop is therefore self-healing -- the table
    is not touched, nothing re-arms, and the next packet re-offers the flow
    against whatever session exists then, which is the assertion that matters
    and the one a stale entry would fail. The UDP upload is Linux's, so the
    direction in hardware on either side of the redial is the download, and
    the session it names is the one it strips.
    """
    r = pppoe_rig
    flows, delta = await _established(r)
    reverse = _direction(flows, INNER_LOCAL, r.lan_ip)
    _assert_session(r, None, reverse)
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

    r.ppp_if, r.ppp_pid = await _dial(r.console, r.ppp_lower, ipv6=r.session_ipv6)
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
        if state["entries"] == 1:
            break
    else:
        pytest.fail(f"the flow was not readmitted after the redial: {state}")
    readmitted = await _download_only(r, retired)
    reverse = _direction(readmitted, INNER_LOCAL, r.lan_ip)
    # Against the session that exists now. A flow that had survived the hangup,
    # or been readmitted from anything cached, would name the old one -- which
    # is exactly the failure that forwards happily and delivers nothing.
    _assert_session(r, None, reverse, session=second)
    after = await r.state()
    # Readmitted through the bindings that were never disturbed: no global
    # invalidation to clear, and nothing to re-arm.
    assert after["bindings"] == 2 and after["rearms"] == before["rearms"], after
    assert after["invalidated"] == after["invalidation_done"] == 0, after
    assert after["errors"] == before["errors"], after
    # And the readmitted flow forwards, measured the same way as any other.
    counts = {f["cookie"]: int(f["packets"]) for f in readmitted}
    await r.exchange(count=32)
    measured = await r.state()
    final = {f["cookie"]: int(f["packets"]) for f in measured["flows"]}
    _assert_undisturbed(r, after, measured, set(final) == set(counts))
    assert all(final[c] - counts[c] == 32 for c in counts), (counts, final)
    r.record("pppoe-redial", {"first": _session_text(first),
                              "second": _session_text(second),
                              "before": before, "retired": retired, "after": after})


@pytest.mark.parametrize("mode", ["6o4", "4o6"])
@pytest.mark.parametrize("pppoe_rig", ["ipv6"], indirect=True)
async def test_flowtable_pppoe_tunnel(pppoe_rig, mode):
    """A tunnel whose outer packets leave by the session: 6rd or a tunnel
    broker on a PPPoE WAN for 6o4, DS-Lite on one for 4o6.

    One direction is both encapsulations at once -- the tunnel's outer header,
    then the session's, then the tag the session runs over -- and the other
    arrives inside all three. The outer header is addressed to the far end of
    the tunnel, which is not the neighbour the frame is for: the concentrator
    is, and the only place its Ethernet address is recorded is the session.
    Frames that reach the concentrator's ppp device, where the capture sits,
    are ones its PPPoE stack took for this session, which is the proof that
    the frame was addressed to it.

    A 4o6 UDP upload is Linux's -- an Ethernet LAN can deliver a full frame
    and the tunnel's path is smaller -- so for 4o6 the direction proved here
    is the one that arrives inside all three, and the records are held by it
    alone.
    """
    import test_flowtable_tunnel as tunnel

    r = pppoe_rig
    shape = tunnel.Shape(mode, 48960, 48961)
    if mode == "6o4":
        shape.outer, shape.mtu = (INNER_REMOTE, INNER_LOCAL), SESSION_MTU - 20
    else:
        shape.outer, shape.mtu = (INNER_REMOTE6, INNER_LOCAL6), SESSION_MTU - 60
    r.shape = shape
    # The concentrator's ppp device is where the outer packets are plain IP.
    r.wan_if = r.server_ppp_if
    cleanup, lan_cleanup = [], []
    transport = None
    try:
        await tunnel._lan_side(r, cleanup, lan_cleanup)
        if shape.family == 6:
            # The LAN advertises the tunnel's MTU, the configuration under
            # which an IPv6 direction into it is offloaded at all.
            key = f"net.ipv6.conf.{TARGET_LAN_IF}.mtu"
            previous = (await command(r.target, r.session, "sysctl", "-n", key))["stdout"].strip()
            cleanup.append((r.target, ["sysctl", "-w", f"{key}={previous}"]))
            await command(r.target, r.session, "sysctl", "-w", f"{key}={shape.mtu}")
        else:
            accept = ["POSTROUTING", "-s", r.lan_address, "-d", shape.inner_orch, "-p", "udp",
                      "--sport", str(shape.sport), "--dport", str(shape.dport), "-j", "ACCEPT"]
            await command(r.target, r.session, "iptables", "-t", "nat", "-I", *accept)
            cleanup.append((r.target, ["iptables", "-t", "nat", "-D", *accept]))
        await tunnel._dut_tunnel(r, cleanup)
        await tunnel._orchestrator_tunnel(r, cleanup)
        await tunnel._wait_reachable(r)
        await tunnel._clear_ct(r)
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            tunnel.EchoServer, local_addr=(shape.inner_orch, shape.dport),
            family=socket.AF_INET6 if shape.family == 6 else socket.AF_INET)
        before = await r.state()
        flows, delta = await tunnel._established(r, name=f"pppoe-{mode}")
        forward, reverse = tunnel._directions(r, flows)
        tunnel._assert_tunnel(r, forward, reverse)
        _assert_session(r, forward, reverse)
        assert all(d == 64 for d in delta.values()), delta
        state = await r.state()
        # One tunnel record and the one session record, each held by every
        # direction of the one connection that is in hardware.
        row = _session_row(state, r.session_identity)
        assert row["refs"] == str(len(flows)), (row, flows)
        tunnels = [t for t in state["tunnels"] if t["dev"] == shape.device]
        assert len(tunnels) == 1 and tunnels[0]["refs"] == str(len(flows)), state["tunnels"]
        assert state["errors"] == before["errors"], (before, state)
        r.record(f"pppoe-tunnel-{mode}", {"flows": flows, "delta": delta, "session": row,
                                          "tunnel": tunnels[0]})
    finally:
        if transport:
            transport.close()
        failures = []
        await command(r.target, r.session, "nft", "delete", "table", "inet", tunnel.TABLE,
                      check=False)
        if hasattr(r, "lan_address"):
            await tunnel._clear_ct(r)
        for agent, argv in reversed(cleanup):
            result = await command(agent, r.session, *argv, check=False)
            if result["rc"] and "Cannot find device" not in (result.get("stderr") or ""):
                failures.append(result)
        for cmd in reversed(lan_cleanup):
            await lan_run(r.lan, cmd)
        assert not failures, failures
