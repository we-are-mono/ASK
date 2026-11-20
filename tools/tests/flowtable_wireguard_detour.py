"""No offline-port entry leaves by a WireGuard device: UDP into a tunnel, and a
decrypted IPsec direction into one, stay in software, and every buffer goes
back to its pool.

A WireGuard device's default MTU (1420) is below what a standard LAN port
delivers, so an IPv4 UDP direction into it used to take the detour
(cdx_detour.c), its entry on the offline port enqueueing to the device's seal
queue (cdx_wg.c); a decrypted direction's entry lives on the IPsec offline
port. An offline-port entry that enqueues to a CPU egress with a storage
profile set (rspid) makes the microcode copy the frame into a fresh buffer and
never release the one it came in, so the pool it came from lost one buffer per
frame: the Ethernet pool for a detoured frame, SEC's output pool for a
decrypted one. A gateway stopped receiving on every port once its Ethernet pool
ran dry. Without the storage profile the frame would sit in its source pool in
the seal queues, which that pool's budget does not bound, so neither direction
is carried.

Whether the UDP direction took the detour depended on an unrelated IPsec policy
being configured (ft_mtu_refused() is skipped then), so that case runs both
ways.

The Ethernet pool's loss is read at idle as the driver's own count of what it
seeded (`ethtool -S`'s `bp count`) less what BMan holds (its sysfs pool_count):
the driver never learns of a buffer the hardware keeps.
"""
import asyncio
import json
import re
import socket
import threading
import time

import pytest
import pytest_asyncio

from _flowtable_rig import TABLE, command, read
from _topology import LAN_NIC, TARGET_LAN_IF, lan_run, lan_run_python
from flowtable_wireguard import host, inner, wg_counters, wg_rig  # noqa: F401  (wg_rig is a fixture)

POOLS = "/sys/devices/platform/soc/1890000.bman/pool_count"
# The WAN host's end of tunnel 0 receives here; the LAN VM sends from SPORT.
UDP_PORT, SPORT = 49170, 40170
FRAMES = 1000
# What idle wobbles by: the driver refills its pool eight buffers at a time
# per CPU, and a frame or two may be in flight when it is read.
SLACK = 16
# A never-matching outbound policy: its presence alone used to decide whether
# the direction took the detour.
DUMMY_POLICY = ["src", "203.0.113.1/32", "dst", "203.0.113.2/32", "dir", "out"]
DUMMY_TMPL = ["tmpl", "src", "203.0.113.1", "dst", "203.0.113.2", "proto", "esp", "mode", "tunnel"]


class WanEnd:
    """A UDP socket on the WAN host's tunnel address: answers "hello", counts
    the rest by size."""

    def __init__(self, address, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((address, port))
        self.sock.settimeout(0.2)
        self.sizes = {}
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while not self.stop.is_set():
            try:
                data, peer = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            if data.startswith(b"hello"):
                self.sock.sendto(b"hello-back", peer)
            else:
                self.sizes[len(data)] = self.sizes.get(len(data), 0) + 1

    def count(self, size):
        return self.sizes.get(size, 0)

    def close(self):
        self.stop.set()
        self.thread.join(timeout=2)
        self.sock.close()


async def ethernet_pool(r, bpid=None):
    """(the pool's id, what the hardware has lost from it): the driver's
    seeded count less BMan's, at idle. The Ethernet pool is by far the
    largest -- cdx's own pools hold 512 or 3584 -- and stays so even after a
    leak has taken thousands from it, which matching the driver's count
    would not."""
    await asyncio.sleep(1)
    out = (await command(r.target, r.session, "ethtool", "-S", TARGET_LAN_IF))["stdout"]
    seeded = int(re.search(r"bp count \[TOTAL\]:\s*(\d+)", out).group(1))
    if bpid is None:
        counts = {}
        for pool in range(64):
            try:
                counts[pool] = int((await read(r.target, r.session, f"{POOLS}/{pool}")).strip())
            except Exception:
                continue
        bpid = max(counts, key=counts.get)
        assert counts[bpid] > 4096, ("no pool large enough to be the Ethernet pool", seeded, counts)
    held = int((await read(r.target, r.session, f"{POOLS}/{bpid}")).strip())
    return bpid, seeded - held


async def sealed(r):
    return (await wg_counters(r))["wgt0"]["sealed"]


async def lan_send(r, count, size, hello=False, gap=0.0):
    """From the LAN VM's tunnel source: `hello` probes answered by the WAN
    end, or `count` datagrams of `size` bytes, `gap` seconds apart. Returns
    what the script printed."""
    script = f"""
import json, socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(({r.sources[0]!r}, {SPORT}))
s.settimeout(1.0)
dst = ({inner(0, 2)!r}, {UDP_PORT})
sent, replies, errors = 0, 0, []
if {hello!r}:
    for i in range(5):
        s.sendto(b"hello %d" % i, dst)
        try:
            s.recvfrom(64)
            replies += 1
        except socket.timeout:
            pass
else:
    payload = b"d" * {size}
    for i in range({count}):
        try:
            s.sendto(payload, dst)
            sent += 1
        except OSError as error:
            errors.append(error.errno)
        if {gap!r}:
            time.sleep({gap!r})
        elif i % 50 == 49:
            time.sleep(0.005)
print(json.dumps({{"sent": sent, "replies": replies, "errors": errors}}))
"""
    result = await lan_run_python(r.lan, script, label="wireguard_detour", timeout=120)
    assert result.rc == 0, result.stdout
    return json.loads(result.stdout.strip().splitlines()[-1])


@pytest.fixture
def wan_end():
    end = WanEnd(inner(0, 2), UDP_PORT)
    yield end
    end.close()


def udp_rows(state):
    """The flowtable's UDP rows leaving by the tunnel."""
    return [f for f in state["flows"] if f.get("out") == "wgt0" and f.get("proto") == "17"]


async def offered(r):
    """Offer the UDP direction into wgt0 (answered probes, so conntrack
    confirms it both ways) and give the adapter the offers it would have
    taken to install it -- Linux offers a flow again about once a second."""
    await command(r.target, r.session, "nft", "add", "rule", "inet", TABLE, "forward", "ip", "saddr",
                  r.sources[0], "ip", "daddr", "10.97.0.0/16", "meta", "l4proto", "udp", "flow", "add", "@fast")
    for _ in range(3):
        probe = await lan_send(r, 0, 0, hello=True)
        assert probe["replies"], ("the tunnel answered no probe", probe)
        await asyncio.sleep(1)


@pytest_asyncio.fixture(params=[False, True], ids=["no-policy", "policy"])
async def policy(request, wg_rig):
    """With and without an IPsec policy that matches nothing of the test's."""
    r = wg_rig
    if not request.param:
        yield False
        return
    await command(r.target, r.session, "ip", "xfrm", "policy", "add", *DUMMY_POLICY, *DUMMY_TMPL)
    try:
        yield True
    finally:
        await command(r.target, r.session, "ip", "xfrm", "policy", "del", *DUMMY_POLICY, check=False)


@pytest.mark.parametrize("wg_rig", [1], ids=["1T"], indirect=True)
async def test_udp_into_the_tunnel_stays_in_software(wg_rig, policy, wan_end):
    """UDP into the tunnel is never installed, whether or not an IPsec policy
    is configured: every datagram is delivered by Linux's own path, none is
    sealed by cdx, and the Ethernet pool keeps every buffer."""
    r = wg_rig
    await offered(r)
    bpid, lost = await ethernet_pool(r)
    seals = await sealed(r)
    # Paced for Linux's own path on a debug kernel.
    sent = await lan_send(r, FRAMES, 200, gap=0.001)
    assert sent["sent"] == FRAMES and not sent["errors"], sent
    deadline = time.monotonic() + 20
    while wan_end.count(200) < FRAMES and time.monotonic() < deadline:
        await asyncio.sleep(0.2)
    assert wan_end.count(200) == FRAMES, ("datagrams lost on the way", wan_end.sizes)
    rows = udp_rows(await r.state())
    assert not rows, ("the UDP direction into the tunnel was installed", rows)
    assert await sealed(r) == seals, "cdx sealed a datagram of a direction it should not carry"
    _, after = await ethernet_pool(r, bpid)
    assert after - lost < SLACK, (f"pool {bpid} lost {after - lost} buffers for {FRAMES} frames", lost, after)


# An ESP tunnel between the LAN VM and the DUT's LAN address, carrying the LAN
# VM's inner address to and from the WireGuard tunnel's subnet. Only the DUT's
# SAs are offloaded; the LAN VM's run in software.
ESP_INNER, ESP_PORT, WAN_PORT = "198.18.97.2", 49171, 40171
SPI_OUT, SPI_IN = "0x0a971171", "0x0a979171"
REQ_OUT, REQ_IN = "49171", "49172"
CIPHER, AUTH = "0x" + "a5" * 16, "0x" + "5a" * 32


def crypto(reqid):
    return ["mode", "tunnel", "reqid", reqid, "enc", "cbc(aes)", CIPHER,
            "auth-trunc", "hmac(sha256)", AUTH, "128"]


async def sec_pool(r):
    """(id, count) of SEC's output pool at idle, as cdx names it."""
    await asyncio.sleep(1)
    bpid = int((await read(r.target, r.session, "/sys/module/cdx/parameters/ipsec_bpid")).strip())
    assert bpid >= 0, "cdx has no SEC output pool"
    return bpid, int((await read(r.target, r.session, f"{POOLS}/{bpid}")).strip())


@pytest.mark.parametrize("wg_rig", [1], ids=["1T"], indirect=True)
async def test_decrypted_udp_into_the_tunnel_stays_in_software(wg_rig):
    """A decrypted IPsec direction leaving by the WireGuard device, whose entry
    would live on the IPsec offline port, is never installed: every datagram is
    delivered by Linux's own path, none is sealed by cdx, and SEC's output pool
    keeps every buffer."""
    r = wg_rig
    lan, dut_ip = r.lan, None
    out = (await command(r.target, r.session, "ip", "-j", "-4", "addr", "show", "dev", TARGET_LAN_IF))["stdout"]
    dut_ip = json.loads(out)[0]["addr_info"][0]["local"]
    link = await lan_run(lan, f"ip -o -4 addr show dev {LAN_NIC}")
    lan_ip = next(word.split("/")[0] for word in link.stdout.split()
                  if word.count(".") == 3 and "/" in word and not word.startswith(r.sources[0]))
    wg_net = "10.97.0.0/24"
    out_state = ["src", dut_ip, "dst", lan_ip, "proto", "esp", "spi", SPI_OUT]
    in_state = ["src", lan_ip, "dst", dut_ip, "proto", "esp", "spi", SPI_IN]
    out_tmpl = ["tmpl", "src", dut_ip, "dst", lan_ip, "proto", "esp", "mode", "tunnel", "reqid", REQ_OUT,
                "level", "required"]
    in_tmpl = ["tmpl", "src", lan_ip, "dst", dut_ip, "proto", "esp", "mode", "tunnel", "reqid", REQ_IN,
               "level", "required"]
    to_lan = ["src", wg_net, "dst", f"{ESP_INNER}/32"]
    from_lan = ["src", f"{ESP_INNER}/32", "dst", wg_net]

    def shell(argv):
        return " ".join(f"'{word}'" if "(" in word else word for word in argv)

    try:
        # The LAN VM's half, in software.
        for cmd in (f"ip xfrm state flush; ip xfrm policy flush; ip address add {ESP_INNER}/32 dev lo 2>/dev/null; true",
                    "ip xfrm state add " + shell([*out_state, *crypto(REQ_OUT), "replay-window", "32"]),
                    "ip xfrm state add " + shell([*in_state, *crypto(REQ_IN), "replay-window", "32"]),
                    "ip xfrm policy add " + shell([*to_lan, "dir", "in", *out_tmpl]),
                    "ip xfrm policy add " + shell([*from_lan, "dir", "out", *in_tmpl])):
            result = await lan_run(lan, cmd, 25)
            assert result.rc == 0, (cmd, result.stdout)
        # The DUT's half, offloaded; and a forward policy, without which a
        # decrypted packet that is forwarded is rejected.
        for argv in (["ip", "xfrm", "state", "add", *out_state, *crypto(REQ_OUT), "offload", "packet",
                      "dev", TARGET_LAN_IF, "dir", "out"],
                     ["ip", "xfrm", "state", "add", *in_state, *crypto(REQ_IN), "offload", "packet",
                      "dev", TARGET_LAN_IF, "dir", "in"],
                     ["ip", "xfrm", "policy", "add", *to_lan, "dir", "out", *out_tmpl, "offload", "packet",
                      "dev", TARGET_LAN_IF],
                     ["ip", "xfrm", "policy", "add", *from_lan, "dir", "in", *in_tmpl, "offload", "packet",
                      "dev", TARGET_LAN_IF],
                     ["ip", "xfrm", "policy", "add", *from_lan, "dir", "fwd", *in_tmpl],
                     ["ip", "route", "replace", f"{ESP_INNER}/32", "via", lan_ip, "dev", TARGET_LAN_IF],
                     # Only an original-direction packet creates a flow, and
                     # every decrypted one carries a sec_path: the WAN host's
                     # side originates it, so the decrypted direction is its
                     # reverse.
                     ["nft", "add", "rule", "inet", TABLE, "forward", "ip", "saddr", wg_net, "ip", "daddr",
                      ESP_INNER, "meta", "l4proto", "udp", "flow", "add", "@fast"],
                     ["conntrack", "-F"]):
            await command(r.target, r.session, *argv)
        # The WAN host's end routes the inner address back through its tunnel.
        peer = host("wg", "show", "wgt0", "peers").stdout.split()[0]
        allowed = host("wg", "show", "wgt0", "allowed-ips").stdout.split()[1:]
        host("wg", "set", "wgt0", "peer", peer, "allowed-ips", ",".join([*allowed, f"{ESP_INNER}/32"]))
        host("ip", "route", "replace", f"{ESP_INNER}/32", "dev", "wgt0")
        # Found and read at idle, before any of the test's traffic.
        bpid, before = await sec_pool(r)

        # The LAN VM answers the WAN host's probes, then sends the load back
        # from the same socket, once the probes have made the flow and the
        # baselines are read.
        task = asyncio.create_task(lan_run_python(lan, f"""
import json, socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(({ESP_INNER!r}, {ESP_PORT}))
s.settimeout(30)
seen, peer = 0, None
while seen < 5:
    data, peer = s.recvfrom(64)
    s.sendto(b"hello-back", peer)
    seen += 1
time.sleep(10)
# Paced for Linux's own path on a debug kernel.
for i in range({FRAMES}):
    s.sendto(b"d" * 200, peer)
    time.sleep(0.001)
print(json.dumps({{"sent": {FRAMES}}}))
""", label="esp_inner_peer", timeout=90))
        await asyncio.sleep(2)
        wan = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        wan.bind((inner(0, 2), WAN_PORT))
        wan.settimeout(1)
        replies = 0
        for i in range(5):
            wan.sendto(b"hello %d" % i, (ESP_INNER, ESP_PORT))
            try:
                wan.recv(64)
                replies += 1
            except OSError:
                pass
        assert replies, "the LAN VM's end answered no probe through both tunnels"

        def decrypted(state):
            return [f for f in state["flows"] if f.get("out") == "wgt0" and f.get("in_sa") not in (None, "0")]
        # The offers an installed direction would have taken, inside the
        # LAN VM's pause before the load.
        await asyncio.sleep(3)
        seals = await sealed(r)
        received, deadline = 0, time.monotonic() + 60
        while received < FRAMES and time.monotonic() < deadline:
            try:
                if len(wan.recv(2048)) == 200:
                    received += 1
            except OSError:
                if task.done():
                    break
        wan.close()
        result = await task
        assert result.rc == 0, result.stdout
        assert received == FRAMES, ("decrypted datagrams lost on the way", received)
        rows = decrypted(await r.state())
        assert not rows, ("the decrypted direction into the tunnel was installed", rows)
        assert await sealed(r) == seals, "cdx sealed a datagram of a direction it should not carry"
        await asyncio.sleep(1)
        after = int((await read(r.target, r.session, f"{POOLS}/{bpid}")).strip())
        assert before - after < SLACK, (f"SEC's pool {bpid} lost {before - after} buffers for {FRAMES} frames",
                                        before, after)
    finally:
        await command(r.target, r.session, "ip", "xfrm", "policy", "flush", check=False)
        await command(r.target, r.session, "ip", "xfrm", "state", "flush", check=False)
        await command(r.target, r.session, "ip", "route", "del", f"{ESP_INNER}/32", check=False)
        await lan_run(lan, f"ip xfrm state flush; ip xfrm policy flush; "
                           f"ip address del {ESP_INNER}/32 dev lo 2>/dev/null; true", 25)
        host("ip", "route", "del", f"{ESP_INNER}/32", check=False)
