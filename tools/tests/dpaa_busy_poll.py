"""No socket on a DPAA port can busy-poll a QMan portal."""

import json
import os

from ask_orch.commands import console_python
from ask_orch.uart import Console

# A QMan portal belongs to one CPU and is drained only by the poll its own
# interrupt scheduled, with that interrupt masked: qman_p_poll_dqrr() BUG()s
# otherwise. Busy polling calls a NAPI's poll from a socket's task, on whatever
# CPU it runs, once an skb the socket received carried the NAPI's id -- and GRO
# stamps every skb it takes with the id of the NAPI it was handed. SO_BUSY_POLL
# needs no privilege, so a portal NAPI with an id on a socket is a panic any
# local user can trigger. Every NAPI that drains a portal is registered
# NO_BUSY_POLL (tools/host_tests/qman_napi_busy_poll.py) and so has no id: a TCP
# socket the DUT holds across a DPAA port, its segments taken by GRO, reports
# none.
#
# The check never busy-polls: on a kernel that still stamps an id, that would
# panic the router. The id is the whole oracle, so the test first makes sure
# GRO ran (receive checksum validation and GRO on, as the driver defaults
# them) and that no global busy-poll setting would have polled the read itself.
PROBE = r"""
import json, os, socket, subprocess

SO_INCOMING_NAPI_ID = 56

route = subprocess.run(["ip", "-j", "route", "get", WAN], capture_output=True, text=True,
                       check=True)
dev = json.loads(route.stdout)[0]["dev"]
features = subprocess.run(["ethtool", "-k", dev], capture_output=True, text=True,
                          check=True).stdout
out = {"dev": dev,
       "driver": os.path.basename(os.readlink(f"/sys/class/net/{dev}/device/driver")),
       "features": {line.split(":")[0].strip(): line.split(":")[1].split()[0]
                    for line in features.splitlines()[1:] if ":" in line},
       "sysctl": {name: open(f"/proc/sys/net/core/{name}").read().strip()
                  for name in ("busy_read", "busy_poll")}}
if out["sysctl"] == {"busy_read": "0", "busy_poll": "0"}:
    sock = socket.create_connection((WAN, 9110), timeout=10)
    try:
        sock.sendall(b"GET /health HTTP/1.0\r\nHost: wan\r\n\r\n")
        received = 0
        while chunk := sock.recv(65536):
            received += len(chunk)
        out["received"] = received
        out["napi_id"] = sock.getsockopt(socket.SOL_SOCKET, SO_INCOMING_NAPI_ID)
    finally:
        sock.close()
print(json.dumps(out))
"""

# The SDK driver every DPAA port of this board is bound to.
DPAA_DRIVERS = ("fsl_dpa",)


async def test_no_dpaa_socket_can_busy_poll_a_portal(splat_window):
    wan = os.environ.get("ASK_WAN_IP", "127.0.0.1")
    result = await console_python(Console.target(), f"WAN = {json.dumps(wan)}\n" + PROBE,
                                  timeout=60)
    out = json.loads(result["stdout"])
    assert out["driver"] in DPAA_DRIVERS, ("the WAN agent is not reached over a DPAA port", out)
    assert out["sysctl"] == {"busy_read": "0", "busy_poll": "0"}, (
        "a global busy-poll setting is left on: reading the socket would busy-poll it", out)
    assert (out["features"].get("rx-checksumming"), out["features"].get(
        "generic-receive-offload")) == ("on", "on"), ("GRO did not take the frames", out)
    assert out["received"] > 0, ("no response from the WAN agent", out)
    assert out["napi_id"] == 0, (
        "a socket on a DPAA port carries a NAPI id: busy-polling it drains a CPU-affine "
        "QMan portal from the socket's task and panics", out)
