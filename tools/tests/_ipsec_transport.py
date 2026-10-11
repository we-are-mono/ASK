"""A packet-offloaded transport-mode SA from the DUT to a software peer on the
WAN host, either family."""
from __future__ import annotations

from _ipsec_inbound_flow_offload import (AUTH, CIPHER)
from _topology import TARGET_WAN_IF

REQID = "49521"
ALGORITHMS = ["mode", "transport", "reqid", REQID, "enc", "cbc(aes)", CIPHER,
              "auth-trunc", "hmac(sha256)", AUTH, "128"]


async def transport_sa(r, wan, step, outer, peer, spi, selector, policy_first=False):
    """The SA from the DUT's `outer` address to `peer` on the WAN host, with
    the policy selecting `selector` on both ends: the DUT's half
    packet-offloaded, the WAN host's ordinary software. `policy_first`
    installs the policies before the states, the order a trap policy has them
    in. `step` runs a command and records how to undo it."""
    state = ["src", outer, "dst", peer, "proto", "esp", "spi", hex(spi)]
    template = ["tmpl", "src", outer, "dst", peer, "proto", "esp", "mode", "transport",
                "reqid", REQID, "level", "required"]
    states = [
        (wan, ["ip", "xfrm", "state", "add", *state, *ALGORITHMS, "replay-window", "32"],
         ["ip", "xfrm", "state", "delete", *state]),
        (r.target, ["ip", "xfrm", "state", "add", *state, *ALGORITHMS,
                    "offload", "packet", "dev", TARGET_WAN_IF, "dir", "out"],
         ["ip", "xfrm", "state", "delete", *state]),
    ]
    policies = [
        (wan, ["ip", "xfrm", "policy", "add", *selector, "dir", "in", *template],
         ["ip", "xfrm", "policy", "delete", *selector, "dir", "in"]),
        (r.target, ["ip", "xfrm", "policy", "add", *selector, "dir", "out", *template,
                    "offload", "packet", "dev", TARGET_WAN_IF],
         ["ip", "xfrm", "policy", "delete", *selector, "dir", "out"]),
    ]
    for group in ((policies, states) if policy_first else (states, policies)):
        for agent, argv, undo in group:
            await step(agent, argv, undo)
