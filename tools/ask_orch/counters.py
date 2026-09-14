"""Software-path counters for the ASK SDK DPAA driver.

Netdev statistics include CDX's hardware counters. The driver's private
ethtool RX counter comes from its per-CPU software statistics instead.
"""

import re


async def kernel_rx_packets(target_agent, session, iface: str) -> int:
    """Read SDK DPAA software RX packets; fail if that counter is unavailable.

    Use a physical ingress port. A low delta proves offload only alongside
    successful delivery; frames dropped before software RX also omit it.
    """
    r = await target_agent.exec_cmd(session, ["ethtool", "-S", iface])
    assert r.get("rc") == 0, f"ethtool -S {iface} failed: {r}"
    values = re.findall(
        r"^\s*rx packets \[TOTAL\]:\s*(\d+)\s*$",
        r.get("stdout", ""), re.M,
    )
    assert len(values) == 1, (
        f"expected one SDK DPAA 'rx packets [TOTAL]' counter on {iface}; "
        f"cannot determine software RX from: {r.get('stdout', '')!r}"
    )
    return int(values[0])
