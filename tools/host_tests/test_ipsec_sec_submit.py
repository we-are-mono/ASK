"""How the DPAA driver hands a packet-offloaded frame to SEC, compiled from
the driver.

SEC takes the IP header length, the next-header offset and the next header
from DPOVRD instead of from the SA's PDB whenever the override bit is set, so
that value decides what a frame is encrypted as: a tunnel's names the inner
protocol, a transport SA's has to describe the frame's own IP header. And the
submit's answer decides what the port counts: `tx toenc` for a frame SEC was
given, a transmit drop for one freed instead.
"""

import os
from pathlib import Path
import subprocess

from test_qos_lifecycle import function

ROOT = Path(__file__).resolve().parents[2]


def test_ipsec_sec_submit(tmp_path):
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    source = (kernel / "drivers/net/ethernet/freescale/sdk_dpaa/dpaa_eth_sg.c").read_text()
    # The header sizes, the L3 finder, the DPOVRD choice and the submit.
    (tmp_path / "ipsec_sec_submit.inc").write_text(
        source[source.index("#define ETH_HDR_SIZE"):
               source.index("/* Whether @dev is a port of this driver")])
    binary = tmp_path / "ipsec_sec_submit"
    subprocess.run([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
        "-I", str(tmp_path), str(Path(__file__).with_name("ipsec_sec_submit.c")),
        "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })


def test_ipsec_inbound_submit_device(tmp_path):
    """Which frames the driver hands SEC on the way in, by the device they
    reached the stack on.

    xfrm_input() finds a packet-offloaded state by address and SPI and asks
    the driver to submit whatever arrived, on a bridge or a veth as readily
    as on a port, and the submit borrows the device's private area as a
    DPAA port's. The state's own port, or a VLAN or PPPoE session over it, is
    submitted as before; anything else, another port included, is given back
    untouched, for xfrm_input() to drop. Every device that is not a port
    keeps its private area on an unreadable page, so borrowing it fails the
    run.
    """
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    source = (kernel / "drivers/net/ethernet/freescale/sdk_dpaa/dpaa_eth_sg.c").read_text()
    (tmp_path / "ipsec_inbound_submit.inc").write_text(
        function(source, "dpa_netdev_is_dpaa_port")
        + function(source, "dpa_inb_port_ok")
        + function(source, "__dpaa_submit_inb_pkt_to_SEC")
        + function(source, "dpaa_submit_inb_pkt_to_SEC"))
    binary = tmp_path / "ipsec_inbound_submit"
    subprocess.run([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
        "-I", str(tmp_path), str(Path(__file__).with_name("ipsec_inbound_submit.c")),
        "-o", str(binary),
    ], check=True)
    # The harness reports a touch of the guard page itself, by name.
    subprocess.run([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1:handle_segv=0",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
