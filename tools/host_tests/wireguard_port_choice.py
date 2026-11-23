"""Which ports WireGuard's fast path sends from, compiled from cdx.

The seal and the decrypted-inner forward ask cdx_wg_can_tx() of every frame
whether its egress port may take it straight onto the port's forwarding
queues. A port a hardware qdisc owns (cdx's HTB tree over CEETM, which marks
it with dpa_enable_ceetm()) sends from its class queues instead, and QMan
stops serving the channel the forwarding queues are on: such a port has to
keep its WireGuard frames on the slow path for as long as the tree is there,
or they wait on those queues until it goes (A457).
"""

import os
from pathlib import Path
import re

from ask_orch.process import run_process

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "cdx/cdx_wg.c"


def function(source, name):
    # The line has to begin with a word, the return type: a comment line that
    # names `foo()' would otherwise match and run on to the next definition.
    match = re.search(r"^(?:static )?\w[^\n]*\b" + name + r"\([^;]*?\)\s*\{", source, re.M)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


def test_wireguard_yields_a_port_a_hardware_qdisc_owns(tmp_path):
    source = SOURCE.read_text()
    table = re.search(r"^#define CDX_WG_PORTS .*?^static unsigned int cdx_wg_nports;\n",
                      source, re.M | re.S)
    assert table, "cdx_wg_ports"
    (tmp_path / "wireguard_port_choice_production.inc").write_text(
        table.group() + function(source, "cdx_wg_port") + function(source, "cdx_wg_can_tx"))
    binary = tmp_path / "wireguard_port_choice"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter", "-Wno-unused-function",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("wireguard_port_choice.c")), "-o", str(binary),
    ], check=True)
    result = run_process([str(binary)], text=True, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "yields an owned port" in result.stdout


def test_both_fast_paths_ask_the_port_choice():
    """The seal and the decrypted-inner forward are the two places cdx puts a
    WireGuard frame on a port's forwarding queues; both are handed the choice
    the first test proves."""
    source = re.sub(r"/\*.*?\*/", "", SOURCE.read_text(), flags=re.S)
    assert re.search(r"o->seal\(\s*dev,\s*cdx_wg_can_tx,", source), "seal"
    assert re.search(r"o->ft_raw\([^;]*\bcdx_wg_can_tx\b", source), "ft_raw"
