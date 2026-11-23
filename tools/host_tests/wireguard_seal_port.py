"""Whether the WireGuard seal asks its caller about the port per packet.

The seal (wg_fastpath_seal(), kernel patch 180) sends from a per-peer header
template it rebuilds once a second, and asks its caller (cdx_wg_can_tx())
whether it can transmit on the port. A hardware qdisc can take the port at any
moment, and from then on the queues the caller sends on are not served, so the
question has to be asked of every packet, not only when the template is
rebuilt: otherwise up to a second of sealed frames never leave (A457).
Compiled from the patched kernel tree.
"""

import os
from pathlib import Path
import re

from ask_orch.process import run_process
from _kernel_source import kernel_source

FASTPATH = Path("drivers/net/wireguard/fastpath.c")


def _block(source, start):
    end, depth = source.index("{", start) + 1, 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def test_seal_refuses_a_port_a_hardware_qdisc_takes(tmp_path):
    source = (kernel_source() / FASTPATH).read_text()
    struct = re.search(r"^struct wg_fastpath_tmpl \{", source, re.M)
    assert struct, "struct wg_fastpath_tmpl"
    (tmp_path / "wireguard_seal_tmpl_struct.inc").write_text(
        _block(source, struct.start()) + ";\n")
    # Every lookup of the template the seal goes through, in source order
    # (wg_fp_build(), which the harness stands in for, is not one).
    lookups = [_block(source, m.start()) for m in re.finditer(
        r"^static struct wg_fastpath_tmpl \*wg_fp_tmpl\w*\(", source, re.M)]
    assert lookups, "wg_fp_tmpl"
    (tmp_path / "wireguard_seal_tmpl_production.inc").write_text("\n\n".join(lookups) + "\n")
    binary = tmp_path / "wireguard_seal_port"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter", "-Wno-unused-function",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("wireguard_seal_port.c")), "-o", str(binary),
    ], check=True)
    result = run_process([str(binary)], text=True, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "refused from the next packet" in result.stdout


def test_seal_takes_its_header_from_the_checked_lookup():
    """The seal reaches the template through the lookup the first test
    proves, and sends only from a template it returned."""
    source = (kernel_source() / FASTPATH).read_text()
    seal = re.search(r"^int wg_fastpath_seal\(", source, re.M)
    assert seal, "wg_fastpath_seal"
    body = re.sub(r"/\*.*?\*/", "", _block(source, seal.start()), flags=re.S)
    assert re.findall(r"\bwg_fp_tmpl\w*\(", body) == ["wg_fp_tmpl("], body
