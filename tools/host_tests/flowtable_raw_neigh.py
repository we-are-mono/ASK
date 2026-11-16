"""The WireGuard raw forward's next hop, compiled from the kernel.

nf_flow_offload_ip_raw() forwards a tunnel's packet where WireGuard decrypted
it, and for a flow it takes, that is the only path the flow's packets take:
the stack's output never sees them, so nothing else tells the neighbour layer
the next hop's entry is in use. A valid entry the layer has not confirmed
(stale, delay, probe) is still sent to at its address, as the stack's own
output does, but with the layer told (neigh_event_send()): that marks the
entry used and moves a stale one on to DELAY and PROBE, which confirms the
address or learns the new one. Untold, the entry stays stale, and a next hop
that changed its address unannounced is sent to at the old one for as long
as the flow lives.
"""

import os
from pathlib import Path
import re

from ask_orch.process import run_process
from _kernel_source import kernel_source

RAW = "nf_flow_offload_ip_raw"
# The neighbour layer's inline helpers, compiled as the tree defines them:
# the address snapshot and the use report to its state machine.
NEIGHBOUR = ("neigh_ha_snapshot", "neigh_event_send_probe", "neigh_event_send")


def _definition(source, name):
    """Where a function is defined, its return type on the line of its name
    or alone on the line above; None when the file defines none. The line has
    to begin with a word, so a comment naming `foo()' never matches."""
    match = re.search(r"^(?:\w[\w ]*\*?[ \t]*\n)?(?:\w[^\n;]*?[\s*])?" + re.escape(name)
                      + r"\([^;]*?\)\s*\{", source, re.M)
    if not match:
        return None
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return match.start(), source[match.start():end] + "\n"


def function(source, name):
    found = _definition(source, name)
    assert found, name
    return found[1]


def macro(source, name):
    match = re.search(r"^#define " + name + r"\b(?:[^\n]*\\\n)*[^\n]*", source, re.M)
    assert match, name
    return match.group() + "\n"


def structure(source, name):
    match = re.search(r"^struct " + name + r" \{.*?^\};\n", source, re.M | re.S)
    assert match, name
    return match.group()


def _code(source):
    """C source without its comments, which name functions too."""
    return re.sub(r"/\*.*?\*/|//[^\n]*", "", source, flags=re.S)


def _raw(source):
    """The raw path and every helper of its file it calls, as the file
    orders them."""
    found = {RAW: _definition(source, RAW)}
    assert found[RAW], RAW
    pending = [RAW]
    while pending:
        for called in set(re.findall(r"\b([a-z_]\w*)\s*\(", _code(found[pending.pop()][1]))):
            if called not in found and (definition := _definition(source, called)):
                found[called] = definition
                pending.append(called)
    return "".join(text for _, text in sorted(found.values()))


def test_raw_forward_tells_the_neighbour_layer_of_an_unconfirmed_next_hop(tmp_path):
    """The raw path forwards a routed, untranslated flow's packet with the
    next hop's entry in every state: one with no address (none, incomplete,
    failed) refuses it untouched for the stack to resolve; one with an address
    the neighbour layer has to confirm again (stale, delay, probe) carries it
    to that address and marks the entry used, a stale one handed to the
    layer's state machine to move on to DELAY; a confirmed one carries it to
    its address and is left alone."""
    kernel = kernel_source()
    source = (kernel / "net/netfilter/nf_flow_table_ip.c").read_text()
    uapi = (kernel / "include/uapi/linux/neighbour.h").read_text()
    neighbour = (kernel / "include/net/neighbour.h").read_text()
    flowtable = (kernel / "include/net/netfilter/nf_flow_table.h").read_text()
    (tmp_path / "flowtable_raw_neigh_types.inc").write_text(
        "".join(re.findall(r"^#define NUD_\w+\s+0x[0-9a-fA-F]+\n", uapi, re.M))
        + macro(neighbour, "NUD_VALID") + macro(neighbour, "NUD_CONNECTED")
        + structure(flowtable, "flow_ports") + structure(flowtable, "nf_flow_raw_xmit"))
    raw = _raw(source)
    # A line with a closing state (6.14) tears a closing flow down on a SYN
    # rather than passing the SYN past conntrack.
    closing = re.search(r"\bNF_FLOW_CLOSING,", flowtable)
    (tmp_path / "flowtable_raw_neigh_production.inc").write_text(
        ("#define HAVE_FLOW_CLOSING\n" if closing else "")
        + "".join(function(neighbour, name) for name in NEIGHBOUR) + raw)
    binary = tmp_path / "flowtable_raw_neigh"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra",
        # The kernel builds without -Wpointer-sign: the u8 address buffer
        # goes to neigh_ha_snapshot()'s char *.
        "-Werror", "-Wno-unused-parameter", "-Wno-pointer-sign",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("flowtable_raw_neigh.c")), "-o", str(binary),
    ], check=True)
    result = run_process([str(binary)], text=True, capture_output=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
    assert result.returncode == 0, result.stdout + result.stderr
    assert "each unconfirmed next hop told" in result.stdout
