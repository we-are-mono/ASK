"""The software flowtable's NEIGH transmit, compiled from the kernel.

A NEIGH flow's frame leaves the software fast path for the routed next hop,
whose neighbour entry may not be resolved: ip_neigh_gw4()/ip_neigh_gw6()
create it empty when missing (after a flush, a link flap's purge, the GC),
and this path is the only one the flow's frames take, so nothing else gets
it resolved or a stale one confirmed again. Writing such an entry's address
into the frame sends the flow to an all-zero or stale destination until the
flow retires: the frame has to go through the neighbour's own output, which
queues it until the entry resolves, as neigh_xmit() does.
"""

import os
from pathlib import Path
import re

from ask_orch.process import run_process
from _kernel_source import kernel_source

HOOKS = ("nf_flow_offload_ip_hook", "nf_flow_offload_ipv6_hook")
# What the harness models rather than compiles: the tuple lookup and the
# forward step before the transmit, and the XFRM transmit beside it.
MODELLED = {"nf_flow_offload_lookup", "nf_flow_offload_ipv6_lookup", "nf_flow_offload_forward",
            "nf_flow_offload_ipv6_forward", "nf_flow_xmit_xfrm"}


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


def _code(source):
    """C source without its comments, which name functions too."""
    return re.sub(r"/\*.*?\*/|//[^\n]*", "", source, flags=re.S)


def _hooks(source):
    """The hooks and every helper of their file they call, as the file
    orders them."""
    found = {name: _definition(source, name) for name in HOOKS}
    assert all(found.values()), found
    pending = list(HOOKS)
    while pending:
        for called in set(re.findall(r"\b([a-z_]\w*)\s*\(", _code(found[pending.pop()][1]))):
            if called not in found and called not in MODELLED and (
                    definition := _definition(source, called)):
                found[called] = definition
                pending.append(called)
    return "".join(text for _, text in sorted(found.values()))


def test_neigh_transmit_resolves_the_next_hop(tmp_path):
    """Both hooks transmit a NEIGH flow's frame with the next hop's entry in
    every state: one not confirmed (none, incomplete, failed, stale, delay,
    probe) reaches the neighbour's output on the route's device and no header
    is written for it; a confirmed one's address is written, read whole under
    the entry's lock. A line whose hooks hand every frame to neigh_xmit()
    must give it every frame, on the route's device."""
    kernel = kernel_source()
    source = (kernel / "net/netfilter/nf_flow_table_ip.c").read_text()
    uapi = (kernel / "include/uapi/linux/neighbour.h").read_text()
    neighbour = (kernel / "include/net/neighbour.h").read_text()
    netdevice = (kernel / "include/linux/netdevice.h").read_text()
    hooks = _hooks(source)
    structs = [re.search(r"^struct nf_flowtable_ctx \{.*?^\};\n", source, re.M | re.S).group()]
    # The transmit's own description of a frame, where the hooks build one.
    if xmit := re.search(r"^struct nf_flow_xmit \{.*?^\};\n", source, re.M | re.S):
        structs.append(xmit.group())
    (tmp_path / "flowtable_neigh_transmit_types.inc").write_text(
        "".join(re.findall(r"^#define NUD_\w+\s+0x[0-9a-fA-F]+\n", uapi, re.M))
        + macro(neighbour, "NUD_VALID") + macro(neighbour, "NUD_CONNECTED")
        + macro(netdevice, "HH_DATA_MOD") + macro(netdevice, "LL_RESERVED_SPACE_EX")
        + macro(netdevice, "LL_RESERVED_SPACE") + "".join(structs))
    (tmp_path / "flowtable_neigh_transmit_production.inc").write_text(
        # How the line's hooks send a NEIGH flow's frame: 6.12 hands it to
        # neigh_xmit() on the route's device, 6.18 writes the header and
        # queues it to the device itself.
        ("#define NEIGH_XMIT_BY_DST\n" if "neigh_xmit(" in _code(hooks) else "")
        + function(neighbour, "neigh_ha_snapshot") + hooks)
    binary = tmp_path / "flowtable_neigh_transmit"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra",
        # The kernel builds without -Wpointer-sign: a u8 address buffer goes
        # to neigh_ha_snapshot()'s char *.
        "-Werror", "-Wno-unused-parameter", "-Wno-pointer-sign",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("flowtable_neigh_transmit.c")), "-o", str(binary),
    ], check=True)
    result = run_process([str(binary)], text=True, capture_output=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
    assert result.returncode == 0, result.stdout + result.stderr
    assert "each next hop resolved" in result.stdout
