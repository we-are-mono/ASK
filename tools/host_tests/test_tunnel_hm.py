"""Check the production tunnel header manipulations' bytes and debug decoding."""

from ask_orch.process import run_process

import os
from pathlib import Path
import re

import pytest

from _host_qos_lifecycle import (function)

ROOT = Path(__file__).resolve().parents[2]
HEADER = "drivers/net/ethernet/freescale/sdk_fman/inc/Peripherals/fm_ehash.h"


def declaration(source, name):
    """One struct as written, brace-matched rather than pattern-matched, so a
    field added inside it comes along instead of truncating the type."""
    match = re.search(r"struct\s+" + name + r"\s*\{", source)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():source.index(";", end) + 1] + "\n"


def typedef(source, tag):
    """A typedef'd struct, tag through to the name it is typedef'd to. The two
    IP headers are declared this way and the L3 description embeds both."""
    match = re.search(r"typedef struct\s+" + tag + r"\b.*?\}\s*\w+\s*;", source, re.S)
    assert match, tag
    return match.group() + "\n"


def display(source, name):
    body = source[source.index("static inline void *" + name + "("):]
    return body[:body.index("\n}") + 3]


@pytest.mark.parametrize("ifstats", [False, True], ids=["no-stats", "stats"])
def test_tunnel_hm(tmp_path, ifstats):
    # Test the shipped patch, without depending on a previously built kernel.
    run_process([
        "git", "apply", f"--include={HEADER}",
        str(ROOT / "patches/kernel/010-ask-fman-dpaa-ehash.patch"),
    ], cwd=tmp_path, check=True)
    header = (tmp_path / HEADER).read_text()
    common = (ROOT / "cdx/cdx_common.h").read_text()
    tunnel = (ROOT / "cdx/control_tunnel.h").read_text()
    ehash = (ROOT / "cdx/cdx_ehash.c").read_text()
    # The real opcode numbers, modes, flags and structures, not a restatement
    # of them: an opcode renumbered or a field resized on either side of the
    # firmware boundary has to fail here rather than pass against a copy.
    (tmp_path / "tunnel_types.inc").write_text(
        "\n".join(re.findall(r"^#define\s+(?:TYPE_4o6|TYPE_6o4|IPID_STARTVAL|"
                             r"INSERT_L3_HDR|REMOVE_FIRST_IP_HDR|"
                             r"COPY_DSCP_OUTER_INNER)\s.*$", header, re.M)) + "\n"
        + re.search(r"enum TNL_MODE \{[^}]*\};", tunnel, re.S).group() + "\n"
        + "\n".join(re.findall(r"^#define\s+(?:INHERIT_TC|DSCP_COPY)\s.*$",
                               tunnel, re.M)) + "\n"
        + "\n".join(re.findall(r"^#define\s+ETHERTYPE_IPV[46]\s.*$",
                               (ROOT / "cdx/fe.h").read_text(), re.M)) + "\n"
        + typedef(common, "IPv4_HDR_STRUCT")
        + typedef(common, "IPv6_HDR_STRUCT")
        + declaration(common, "dpa_l3hdr_info")
        + declaration(header, "en_ehash_stats")
        + declaration(header, "en_ehash_insert_l3_hdr")
        + declaration(header, "en_ehash_remove_first_ip_hdr"))
    (tmp_path / "tunnel_hm.inc").write_text(
        # Get_Tnl_Ethertype() answers (outer << 16) | inner as a signed int, and
        # the 4o6 arm shifts 0x86dd into the sign bit -- undefined behaviour its
        # one caller then masks away. The real function is compiled rather than
        # restated, with that shift alone exempted from the sanitizer, so the
        # values it returns stay pinned to the production source.
        '__attribute__((no_sanitize("shift")))\n'
        + function(ehash, "Get_Tnl_Ethertype")
        # Only compiled into the statistics build, where the two opcodes reach
        # for it; without it there is no pointer to emit and no caller.
        + (function(ehash, "tunnel_stats_pointer") if ifstats else "")
        + function(ehash, "create_tunnel_insert_hm")
        + function(ehash, "create_tunnel_remove_hm")
        + display(header, "display_l3hdr_insert_opc")
        + display(header, "display_strip_first_iphdr"))
    binary = tmp_path / "tunnel_hm"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-I", str(tmp_path),
        *(["-DINCLUDE_TUNNEL_IFSTATS=1"] if ifstats else []),
        str(Path(__file__).with_name("tunnel_hm.c")), "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
