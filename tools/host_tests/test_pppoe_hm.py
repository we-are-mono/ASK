"""Check the production PPPoE header manipulations and what feeds them."""

from ask_orch.process import run_process

from _host_pppoe_hm import (HEADER, ROOT, declaration, display, typedef)

import os
from pathlib import Path
import re

from _host_qos_lifecycle import (function)


def test_pppoe_hm(tmp_path):
    # The shipped patch, so this does not depend on a previously built kernel.
    run_process([
        "git", "apply", f"--include={HEADER}",
        str(ROOT / "patches/kernel/010-ask-fman-dpaa-ehash.patch"),
    ], cwd=tmp_path, check=True)
    header = (tmp_path / HEADER).read_text()
    common = (ROOT / "cdx/cdx_common.h").read_text()
    ehash = (ROOT / "cdx/cdx_ehash.c").read_text()
    # The real L2 description and the real caller-supplied encapsulation, not a
    # restatement of them: a field renamed or resized on either side of that
    # boundary has to fail here rather than compile into a silent mismatch.
    tunnel = (ROOT / "cdx/control_tunnel.h").read_text()
    (tmp_path / "pppoe_hm_types.inc").write_text(
        re.search(r"^#define DPA_CLS_HM_MAX_VLANs.*$", common, re.M).group() + "\n"
        + re.search(r"enum TNL_MODE \{[^}]*\};", tunnel, re.S).group() + "\n"
        + "\n".join(re.findall(r"^#define\s+(?:INHERIT_TC|DSCP_COPY)\s.*$",
                               tunnel, re.M)) + "\n"
        + declaration(common, "vlan_header")
        + declaration(common, "dpa_l2hdr_info")
        # The L3 description too: an encapsulation naming a tunnel reaches past
        # the L2 half into this one, so the same "real type, not a copy" rule
        # has to cover it.
        + typedef(common, "IPv4_HDR_STRUCT")
        + typedef(common, "IPv6_HDR_STRUCT")
        + declaration(common, "dpa_l3hdr_info")
        + declaration((ROOT / "cdx/control_ipv4.h").read_text(), "cdx_l2_encap")
        + "\n".join(re.findall(r"^#define\s+(?:PPPoE_VERSION|PPPoE_TYPE|PPPoE_CODE|"
                               r"STATS_WITH_TS|INSERT_PPPoE_HDR|STRIP_PPPoE_HDR)\s.*$",
                               header, re.M)) + "\n"
        + declaration(header, "en_ehash_stats_with_ts")
        + declaration(header, "en_ehash_insert_pppoe_hdr")
        + declaration(header, "en_ehash_strip_pppoe_hdr"))
    (tmp_path / "pppoe_hm.inc").write_text(
        function(ehash, "pppoe_stats_pointer")
        + function(ehash, "create_pppoe_ins_hm")
        + function(ehash, "insert_remove_pppoe_hm")
        + function(ehash, "apply_l2_encap")
        + display(header, "display_pppoehdr_insert_opc")
        + display(header, "display_strip_pppoe_hdr_opc"))
    binary = tmp_path / "pppoe_hm"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-I", str(tmp_path),
        "-DINCLUDE_VLAN_IFSTATS=1", "-DINCLUDE_PPPoE_IFSTATS=1",
        "-DINCLUDE_ETHER_IFSTATS=1", "-DVLAN_FILTER=1",
        str(Path(__file__).with_name("pppoe_hm.c")), "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
