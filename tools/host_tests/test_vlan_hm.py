"""Check the production VLAN header manipulations and what feeds them."""

import os
from pathlib import Path
import re
import subprocess

from test_ifstats import declaration as typed_declaration
from test_pppoe_hm import display, typedef
from test_qos_lifecycle import function


def declaration(source, name):
    """A struct as written, whichever line its brace opens on."""
    return typed_declaration(source, "struct", name)

ROOT = Path(__file__).resolve().parents[2]
HEADER = "drivers/net/ethernet/freescale/sdk_fman/inc/Peripherals/fm_ehash.h"


def test_vlan_hm(tmp_path):
    # The shipped patch, so this does not depend on a previously built kernel.
    subprocess.run([
        "git", "apply", f"--include={HEADER}",
        str(ROOT / "patches/kernel/010-ask-fman-dpaa-ehash.patch"),
    ], cwd=tmp_path, check=True)
    header = (tmp_path / HEADER).read_text()
    common = (ROOT / "cdx/cdx_common.h").read_text()
    ehash = (ROOT / "cdx/cdx_ehash.c").read_text()
    # The real L2 description, the real caller-supplied encapsulation and the
    # real opcode layouts: an index array resized or a list reordered on one
    # side of that boundary has to fail here rather than compile into a
    # counter update landing in another interface's record.
    (tmp_path / "vlan_hm_types.inc").write_text(
        re.search(r"^#define DPA_CLS_HM_MAX_VLANs.*$", common, re.M).group() + "\n"
        + re.search(r"^#define PAD\(.*$", ehash, re.M).group() + "\n"
        + declaration(common, "vlan_header")
        + declaration(common, "dpa_l2hdr_info")
        # And the L3 half, which an encapsulation naming a tunnel writes into.
        + typedef(common, "IPv4_HDR_STRUCT")
        + typedef(common, "IPv6_HDR_STRUCT")
        + declaration(common, "dpa_l3hdr_info")
        + declaration((ROOT / "cdx/control_ipv4.h").read_text(), "cdx_l2_encap")
        # Without their trailing comments: the header runs one of them over
        # several lines, and the first line alone is an unterminated comment
        # that would swallow the defines after it.
        + "\n".join(re.sub(r"\s*/\*.*$", "", line) for line in
                    re.findall(r"^#define\s+(?:MAX_VLAN_PER_FLOW|INSERT_VLAN_HDR|"
                               r"STRIP_ALL_VLAN_HDRS)\s.*$",
                               header, re.M)) + "\n"
        + declaration(header, "en_ehash_stats")
        + declaration(header, "en_ehash_insert_vlan_hdr")
        + declaration(header, "en_ehash_insert_vlan_hdr_stats")
        + declaration(header, "en_ehash_strip_all_vlan_hdrs"))
    (tmp_path / "vlan_hm.inc").write_text(
        function(ehash, "vlan_flow_stats_named")
        + function(ehash, "create_vlan_ins_hm")
        + function(ehash, "insert_remove_vlan_hm")
        + function(ehash, "apply_l2_encap")
        + display(header, "display_vlanhdr_insert_opc")
        + display(header, "display_strip_allvlan_hdr_opc"))
    binary = tmp_path / "vlan_hm"
    subprocess.run([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
        # Two warnings the kernel build does not enable and the vendor's
        # encoder does not satisfy: it walks packed opcode parameters through
        # word pointers and counts headers with a signed index.
        "-Wno-address-of-packed-member", "-Wno-sign-compare",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie", "-I", str(tmp_path),
        "-DINCLUDE_VLAN_IFSTATS=1", "-DINCLUDE_PPPoE_IFSTATS=1",
        "-DINCLUDE_ETHER_IFSTATS=1", "-DVLAN_FILTER=1",
        str(Path(__file__).with_name("vlan_hm.c")), "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
