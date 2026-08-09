"""The enqueue opcode an entry hands a CPU egress, a WireGuard seal queue or a
Wi-Fi VAP's forwarding queue: kept on a receive port, refused on an offline
port. Compiled from create_enque_hm() (cdx/cdx_ehash.c) and the WireGuard arm
of the egress lookups (cdx/devman.c)."""

from ask_orch import kernel_line
from ask_orch.process import run_process

import os
from pathlib import Path
import re

from _host_pppoe_hm import (declaration, typedef)
from _host_qos_lifecycle import (function)
from mcast_hm import (loose_declaration)
from natpt_hm import (defines)

ROOT = Path(__file__).resolve().parents[2]
HEADER = "drivers/net/ethernet/freescale/sdk_fman/inc/Peripherals/fm_ehash.h"


def test_cpu_egress_storage_profile(tmp_path):
    # The line's SDK copy, so this does not depend on a previously built kernel.
    header = (kernel_line.sdk() / HEADER).read_text()
    common = (ROOT / "cdx/cdx_common.h").read_text()
    ipv4 = (ROOT / "cdx/control_ipv4.h").read_text()
    fe = (ROOT / "cdx/fe.h").read_text()
    ipsec = (ROOT / "cdx/cdx_dpa_ipsec.h").read_text()
    detour = (ROOT / "cdx/cdx_detour.h").read_text()
    portdefs = (ROOT / "cdx/portdefs.h").read_text()
    ehash = (ROOT / "cdx/cdx_ehash.c").read_text()
    devman = (ROOT / "cdx/devman.c").read_text()
    # The real descriptions: the entry builder's state, the enqueue and
    # preemptive-check parameters as the microcode reads them, the word's
    # flags, the detour stages and WireGuard's record.
    (tmp_path / "enqueue_types.inc").write_text(
        defines(common, "MAX_VLAN_HDRS|DPA_CLS_HM_MAX_VLANs|ETHER_ADDR_LEN|ETHER_TYPE_LEN")
        + declaration(common, "vlan_header")
        + declaration(common, "dpa_l2hdr_info")
        + typedef(common, "IPv4_HDR_STRUCT")
        + typedef(common, "IPv6_HDR_STRUCT")
        + declaration(common, "dpa_l3hdr_info")
        + declaration(common, "ins_entry_info")
        + defines(header, "ENQUEUE_PKT|PREEMPT_TX_VALIDATE|PREEMPT_DFBIT_HONOR")
        + loose_declaration(header, "en_ehash_preempt_op")
        + loose_declaration(header, "en_ehash_enqueue_param")
        + loose_declaration(header, "en_ehash_stats")
        + defines(ipsec, "DSCP_FQ_MAP_ENABLE|IPSEC_DPOVRD_ENABLE|IPSEC_IPV4_ENCAPSULATION|"
                         "IPSEC_IPV6_ENCAPSULATION|FRAG_DISABLE")
        + defines(detour, "CDX_DETOUR_NONE|CDX_DETOUR_OFFLINE|CDX_DETOUR_REDIRECT")
        + defines(ipv4, "FFTYPE_IPV4|FFTYPE_IPV6|FFTYPE_NATPT|CDX_NATPT_SLACK")
        + "".join(m.group() + "\n" for m in re.finditer(
            r"^#define IS_(IPV4_FLOW|IPV6_FLOW|NATPT)\(.*$", fe, re.M))
        + declaration(portdefs, "wg_iface_info"))
    (tmp_path / "enqueue_production.inc").write_text(
        re.search(r"^#define EHASH_IPV6_FLOW\s.*$", ehash, re.M).group() + "\n"
        + re.search(r"^#define MURAM_VIRT_TO_PHYS_ADDR\(.*$", ehash, re.M).group() + "\n"
        + re.search(r"^#define NULL_MAC_ADDR\(.*$", devman, re.M).group() + "\n"
        + function(ehash, "seal_preemptive_checks_hm")
        + function(ehash, "create_enque_hm")
        + function(devman, "dpa_l2_wg_egress"))
    binary = tmp_path / "enqueue_hm"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra", "-Werror",
        "-Wno-unused-function", "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
        "-I", str(tmp_path), str(Path(__file__).with_name("enqueue_hm.c")), "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
