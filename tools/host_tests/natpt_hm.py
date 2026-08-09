"""A direction translated between the families (NAT64, SIIT): the production
action selector's order and flags for it, and the bytes its NAT, NAT-PT and
Ethernet emitters write, as the microcode reads them (docs/flowtable/nat64.md).
"""

from ask_orch import kernel_line
from ask_orch.process import run_process

import os
from pathlib import Path
import re

from _host_pppoe_hm import (declaration, typedef)
from _host_qos_lifecycle import (function)
from mcast_hm import (loose_declaration)

ROOT = Path(__file__).resolve().parents[2]
HEADER = "drivers/net/ethernet/freescale/sdk_fman/inc/Peripherals/fm_ehash.h"


def defines(text, names):
    """Name and value only, as several definitions carry comments past the
    line."""
    return "".join(f"#define {name} {value}\n" for name, value in re.findall(
        r"^#define\s+(" + names + r")\s+(\([^)]*\)|\S+)", text, re.M))


def test_natpt_selector_and_emitters(tmp_path):
    # The line's SDK copy, so this does not depend on a previously built kernel.
    header = (kernel_line.sdk() / HEADER).read_text()
    common = (ROOT / "cdx/cdx_common.h").read_text()
    ipv4 = (ROOT / "cdx/control_ipv4.h").read_text()
    fe = (ROOT / "cdx/fe.h").read_text()
    ehash = (ROOT / "cdx/cdx_ehash.c").read_text()
    # The real descriptions, not restatements: the entry builder's own state,
    # the opcode parameters as the microcode reads them, and the entry type
    # and flags the selector keys on.
    (tmp_path / "natpt_types.inc").write_text(
        defines(common, "MAX_VLAN_HDRS|DPA_CLS_HM_MAX_VLANs|ETHER_ADDR_LEN|ETHER_TYPE_LEN")
        + declaration(common, "vlan_header")
        + declaration(common, "dpa_l2hdr_info")
        + typedef(common, "IPv4_HDR_STRUCT")
        + typedef(common, "IPv6_HDR_STRUCT")
        + declaration(common, "dpa_l3hdr_info")
        + declaration(common, "ins_entry_info")
        + defines(header, "IPID_STARTVAL|UPDATE_SPORT|UPDATE_DPORT|UPDATE_TTL|UPDATE_HOPLIMIT|"
                          "UPDATE_SIP_V4|UPDATE_DIP_V4|UPDATE_SIP_V6|UPDATE_DIP_V6|INSERT_L2_HDR")
        + loose_declaration(header, "en_ehash_update_port")
        + loose_declaration(header, "en_ehash_update_ipv4_ip")
        + loose_declaration(header, "en_ehash_update_ipv6_ip")
        + loose_declaration(header, "en_ehash_insert_l2_hdr")
        + re.search(r"union ctentry_qosmark \{.*?\n\};\n", ipv4, re.S).group()
        + re.search(r"^#define INGRESS_FLOW_POLICER_QUEUES\s.*$",
                    (ROOT / "cdx/cdx_ioctl.h").read_text(), re.M).group() + "\n"
        + defines(ipv4, "FFTYPE_IPV4|FFTYPE_IPV6|FFTYPE_NATPT|CDX_NATPT_SLACK|CDX_NATPT_TOS_COPY|"
                        "CONNTRACK_NAT|CONNTRACK_SNAT|CONNTRACK_DNAT|CONNTRACK_ORIG")
        + "".join(m.group() + "\n" for m in re.finditer(
            r"^#define IS_(IPV4|IPV4_FLOW|IPV6|IPV6_FLOW|NATPT)\(.*$", fe, re.M)))
    start = ehash.index("#ifndef NATPT_4to6")
    end = ehash.index("} __attribute__((packed));", start) + len("} __attribute__((packed));")
    (tmp_path / "natpt_emitters.inc").write_text(
        # The selector's flags, and NAT-PT's opcodes and parameter.
        ehash[ehash.index("#define TTL_HM_VALID"):ehash.index("#define MURAM_VIRT_TO_PHYS_ADDR")]
        + ehash[start:end] + "\n"
        + function(ehash, "create_natpt_hm")
        + function(ehash, "create_nat_hm")
        + function(ehash, "create_ethernet_hm"))
    (tmp_path / "natpt_select.inc").write_text(function(ehash, "fill_actions"))
    binary = tmp_path / "natpt_hm"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra", "-Werror",
        "-Wno-unused-but-set-variable", "-Wno-unused-function", "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("natpt_hm.c")), "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=30)
