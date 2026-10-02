"""The bridged multicast tables: the PCD, the table types and the key layout
agree with one another.

A bridged group is keyed on the frame's own Ethernet pair as well as its
(S,G), so it has tables of its own, reached from a routed multicast table's
miss. Five places have to say the same thing -- the distribution's fields, the
table's key size, the C key the root is composed into, the names dpa_app maps
to types, and the miss chain cdx programs -- and a mismatch in any of them is a
key the hardware never matches, with nothing on the rig to say why.
"""

from ask_orch.process import run_process
import os
from pathlib import Path
import re
import xml.etree.ElementTree as ET

from _host_qos_lifecycle import (function)

ROOT = Path(__file__).resolve().parents[2]
PCD = ROOT / "dpa_app/files/etc/cdx_pcd.xml"
FIELD_BYTES = {
    "ethernet.dst": 6, "ethernet.src": 6,
    "ipv4.src": 4, "ipv4.dst": 4, "ipv4.nextp": 1,
    "ipv6.src": 16, "ipv6.dst": 16, "ipv6.nexthdr": 1,
}


def pcd():
    return ET.fromstring(PCD.read_text())


def keysize(tree, table):
    node = tree.find(f"classification[@name='{table}']/key/hashtable")
    assert node is not None, table
    return int(node.get("keysize"))


def fields(tree, dist):
    node = tree.find(f"distribution[@name='{dist}']")
    assert node is not None, dist
    return [f.get("name") for f in node.findall("key/fieldref")], node


def test_key_sizes_follow_the_fields():
    """The port id ahead of the extracted fields. The routed multicast tables
    are the check that the rule is the one the PCD already follows."""
    tree = pcd()
    for dist, table in (("cdx_ipv4multicast_dist", "cdx_multicast4_cc"),
                        ("cdx_ipv6multicast_dist", "cdx_multicast6_cc"),
                        ("cdx_bridged_mcast4_dist", "cdx_bridged_mcast4_cc"),
                        ("cdx_bridged_mcast6_dist", "cdx_bridged_mcast6_cc")):
        names, node = fields(tree, dist)
        assert node.find("action").get("name") == table
        assert keysize(tree, table) == 1 + sum(FIELD_BYTES[n] for n in names), dist
    assert keysize(tree, "cdx_bridged_mcast4_cc") == 22
    assert keysize(tree, "cdx_bridged_mcast6_cc") == 46


def test_the_ethernet_pair_leads_the_key():
    """The key generator extracts by hardware field id, Ethernet first, so the
    C key the root is composed into puts the pair first too -- destination,
    then source -- and the routed key's fields after it."""
    tree = pcd()
    for dist, family in (("cdx_bridged_mcast4_dist", "ipv4"),
                         ("cdx_bridged_mcast6_dist", "ipv6")):
        names, node = fields(tree, dist)
        proto = "nextp" if family == "ipv4" else "nexthdr"
        assert names == ["ethernet.dst", "ethernet.src", f"{family}.src",
                         f"{family}.dst", f"{family}.{proto}"], names
        assert [p.get("name") for p in node.findall("protocols/protocolref")] == [family]


def test_the_routed_tables_are_asked_first_in_every_policy():
    """The key generator selects the first distribution in a policy whose
    protocols the frame has, and the routed and bridged ones have the same
    protocols. So the bridged ones sit right behind the routed ones, reached
    only as their miss, the way the 3-tuple UDP distributions sit behind the
    5-tuple ones -- and the groups fmc numbers first (Ethernet, PPPoE and the
    3-tuple tables, which the soft parser's PPPoE path counts from) keep their
    places."""
    tree = pcd()
    # The IPsec offline port classifies with distributions of its own alone
    # (test_pcd_ipsec_offline_port.py), and so has none of these.
    policies = [p for p in tree.findall("policy")
                if not all(d.get("name").startswith("cdx_sec_")
                           for d in p.findall("dist_order/distributionref"))]
    assert len(policies) == len(tree.findall("policy")) - 1, [p.get("name") for p in policies]
    for policy in policies:
        order = [d.get("name") for d in policy.findall("dist_order/distributionref")]
        at = order.index("cdx_ipv6multicast_dist")
        assert order[at - 1] == "cdx_ipv4multicast_dist", order
        assert order[at + 1:at + 3] == ["cdx_bridged_mcast4_dist",
                                        "cdx_bridged_mcast6_dist"], order
        assert order[-4:] == ["cdx_tup3udp4_dist", "cdx_tup3udp6_dist",
                              "cdx_pppoe_dist", "cdx_ethernet_dist"], order


def test_every_distribution_has_its_own_queues():
    bases = [int(d.find("queue").get("base"), 16) for d in pcd().findall("distribution")]
    assert len(bases) == len(set(bases)), bases


def test_the_types_agree_everywhere():
    """cdx indexes a port's tables by the type dpa_app reports, and needs two
    numbers no other table uses; the kernel reads a table type for its
    microcode class alone, and the bridged tables are multicast (L3) tables."""
    ioctl = (ROOT / "cdx/cdx_ioctl.h").read_text()
    assert "#define IPV4_BRIDGED_MULTICAST_TABLE\tIPV4_3TUPLE_TCP_TABLE" in ioctl
    assert "#define IPV6_BRIDGED_MULTICAST_TABLE\tIPV6_3TUPLE_TCP_TABLE" in ioctl
    assert "3TUPLE_TCP_DIST" not in ioctl, "the reserved slots are the bridged ones now"

    dpa = (ROOT / "dpa_app/dpa.c").read_text()
    assert '{(char *)"cdx_bridged_mcast4", IPV4_BRIDGED_MULTICAST_TABLE}' in dpa
    assert '{(char *)"cdx_bridged_mcast6", IPV6_BRIDGED_MULTICAST_TABLE}' in dpa
    assert '{(char *)"cdx_bridged_mcast4_dist", IPV4_BRIDGED_MULTICAST_DIST}' in dpa
    assert '{(char *)"cdx_bridged_mcast6_dist", IPV6_BRIDGED_MULTICAST_DIST}' in dpa
    kernel = function(dpa, "set_table_types")
    for family in ("4", "6"):
        arm = kernel[kernel.index(f'"cdx_bridged_mcast{family}"'):]
        arm = arm[:arm.index("break;")]
        assert f"IPV{family}_MULTICAST_TABLE" in arm, arm

    cfg = (ROOT / "cdx/dpa_cfg.c").read_text()
    miss = function(cfg, "cdxdrv_set_miss_action")
    routed = miss[miss.index("case IPV4_MULTICAST_TABLE:"):]
    routed = routed[:routed.index("break;")]
    assert "IPV4_BRIDGED_MULTICAST_TABLE" in routed and "ETHERNET_TABLE" in routed, (
        "a routed miss goes to the bridged tables, and to Ethernet without them")
    bridged = miss[miss.index("case IPV4_BRIDGED_MULTICAST_TABLE:"):]
    bridged = bridged[:bridged.index("break;")]
    assert "get_dist_info_by_fman_params(finfo, ETHERNET_TABLE)" in bridged
    dist = cfg[cfg.index("static void *get_dist_info_by_fman_params("):]
    dist = dist[:dist.index("\n}\n")]
    assert "table_distrb_type =  IPV4_BRIDGED_MULTICAST_DIST;" in dist
    assert "table_distrb_type =  IPV6_BRIDGED_MULTICAST_DIST;" in dist


def test_the_c_key_is_the_size_the_table_expects(tmp_path):
    """The composer returns sizeof(key) + 1, and the table compares exactly
    keysize bytes: the two have to be one number."""
    common = (ROOT / "cdx/cdx_common.h").read_text()
    source = tmp_path / "keys.c"
    source.write_text(
        "#include <stdint.h>\n#include <assert.h>\n#define DPA_PACKED __attribute__((packed))\n"
        + common[common.index("//ipv4 tcp key used in cc table"):
                 common.index("#define MAX_KEY_SIZE")]
        + "int main(void) {\n"
          "  assert(sizeof(struct ipv4_mcast_mac_key) + 1 == 22);\n"
          "  assert(sizeof(struct ipv6_mcast_mac_key) + 1 == 46);\n"
          "  return 0;\n}\n")
    binary = tmp_path / "keys"
    run_process([os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-Wall", "-Werror",
                    str(source), "-o", str(binary)], check=True)
    run_process([str(binary)], check=True)
    # And the composer really returns that.
    ehash = (ROOT / "cdx/cdx_ehash.c").read_text()
    body = function(ehash, "fill_mcast_mac_key")
    assert "return sizeof(*k) + 1;" in body
    assert "return sizeof(key->ipv4_mcast_mac_key) + 1;" in body
    assert re.search(r"memcpy\(k->ether_da, mac_pair, ETHER_ADDR_LEN\)", body)
