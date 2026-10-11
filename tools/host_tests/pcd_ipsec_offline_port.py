"""IPsec classifier keys match the physical and SEC port layouts."""

from ask_orch.process import run_process
import os
from pathlib import Path
import re
import struct
import subprocess
import xml.etree.ElementTree as ET

from _host_qos_lifecycle import (function)

ROOT = Path(__file__).resolve().parents[2]
FIELDS = {"ethernet.src": 6, "ethernet.dst": 6, "ethernet.type": 2,
          "ipv4.src": 4, "ipv4.dst": 4, "ipv4.nextp": 1,
          "ipv6.src": 16, "ipv6.dst": 16, "ipv6.nexthdr": 1,
          "tcp.sport": 2, "tcp.dport": 2, "udp.sport": 2, "udp.dport": 2,
          "ipsec_esp.spi": 4, "vlan.tci": 2}


def test_offline_port_keys(tmp_path):
    tree = ET.parse(ROOT / 'config/pcd/cdx_pcd.xml').getroot()
    policy = tree.find("policy[@name='cdx_port_of2_policy']")
    names = [ref.get('name') for ref in policy.findall('dist_order/distributionref')]
    assert len(names) == 7 and names[-1] == 'cdx_sec_ethernet_dist'
    assert len(tree.findall('distribution')) == 21
    for name in names:
        assert name.startswith('cdx_sec_')
        dist = tree.find(f"distribution[@name='{name}']")
        extracts = dist.findall("key/nonheader")
        fields = [ref.get('name') for ref in dist.findall('key/fieldref')]
        table = dist.find('action').get('name')
        size = int(tree.find(f"classification[@name='{table}']/key/hashtable").get('keysize'))
        assert size == 1 + sum(FIELDS[field] for field in fields) + sum(int(e.get('size')) for e in extracts)
        if name != names[-1]:
            assert not extracts and 'vlan.tci' not in fields
    for other in tree.findall('policy'):
        if other is not policy:
            assert not any(ref.get('name') in names for ref in other.findall('dist_order/distributionref'))
    header = (ROOT / 'cdx/cdx_dpa_ipsec.h').read_text()
    helpers = header[header.index('static inline void cdx_ipsec_vlan_tag'):
                     header.index('int cdx_ipsec_delete_fp_entry')]
    helpers = helpers.replace('uint32_t cdx_ipsec_key_tag_of(PSAEntry sa);', '')
    source = tmp_path / 'sec_tag.c'
    source.write_text('''#include <stdint.h>
#include <string.h>
#include <assert.h>
''' + helpers + '''
int main(void) {
    uint8_t stamp[4];
    cdx_ipsec_vlan_tag(stamp, 0x345);
    assert(!memcmp(stamp, "\\x81\\x00\\x03\\x45", 4));
}
''')
    binary = tmp_path / 'sec_tag'
    run_process([os.environ.get('HOSTCC', 'cc'), '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-pie', '-no-pie',
                    str(source), '-o', str(binary)], check=True)
    run_process([str(binary)], check=True)


def test_soft_parser_scope():
    tree = ET.parse(ROOT / 'config/pcd/cdx_sp.xml').getroot()
    pppoe = tree.find("protocol[@name='pppoeschema']/execute-code/before/if")
    assert pppoe.get('expr') == '$logicalportid != 9'
    vlan = tree.find("protocol[@name='vlanschema']/execute-code/before/if")
    assert vlan.get('expr').startswith('($logicalportid == 9) and ')
    # A TTL or hop limit of 1 or 0 sends a frame to the CPU, before any
    # forwarding entry could pass it on expired -- except, on the IPsec
    # offline port, ESP its fixed header names: SEC's output for an outbound
    # SA, which leaves as the packet's own and is freed if it is excepted.
    for schema, limit, protocol in (('ipv4schema', 'ipv4.ttl', 'ipv4.nextp'),
                                    ('ipv6schema', 'ipv6.hop', 'ipv6.nexthdr')):
        checks = tree.findall(f"protocol[@name='{schema}']/execute-code/before/if")
        assert checks[0].get('expr') == (f'({limit} == 1 or {limit} == 0) and '
                                         f'($logicalportid != 9 or {protocol} != 0x32)'), schema
    # An inbound SA's PDB states a plain IPv4 header: ESP behind options goes
    # to the CPU from every port but the offline one, whose ESP is SEC's.
    options = tree.findall("protocol[@name='ipv4schema']/execute-code/before/if")[1]
    assert options.get('expr') == '$logicalportid != 9 and ipv4.nextp == 0x32 and ipv4.hlen != 5'
    assert options.find("if-true/assign-variable[@name='$nia']").get('value') == '0x500002'


# KeyGen's known-field bits (fm_kg.h). A scheme's key carries its known fields
# in descending bit order, whatever order the distribution lists them in. The
# protocol byte of the fixed IP header is PTYPE1; for IPv6, header_index="last"
# reads the last header's next header instead, IPPID, which names ESP behind
# extension headers.
KEYGEN_BITS = {("ipv4.dst", None): 0x80000, ("ipv6.dst", None): 0x80000,
               ("ipv4.nextp", None): 0x40000, ("ipv6.nexthdr", None): 0x40000,
               ("ipsec_esp.spi", None): 0x200, ("ipv6.nexthdr", "last"): 0x80}


def key_order(tree, distribution):
    refs = tree.findall(f"distribution[@name='{distribution}']/key/fieldref")
    return [name for name, _ in sorted(((ref.get("name"), ref.get("header_index")) for ref in refs),
                                       key=lambda field: -KEYGEN_BITS[field])]


def test_esp_keys_follow_each_table_s_key_order(tmp_path):
    """An SA's ESP key carries its fields in the order KeyGen extracts them for
    the table the SA's entry lives in: an inbound SA's on the physical ports,
    an outbound SA's on the IPsec offline port. The offline port classifies
    SEC's output by the last next header, which is ESP however many extension
    headers a transport-mode packet keeps ahead of it; the fixed header's
    would name the first extension header, and the frame would miss."""
    tree = ET.parse(ROOT / "config/pcd/cdx_pcd.xml").getroot()
    sec6 = {ref.get("name"): ref.get("header_index")
            for ref in tree.findall("distribution[@name='cdx_sec_esp6_dist']/key/fieldref")}
    assert sec6["ipv6.nexthdr"] == "last", sec6
    common = (ROOT / "cdx/cdx_common.h").read_text()
    control = (ROOT / "cdx/control_ipsec.h").read_text()
    source = tmp_path / "esp_key.c"
    source.write_text(r"""
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define DPA_PACKED __attribute__((packed))
#define PROTO_IPV4 4
#define IPPROTOCOL_ESP 50
""" + common[common.index("struct ipv4_tcpudp_key{"):
             common.index("#define MAX_KEY_SIZE")]
        + "\n".join(re.findall(r"^#define CDX_DPA_IPSEC_(?:IN|OUT)BOUND\s.*$", control, re.M))
        + r"""
typedef struct {
    int family, direction;
    struct { uint32_t spi; struct { uint32_t a6[4]; } daddr; } id;
} SAEntry, *PSAEntry;
struct en_exthash_tbl_entry { struct { uint8_t key[64]; } hashentry; };
""" + function((ROOT / "cdx/cdx_dpa_ipsec.c").read_text(), "fill_ipsec_key_info")
        + r"""
int main(void) {
    for (int family = 4; family <= 6; family += 2) {
        for (int inbound = 1; inbound >= 0; inbound--) {
            SAEntry sa = {.family = family, .direction = inbound ?
                CDX_DPA_IPSEC_INBOUND : CDX_DPA_IPSEC_OUTBOUND};
            struct en_exthash_tbl_entry entry;
            for (int i = 0; i < 16; i++)
                ((uint8_t *)sa.id.daddr.a6)[i] = i + 17;
            memcpy(&sa.id.spi, "\xa9\x00\x00\x01", 4);
            memset(&entry, 0xa5, sizeof(entry));
            int size = fill_ipsec_key_info(&sa, &entry, 7);
            assert(size > 0 && size < 64 && entry.hashentry.key[size] == 0xa5);
            for (int i = 0; i < size; i++) printf("%02x", entry.hashentry.key[i]);
            puts("");
        }
    }
}
""")
    binary = tmp_path / "esp_key"
    run_process([os.environ.get("HOSTCC", "cc"), "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
                    str(source), "-o", str(binary)], check=True)
    actual = subprocess.check_output([str(binary)], text=True).splitlines()
    values = {"ipv4.dst": bytes(range(17, 21)), "ipv6.dst": bytes(range(17, 33)),
              "ipv4.nextp": b"\x32", "ipv6.nexthdr": b"\x32", "ipsec_esp.spi": b"\xa9\x00\x00\x01"}
    expected = [(b"\x07" + b"".join(values[field] for field in key_order(tree, table))).hex()
                for table in ("cdx_esp4_dist", "cdx_sec_esp4_dist", "cdx_esp6_dist", "cdx_sec_esp6_dist")]
    assert actual == expected


def test_natt_keys_match_the_physical_and_sec_tables(tmp_path):
    common = (ROOT / "cdx/cdx_common.h").read_text()
    control = (ROOT / "cdx/control_ipsec.h").read_text()
    ioctl = (ROOT / "cdx/cdx_ioctl.h").read_text()
    source = tmp_path / "natt_key.c"
    source.write_text(r"""
#include <arpa/inet.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define DPA_PACKED __attribute__((packed))
#define cpu_to_be16 htons
#define PROTO_IPV4 4
""" + common[common.index("struct ipv4_tcpudp_key{"):
             common.index("#define MAX_KEY_SIZE")]
        + "\n".join(re.findall(r"^#define CDX_UNICAST\w*KEY_SIZE\s.*$", ioctl, re.M)) + "\n"
        + "\n".join(re.findall(r"^#define CDX_DPA_IPSEC_(?:IN|OUT)BOUND\s.*$", control, re.M))
        + r"""
typedef struct {
    int family, direction;
    struct { uint32_t saddr[4]; struct { uint32_t a6[4]; } daddr; } id;
    struct { uint16_t sport, dport; } natt;
} SAEntry, *PSAEntry;
struct en_exthash_tbl_entry { struct { uint8_t key[64]; } hashentry; };
""" + function((ROOT / "cdx/cdx_dpa_ipsec.c").read_text(), "fill_natt_key_info")
        + r"""
int main(void) {
    for (int family = 4; family <= 6; family += 2) {
        for (int inbound = 0; inbound <= 1; inbound++) {
            SAEntry sa = {.family = family, .direction = inbound ?
                CDX_DPA_IPSEC_INBOUND : CDX_DPA_IPSEC_OUTBOUND, .natt = {4500, 31000}};
            struct en_exthash_tbl_entry entry;
            for (int i = 0; i < 16; i++) {
                ((uint8_t *)sa.id.saddr)[i] = i + 1;
                ((uint8_t *)sa.id.daddr.a6)[i] = i + 17;
            }
            memset(&entry, 0xa5, sizeof(entry));
            int size = fill_natt_key_info(&sa, &entry, 7);
            assert(size > 0 && size < 64 && entry.hashentry.key[size] == 0xa5);
            for (int i = 0; i < size; i++) printf("%02x", entry.hashentry.key[i]);
            puts("");
        }
    }
}
""")
    binary = tmp_path / "natt_key"
    run_process([os.environ.get("HOSTCC", "cc"), "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
                    str(source), "-o", str(binary)], check=True)
    actual = subprocess.check_output([str(binary)], text=True).splitlines()
    expected = []
    for address_size, guard_size in ((4, 42), (16, 17)):
        addresses = bytes(range(1, address_size + 1)) + bytes(range(17, 17 + address_size))
        ports = struct.pack("!HH", 4500, 31000)
        expected.extend((b"\x07" + addresses + b"\x11" + ports,
                         b"\x07" + addresses + ports + b"\x11" + bytes(guard_size)))
    assert actual == [key.hex() for key in expected]
