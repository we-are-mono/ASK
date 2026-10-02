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
