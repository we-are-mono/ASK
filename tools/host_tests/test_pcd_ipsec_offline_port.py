"""SEC identity stays out of the lookup key and is encoded as a private VLAN."""
import os
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
FIELDS = {"ethernet.src": 6, "ethernet.dst": 6, "ethernet.type": 2,
          "ipv4.src": 4, "ipv4.dst": 4, "ipv4.nextp": 1,
          "ipv6.src": 16, "ipv6.dst": 16, "ipv6.nexthdr": 1,
          "tcp.sport": 2, "tcp.dport": 2, "udp.sport": 2, "udp.dport": 2,
          "ipsec_esp.spi": 4, "vlan.tci": 2}


def test_offline_port_keys(tmp_path):
    tree = ET.parse(ROOT / 'dpa_app/files/etc/cdx_pcd.xml').getroot()
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
    subprocess.run([os.environ.get('HOSTCC', 'cc'), '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-pie', '-no-pie',
                    str(source), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)


def test_soft_parser_scope():
    tree = ET.parse(ROOT / 'dpa_app/files/etc/cdx_sp.xml').getroot()
    pppoe = tree.find("protocol[@name='pppoeschema']/execute-code/before/if")
    assert pppoe.get('expr') == '$logicalportid != 9'
    vlan = tree.find("protocol[@name='vlanschema']/execute-code/before/if")
    assert vlan.get('expr').startswith('($logicalportid == 9) and ')
