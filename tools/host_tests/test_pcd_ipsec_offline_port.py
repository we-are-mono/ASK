"""The IPsec offline port's own classification: every key names the SA a frame
left SEC by, as well as the tuple.

Every SA's FROM_SEC queue feeds that one port. A decrypted flow's entry that
matched on the tuple alone forwarded whatever any SA decrypted into that
tuple, and an outbound SA's entry forwarded any decrypted packet shaped like
that SA's output. So the port has distributions and tables of its own, their
Ethernet counterparts' keys with the frame's enqueue FQID appended -- the FQID
the SA's FROM_SEC queue names in Context B -- and cdx appends the same FQID to
every key it composes for that port.

Six places have to say the same thing: the distributions' fields, the tables'
key sizes, the policy the port is bound to, dpa_app's name-to-type tables, the
key composers, and the miss chain cdx programs. A disagreement in any of them
is a key the hardware never matches -- the flow falls back to software with
nothing on the rig to say why -- or, worse, a key it matches too loosely.
"""
import os
from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET

import pytest

from test_ipsec_adapter import definition
from test_mcast_hm import loose_declaration
from test_qos_lifecycle import function

ROOT = Path(__file__).resolve().parents[2]
PCD = ROOT / "dpa_app/files/etc/cdx_pcd.xml"
FIELD_BYTES = {
    "ethernet.dst": 6, "ethernet.src": 6, "ethernet.type": 2,
    "ipv4.src": 4, "ipv4.dst": 4, "ipv4.nextp": 1,
    "ipv6.src": 16, "ipv6.dst": 16, "ipv6.nexthdr": 1,
    "udp.sport": 2, "udp.dport": 2, "tcp.sport": 2, "tcp.dport": 2,
    "ipsec_esp.spi": 4,
}
# Each of the port's distributions and the shared one it stands in for.
COUNTERPARTS = {
    "cdx_sec_esp4_dist": "cdx_esp4_dist",
    "cdx_sec_esp6_dist": "cdx_esp6_dist",
    "cdx_sec_udp4_dist": "cdx_udp4_dist",
    "cdx_sec_tcp4_dist": "cdx_tcp4_dist",
    "cdx_sec_udp6_dist": "cdx_udp6_dist",
    "cdx_sec_tcp6_dist": "cdx_tcp6_dist",
    "cdx_sec_ethernet_dist": "cdx_ethernet_dist",
}
KG_NUM_OF_SCHEMES = 32   # FM_PCD_KG_NUM_OF_SCHEMES, dpaa_integration_ext.h


def kernel_tree():
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
                  "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    if not (kernel / "drivers/net/ethernet/freescale/sdk_fman").exists():
        pytest.fail("build the ASK kernel or set ASK_KERNEL_SOURCE to its patched source")
    return kernel


def pcd():
    return ET.fromstring(PCD.read_text())


def tag_len():
    header = (ROOT / "cdx/cdx_dpa_ipsec.h").read_text()
    return int(re.search(r"^#define CDX_IPSEC_KEY_TAG_LEN\s+(\d+)", header, re.M).group(1))


def distribution(tree, name):
    node = tree.find(f"distribution[@name='{name}']")
    assert node is not None, name
    return node


def table_of(tree, dist):
    name = distribution(tree, dist).find("action[@type='classification']").get("name")
    node = tree.find(f"classification[@name='{name}']/key/hashtable")
    assert node is not None, name
    return name, node


def ipsec_policy(tree):
    """The policy cdx_cfg.xml binds the offline port devoh gives IPsec to."""
    devoh = (ROOT / "cdx/devoh.c").read_text()
    number = int(re.search(r'\{"dpa-fman0-oh@(\d+)", PORT_TYPE_IPSEC\}', devoh).group(1)) - 1
    cfg = ET.parse(ROOT / "config/gateway-dk/cdx_cfg.xml").getroot()
    port = cfg.find(f".//port[@type='OFFLINE'][@number='{number}']")
    assert port is not None
    policy = tree.find(f"policy[@name='{port.get('policy')}']")
    assert policy is not None, port.get("policy")
    return policy, int(port.get("portid"))


def order(policy):
    return [d.get("name") for d in policy.findall("dist_order/distributionref")]


def test_the_keys_are_their_counterparts_with_the_fqid_last():
    """Same protocols, same fields, one nonheader FQID of CDX_IPSEC_KEY_TAG_LEN
    bytes from the start of the key generator's FQID area; the key size is the
    port id, the fields, and the FQID. The key generator places generic
    extractions after the known fields, which is why cdx appends it."""
    tree, length = pcd(), tag_len()
    assert length == 3, "an FQID is 24 bits"
    for sec, shared in COUNTERPARTS.items():
        mine, theirs = distribution(tree, sec), distribution(tree, shared)
        assert ([p.get("name") for p in mine.findall("protocols/protocolref")]
                == [p.get("name") for p in theirs.findall("protocols/protocolref")]), sec
        fields = [(f.get("name"), f.get("header_index")) for f in mine.findall("key/fieldref")]
        assert fields == [(f.get("name"), f.get("header_index"))
                          for f in theirs.findall("key/fieldref")], sec
        tags = mine.findall("key/nonheader")
        _, table = table_of(tree, sec)
        _, shared_table = table_of(tree, shared)
        base = 1 + sum(FIELD_BYTES[name] for name, _ in fields)
        assert int(shared_table.get("keysize")) == base, shared
        if sec == "cdx_sec_ethernet_dist":
            # The catch-all never holds an entry; its key needs no SA.
            assert not tags and int(table.get("keysize")) == base
        else:
            assert len(tags) == 1, sec
            assert (tags[0].get("source"), int(tags[0].get("offset")),
                    int(tags[0].get("size"))) == ("fqid", 0, length), sec
            assert int(table.get("keysize")) == base + length, sec
            # The key generator requires a not-from-data default for an FQID
            # extraction (fm_kg.c GetGenericSwDefault(), whose absence it
            # reports at every boot), though the FQID is always present.
            defaults = [(d.get("type"), d.get("select"))
                        for d in mine.findall("defaults/default")]
            assert ("not_from_data", "gbl0") in defaults, (sec, defaults)
        # Sized like the table it stands in for.
        for attr in ("mask", "hashshift"):
            assert table.get(attr) == shared_table.get(attr), (sec, attr)
        assert int(table.get("keysize")) <= 56, "FM_PCD_MAX_SIZE_OF_KEY"


def test_the_port_classifies_with_its_own_distributions_alone():
    """The key generator takes the first scheme by number whose protocols a
    frame has, and fmc numbers the shared schemes, applied with the first
    port, before these. Any shared distribution on the port would take its
    frames -- the routed multicast one has only ipv4 -- so the port has none,
    and its catch-all comes last, as Ethernet does on every other port. No
    other port names these."""
    tree = pcd()
    policy, _ = ipsec_policy(tree)
    ethernet = order(tree.find("policy[@name='cdx_ethport_1_policy']"))
    expected = [sec for shared in ethernet for sec, s in COUNTERPARTS.items() if s == shared]
    assert order(policy) == expected, order(policy)
    assert expected[-1] == "cdx_sec_ethernet_dist"
    for other in tree.findall("policy"):
        if other is not policy:
            assert not any(n.startswith("cdx_sec_") for n in order(other)), other.get("name")
    # Every classification a sec distribution names is its own, and named
    # by that distribution alone.
    tables = [table_of(tree, sec)[0] for sec in COUNTERPARTS]
    assert len(set(tables)) == len(tables) and all(t.startswith("cdx_sec_") for t in tables)


def test_the_schemes_fit_the_key_generator():
    """One scheme per distribution any policy names; 32 on the FMan."""
    tree = pcd()
    used = {name for policy in tree.findall("policy") for name in order(policy)}
    assert len(used) <= KG_NUM_OF_SCHEMES, sorted(used)
    assert set(COUNTERPARTS) <= used


def test_every_queue_base_leaves_the_port_id_its_bits():
    """The combine ORs the logical port id into FQID bits 8-11, so a base with
    one of those set would share its queues with another port's."""
    tree = pcd()
    bases = []
    for dist in tree.findall("distribution"):
        queue = dist.find("queue")
        base, count = int(queue.get("base"), 16), int(queue.get("count"))
        bases.append(base)
        if dist.get("name") in COUNTERPARTS:
            assert base & 0xf00 == 0 and base % count == 0, dist.get("name")
            assert dist.find("combine").get("portid") == "true"
    assert len(bases) == len(set(bases)), bases


def strstr_first(name, table):
    """dpa_app's lookups: the first entry whose name the argument contains."""
    return next(value for key, value in table if key in name)


def test_dpa_app_types_them_as_the_tables_they_replace(tmp_path):
    """cdx indexes a port's tables by type, and the port has these in place
    of the shared ones, so each takes the type -- and the microcode class --
    of its counterpart; the distributions likewise. dpa_app resolves a name by
    its first substring match, so an earlier entry that a name contains would
    type it as something else."""
    tree = pcd()
    dpa = (ROOT / "dpa_app/dpa.c").read_text()
    params = re.findall(r'\{\(char \*\)"(cdx_\w+)",\s*(\w+)\}',
                        dpa[dpa.index("table_params[] = {"):dpa.index("#define MAX_TABLE_PARAMS")])
    dists = re.findall(r'\{\(char \*\)"(cdx_\w+)",\s*(\w+)\}',
                       dpa[dpa.index("dist_name[] = {"):dpa.index("#define MAX_DIST_PARAMS")])
    kernel = function(dpa, "set_table_types")
    arms = re.findall(r'strstr\(model->htnode_name\[index\], "(cdx_\w+)"\)\) \{\s*'
                      r'model->htnode\[index\]\.table_type = (\w+);', kernel)
    assert arms
    default = re.search(r"model->htnode\[index\]\.table_type = (\w+);\s*break;\s*\} while",
                        kernel).group(1)

    def kernel_type(name):
        return next((t for key, t in arms if key in name), default)

    for sec, shared in COUNTERPARTS.items():
        # fmc's names: fm0/dist/<distribution>, and a table as
        # fm0/port/<type>/<n>/ccnode/<classification>.
        mine, theirs = f"fm0/dist/{sec}", f"fm0/dist/{shared}"
        assert strstr_first(mine, dists) == strstr_first(theirs, dists), sec
        table, _ = table_of(tree, sec)
        shared_table, _ = table_of(tree, shared)
        node = f"fm0/port/OFFLINE/1/ccnode/{table}"
        assert strstr_first(node, params) == strstr_first(
            f"fm0/port/1G/1/ccnode/{shared_table}", params), table
        assert kernel_type(node) == kernel_type(f"fm0/port/1G/1/ccnode/{shared_table}"), table


def test_cdx_appends_the_fqid_where_it_composes_the_port_keys():
    """Two composers write keys into the port's tables: a flow's, for a
    direction some SA decrypts, and an outbound SA's own. Both append the SA's
    FQID after the key and before the opcode area is laid out behind it."""
    ehash = (ROOT / "cdx/cdx_ehash.c").read_text()
    body = function(ehash, "insert_entry_in_classif_table_encap")
    tag = ("if (info->l3_info.ipsec_inbound_flow)\n"
           "\t\tkey_size = cdx_ipsec_key_tag(&tbl_entry->hashentry.key[0],\n"
           "\t\t\t\t\t     key_size, info->sec_tag);")
    assert tag in body
    assert (body.index("key_size = fill_key_info(entry,") < body.index(tag)
            < body.index("ptr += ALIGN(key_size, TBLENTRY_OPC_ALIGN);"))
    assert body.index("cdx_ipsec_fill_sec_info(entry,info)") < body.index(tag)
    sa = (ROOT / "cdx/cdx_dpa_ipsec.c").read_text()
    body = function(sa, "cdx_ipsec_add_classification_table_entry")
    tag = ("if (!sa_dir_in)\n"
           "\t\tkey_size = cdx_ipsec_key_tag(&tbl_entry->hashentry.key[0],\n"
           "\t\t\t\t\t     key_size, cdx_ipsec_key_tag_of(sa));")
    assert tag in body
    assert (body.index("key_size = fill_ipsec_key_info(sa, tbl_entry, info->port_id);")
            < body.index(tag) < body.index("ptr += ALIGN(key_size, TBLENTRY_OPC_ALIGN);"))
    # Where the outbound entry lives: the offline port's table of its type.
    assert re.search(r"dpa_ipsec_ofport_td\(ipsec_instance, tbl_type, &sa->ct->td,", body)
    # The same FQID the SA's FROM_SEC queue names in Context B.
    dpa = (ROOT / "cdx/dpa_ipsec.c").read_text()
    fqs = function(dpa, "create_ipsec_fqs")
    from_sec = fqs[fqs.index("case FQ_FROM_SEC:"):fqs.index("case FQ_TO_SEC:")]
    assert "CDX_FQD_CTX_A_OVERRIDE_FQ" in from_sec
    assert "opts.fqd.context_b = fqids_base + FQ_TO_CP;" in from_sec
    assert "return sa->pSec_sa_context->to_cp_fqid;" in function(sa, "cdx_ipsec_key_tag_of")


def test_an_outbound_nat_t_entry_is_its_own():
    """Keyed on the SA, two outbound NAT-T SAs on one UDP tuple cannot share
    an entry, as they did while the key was the tuple alone. Inbound ones
    still do: their entry is on the port the peer's frames arrive by and picks
    the SA by SPI."""
    sa = (ROOT / "cdx/cdx_dpa_ipsec.c").read_text()
    body = function(sa, "cdx_ipsec_process_udp_classification_table_entry")
    assert body.count("M_ipsec_get_matched_natt_tunnel(sa)") == 1
    assert re.search(r"if \(sa->direction == CDX_DPA_IPSEC_INBOUND\)\s*"
                     r"natt_sa = M_ipsec_get_matched_natt_tunnel\(sa\);", body)
    assert "natt_out_refcnt++" not in body
    assert "natt_out_refcnt--" not in function(sa, "cdx_ipsec_delete_fp_entry")


def test_the_keys_and_the_port_in_c(tmp_path):
    """The composers, the flow's SA lookup, the offline port's table lookup,
    the miss chain and the SA's own delete, compiled from cdx and run."""
    kernel = kernel_tree()
    tree = pcd()
    sdk = kernel / "drivers/net/ethernet/freescale/sdk_fman/inc/Peripherals"
    common = (ROOT / "cdx/cdx_common.h").read_text()
    header = (ROOT / "cdx/cdx_dpa_ipsec.h").read_text()
    ioctl = (ROOT / "cdx/cdx_ioctl.h").read_text()
    control = (ROOT / "cdx/control_ipsec.h").read_text()
    ehash_h = (sdk / "fm_ehash.h").read_text()
    enum = re.search(r"^enum \{\s*IPV4_UDP_TABLE.*?^\};", (sdk / "fm_eh_types.h").read_text(),
                     re.S | re.M).group()
    sa = (ROOT / "cdx/cdx_dpa_ipsec.c").read_text()
    ehash = (ROOT / "cdx/cdx_ehash.c").read_text()
    dpa = (ROOT / "cdx/dpa_ipsec.c").read_text()
    cfg = (ROOT / "cdx/dpa_cfg.c").read_text()
    (tmp_path / "sec_key_types.inc").write_text(
        common[common.index("//ipv4 tcp key used in cc table"):common.index("#define MAX_KEY_SIZE")]
        + re.search(r"^struct hw_ct \{.*?^\};", common, re.S | re.M).group() + "\n"
        + re.search(r"^#define CDX_IPSEC_KEY_TAG_LEN.*$", header, re.M).group() + "\n"
        + "\n".join(re.findall(r"^#define\s+(?:IPPROTOCOL_(?:TCP|UDP|ESP))\s.*$",
                               (ROOT / "cdx/fe.h").read_text(), re.M)) + "\n"
        + "\n".join(re.findall(r"^#define\s+(?:CDX_DPA_IPSEC_(?:IN|OUT)BOUND|SA_MAX_OP)\s.*$",
                               control, re.M)) + "\n"
        + enum + "\n"
        + "#define CDX_RTP_RELAY\n"
        + re.search(r"^enum \{\s*IPV4_TCP_DIST.*?^\};", ioctl, re.S | re.M).group() + "\n"
        + re.search(r"^#define CDX_CTRL_PORT_NAME_LEN.*$", ioctl, re.M).group() + "\n"
        + re.search(r"^#define\s+TABLE_NAME_SIZE.*$", ioctl, re.M).group() + "\n"
        + "".join(re.search(rf"^struct {name} \{{.*?^\}};", ioctl, re.S | re.M).group() + "\n"
                  for name in ("cdx_dist_info", "cdx_port_info", "table_info"))
        + re.search(r"^#define MAX_SPI_PER_FLOW.*$", ehash_h, re.M).group() + "\n"
        + loose_declaration(ehash_h, "spi_info")
        + loose_declaration(ehash_h, "en_ehash_ipsec_preempt_op")
        + dpa[dpa.index("struct ipsec_info {"):dpa.index("static struct ipsec_info ipsecinfo")])
    (tmp_path / "sec_key_production.inc").write_text(
        header[header.index("static inline uint32_t cdx_ipsec_key_tag("):
               header.index("int cdx_ipsec_delete_fp_entry(PSAEntry pSA);")]
        + function(ehash, "fill_key_info")
        + function(sa, "fill_natt_key_info") + function(sa, "fill_ipsec_key_info")
        + function(dpa, "dpa_ipsec_ofport_td")
        + function(sa, "cdx_ipsec_expansion_of") + function(sa, "cdx_ipsec_key_tag_of")
        + function(sa, "cdx_ipsec_decrypted_table") + function(sa, "cdx_ipsec_fill_sec_info")
        + function(sa, "reset_natt_arr_mask") + function(sa, "cdx_ipsec_delete_fp_entry")
        + definition(cfg, "miss_scheme_on_port"))
    sizes = {}
    for sec in COUNTERPARTS:
        _, table = table_of(tree, sec)
        _, shared = table_of(tree, COUNTERPARTS[sec])
        stem = sec[len("cdx_sec_"):-len("_dist")].upper()
        sizes[f"SEC_{stem}_KEYSIZE"] = int(table.get("keysize"))
        sizes[f"{stem}_KEYSIZE"] = int(shared.get("keysize"))
    _, ipsec_portid = ipsec_policy(tree)
    binary = tmp_path / "ipsec_key_tag"
    subprocess.run([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
        # The vendor's composers compare an int loop index with a size, and
        # its NAT-T delete takes the address of a packed member, as the
        # kernel's own warning set allows.
        "-Wno-sign-compare", "-Wno-address-of-packed-member",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
        *[f"-D{k}={v}" for k, v in sizes.items()], f"-DIPSEC_PORTID={ipsec_portid}",
        "-I", str(tmp_path), str(Path(__file__).with_name("ipsec_key_tag.c")),
        "-o", str(binary),
    ], check=True)
    result = subprocess.run([str(binary)], text=True, capture_output=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
    assert result.returncode == 0, result.stdout + result.stderr
    assert "offline-port keys:" in result.stdout, result.stdout
