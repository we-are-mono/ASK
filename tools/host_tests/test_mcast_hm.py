"""The multicast listener's header manipulations, and who owns their cursor."""

import os
from pathlib import Path
import re
import subprocess

from test_pppoe_hm import declaration, typedef
from test_qos_lifecycle import function

ROOT = Path(__file__).resolve().parents[2]
HEADER = "drivers/net/ethernet/freescale/sdk_fman/inc/Peripherals/fm_ehash.h"


def test_mcast_root_hop_semantics(tmp_path):
    source = (ROOT / "cdx/cdx_ehash.c").read_text()
    definitions = source[source.index("#define TTL_HM_VALID"):source.index("#define MURAM_VIRT_TO_PHYS_ADDR")]
    (tmp_path / "mcast_root.inc").write_text(definitions + function(source, "fill_actions"))
    binary = tmp_path / "mcast_root"
    subprocess.run([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra", "-Werror",
        "-Wno-unused-but-set-variable", "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
        "-DVLAN_FILTER", "-DINCLUDE_ETHER_IFSTATS", "-I", str(tmp_path),
        str(Path(__file__).with_name("mcast_root.c")), "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True, timeout=30)


def test_bridge_mode_reaches_root_and_cannot_change_on_replace():
    from test_mcast_backend import code
    adapter = (ROOT / "cdx/ask_flowtable.c").read_text()
    encoder = (ROOT / "cdx/cdx_ehash.c").read_text()
    assert "spec->bridged = true;" in function(adapter, "ft_mc_group_spec")
    assert "ft_mc_group_spec(target, &spec);" in function(adapter, "ft_mc_work_fn")
    assert "cdx_mc_describe(grp, spec);" in code("cdx_mc_group_add")
    assert "grp->bridged = spec->bridged;" in code("cdx_mc_describe")
    assert "grp->bridged != spec->bridged" in code("cdx_mc_same_key")
    assert "pMcastGrpInfo->bridged" in code("cdx_add_mcast_table_entry")
    assert "fill_actions(entry, info, !bridged)" in function(encoder, "insert_mcast_entry_in_classif_table")
    assert "fill_actions(entry, info, true)" in function(encoder, "insert_entry_in_classif_table_encap")


def loose_declaration(source, name):
    """As declaration(), but tolerating the vendor's other brace style. Some of
    these structs open on the line after their tag, and the point of pulling
    them from source at all is that the test breaks when the real one changes.
    """
    start = re.search(r"^struct\s+" + name + r"\s*\n?\s*\{", source, re.M)
    assert start, name
    end, depth = start.end(), 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start.start():source.index(";", end) + 1] + "\n"


def test_mcast_hm(tmp_path):
    # The shipped patch, so this does not depend on a previously built kernel.
    subprocess.run([
        "git", "apply", f"--include={HEADER}",
        str(ROOT / "patches/kernel/010-ask-fman-dpaa-ehash.patch"),
    ], cwd=tmp_path, check=True)
    header = (tmp_path / HEADER).read_text()
    common = (ROOT / "cdx/cdx_common.h").read_text()
    ehash = (ROOT / "cdx/cdx_ehash.c").read_text()
    # The real descriptions, not restatements: a field renamed or resized on
    # either side of the encapsulation boundary has to fail here rather than
    # compile into a silent mismatch.
    (tmp_path / "mcast_hm_types.inc").write_text(
        re.search(r"^#define DPA_CLS_HM_MAX_VLANs.*$", common, re.M).group() + "\n"
        + declaration(common, "vlan_header")
        + declaration(common, "dpa_l2hdr_info")
        # And the L3 half, which an encapsulation naming a tunnel writes into.
        + typedef(common, "IPv4_HDR_STRUCT")
        + typedef(common, "IPv6_HDR_STRUCT")
        + declaration(common, "dpa_l3hdr_info")
        + declaration((ROOT / "cdx/control_ipv4.h").read_text(), "cdx_l2_encap")
        # Name and value only: several of these carry comments that run on
        # past the line.
        + "".join(f"#define {name} {value}\n" for name, value in re.findall(
            r"^#define\s+(INSERT_VLAN_HDR|INSERT_L2_HDR|STRIP_ALL_VLAN_HDRS|"
            r"OP_SKIP_VLAN_VALIDATE|OP_VLAN_FILTER_EN|OP_VLAN_FILTER_PVID_SET|"
            r"MAX_VLAN_PER_FLOW|UPDATE_TTL|UPDATE_HOPLIMIT)\s+(\([^)]*\)|\S+)",
            header, re.M))
        + loose_declaration(header, "en_ehash_stats")
        + loose_declaration(header, "en_ehash_insert_vlan_hdr")
        + loose_declaration(header, "en_ehash_insert_l2_hdr")
        + loose_declaration(header, "en_ehash_strip_all_vlan_hdrs")
        + loose_declaration(header, "en_ehash_update_dscp")
        # Every classifier key layout, the bridged multicast ones included,
        # and the union they are composed through.
        + common[common.index("//ipv4 tcp key used in cc table"):
                 common.index("#define MAX_KEY_SIZE")]
        # What a listener's copy owes to something other than its interface.
        + declaration((ROOT / "cdx/dpa_control_mc.h").read_text(),
                      "cdx_mc_member_frame")
        # The entry-builder flags the ingress strip reads.
        + "".join(f"#define {name} {value}\n" for name, value in re.findall(
            r"^#define\s+(EHASH_BRIDGE_FLOW|ROUTE_FLOW_VLAN_FIL_EN|ROUTE_FLOW_PVID_SET|"
            r"TTL_HM_VALID|EHASH_IPV6_FLOW)"
            r"\s+(\([^)]*\))", ehash, re.M))
        + re.search(r"^#define PAD\(.*$", ehash, re.M).group() + "\n")
    (tmp_path / "mcast_hm.inc").write_text(
        function(ehash, "apply_l2_encap")
        # The predicate the tag emitter gates its statistics pointer on, which
        # it calls and this test therefore has to carry.
        + function(ehash, "vlan_flow_stats_named")
        + function(ehash, "create_vlan_ins_hm")
        + function(ehash, "create_ethernet_hm")
        # A bridged group's root key and its copies' Ethernet pair, and the
        # strip that validates the tags the group arrives with.
        + function(ehash, "fill_mcast_mac_key")
        + function(ehash, "mcast_member_frame")
        # A routed copy's own hop decrement in a group whose root kept it.
        + function(ehash, "insert_opcodeonly_hm")
        + function(ehash, "create_member_hop_hm")
        + function(ehash, "insert_remove_vlan_hm"))
    binary = tmp_path / "mcast_hm"
    subprocess.run([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined",
        # The tag array inside the opcode parameter is a packed member and the
        # emitter walks it through a uint32_t *. That is deliberate -- the
        # ucode reads whole words there -- and the kernel disables this
        # diagnostic globally, so requiring it here would only reject the
        # production source for a property the production build accepts.
        "-Wno-address-of-packed-member",
        # The ingress strip compares a signed index with an unsigned count,
        # which the kernel build does not warn about (-Wsign-compare is not
        # part of its warning set); the harness would reject the production
        # source for it all the same.
        "-Wno-sign-compare",
        "-fno-pie", "-no-pie", "-I", str(tmp_path),
        "-DINCLUDE_VLAN_IFSTATS=1", "-DVLAN_FILTER=1",
        str(Path(__file__).with_name("mcast_hm.c")), "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })


def test_listener_builder_owns_its_cursor():
    """struct ins_entry_info is the write cursor into one entry's fixed opcode
    and parameter area. The multicast builder used to be handed one per group
    and re-based only opcptr, paramptr and param_size per entry, leaving
    opc_count -- which nothing in the tree ever assigns zero -- to accumulate
    across every listener. Assert the shape that makes that unrepresentable:
    the builder takes no cursor from its caller and allocates its own, and
    neither mcast caller keeps one to hand it.
    """
    ehash = (ROOT / "cdx/cdx_ehash.c").read_text()
    mc = (ROOT / "cdx/dpa_control_mc.c").read_text()

    signature = re.search(
        r"create_exthash_entry4mcast_member\(([^)]*)\)\s*\{", ehash, re.S)
    assert signature, "listener builder definition not found"
    assert "ins_entry_info" not in signature.group(1), (
        "the listener builder must not accept a caller's cursor")

    body = function(ehash, "create_exthash_entry4mcast_member")
    assert "kzalloc(sizeof(struct ins_entry_info)" in body, (
        "the listener builder must allocate its own cursor")
    # Every exit releases it. One kfree would be a leak on the other path.
    assert body.count("kfree(pInsEntryInfo)") == 2, (
        "both the success and the failure exit must free the cursor")

    for caller in ("cdx_create_mcast_group", "cdx_update_mcast_group"):
        assert "ins_entry_info" not in function(mc, caller), (
            f"{caller} must not hold a cursor to share between listeners")


def test_only_a_bridged_root_gives_a_routed_copy_its_own_hop():
    """The routed learner marks every copy routed, and a routed group's root
    already decrements for all of them. Only a root that keeps the hop count
    -- the bridged one, keyed on the frame's own pair -- may have a routed copy
    decrement again in its own entry, or a routed group's copies would leave
    two hops down. And such a copy is a router's frame: from the egress port
    to the group's mapped address, not the matched pair.
    """
    from test_mcast_backend import code
    body = code("cdx_mc_build_listeners")
    guard = "if (grp->mac_keyed && spec->listener[ii].routed) {"
    assert guard in body
    arm = body[body.index(guard):]
    arm = arm[:arm.index("}")]
    assert "copy.hop = true;" in arm and "copy.mac_pair = NULL;" in arm
    assert "memcpy(pRtEntry->dstmac, mapped, ETH_ALEN);" in arm
    assert body.count("copy.hop = true;") == 1
    # Every copy starts from the root's framing, the per-copy change on top.
    assert body.index("memcpy(pRtEntry->dstmac, arrived, ETH_ALEN);") < body.index(guard)


def test_an_ipv6_listener_is_framed_as_ipv6_in_either_table():
    """A listener's rebuilt Ethernet header takes its EtherType from the
    entry's family, and the builder learns the family from the table it draws
    the entry from. A bridged group's listeners come from the bridged tables,
    so testing for the routed IPv6 type alone framed every bridged IPv6 copy
    as IPv4.
    """
    body = function((ROOT / "cdx/cdx_ehash.c").read_text(),
                    "create_exthash_entry4mcast_member")
    flag = body.index("pInsEntryInfo->flags |= EHASH_IPV6_FLOW")
    condition = body[body.rindex("if", 0, flag):flag]
    for table in ("IPV6_MULTICAST_TABLE", "IPV6_BRIDGED_MULTICAST_TABLE"):
        assert f"tbl_type == {table}" in condition, (
            f"a listener drawn from {table} must be framed as IPv6")
    assert "IPV4" not in condition


def test_listener_arrives_resolved():
    """The two owners resolve a listener differently and neither way serves the
    other: dpa_add_vlan_if() records a VLAN's dpa_iface_info without a net_dev
    and without IF_TYPE_ETHERNET, so dpa_get_ifinfo_by_netdev() cannot find
    CMM's tagged listeners, while a caller holding a netdev has no name worth
    trusting. So the builder takes the resolved pair and neither lookup.
    """
    ehash = (ROOT / "cdx/cdx_ehash.c").read_text()
    mc = (ROOT / "cdx/dpa_control_mc.c").read_text()
    body = function(ehash, "create_exthash_entry4mcast_member")

    signature = re.search(
        r"create_exthash_entry4mcast_member\(([^)]*)\)\s*\{", ehash, re.S).group(1)
    assert "POnifDesc onif_desc" in signature and "struct net_device *dev" in signature
    assert "MC4Output" not in signature, (
        "the builder must not take a wire message's listener record")
    for lookup in ("get_onif_by_name(", "dev_get_by_name("):
        assert lookup not in body, (
            f"the builder must not resolve the listener itself ({lookup})")

    # And the name lookup the legacy owner still needs lives in one place,
    # which is also where the netdev reference it borrows is released.
    helper = function(mc, "mcast_member_by_name")
    assert "get_onif_by_name(name)" in helper and "dev_get_by_name(" in helper
    assert helper.count("dev_put(dev)") == 1


def test_root_entry_needs_no_wire_message():
    """A group's root entry carries the classifier key and the head of the
    listener chain. Everything it needs is in the group -- the ingress name,
    both addresses, the family -- so reading them back out of an FCI message
    meant a group could only be built by a caller holding one.
    """
    mc = (ROOT / "cdx/dpa_control_mc.c").read_text()
    signature = re.search(
        r"cdx_add_mcast_table_entry\(([^)]*)\)\s*\{", mc, re.S).group(1)
    assert "mcast_cmd" not in signature and "MC4Command" not in signature, (
        "the root-entry builder must take the group, not a wire message")

    body = function(mc, "cdx_add_mcast_table_entry")
    for field in ("pMcastGrpInfo->ipv4_saddr", "pMcastGrpInfo->ipv4_daddr",
                  "pMcastGrpInfo->ucIngressIface"):
        assert field in body, f"{field} must come from the group"


def test_listener_takes_its_tags_from_the_caller():
    """A registered VLAN interface is how the legacy owner describes a tagged
    listener, and only an FCI command CMM sends creates one. An ownership mode
    without CMM therefore has no interface for the walk to find and has to name
    the tags itself, which is what the encap argument is for. Assert the
    builder accepts one and applies it where apply_l2_encap() requires -- after
    the interface walk, which is the description it refuses to overwrite.
    """
    ehash = (ROOT / "cdx/cdx_ehash.c").read_text()
    body = function(ehash, "create_exthash_entry4mcast_member")

    signature = re.search(
        r"create_exthash_entry4mcast_member\(([^)]*)\)\s*\{", ehash, re.S)
    assert "const struct cdx_l2_encap *encap" in signature.group(1), (
        "the listener builder must accept a caller-named tag stack")
    assert "apply_l2_encap(pInsEntryInfo, encap)" in body, (
        "the named tag stack must reach the L2 description")
    assert body.index("dpa_get_tx_info_by_itf(") < body.index("apply_l2_encap("), (
        "the encapsulation must be applied after the interface walk")


def test_listener_builder_resolves_its_own_fman_index():
    """dpa_get_tdinfo() reads info->fm_idx, so the port lookup has to write it
    there rather than into a local copied over afterwards. It used to be
    copied ten lines late, so every listener selected its table descriptor
    with the previous listener's FMAN index -- or with zero, on the first.
    Invisible on a single-FMAN part and wrong on any other.
    """
    body = function((ROOT / "cdx/cdx_ehash.c").read_text(),
                    "create_exthash_entry4mcast_member")
    # The assignments rather than the names, so prose about either call in a
    # comment cannot satisfy or break the ordering assertion.
    lookup = body.index("if(dpa_get_fm_port_index(")
    tdinfo = body.index("pInsEntryInfo->td = dpa_get_tdinfo(")
    assert lookup < tdinfo, "the port lookup must precede the table lookup"
    args = body[lookup:body.index(")", lookup)]
    assert "&pInsEntryInfo->fm_idx" in args, (
        "the FMAN index must be resolved into the cursor, not into a local")
