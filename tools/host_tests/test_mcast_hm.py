"""The multicast listener's header manipulations, and who owns their cursor."""

import os
from pathlib import Path
import re
import subprocess

from test_pppoe_hm import declaration
from test_qos_lifecycle import function

ROOT = Path(__file__).resolve().parents[2]
HEADER = "drivers/net/ethernet/freescale/sdk_fman/inc/Peripherals/fm_ehash.h"


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
        + declaration((ROOT / "cdx/control_ipv4.h").read_text(), "cdx_l2_encap")
        + "\n".join(re.findall(r"^#define\s+(?:INSERT_VLAN_HDR|INSERT_L2_HDR)\s.*$",
                               header, re.M)) + "\n"
        + loose_declaration(header, "en_ehash_stats")
        + loose_declaration(header, "en_ehash_insert_vlan_hdr")
        + loose_declaration(header, "en_ehash_insert_l2_hdr"))
    (tmp_path / "mcast_hm.inc").write_text(
        function(ehash, "apply_l2_encap")
        + function(ehash, "create_vlan_ins_hm")
        + function(ehash, "create_ethernet_hm"))
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
