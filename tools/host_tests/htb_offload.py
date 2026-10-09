"""Compile the production HTB offload commands and drive sch_htb's sequence.

Run without the board fixtures:
    pytest tools/host_tests/htb_offload.py
"""

from ask_orch.process import run_process

from pathlib import Path
import os
import re
import shutil

import pytest

ROOT = Path(__file__).resolve().parents[2]


def function(source, name):
    # The line has to begin with a word, the return type: a comment line that
    # names `foo()' would otherwise match and run on to the next definition.
    match = re.search(r"^(?:static )?\w[^\n]*\b" + name + r"\([^;]*?\)\s*\{", source, re.M)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


def test_htb_offload(tmp_path):
    compiler = os.environ.get("CC", "cc")
    assert shutil.which(compiler), f"C compiler required: {compiler}"
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    dsfield = kernel / "include/net/dsfield.h"
    if not dsfield.exists():
        pytest.fail("build the ASK kernel or set ASK_KERNEL_SOURCE for include/net/dsfield.h")
    # The kernel's own rewrite, so a remark is checked against the header and
    # checksum it really leaves rather than against a restatement of it.
    (tmp_path / "dsfield.inc").write_text("".join(
        function(dsfield.read_text(), name) for name in
        ("ipv4_get_dsfield", "ipv6_get_dsfield", "ipv4_change_dsfield",
         "ipv6_change_dsfield")))
    source = (ROOT / "cdx/cdx_htb.c").read_text()
    backend = (ROOT / "cdx/cdx_flowtable_backend.h").read_text()
    # The pools a tree's class queues are budgeted against, as the headers
    # define them, and the hardware layer's own reading of how narrow a WRED
    # band it can draw, which the curve's conversion to frames widens to.
    ipsec = (ROOT / "cdx/dpa_ipsec.h").read_text()
    ceetm = (ROOT / "cdx/cdx_ceetm_app.c").read_text()
    # And the depth a queue a class gave back is parked at, which bounds what
    # the classifier entries still naming it can put on it.
    ceetm_h = (ROOT / "cdx/cdx_ceetm_app.h").read_text()
    (tmp_path / "htb_pools.inc").write_text(
        "".join(re.search(rf"^#define\s+{name}\s.*$", ipsec, re.M).group() + "\n"
                for name in ("IPSEC_BUFCOUNT", "IPSEC_SHARE_FRAMES", "IPSEC_QDISC_FRAMES"))
        + re.search(r"^#define\s+CEETM_PARKED_CQ_DEPTH\s.*$", ceetm_h, re.M).group() + "\n"
        + "".join(line + "\n" for line in ceetm.splitlines()
                  if line.startswith("#define CEETM_WRED_"))
        + function(ceetm, "ceetm_wred_maxp") + function(ceetm, "ceetm_wred_min_band"))
    (tmp_path / "htb_types.inc").write_text(
        # The class encoding first: the queue budget asserts against it, and the
        # Tx path masks a decoded class with it before indexing.
        backend[backend.index("/* Layout of cdx_ft_rule.qos"):
                backend.index("struct cdx_ft_counters")]
        # The queue budget and both structures, stopping where the file's own
        # storage begins: the harness declares that itself so it can inspect it.
        + source[source.index("/* Leaf classes are handed netdev"):
                 source.index("/* Indexed the way gQMCtx is")]
        # And what the Tx path reads a frame into, with the datagram a
        # fragment is of and the per-CPU memory of first fragments' classes.
        + source[source.index("struct cdx_htb_datagram {"):
                 source.index("};", source.index("struct cdx_htb_frame {")) + 3]
        + re.search(r"^#define CDX_HTB_MAX_TAGS\s.*$", source, re.M).group() + "\n"
        + source[source.index("#define CDX_HTB_DATAGRAMS"):
                 source.index("static DEFINE_PER_CPU(struct cdx_htb_datagrams, cdx_htb_datagrams);")]
        + "static DEFINE_PER_CPU(struct cdx_htb_datagrams, cdx_htb_datagrams);\n")
    # The kernel's test for an IPv6 extension header, which the Tx path's own
    # walk to a transport header uses, with the constants and lengths it is
    # written in.
    ipv6 = (kernel / "include/net/ipv6.h").read_text()
    lengths = (kernel / "include/linux/ipv6.h").read_text()
    exthdrs = (kernel / "net/ipv6/exthdrs_core.c").read_text()
    (tmp_path / "exthdrs.inc").write_text(
        "\n".join(re.findall(r"^#define NEXTHDR_\w+\s.*$", ipv6, re.M)) + "\n"
        + re.search(r"^#define ipv6_optlen\(p\).*$", lengths, re.M).group() + "\n"
        + re.search(r"^#define ipv6_authlen\(p\).*$", lengths, re.M).group() + "\n"
        + function(exthdrs, "ipv6_ext_hdr"))
    # In dependency order, which is file order but for the eligibility sync
    # the publish calls and the file declares ahead: no forward declarations
    # are needed and the compiler catches a call to something not yet defined.
    names = [
        "cdx_htb_entry", "cdx_htb_port_of", "cdx_htb_port_name", "cdx_htb_find",
        "cdx_htb_find_qid", "cdx_htb_channel_owned",
        "cdx_htb_live_trees", "cdx_htb_budget", "cdx_htb_red_frame",
        "cdx_htb_red_want", "cdx_htb_red_frames", "cdx_htb_cap_queues",
        "cdx_htb_tree_mask", "cdx_htb_channel_port",
        "cdx_htb_cap_share", "cdx_htb_cap_write", "cdx_htb_cap_charge",
        "cdx_htb_cap_room", "cdx_htb_cap_apply", "cdx_htb_cap",
        "cdx_htb_cap_trees",
        "cdx_htb_regrow_work", "cdx_htb_implicit_sync",
        "cdx_htb_control_budget", "cdx_htb_publish", "cdx_htb_resize",
        "cdx_htb_channel_get", "cdx_htb_cq_get", "cdx_htb_implicit_forget",
        "cdx_htb_cq_configure", "cdx_htb_cq_release", "cdx_htb_cq_restore",
        "cdx_htb_shape", "cdx_htb_unshape", "cdx_htb_class_free", "cdx_htb_qid_free",
        "cdx_htb_create", "cdx_htb_destroy", "cdx_htb_leaf_alloc",
        "cdx_htb_leaf_to_inner", "cdx_htb_leaf_del", "cdx_htb_leaf_del_last",
        "cdx_htb_node_modify", "cdx_htb_query_queue", "cdx_htb_command",
        "cdx_ft_egress_changed", "cdx_ft_egress_drain", "cdx_ft_egress_restarted",
        "cdx_htb_setup_tc",
        "cdx_register_ft_egress", "cdx_unregister_ft_egress",
        "cdx_htb_class_queue",
        "cdx_htb_port_gone", "cdx_htb_port_released", "cdx_htb_mtu_changed",
        "cdx_register_ft_qos_class",
        "cdx_unregister_ft_qos_class", "cdx_htb_l4", "cdx_htb_ip_family",
        "cdx_htb_parse", "cdx_htb_control", "cdx_htb_control_admit",
        "cdx_ft_qos_control_overruns", "cdx_htb_frame_class", "cdx_htb_same_datagram", "cdx_htb_fragment_class",
        "cdx_htb_dscp_slot",
        "cdx_htb_routed", "cdx_ft_qos_remark_failures", "cdx_htb_remark",
        "cdx_htb_select_queue", "cdx_htb_txq_fq", "cdx_htb_resolve_class",
        "cdx_htb_class_stats", "cdx_htb_red", "cdx_htb_setup_red",
        "cdx_register_ft_setup_tc",
        "cdx_unregister_ft_setup_tc", "cdx_setup_tc", "cdx_htb_init",
        "cdx_htb_exit",
    ]
    # The cap's view of one class queue is a structure among the functions.
    cap_queue = source.index("struct cdx_htb_cap_queue {")
    (tmp_path / "htb_production.inc").write_text(
        source[cap_queue:source.index("};", cap_queue) + 3]
        + "\n".join(function(source, name) for name in names))
    binary = tmp_path / "htb_offload"
    run_process([
        compiler, "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra", "-Werror",
        "-Wno-unused-parameter", "-fsanitize=address,undefined",
        "-fno-omit-frame-pointer", "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("htb_offload.c")), "-o", str(binary),
    ], check=True)
    result = run_process([str(binary)], text=True, capture_output=True, timeout=60,
                            env={**os.environ,
                                 "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
                                 "UBSAN_OPTIONS": "halt_on_error=1"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert "fault points" in result.stdout
    print(result.stdout.strip())


def test_htb_queue_budget_matches_the_driver(tmp_path):
    """The leaf qids handed to sch_htb have to be netdev queues that exist.

    sch_htb turns the index the driver returns straight into
    netdev_get_tx_queue() with no bounds check, so the budget this file hands
    out and the headroom patch 150 reserves are one number, not two that happen
    to agree.
    """
    patch = (ROOT / "patches/kernel/150-sdk_dpaa-hardware-qdisc.patch").read_text()
    assert "+#define DPAA_ETH_CEETM_LEAF_QUEUES\t16" in patch
    assert "+#define DPAA_ETH_TX_QUEUES\t16" in patch
    source = (ROOT / "cdx/cdx_htb.c").read_text()
    assert "#define CDX_HTB_QID_BASE\tDPAA_ETH_TX_QUEUES" in source
    assert "#define CDX_HTB_MAX_LEAVES\tDPAA_ETH_CEETM_LEAF_QUEUES" in source
