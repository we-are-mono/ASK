"""Compile the production HTB offload commands and drive sch_htb's sequence.

Run without the board fixtures:
    pytest tools/host_tests/test_htb_offload.py
"""

from pathlib import Path
import os
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def function(source, name):
    match = re.search(r"^(?:static )?[^\n]+\b" + name + r"\([^;]*?\)\s*\{", source, re.M)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


def test_htb_offload(tmp_path):
    compiler = os.environ.get("CC", "cc")
    assert shutil.which(compiler), f"C compiler required: {compiler}"
    source = (ROOT / "cdx/cdx_htb.c").read_text()
    backend = (ROOT / "cdx/cdx_flowtable_backend.h").read_text()
    (tmp_path / "htb_types.inc").write_text(
        # The class encoding first: the queue budget asserts against it, and the
        # Tx path masks a decoded class with it before indexing.
        backend[backend.index("/* Layout of cdx_ft_rule.qos"):
                backend.index("struct cdx_ft_counters")]
        # The queue budget and both structures, stopping where the file's own
        # storage begins: the harness declares that itself so it can inspect it.
        + source[source.index("/* Leaf classes are handed netdev"):
                 source.index("/* Indexed the way gQMCtx is")])
    # In file order, which is also dependency order: no forward declarations
    # are needed and the compiler catches a call to something not yet defined.
    names = [
        "cdx_htb_entry", "cdx_htb_port_of", "cdx_htb_find", "cdx_htb_find_qid",
        "cdx_htb_channel_owned", "cdx_htb_publish", "cdx_htb_resize",
        "cdx_htb_channel_get", "cdx_htb_cq_get",
        "cdx_htb_cq_configure", "cdx_htb_cq_release", "cdx_htb_cq_restore",
        "cdx_htb_shape", "cdx_htb_class_free", "cdx_htb_qid_free",
        "cdx_htb_create", "cdx_htb_destroy", "cdx_htb_leaf_alloc",
        "cdx_htb_leaf_to_inner", "cdx_htb_leaf_del", "cdx_htb_leaf_del_last",
        "cdx_htb_node_modify", "cdx_htb_query_queue", "cdx_htb_command",
        "cdx_htb_setup_tc", "cdx_htb_class_queue",
        "cdx_htb_port_gone", "cdx_register_ft_qos_class",
        "cdx_unregister_ft_qos_class", "cdx_htb_dscp_slot",
        "cdx_htb_select_queue", "cdx_htb_txq_fq",
        "cdx_htb_class_stats", "cdx_htb_red", "cdx_htb_setup_red",
        "cdx_register_ft_setup_tc",
        "cdx_unregister_ft_setup_tc", "cdx_setup_tc", "cdx_htb_init",
        "cdx_htb_exit",
    ]
    (tmp_path / "htb_production.inc").write_text(
        "\n".join(function(source, name) for name in names))
    binary = tmp_path / "htb_offload"
    subprocess.run([
        compiler, "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra", "-Werror",
        "-Wno-unused-parameter", "-fsanitize=address,undefined",
        "-fno-omit-frame-pointer", "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("htb_offload.c")), "-o", str(binary),
    ], check=True)
    result = subprocess.run([str(binary)], text=True, capture_output=True, timeout=60,
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
