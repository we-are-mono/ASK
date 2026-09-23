"""The DPAA driver's end of the offload module's hooks, compiled from the kernel.

Every hook the module registers is a pointer into loadable text that a
built-in driver calls. The unregisters wait for the calls already inside it --
SRCU for ndo_setup_tc, whose handler sleeps, and an RCU grace period for the
data path -- which only holds if the driver takes those read-side sections
itself rather than trusting its caller's context.
"""

import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SDK = Path("drivers/net/ethernet/freescale/sdk_dpaa")


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


def test_dpaa_hooks(tmp_path):
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    eth = (kernel / SDK / "dpaa_eth.c").read_text()
    sg = (kernel / SDK / "dpaa_eth_sg.c").read_text()
    header = (kernel / SDK / "dpaa_eth_common.h").read_text()
    types = [re.search(pattern, header, re.S).group() for pattern in (
        r"typedef struct qman_fq \*\(\*cdx_get_ipsec_fq_hook_t\)\([^;]*;",
        r"typedef struct qman_fq \*\(\*cdx_get_ceetm_egressfq\)\([^;]*;",
        r"typedef struct qman_fq \*\(\*cdx_get_ceetm_dscp_fq\)\([^;]*;",
        r"typedef int \(\*dpa_setup_tc_handler\)\([^;]*;",
        r"#define DPA_SELECT_QUEUE_NONE[^\n]*",
        r"#define DPA_CEETM_CLASS_STATS[^\n]*",
        r"struct dpa_qdisc_ops \{.*?\n\};")]
    (tmp_path / "dpaa_hooks_types.inc").write_text("\n".join(types) + "\n")
    (tmp_path / "dpaa_hooks_production.inc").write_text(
        "".join(function(eth, name) for name in (
            "dpa_register_setup_tc", "dpa_unregister_setup_tc", "dpa_setup_tc",
            "dpa_register_qdisc_ops", "dpa_unregister_qdisc_ops", "dpa_qdisc_txq_fq",
            "dpa_qdisc_class_stats", "dpa_qdisc_select_queue"))
        + "".join(function(sg, name) for name in (
            "dpa_register_ceetm_get_egress_fq", "dpa_unregister_ceetm_get_egress_fq",
            "dpa_register_ipsec_fq_handler", "dpa_unregister_ipsec_fq_handler",
            "dpaa_submit_outb_pkt_to_SEC", "dpaa_submit_inb_pkt_to_SEC", "cpe_fp_tx")))
    binary = tmp_path / "dpaa_hooks"
    subprocess.run([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra",
        "-Werror", "-Wno-unused-parameter", "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("dpaa_hooks.c")), "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
