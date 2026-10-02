"""A177: compile the IPsec acquisition/unwind and SDK buffer ownership code."""

from ask_orch.process import run_process

import os
from pathlib import Path

from _host_qos_lifecycle import (function)

ROOT = Path(__file__).resolve().parents[2]
SDK_REL = Path("drivers/net/ethernet/freescale/sdk_dpaa")


def test_ipsec_lifecycle(tmp_path):
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    # Accept either an already rebuilt SDK or the previous build. In the
    # latter case apply the committed patch in isolation, never in the build.
    relative = SDK_REL / "dpaa_eth_sg.c"
    staged = tmp_path / relative
    staged.parent.mkdir(parents=True)
    staged.write_bytes((kernel / relative).read_bytes())
    patch = ROOT / "patches/kernel/105-sdk_dpaa-buffer-seed-failure.patch"
    reverse = run_process(["git", "apply", "--reverse", "--check", str(patch)],
                             cwd=tmp_path, capture_output=True)
    if reverse.returncode:
        run_process(["git", "apply", str(patch)], cwd=tmp_path, check=True)
    sdk = (kernel / SDK_REL / "dpaa_eth_common.c").read_text()
    sdk = sdk.replace("__cold __attribute__((nonnull))\n", "")
    source = (ROOT / "cdx/dpa_ipsec.c").read_text()
    devman = (ROOT / "cdx/devman.c").read_text()
    (tmp_path / "ipsec_types.inc").write_text(
        source[source.index("struct cgr_priv {"):
               source.index("/* The following macro")]
        + source[source.index("struct dpa_ipsec_sainfo {"):
               source.index("#if defined(CONFIG_INET_IPSEC_OFFLOAD)",
                            source.index("struct ipsec_info {"))])
    names = ["cdx_find_ipsec_pcd_fqinfo", "ipsec_addfq_to_exceptionfq_list",
             "ipsec_delfq_from_exceptionfq_list",
             "create_ipsec_pcd_fqs", "ipsec_init_ohport",
             "ipsec_free_pool_buffer", "release_ipsec_bpool", "add_ipsec_bpool",
             "ipsec_free_sg_buffer", "release_ipsec_sg_pools",
             "cdx_init_scatter_gather_bpool", "cdx_init_skb_2bfreed_bpool",
             "cdx_dpaa_ingress_cgr_init", "ipsec_delete_cgr_on_cpu",
             "cdx_dpaa_ingress_cgr_exit", "cdx_dpa_ipsec_ready",
             "cdx_dpa_ipsec_init", "cdx_dpa_ipsec_exit"]
    (tmp_path / "ipsec_lifecycle.inc").write_text(
        source[source.index("#define CDX_MAX_SG_BUFF_SIZE"):
               source.index("static void ipsec_free_sg_buffer")]
        + function(staged.read_text(), "dpaa_bp_alloc_n_add_buffs")
        + function(staged.read_text(), "dpa_bp_recycle_frag")
        + function(sdk, "dpa_bp_drain") + function(sdk, "_dpa_bp_free")
        + "\n".join(function(devman, n) for n in
                    ["cdx_drain_fq", "cdx_destroy_fq", "cdx_drain_fq_list", "cdx_destroy_fq_list"])
        + "\n".join(function(source, n) for n in names)
        + function(source, "create_ipsec_fqs")
        + source[source.index("void *cdx_dpa_ipsecsa_alloc("):
                 source.index("/* change the state of frame queues */")]
        # The FQIDs a possibly linked classifier entry holds back, until the
        # datapath restart that settles it.
        + function(source, "dpa_ipsec_release_fqids")
        + function(source, "cdx_dpa_ipsecsa_release")
        + function(source, "cdx_dpa_ipsecsa_keep_fqids")
        + function(source, "cdx_dpa_ipsec_release_held_fqids")
        # And at unload, once CDX knows whether anything may still name them.
        + function(source, "cdx_dpa_ipsec_held_fqids_exit"))
    binary = tmp_path / "ipsec_lifecycle"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
        "-Wno-sign-compare", "-Wno-pointer-sign",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
        "-I", str(tmp_path), str(Path(__file__).with_name("ipsec_lifecycle.c")),
        "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=60, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
