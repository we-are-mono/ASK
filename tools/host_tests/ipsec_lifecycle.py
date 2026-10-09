"""A177: compile the IPsec acquisition/unwind and SDK buffer ownership code,
and (A308) an SA's release, step by step from its deletion timer."""

from ask_orch.process import run_process

import os
import re
from pathlib import Path

from _host_qos_lifecycle import (function)

ROOT = Path(__file__).resolve().parents[2]
SDK_REL = Path("drivers/net/ethernet/freescale/sdk_dpaa")


def definition(source, name):
    """A function definition by name, whatever it returns."""
    match = re.search(r"^[A-Za-z_][^\n;{}()]*?\b" + name + r"\s*\([^;{]*?\)\s*\{",
                      source, re.M)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


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
    sec = (ROOT / "cdx/cdx_dpa_ipsec.c").read_text()
    control = (ROOT / "cdx/control_ipsec.h").read_text()
    regs = (kernel / "drivers/crypto/caam/regs.h").read_text()
    header = (ROOT / "cdx/dpa_ipsec.h").read_text()
    (tmp_path / "ipsec_types.inc").write_text(
        re.search(r"^#define\s+IPSEC_EXCEPTION_FRAMES\s.*$", header, re.M).group() + "\n"
        + source[source.index("struct cgr_priv {"):
               source.index("/* The following macro")]
        + source[source.index("struct dpa_ipsec_sainfo {"):
               source.index("#if defined(CONFIG_INET_IPSEC_OFFLOAD)",
                            source.index("struct ipsec_info {"))]
        # The SA's release: its steps, flags and timing, the SEC context it
        # frees, and the DECO watchdog bit as the kernel defines it.
        + re.search(r"^#define\s+SA_DELETE\s.*$", control, re.M).group() + "\n"
        + control[control.index("struct cipher_params {"):
                  control.index("typedef struct _tSAEntry {")]
        + re.search(r"^#define MCFGR_WDENABLE\s.*$", regs, re.M).group() + "\n")
    names = ["cdx_find_ipsec_pcd_fqinfo", "ipsec_addfq_to_exceptionfq_list",
             "ipsec_delfq_from_exceptionfq_list",
             "create_ipsec_pcd_fqs", "ipsec_init_ohport",
             "ipsec_free_pool_buffer", "release_ipsec_bpool", "add_ipsec_bpool",
             "ipsec_free_sg_buffer", "release_ipsec_sg_pools",
             "cdx_init_scatter_gather_bpool", "cdx_init_skb_2bfreed_bpool",
             "cdx_dpaa_ingress_cgr_init", "ipsec_delete_cgr_on_cpu",
             "cdx_dpaa_ingress_cgr_exit", "ipsec_exception_cgr_init",
             "ipsec_exception_cgr_exit", "cdx_dpa_ipsec_ready",
             "cdx_dpa_ipsec_init", "cdx_dpa_ipsec_exit"]
    (tmp_path / "ipsec_lifecycle.inc").write_text(
        # What an SA queue gives back undelivered, rejected or drained.
        re.search(r"^static atomic_t dpa_ipsec_ern_count\b.*$", source, re.M).group() + "\n"
        + function(source, "dpa_ipsec_fd_drop")
        + function(source, "dpa_ipsec_ern_cb")
        + function(source, "dpa_ipsec_drain_dqrr")
        + source[source.index("#define CDX_MAX_SG_BUFF_SIZE"):
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
        + function(source, "cdx_dpa_ipsec_held_fqids_exit")
        # The SA's accessors and its queues' steps out of service.
        + definition(source, "get_shared_desc")
        + "".join(function(source, n) for n in
                  ["get_fqid_to_sec", "ipsec_get_to_cp_fqid",
                   "cdx_dpa_ipsec_retire_fq", "cdx_dpa_ipsec_fq_stop",
                   "cdx_ipsec_sa_fq_check_if_retired_state"])
        # The release itself, from the SEC side: what SEC is seen to do, the
        # context built and freed, and the timer steps between.
        + re.search(r"^#define CDX_SEC_CSTA_IDLE\s.*$", sec, re.M).group() + "\n"
        + re.search(r"^static unsigned int sa_release_held;$", sec, re.M).group() + "\n"
        + re.search(r"^struct cdx_sec_sample \{.*?^\};", sec, re.S | re.M).group() + "\n"
        + function(sec, "cdx_ipsec_sec_sample")
        + function(sec, "cdx_ipsec_sec_sa_context_free")
        + sec[sec.index("PDpaSecSAContext  cdx_ipsec_sec_sa_context_alloc("):
              sec.index("/* How much of the shared descriptor the PDB takes")]
        + "".join(function(sec, n) for n in
                  ["cdx_ipsec_sa_sec_done", "cdx_ipsec_sa_release_stalled",
                   "cdx_ipsec_release_sa_ctx_cbk", "cdx_ipsec_release_sa_resources"]))
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
