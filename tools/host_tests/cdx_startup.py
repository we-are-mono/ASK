"""Exercise the production CDX startup transaction under ASan/UBSan."""

from ask_orch.process import run_process

from pathlib import Path
import os
import re

import pytest

from _host_qos_lifecycle import function

ROOT = Path(__file__).resolve().parents[2]


def control_locks():
    source = (ROOT / "cdx/cdx_main.c").read_text()
    return (function(source, "cdx_ctrl_lock_with_rtnl")
            + function(source, "cdx_ctrl_unlock_with_rtnl"))


def test_cdx_shutdown(tmp_path):
    main = (ROOT / "cdx/cdx_main.c").read_text()
    qos = (ROOT / "cdx/control_qm.c").read_text()
    timer = (ROOT / "cdx/cdx_timer.c").read_text()
    (tmp_path / "cdx_shutdown.inc").write_text(
        control_locks() + function(timer, "cdx_ctrl_timer_stop")
        + function(qos, "qm_quiesce") + function(main, "cdx_module_deinit"))
    binary = tmp_path / "cdx_shutdown"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
        "-Werror=implicit-function-declaration", "-I", str(tmp_path),
        str(Path(__file__).with_name("cdx_shutdown.c")), "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=30,
                   env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
                        "UBSAN_OPTIONS": "halt_on_error=1"})


@pytest.mark.parametrize("ipsec", [True, False])
def test_cdx_subsystems(tmp_path, ipsec):
    """Each subsystem's exit runs once, only if its init succeeded, and in the
    reverse of the order they came up -- at every failure point, since the
    module's deinit chain runs the exit whatever the init returned."""
    main = (ROOT / "cdx/cdx_main.c").read_text()
    # The per-subsystem flags, as declared: the IPsec one only where IPsec is
    # built, or a build without it warns about a flag nothing reads.
    flags = main[main.index("static bool cdx_tx_up"):main.index("static int __init cdx_subsys_init")]
    (tmp_path / "cdx_subsys.inc").write_text(
        flags + function(main, "cdx_subsys_init") + function(main, "cdx_subsys_exit"))
    binary = tmp_path / "cdx_subsys"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
        *(["-DDPA_IPSEC_OFFLOAD"] if ipsec else []),
        "-I", str(tmp_path), str(Path(__file__).with_name("cdx_subsys.c")),
        "-o", str(binary),
    ], check=True)
    result = run_process([str(binary)], text=True, capture_output=True, timeout=30,
                            env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
                                 "UBSAN_OPTIONS": "halt_on_error=1"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert f"CDX subsystem fault points passed: {6 if ipsec else 5}" in result.stdout


def test_cdx_startup(tmp_path):
    source = (ROOT / "cdx/dpa_cfg.c").read_text()
    # The port coverage helpers come with the declarations above the port
    # resolution; the netdev lookup a resume makes is the harness's.
    names = ["release_cfg_info", "dpa_prepare_ports", "dpa_set_ports_enabled",
             "dpa_release_pcd_fqs", "dpa_rollback_resources", "dpa_detach_ports",
             "dpa_ports_fence", "dpa_ports_wait_stopped", "dpa_ports_stop",
             "dpa_ports_start", "dpa_cfg_stop", "dpa_cfg_covered", "dpa_cfg_shared_icid",
             "dpa_cfg_port_rejected", "dpa_cfg_resume",
             "dpa_cfg_quiesce", "dpa_cfg_deinit", "dpa_cfg_set_expt_defaults",
             "dpa_cfg_publish", "dpa_cfg_install"]
    (tmp_path / "cdx_startup.inc").write_text(
        control_locks()
        + source[source.index("struct dpa_init_port {"):source.index("/* Resolve every port")]
        + "\n".join(function(source, n) for n in names))
    qos = (ROOT / "cdx/cdx_qos.c").read_text()
    (tmp_path / "cdx_policers.inc").write_text(
        function(qos, "cdxdrv_release_port_policer_slots")
        + function(qos, "cdxdrv_release_shared_policers"))
    binary = tmp_path / "cdx_startup"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-fno-pie", "-no-pie",
        "-Werror=implicit-function-declaration", "-I", str(tmp_path),
        "-I", str(ROOT / "cdx"), str(Path(__file__).with_name("cdx_startup.c")),
        "-o", str(binary),
    ], check=True)
    result = run_process([str(binary)], text=True, capture_output=True, timeout=30,
                            env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
                                 "UBSAN_OPTIONS": "halt_on_error=1"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert "CDX startup fault points passed" in result.stdout
    print(result.stdout.strip())


@pytest.mark.parametrize("queues", [8, 16])
def test_queues(tmp_path, queues):
    source = (ROOT / "cdx/devman.c").read_text()
    pool = (ROOT / "cdx/dpa_ipsec.h").read_text()
    bound = "".join(line + "\n" for line in source.splitlines()
                    if line.startswith(("#define FWD_CGR_", "static unsigned int fwd_queue_us")))
    bound += "".join(line + "\n" for line in pool.splitlines()
                     if line.startswith(("#define IPSEC_BUFCOUNT", "#define IPSEC_EGRESS_FRAMES")))
    (tmp_path / "cdx_queues.inc").write_text(
        bound + function(source, "fwd_tx_drain_dqrr") + function(source, "fwd_tx_ern")
        + function(source, "fwd_cgr_bytes") + function(source, "fwd_cgr_frames")
        + function(source, "fwd_pool_frames") + function(source, "fwd_cgr_set")
        + function(source, "fwd_cgr_owner") + function(source, "fwd_cgr_link_speed")
        + function(source, "dpa_fwd_cgr_follow_link") + function(source, "fwd_cgr_release")
        + function(source, "sec_cgr_init") + function(source, "sec_cgr_release")
        + function(source, "create_tx_fq_set")
        + function(source, "cdx_drain_fq") + function(source, "cdx_destroy_fq")
        + function(source, "cdx_drain_fq_list") + function(source, "cdx_destroy_fq_list") + function(source, "create_fwd_tx_fqs")
        + function(source, "destroy_tx_fq_set") + function(source, "destroy_fwd_tx_fqs"))
    binary = tmp_path / "cdx_queues"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
        "-Werror=implicit-function-declaration", "-I", str(tmp_path),
        f"-DDPAA_FWD_TX_QUEUES={queues}",
        str(Path(__file__).with_name("cdx_queues.c")), "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=30,
                   env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
                        "UBSAN_OPTIONS": "halt_on_error=1"})


def test_port_records_keep_no_mtu():
    """A port's MTU changes under RTNL with nothing telling devman, and with
    jumbo frames it changes what the port receives (A316): a copy taken when
    the port registered goes stale the first time it moves. Nothing reads one,
    so a record keeps none, and whatever needs the MTU asks the netdev."""
    portdefs = (ROOT / "cdx/portdefs.h").read_text()
    start = portdefs.index("struct dpa_iface_info {")
    record = portdefs[start:portdefs.index("\n};", start)]
    assert not re.search(r"\bmtu\b", record), "dpa_iface_info caches an MTU"
    devman = (ROOT / "cdx/devman.c").read_text()
    assert not re.search(r"iface_info->mtu\b", devman)


def test_fragment_pool_holds_a_port_frame():
    """The fragmenter writes a fragment as large as its path into one buffer
    of this pool, so a jumbo path needs the ports' own buffer size; and at
    that size the count is what SEC's output pool can have in flight, not the
    2048 that cost 21 MB of jumbo buffers."""
    source = (ROOT / "cdx/cdx_ehash.c").read_text()
    assert re.search(r"^#define CDX_FRAG_BUFF_SIZE\s+dpa_bp_size\(NULL\)$", source, re.M)
    count = re.search(r"^#define CDX_FRAG_BUFFERS_CNT\s+(\d+)$", source, re.M)
    assert count and int(count.group(1)) == 512
    body = function(source, "cdx_create_fragment_bufpool")
    # The port pool it borrows a device from is asked for the size this one
    # is, after that size is set.
    assert body.index("bp->size = CDX_FRAG_BUFF_SIZE;") < \
        body.index("get_phys_port_poolinfo_bysize(bp->size,")


def test_eqcr(tmp_path):
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    high = kernel / "drivers/staging/fsl_qbman/qman_high.c"
    low = high.with_name("qman_low.h")
    if not high.exists():
        pytest.fail("build the ASK kernel or set ASK_KERNEL_SOURCE to its patched source")
    text = low.read_text()
    start = text.index("static inline u8 qm_eqcr_get_hw_fill(")
    end = text.index("\n}", start) + 3
    cached = text.index("static inline u8 qm_eqcr_get_fill(")
    cached_end = text.index("\n}", cached) + 3
    (tmp_path / "cdx_eqcr.inc").write_text(text[start:end] + "\n"
        + text[cached:cached_end] + "\n" + function(high.read_text(), "qman_eqcr_is_empty"))
    binary = tmp_path / "cdx_eqcr"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("cdx_eqcr.c")), "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=30,
                   env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
                        "UBSAN_OPTIONS": "halt_on_error=1"})
