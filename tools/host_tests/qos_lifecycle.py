"""Compile production QoS lifecycle functions with fault-injected SDK calls.

Run without the board fixtures:
    pytest tools/host_tests/qos_lifecycle.py
"""

from ask_orch.process import run_process

from _host_qos_lifecycle import (ROOT, function)

from pathlib import Path
import os
import re
import shutil


def test_qos_lifecycle(tmp_path):
    compiler = os.environ.get("CC", "cc")
    assert shutil.which(compiler), f"C compiler required: {compiler}"
    source = (ROOT / "cdx/cdx_ceetm_app.c").read_text()
    control = (ROOT / "cdx/control_qm.c").read_text()
    header = (ROOT / "cdx/module_qm.h").read_text()
    constants = (ROOT / "cdx/cdx_ceetm_app.h").read_text()
    (tmp_path / "qos_types.inc").write_text(
        constants[constants.index("#define CDX_CEETM_MAX_LNIS"):constants.index("   Function Prototypes")].rsplit("/*", 1)[0]
        + header[header.index("struct ceetm_fq {"):header.index("/* return values */")]
    )
    names = [
        "ceetm_resolve_channel", "ceetm_get_egressfq", "ceetm_egressfq_hook",
        "ceetm_release_lni", "ceetm_program_channel_shaper",
        "ceetm_create_lni", "ceetm_get_fqcount", "ceetm_class_queue_backlog",
        "ceetm_create_ccg_for_class_queue", "ceetm_num_to_2powN_multiple",
        "ceetm_cfg_td_on_class_queue", "ceetm_cq_wred_off", "ceetm_park_class_queue",
        "ceetm_create_cq",
        "ceetm_create_queues", "ceetm_create_channel", "ceetm_init_channels",
        "ceetm_assign_chnl",
        "ceetm_release_fd", "ceetm_sync_portal", "ceetm_sync_portals",
        "ceetm_drain_queue", "ceetm_drain_channel", "ceetm_pop_leftovers",
        "ceetm_quiesce_port", "ceetm_put_channel_devices",
        "ceetm_dscp_map_release", "ceetm_release_iface", "ceetm_release_queue", "ceetm_release_channels",
        "ceetm_exit",
    ]
    (tmp_path / "qos_production.inc").write_text(
        "static struct ceetm_chnl_info qm_chnl_info[CDX_CEETM_MAX_CHANNELS];\n"
        "static bool ceetm_callbacks_registered;\n"
        "static int ceetm_release_channels(void);\n"
        "static int ceetm_pop_leftovers(struct classque_info *cqinfo);\n"
        + re.search(r"^#define CEETM_DRAIN_ALL\s.*$", source, re.M).group() + "\n"
        + "\n".join(function(source, name) for name in names)
        + "\n".join(function(control, name) for name in [
            "qm_init", "qm_quiesce", "qm_exit", "cdx_enable_ceetm_on_iface", "cdx_disable_ceetm_on_iface",
        ])
    )
    binary = tmp_path / "qos_lifecycle"
    run_process([
        compiler, "-std=gnu11", "-g", "-O1", "-fsanitize=address,undefined",
        "-fno-omit-frame-pointer", "-fno-pie", "-no-pie",
        "-Werror=implicit-function-declaration", "-I", str(tmp_path),
        str(Path(__file__).with_name("qos_lifecycle.c")), "-o", str(binary),
    ], check=True)
    result = run_process([str(binary)], text=True, capture_output=True,
                            env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
                                 "UBSAN_OPTIONS": "halt_on_error=1"}, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "fault points passed" in result.stdout
    print(result.stdout.strip())


def test_qos_sdk_lifecycle(tmp_path):
    import pytest

    kernel = Path(os.environ.get(
        "ASK_KERNEL_SOURCE",
        ROOT / "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source",
    ))
    path = kernel / "drivers/staging/fsl_qbman/qman_high.c"
    if not path.exists():
        pytest.fail("build the ASK kernel or set ASK_KERNEL_SOURCE to its patched source")
    source = path.read_text()
    (tmp_path / "lfq_production.inc").write_text(
        function(source, "qman_ceetm_lfq_claim")
        + function(source, "qman_ceetm_lfq_release")
        + function(source, "qman_drain_ern")
    )
    compiler = os.environ.get("CC", "cc")
    binary = tmp_path / "ceetm_lfq"
    run_process([
        compiler, "-std=gnu11", "-g", "-O1", "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("ceetm_lfq.c")), "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True,
                   env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
                        "UBSAN_OPTIONS": "halt_on_error=1"}, timeout=10)


def test_qos_sdk_cq_pop(tmp_path):
    import pytest

    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    path = kernel / "drivers/staging/fsl_qbman/qman_high.c"
    if not path.exists():
        pytest.fail("build the ASK kernel or set ASK_KERNEL_SOURCE to its patched source")
    source = path.read_text()
    start = source.index("static inline void hw_fd_to_cpu(")
    end = source.index("\n}", start) + 3
    (tmp_path / "cq_production.inc").write_text(source[start:end] + "\n"
        + function(source, "qman_ceetm_cq_peek_pop_xsfdrread")
        + function(source, "qman_ceetm_cq_pop"))
    binary = tmp_path / "ceetm_cq"
    run_process([
        os.environ.get("CC", "cc"), "-std=gnu11", "-g", "-O1",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
        "-Werror=implicit-function-declaration", "-I", str(tmp_path),
        str(Path(__file__).with_name("ceetm_cq.c")), "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=10,
                   env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
                        "UBSAN_OPTIONS": "halt_on_error=1"})
