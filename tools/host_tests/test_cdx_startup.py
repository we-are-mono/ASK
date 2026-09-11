"""Exercise the production CDX SET_PARAMS transaction under ASan/UBSan."""

from pathlib import Path
import os
import subprocess

import pytest

from test_qos_lifecycle import function

ROOT = Path(__file__).resolve().parents[2]


def test_cdx_startup(tmp_path):
    source = (ROOT / "cdx/dpa_cfg.c").read_text()
    names = ["release_cfg_info", "dpa_prepare_ports", "dpa_set_ports_enabled",
             "dpa_release_pcd_fqs", "dpa_rollback_resources", "cdx_ioc_set_dpa_params"]
    (tmp_path / "cdx_startup.inc").write_text("\n".join(function(source, n) for n in names))
    qos = (ROOT / "cdx/cdx_qos.c").read_text()
    (tmp_path / "cdx_policers.inc").write_text(
        function(qos, "cdxdrv_release_port_policer_slots")
        + function(qos, "cdxdrv_release_shared_policers"))
    binary = tmp_path / "cdx_startup"
    subprocess.run([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-fno-pie", "-no-pie",
        "-Werror=implicit-function-declaration", "-I", str(tmp_path),
        "-I", str(ROOT / "cdx"), str(Path(__file__).with_name("cdx_startup.c")),
        "-o", str(binary),
    ], check=True)
    result = subprocess.run([str(binary)], text=True, capture_output=True, timeout=30,
                            env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
                                 "UBSAN_OPTIONS": "halt_on_error=1"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert "CDX startup fault points passed" in result.stdout
    print(result.stdout.strip())


@pytest.mark.parametrize("queues", [8, 16])
def test_cdx_startup_queues(tmp_path, queues):
    source = (ROOT / "cdx/devman.c").read_text()
    (tmp_path / "cdx_queues.inc").write_text(
        function(source, "cdx_drain_fq") + function(source, "cdx_destroy_fq")
        + function(source, "cdx_destroy_fq_list") + function(source, "create_fwd_tx_fqs"))
    binary = tmp_path / "cdx_queues"
    subprocess.run([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
        "-Werror=implicit-function-declaration", "-I", str(tmp_path),
        f"-DDPAA_FWD_TX_QUEUES={queues}",
        str(Path(__file__).with_name("cdx_queues.c")), "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True, timeout=30,
                   env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
                        "UBSAN_OPTIONS": "halt_on_error=1"})


def test_cdx_startup_eqcr(tmp_path):
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    high = kernel / "drivers/staging/fsl_qbman/qman_high.c"
    low = high.with_name("qman_low.h")
    if not high.exists():
        pytest.skip("build the ASK kernel or set ASK_KERNEL_SOURCE to its patched source")
    text = low.read_text()
    start = text.index("static inline u8 qm_eqcr_get_hw_fill(")
    end = text.index("\n}", start) + 3
    cached = text.index("static inline u8 qm_eqcr_get_fill(")
    cached_end = text.index("\n}", cached) + 3
    (tmp_path / "cdx_eqcr.inc").write_text(text[start:end] + "\n"
        + text[cached:cached_end] + "\n" + function(high.read_text(), "qman_eqcr_is_empty"))
    binary = tmp_path / "cdx_eqcr"
    subprocess.run([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("cdx_eqcr.c")), "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True, timeout=30)
