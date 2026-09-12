"""Fault the actual SDK HC transport and Linux enqueue/confirmation wrapper."""
from pathlib import Path
import os
import shutil
import subprocess

import pytest

from test_sdk_scheme_delete import ROOT, function


def test_sdk_hc_transport(tmp_path):
    default = ROOT / "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", default))
    sdk = kernel / "drivers/net/ethernet/freescale/sdk_fman"
    if not (sdk / "inc").exists():
        pytest.skip("build the ASK kernel or set ASK_KERNEL_SOURCE")
    hc = (sdk / "Peripherals/FM/HC/hc.c").read_text()
    wrapper = (sdk / "src/wrapper/lnxwrp_fm_port.c").read_text()
    qman_path = kernel / "include/linux/fsl_qman.h"
    if not qman_path.exists():
        qman_path = default / "include/linux/fsl_qman.h"
    qman = qman_path.read_text()
    (tmp_path / "hc_layout.inc").write_text(
        hc[hc.index("#define DEFAULT_dataMemId"):hc.index("static t_Error FillBufPool")])
    (tmp_path / "qman_layout.inc").write_text(
        qman[qman.index("struct qm_fd {"):qman.index("#define QM_FD_DD_NULL")])
    (tmp_path / "hc_production.inc").write_text("\n".join(function(hc, name) for name in [
        "FillBufPool", "GetBuf", "PutBuf", "EnQFrm", "FmHcQuiesce", "FmHcFree",
        "FmHcSetFramesDataMemory", "FmHcTxConf", "FmHcPcdSync",
        "FmAllowHcUsage", "FmIsHcUsageAllowed",
    ]))
    (tmp_path / "hc_wrapper.inc").write_text("\n".join(function(wrapper, name) for name in [
        "hc_swap_frame", "qm_tx_conf_dqrr_cb", "QmEnqueueCB",
    ]))
    shutil.copyfile(Path(__file__).with_name("sdk_types_linux.h"), tmp_path / "types_linux.h")
    binary = tmp_path / "hc_transport"
    command = [os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
               "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-fno-pie", "-no-pie",
               "-Werror=implicit-function-declaration", "-include", str(sdk / "ls1043_dflags.h"),
               "-I", str(tmp_path)]
    for inc in ["inc", "inc/etc", "inc/Peripherals", "inc/flib", "inc/integrations/LS1043",
                "Peripherals/FM/inc", "Peripherals/FM/Pcd"]:
        command.extend(["-I", str(sdk / inc)])
    command.extend([str(Path(__file__).with_name("sdk_hc_transport.c")), "-o", str(binary)])
    subprocess.run(command, check=True)
    subprocess.run([str(binary)], check=True, timeout=30,
                   env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
                        "UBSAN_OPTIONS": "halt_on_error=1"})
