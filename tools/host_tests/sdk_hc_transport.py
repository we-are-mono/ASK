"""Fault the actual SDK HC transport and Linux enqueue/confirmation wrapper."""

from ask_orch.process import run_process
from pathlib import Path
import os
import shutil

from _host_sdk_scheme_delete import (function)
from _kernel_source import (kernel_source)


def test_sdk_hc_transport(tmp_path):
    kernel = kernel_source()
    sdk = kernel / "drivers/net/ethernet/freescale/sdk_fman"
    hc = (sdk / "Peripherals/FM/HC/hc.c").read_text()
    wrapper = (sdk / "src/wrapper/lnxwrp_fm_port.c").read_text()
    qman = (kernel / "include/linux/fsl_qman.h").read_text()
    (tmp_path / "hc_layout.inc").write_text(
        hc[hc.index("#define DEFAULT_dataMemId"):hc.index("static t_Error FillBufPool")])
    (tmp_path / "qman_layout.inc").write_text(
        qman[qman.index("struct qm_fd {"):qman.index("#define QM_FD_DD_NULL")])
    (tmp_path / "hc_production.inc").write_text("\n".join(function(hc, name) for name in [
        "FillBufPool", "GetBuf", "PutBuf", "EnQFrm", "FmHcQuiesce", "FmHcFree",
        "FmHcSetFramesDataMemory", "FmHcTxConf", "FmHcPcdSync", "FmHcPcdCcDoDynamicChange",
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
    run_process(command, check=True)
    run_process([str(binary)], check=True, timeout=30,
                   env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
                        "UBSAN_OPTIONS": "halt_on_error=1"})
