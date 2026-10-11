"""Exercise SDK scheme deletion and its ownership helpers with command faults."""

from ask_orch.process import run_process

from _host_sdk_scheme_delete import (function)
from _kernel_source import (kernel_source)
from pathlib import Path
import os
import shutil


def test_sdk_scheme_delete(tmp_path):
    kernel = kernel_source()
    sdk = kernel / "drivers/net/ethernet/freescale/sdk_fman"
    pcd = (sdk / "Peripherals/FM/Pcd/fm_pcd.c").read_text()
    kg = (sdk / "Peripherals/FM/Pcd/fm_kg.c").read_text()
    hc = (sdk / "Peripherals/FM/HC/hc.c").read_text()
    (tmp_path / "scheme_hc_layout.inc").write_text(
        hc[hc.index("#define DEFAULT_dataMemId"):hc.index("static t_Error FillBufPool")])
    production = "\n".join(function(pcd, name) for name in [
        "NetEnvLock", "NetEnvUnlock", "FmPcdIncNetEnvOwners", "FmPcdDecNetEnvOwners",
        "FmPcdLock", "FmPcdUnlock", "EnqueueLockToFreeLst", "FmPcdReleaseLock",
        "FmPcdLockTryLockAll", "FmPcdLockUnlockAll",
    ])
    production += "\n".join(function(kg, name) for name in [
        "KgHwLock", "KgHwUnlock", "KgSchemeFlagTryLock", "KgSchemeFlagUnlock",
        "WriteKgarWait", "UpdateRequiredActionFlag", "ValidateSchemeSw", "InvalidateSchemeSw",
        "FmPcdKgBuildWriteSchemeActionReg", "FmPcdKgGetSchemeId", "FM_PCD_KgSchemeDelete",
    ])
    production += "\n".join(function(hc, name) for name in [
        "GetBuf", "PutBuf", "FmHcPcdKgDeleteScheme",
    ])
    (tmp_path / "scheme_delete_production.inc").write_text(production)
    shutil.copyfile(Path(__file__).with_name("sdk_types_linux.h"), tmp_path / "types_linux.h")
    binary = tmp_path / "scheme_delete"
    command = [os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
               "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-fno-pie", "-no-pie",
               "-Werror=implicit-function-declaration", "-include", str(sdk / "ls1043_dflags.h"),
               "-I", str(tmp_path)]
    for inc in ["inc", "inc/etc", "inc/Peripherals", "inc/flib", "inc/integrations/LS1043",
                "Peripherals/FM/inc", "Peripherals/FM/Pcd"]:
        command.extend(["-I", str(sdk / inc)])
    command.extend([str(Path(__file__).with_name("sdk_scheme_delete.c")), "-o", str(binary)])
    run_process(command, check=True)
    run_process([str(binary)], check=True, timeout=30,
                   env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
                        "UBSAN_OPTIONS": "halt_on_error=1"})
