"""Run actual scheme construction, ownership and HC transport with faults."""
from pathlib import Path
import os
import shutil
import subprocess

import pytest

from test_sdk_scheme_delete import ROOT, function


def test_sdk_scheme_set(tmp_path):
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    sdk = kernel / "drivers/net/ethernet/freescale/sdk_fman"
    if not (sdk / "inc").exists():
        pytest.skip("build the ASK kernel or set ASK_KERNEL_SOURCE")
    pcd = (sdk / "Peripherals/FM/Pcd/fm_pcd.c").read_text()
    kg = (sdk / "Peripherals/FM/Pcd/fm_kg.c").read_text()
    hc = (sdk / "Peripherals/FM/HC/hc.c").read_text()
    (tmp_path / "scheme_hc_layout.inc").write_text(
        hc[hc.index("#define DEFAULT_dataMemId"):hc.index("static t_Error FillBufPool")])
    production = "\n".join(function(pcd, name) for name in [
        "NetEnvLock", "NetEnvUnlock", "FmPcdIncNetEnvOwners", "FmPcdDecNetEnvOwners",
        "FmPcdGetNetEnvId", "PcdGetUnitsVector", "FmPcdLock", "FmPcdUnlock",
        "EnqueueLockToFreeLst", "DequeueLockFromFreeLst", "EnqueueLockToAcquiredLst",
        "FillFreeLocksLst", "ReleaseFreeLocksLst", "FmPcdAcquireLock", "FmPcdReleaseLock",
        "FmPcdLockTryLockAll", "FmPcdLockUnlockAll",
    ])
    production += "\n".join(function(hc, name) for name in [
        "GetBuf", "PutBuf", "EnQFrm", "FmHcTxConf", "FmHcPcdKgSetScheme",
        "FmHcPcdKgDeleteScheme", "FmAllowHcUsage", "FmIsHcUsageAllowed",
    ])
    production += kg[kg.index("static e_FmPcdKgExtractDfltSelect GetGenericSwDefault"):
                     kg.index("static void IncSchemeOwners")]
    production += "\n".join(function(kg, name) for name in [
        "KgHwLock", "KgHwUnlock", "KgSchemeFlagTryLock", "KgSchemeFlagUnlock",
        "WriteKgarWait", "UpdateRequiredActionFlag", "ValidateSchemeSw", "InvalidateSchemeSw",
        "BuildSchemeRegs", "FmPcdKgIsSchemeValidSw", "FmPcdKgGetSchemeId",
        "FmPcdKgBuildWriteSchemeActionReg", "FM_PCD_KgSchemeSet", "FM_PCD_KgSchemeDelete",
    ])
    (tmp_path / "scheme_set_production.inc").write_text(production)
    shutil.copyfile(Path(__file__).with_name("sdk_types_linux.h"), tmp_path / "types_linux.h")
    binary = tmp_path / "scheme_set"
    command = [os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
               "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-fno-pie", "-no-pie",
               "-Werror=implicit-function-declaration", "-include", str(sdk / "ls1043_dflags.h"),
               "-I", str(tmp_path)]
    for inc in ["inc", "inc/etc", "inc/Peripherals", "inc/flib", "inc/integrations/LS1043",
                "Peripherals/FM/inc", "Peripherals/FM/Pcd"]:
        command.extend(["-I", str(sdk / inc)])
    command.extend([str(Path(__file__).with_name("sdk_scheme_set.c")), "-o", str(binary)])
    subprocess.run(command, check=True)
    subprocess.run([str(binary)], check=True, timeout=30,
                   env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
                        "UBSAN_OPTIONS": "halt_on_error=1"})
