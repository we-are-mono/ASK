"""Exercise SDK scheme deletion and its ownership helpers with command faults."""
from pathlib import Path
import os
import re
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]


def function(source, name):
    match = re.search(r"^(?:static\s+)?(?:__inline__\s+)?"
                      r"(?:t_Error|t_Handle|t_HcFrame\s*\*|void|bool|uint(?:8|32)_t|"
                      r"enum qman_cb_dqrr_result)\s*"
                      + name + r"\s*\([^;]*?\)\s*\{", source, re.M)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


def test_sdk_scheme_delete(tmp_path):
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
    subprocess.run(command, check=True)
    subprocess.run([str(binary)], check=True, timeout=30,
                   env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
                        "UBSAN_OPTIONS": "halt_on_error=1"})
