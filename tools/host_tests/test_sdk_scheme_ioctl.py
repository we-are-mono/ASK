"""Run scheme ioctl/SDK validation, compat conversion and fmlib serialization."""
from pathlib import Path
import os
import shutil
import subprocess

import pytest

from test_sdk_scheme_delete import ROOT, function


def test_sdk_scheme_ioctl(tmp_path):
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    sdk = kernel / "drivers/net/ethernet/freescale/sdk_fman"
    fmlib = Path(os.environ.get("ASK_FMLIB_SOURCE", ROOT /
        "meta-ask/build/tmp/work/cortexa72-oe-linux/fmlib/git/git"))
    if not (sdk / "inc").exists() or not (fmlib / "src/fm_lib.c").exists():
        pytest.skip("build the ASK kernel/fmlib or set their source overrides")
    source = (sdk / "src/wrapper/lnxwrp_ioctls_fm.c").read_text()
    marker = "#if defined(CONFIG_COMPAT)\n        case FM_PCD_IOC_KG_SCHEME_SET_COMPAT:"
    start = source.index(marker)
    end = source.index("#if defined(CONFIG_COMPAT)\n        case FM_PCD_IOC_KG_SCHEME_GET_CNTR_COMPAT:", start)
    production = function(source, "fm_pcd_kg_scheme_set") if "static t_Handle fm_pcd_kg_scheme_set(" in source else ""
    production += "static t_Error scheme_ioctl(t_LnxWrpFmDev *p_LnxWrpFmDev, unsigned cmd, unsigned long arg, bool compat) { t_Error err = E_OK; switch (cmd) {\n"
    production += source[start:end] + "default: return E_INVALID_SELECTION; } return err; }\n"
    (tmp_path / "scheme_ioctl_production.inc").write_text(production)
    (tmp_path / "scheme_compat_production.inc").write_text(function(
        (sdk / "src/wrapper/lnxwrp_ioctls_fm_compat.c").read_text(), "compat_copy_fm_pcd_kg_scheme"))
    source = (sdk / "Peripherals/FM/Pcd/fm_kg.c").read_text()
    (tmp_path / "scheme_set_production.inc").write_text(function(source, "FM_PCD_KgSchemeSet"))
    source = (fmlib / "src/fm_lib.c").read_text()
    (tmp_path / "scheme_fmlib_production.inc").write_text(function(source, "FM_PCD_KgSchemeSet").replace(
        "FM_PCD_KgSchemeSet", "LibrarySchemeSet", 1))
    (tmp_path / "linux").mkdir()
    (tmp_path / "linux/compat.h").write_text(
        "#include <stdint.h>\ntypedef uint32_t compat_uptr_t;\n"
        "#define compat_ptr(p) ((void *)(uintptr_t)(p))\n")
    shutil.copyfile(Path(__file__).with_name("sdk_types_linux.h"), tmp_path / "types_linux.h")
    command = [os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
               "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-fno-pie", "-no-pie",
               "-Werror=implicit-function-declaration", "-include", str(sdk / "ls1043_dflags.h"),
               "-I", str(tmp_path)]
    for inc in ["inc", "inc/etc", "inc/Peripherals", "inc/flib", "inc/integrations/LS1043",
                "Peripherals/FM/inc", "Peripherals/FM/Pcd", "src/wrapper"]:
        command += ["-I", str(sdk / inc)]
    uapi = kernel / "include/uapi/linux/fmd"
    for inc in [uapi, uapi / "Peripherals", uapi / "integrations"]:
        command += ["-I", str(inc)]
    binary = tmp_path / "scheme_ioctl"
    subprocess.run(command + [str(Path(__file__).with_name("sdk_scheme_ioctl.c")), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=30,
                   env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
                        "UBSAN_OPTIONS": "halt_on_error=1"})
