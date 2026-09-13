"""Exercise port-state queries and enable errors through native/compat ioctls."""
from pathlib import Path
import os
import shutil
import subprocess

import pytest

from test_sdk_port_pcd import ROOT, function


@pytest.mark.parametrize("compat", [False, True])
def test_sdk_port_state(tmp_path, compat):
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    sdk = kernel / "drivers/net/ethernet/freescale/sdk_fman"
    fmlib = Path(os.environ.get("ASK_FMLIB_SOURCE", ROOT /
        "meta-ask/build/tmp/work/cortexa72-oe-linux/fmlib/git/git"))
    if not (sdk / "inc").exists() or not (fmlib / "src/fm_lib.c").exists():
        pytest.fail("build the ASK kernel/fmlib or set their source overrides")
    port = (sdk / "Peripherals/FM/Port/fm_port.c").read_text()
    wrapper = (sdk / "src/wrapper/lnxwrp_ioctls_fm.c").read_text()
    start = wrapper.index("        case FM_PORT_IOC_DISABLE:")
    end = wrapper.index("        case FM_PORT_IOC_SET_ERRORS_ROUTE:", start)
    production = function(port, "FM_PORT_GetEnabled")
    production += "static t_Error port_ioctl(t_LnxWrpFmPortDev *p_LnxWrpFmPortDev, unsigned cmd, unsigned long arg, bool compat) { t_Error err = E_OK; switch (cmd) {\n"
    production += wrapper[start:end] + "default: return E_INVALID_SELECTION; } }\n"
    (tmp_path / "port_state.inc").write_text(production)
    (tmp_path / "port_state_fmlib.inc").write_text(function(
        (fmlib / "src/fm_lib.c").read_text(), "FM_PORT_GetEnabled").replace(
            "FM_PORT_GetEnabled", "LibraryGetEnabled", 1))
    shutil.copyfile(Path(__file__).with_name("sdk_types_linux.h"), tmp_path / "types_linux.h")
    (tmp_path / "linux").mkdir()
    (tmp_path / "linux/compat.h").write_text(
        "#include <stdint.h>\ntypedef uint32_t compat_uptr_t;\n"
        "#define compat_ptr(p) ((void *)(uintptr_t)(p))\n")
    command = [os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
               "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
               "-Werror=implicit-function-declaration", "-include", str(sdk / "ls1043_dflags.h"),
               "-I", str(tmp_path)]
    if compat:
        command += ["-DCONFIG_COMPAT", "-DFM_COMPAT"]
    for inc in ["inc", "inc/etc", "inc/Peripherals", "inc/flib", "inc/integrations/LS1043",
                "Peripherals/FM/inc", "Peripherals/FM/Port"]:
        command += ["-I", str(sdk / inc)]
    uapi = kernel / "include/uapi/linux/fmd"
    for inc in [uapi, uapi / "Peripherals", uapi / "integrations"]:
        command += ["-I", str(inc)]
    binary = tmp_path / "port_state"
    subprocess.run(command + [str(Path(__file__).with_name("sdk_port_state.c")), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=30,
                   env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
                        "UBSAN_OPTIONS": "halt_on_error=1"})
