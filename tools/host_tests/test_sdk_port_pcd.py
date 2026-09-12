"""Run the SDK's port setup and classification-plan transactions on the host."""
from pathlib import Path
import os
import re
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]


def function(source, name):
    match = re.search(r"^(?:static )?(?:t_Error|t_Handle|void|uint32_t|int) " + name
                      + r"\([^;]*?\)\s*\{", source, re.M)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


@pytest.mark.parametrize("unit", ["port_pcd", "port_api", "port_ioctl", "port_ioctl_native",
                                  "port_free", "port_free_legacy", "kg_plan", "reassembly"])
def test_sdk_port_pcd(tmp_path, unit):
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    sdk = kernel / "drivers/net/ethernet/freescale/sdk_fman"
    if not (sdk / "inc").exists():
        pytest.skip("build the ASK kernel or set ASK_KERNEL_SOURCE to its patched source")
    if unit.startswith("port_ioctl"):
        source = (sdk / "src/wrapper/lnxwrp_ioctls_fm.c").read_text()
        uapi = kernel / "include/uapi/linux/fmd"
        production = function(source, "fm_reassembly_ioctl") + function(source, "fm_ioctls")
        (tmp_path / "linux").mkdir()
        (tmp_path / "linux/compat.h").write_text(
            "#include <stdint.h>\ntypedef uint32_t compat_uptr_t;\n"
            "#define compat_ptr(p) ((void *)(uintptr_t)(p))\n")
    elif unit == "reassembly":
        layout = (sdk / "inc/Peripherals/fm_ehash.h").read_text().split("static inline void display_mcast_member_tbl_entry", 1)[0]
        (tmp_path / "ehash_layout.h").write_text(layout + "\n#endif\n")
        production = function((sdk / "Peripherals/FM/Pcd/fm_manip.c").read_text(), "FM_PCD_ManipNodeSet")
        production += function((sdk / "Peripherals/FM/Pcd/fm_ehash.c").read_text(), "ExternalHashTableSet")
        production += function((sdk / "Peripherals/FM/Pcd/fm_cc.c").read_text(), "FM_PCD_HashTableSet")
    elif unit.startswith("port_free"):
        source = (sdk / "Peripherals/FM/Port/fm_port.c").read_text()
        production = "\n".join(function(source, name) for name in [
            "FmPortDriverParamFree", "FM_PORT_Init", "FM_PORT_Free",
            "FM_PORT_ConfigFifoDeqPipelineDepth",
        ])
    elif unit in ("port_pcd", "port_api"):
        source = (sdk / "Peripherals/FM/Port/fm_port.c").read_text()
        production = function(source, "GetPortSchemeBindParams")
        production += source[source.index("static t_Error DeletePcd(t_FmPort *p_FmPort);"):
                             source.index("static t_Error AttachPCD")]
        if unit == "port_api":
            production += function(source, "FmPortGetSetCcParams").replace(
                "t_Error FmPortGetSetCcParams(", "static t_Error RealGetSetCcParams(")
            production += "\n".join(function(source, name) for name in [
                "FmPortSetGprFunc", "FmPortSetFESupport", "FmPortDeleteFESupport",
                "FM_PORT_Free", "AttachPCD", "DetachPCD", "FM_PORT_AttachPCD", "FM_PORT_DetachPCD",
                "FM_PORT_ConfigureMuramPage", "DeletePortPcd", "FM_PORT_SetPCD", "FM_PORT_DeletePCD",
                "FM_PORT_PcdKgBindSchemes", "FM_PORT_PcdKgUnbindSchemes",
                "FM_PORT_PcdCcModifyTree",
            ])
    else:
        source = (sdk / "Peripherals/FM/Pcd/fm_kg.c").read_text()
        production = "\n".join(function(source, name) for name in [
            "UnbindPortToClsPlanGrp", "FmPcdKgBuildClsPlanGrp", "FmPcdKgDestroyClsPlanGrp", "FmPcdKgSetOrBindToClsPlanGrp",
            "FmPcdKgDeleteOrUnbindPortToClsPlanGrp",
        ])
    fixture = ("port_free" if unit.startswith("port_free") else
               "port_ioctl" if unit.startswith("port_ioctl") else unit)
    (tmp_path / f"{fixture}_production.inc").write_text(production)
    shutil.copyfile(Path(__file__).with_name("sdk_types_linux.h"), tmp_path / "types_linux.h")
    binary = tmp_path / unit
    command = [os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
               "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-fno-pie", "-no-pie",
               "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections",
               "-Werror=implicit-function-declaration", "-include", str(sdk / "ls1043_dflags.h"),
               "-I", str(tmp_path)]
    for inc in ["inc", "inc/etc", "inc/Peripherals", "inc/flib", "inc/integrations/LS1043",
                "Peripherals/FM/inc", "Peripherals/FM/Port", "Peripherals/FM/Pcd"]:
        command.extend(["-I", str(sdk / inc)])
    if unit.startswith("port_ioctl"):
        for inc in [uapi, uapi / "Peripherals", uapi / "integrations", sdk / "src/wrapper"]:
            command.extend(["-I", str(inc)])
    if unit == "port_free_legacy":
        command.append("-DTEST_LEGACY_DEQ")
    if unit == "port_ioctl_native":
        command.append("-DTEST_NO_COMPAT")
    command.extend([str(Path(__file__).with_name(f"sdk_{fixture}.c")), "-o", str(binary)])
    subprocess.run(command, check=True)
    subprocess.run([str(binary)], check=True, timeout=30,
                   env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
                        "UBSAN_OPTIONS": "halt_on_error=1"})
