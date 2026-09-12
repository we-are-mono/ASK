"""Run the SDK's port setup and classification-plan transactions on the host."""
from pathlib import Path
import os
import re
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]


def function(source, name):
    match = re.search(r"^(?:static )?(?:t_Error|void|uint32_t) " + name
                      + r"\([^;]*?\)\s*\{", source, re.M)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


@pytest.mark.parametrize("unit", ["port_pcd", "kg_plan"])
def test_sdk_port_pcd(tmp_path, unit):
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    sdk = kernel / "drivers/net/ethernet/freescale/sdk_fman"
    if not (sdk / "inc").exists():
        pytest.skip("build the ASK kernel or set ASK_KERNEL_SOURCE to its patched source")
    if unit == "port_pcd":
        source = (sdk / "Peripherals/FM/Port/fm_port.c").read_text()
        production = function(source, "GetPortSchemeBindParams")
        production += source[source.index("struct fm_port_pcd_bindings"):
                             source.index("static t_Error AttachPCD")]
    else:
        source = (sdk / "Peripherals/FM/Pcd/fm_kg.c").read_text()
        production = "\n".join(function(source, name) for name in [
            "FmPcdKgBuildClsPlanGrp", "FmPcdKgDestroyClsPlanGrp", "FmPcdKgSetOrBindToClsPlanGrp",
        ])
    (tmp_path / f"{unit}_production.inc").write_text(production)
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
    command.extend([str(Path(__file__).with_name(f"sdk_{unit}.c")), "-o", str(binary)])
    subprocess.run(command, check=True)
    subprocess.run([str(binary)], check=True, timeout=30,
                   env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
                        "UBSAN_OPTIONS": "halt_on_error=1"})
