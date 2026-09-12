"""Exercise FM resource allocation with the actual SDK and register helpers."""
from pathlib import Path
import os
import re
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]


def function(source, name):
    match = re.search(r"^(?:static )?(?:t_Error|void|uint(?:8|16|32)_t) " + name
                      + r"\([^;]*?\)\s*\{", source, re.M)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


@pytest.mark.parametrize("legacy", [False, True], ids=["ls104x", "legacy"])
def test_sdk_port_resources(tmp_path, legacy):
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    sdk = kernel / "drivers/net/ethernet/freescale/sdk_fman"
    if not (sdk / "inc").exists():
        pytest.skip("build the ASK kernel or set ASK_KERNEL_SOURCE")
    source = (sdk / "Peripherals/FM/fm.c").read_text()
    marker = "/* All shared resource accounting is protected by the FM lock."
    production = source[source.index(marker):source.index("t_Error FmGetSetPortParams(")] if marker in source else ""
    production += "\n".join(function(source, name) for name in [
        "FmGetSetPortParams", "FmFreePortParams", "FmSetNumOfTasks",
        "FmSetSizeOfFifo", "FmSetNumOfOpenDmas",
    ])
    port = (sdk / "Peripherals/FM/Port/fm_port.c").read_text()
    production += function(port, "VerifySizeOfFifo")
    production += function(port, "FM_PORT_SetSizeOfFifo")
    (tmp_path / "resources_production.inc").write_text(production)
    flib = (sdk / "Peripherals/FM/fman.c").read_text()
    (tmp_path / "resources_flib.inc").write_text("\n".join(function(flib, name) for name in [
        "fman_get_num_of_tasks", "fman_get_num_extra_tasks", "fman_set_num_of_tasks",
        "fman_get_size_of_fifo", "fman_get_size_of_extra_fifo", "fman_set_size_of_fifo",
        "fman_get_num_of_dmas", "fman_get_num_extra_dmas", "fman_set_num_of_open_dmas",
        "fman_get_qmi_enq_th", "fman_get_qmi_deq_th", "fman_set_qmi_enq_th", "fman_set_qmi_deq_th",
        "fman_qmi_disable_dispatch_limit", "fman_set_order_restoration_per_port", "fman_set_liodn_per_port",
    ]))
    shutil.copyfile(Path(__file__).with_name("sdk_types_linux.h"), tmp_path / "types_linux.h")
    binary = tmp_path / "resources"
    command = [os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
               "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-fno-pie", "-no-pie",
               "-Werror=implicit-function-declaration", "-include", str(sdk / "ls1043_dflags.h"),
               "-I", str(tmp_path)]
    for inc in ["inc", "inc/etc", "inc/Peripherals", "inc/flib", "inc/integrations/LS1043",
                "Peripherals/FM", "Peripherals/FM/inc", "Peripherals/FM/Port"]:
        command.extend(["-I", str(sdk / inc)])
    if legacy:
        command.extend(["-DFM_HAS_TOTAL_DMAS", "-DFM_LOW_END_RESTRICTION", "-DTEST_LEGACY"])
    command.extend([str(Path(__file__).with_name("sdk_port_resources.c")), "-o", str(binary)])
    subprocess.run(command, check=True)
    subprocess.run([str(binary)], check=True, timeout=30,
                   env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
                        "UBSAN_OPTIONS": "halt_on_error=1"})
