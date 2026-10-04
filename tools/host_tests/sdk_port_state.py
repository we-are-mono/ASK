"""Exercise the SDK port-state queries, fence and enable."""

from ask_orch.process import run_process
from pathlib import Path
import os
import shutil

import pytest

from _host_ehash_cumulative import (function as definition)
from _host_sdk_port_pcd import (ROOT, function)


def test_sdk_port_state(tmp_path):
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    sdk = kernel / "drivers/net/ethernet/freescale/sdk_fman"
    if not (sdk / "inc").exists():
        pytest.fail("build the ASK kernel or set ASK_KERNEL_SOURCE to its patched source")
    port = (sdk / "Peripherals/FM/Port/fm_port.c").read_text()
    flib = (sdk / "Peripherals/FM/Port/fman_port.c").read_text()
    production = function(port, "FM_PORT_GetEnabled")
    # Whether a port has finished stopping, as the registers say; whether it
    # hands frames to a PCD; and the fence its owner keeps it stopped by,
    # with the enable that honours it.
    production += (definition(flib, "fman_port_is_stopped") + definition(flib, "fman_port_enable")
                   + function(port, "FM_PORT_GetStopped") + function(port, "FM_PORT_IsPcdAttached")
                   + function(port, "FM_PORT_SetFenced") + function(port, "FM_PORT_Enable"))
    (tmp_path / "port_state.inc").write_text(production)
    shutil.copyfile(Path(__file__).with_name("sdk_types_linux.h"), tmp_path / "types_linux.h")
    command = [os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
               "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
               "-Werror=implicit-function-declaration", "-include", str(sdk / "ls1043_dflags.h"),
               "-I", str(tmp_path)]
    for inc in ["inc", "inc/etc", "inc/Peripherals", "inc/flib", "inc/integrations/LS1043",
                "Peripherals/FM/inc", "Peripherals/FM/Port"]:
        command += ["-I", str(sdk / inc)]
    binary = tmp_path / "port_state"
    run_process(command + [str(Path(__file__).with_name("sdk_port_state.c")), "-o", str(binary)], check=True)
    run_process([str(binary)], check=True, timeout=30,
                   env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
                        "UBSAN_OPTIONS": "halt_on_error=1"})
