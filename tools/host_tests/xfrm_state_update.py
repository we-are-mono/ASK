"""Which in-place xfrm state updates the kernel lets through for a
packet-offloaded SA, compiled from the patched kernel.

An update reaches no driver. A packet-offloaded SA's encapsulation ports are
in its hardware SA, and its output mark chose the route that addressed it, so
an update may keep them but not change them.
"""

from ask_orch.process import run_process

import os
from pathlib import Path

from _host_qos_lifecycle import (function)

ROOT = Path(__file__).resolve().parents[2]


def test_xfrm_state_update(tmp_path):
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    source = (kernel / "net/xfrm/xfrm_state.c").read_text()
    (tmp_path / "xfrm_state_update.inc").write_text(function(source, "xfrm_state_update_offload_ok"))
    binary = tmp_path / "xfrm_state_update"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
        "-I", str(tmp_path), str(Path(__file__).with_name("xfrm_state_update.c")),
        "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
