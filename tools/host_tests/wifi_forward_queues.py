"""The Wi-Fi VAPs' forwarding queues, compiled with the group that bounds them.

No rig test sends a flow out of a VAP, so the queues and their group are
compiled and run here instead.
"""

from ask_orch.process import run_process

import os
import re
from pathlib import Path

from _host_qos_lifecycle import (function)

ROOT = Path(__file__).resolve().parents[2]


def defines(path, *names):
    text = (ROOT / path).read_text()
    lines = [line for line in text.splitlines() if re.match(rf"#define\s+({'|'.join(names)})\s", line)]
    assert len(lines) == len(names), (path, names, lines)
    return "".join(line + "\n" for line in lines)


def test_wifi_forward_queues(tmp_path):
    source = (ROOT / "cdx/dpa_wifi.c").read_text()
    (tmp_path / "wifi_forward_queues_limits.inc").write_text(
        defines("cdx/dpa_ipsec.h", "IPSEC_BUFCOUNT", "IPSEC_EXCEPTION_FRAMES", "IPSEC_EGRESS_FRAMES")
        + defines("cdx/dpa_wifi.h", "CDX_VWD_FWD_FQ_MAX")
        + defines("cdx/dpa_wifi.c", "VWD_FWD_FRAMES"))
    (tmp_path / "wifi_forward_queues_production.inc").write_text(
        "\n".join(function(source, name) for name in [
            "vwd_fwd_cgr_init",
            "vwd_fwd_cgr_exit",
            "create_vap_fwd_from_fman_fqs",
            "release_vap_fqs",
        ]))
    binary = tmp_path / "wifi_forward_queues"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
        "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("wifi_forward_queues.c")), "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })


def test_group_outlives_every_vap_queue():
    """The group is there before a VAP can open and goes only after every
    VAP's queues have: QMan leaks a group a live queue still names."""
    source = (ROOT / "cdx/dpa_wifi.c").read_text()
    init = function(source, "dpaa_vwd_init")
    assert init.index("vwd_fwd_cgr_init(priv)") < init.index("dpaa_vwd_up(priv)")
    unwind = init[init.index("err_device:"):]
    assert unwind.index("vwd_fwd_cgr_exit(priv)") < unwind.index("vwd_free_ohport(priv)")
    exit_ = function(source, "dpaa_vwd_exit")
    assert exit_.index("release_vap_fqs(") < exit_.index("vwd_fwd_cgr_exit(priv)")
