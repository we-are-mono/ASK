"""The Wi-Fi VAP admission contract, compiled rather than restated.

Step 5 rests on an asymmetry -- a VAP may be a flow's egress and may never be
its ingress -- expressed as two predicates that share a body. Compiling both
from the backend is what keeps the narrow one from quietly widening along with
the wide one, which no assertion about behaviour on the rig would catch.
"""

from ask_orch.process import run_process

import os
from pathlib import Path

from _host_qos_lifecycle import (function)

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "cdx/cdx_flowtable_backend.c"


def test_wifi_admission(tmp_path):
    source = SOURCE.read_text()
    (tmp_path / "wifi_admission_production.inc").write_text(
        "\n".join(function(source, name) for name in [
            "cdx_ft_onif_type",
            "cdx_ft_port_supported",
            "cdx_ft_egress_supported",
        ]))
    binary = tmp_path / "wifi_admission"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
        "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("wifi_admission.c")), "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })


def test_hardware_path_agrees_with_admission():
    """cdx_ft_hw_add() asks the same question again, on the onif it already
    holds rather than on a netdev. That duplication is deliberate and
    documented, and it is also how the third gate stayed shut after the first
    was opened -- so assert the two sets are still the same set."""
    hw = (ROOT / "cdx/cdx_flowtable_hw.c").read_text()
    egress = function(hw, "ft_hw_egress_onif")
    # The whole body, not two substrings: a third accepted type, or one of
    # these two dropped, would still contain both names.
    body = " ".join(egress.split("{", 1)[1].rsplit("}", 1)[0].split())
    assert body == ("return type == (IF_TYPE_ETHERNET | IF_TYPE_PHYSICAL) || "
                    "type == (IF_TYPE_WLAN | IF_TYPE_PHYSICAL);"), body
    # The ingress beside it must not have been widened by the same edit.
    assert "in->itf->type != (IF_TYPE_ETHERNET | IF_TYPE_PHYSICAL)" in hw
