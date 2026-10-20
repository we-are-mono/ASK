"""Compile the ingress-police offload over the policer layer it programs, against
a stub FMan, and exercise it."""

from ask_orch.process import run_process

import os
import shutil
from pathlib import Path

import pytest

from _host_policer import ROOT, after_includes, policer_layer


# The walk through the verbs, then the cases that stand apart from it: each a
# failure of the hardware, run in a process of its own so that one assertion
# failing does not hide the next case.
CASES = ["verbs", "matchall_deferred", "matchall_destroy_deferred",
         "matchall_refused_destroy", "flower_destroy_deferred", "counters_unread",
         "channel_shut", "locking"]


@pytest.fixture(scope="module")
def binary(tmp_path_factory):
    compiler = os.environ.get("CC", "cc")
    assert shutil.which(compiler), f"C compiler required: {compiler}"
    tmp_path = tmp_path_factory.mktemp("police")
    policer_layer(tmp_path)
    (tmp_path / "police_production.inc").write_text(
        after_includes((ROOT / "cdx/cdx_police.c").read_text()))
    binary = tmp_path / "police"
    run_process([
        compiler, "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra", "-Werror",
        "-Wno-unused-parameter", "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-I", str(tmp_path), "-I", str(ROOT / "cdx"),
        "-I", str(Path(__file__).parent),
        str(Path(__file__).with_name("police.c")), "-o", str(binary),
    ], check=True)
    return binary


@pytest.mark.parametrize("case", CASES)
def test_offload(binary, case):
    result = run_process([str(binary), case], text=True, capture_output=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
    assert result.returncode == 0, result.stdout + result.stderr
    assert f"police {case}: passed" in result.stdout
