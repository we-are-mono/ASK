"""A DPAA netdev's open, compiled from the kernel.

An open that fails -- a port its owner holds fenced, a MAC that will not
start -- leaves NAPI off, the PHY let go and every port disabled, and answers
with an errno, so that the next open works once the port may start.
"""

from ask_orch.process import run_process

import os
from pathlib import Path
import re

from _kernel_source import kernel_source

FREESCALE = Path("drivers/net/ethernet/freescale")


def function(source, name):
    # The SDK's wrapper puts a space before the parameter list.
    match = re.search(r"^(?:static )?\w[^\n]*\b" + name + r"\s*\([^;]*?\)\s*\{", source, re.M)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


def macro(source, name):
    match = re.search(r"^#define " + name + r"\b(?:[^\n]*\\\n)*[^\n]*", source, re.M)
    assert match, name
    return match.group() + "\n"


def test_failed_open_unwinds(tmp_path):
    kernel = kernel_source() / FREESCALE
    errors = (kernel / "sdk_fman/inc/error_ext.h").read_text()
    wrapper = (kernel / "sdk_fman/src/wrapper/lnxwrp_fm.c").read_text()
    mac = (kernel / "sdk_dpaa/mac.h").read_text()
    common = (kernel / "sdk_dpaa/dpaa_eth_common.c").read_text()
    eth = (kernel / "sdk_dpaa/dpaa_eth.c").read_text()
    (tmp_path / "dpaa_open_production.inc").write_text(
        macro(errors, "ERROR_CODE") + macro(errors, "GET_ERROR_TYPE")
        + macro(mac, "for_each_port_device")
        + "".join(function(wrapper, name) for name in (
            "fm_port_enable", "fm_port_disable", "fm_port_enable_rx_l4csum",
            "fm_port_suspend", "fm_port_resume"))
        + function(common, "dpa_start") + function(eth, "dpa_eth_priv_start"))
    binary = tmp_path / "dpaa_open"
    # The kernel builds without -Wsign-compare, which the SDK's port loop
    # (an int against ARRAY_SIZE()) would otherwise trip.
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra",
        "-Werror", "-Wno-sign-compare", "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
        "-I", str(tmp_path),
        str(Path(__file__).with_name("dpaa_open.c")), "-o", str(binary),
    ], check=True)
    result = run_process([str(binary)], text=True, capture_output=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
    assert result.returncode == 0, result.stdout + result.stderr
    assert "DPAA failed opens unwind: passed" in result.stdout
