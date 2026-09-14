"""Check the production tunnel-decap command's bytes and debug decoding."""

import os
from pathlib import Path
import re
import subprocess

import pytest

from test_qos_lifecycle import function

ROOT = Path(__file__).resolve().parents[2]
HEADER = "drivers/net/ethernet/freescale/sdk_fman/inc/Peripherals/fm_ehash.h"


@pytest.mark.parametrize("ifstats", [False, True], ids=["no-stats", "stats"])
def test_tunnel_remove_hm(tmp_path, ifstats):
    # Test the shipped patch, without depending on a previously built kernel.
    subprocess.run([
        "git", "apply", f"--include={HEADER}",
        str(ROOT / "patches/kernel/010-ask-fman-dpaa-ehash.patch"),
    ], cwd=tmp_path, check=True)
    header = (tmp_path / HEADER).read_text()
    struct = re.search(
        r"struct en_ehash_remove_first_ip_hdr \{.*?\}__attribute__ \(\(packed\)\);",
        header, re.S,
    ).group()
    constant = re.search(r"^#define COPY_DSCP_OUTER_INNER .*", header, re.M).group()
    display = header[header.index("static inline void *display_strip_first_iphdr("):]
    display = display[:display.index("\n}") + 3]
    (tmp_path / "tunnel_remove.inc").write_text(
        constant + "\n" + struct + "\n"
        + function((ROOT / "cdx/cdx_ehash.c").read_text(), "create_tunnel_remove_hm")
        + display
    )
    binary = tmp_path / "tunnel_hm"
    subprocess.run([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-I", str(tmp_path),
        *(["-DINCLUDE_TUNNEL_IFSTATS=1"] if ifstats else []),
        str(Path(__file__).with_name("tunnel_hm.c")), "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
