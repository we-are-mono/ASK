"""A189: execute the kernel's complete multicast egress snapshot."""
import os
from pathlib import Path
import subprocess

import pytest

from test_qos_lifecycle import function

ROOT = Path(__file__).resolve().parents[2]
PATCH = ROOT / "patches/kernel/161-bridge-multicast-egress-snapshot.patch"


def snapshot_source():
    # This is an entirely new function. Read its actual patch payload, not a
    # build tree that may contain a previous recipe's implementation.
    added = "\n".join(line[1:] for line in PATCH.read_text().splitlines()
                      if line.startswith("+") and not line.startswith("+++"))
    return function(added, "br_multicast_list_ports")


@pytest.mark.parametrize("ipv6", [0, 1])
def test_bridge_mcast_snapshot(tmp_path, ipv6):
    (tmp_path / "bridge_mcast_snapshot.inc").write_text(snapshot_source())
    binary = tmp_path / "snapshot"
    subprocess.run([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
        "-Wno-sign-compare", f"-DCONFIG_IPV6={ipv6}",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
        "-I", str(tmp_path),
        str(Path(__file__).with_name("bridge_mcast_snapshot.c")),
        "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
