"""A189: execute the kernel's complete multicast egress snapshot."""

from ask_orch import kernel_line
from ask_orch.process import run_process
import os
from pathlib import Path
import re

import pytest

from _host_qos_lifecycle import (function)

PATCH = kernel_line.patches() / "161-bridge-multicast-egress-snapshot.patch"


def snapshot_source():
    # This is an entirely new function. Read its actual patch payload, not a
    # build tree that may contain a previous recipe's implementation.
    source = PATCH.read_text().split("+++ b/net/bridge/br_multicast.c\n", 1)[1]
    added = "\n".join(line[1:] for line in source.splitlines()
                      if line.startswith("+") and not line.startswith("+++"))
    return (function(added, "br_multicast_list_ports")
            + function(added, "br_multicast_membership_interval"))


def snapshot_flags():
    """What the line's patch says the host is handed a group's frames for:
    6.18's adds an all-multicast bridge (BR_MCAST_TO_HOST_ALLMULTI)."""
    header = PATCH.read_text().split("+++ b/include/linux/if_bridge.h\n", 1)[1].split("\ndiff --git ", 1)[0]
    flags = re.findall(r"^\+(#define BR_MCAST_\w+\s+\(1U << \d+\))", header, re.M)
    assert flags
    return "\n".join(flags) + "\n"


@pytest.mark.parametrize("ipv6", [0, 1])
def test_bridge_mcast_snapshot(tmp_path, ipv6):
    (tmp_path / "bridge_mcast_flags.inc").write_text(snapshot_flags())
    (tmp_path / "bridge_mcast_snapshot.inc").write_text(snapshot_source())
    binary = tmp_path / "snapshot"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
        "-Wno-sign-compare", f"-DCONFIG_IPV6={ipv6}",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
        "-I", str(tmp_path),
        str(Path(__file__).with_name("bridge_mcast_snapshot.c")),
        "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })


def test_the_router_attribute_keeps_its_transitions():
    """PORT_MROUTER is one boolean for both families, and drivers count
    references by it: mlxsw takes one per MDB entry for every true it is sent
    and gives one back per false. A true sent while the port is already a
    router -- one family arriving while the other stands -- is a reference
    never returned. So the patch leaves the attribute's sends where the
    bridge has them, on the union's transitions, and callers re-read the
    snapshot instead."""
    diff = PATCH.read_text()
    changed = [line for line in diff.splitlines()
               if line[:1] in "+-" and not line.startswith(("+++", "---"))]
    assert not [line for line in changed if "br_port_mc_router_state_change" in line]
    assert not [line for line in changed if "br_multicast_rport_del_notify" in line]
