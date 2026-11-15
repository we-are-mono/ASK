"""The bound of a DPAA port's queues to the CPU, compiled from the kernel.

A frame waiting for the CPU holds a buffer of the pool every private port
receives into, so each port's ingress congestion groups refuse FMan's enqueue
past a bound: a share of the port's own part of that pool, so that one port's
flood leaves the others theirs. The pool's count is the running total of the
ports probed so far, raised for each port after the first only once that
port's groups are made: a bound taken from it grows with the port's place in
the probe order (a half, a half, one, one and a half, two shares at the
default ingress_quarters), not with the port.
"""

import os
from pathlib import Path
import re

from ask_orch.process import run_process
from _kernel_source import kernel_source

SDK = Path("drivers/net/ethernet/freescale/sdk_dpaa")


def function(source, name):
    # The return type is on the line of the name or alone on the line above;
    # the line has to begin with a word, so a comment naming `foo()' does not
    # match and run on to the next definition.
    match = re.search(r"^(?:\w[\w ]*\*?[ \t]*\n)?(?:\w[^\n;]*?[\s*])?" + name
                      + r"\([^;]*?\)\s*\{", source, re.M)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


def test_each_port_bounds_its_queues_by_its_own_share(tmp_path):
    """Five ports probe in turn, at every ingress_quarters and CPU count;
    each port's groups are bounded at its own share, whatever the shared
    pool's count when it probes."""
    eth = (kernel_source() / SDK / "dpaa_eth.c").read_text()
    probe = function(eth, "dpaa_eth_priv_probe")
    entry = re.search(r"\b(dpaa_eth_priv_ingress_\w+)\(priv\);", probe)
    assert entry, "the probe's ingress congestion group setup"
    # What the pool's count is when a port makes its groups: the first port's
    # share, as the pool is made with, and each later port's share once its
    # probe raises the count, before its groups are made or after.
    assert "dpa_bp->target_count = CONFIG_FSL_DPAA_ETH_MAX_BUF_COUNT;" in function(
        eth, "dpa_priv_bp_probe")
    raise_at = probe.find("dpa_bp->config_count += CONFIG_FSL_DPAA_ETH_MAX_BUF_COUNT;")
    # Every ingress group helper, in the order the driver defines them.
    helpers = re.findall(r"^static int (dpaa_eth_priv_ingress_\w+)\(", eth, re.M)
    assert entry[1] in helpers, helpers
    (tmp_path / "dpaa_ingress_bound_production.inc").write_text(
        f"#define INGRESS_INIT {entry[1]}\n"
        f"#define POOL_RAISED {int(raise_at >= 0)}\n"
        f"#define POOL_RAISED_BEFORE_INGRESS {int(0 <= raise_at < probe.index(entry[0]))}\n"
        + "".join(function(eth, name) for name in helpers))
    binary = tmp_path / "dpaa_ingress_bound"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra",
        "-Werror", "-Wno-unused-parameter", "-fsanitize=address,undefined", "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("dpaa_ingress_bound.c")), "-o", str(binary),
    ], check=True)
    result = run_process([str(binary)], text=True, capture_output=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
    assert result.returncode == 0, result.stdout + result.stderr
    assert "bounded by its own share" in result.stdout
