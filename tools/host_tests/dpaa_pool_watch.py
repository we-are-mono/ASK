"""The receive pool watch's verdicts, compiled from the kernel.

Every private DPAA port receives into one BMan pool, which only the CPU's
receive refilled, once its per-CPU count of what it took out ran low: buffers
the hardware lost left that count high, so a pool run dry stayed dry, every
port discarding every frame (A454). The driver's watch reads the pool once a
second beside the ports' out-of-buffer discards; its verdict on each reading
-- whether an episode begins, goes on, has spent its allowance or is over,
and how many buffers to put back -- is production code
(drivers/net/ethernet/freescale/sdk_dpaa/dpaa_eth_pool.c), driven here through
a dry pool, a transient, sparse and idle traffic, frames waiting for the CPU,
a pool the counts over-state, a loss as fast as the reseed, reseeds that fall
short, and an episode after another.
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


def definition(source, kind, name):
    """A struct or enum definition, through its closing brace."""
    match = re.search(rf"^{kind} {name} \{{.*?^\}};\n", source, re.M | re.S)
    assert match, f"{kind} {name}"
    return match.group(0)


def test_pool_watch_verdicts(tmp_path):
    """Every case in dpaa_pool_watch.c, against the driver's own code."""
    path = kernel_source() / SDK / "dpaa_eth_pool.c"
    assert path.exists(), f"{path}: the driver has no receive pool watch"
    source = path.read_text()
    defines = ""
    for name in ("DPA_POOL_DRY_READINGS", "DPA_POOL_BATCH"):
        found = re.search(rf"^#define {name}\s+(\d+)", source, re.M)
        assert found, name
        defines += f"#define {name} {found[1]}\n"
    (tmp_path / "dpaa_pool_watch_production.inc").write_text(
        defines
        + definition(source, "struct", "dpa_pool_episode")
        + definition(source, "enum", "dpa_pool_verdict")
        + "".join(function(source, name)
                  for name in ("dpa_pool_step", "dpa_pool_wants_queued", "dpa_pool_added")))
    binary = tmp_path / "dpaa_pool_watch"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra",
        "-Werror", "-Wno-unused-parameter", "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("dpaa_pool_watch.c")), "-o", str(binary),
    ], check=True)
    result = run_process([str(binary)], text=True, capture_output=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
    assert result.returncode == 0, result.stdout + result.stderr
    assert "pool watch: every case holds" in result.stdout, result.stdout
