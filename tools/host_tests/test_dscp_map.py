"""Compile the DSCP egress-classification offload against a stub and drive it."""

import os
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def function(source: str, name: str) -> str:
    """Lift one function definition out of a production source file."""
    # The line has to begin with a return type, not with the ` * ' of a comment
    # continuation: a comment naming `foo()' above the definition of foo would
    # otherwise be lifted instead.
    match = re.search(rf"^(?:static\s+)?\w[\w \*]*\b{name}\(", source, re.M)
    assert match, name
    end = source.index("{", match.start()) + 1
    depth = 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


def test_dscp_map(tmp_path):
    compiler = os.environ.get("CC", "cc")
    assert shutil.which(compiler), f"C compiler required: {compiler}"
    source = (ROOT / "cdx/cdx_dscp.c").read_text()
    # In file order, which is also dependency order. cdx_dscp_setup_block and
    # the block callback are left out: they are plumbing over kernel helpers
    # the stub does not model.
    names = ["cdx_dscp_entry", "cdx_dscp_port_of", "cdx_dscp_qm_ctx",
             "cdx_dscp_find", "cdx_dscp_program", "cdx_dscp_publish",
             "cdx_dscp_enable", "cdx_dscp_disable", "cdx_dscp_parse",
             "cdx_dscp_action", "cdx_dscp_replace", "cdx_dscp_destroy",
             "cdx_dscp_tree_changed", "cdx_dscp_port_gone", "cdx_dscp_class",
             "cdx_dscp_flower"]
    (tmp_path / "dscp_production.inc").write_text(
        # The filter record and the per-port state are file-scope, so they are
        # sliced rather than lifted by name: what the map ends up holding
        # depends on the state as much as on the code.
        source[source.index("#define CDX_DSCP_MASK"):
               source.index("/* Indexed the way gQMCtx is")]
        + "\n".join(function(source, name) for name in names))
    binary = tmp_path / "dscp_map"
    subprocess.run([
        compiler, "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra", "-Werror",
        "-Wno-unused-parameter", "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-Werror=implicit-function-declaration",
        "-I", str(tmp_path),
        str(Path(__file__).with_name("dscp_map.c")), "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
