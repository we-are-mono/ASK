"""Compile the CEETM egress-FQ lookup against a stub and exercise both readings."""

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


def test_ceetm_egress_fq(tmp_path):
    compiler = os.environ.get("CC", "cc")
    assert shutil.which(compiler), f"C compiler required: {compiler}"
    source = (ROOT / "cdx/cdx_ceetm_app.c").read_text()
    names = ["ceetm_resolve_channel", "ceetm_get_egressfq", "ceetm_egress_fqid"]
    (tmp_path / "egress_fq_production.inc").write_text(
        "\n".join(function(source, name) for name in names))
    binary = tmp_path / "ceetm_egress_fq"
    subprocess.run([
        compiler, "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra", "-Werror",
        "-Wno-unused-parameter", "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-Werror=implicit-function-declaration",
        "-I", str(tmp_path),
        str(Path(__file__).with_name("ceetm_egress_fq.c")), "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
