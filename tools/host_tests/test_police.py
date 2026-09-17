"""Compile the ingress-police offload against a stub kernel and exercise it."""

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def function(source: str, name: str) -> str:
    """Lift one function definition out of a production source file."""
    match = re.search(rf"^(?:static\s+)?[\w \*]+\b{name}\(", source, re.M)
    assert match, name
    end = source.index("{", match.start()) + 1
    depth = 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


def test_police_offload(tmp_path):
    compiler = os.environ.get("CC", "cc")
    assert shutil.which(compiler), f"C compiler required: {compiler}"
    source = (ROOT / "cdx/cdx_police.c").read_text()
    # In file order, which is also dependency order. cdx_police_setup_block is
    # left out: it is block plumbing over kernel helpers the stub does not
    # model, and nothing it does is a decision worth pinning here.
    names = ["cdx_police_bytes_to_kbits", "cdx_police_check",
             "cdx_police_replace", "cdx_police_matchall"]
    (tmp_path / "police_production.inc").write_text(
        "\n".join(function(source, name) for name in names))
    binary = tmp_path / "police"
    subprocess.run([
        compiler, "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra", "-Werror",
        "-Wno-unused-parameter", "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("police.c")), "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
