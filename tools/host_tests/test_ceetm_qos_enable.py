"""Compile the production QoS enable/disable pair and cycle it.

Run without the board fixtures:
    pytest tools/host_tests/test_ceetm_qos_enable.py
"""

from pathlib import Path
import os
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def function(source, name):
    match = re.search(r"^(?:static )?[^\n]+\b" + name + r"\([^;]*?\)\s*\{", source, re.M)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


def test_ceetm_qos_enable_is_symmetric(tmp_path):
    compiler = os.environ.get("CC", "cc")
    assert shutil.which(compiler), f"C compiler required: {compiler}"
    source = (ROOT / "cdx/cdx_ceetm_app.c").read_text()
    names = ["ceetm_program_port_shaper", "ceetm_program_channel_shaper",
             "ceetm_setup_lni", "ceetm_enable_or_disable_qos"]
    (tmp_path / "qos_enable_production.inc").write_text(
        "\n".join(function(source, name) for name in names))
    binary = tmp_path / "ceetm_qos_enable"
    subprocess.run([
        compiler, "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra", "-Werror",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
        "-Werror=implicit-function-declaration", "-I", str(tmp_path),
        str(Path(__file__).with_name("ceetm_qos_enable.c")), "-o", str(binary),
    ], check=True)
    result = subprocess.run([str(binary)], text=True, capture_output=True, timeout=30,
                            env={**os.environ,
                                 "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
                                 "UBSAN_OPTIONS": "halt_on_error=1"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert "shaper symmetric" in result.stdout
    print(result.stdout.strip())
