"""Compile the production WRED conversion and check the curve it encodes.

Run without the board fixtures:
    pytest tools/host_tests/test_ceetm_wred.py
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


def test_ceetm_wred_curve(tmp_path):
    compiler = os.environ.get("CC", "cc")
    assert shutil.which(compiler), f"C compiler required: {compiler}"
    source = (ROOT / "cdx/cdx_ceetm_app.c").read_text()
    names = ["ceetm_wred_maxth", "ceetm_wred_slope",
             "ceetm_set_class_wred", "ceetm_clear_class_wred"]
    (tmp_path / "wred_production.inc").write_text(
        "#define CEETM_WRED_MAXP_UNITS\t256u\n"
        + "\n".join(function(source, name) for name in names))
    binary = tmp_path / "ceetm_wred"
    subprocess.run([
        compiler, "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra", "-Werror",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
        "-Werror=implicit-function-declaration", "-I", str(tmp_path),
        str(Path(__file__).with_name("ceetm_wred.c")), "-o", str(binary), "-lm",
    ], check=True)
    result = subprocess.run([str(binary)], text=True, capture_output=True, timeout=30,
                            env={**os.environ,
                                 "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
                                 "UBSAN_OPTIONS": "halt_on_error=1"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert "implied minimum" in result.stdout
    print(result.stdout.strip())


def test_ceetm_wred_units_are_stated(tmp_path):
    """The one number the SDK headers give no units for must stay written down.

    MaxP = 4 * (Pn + 1) is a fraction of something the headers never say, and
    the whole curve hangs off which. It is calibrated on hardware, so the
    constant and the reasoning have to travel together.
    """
    source = (ROOT / "cdx/cdx_ceetm_app.c").read_text()
    assert "#define CEETM_WRED_MAXP_UNITS\t256u" in source
    # Flatten the comment's own wrapping before looking for a sentence in it.
    prose = re.sub(r"\s*\n\s*\*\s*", " ", source)
    assert "the SDK headers state no units for" in prose
    assert "calibrated against the rejected-frame counters on hardware" in prose
