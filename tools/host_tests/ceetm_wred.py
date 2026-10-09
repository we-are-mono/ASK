"""Compile the production WRED conversion and check the curve it encodes.

Run without the board fixtures:
    pytest tools/host_tests/ceetm_wred.py
"""

from ask_orch.process import run_process

from pathlib import Path
import os
import re
import shutil

ROOT = Path(__file__).resolve().parents[2]


def function(source, name):
    # The line has to begin with a return type, not with the ` * ' of a comment
    # continuation: a comment naming `foo()' above the definition of foo would
    # otherwise be lifted instead.
    match = re.search(r"^(?:static\s+)?\w[\w \*]*\b" + name + r"\([^;]*?\)\s*\{", source, re.M)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


def test_curve(tmp_path):
    compiler = os.environ.get("CC", "cc")
    assert shutil.which(compiler), f"C compiler required: {compiler}"
    source = (ROOT / "cdx/cdx_ceetm_app.c").read_text()
    header = (ROOT / "cdx/cdx_ceetm_app.h").read_text()
    names = ["ceetm_cq_wred_off", "ceetm_wred_maxp", "ceetm_wred_min_band",
             "ceetm_wred_maxth", "ceetm_wred_slope",
             "ceetm_set_class_wred", "ceetm_clear_class_wred",
             "ceetm_set_class_depth", "ceetm_class_queue_state",
             "ceetm_set_class_queue", "ceetm_park_class_queue",
             "ceetm_reset_class_queue"]
    (tmp_path / "wred_production.inc").write_text(
        # The depth a queue given back is parked at, as the header has it.
        re.search(r"^#define\s+CEETM_PARKED_CQ_DEPTH\s.*$", header, re.M).group() + "\n"
        + "".join(line + "\n" for line in source.splitlines()
                  if line.startswith("#define CEETM_WRED_"))
        + "\n".join(function(source, name) for name in names))
    binary = tmp_path / "ceetm_wred"
    run_process([
        compiler, "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra", "-Werror",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
        "-Werror=implicit-function-declaration", "-I", str(tmp_path),
        str(Path(__file__).with_name("ceetm_wred.c")), "-o", str(binary), "-lm",
    ], check=True)
    result = run_process([str(binary)], text=True, capture_output=True, timeout=30,
                            env={**os.environ,
                                 "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
                                 "UBSAN_OPTIONS": "halt_on_error=1"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert "implied minimum" in result.stdout
    print(result.stdout.strip())


def test_units_are_stated(tmp_path):
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
