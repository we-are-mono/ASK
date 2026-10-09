"""Compile the CEETM egress-FQ lookup against a stub and exercise both readings."""

from ask_orch.process import run_process

import os
import re
import shutil
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
    names = ["ceetm_resolve_channel", "ceetm_get_egressfq", "ceetm_egress_fqid",
             "txfqid", "cdx_get_txfqid", "cdx_get_sec_txfqid"]
    # The test for a DPAA port, from where cdx keeps it, ahead of its user.
    (tmp_path / "egress_fq_production.inc").write_text(
        function((ROOT / "cdx/devman.c").read_text(), "dpa_netdev_is_dpaa")
        + "\n".join(function(source, name) for name in names))
    # The mark's layout as the encoder reads it, not a restatement of it.
    union = re.search(r"union ctentry_qosmark \{.*?\n\};\n",
                      (ROOT / "cdx/control_ipv4.h").read_text(), re.S)
    assert union
    (tmp_path / "qosmark.inc").write_text(union.group())
    binary = tmp_path / "ceetm_egress_fq"
    run_process([
        compiler, "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra", "-Werror",
        "-Wno-unused-parameter", "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-Werror=implicit-function-declaration",
        "-I", str(tmp_path),
        str(Path(__file__).with_name("ceetm_egress_fq.c")), "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })


def test_dscp_fq_lookup_holds_its_own_section(tmp_path):
    """The DSCP map is freed after a grace period once its port's last filter
    goes, and the transmit path reads it per frame; the lookup takes the
    read-side section itself rather than relying on its caller's context."""
    compiler = os.environ.get("CC", "cc")
    source = (ROOT / "cdx/cdx_ceetm_app.c").read_text()
    header = (ROOT / "cdx/module_qm.h").read_text()
    (tmp_path / "dscp_fq_types.inc").write_text(
        re.search(r"^#define MAX_DSCP\s.*$", header, re.M).group() + "\n"
        + re.search(r"struct qm_dscp_fq_map \{.*?\n\};\n", header, re.S).group())
    (tmp_path / "dscp_fq_production.inc").write_text(function(source, "ceetm_get_dscp_fq"))
    binary = tmp_path / "dscp_fq_lookup"
    run_process([
        compiler, "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra", "-Werror",
        "-Wno-unused-parameter", "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("dscp_fq_lookup.c")), "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
