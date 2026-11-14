"""A management command a QMan portal stops answering ends the wait, not the CPU.

An FMan host command that times out is described from QMan's own state, and
QMan may be what stopped. The description's queries wait for their answers
within a bound and say when one did not come, rather than spinning with
interrupts masked for an answer that may never come; the command they leave
unanswered is consumed by the portal's next command before that one is
written, so a late answer is never taken for a later command's, and a bounded
query refuses to write while one is owed. The real portal bookkeeping,
queries and description run against a modelled QMan (qman_mc_timeout.c).
"""

import os
import re
from pathlib import Path

from ask_orch.process import run_process
from _kernel_source import kernel_source

HERE = Path(__file__).parent
FSL_QMAN_DEFINES = (
    "QM_MCC_VERB_VBIT", "QM_MCC_VERB_MASK", "QM_MCC_VERB_QUERYFQ_NP", "QM_MCC_VERB_QUERYWQ",
    "QM_MCC_VERB_QUERYWQ_DEDICATED", "QM_MCR_VERB_MASK", "QM_MCR_VERB_QUERYFQ_NP",
    "QM_MCR_VERB_QUERYWQ", "QM_MCR_VERB_QUERYWQ_DEDICATED", "QM_MCR_RESULT_OK",
    "QM_MCR_RESULT_ERR_FQID",
)
LOW_DEFINES = ("QM_MC_DELAY_US", "QM_EQCR_SIZE", "QM_DQRR_SIZE")
LOW = ("qm_cyc_diff", "EQCR_PTR2IDX", "qm_eqcr_get_hw_fill", "qm_mc_settle", "qm_mc_start", "qm_mc_commit",
       "qm_mc_result", "qm_mc_result_timeout", "qm_mc_start_timeout")
HIGH = ("qman_affine_portal_dqrr_pending", "qman_affine_portal_eqcr_fill", "query_start",
        "query_result", "__qman_query_fq_np", "qman_query_fq_np", "qman_query_fq_np_timeout",
        "__qman_query_wq", "qman_query_wq", "qman_query_wq_timeout")


def define(source, name):
    match = re.search(r"^#define\s+" + re.escape(name) + r"\b.*$", source, re.M)
    assert match, name
    return match.group(0)


def function(source, name):
    """(offset, text) of the definition of `name`."""
    for match in re.finditer(r"^[A-Za-z_][\w \t*]*?\b" + re.escape(name) + r"\s*\(", source, re.M):
        depth, end = 1, match.end()
        while depth:
            depth += {"(": 1, ")": -1}.get(source[end], 0)
            end += 1
        body = re.match(r"\s*\{", source[end:])
        if not body:
            continue  # a declaration
        end += body.end()
        depth = 1
        while depth:
            depth += {"{": 1, "}": -1}.get(source[end], 0)
            end += 1
        return match.start(), source[match.start():end] + "\n"
    raise AssertionError(f"no definition of {name}")


def in_order(source, names):
    return "\n".join(text for _, text in sorted(function(source, name) for name in names))


def test_management_command_wait_is_bounded(tmp_path):
    kernel = kernel_source()
    qbman = kernel / "drivers/staging/fsl_qbman"
    fsl_qman = (kernel / "include/linux/fsl_qman.h").read_text()
    low = (qbman / "qman_low.h").read_text()
    high = (qbman / "qman_high.c").read_text()
    wrapper = (kernel / "drivers/net/ethernet/freescale/sdk_fman/src/wrapper/"
               "lnxwrp_fm_port.c").read_text()

    (tmp_path / "qman_defines.inc").write_text(
        "\n".join([define(fsl_qman, name) for name in FSL_QMAN_DEFINES] +
                  [define(low, name) for name in LOW_DEFINES]) + "\n")
    struct = re.search(r"^struct qm_mc \{.*?^\};", low, re.M | re.S)
    assert struct, "struct qm_mc"
    (tmp_path / "qman_mc_struct.inc").write_text(struct.group(0) + "\n")
    (tmp_path / "qman_mc_low.inc").write_text(in_order(low, LOW))
    (tmp_path / "qman_mc_high.inc").write_text(in_order(high, HIGH))
    (tmp_path / "qman_mc_describe.inc").write_text(
        define(wrapper, "HC_DESCRIBE_TIMEOUT_US") + "\n" + function(wrapper, "QmDescribeCB")[1])

    binary = tmp_path / "qman_mc_timeout"
    run_process([os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1", "-Wall", "-Werror",
                 "-Wno-unused-function", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                 "-I", str(tmp_path), str(HERE / "qman_mc_timeout.c"), "-o", str(binary)],
                check=True)
    result = run_process([str(binary)], check=False, timeout=60, capture_output=True, text=True,
                         env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
                              "UBSAN_OPTIONS": "halt_on_error=1"})
    assert result.returncode == 0 and result.stdout.strip() == "ok", result.stderr
