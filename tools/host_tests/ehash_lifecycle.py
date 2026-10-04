"""Exercise the kernel external hash-table teardown and CDX quarantine."""

from ask_orch.process import run_process

from pathlib import Path
import os
import re

import pytest

ROOT = Path(__file__).resolve().parents[2]


def test_ehash_teardown(tmp_path):
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    sdk = kernel / "drivers/net/ethernet/freescale/sdk_fman"
    if not sdk.exists():
        pytest.fail("build the ASK kernel or set ASK_KERNEL_SOURCE to its patched source")

    def function(source, name):
        match = re.search(r"^(?:static )?(?:void|t_Error|uint32_t) " + name
                          + r"\([^;]*?\)\s*\{", source, re.M)
        assert match, name
        end, depth = match.end(), 1
        while depth:
            depth += (source[end] == "{") - (source[end] == "}")
            end += 1
        return source[match.start():end] + "\n"

    ehash = (sdk / "Peripherals/FM/Pcd/fm_ehash.c").read_text()
    cc = (sdk / "Peripherals/FM/Pcd/fm_cc.c").read_text()
    (tmp_path / "ehash_production.inc").write_text(
        function(ehash, "FreeEnEhashInfo") + function(ehash, "FM_PCD_HashTableDelete")
        + function(cc, "copy_td_to_ccbase") + function(cc, "FM_PCD_CcRootDelete")
        + function(cc, "FM_PCD_CcRootModifyNextEngine")
        + function(cc, "FmPcdCcModifyNextEngineParamTree")
    )
    # CDX's quarantine over the same table API: its node type through
    # cdx_ehash_delete_entry(), the one delete every CDX path goes through.
    quarantine = (ROOT / "cdx/cdx_ehash.c").read_text()
    (tmp_path / "quarantine_production.inc").write_text(
        quarantine[quarantine.index("struct cdx_ehash_pending_free {"):
                   quarantine.index("/* delete classif entry from table.")])
    binary = tmp_path / "ehash_lifecycle"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-fno-pie", "-no-pie",
        "-Werror=implicit-function-declaration", "-I", str(tmp_path),
        str(Path(__file__).with_name("ehash_lifecycle.c")), "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=30,
                   env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
                        "UBSAN_OPTIONS": "halt_on_error=1"})
