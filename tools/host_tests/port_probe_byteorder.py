"""nftables' byteorder expression as patch 148's port probe models it, run
against the expression itself, both compiled from the kernel tree."""

import os
import re
from pathlib import Path

from ask_orch.process import run_process
from _host_qos_lifecycle import function
from _kernel_source import kernel_source


def _declaration(source, start):
    return re.search(r"^" + re.escape(start) + r".*?^\};\n", source, re.M | re.S).group()


def _inline(header, name):
    match = re.search(r"^static inline [^\n]*\b" + re.escape(name) + r"\(", header, re.M)
    assert match, name
    return header[match.start():header.index("\n}\n", match.start()) + 3]


def test_the_probe_knows_only_what_the_expression_leaves(tmp_path):
    """The probe follows a byteorder expression bit by bit, the data and which
    of its bits are known, so a later comparison or set lookup can tell
    whether the stream's ports decide it. A bit it calls known must be the
    one nft_byteorder_eval() leaves there on every packet that agrees with
    what was known before: since 6.18 a 16-bit result clears the rest of its
    register (nft_reg_store16()), which a 4-byte read of the register -- a
    concatenated set key, say -- sees as zeroes, not as whatever the register
    held before."""
    kernel = kernel_source()
    tables = (kernel / "include/net/netfilter/nf_tables.h").read_text()
    core = (kernel / "include/net/netfilter/nf_tables_core.h").read_text()
    uapi = (kernel / "include/uapi/linux/netfilter/nf_tables.h").read_text()
    byteorder = (kernel / "net/netfilter/nft_byteorder.c").read_text()
    probe = (kernel / "net/netfilter/nf_tables_port_probe.c").read_text()

    (tmp_path / "byteorder_types.inc").write_text(
        _declaration(uapi, "enum nft_byteorder_ops {")
        + _declaration(core, "struct nft_byteorder {")
        + _declaration(probe, "enum nft_probe_res {")
        + _declaration(probe, "struct nft_probe_regs {"))
    (tmp_path / "byteorder_production.inc").write_text(
        "".join(_inline(tables, name) for name in (
            "nft_reg_store16", "nft_reg_store_be16", "nft_reg_load16",
            "nft_reg_load_be16", "nft_reg_store64", "nft_reg_load64"))
        + function(byteorder, "nft_byteorder_eval")
        + function(probe, "nft_probe_stop")
        + function(probe, "nft_probe_span")
        + function(probe, "nft_probe_byteorder_apply")
        + function(probe, "nft_probe_byteorder"))
    binary = tmp_path / "port_probe_byteorder"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra",
        "-Werror", "-Wno-unused-parameter", "-fno-strict-aliasing",
        "-fsanitize=address,undefined", "-I", str(tmp_path),
        str(Path(__file__).with_name("port_probe_byteorder.c")), "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=60, env={
        **os.environ, "ASAN_OPTIONS": "abort_on_error=1", "UBSAN_OPTIONS": "halt_on_error=1",
    })

    # The walk models the expression through this function alone.
    assert re.search(r"if \(type == &nft_byteorder_type\)\s*"
                     r"return nft_probe_byteorder\(ctx, expr\);", probe)
    assert probe.count("nft_probe_byteorder(ctx, expr)") == 1
