"""The SEC shared descriptor an IPsec SA runs, compiled from the descriptor
builder and the kernel's own command encoders, and checked command by
command: nothing moves data after the protocol until its output has drained
(A328)."""

from ask_orch.process import run_process

import os
from pathlib import Path
import re

import pytest

ROOT = Path(__file__).resolve().parents[2]


def function(source, name):
    """A file-scope C function's definition, by name."""
    match = re.search(r"^(?:static\s+)?(?:inline\s+)?[A-Za-z_][\w ]*?\b%s\([^;{]*\)\s*\{.*?^\}\n" % name,
                      source, re.S | re.M)
    assert match, name
    return match.group() + "\n"

# What desc_constr.h needs from the kernel's register header, on the host:
# SEC's words in host order, and the few kernel helpers it calls.
REGS = """\
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint64_t dma_addr_t;
typedef uint32_t __be32;
#define cpu_to_caam32(x) ((u32)(x))
#define caam32_to_cpu(x) ((u32)(x))
#define cpu_to_caam_dma(x) ((dma_addr_t)(x))
#define cpu_to_be32(x) __builtin_bswap32(x)
#define lower_32_bits(n) ((u32)(n))
#define upper_32_bits(n) ((u32)((n) >> 32))
#define ALIGN(x, a) (((x) + (a) - 1) & ~((a) - 1))
#define IS_ENABLED(option) 0
#define printk(...) ((void)0)
#define KERN_DEBUG ""
"""


def test_ipsec_descriptor_drains_before_counters(tmp_path):
    sec = (ROOT / "cdx/cdx_dpa_ipsec.c").read_text()
    sec_h = (ROOT / "cdx/cdx_dpa_ipsec.h").read_text()
    control = (ROOT / "cdx/control_ipsec.h").read_text()
    layout = (ROOT / "cdx/dpa_ipsec.h").read_text()
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    caam = kernel / "drivers/crypto/caam"
    if not (caam / "desc_constr.h").exists():
        pytest.fail("build the ASK kernel or set ASK_KERNEL_SOURCE to its patched source")
    pdb = (caam / "pdb.h").read_text()
    decap = re.search(r"struct ipsec_decap_pdb \{.*?\n\}[^;\n]*;", pdb, re.S).end()
    for name in ("desc.h", "desc_constr.h"):
        (tmp_path / name).write_text((caam / name).read_text())
    (tmp_path / "regs.h").write_text(REGS)
    (tmp_path / "ipsec_descriptor_types.inc").write_text(
        pdb[pdb.index("struct ipsec_encap_cbc {"):decap] + "\n"
        + re.search(r"^#define MAX_SHARED_DESC_SIZE\s.*$", layout, re.M).group() + "\n"
        + layout[layout.index("struct desc_hdr {"):layout.index("/* For all Buffer pools")]
        + re.search(r"^struct cipher_params \{.*?^\};", control, re.S | re.M).group() + "\n"
        + re.search(r"^struct auth_params \{.*?^\};", control, re.S | re.M).group() + "\n"
        + "\n".join(re.findall(r"^#define\s+(?:SA_MODE_TUNNEL|CDX_DPA_IPSEC_(?:IN|OUT)BOUND)\s.*$",
                               control, re.M)) + "\n"
        + "\n".join(re.findall(r"^#define\s+(?:MAX_CAAM_SHARED_DESCSIZE|CDX_DPA_IPSEC_STATS_LEN)\s+\d+",
                               sec_h, re.M)) + "\n"
        + re.search(r"^#define OP_PCLID_IPSEC_TUNNEL\s.*$", sec_h, re.M).group() + "\n"
        + re.search(r"^#define ETH_HDR_LEN\s.*$", sec, re.M).group() + "\n")
    (tmp_path / "ipsec_descriptor_production.inc").write_text(
        function(sec_h, "cdx_ipsec_vlan_tag")
        + "".join(function(sec, name) for name in (
            "cdx_ipsec_cipher_is_gcm", "cdx_ipsec_sh_desc_hdr_flags", "cdx_ipsec_pdb_len",
            "cdx_ipsec_stats_offset", "build_stats_descriptor_part",
            "save_sa_state_in_external_mem", "cdx_ipsec_build_shared_descriptor")))
    binary = tmp_path / "ipsec_descriptor"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter", "-Wno-unused-function",
        # desc.h builds its command words by shifting into the sign bit,
        # which the kernel's own build tolerates, and desc_constr.h stores a
        # 64-bit pointer wherever the descriptor's next word falls, which
        # SEC's layout requires.
        "-fsanitize=address,undefined", "-fno-sanitize=shift,alignment",
        "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("ipsec_descriptor.c")), "-o", str(binary),
    ], check=True)
    result = run_process([str(binary)], text=True, capture_output=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
    assert result.returncode == 0, result.stdout + result.stderr
