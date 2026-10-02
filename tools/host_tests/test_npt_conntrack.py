"""ip6t_NPT's conntrack fix-up, compiled from the patched kernel: it writes a
connection's reply tuple only while the conntrack is unconfirmed, never a
hashed entry in place."""

from ask_orch.process import run_process

import os
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]


def target(source, name):
    """A target's definition, whose return type netfilter writes on the line
    above its name."""
    match = re.search(r"^static unsigned int\n" + name + r"\([^;]*?\)\s*\{", source, re.M)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


def test_npt_conntrack(tmp_path):
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    uapi = (kernel / "include/uapi/linux/netfilter/nf_conntrack_common.h").read_text()
    npt = (kernel / "include/uapi/linux/netfilter_ipv6/ip6t_NPT.h").read_text()
    start = "enum ip_conntrack_info {"
    (tmp_path / "npt_types.inc").write_text(
        uapi[uapi.index(start):uapi.index("};", uapi.index(start)) + 3]
        + npt[npt.index("struct ip6t_npt_tginfo {"):npt.index("};", npt.index(
            "struct ip6t_npt_tginfo {")) + 3])
    source = (kernel / "net/ipv6/netfilter/ip6t_NPT.c").read_text()
    (tmp_path / "npt_production.inc").write_text(
        target(source, "ip6t_snpt_tg") + target(source, "ip6t_dnpt_tg"))
    binary = tmp_path / "npt_conntrack"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra",
        "-Werror", "-Wno-unused-parameter", "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("npt_conntrack.c")), "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
