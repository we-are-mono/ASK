"""The x_tables port probe, as patch 148 adds it, over rule blobs laid out the
way ip_tables lays a table out.

The probe's code is taken from the patch -- both walkers, the pure-match and
passing-target lists, the core's dispatcher -- and the kernel's own
ip_packet_match() and ifname_compare_aligned() from the kernel tree, so the
header test the walk applies to every rule is the packet path's, not a copy.
"""
import os
from pathlib import Path
import re
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]
PATCH = ROOT / "patches/kernel/148-netfilter-nftables-commit-in-progress.patch"


def sections():
    patch = PATCH.read_text()
    return dict(re.findall(r"\+\+\+ b/(\S+)\n(.*?)(?=\ndiff --git |\Z)", patch, re.S))


def patched(section):
    """The patched file's side of a section's hunks: added and context lines."""
    lines = []
    for line in section.split("\n"):
        if line.startswith(("+", " ")):
            lines.append(line[1:])
        elif line == "":
            lines.append("")
    return "\n".join(lines) + "\n"


def between(text, first, last):
    start = text.index(first)
    end = text.index(last, start) + len(last)
    return text[start:end] + "\n"


def braced(text, head):
    """A definition from its head through the brace that closes its body."""
    match = re.search(head, text, re.M)
    assert match, head
    end = text.index("{", match.end())
    depth = 1
    end += 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[match.start():end] + "\n"


def test_xt_port_probe(tmp_path):
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    ip_tables = kernel / "net/ipv4/netfilter/ip_tables.c"
    x_tables_h = kernel / "include/linux/netfilter/x_tables.h"
    if not ip_tables.exists() or not x_tables_h.exists():
        pytest.fail("build the ASK kernel or set ASK_KERNEL_SOURCE to its patched source")
    (tmp_path / "ip_packet_match.inc").write_text(braced(
        ip_tables.read_text(), r"^static inline bool\nip_packet_match\("))
    (tmp_path / "ifname.inc").write_text(braced(
        x_tables_h.read_text(), r"^static inline unsigned long ifname_compare_aligned\("))

    patch = sections()
    v4 = patched(patch["net/ipv4/netfilter/ip_tables.c"])
    v6 = patched(patch["net/ipv6/netfilter/ip6_tables.c"])
    xt = patched(patch["net/netfilter/x_tables.c"])
    core = patched(patch["net/netfilter/core.c"])
    walker = "/* ---- whether the tables could tell two UDP streams apart"
    (tmp_path / "ipt_probe.inc").write_text(between(
        v4, walker, "static const struct nf_xt_probe_hook ipt_probe_hook = {\n"
        "\t.port_dependent = ipt_port_dependent,\n};"))
    (tmp_path / "ip6t_probe.inc").write_text(between(
        v6, walker, "static const struct nf_xt_probe_hook ip6t_probe_hook = {\n"
        "\t.port_dependent = ip6t_port_dependent,\n};"))
    (tmp_path / "xt_probe_lists.inc").write_text(between(
        xt, "/* Matches that do nothing but decide.",
        "EXPORT_SYMBOL_GPL(xt_probe_passing_target);"))
    (tmp_path / "xt_probe_core.inc").write_text(between(
        core, "const struct nf_xt_probe_hook __rcu *nf_ipt_probe_hook",
        "EXPORT_SYMBOL_GPL(nf_xt_port_dependent);"))

    # What the harness takes as given about the patch around the walkers:
    # the device name both read for a hook without a device is the file's,
    # and each family's tables are typed for the walk to find them, mangle's
    # wrapper included.
    for name, text in (("ip_tables", v4), ("ip6_tables", v6)):
        assert "static const char nulldevname[IFNAMSIZ] __aligned(sizeof(long));" in text, name
        assert "ops[i].hook_ops_type = NF_HOOK_OP_XTABLES;" in text, name

    binary = tmp_path / "xt_port_probe"
    subprocess.run([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
        # The kernel's own helpers pass unsigned interface masks as char
        # pointers, which the kernel builds without this warning for.
        "-Wno-pointer-sign",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
        "-I", str(tmp_path), str(Path(__file__).with_name("xt_port_probe.c")),
        "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True, timeout=60, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
