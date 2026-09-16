"""Check the production interface-statistics allocator against a simulated MURAM."""

import os
from pathlib import Path
import re
import subprocess

from test_qos_lifecycle import function

ROOT = Path(__file__).resolve().parents[2]
HEADER = "drivers/net/ethernet/freescale/sdk_fman/inc/Peripherals/fm_ehash.h"


def declaration(source, kind, name):
    """One struct or enum as written, brace-matched rather than pattern-matched,
    so a field added inside it comes along instead of truncating the type. The
    opening brace is matched by regex rather than by literal text: the sources
    this reads from put it on the next line, on the same line, and directly
    against the name, all three."""
    match = re.search(rf"\b{kind}\s+{name}\s*\{{", source)
    assert match, (kind, name)
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():source.index(";", end) + 1] + "\n"


def stats_fields(source):
    """The statistics tail of `struct dpa_iface_info`, taken verbatim with the
    conditional it lives inside.

    The rest of that structure is a union of six device descriptions and drags
    in most of the driver's headers, none of which the allocator touches. What
    it does touch is these four fields, so these four are the real ones and the
    surrounding structure is not modelled at all -- a rename or a resize here
    still has to fail, which is the whole point of not restating them.
    """
    body = declaration(source, "struct", "dpa_iface_info")
    start = body.index("#ifdef INCLUDE_IFSTATS_SUPPORT")
    return "struct dpa_iface_info {\n" + body[start:body.index("#endif", start) + 6] + "\n};\n"


def test_ifstats(tmp_path):
    # The shipped patch, so this does not depend on a previously built kernel.
    subprocess.run([
        "git", "apply", f"--include={HEADER}",
        str(ROOT / "patches/kernel/010-ask-fman-dpaa-ehash.patch"),
    ], cwd=tmp_path, check=True)
    header = (tmp_path / HEADER).read_text()
    common = (ROOT / "cdx/cdx_common.h").read_text()
    ports = (ROOT / "cdx/portdefs.h").read_text()
    backend = (ROOT / "cdx/cdx_flowtable_backend.h").read_text()
    hardware = (ROOT / "cdx/cdx_flowtable_hw.h").read_text()
    source = (ROOT / "cdx/cdx_ifstats.c").read_text()
    # The real pool sizes, the real record shapes and the real slot, not a
    # restatement of them: the indices this test computes are a division by
    # one record's size and a multiplication by another's, so a shape that
    # changed on one side of that boundary has to fail here rather than
    # silently produce indices the firmware reads differently.
    (tmp_path / "ifstats_types.inc").write_text(
        "\n".join(re.findall(r"^#define\s+(?:MAX_LOGICAL_INTERFACES|"
                             r"MAX_PPPoE_INTERFACES)\s.*$", common, re.M)) + "\n"
        + re.search(r"^#define STATS_WITH_TS\s.*$", header, re.M).group() + "\n"
        + declaration(header, "struct", "en_ehash_portinfo")
        + declaration(header, "struct", "en_ehash_ifportinfo")
        + declaration(header, "struct", "en_ehash_stats")
        + declaration(header, "struct", "en_ehash_stats_with_ts")
        + declaration(header, "struct", "en_ehash_ifstats")
        + declaration(header, "struct", "en_ehash_ifstats_with_ts")
        + declaration(common, "struct", "cdx_iface_ifinfo")
        + declaration(common, "struct", "cdx_pppoe_iface_ifinfo")
        + declaration(ports, "struct", "iface_stats")
        + stats_fields(ports)
        + declaration(backend, "struct", "cdx_ft_stats")
        + declaration(backend, "enum", "cdx_ft_stats_kind")
        + declaration(hardware, "struct", "cdx_ft_stats_slot"))
    # The module state the two owners share, taken as a block so the free
    # lists and the carve stay exactly as declared -- including which of them
    # are file-scoped, which is what decides whether a test can read one.
    state = source[source.index("DEFINE_SPINLOCK(dpa_statslist_lock);"):
                   source.index("extern void *FmMurambaseAddr;") + 29]
    (tmp_path / "ifstats.inc").write_text(
        state + "\n"
        + function(source, "cdx_deinit_iface_stats")
        + function(source, "cdxdrv_init_stats")
        + function(source, "alloc_iface_stats")
        + function(source, "free_iface_stats")
        + function(source, "get_logical_ifstats_base")
        + function(source, "ifstats_slot_index")
        + function(source, "cdx_ft_ifstats_alloc")
        + function(source, "cdx_ft_ifstats_free")
        + function(source, "cdx_ft_ifstats_read"))
    binary = tmp_path / "ifstats"
    subprocess.run([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-I", str(tmp_path),
        "-DINCLUDE_IFSTATS_SUPPORT=1", "-DINCLUDE_PPPoE_IFSTATS=1",
        "-DINCLUDE_VLAN_IFSTATS=1", "-DINCLUDE_ETHER_IFSTATS=1",
        str(Path(__file__).with_name("ifstats.c")), "-o", str(binary),
    ], check=True)
    result = subprocess.run([str(binary)], timeout=60, text=True,
                            capture_output=True, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
    # The assertion that fired, or the sanitizer report, rather than a bare
    # exit status: both land on stderr and neither survives check=True.
    assert result.returncode == 0, result.stdout + result.stderr
    assert "checks passed" in result.stdout, result.stdout + result.stderr
    print(result.stdout.strip())
