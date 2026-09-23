"""Compile the ehash add and delete from the shipped patch and check what a
failed barrier leaves behind in a bucket whose keys collide."""

import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
PCD = "drivers/net/ethernet/freescale/sdk_fman/Peripherals/FM/Pcd/fm_ehash.c"
HEADER = "drivers/net/ethernet/freescale/sdk_fman/inc/Peripherals/fm_ehash.h"


def declaration(source, name):
    """One struct as written, brace-matched, so a field added inside it comes
    along instead of truncating the type."""
    match = re.search(r"struct\s+" + name + r"\s*\{", source)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():source.index(";", end) + 1] + "\n"


def function(source, name):
    """A definition, whatever it returns: its parameter list is followed by a
    brace, which a call or a prototype never is."""
    match = re.search(r"^[^\n;{}]*\b" + name + r"\([^;{]*?\)\s*\{", source, re.M)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


def test_ehash_cumulative(tmp_path):
    # Every patch that writes either file, in order, so the types are the
    # shipped ones: a later patch turns the key into a flexible array.
    for patch in sorted((ROOT / "patches/kernel").glob("*.patch")):
        if patch.name.startswith("999") or not re.search(
                r"^diff --git a/(?:" + re.escape(PCD) + "|" + re.escape(HEADER) + ") ",
                patch.read_text(), re.M):
            continue
        subprocess.run(["git", "apply", "--whitespace=nowarn", f"--include={PCD}",
                        f"--include={HEADER}", str(patch)], cwd=tmp_path, check=True)
    header = (tmp_path / HEADER).read_text()
    pcd = (tmp_path / PCD).read_text()
    (tmp_path / "ehash_types.inc").write_text(
        "\n".join(re.findall(r"^#define\s+(?:MAX_EN_EHASH_(?:EXT_)?ENTRY_SIZE|EN_EHASH_ENTRY_ALIGN|"
                             r"EN_CUMULATIVE_NODE(?:_MAX_SIZE)?|EN_INVALID_CUMULATIVE_NODE|"
                             r"EN_NEXT_CUMULATIVE_NODE|EN_CU_HASH_TABLE_ENTRY_ADDR_SIZE|"
                             r"EN_CU_FIXED_ELEMENTS_SIZE|EN_EHASH_DELETE_UNSYNCED)\s.*$",
                             header, re.M)) + "\n"
        + "".join(declaration(header, name) for name in (
            "en_ehash_entry", "en_cumulative_entry", "en_cumulative_tbl_entry", "en_exthash_node",
            "en_exthash_info", "en_exthash_tbl_entry", "en_exthash_bucket")))
    (tmp_path / "ehash_production.inc").write_text(
        # The parked list's own state, as declared.
        pcd[pcd.index("static DEFINE_SPINLOCK(ehash_parked_lock);"):pcd.index("static void ehash_park_node(")]
        + "".join(function(pcd, name) for name in (
            "find_entry_in_bucket", "ExternalHashTableAllocCumulativeEntry",
            "ExternalHashTableCumulativeEntryFree", "ehash_park_node", "ehash_barrier",
            "ExternalHashTableAddKey", "ExternalHashTableFmPcdHcSync", "ExternalHashTableDeleteKey")))
    binary = tmp_path / "ehash_cumulative"
    subprocess.run([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1", "-Wall", "-Wno-unused-function",
        "-Wno-unused-but-set-variable", "-Werror", "-fsanitize=address,undefined",
        # A cumulative node packs its entry addresses at odd offsets, which is
        # the microcode's format; the SoC loads them unaligned without fault.
        "-fno-sanitize=alignment",
        "-fno-omit-frame-pointer", "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("ehash_cumulative.c")), "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
