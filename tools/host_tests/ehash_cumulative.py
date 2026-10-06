"""Compile the ehash add and delete from the shipped patch and check what a
failed barrier or a failed allocation leaves behind in a bucket whose keys
collide."""

from ask_orch.process import run_process

from _host_ehash_cumulative import (HEADER, PCD, ROOT, declaration, function)

import os
from pathlib import Path
import re


def test_ehash_cumulative(tmp_path):
    # Every patch that writes either file, in order, so the types are the
    # shipped ones: a later patch turns the key into a flexible array.
    for patch in sorted((ROOT / "patches/kernel").glob("*.patch")):
        if patch.name.startswith("999") or not re.search(
                r"^diff --git a/(?:" + re.escape(PCD) + "|" + re.escape(HEADER) + ") ",
                patch.read_text(), re.M):
            continue
        run_process(["git", "apply", "--whitespace=nowarn", f"--include={PCD}",
                        f"--include={HEADER}", str(patch)], cwd=tmp_path, check=True)
    header = (tmp_path / HEADER).read_text()
    pcd = (tmp_path / PCD).read_text()
    (tmp_path / "ehash_types.inc").write_text(
        "\n".join(re.findall(r"^#define\s+(?:MAX_EN_EHASH_(?:EXT_)?ENTRY_SIZE|EN_EHASH_ENTRY_ALIGN|"
                             r"EN_CUMULATIVE_NODE(?:_MAX_SIZE)?|EN_INVALID_CUMULATIVE_NODE|"
                             r"EN_NEXT_CUMULATIVE_NODE|EN_CU_HASH_TABLE_ENTRY_ADDR_SIZE|"
                             r"EN_CU_FIXED_ELEMENTS_SIZE|EN_EHASH_DELETE_UNSYNCED|"
                             r"EHASH_ADD_BUCKET_FULL)\s.*$",
                             header, re.M)) + "\n"
        + "".join(declaration(header, name) for name in (
            "en_ehash_entry", "en_cumulative_entry", "en_cumulative_tbl_entry", "en_exthash_node",
            "en_exthash_info", "en_exthash_tbl_entry", "en_exthash_bucket")))
    (tmp_path / "ehash_production.inc").write_text(
        # The parked list's own state, as declared, and the delete's private
        # return code and the search's bound.
        pcd[pcd.index("static DEFINE_SPINLOCK(ehash_parked_lock);"):pcd.index("static void ehash_park_node(")]
        + re.search(r"^#define\s+EHASH_DELETE_NEEDS_NODE\s.*$", pcd, re.M).group() + "\n"
        + re.search(r"^#define\s+EHASH_CHAIN_MAX\s.*$", pcd, re.M).group() + "\n"
        + re.search(r"^#define\s+EHASH_BUCKET_KEYS_MAX\s.*$", pcd, re.M).group() + "\n"
        + "".join(function(pcd, name) for name in (
            "find_entry_in_bucket", "ehash_bucket_keys", "ehash_node_entry",
            "ExternalHashTableAllocCumulativeEntry",
            "ExternalHashTableCumulativeEntryFree", "ehash_node_take_spare", "ehash_node_alloc",
            "ehash_node_release",
            "ehash_park_node", "ehash_barrier", "ehash_unpark_table", "ExternalHashTableAddKey",
            "ExternalHashTableFmPcdHcSync", "ehash_delete_key", "ehash_delete",
            "ExternalHashTableDeleteKey", "ExternalHashTableUnlinkKey", "ExternalHashTableDeleteSync",
            "ehash_bucket_links", "ExternalHashTableFindEntry",
            "ExternalHashTableHcFailed")))
    binary = tmp_path / "ehash_cumulative"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1", "-Wall", "-Wno-unused-function",
        "-Wno-unused-but-set-variable", "-Werror", "-fsanitize=address,undefined",
        # A cumulative node packs its entry addresses at odd offsets, which is
        # the microcode's format; the SoC loads them unaligned without fault.
        "-fno-sanitize=alignment",
        "-fno-omit-frame-pointer", "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("ehash_cumulative.c")), "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
