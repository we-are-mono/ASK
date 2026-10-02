"""Check the production interface-statistics allocator, the fold of its
records into a net device's counters, and the packet counts carried past the
firmware's 32 bits, against a simulated MURAM and workqueue."""

from ask_orch.process import run_process

from _host_ifstats import (HEADER, ROOT, declaration, stats_fields)

import os
from pathlib import Path
import re

from _host_qos_lifecycle import (function)


def test_ifstats(tmp_path):
    # The shipped patch, so this does not depend on a previously built kernel.
    run_process([
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
        + function(source, "ifstats_record_index")
        + function(source, "ifstats_widen")
        + function(source, "ifstats_sample")
        + function(source, "ifstats_wide_claim")
        + function(source, "cdx_deinit_iface_stats")
        + function(source, "cdxdrv_init_stats")
        + function(source, "alloc_iface_stats")
        + function(source, "free_iface_stats")
        + function(source, "get_logical_ifstats_base")
        + function(source, "ifstats_slot_index")
        + function(source, "cdx_ft_ifstats_alloc")
        + function(source, "cdx_ft_ifstats_hold")
        + function(source, "cdx_ft_ifstats_put")
        + function(source, "cdx_ft_ifstats_free")
        + function(source, "cdx_ft_ifstats_retention")
        + function(source, "ifstats_read_locked")
        + function(source, "cdx_ifstats_read")
        + function(source, "cdx_ft_ifstats_read")
        + function(source, "cdx_ft_ifstats_publish")
        + function(source, "cdx_ft_ifstats_unpublish")
        + function(source, "ifstats_restated")
        + function(source, "cdx_ifstats_fold")
        + function(source, "cdx_ft_ifstats_fold")
        + function(source, "ifstats_sampler_run")
        + function(source, "cdx_ifstats_start")
        + function(source, "cdx_ifstats_stop"))
    binary = tmp_path / "ifstats"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-I", str(tmp_path),
        "-DINCLUDE_IFSTATS_SUPPORT=1", "-DINCLUDE_PPPoE_IFSTATS=1",
        "-DINCLUDE_VLAN_IFSTATS=1", "-DINCLUDE_ETHER_IFSTATS=1",
        str(Path(__file__).with_name("ifstats.c")), "-o", str(binary),
    ], check=True)
    result = run_process([str(binary)], timeout=60, text=True,
                            capture_output=True, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
    # The assertion that fired, or the sanitizer report, rather than a bare
    # exit status: both land on stderr and neither survives check=True.
    assert result.returncode == 0, result.stdout + result.stderr
    assert "checks passed" in result.stdout, result.stdout + result.stderr
    print(result.stdout.strip())
