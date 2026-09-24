"""A189: run the actual routed worker through refresh, faults and teardown."""
import os
from pathlib import Path
import subprocess

from test_pppoe_hm import declaration
from test_qos_lifecycle import function

ROOT = Path(__file__).resolve().parents[2]


def test_mroute_refresh(tmp_path):
    source = (ROOT / "cdx/ask_flowtable.c").read_text()
    header = (ROOT / "cdx/cdx_mcast_backend.h").read_text()
    (tmp_path / "mroute_backend.inc").write_text(
        declaration(header, "cdx_mc_listener")
        + declaration(header, "cdx_mc_group_spec"))
    start = source.index("enum ft_mr_state {")
    structs = source[source.index("struct ft_mr_vif {"):
                     source.index("static LIST_HEAD(ft_mr_groups)")]
    # What a group routed through a bridge publishes, as the adapter
    # declares it.
    route = source[source.index("struct ft_mc_route {"):
                   source.index("struct ft_mc_tap {")]
    (tmp_path / "mroute_types.inc").write_text(
        route + source[start:source.index("};", start) + 3] + structs)
    # The confirmation table and the ruleset it is armed for, as declared.
    (tmp_path / "mroute_confirm_types.inc").write_text(
        source[source.index("struct ft_mr_watch {"):
               source.index("/* The ruleset in force, as the packet path reads it.")])
    (tmp_path / "mroute_refresh.inc").write_text("\n".join(
        function(source, name) for name in [
            # What Linux itself forwarded: the table the hook fills, the
            # ruleset it is good for, and the admission they decide.
            "ft_mr_ruleset_read", "ft_mr_ruleset_applying", "ft_mr_ruleset_current",
            "ft_mr_watch_bucket",
            "ft_mr_watch_complete", "ft_mr_confirm_seen", "ft_mr_ruleset_sync",
            "ft_mr_ruleset_wait", "ft_mr_watch_arm", "ft_mr_watch_drop", "ft_mr_admit",
            "ft_mr_ruleset_fn",
            "ft_mr_refusal", "ft_mr_state_text", "ft_mr_plan_same",
            "ft_mr_plan_put", "ft_mr_offload_flag", "ft_mr_counters",
            "ft_mr_release_copies", "ft_mr_release_set", "ft_mr_group_free",
            "ft_mr_dirty_family",
            "ft_mr_device_gone", "ft_mr_may_list", "ft_mr_egress_mark",
            "ft_mr_egress_drain", "ft_mr_key_taken",
            "ft_mr_publish", "ft_mr_record", "ft_mr_work_fn", "ft_mr_stats_fn",
            "ft_mr_exit",
        ]))
    binary = tmp_path / "refresh"
    subprocess.run([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
        "-I", str(tmp_path), str(Path(__file__).with_name("mroute_refresh.c")),
        "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
