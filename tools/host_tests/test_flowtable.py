"""Exercise the production flowtable decoder and directional lifecycle on the host.

Only kernel infrastructure and the firmware boundary are simulated. Rule parsing,
replace/remove, counter deltas, and invalidation are compiled from CDX itself.
"""
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def function(source, name):
    match = re.search(r"^static [^\n]+\b" + name + r"\([^;]*?\)\s*\{", source, re.M)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


def test_flowtable_decoder_and_lifecycle(tmp_path):
    source = (ROOT / "cdx/cdx_flowtable.c").read_text()
    hardware = (ROOT / "cdx/cdx_flowtable_hw.h").read_text()
    (tmp_path / "flowtable_types.inc").write_text(
        hardware[hardware.index("struct cdx_ft_rule {"):hardware.index("int cdx_ft_hw_add")]
        + source[source.index("struct cdx_ft_binding {"):source.index("static LIST_HEAD")]
    )
    names = ["ft_fault", "ft_find", "ft_handle_invalidate", "ft_neigh_invalidate", "ft_neigh_matches", "ft_neigh_check",
             "ft_next_hop", "ft_routes_valid", "ft_neigh_attach", "ft_neigh_detach", "ft_neigh_used", "ft_route_event", "ft_neigh_event", "ft_fib_event",
             "ft_remove", "ft_retire_workfn", "ft_parse", "ft_same_key",
             "ft_replace", "ft_stats", "ft_rule_callback", "ft_release", "ft_can_rearm", "ft_bind",
             "ft_invalidate_work"]
    (tmp_path / "flowtable_production.inc").write_text(
        "\n".join(function(source, name) for name in names))
    binary = tmp_path / "flowtable"
    subprocess.run([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra",
        "-Werror", "-Wno-unused-parameter", "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("flowtable.c")), "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })


def test_flowtable_hardware_ownership(tmp_path):
    hardware = (ROOT / "cdx/cdx_flowtable_hw.h").read_text()
    source = (ROOT / "cdx/cdx_flowtable_hw.c").read_text()
    (tmp_path / "hardware_types.inc").write_text(
        hardware[hardware.index("struct cdx_ft_rule {"):hardware.index("int cdx_ft_hw_add")])
    (tmp_path / "hardware_production.inc").write_text(source[source.index("struct cdx_ft_hw {"):])
    binary = tmp_path / "flowtable_hw"
    subprocess.run([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra",
        "-Werror", "-Wno-unused-parameter", "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("flowtable_hw.c")), "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })


def test_flowtable_neighbour_fallback(tmp_path):
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    source = (kernel / "net/netfilter/nf_flow_table_ip.c").read_text()
    offload = (kernel / "net/netfilter/nf_flow_table_offload.c").read_text()
    (tmp_path / "neigh_fallback_production.inc").write_text(
        function(source, "nf_flow_dst_check") + function(offload, "nf_flow_offload_dst"))
    binary = tmp_path / "flowtable_neigh"
    subprocess.run([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra",
        "-Werror", "-fsanitize=address,undefined", "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("flowtable_neigh.c")), "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
