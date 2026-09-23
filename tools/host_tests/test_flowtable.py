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
    match = re.search(r"^(?:static )?[^\n]+\b" + name + r"\([^;]*?\)\s*\{", source, re.M)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


def test_flowtable_decoder_and_lifecycle(tmp_path):
    source = (ROOT / "cdx/ask_flowtable.c").read_text()
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    hashes = (kernel / "include/linux/jhash.h").read_text()
    (tmp_path / "flowtable_hash.inc").write_text(
        # From __jhash_mix, not __jhash_final: jhash2 needs both macros.
        hashes[hashes.index("#define __jhash_mix"):hashes.index("/* jhash -")]
        + function(hashes, "jhash2")
        + function(hashes, "__jhash_nwords") + function(hashes, "jhash_3words"))
    hardware = (ROOT / "cdx/cdx_flowtable_backend.h").read_text()
    (tmp_path / "flowtable_types.inc").write_text(
        # From the encapsulation bound, not the rule: the rule embeds the tag
        # type and its depth, so slicing past them leaves an incomplete struct.
        hardware[hardware.index("#define CDX_FT_VLAN_MAX"):hardware.index("/* Process-context transactions")]
        + source[source.index("struct cdx_ft_binding {"):source.index("static LIST_HEAD")]
        # The framing a VLAN device's record is published with, as the
        # adapter defines it: the cases below assert the published values.
        + "\n".join(re.findall(r"^#define FT_(?:VLAN|PPP)_[RT]X_OVERHEAD\s.*$", source, re.M)) + "\n"
    )
    names = ["ft_fault", "ft_devices_hold", "ft_devices_put",
             "ft_find", "ft_handle_invalidate", "ft_neigh_invalidate", "ft_neigh_matches",
             "ft_neigh_table", "ft_neigh_check", "ft_nexthop_usable",
             "ft_next_hop", "ft_routes_valid", "ft_neigh_attach", "ft_neigh_detach", "ft_neigh_used",
             "ft_route_event", "ft_route6_event", "ft_neigh_event", "ft_fib_event", "ft_nexthop_event",
             "ft_ppp_rx_overhead", "ft_tunnel_under",
             "ft_dev_stats_release",
             "ft_dev_stats_get", "ft_dev_stats_put", "ft_dev_stats_gone",
             "ft_dev_stats_reap", "ft_dev_stats_drop_all", "ft_stats_attach",
             "ft_stats_detach", "ft_stats_binding",
             "ft_l2_overhead", "ft_remove", "ft_retire_workfn", "ft_endpoint", "ft_exact6", "ft_qos_class_valid", "ft_qos_class", "ft_tuple_matches", "ft_nat_edit", "ft_translation",
             "ft_vlan_lower", "ft_bridge_vlan", "ft_tunnel_dev", "ft_tunnel_hop", "ft_path_stack", "ft_same_tags", "ft_vlan_match", "ft_vlan_actions", "ft_ipv6_mtu_bounded", "ft_parse", "ft_same_key", "ft_key_hash",
             "ft_replace", "ft_stats", "ft_request_targets", "ft_admission_fault", "ft_rule_callback", "ft_release", "ft_can_rearm", "ft_bind_admissible", "ft_passive_callback", "ft_passive_release", "ft_block_setup", "ft_bind", "cdx_ft_setup_tc",
             "ft_invalidate_work", "ft_entry_uses", "ft_device_used", "ft_device_retire",
             "ft_port_stopped", "ft_stopped_clean", "ft_stopped_workfn", "ft_netdev_event",
             "ft_fdb_event", "ft_stp_stopped", "ft_swdev_event", "ft_egress_changed", "ft_init_fault", "ask_flowtable_init", "ft_block_drain", "ask_flowtable_exit", "ft_position", "ft_start", "ft_next", "ft_stop"]
    (tmp_path / "flowtable_production.inc").write_text(
        # The stopped-port sweep's queue, lock and work item, as declared.
        source[source.index("struct ft_stopped {"):source.index("static void ft_port_stopped(")]
        + "\n".join(function(source, name) for name in names))
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
    hardware = (ROOT / "cdx/cdx_flowtable_backend.h").read_text()
    source = (ROOT / "cdx/cdx_flowtable_hw.c").read_text()
    # The real port-table size, not a stub one: the backend asserts that the
    # binding bound equals it, and an invented value would assert nothing.
    system = re.search(r"^#define MAX_PHY_PORTS\s+\d+", (ROOT / "cdx/system.h").read_text(), re.M)
    assert system
    (tmp_path / "hardware_types.inc").write_text(
        system.group() + "\n" +
        hardware[hardware.index("#define CDX_FT_VLAN_MAX"):hardware.index("/* Process-context transactions")])
    (tmp_path / "physical_production.inc").write_text(
        function((ROOT / "cdx/devman.c").read_text(), "dpa_get_ifinfo_by_netdev") +
        function((ROOT / "cdx/devman.c").read_text(), "dpa_netdev_is_physical"))
    # The outer header a tunnel egress inserts, and the types the builder is
    # written against -- the real IP headers and the real mode numbers, so a
    # field reordered or a mode renumbered fails here rather than compiling
    # into bytes the legacy owner and this one disagree about.
    common = (ROOT / "cdx/cdx_common.h").read_text()
    tunnel = (ROOT / "cdx/control_tunnel.h").read_text()
    (tmp_path / "tunnel_types.inc").write_text(
        "#define ENDIAN_LITTLE 1\n"
        + re.search(r"^#define IPV6_ADDRESS_LENGTH\s.*$", common, re.M).group() + "\n"
        + "\n".join(re.findall(r"^#define\s+IPPROTOCOL_(?:IPIP|IPV6)\s.*$",
                               (ROOT / "cdx/fe.h").read_text(), re.M)) + "\n"
        + re.search(r"enum TNL_MODE \{[^}]*\};", tunnel, re.S).group() + "\n"
        + "\n".join(re.findall(r"^#define\s+(?:INHERIT_TC|DSCP_COPY)\s.*$",
                               tunnel, re.M)) + "\n"
        + re.search(r"typedef struct\s+IPv4_HDR_STRUCT\b.*?\}\s*\w+\s*;",
                    common, re.S).group() + "\n"
        + re.search(r"typedef struct\s+IPv6_HDR_STRUCT\b.*?\}\s*\w+\s*;",
                    common, re.S).group() + "\n"
        + re.search(r"#define IPV6_SET_VER_TC_FL.*?while \(0\)\n",
                    (ROOT / "cdx/control_ipv6.h").read_text(), re.S).group())
    (tmp_path / "tunnel_production.inc").write_text(
        function((ROOT / "cdx/cdx_hal.h").read_text(), "__WRITE_UNALIGNED_INT")
        + "#define WRITE_UNALIGNED_INT(var, val) __WRITE_UNALIGNED_INT(&(var), (val))\n"
        + function((ROOT / "cdx/control_tunnel.c").read_text(), "tnl_build_header"))
    (tmp_path / "hardware_production.inc").write_text(source[source.index("struct cdx_ft_hw {"):])
    backend = (ROOT / "cdx/cdx_flowtable_backend.c").read_text()
    (tmp_path / "backend_production.inc").write_text(backend[backend.index("static bool ft_observe"):])
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
        function(source, "nf_flow_dst_check")
        # The predicate the accessor is built on, not a detail of it: which
        # transmit types keep a destination in that union is the whole
        # question this test asks, so it is compiled rather than stubbed.
        + function(offload, "nf_flow_offload_has_dst")
        + function(offload, "nf_flow_offload_dst"))
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
