"""Exercise the production flowtable decoder and directional lifecycle on the host.

Only kernel infrastructure and the firmware boundary are simulated. Rule parsing,
replace/remove, counter deltas, and invalidation are compiled from CDX itself.
"""

from ask_orch.process import run_process

from _host_flowtable import (ROOT, flowtable_source, function)
import os
from pathlib import Path
import re

import pytest


def test_decoder_and_lifecycle(tmp_path):
    source = flowtable_source()
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
        + source[source.index("struct cdx_ft_binding {"):
                 source.index("\n", source.index("#define CDX_FT_HASH_BITS")) + 1]
        # The framing a VLAN device's record is published with, as the
        # adapter defines it: the cases below assert the published values.
        + "\n".join(re.findall(r"^#define FT_(?:VLAN|PPP)_[RT]X_OVERHEAD\s.*$", source, re.M)) + "\n"
    )
    names = ["ft_fault", "ft_devices_hold", "ft_devices_put", "ft_rule_names", "ft_crossed_hold", "ft_crossed_hold_all", "ft_crossed_put_all",
             "ft_find", "ft_handle_invalidate", "ft_neigh_invalidate", "ft_neigh_matches",
             "ft_neigh_table", "ft_neigh_check", "ft_neigh_moved", "ft_nexthop_usable",
             "ft_next_hop", "ft_routes_valid", "ft_offer_routes_current", "ft_offer_current", "ft_policy_covers", "ft_fdb_key", "ft_watch_publish", "ft_neigh_attach", "ft_neigh_detach", "ft_neigh_used",
             "ft_route_event", "ft_route6_event", "ft_neigh_event", "ft_fib_event", "ft_nexthop_event",
             "ft_ppp_rx_overhead", "ft_tunnel_under",
             "ft_dev_stats_release",
             "ft_dev_stats_get", "ft_dev_stats_put", "ft_dev_stats_gone",
             "ft_dev_stats_reap", "ft_dev_stats_drop_all", "ft_stats_attach",
             "ft_stats_detach", "ft_stats_binding",
             "ft_l2_overhead", "ft_remove", "ft_retire_workfn", "ft_endpoint", "ft_exact6", "ft_qos_class_valid", "ft_qos_class", "ft_qos_remarks", "ft_tuple_matches", "ft_nat_edit", "ft_translation",
             "ft_vlan_lower", "ft_bridge_vlan", "ft_tunnel_dev", "ft_tunnel_hop", "ft_path_stack", "ft_same_tags", "ft_vlan_match", "ft_vlan_actions", "ft_port_arriving", "ft_rule_stripped", "ft_ipv6_mtu_bounded", "ft_ipv4_arriving", "ft_ipv4_mtu_carried", "ft_mtu_refused", "ft_bridge_egress_filtered", "ft_tunnel_inbound_allowed", "ft_parse", "ft_same_key", "ft_key_hash",
             "ft_replace", "ft_entry_bounded", "ft_stats", "ft_request_targets", "ft_software_reoffers", "ft_offer_installed", "ft_admission_fault", "ft_rule_callback",
             "ft_invalid_complete", "ft_drained", "ft_can_rearm", "ft_rearm", "ft_rearm_workfn",
             "ft_release",
             "ft_bind_admissible", "ft_passive_callback", "ft_bind_passive",
             "ft_block_setup", "ft_bind", "cdx_ft_setup_tc",
             "ft_invalidate_work", "ft_entry_crosses", "ft_entry_uses", "ft_device_used", "ft_device_role", "ft_device_retire",
             "ft_port_stopped", "ft_stopped_clean", "ft_stopped_workfn", "ft_netdev_event",
             "ft_fdb_event", "ft_stp_stopped", "ft_swdev_event", "ft_egress_changed", "ft_egress_drain", "ft_egress_restarted", "ft_block_drain", "ft_hw_settle", "ft_init_fault", "ask_flowtable_init", "ask_flowtable_exit", "ft_position", "ft_start", "ft_next", "ft_stop"]
    (tmp_path / "flowtable_production.inc").write_text(
        # The stopped-port sweep's queue, lock and work item, as declared.
        source[source.index("struct ft_stopped {"):source.index("static void ft_port_stopped(")]
        + "\n".join(function(source, name) for name in names))
    binary = tmp_path / "flowtable"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra",
        "-Werror", "-Wno-unused-parameter", "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("flowtable.c")), "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })


def test_hardware_ownership(tmp_path):
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
    (tmp_path / "hardware_production.inc").write_text(
        function((ROOT / "cdx/cdx_ehash.c").read_text(), "fill_tunnel_key")
        + source[source.index("struct cdx_ft_hw {"):])
    backend = (ROOT / "cdx/cdx_flowtable_backend.c").read_text()
    (tmp_path / "backend_production.inc").write_text(backend[backend.index("static bool ft_observe"):])
    binary = tmp_path / "flowtable_hw"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra",
        "-Werror", "-Wno-unused-parameter", "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("flowtable_hw.c")), "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })


def test_neighbour_fallback(tmp_path):
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
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra",
        "-Werror", "-fsanitize=address,undefined", "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("flowtable_neigh.c")), "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })


def test_stats_poll(tmp_path):
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    offload = (kernel / "net/netfilter/nf_flow_table_offload.c").read_text()
    header = (kernel / "include/net/netfilter/nf_flow_table.h").read_text()
    stats = function(offload, "nf_flow_offload_stats")
    # The tree the image build unpacked; it follows patches/kernel/ only once a
    # build has run since the patch changed.
    if "stats_time" not in stats:
        pytest.skip(f"{kernel} predates patch 140's partial-flow statistics poll")
    (tmp_path / "stats_poll_production.inc").write_text(
        function(header, "nf_flow_timeout_delta") + stats)
    binary = tmp_path / "flowtable_stats_poll"
    run_process([
        # Upstream compares the signed timeout delta with the unsigned
        # timeout, which the kernel's flags never warn about and -Wextra does.
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra",
        "-Wno-sign-compare",
        "-Werror", "-fsanitize=address,undefined", "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("flowtable_stats_poll.c")), "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })


def test_idle_counts_what_the_other_backends_own():
    """With no adapter registered, CDX asks the backend whether anything the
    adapter installed is still in the hardware. SAs and multicast groups go in
    through backends of their own, and an adapter on its way out retires them
    only after it has unregistered the hook that would otherwise answer; so
    each backend counts what it holds, on the one path that hands an object
    back and the one that consumes it, and the answer includes both: that
    cdx_ft_idle() reads both counts is test_hardware_ownership's, against the
    compiled backend."""
    for path, add, delete, counter in (
            ("cdx/cdx_ipsec_backend.c", "cdx_ipsec_sa_add", "cdx_ipsec_sa_del",
             "cdx_ipsec_sa_owned"),
            ("cdx/dpa_control_mc.c", "cdx_mc_group_add", "cdx_mc_group_del",
             "cdx_mc_groups_owned")):
        source = (ROOT / path).read_text()
        body = function(source, add)
        assert body.count(counter + "++") == 1, add
        # After every way out that installed nothing, before the success.
        assert body.rindex("goto ") < body.index(counter + "++") < \
            body.index("return 0;"), add
        assert function(source, delete).count(counter + "--") == 1, delete


def test_qos_flow_class(tmp_path):
    """The adapter's classifier for the software Tx path finds a frame's
    connection again when a scrub took its conntrack, by the inverse of the
    packet's own tuple, and gives back the reference the lookup took."""
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    uapi = (kernel / "include/uapi/linux/netfilter/nf_conntrack_common.h").read_text()
    start = "enum ip_conntrack_info {"
    (tmp_path / "qos_flow_class_types.inc").write_text(
        uapi[uapi.index(start):uapi.index("};", uapi.index(start)) + 3])
    source = flowtable_source()
    (tmp_path / "qos_flow_class_production.inc").write_text(
        function(source, "ft_qos_class") + function(source, "ft_qos_flow_class"))
    binary = tmp_path / "qos_flow_class"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra",
        "-Werror", "-Wno-unused-parameter", "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("qos_flow_class.c")), "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })


def test_software_path_carries_the_conntrack(tmp_path):
    """The software flowtable's forward step, compiled from the kernel, hands
    every frame it forwards its flow's conntrack with a reference of its own,
    and none to a frame it gives back to the stack."""
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    source = (kernel / "net/netfilter/nf_flow_table_ip.c").read_text()
    uapi = (kernel / "include/uapi/linux/netfilter/nf_conntrack_common.h").read_text()
    (tmp_path / "flowtable_ct_types.inc").write_text("".join(
        uapi[uapi.index(start):uapi.index("};", uapi.index(start)) + 3]
        for start in ("enum ip_conntrack_info {", "enum ip_conntrack_status {")))
    (tmp_path / "flowtable_ct_production.inc").write_text(
        function(source, "nf_flow_ct_set")
        + function(source, "nf_flow_pppoe_peer_valid")
        + function(source, "nf_flow_offload_forward")
        + function(source, "nf_flow_offload_ipv6_forward"))
    binary = tmp_path / "flowtable_ct"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra",
        "-Werror", "-Wno-unused-parameter", "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("flowtable_ct.c")), "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
