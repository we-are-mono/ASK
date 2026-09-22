"""The adapter's IPsec decision logic, compiled rather than stubbed.

The datapath boundary stays simulated -- nothing here encrypts. What is
compiled from the adapter is every function that decides: which transform
covers a direction, which SA it may name, what an xfrm_state translates to,
and which installed SA has to be followed when its peer moves.
"""

import os
from pathlib import Path
import subprocess

from test_qos_lifecycle import function

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "cdx/ask_flowtable.c"


def test_ipsec_adapter(tmp_path):
    source = SOURCE.read_text()
    rule = (ROOT / "cdx/cdx_flowtable_backend.h").read_text()
    backend = (ROOT / "cdx/cdx_ipsec_backend.h").read_text()
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    policy = (kernel / "net/xfrm/xfrm_policy.c").read_text()
    # The real descriptions, not restatements of them. A field added to the
    # SA spec, to the rule or to the watch has to fail here rather than
    # compile into a harness that no longer matches what the adapter keeps.
    (tmp_path / "ipsec_types.inc").write_text(
        rule[rule.index("#define CDX_FT_VLAN_MAX"):
             rule.index("/* Process-context transactions")]
        + backend[backend.index("#define CDX_IPSEC_KEY_MAX"):
                  backend.index("/* What SEC counted")]
        # Up to the work item, which is the kernel's and not a type.
        + source[source.index("struct ft_ipsec_watch {"):
                 source.index("static void ft_ipsec_follow_work(struct work_struct")])
    # The extraction order is not the file's: the policy half sits with the
    # rule callbacks, the watch with the other dependency watches and the
    # translation with the xfrmdev ops. Ordering here rather than
    # forward-declaring keeps the harness from depending on where in the
    # source a function happens to sit.
    names = [
        "ft_ipsec_offloaded", "ft_ipsec_paired_inbound", "ft_ipsec_record",
        "ft_ipsec_resolve", "ft_ipsec_flowi", "ft_ipsec_receiving", "ft_ipsec_handle",
        "ft_ipsec_mark", "ft_ipsec_neigh_moved", "ft_ipsec_route_moved",
        "ft_ipsec_all_moved", "ft_ipsec_device_moved",
        "ft_ipsec_watch_add", "ft_ipsec_watch_del", "ft_ipsec_watch_flush",
        "ft_ipsec_peer_mac", "ft_ipsec_next_hop", "ft_ipsec_spec",
        "ft_xdo_state_add", "ft_ipsec_retire_work",
        "ft_ipsec_watch_find", "ft_ipsec_watch_stale", "ft_ipsec_follow_work",
        "ft_xdo_state_delete", "ft_xdo_policy_add",
        "ft_xdo_state_free", "ft_xdo_offload_ok",
        "ft_xdo_policy_delete", "ft_xdo_policy_free",
    ]
    # The attachment comes last: it names the ops table, which names every
    # callback above.
    attachment = ["ft_ipsec_attach", "ft_ipsec_detach"]
    (tmp_path / "ipsec_production.inc").write_text(
        "\n".join(function(policy, name) for name in (
            "xfrm_state_ok", "xfrm_policy_ok", "secpath_has_nontransport",
            "xfrm_flowtable_policy_check"))
        +
        # The neighbour wait's own bounds, which decide whether an install
        # waits at all; a harness inventing them would assert nothing.
        source[source.index("#define FT_IPSEC_NEIGH_TRIES"):
               source.index("static int ft_ipsec_peer_mac")]
        + "\n".join(function(source, name) for name in names)
        + source[source.index("static const struct xfrmdev_ops ft_xfrmdev_ops = {"):
                 source.index("/* Attach the ops to a CDX physical port")]
        + "\n".join(function(source, name) for name in attachment))
    binary = tmp_path / "ipsec_adapter"
    subprocess.run([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
        "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("ipsec_adapter.c")), "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })


def test_ipsec_receive_ownership(tmp_path):
    source = (ROOT / "cdx/dpa_ipsec.c").read_text()
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    text = (kernel / "net/xfrm/xfrm_input.c").read_text()
    start = text.index("struct sec_path *secpath_set(")
    end = text.index("\nEXPORT_SYMBOL(secpath_set)", start)
    (tmp_path / "ipsec_receive_production.inc").write_text(
        text[start:end] + source[source.index("/* Only buffers transferred permanently"):
                                source.index("struct dpa_bp* get_ipsec_bp(void)")]
        + function(source, "ipsec_exception_pkt_handler"))
    for portal_napi in (False, True):
        binary = tmp_path / f"ipsec_receive_{portal_napi}"
        subprocess.run([
            os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
            "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter", "-Wno-unused-but-set-variable",
            "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
            "-DCONFIG_INET_IPSEC_OFFLOAD",
            *(["-DCONFIG_FSL_ASK_QMAN_PORTAL_NAPI"] if portal_napi else []),
            "-I", str(tmp_path), str(Path(__file__).with_name("ipsec_receive.c")), "-o", str(binary),
        ], check=True)
        subprocess.run([str(binary)], check=True, timeout=30, env={
            **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
            "UBSAN_OPTIONS": "halt_on_error=1",
        })
