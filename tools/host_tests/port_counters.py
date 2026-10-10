"""A registered Ethernet port's standard counters, compiled from devman.c: its
transmit counts from the MAC, its receive drops from the BMI and the MAC."""

from ask_orch.process import run_process

import os
import re
from pathlib import Path

from _host_qos_lifecycle import (function)

ROOT = Path(__file__).resolve().parents[2]


def test_port_counters(tmp_path):
    source = (ROOT / "cdx/devman.c").read_text()
    layer2 = (ROOT / "cdx/layer2.h").read_text()
    flags = re.findall(r"^#define\s+(?:IF_TYPE_ETHERNET|IF_TYPE_PHYSICAL|IF_TYPE_WLAN|IF_STATS_ENABLED)\s.*$",
                       layer2, re.M)
    assert len(flags) == 4, flags
    (tmp_path / "port_counters_flags.inc").write_text("\n".join(flags) + "\n")
    # The port's own state as portdefs.h declares it, not a restatement.
    ports = (ROOT / "cdx/portdefs.h").read_text()
    count = re.search(r"^struct port_bmi_count \{.*?\n\};\n", ports, re.S | re.M)
    mac_count = re.search(r"^struct port_mac_count \{.*?\n\};\n", ports, re.S | re.M)
    state = re.search(r"\tstruct \{\n\t\tbool ready;\n\t\tu64 base_packets.*?rx_mac_dropped;\n", ports, re.S)
    speeds = re.findall(r"^\tuint32_t (?:speed|fwd_cgr_speed|fwd_cgr_mtu);.*$", ports, re.M)
    assert count and mac_count and state and len(speeds) == 3, \
        "port_bmi_count / port_mac_count / speed / fwd_cgr_speed / fwd_cgr_mtu / tx_wire / rx_mac_dropped"
    (tmp_path / "port_counters_types.inc").write_text(
        count.group() + mac_count.group() +
        "struct eth_iface_info {\n\tstruct net_device *net_dev;\n" + "\n".join(speeds) + "\n" +
        state.group() + "};\n")
    defines = re.findall(r"^#define (?:MEMAC_PAUSE_OCTETS|MEMAC_TX_TRIES|MEMAC_TX_PRIME_GAP_US|"
                         r"MEMAC_TX_PRIME_BUDGET_US|MEMAC_TX_LATE_GAP_MAX_US|FWD_CGR_WIRE_OVERHEAD)\s.*$",
                         source, re.M)
    assert len(defines) == 6, defines
    (tmp_path / "port_counters_production.inc").write_text("\n".join(defines) + "\n" + "\n".join(function(source, name) for name in [
        "fwd_cgr_owner", "dpa_fwd_cgr_follow_link", "memac_counter", "memac_tx_frames", "port_mac_tx", "port_tx_gap_us", "port_tx_still",
        "port_tx_base", "port_tx_from_wire",
        "port_bmi_read", "port_bmi_advance", "port_mac_rx_advance", "port_rx_drops_advance", "port_counters_prime",
        "port_tx_prime_late", "dpa_port_counters_sample", "virt_iface_stats_callback",
    ]))
    binary = tmp_path / "port_counters"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("port_counters.c")), "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })


def test_port_tx_queued(tmp_path):
    source = (ROOT / "cdx/devman.c").read_text()
    (tmp_path / "port_tx_queued_production.inc").write_text(
        "".join(function(source, name) for name in ["port_cdx_queued", "port_tx_queued"]))
    binary = tmp_path / "port_tx_queued"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("port_tx_queued.c")), "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
