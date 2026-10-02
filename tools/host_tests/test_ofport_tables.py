"""An offline port's tables, as get_ofport_info() reports them, against the
tables the shipped configuration attaches.

The table types come from the configuration the image ships, the way dpa_app
derives them: the offline port's policy in cdx_cfg.xml, the distributions it
names in cdx_pcd.xml, the classification each one leads to, and dpa_app's
name-to-type table. The types the IPsec port's consumers look up come from the
two functions that choose them. Neither list is written down here, so a PCD or
consumer change moves the test with it.

Run without the board fixtures:
    pytest tools/host_tests/test_ofport_tables.py
"""

from ask_orch.process import run_process
import os
from pathlib import Path
import re
import xml.etree.ElementTree as ET

import pytest

from _host_qos_lifecycle import (function)

ROOT = Path(__file__).resolve().parents[2]
FM_EH_TYPES = "drivers/net/ethernet/freescale/sdk_fman/inc/Peripherals/fm_eh_types.h"


def kernel_tree():
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
                  "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    if not (kernel / FM_EH_TYPES).exists():
        pytest.fail("build the ASK kernel or set ASK_KERNEL_SOURCE to its patched source")
    return kernel


def table_types(kernel):
    """The table-type enum as the kernel declares it, and its values."""
    header = (kernel / FM_EH_TYPES).read_text()
    enum = re.search(r"^enum \{\s*IPV4_UDP_TABLE.*?^\};", header, re.S | re.M).group()
    names = re.findall(r"^\s*(\w+),?\s*$", enum[enum.index("{") + 1:enum.rindex("}")], re.M)
    assert "=" not in enum and names[-1] == "MAX_MATCH_TABLES", enum
    values = {name: value for value, name in enumerate(names)}
    ioctl = (ROOT / "cdx/cdx_ioctl.h").read_text()
    for alias, target in re.findall(r"^#define\s+(IPV[46]_BRIDGED_MULTICAST_TABLE)\s+(\w+)",
                                    ioctl, re.M):
        values[alias] = values[target]
    return enum, values


def offline_ports():
    """Each offline port devoh assigns, with the portid and table types the
    shipped configuration gives it."""
    devoh = (ROOT / "cdx/devoh.c").read_text()
    assigned = dict((ptype, int(number) - 1) for number, ptype in re.findall(
        r'\{"dpa-fman0-oh@(\d+)", PORT_TYPE_(\w+)\}', devoh))
    assert set(assigned) == {"IPSEC", "WIFI"}, assigned
    cfg = ET.parse(ROOT / "config/gateway-dk/cdx_cfg.xml").getroot()
    pcd = ET.parse(ROOT / "dpa_app/files/etc/cdx_pcd.xml").getroot()
    dpa = (ROOT / "dpa_app/dpa.c").read_text()
    params = re.findall(r'\{\(char \*\)"(cdx_\w+)",\s*(\w+)\}',
                        dpa[dpa.index("table_params[] = {"):dpa.index("#define MAX_TABLE_PARAMS")])
    assert params
    ports = {}
    for ptype, number in assigned.items():
        port = cfg.find(f".//port[@type='OFFLINE'][@number='{number}']")
        assert port is not None, ptype
        policy = pcd.find(f"policy[@name='{port.get('policy')}']")
        assert policy is not None, port.get("policy")
        types = []
        for ref in policy.findall("dist_order/distributionref"):
            dist = pcd.find(f"distribution[@name='{ref.get('name')}']")
            table = dist.find("action[@type='classification']").get("name")
            # get_tbl_params(): the first entry whose name the table's contains.
            match = next(t for name, t in params if name in table)
            types.append(match)
        ports[ptype] = (int(port.get("portid")), types)
    return ports


def consumer_types():
    """The table types the IPsec port's tables are looked up by: an SA's own
    (get_tbl_type) and a flow's through an inbound SA, which is one of the
    types get_table_type() files a flow under and whose actions validate the SA
    (cdx_ipsec_decrypted_table()); any other is refused before the lookup."""
    sa = (ROOT / "cdx/cdx_dpa_ipsec.c").read_text()
    calls = re.findall(r"dpa_ipsec_ofport_td\(\s*\w+,\s*([\w>.-]+)", sa)
    assert sorted(calls) == ["info->tbl_type", "tbl_type"], calls
    assert re.search(r"tbl_type = get_tbl_type\(sa\);", sa)
    ehash = (ROOT / "cdx/cdx_ehash.c").read_text()
    assert "info->tbl_type = tbl_type;" in ehash
    pattern = r"\b(IPV[46]_\w+_TABLE|ESP_IPV[46]_TABLE)\b"
    fill = function(sa, "cdx_ipsec_fill_sec_info")
    assert fill.index("if (!cdx_ipsec_decrypted_table(info->tbl_type))") < \
        fill.index("dpa_ipsec_ofport_td("), fill
    decrypted = set(re.findall(pattern, function(sa, "cdx_ipsec_decrypted_table")))
    filed = set(re.findall(pattern, function(ehash, "get_table_type")))
    assert decrypted and decrypted < filed, (decrypted, filed)
    names = set(re.findall(pattern, function(sa, "get_tbl_type"))) | decrypted
    assert names
    return names


def test_ofport_tables(tmp_path):
    kernel = kernel_tree()
    enum, values = table_types(kernel)
    ports = offline_ports()
    portdefs = (ROOT / "cdx/portdefs.h").read_text()
    flag_defines = re.findall(r"^#define\s+(?:OF_FQID_VALID|IN_USE|PORT_VALID|PORT_TYPE_\w+)\s.*$",
                              portdefs, re.M)
    flags = {name: int(value) << int(shift) for name, value, shift in (
        re.match(r"#define\s+(\w+)\s+\((\d+) << (\d+)\)", d).groups() for d in flag_defines)}
    port_bits = flags["OF_FQID_VALID"] | flags["IN_USE"] | flags["PORT_VALID"] | flags["PORT_TYPE_MASK"]

    # The Wi-Fi port carries the shared tables and the IPsec port its own, one
    # of each type it classifies by (cdx_pcd.xml), and among them the ones
    # whose type is a port flag's bit -- which is what made collecting them in
    # the flags word wrong.
    (ipsec_portid, ipsec_types), (wifi_portid, wifi_types) = ports["IPSEC"], ports["WIFI"]
    assert len(ipsec_types) == len(set(ipsec_types)), ipsec_types
    ipsec_shipped = sorted({values[name] for name in ipsec_types})
    wifi_shipped = sorted({values[name] for name in wifi_types})
    colliding = sorted(t for t in set(ipsec_shipped) | set(wifi_shipped) if port_bits & (1 << t))
    assert colliding == [8, 9, 12, 13], colliding

    # What the IPsec port's consumers ask for sits below every port flag, so
    # the change leaves their answers as they were; the harness checks the
    # answers are the tables themselves, and that the port has every one.
    used = sorted({values[name] for name in consumer_types()})
    assert used and all(not (port_bits & (1 << t)) for t in used), used
    assert set(used) <= set(ipsec_shipped), (used, ipsec_shipped)

    cdx_common = (ROOT / "cdx/cdx_common.h").read_text()
    ioctl = (ROOT / "cdx/cdx_ioctl.h").read_text()
    (tmp_path / "ofport_types.inc").write_text(
        "\n".join(re.findall(r"^#define\s+MAX_(?:FRAME_MANAGERS|OF_PORTS)\s.*$", cdx_common, re.M))
        + "\n" + "\n".join(flag_defines) + "\n" + enum + "\n"
        + "\n".join(re.findall(r"^#define\s+IPV[46]_BRIDGED_MULTICAST_TABLE\s.*$", ioctl, re.M))
        + "\n" + re.search(r"^#define\s+TABLE_NAME_SIZE.*$", ioctl, re.M).group() + "\n"
        + re.search(r"^struct table_info \{.*?^\};", ioctl, re.S | re.M).group() + "\n"
        + "#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))\n")
    devoh = (ROOT / "cdx/devoh.c").read_text()
    cfg = (ROOT / "cdx/dpa_cfg.c").read_text()
    (tmp_path / "ofport_tables.inc").write_text(
        re.search(r"^struct oh_port_info \{.*?^\};", devoh, re.S | re.M).group() + "\n"
        + re.search(r"^static struct oh_port_info offline_port_info\[.*?\];$", devoh, re.M).group()
        + "\n" + "".join(function(cfg, "get_tableInfo_by_portid")
                         + "".join(function(devoh, name) for name in (
                             "get_ofport_info", "alloc_offline_port", "release_offline_port"))))
    (tmp_path / "ofport_config.inc").write_text(
        f"#define IPSEC_PORTID {ipsec_portid}\n#define WIFI_PORTID {wifi_portid}\n"
        f"static const uint32_t ipsec_table_types[] = {{ {', '.join(map(str, ipsec_shipped))} }};\n"
        f"static const uint32_t wifi_table_types[] = {{ {', '.join(map(str, wifi_shipped))} }};\n"
        f"static const uint32_t ipsec_used_types[] = {{ {', '.join(map(str, used))} }};\n"
        f"#define COLLIDING_TYPES {', '.join(map(str, colliding))}\n")

    binary = tmp_path / "ofport_tables"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter", "-Wno-unused-function",
        # As the kernel builds it: the flags word is a uint32_t and the table
        # scan takes an int *, which is what the production call passes.
        "-Wno-pointer-sign",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
        "-Werror=implicit-function-declaration", "-I", str(tmp_path),
        str(Path(__file__).with_name("ofport_tables.c")), "-o", str(binary),
    ], check=True)
    result = run_process([str(binary)], text=True, capture_output=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
    assert result.returncode == 0, result.stdout + result.stderr
    assert "offline-port tables:" in result.stdout
