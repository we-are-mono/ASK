"""Which queue the IPsec offline port's entries leave an Ethernet port by,
compiled from cdx_dpa_ipsec.c and devman.c."""

from ask_orch.process import run_process

import os
import re
from pathlib import Path

from _host_qos_lifecycle import (function)

ROOT = Path(__file__).resolve().parents[2]


def test_decrypted_flow_egress(tmp_path):
    sa = (ROOT / "cdx/cdx_dpa_ipsec.c").read_text()
    devman = (ROOT / "cdx/devman.c").read_text()
    union = re.search(r"union ctentry_qosmark \{.*?\n\};\n",
                      (ROOT / "cdx/control_ipv4.h").read_text(), re.S)
    assert union
    (tmp_path / "qosmark.inc").write_text(union.group())
    (tmp_path / "ipsec_offline_port_egress_production.inc").write_text(
        function(devman, "dpa_get_fqid_from_eth") + function(devman, "dpa_get_sec_tx_fqid")
        + function(sa, "cdx_ipsec_decrypted_table") + function(sa, "cdx_ipsec_fill_sec_info"))
    binary = tmp_path / "ipsec_offline_port_egress"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("ipsec_offline_port_egress.c")), "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })


def test_sa_output_takes_the_queues_for_sec_frames():
    """An SA's ESP output is matched only on the offline port, and so leaves
    by the queues for SEC's frames; a flow the port does not own, by the
    forwarding queues."""
    devman = (ROOT / "cdx/devman.c").read_text()
    out = function(devman, "dpa_get_out_tx_info_by_itf_id")
    assert re.findall(r"dpa_get_fqid_from_eth\([^()]*\)", out) == [
        "dpa_get_fqid_from_eth(eth_info, &l2_info->fqid, NULL, hash, true)"]
    flow = function(devman, "dpa_get_tx_info_by_itf")
    assert re.findall(r"dpa_get_fqid_from_eth\([^()]*\)", flow) == [
        "dpa_get_fqid_from_eth(eth_info, &l2_info->fqid, qosinfo, hash, false)"]
    sa = (ROOT / "cdx/cdx_dpa_ipsec.c").read_text()
    assert "dpa_get_out_tx_info_by_itf_id(" in function(sa, "cdx_ipsec_add_classification_table_entry")
    # Its definition and that one call; a comment naming it has no arguments.
    assert len(re.findall(r"\bdpa_get_out_tx_info_by_itf_id\(\s*[^)\s]", "".join(
        p.read_text() for p in (ROOT / "cdx").glob("*.c")))) == 2
