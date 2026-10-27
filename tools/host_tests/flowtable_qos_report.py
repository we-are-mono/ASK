"""The adapter's report of the hardware QoS it has to give, compiled from the
adapter and read back: the status keys, and the qos_ports and qos_classes rows.

cdx's side of it -- what the budget, the ports and their classes hold -- is
htb_offload.c's and police.c's; here cdx answers whatever each case sets, and
what is checked is what a reader of /proc/ask_flowtable is shown.
"""

from ask_orch.process import run_process

import os
import re
from pathlib import Path

from _host_flowtable import ROOT, flowtable_source, function

# What renders the report, in dependency order.
NAMES = ["ft_kv", "ft_qos_mark_shift", "ft_qos_mark", "ft_qos_status", "ft_qos_list",
         "ft_qos_class_row", "ft_qos_ports_show", "ft_qos_classes_show"]


def test_qos_report(tmp_path):
    source = flowtable_source()
    backend = (ROOT / "cdx/cdx_flowtable_backend.h").read_text()
    exports = (ROOT / "cdx/cdx_flowtable.h").read_text()
    (tmp_path / "qos_report_types.inc").write_text(
        # The class layout as the rule's header states it, and what cdx's
        # report hands the adapter, as cdx declares it.
        "\n".join(re.findall(r"^#define CDX_FT_QOS_\w+(?:[^\n]*\\\n)*[^\n]*$", backend, re.M))
        + "\n" + exports[exports.index("/* What the hardware qdisc has to give"):
                         exports.index("/* A port's egress changed")])
    (tmp_path / "qos_report_production.inc").write_text(
        # The status layout's columns and the channel list's room, as the
        # adapter defines them.
        "".join(re.search(rf"^#define {name}\s.*$", source, re.M).group() + "\n"
                for name in ("FT_KEY_COLUMNS", "FT_VALUE_COLUMNS", "FT_QOS_LIST"))
        + "".join(function(source, name) for name in NAMES))
    binary = tmp_path / "qos_report"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1", "-Wall", "-Wextra",
        "-Werror", "-Wno-unused-parameter", "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("flowtable_qos_report.c")), "-o", str(binary),
    ], check=True)
    result = run_process([str(binary)], text=True, capture_output=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
    assert result.returncode == 0, result.stdout + result.stderr
    assert "qos report: passed" in result.stdout
    print(result.stdout.strip())
