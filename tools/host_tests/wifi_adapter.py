"""The adapter's Wi-Fi VAP decision logic, compiled rather than stubbed.

The rig can show an AP interface becoming a VAP. It cannot cheaply show one
stopping: the driver on that board refuses `ip link del` for its own
interfaces and hostapd holds the module open, so an AP-mode netdev there
essentially never unregisters. That is the path where the netdev pointer stops
being safe to follow, so it is the path this compiles and runs under ASan.
"""

from ask_orch.process import run_process

import os
from pathlib import Path

from _host_flowtable import (flowtable_source)
from _host_qos_lifecycle import (function)

ROOT = Path(__file__).resolve().parents[2]


def test_wifi_adapter(tmp_path):
    source = flowtable_source()
    # The real declarations, not a restatement of them. A field added to the
    # watch has to fail here rather than compile into a harness that no
    # longer describes what the adapter keeps.
    (tmp_path / "wifi_production.inc").write_text(
        source[source.index("struct ft_wifi_watch {"):
               source.index("static void ft_wifi_work_fn(struct work_struct *work);")]
        # The work item's forward declaration is the kernel's, not a type.
        + "static void ft_wifi_work_fn(struct work_struct *work);\n"
        + "static struct work_struct ft_wifi_work;\n"
        + "\n".join(function(source, name) for name in [
            "ft_wifi_is_vap",
            "ft_wifi_reconsider",
            "ft_wifi_device_gone",
            "ft_wifi_address_changed",
            "ft_wifi_work_fn",
            "ft_wifi_exit",
        ]))
    binary = tmp_path / "wifi_adapter"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
        "-fsanitize=address,undefined",
        "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("wifi_adapter.c")), "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
