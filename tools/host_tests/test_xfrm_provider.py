"""Exercise the kernel's retained XFRM callback ownership with fault injection."""
import os
from pathlib import Path
import subprocess

from test_qos_lifecycle import function

ROOT = Path(__file__).resolve().parents[2]


def test_xfrm_provider(tmp_path):
    kernel = Path(os.environ.get("ASK_KERNEL_SOURCE", ROOT /
        "meta-ask/build/tmp/work-shared/ask-ls1046a/kernel-source"))
    units = {
        "include/net/xfrm.h": ["xfrm_dev_ops_get", "xfrm_dev_ops_put",
            "xfrm_dev_state_update_stats", "xfrm_dev_state_advance_esn",
            "xfrm_dev_policy_delete", "xfrm_dev_policy_free"],
        "net/xfrm/xfrm_device.c": ["xfrm_dev_state_add", "xfrm_dev_policy_add"],
        "net/xfrm/xfrm_state.c": ["xfrm_dev_state_delete", "xfrm_dev_state_free",
                                  "xfrm_state_free"],
        "drivers/net/bonding/bond_main.c": ["bond_ipsec_ops"],
    }
    (tmp_path / "xfrm_provider_production.inc").write_text("\n".join(
        function((kernel / path).read_text(), name)
        for path, names in units.items() for name in names))
    binary = tmp_path / "xfrm_provider"
    subprocess.run([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("xfrm_provider.c")), "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
