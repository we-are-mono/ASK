"""Exercise the kernel's retained XFRM callback ownership with fault injection."""

from ask_orch.process import run_process
import os
from pathlib import Path
import re

from _host_qos_lifecycle import (function)
from _kernel_source import (kernel_source)


def test_xfrm_provider(tmp_path):
    kernel = kernel_source()
    xfrm = (kernel / "include/net/xfrm.h").read_text()
    ops = re.search(r"^struct xfrmdev_ops \{.*?^\};",
                    (kernel / "include/linux/netdevice.h").read_text(), re.M | re.S).group()
    # What the line's xfrm does with a state's offload type: since 6.18 it
    # pins it on request (xfrm_set_type_offload()) and drops it again when
    # a provider refuses the state; before, the state holds it from its
    # construction to its destruction (xfrm_put_type_offload()). And
    # whether xfrmdev_ops' state callbacks take the device (6.16).
    unset = "xfrm_unset_type_offload(" in xfrm
    units = {
        "include/net/xfrm.h": [*(["xfrm_unset_type_offload"] if unset else []),
            "xfrm_dev_ops_get", "xfrm_dev_ops_put",
            "xfrm_dev_state_update_stats", "xfrm_dev_state_advance_esn",
            "xfrm_dev_policy_delete", "xfrm_dev_policy_free"],
        "net/xfrm/xfrm_device.c": ["xfrm_dev_state_add", "xfrm_dev_policy_add"],
        "net/xfrm/xfrm_state.c": [*([] if unset else ["xfrm_put_type_offload"]),
                                  "xfrm_dev_state_delete", "xfrm_dev_state_free",
                                  "xfrm_state_free"],
        "drivers/net/bonding/bond_main.c": ["bond_ipsec_ops"],
    }
    add = function((kernel / "net/xfrm/xfrm_device.c").read_text(), "xfrm_dev_state_add")
    (tmp_path / "xfrm_provider_line.inc").write_text(
        ("#define UNSET_TYPE_OFFLOAD\n" if unset else "")
        + ("#define REFUSAL_DROPS_TYPE\n" if "xfrm_unset_type_offload(x);" in add else "")
        + ("#define XDO_PASSES_DEV\n"
           if re.search(r"\(\*xdo_dev_state_add\)\s*\(struct net_device \*dev,", ops) else ""))
    (tmp_path / "xfrm_provider_production.inc").write_text("\n".join(
        function((kernel / path).read_text(), name)
        for path, names in units.items() for name in names))
    binary = tmp_path / "xfrm_provider"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie", "-I", str(tmp_path),
        str(Path(__file__).with_name("xfrm_provider.c")), "-o", str(binary),
    ], check=True)
    run_process([str(binary)], check=True, timeout=30, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
