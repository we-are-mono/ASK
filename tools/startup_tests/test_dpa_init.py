"""CDX startup rollback on a dedicated rdinit=/bin/sh boot, before CDX loads.

Run separately from tools/tests: these cases require an unconfigured FMAN.
The final check loads CDX successfully in the same boot.
"""

import base64
import gzip
import json
import re
import shlex

from ask_orch.uart import Console

# Check each resource class, partial queue batches and the final handoff.
FAULTS = [
    ("cdx_ioc_set_dpa_params", 1),        # MURAM statistics
    ("cdx_ioc_set_dpa_params", 2),        # first offline interface
    ("dpa_add_port_ff_policier_profile", 1),  # private slot, before profile SET
    ("create_fwd_tx_fqs", 1),
    ("create_fwd_tx_fqs", 16),
    ("cdx_ioc_set_dpa_params", 4),        # first complete Ethernet interface
    ("dpa_add_port_ff_policier_profile", 5),
    ("cdxdrv_create_pcd_fqs", 1),
    ("cdxdrv_create_pcd_fqs", 128),
    ("cdxdrv_create_of_fqs", 1),
    ("cdxdrv_create_of_fqs", 4),
    ("cdxdrv_create_missaction_policer_profiles", 1),
    ("cdxdrv_create_ingress_qos_policer_profiles", 9),
    ("cdx_ioc_set_dpa_params", 9),        # all CEETM policers
    ("cdx_ioc_set_dpa_params", 10),       # classifier miss actions
]
SPLATS = re.compile(r"BUG:|WARNING: CPU:|Oops:|Kernel panic|possible circular locking|"
                    r"inconsistent lock state|sleeping function called|did not drain|"
                    r"cannot delete .*profile|cannot free profiles|PlcrProfileDelete failed")


def test_dpa_init_rollback(tmp_path):
    with Console.target(log_path=str(tmp_path / "uart.log")) as con:
        con.login("root", None)

        def run(command, timeout=20):
            result = con.run(command, timeout=timeout)
            assert result.rc == 0, (command, result.stdout)
            return result.stdout.strip()

        run("stty cols 240 -echo")
        assert run("cat /proc/1/comm") in ("sh", "bash"), "boot with rdinit=/bin/sh first"
        assert not re.search(r"^cdx ", run("cat /proc/modules"), re.M)
        boot = run("cat /proc/sys/kernel/random/boot_id")
        muram_paths = run("find /sys/devices -name fm_muram_free_size").splitlines()
        assert muram_paths, "FMAN MURAM accounting is required"
        muram_command = "cat " + " ".join(shlex.quote(p) for p in muram_paths)
        muram_before = run(muram_command)
        dmesg_before = run("dmesg")
        run("echo scan > /sys/kernel/debug/kmemleak")
        run("echo clear > /sys/kernel/debug/kmemleak")
        run("mv /usr/bin/dpa_app /usr/bin/dpa_app.startup-test")
        results = []
        try:
            wrapper = "#!/bin/sh\nexec /usr/bin/dpa_app.startup-test > /tmp/dpa-startup.log 2>&1\n"
            run("printf %s " + shlex.quote(wrapper) + " > /usr/bin/dpa_app")
            run("chmod +x /usr/bin/dpa_app")
            for site, step in FAULTS:
                command = f"modprobe cdx dpa_init_fail_site={site} dpa_init_fail_step={step}"
                result = con.run(command, timeout=90)
                log = run("cat /tmp/dpa-startup.log")
                kernel = run("dmesg")
                (tmp_path / f"{site}-{step}.log").write_text(result.stdout + log + kernel)
                assert result.rc != 0, f"fault checkpoint not reached: {site}:{step}"
                assert f"injecting DPA startup failure at {site} step {step}" in result.stdout
                assert "FMC rollback failed" not in log, log
                assert not SPLATS.search(kernel[len(dmesg_before):]), kernel
                assert not re.search(r"^cdx ", run("cat /proc/modules"), re.M)
                assert run(muram_command) == muram_before, (site, step, "MURAM leaked")
                run("test ! -e /proc/fqid_stats")
                results.append({"site": site, "step": step, "muram": muram_before})
                print(f"rollback passed: {site}:{step}", flush=True)
            run("echo scan > /sys/kernel/debug/kmemleak")
            # X3's hardware-owned boot pool can age into kmemleak after the
            # initial clear. Transfer the complete report compressed: dumping
            # thousands of these objects verbatim exceeds the UART timeout.
            encoded = run("cat /sys/kernel/debug/kmemleak | gzip -c | base64 -w0", timeout=120)
            raw_leaks = gzip.decompress(base64.b64decode(encoded)).decode()
            (tmp_path / "kmemleak.txt").write_text(raw_leaks)
            objects = re.findall(r"unreferenced object .*?(?=unreferenced object |\Z)",
                                 raw_leaks, re.S)
            assert "".join(objects).strip() == raw_leaks.strip(), "Unrecognized kmemleak report"
            known_pool = {obj for obj in objects
                          if 'comm "swapper/0", pid 1,' in obj
                          and "dpaa_eth_priv_probe+" in obj
                          and "dpaa_eth_refill_bpools+" in obj}
            leaks = [obj for obj in objects if obj not in known_pool]
            (tmp_path / "kmemleak-unexpected.txt").write_text("".join(leaks))
            assert not leaks, "".join(leaks)
            print(f"kmemleak: no unexpected objects; {len(known_pool)} known X3 boot-pool objects", flush=True)
            result = con.run("modprobe cdx", timeout=90)
            assert result.rc == 0, result.stdout + run("cat /tmp/dpa-startup.log")
            assert re.search(r"^cdx ", run("cat /proc/modules"), re.M)
            assert run("cat /proc/sys/kernel/random/boot_id") == boot
            kernel = run("dmesg")
            assert not SPLATS.search(kernel[len(dmesg_before):]), kernel
            (tmp_path / "results.json").write_text(json.dumps({"boot_id": boot, "faults": results,
                "same_boot_retry": True, "kernel_splats": False, "kmemleak": [],
                "known_boot_pool_objects": len(known_pool)}, indent=2))
            print("normal initialization passed in the same boot", flush=True)
        finally:
            run("mv /usr/bin/dpa_app.startup-test /usr/bin/dpa_app")
            run("stty echo")
