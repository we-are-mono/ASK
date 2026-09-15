"""CDX startup rollback, driven from a boot where CDX has not loaded yet.

Run separately from tools/tests: these cases require an unconfigured FMAN, so
boot an image with cdx and fci commented out of config/ask-modules.conf (fci
depends on cdx and would pull it back in). The final checks load and unload CDX
successfully in the same boot.
"""

import base64
import gzip
import json
import re
import shlex

from ask_orch.uart import Console

# Check each resource class, partial queue batches and the final handoff.
FAULTS = [
    ("dpa_cfg_install", 1),        # MURAM statistics
    ("dpa_cfg_install", 2),        # first offline interface
    ("dpa_add_port_ff_policier_profile", 1),  # private slot, before profile SET
    ("create_fwd_tx_fqs", 1),
    ("create_fwd_tx_fqs", 16),
    ("dpa_cfg_install", 4),        # first complete Ethernet interface
    ("dpa_add_port_ff_policier_profile", 5),
    ("cdxdrv_create_pcd_fqs", 1),
    ("cdxdrv_create_pcd_fqs", 128),
    ("cdxdrv_create_of_fqs", 1),
    ("cdxdrv_create_of_fqs", 4),
    ("cdxdrv_create_missaction_policer_profiles", 1),
    ("cdxdrv_create_ingress_qos_policer_profiles", 9),
    ("dpa_cfg_install", 9),        # all CEETM policers
    ("dpa_cfg_install", 10),       # classifier miss actions
]
SPLATS = re.compile(r"BUG:|WARNING: CPU:|Oops:|Kernel panic|possible circular locking|"
                    r"inconsistent lock state|sleeping function called|did not drain|"
                    r"cannot delete .*profile|cannot free profiles|PlcrProfileDelete failed|"
                    r"cannot quiesce|DPA resource cleanup failed|cannot restore port state|"
                    r"unable to release|Error in releasing")


def test_dpa_init_rollback(tmp_path):
    with Console.target(log_path=str(tmp_path / "uart.log")) as con:
        con.login("root", None)

        def run(command, timeout=20):
            result = con.run(command, timeout=timeout)
            assert result.rc == 0, (command, result.stdout)
            return result.stdout.strip()

        run("stty cols 240 -echo")
        # The only precondition that matters is an FMAN nothing has configured
        # yet. Boot an image with cdx and fci left out of
        # /etc/modules-load.d/ask.conf; the sweep loads and unloads cdx itself.
        assert not re.search(r"^cdx ", run("cat /proc/modules"), re.M), \
            "boot an image with cdx left out of the autoload list"
        boot = run("cat /proc/sys/kernel/random/boot_id")
        muram_paths = run("find /sys/devices -name fm_muram_free_size").splitlines()
        assert muram_paths, "FMAN MURAM accounting is required"
        muram_command = "cat " + " ".join(shlex.quote(p) for p in muram_paths)
        muram_before = run(muram_command)
        port_state_code = """import errno, fcntl, glob, json, os
states = {}
for path in sorted(glob.glob('/dev/fm0-port-*')):
    try:
        fd = os.open(path, os.O_RDWR)
    except OSError as error:
        if error.errno == errno.ENODEV:
            continue
        raise
    try:
        enabled = bytearray(1)
        fcntl.ioctl(fd, 0x8001e172, enabled)
        assert enabled[0] in (0, 1)
        states[path] = enabled[0]
    finally:
        os.close(fd)
assert states
print(json.dumps(states, sort_keys=True))
"""
        port_state_command = "python3 -c " + shlex.quote("exec(" + repr(port_state_code) + ")")
        ports_before = json.loads(run(port_state_command))
        dmesg_before = run("dmesg")
        run("echo scan > /sys/kernel/debug/kmemleak", timeout=120)
        run("echo clear > /sys/kernel/debug/kmemleak", timeout=120)
        results = []
        try:
            for site, step in FAULTS:
                command = f"modprobe cdx dpa_init_fail_site={site} dpa_init_fail_step={step}"
                result = con.run(command, timeout=90)
                kernel = run("dmesg")
                (tmp_path / f"{site}-{step}.log").write_text(result.stdout + kernel)
                assert result.rc != 0, f"fault checkpoint not reached: {site}:{step}"
                assert f"injecting DPA startup failure at {site} step {step}" in result.stdout
                assert not SPLATS.search(kernel[len(dmesg_before):]), kernel
                assert not re.search(r"^cdx ", run("cat /proc/modules"), re.M)
                assert run(muram_command) == muram_before, (site, step, "MURAM leaked")
                assert json.loads(run(port_state_command)) == ports_before, (site, step, "port state changed")
                run("test ! -e /proc/fqid_stats")
                # Each failed install leaks ~930k bucket allocations that this
                # build cannot reclaim (ISSUES.md A138). Left to accumulate,
                # fifteen cycles reach ~14M objects: the scan below grows by
                # ~6s per cycle and the report becomes too large to move over
                # the console. Clear per cycle so the final scan is about the
                # load/unload path. Drop this once A138 is fixed.
                run("echo clear > /sys/kernel/debug/kmemleak", timeout=120)
                results.append({"site": site, "step": step, "muram": muram_before})
                print(f"rollback passed: {site}:{step}", flush=True)
            # A clean scan is ~5s; allow generous headroom so a slow one is
            # reported as leaks rather than as a console timeout.
            run("echo scan > /sys/kernel/debug/kmemleak", timeout=120)
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
            assert result.rc == 0, result.stdout + run("dmesg")
            assert re.search(r"^cdx ", run("cat /proc/modules"), re.M)
            assert run("cat /proc/sys/kernel/random/boot_id") == boot
            assert json.loads(run(port_state_command)) == ports_before
            kernel = run("dmesg")
            assert not SPLATS.search(kernel[len(dmesg_before):]), kernel
            print("normal initialization passed in the same boot", flush=True)
            muram_loaded = run(muram_command)
            run("modprobe -r cdx", timeout=90)
            assert not re.search(r"^cdx ", run("cat /proc/modules"), re.M)
            run("test ! -e /proc/fqid_stats")
            assert json.loads(run(port_state_command)) == ports_before
            muram_unloaded = run(muram_command)
            kernel = run("dmesg")
            assert not SPLATS.search(kernel[len(dmesg_before):]), kernel
            (tmp_path / "unload-dmesg.txt").write_text(kernel)
            print("normal unload preserved port state without kernel diagnostics", flush=True)
            (tmp_path / "results.json").write_text(json.dumps({"boot_id": boot, "faults": results,
                "same_boot_retry": True, "module_unloaded": True,
                "muram_loaded": muram_loaded, "muram_unloaded": muram_unloaded,
                "kernel_splats": False, "kmemleak": [],
                "known_boot_pool_objects": len(known_pool),
                "port_states_restored": ports_before}, indent=2))
        finally:
            run("stty echo")
