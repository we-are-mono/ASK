"""A178: execute the patched driver's scan paths with competing completions."""

import io
import os
from pathlib import Path
import re
import subprocess
import tarfile

from test_qos_lifecycle import function

ROOT = Path(__file__).resolve().parents[2]


def test_scan_lifecycle(tmp_path):
    recipe = ROOT / "meta-ask/recipes-kernel/nxp-mwifiex/nxp-mwifiex_git.bb"
    source = Path(os.environ.get("ASK_MWIFIEX_SOURCE", ROOT /
        "meta-ask/build/tmp/work/ask_ls1046a-oe-linux/nxp-mwifiex/git/git"))
    revision = re.search(r'SRCREV = "([0-9a-f]+)"', recipe.read_text())[1]
    # Apply the entire recipe series to its pinned source, independently of
    # whether bitbake's working copy has rebuilt since the latest patch.
    archive = subprocess.check_output(["git", "archive", revision], cwd=source)
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(tmp_path, filter="data")
    for patch in re.findall(r"file://(\S+\.patch)", recipe.read_text()):
        subprocess.run(["git", "apply", "--whitespace=error",
                        str(recipe.parent / "files" / patch)],
                       cwd=tmp_path, check=True)

    def read(name):
        return (tmp_path / "mlinux" / name).read_text().replace(
            "mlan_status ", "int ").replace("t_void ", "void ")

    main, ioctl, shim = map(read, ["moal_main.c", "moal_ioctl.c", "moal_shim.c"])
    sta = read("moal_sta_cfg80211.c")
    # The definition has alternate prototypes inside preprocessor branches.
    # Retain its entire body, including the version-dependent setup paths.
    start = sta.index("\n{", sta.rindex("static int woal_cfg80211_scan("))
    end = sta.index("\n#if CFG80211_VERSION_CODE >= KERNEL_VERSION(4, 5, 0)", start)
    scan = ("static int woal_cfg80211_scan(struct wiphy *wiphy, "
            "struct cfg80211_scan_request *request)" + sta[start:end])
    names = ["woal_cfg80211_scan_busy", "woal_cfg80211_scan_begin",
             "woal_cfg80211_scan_complete", "woal_cfg80211_scan_stop",
             "woal_cfg80211_scan_restart", "woal_scan_timeout_handler",
             "woal_send_bss_scan_result", "woal_terminate_workqueue"]
    (tmp_path / "scan_production.inc").write_text(
        "\n".join(function(main, n) for n in names)
        + "\n".join(function(ioctl, n) for n in [
            "woal_scan_pending_start", "woal_scan_pending_complete",
            "woal_cancel_scan"])
        + function(shim, "woal_send_bss_scan_result_event") + scan)

    # Large teardown/init functions are cross-compiled separately. Check
    # their wiring here as well as executing the actual queue teardown below.
    assert "woal_cfg80211_scan_stop(handle);" in function(main, "woal_clean_up")
    assert "woal_cfg80211_scan_stop(handle);" in function(main, "woal_cleanup_module")
    assert "INIT_DELAYED_WORK(&handle->scan_timeout_work," in function(main, "woal_init_sw")
    assert "woal_cfg80211_scan_restart(handle);" in function(main, "woal_post_reset")
    assert "woal_cfg80211_scan_stop(handle);" in function(main, "woal_switch_drv_mode")
    assert "evt->scan_generation" in function(main, "woal_evt_work_queue")

    binary = tmp_path / "scan_lifecycle"
    subprocess.run([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
        "-Wno-sign-compare", "-Wno-pointer-sign",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
        "-I", str(tmp_path), str(Path(__file__).with_name("scan_lifecycle.c")),
        "-o", str(binary),
    ], check=True)
    result = subprocess.run([str(binary)], check=True, timeout=60,
                            text=True, capture_output=True, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
    assert "scan lifecycle scenarios passed" in result.stdout
    print(result.stdout.strip())
