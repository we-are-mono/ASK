"""A178: execute the patched driver's scan paths with competing completions."""

from ask_orch.process import run_process

import os
from pathlib import Path
import re

import _host_mwifiex as mwifiex
from _host_qos_lifecycle import (function)


def test_scan_lifecycle(tmp_path):
    # The entire recipe series on its pinned source.
    mwifiex.unpack(tmp_path)

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
    # What delivers a queued scan result: woal_send_cfg_bss_scan_result() in
    # the release the 6.18 line pins, woal_send_bss_scan_result() before.
    send = next(name for name in ("woal_send_cfg_bss_scan_result", "woal_send_bss_scan_result")
                if re.search(rf"^static void {name}\(", main, re.M))
    names = ["woal_cfg80211_scan_busy", "woal_cfg80211_scan_begin",
             "woal_cfg80211_scan_complete", "woal_cfg80211_scan_stop",
             "woal_cfg80211_scan_restart", "woal_scan_timeout_handler",
             send, "woal_terminate_workqueue"]
    (tmp_path / "scan_production.inc").write_text(
        "\n".join(function(main, n) for n in names)
        + "\n".join(function(ioctl, n) for n in [
            "woal_scan_pending_start", "woal_scan_pending_complete",
            "woal_cancel_scan"])
        + function(shim, "woal_send_bss_scan_result_event") + scan
        + f"\n#define send_scan_result {send}\n")

    # Large teardown/init functions are cross-compiled separately. Check
    # their wiring here as well as executing the actual queue teardown below.
    assert "woal_cfg80211_scan_stop(handle);" in function(main, "woal_clean_up")
    assert "woal_cfg80211_scan_stop(handle);" in function(main, "woal_cleanup_module")
    assert "INIT_DELAYED_WORK(&handle->scan_timeout_work," in function(main, "woal_init_sw")
    assert "woal_cfg80211_scan_restart(handle);" in function(main, "woal_post_reset")
    assert "woal_cfg80211_scan_stop(handle);" in function(main, "woal_switch_drv_mode")
    # woal_evt_work_queue() opens a brace in both arms of an #if/#else, which
    # the brace-counting extractor cannot follow: take it to the closing brace
    # at column 0 instead.
    evt = main[main.index("\nvoid woal_evt_work_queue("):]
    assert "evt->scan_generation" in evt[:evt.index("\n}\n")]

    binary = tmp_path / "scan_lifecycle"
    run_process([
        os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-g", "-O1",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
        "-Wno-sign-compare", "-Wno-pointer-sign",
        "-fsanitize=address,undefined", "-fno-pie", "-no-pie",
        "-I", str(tmp_path), str(Path(__file__).with_name("scan_lifecycle.c")),
        "-o", str(binary),
    ], check=True)
    result = run_process([str(binary)], check=True, timeout=60,
                            text=True, capture_output=True, env={
        **os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1",
    })
    assert "scan lifecycle scenarios passed" in result.stdout
    print(result.stdout.strip())
