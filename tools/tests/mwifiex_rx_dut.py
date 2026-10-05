"""Run the real moal receive-drop path under the DUT's KASAN kernel.

The probe is built against this tree's kernel and moal with
tools/dut/mwifiex-rx/build.py; ASK_MWIFIEX_RX_MODULE=DIR/ask_mwifiex_rx_test.ko
uses one built beforehand instead.
"""
import asyncio
import os
from pathlib import Path
import subprocess
import sys

import pytest

from ask_orch.uart import Console
from _flowtable_rig import (artifact_dir, command, console_command)

REPO = Path(__file__).resolve().parents[2]
SOURCE = REPO / "meta-ask/build/tmp/work/ask_ls1046a-oe-linux/nxp-mwifiex/git/git"
OBJCOPY = SOURCE.parent / "recipe-sysroot-native/usr/bin/aarch64-oe-linux/aarch64-oe-linux-objcopy"


@pytest.fixture(scope="module")
def probe_module():
    """The probe, built against this tree's kernel and moal unless one is
    given, without debug info: the DUT does not need it, and it is most of
    the module's size on a 115200-baud line."""
    dest = artifact_dir("mwifiex-rx-probe")
    given = os.environ.get("ASK_MWIFIEX_RX_MODULE")
    if given:
        built = Path(given)
    else:
        result = subprocess.run([sys.executable, str(REPO / "tools/dut/mwifiex-rx/build.py"), str(dest)],
                                capture_output=True, text=True)
        assert result.returncode == 0, result.stdout + result.stderr
        built = dest / "ask_mwifiex_rx_test.ko"
    stripped = dest / "ask_mwifiex_rx_test.stripped.ko"
    subprocess.run([str(OBJCOPY), "--strip-debug", str(built), str(stripped)], check=True)
    return stripped


async def test_mwifiex_receive_drop(aiohttp_session, target_agent, splat_window, probe_module):
    module = probe_module
    # Refuse to test a different driver from the one whose headers built the
    # probe. Compare the ELF note directly, without depending on DUT readelf.
    note = module.parent / "moal-build-id.note"
    subprocess.run([str(OBJCOPY), "--dump-section", f".note.gnu.build-id={note}",
                    str(SOURCE / "moal.ko"), str(module.parent / "moal-copy.ko")], check=True)
    actual = await target_agent.fs_read(aiohttp_session, "/sys/module/moal/notes/.note.gnu.build-id")
    assert actual["errno"] == 0 and bytes.fromhex(actual["content_hex"]) == note.read_bytes(), actual
    path = "/tmp/ask_mwifiex_rx_test.ko"
    data = module.read_bytes()
    # Allow the line about 2 KB/s, well under what it carries, plus margin.
    result = await target_agent.fs_write(aiohttp_session, path, data,
                                         timeout_ms=30000 + len(data) // 2)
    assert result["errno"] == 0 and result["rc"] == len(data), result
    with Console.target(log_path=str(artifact_dir() / "mwifiex-rx-uart.log")) as con:
        await asyncio.to_thread(con.login, "root", None)
        try:
            await command(target_agent, aiohttp_session, "insmod", path)
            await command(target_agent, aiohttp_session, "rmmod", "ask_mwifiex_rx_test")
            log = await command(target_agent, aiohttp_session, "dmesg")
            assert "mwifiex RX cleanup: 64 detached EasyMesh drops passed" in log["stdout"]
        finally:
            await command(target_agent, aiohttp_session, "rmmod", "ask_mwifiex_rx_test", check=False)
            await console_command(con, "rm", "-f", path)
