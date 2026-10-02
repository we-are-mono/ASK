"""Run the real moal receive-drop path under the DUT's KASAN kernel.

Build the probe first with tools/dut/mwifiex-rx/build.py DIR, then set
ASK_MWIFIEX_RX_MODULE=DIR/ask_mwifiex_rx_test.ko when running this test.
"""
import asyncio
import base64
import os
from pathlib import Path
import subprocess

from ask_orch.uart import Console
from test_flowtable_offload import ARTIFACTS, command, console_command


async def test_mwifiex_receive_drop(aiohttp_session, target_agent, splat_window):
    module = Path(os.environ["ASK_MWIFIEX_RX_MODULE"])
    source = Path(__file__).resolve().parents[2] / "meta-ask/build/tmp/work/ask_ls1046a-oe-linux/nxp-mwifiex/git/git"
    # Refuse to test a different driver from the one whose headers built the
    # probe. Compare the ELF note directly, without depending on DUT readelf.
    note = module.parent / "moal-build-id.note"
    objcopy = source.parent / "recipe-sysroot-native/usr/bin/aarch64-oe-linux/aarch64-oe-linux-objcopy"
    subprocess.run([str(objcopy), "--dump-section", f".note.gnu.build-id={note}",
                    str(source / "moal.ko"), str(module.parent / "moal-copy.ko")], check=True)
    actual = await target_agent.fs_read(aiohttp_session, "/sys/module/moal/notes/.note.gnu.build-id")
    assert actual["errno"] == 0 and bytes.fromhex(actual["content_hex"]) == note.read_bytes(), actual
    path = "/tmp/ask_mwifiex_rx_test.ko"
    encoded = base64.b64encode(module.read_bytes()).decode()
    result = await target_agent.fs_write(aiohttp_session, path + ".b64", encoded)
    assert result["errno"] == 0, result
    with Console.target(log_path=str(ARTIFACTS / "mwifiex-rx-uart.log")) as con:
        await asyncio.to_thread(con.login, "root", None)
        try:
            await console_command(con, "sh", "-c", f"base64 -d {path}.b64 > {path}")
            await command(target_agent, aiohttp_session, "insmod", path)
            await command(target_agent, aiohttp_session, "rmmod", "ask_mwifiex_rx_test")
            log = await command(target_agent, aiohttp_session, "dmesg")
            assert "mwifiex RX cleanup: 64 detached EasyMesh drops passed" in log["stdout"]
        finally:
            await command(target_agent, aiohttp_session, "rmmod", "ask_mwifiex_rx_test", check=False)
            await console_command(con, "rm", "-f", path, path + ".b64")
