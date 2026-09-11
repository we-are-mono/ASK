"""Exercise the production RTP payload handler under ASan/UBSan."""

from pathlib import Path
import os
import re
import subprocess


ROOT = Path(__file__).resolve().parents[2]


def _definition(source, start, typedef=False):
    begin = source.index(start)
    end = source.index("{", begin) + 1
    depth = 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    if typedef:
        end = source.index(";", end) + 1
    return source[begin:end] + "\n"


def test_rtp_payload_bounds(tmp_path):
    header = (ROOT / "cdx/module_rtp_relay.h").read_text()
    errors = (ROOT / "cdx/fe.h").read_text()
    constants = re.search(r"^#define RTP_SPECIAL_PAYLOAD_LEN\s+\d+", header, re.M).group()
    for name in ("NO_ERR", "ERR_WRONG_COMMAND_SIZE", "ERR_RTP_UNKNOWN_CALL",
                 "ERR_RTP_SPECIAL_PKT_LEN"):
        value = re.search(r"\b" + name + r"\s*=\s*(\d+)", errors).group(1)
        constants += f"\n#define {name} {value}"
    (tmp_path / "rtp_types.inc").write_text(
        constants + "\n"
        + _definition((ROOT / "cdx/list.h").read_text(), "struct slist_entry\n") + ";\n"
        + _definition(header, "typedef struct _tRTPcall {", typedef=True)
        + _definition(header, "typedef struct _tRTPSpecTxPayloadCommand {", typedef=True)
    )
    (tmp_path / "rtp_handler.inc").write_text(_definition(
        (ROOT / "cdx/control_rtp_relay.c").read_text(),
        "static U16 RTP_Call_SpecialTx_Payload ",
    ))
    (tmp_path / "check.c").write_text(r"""
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint8_t U8;
typedef uint16_t U16;
#include "rtp_types.inc"

static RTPCall call;

static PRTPCall RTP_find_call(U16 id)
{
    return id == call.call_id ? &call : NULL;
}

#include "rtp_handler.inc"

int main(void)
{
    const unsigned ids[] = {0, 1, UINT16_MAX};
    RTPSpecTxPayloadCommand cmd = {.CallID = 1};
    RTPCall before;

    memset(cmd.payload, 0x3c, sizeof(cmd.payload));
    /* Every valid length, then one byte over the limit and the largest
     * wire value. Nonzero IDs keep selecting the second payload slot. */
    for (unsigned id = 0; id < sizeof(ids) / sizeof(ids[0]); id++) {
        cmd.payloadID = ids[id];
        for (unsigned len = 0; len <= RTP_SPECIAL_PAYLOAD_LEN + 2; len++) {
            cmd.payloadLength = len == RTP_SPECIAL_PAYLOAD_LEN + 2 ? UINT16_MAX : len;
            memset(&call, 0xa5, sizeof(call));
            call.call_id = cmd.CallID;
            memcpy(&before, &call, sizeof(before));
            U16 rc = RTP_Call_SpecialTx_Payload((U16 *)&cmd, sizeof(cmd));

            if (cmd.payloadLength > RTP_SPECIAL_PAYLOAD_LEN) {
                assert(rc == ERR_RTP_SPECIAL_PKT_LEN);
                assert(memcmp(&call, &before, sizeof(call)) == 0);
                continue;
            }
            assert(rc == NO_ERR);
            U8 *selected = ids[id] ? call.Next_Special_payload2 : call.Next_Special_payload1;
            size_t offset = selected - (U8 *)&call;
            for (size_t i = 0; i < sizeof(call); i++) {
                U8 expected = ((U8 *)&before)[i];
                if (i >= offset && i < offset + RTP_SPECIAL_PAYLOAD_LEN)
                    expected = i - offset < cmd.payloadLength ? 0x3c : 0;
                assert(((U8 *)&call)[i] == expected);
            }
        }
    }

    cmd.payloadLength = RTP_SPECIAL_PAYLOAD_LEN;
    memcpy(&before, &call, sizeof(before));
    for (unsigned len = 0; len < sizeof(cmd); len++) {
        assert(RTP_Call_SpecialTx_Payload((U16 *)&cmd, len) == ERR_WRONG_COMMAND_SIZE);
        assert(memcmp(&call, &before, sizeof(call)) == 0);
    }
    cmd.CallID++;
    assert(RTP_Call_SpecialTx_Payload((U16 *)&cmd, sizeof(cmd)) == ERR_RTP_UNKNOWN_CALL);
    assert(memcmp(&call, &before, sizeof(call)) == 0);
    puts("RTP payload boundary and state-preservation checks passed");
}
""")
    binary = tmp_path / "rtp_payload"
    subprocess.run([
        os.environ.get("CC", "cc"), "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-fno-pie", "-no-pie",
        str(tmp_path / "check.c"), "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True, timeout=10,
                   env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
                        "UBSAN_OPTIONS": "halt_on_error=1"})
