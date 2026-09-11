"""Exercise RTP command lengths and special payloads on a real relay call."""

import struct

import pytest

from _topology import TARGET_LAN_IF


# Command layouts in cdx/module_rtp_relay.h. Special TX and RTCP accept
# trailing bytes; the other handlers require an exact command size.
COMMANDS = [
    (0x0801, 8, True), (0x0802, 8, True), (0x0803, 28, True),
    (0x0804, 8, True), (0x0805, 166, False), (0x0806, 4, False),
    (0x0807, 4, False), (0x0808, 4, True), (0x0813, 2, True),
]
CALL = 0xF805
SOCKETS = (0xF806, 0xF807)
ROUTE = 0x0805A001


async def send(agent, session, code, payload):
    reply = await agent.fci_send(session, code, len(payload), payload, timeout_ms=3000)
    assert reply.get("send_error") is None, reply
    return reply.get("reply_rc")


@pytest.mark.parametrize("code,size,exact", COMMANDS,
                         ids=[f"0x{code:04x}" for code, _, _ in COMMANDS])
async def test_rtp_command_lengths(aiohttp_session, target_agent, splat_window,
                                   code, size, exact):
    lengths = {0, 1, size - 1}
    if exact:
        lengths.update((size + 1, 509))
    for length in sorted(lengths):
        rc = await send(target_agent, aiohttp_session, code, bytes(length))
        assert rc == 2, (hex(code), length, rc)


def route(action):
    return struct.pack(
        "<HH6sHHH16s16s16sII16s", action, 1500,
        bytes.fromhex("020000080501"), 0, 0, 0,
        TARGET_LAN_IF.encode(), b"", b"", ROUTE, 0, b"",
    )


def socket_open(socket_id, port):
    # SockOpenCommand: connected UDP socket, FPP type, explicit L2 route.
    return struct.pack(
        "<HBB4s4s2s2sBBHI", socket_id, 0, 1,
        bytes((192, 0, 2, 5)), bytes((198, 51, 100, 5)),
        struct.pack("!H", port), struct.pack("!H", port + 1),
        17, 0, 0, ROUTE,
    ) + bytes(28)


async def test_rtp_special_payload_bounds(aiohttp_session, target_agent, splat_window):
    async def command(code, payload):
        return await send(target_agent, aiohttp_session, code, payload)

    close = struct.pack("<HH", CALL, 0)
    await command(0x0808, close)
    for socket_id in SOCKETS:
        await command(0x0331, struct.pack("<HH", socket_id, 0))
    await command(0x0313, route(1))

    opened = []
    call_open = False
    assert await command(0x0313, route(0)) == 0
    try:
        for index, socket_id in enumerate(SOCKETS):
            assert await command(0x0330, socket_open(socket_id, 45000 + 2 * index)) == 0
            opened.append(socket_id)
        assert await command(0x0801, struct.pack("<4H", CALL, *SOCKETS, 0)) == 0
        call_open = True

        for slot in (0, 1, 65535):
            for length in (0, 1, 159, 160, 161, 65535, 160, 0):
                payload = struct.pack("<3H", CALL, slot, length) + bytes(range(160))
                rc = await command(0x0805, payload)
                assert rc == (1210 if length > 160 else 0), (slot, length, rc)

        # A valid control/query after rejected payloads checks that the call
        # and both socket statistics remain usable; KASAN checks the copies.
        payload = struct.pack("<3H", CALL, 0, 160) + bytes(range(160))
        assert await command(0x0805, payload.ljust(512, b"\xa5")) == 0
        assert await command(0x0804, struct.pack("<4H", CALL, 0, 0, 0)) == 0
        for socket_id in SOCKETS:
            for size in (4, 5, 512):
                payload = struct.pack("<HH", socket_id, 0).ljust(size, b"\xa5")
                assert await command(0x0807, payload) == 0
    finally:
        if call_open:
            assert await command(0x0808, close) == 0
        for socket_id in reversed(opened):
            assert await command(0x0331, struct.pack("<HH", socket_id, 0)) == 0
        assert await command(0x0313, route(1)) == 0
