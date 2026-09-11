"""QoS command regressions that preserve the board's current configuration."""

import struct

import pytest

from _topology import TARGET_LAN_IF, TARGET_WAN_IF

CMD_QM_QUERY = 0x020D
CMD_QM_CHNL_ASSIGN = 0x0217
CMD_QM_QUERY_QUEUE = 0x0221
CMD_OK = 0
CMD_ERR = 0xFFFE
CHANNELS = 8
QUEUES = 16
PORT_QUERY_SIZE = 164
QUEUE_QUERY_SIZE = 100


async def _send(agent, session, code, payload):
    reply = await agent.fci_send(session, fcode=code, length=len(payload),
                                 payload=payload, timeout_ms=2000)
    assert not reply.get("send_error"), reply
    return reply


async def _config(agent, session, iface):
    payload = struct.pack("<HH16s", 0, 0, iface.encode())
    payload += bytes(PORT_QUERY_SIZE - len(payload))
    reply = await _send(agent, session, CMD_QM_QUERY, payload)
    assert reply.get("reply_rc") == CMD_OK, reply
    data = bytes.fromhex(reply["payload_hex"])
    assert len(data) == PORT_QUERY_SIZE, reply
    assert data[4:20].rstrip(b"\0") == iface.encode(), reply
    enabled, shaper = struct.unpack_from("<II", data, 20)
    assert enabled in (0, 1) and shaper in (0, 1), reply
    return data


@pytest.mark.parametrize("iface", [TARGET_LAN_IF, TARGET_WAN_IF])
@pytest.mark.parametrize("channel", [CHANNELS, 0xFFFFFFFF])
async def test_qos_invalid_assignment_preserves_config(
    aiohttp_session, target_agent, splat_window, iface, channel,
):
    before = await _config(target_agent, aiohttp_session, iface)
    payload = struct.pack("<HH16sI", 0, 0, iface.encode(), channel)
    reply = await _send(target_agent, aiohttp_session, CMD_QM_CHNL_ASSIGN, payload)
    assert reply.get("reply_rc") == CMD_ERR, reply
    assert await _config(target_agent, aiohttp_session, iface) == before


@pytest.mark.parametrize("channel,queue", [
    (CHANNELS, 0), (0xFFFFFFFF, 0), (0, QUEUES), (0, 0xFFFFFFFF),
])
async def test_qos_queue_query_bounds(
    aiohttp_session, target_agent, splat_window, channel, queue,
):
    payload = struct.pack("<HHIII", 0, 0, channel, queue, 0)
    payload += bytes(QUEUE_QUERY_SIZE - len(payload))
    reply = await _send(target_agent, aiohttp_session, CMD_QM_QUERY_QUEUE, payload)
    assert reply.get("reply_rc") == CMD_ERR, reply


async def test_qos_all_queues_remain_queryable(
    aiohttp_session, target_agent, splat_window,
):
    before = {iface: await _config(target_agent, aiohttp_session, iface)
              for iface in (TARGET_LAN_IF, TARGET_WAN_IF)}
    fqids = set()
    for channel in range(CHANNELS):
        for queue in range(QUEUES):
            payload = struct.pack("<HHIII", 0, 0, channel, queue, 0)
            payload += bytes(QUEUE_QUERY_SIZE - len(payload))
            reply = await _send(target_agent, aiohttp_session, CMD_QM_QUERY_QUEUE, payload)
            assert reply.get("reply_rc") == CMD_OK, reply
            data = bytes.fromhex(reply["payload_hex"])
            assert len(data) == QUEUE_QUERY_SIZE, reply
            assert struct.unpack_from("<II", data, 4) == (channel, queue)
            fqid = struct.unpack_from("<I", data, 32)[0] & 0xFFFFFF
            assert fqid and fqid not in fqids, reply
            fqids.add(fqid)
    for iface, config in before.items():
        assert await _config(target_agent, aiohttp_session, iface) == config
