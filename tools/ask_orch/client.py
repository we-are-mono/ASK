"""HTTP client for askd-agent. Thin wrapper over aiohttp."""

from __future__ import annotations

import os
from dataclasses import dataclass
import aiohttp


@dataclass
class Agent:
    name: str           # human label, e.g. "target", "lan", "wan"
    base_url: str       # e.g. "http://10.0.0.62:9110"

    async def health(self, session: aiohttp.ClientSession) -> dict:
        async with session.get(f"{self.base_url}/health", timeout=aiohttp.ClientTimeout(total=5)) as r:
            r.raise_for_status()
            return await r.json()

    async def counters(self, session: aiohttp.ClientSession, ifaces: list[str] | None = None) -> dict:
        params = [("iface", i) for i in (ifaces or [])]
        async with session.get(f"{self.base_url}/counters", params=params) as r:
            r.raise_for_status()
            return await r.json()

    async def capture_start(self, session: aiohttp.ClientSession, ifaces: list[str] | None = None) -> str:
        body = {"ifaces": ifaces or []}
        async with session.post(f"{self.base_url}/capture-start", json=body) as r:
            r.raise_for_status()
            return (await r.json())["capture_id"]

    async def capture_stop(self, session: aiohttp.ClientSession, cap_id: str) -> dict:
        async with session.post(f"{self.base_url}/capture-stop/{cap_id}") as r:
            r.raise_for_status()
            return await r.json()

    async def kmemleak(
        self,
        session: aiohttp.ClientSession,
        filter_substrs: list[str] | None = None,
    ) -> dict:
        params = []
        if filter_substrs:
            params.append(("filter", ",".join(filter_substrs)))
        async with session.get(
            f"{self.base_url}/kmemleak-scan",
            params=params,
            timeout=aiohttp.ClientTimeout(total=30),
        ) as r:
            return await r.json()

    async def kmemleak_clear(self, session: aiohttp.ClientSession) -> dict:
        async with session.post(
            f"{self.base_url}/kmemleak-clear",
            timeout=aiohttp.ClientTimeout(total=10),
        ) as r:
            r.raise_for_status()
            return await r.json()

    async def cmm_query(self, session: aiohttp.ClientSession, table: str = "connections") -> dict:
        async with session.post(f"{self.base_url}/cmm/query", json={"table": table}) as r:
            r.raise_for_status()
            return await r.json()

    async def fci_send(
        self,
        session: aiohttp.ClientSession,
        fcode: int,
        length: int,
        payload: bytes = b"",
        timeout_ms: int = 500,
        nlmsg_len_override: int | None = None,
    ) -> dict:
        body: dict = {
            "fcode":       fcode & 0xFFFF,
            "length":      length & 0xFFFF,
            "payload_hex": payload.hex(),
            "timeout_ms":  timeout_ms,
        }
        if nlmsg_len_override is not None:
            body["nlmsg_len_override"] = nlmsg_len_override
        async with session.post(f"{self.base_url}/fci/send", json=body) as r:
            r.raise_for_status()
            return await r.json()

    async def netlink_send(
        self,
        session: aiohttp.ClientSession,
        protocol: int,
        msg: bytes,
        *,
        nlmsg_type: int = 0,
        nlmsg_flags: int = 0,
        nlmsg_len_override: int | None = None,
        timeout_ms: int = 500,
    ) -> dict:
        body: dict = {
            "protocol":    protocol,
            "body_hex":    msg.hex(),
            "nlmsg_type":  nlmsg_type,
            "nlmsg_flags": nlmsg_flags,
            "timeout_ms":  timeout_ms,
        }
        if nlmsg_len_override is not None:
            body["nlmsg_len_override"] = nlmsg_len_override
        async with session.post(f"{self.base_url}/netlink/send", json=body) as r:
            r.raise_for_status()
            return await r.json()

    async def ioctl_send(
        self,
        session: aiohttp.ClientSession,
        device: str,
        cmd: int,
        data: bytes = b"",
        *,
        uid: int | None = None,
        timeout_ms: int = 1000,
    ) -> dict:
        body: dict = {
            "device":     device,
            "cmd":        int(cmd),
            "data_hex":   data.hex(),
            "timeout_ms": timeout_ms,
        }
        if uid is not None:
            body["uid"] = int(uid)
        async with session.post(f"{self.base_url}/ioctl/send", json=body) as r:
            r.raise_for_status()
            return await r.json()

    async def exec_cmd(
        self,
        session: aiohttp.ClientSession,
        argv: list[str],
        *,
        timeout_ms: int = 5000,
    ) -> dict:
        async with session.post(
            f"{self.base_url}/exec",
            json={"argv": argv, "timeout_ms": timeout_ms},
        ) as r:
            r.raise_for_status()
            return await r.json()

    async def fs_write(
        self,
        session: aiohttp.ClientSession,
        path: str,
        content: str | bytes,
        *,
        uid: int | None = None,
        timeout_ms: int = 1000,
    ) -> dict:
        body: dict = {
            "path":       path,
            "content":    content if isinstance(content, str) else content.decode("latin-1"),
            "timeout_ms": timeout_ms,
        }
        if uid is not None:
            body["uid"] = int(uid)
        async with session.post(f"{self.base_url}/fs/write", json=body) as r:
            r.raise_for_status()
            return await r.json()


# Node endpoints — overridable via env so the harness works on anyone's
# lab setup. The orchestrator runs on the WAN-side host; LAN is the
# traffic-generator VM/box behind the DUT's NAT.
_DEFAULT_PORT = "9110"

TARGET = Agent("target", f"http://{os.environ.get('ASK_TARGET_IP', '10.0.0.62')}:{_DEFAULT_PORT}")
LAN    = Agent("lan",    f"http://{os.environ.get('ASK_LAN_IP',    '172.30.0.10')}:{_DEFAULT_PORT}")
WAN    = Agent("wan",    f"http://{os.environ.get('ASK_WAN_IP',    '127.0.0.1')}:{_DEFAULT_PORT}")
