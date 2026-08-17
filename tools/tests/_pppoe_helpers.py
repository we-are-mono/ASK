"""Shared PPPoE FCI helpers.

Wire layout for CMD_PPPOE_ENTRY (44 bytes) lives in
cdx/control_pppoe.h:35-42 (struct _tPPPoECommand). The fcode encodes the
event class (PPPoE = 0x06) in the high byte and the command index
(ENTRY = 0x01) in the low byte; callers pass the 16-bit fcode directly
to fci_send.

Action constants are read off the switch in PPPoE_Handle_Entry
(cdx/control_pppoe.c:93-177). Length validation is enforced by
cdx_dispatch_cmd via the CDX_CMD min/max length plumbed off
sizeof(PPPoECommand) — handlers don't repeat the check.
"""

from __future__ import annotations

import struct


CMD_PPPOE_ENTRY = 0x0601  # cdx/cdx_cmdhandler.h:126

ACTION_REGISTER   = 0
ACTION_DEREGISTER = 1
ACTION_QUERY      = 6
ACTION_QUERY_CONT = 7

IF_NAME_SIZE = 16


# Symbol substrings used to scope kmemleak filtering to the PPPoE handler
# call graph. Each name is verified against cdx/control_pppoe.c — anything
# added by analogy to other subsystems gets dropped on first false-positive
# rather than left in to mask a real leak.
PPPOE_LEAK_FILTER = [
    "PPPoE_Handle_Entry",        # endpoint REGISTER/DEREGISTER/QUERY
    "pppoe_entry_handle",        # dispatch wrapper
    "M_pppoe_cmdproc",           # event dispatcher
    "pppoe_alloc",               # the allocator failslab targets
    "pppoe_add",                 # cache insertion that follows alloc
]


def pppoe_cmd(
    action: int,
    session_id: int = 0,
    mac: bytes = b"\x00" * 6,
    phy_intf: bytes = b"",
    log_intf: bytes = b"",
    mode: int = 0,
) -> bytes:
    """Build a 44-byte PPPoECommand wire payload.

    struct PPPoECommand (cdx/control_pppoe.h:35-42) is not __packed; the
    trailing fields land on natural boundaries. The wire layout is:

        action(U16) sessionID(U16) macAddr[6] phy_intf[16] log_intf[16] mode(U16)

    sessionID is byte-swapped to network order by the handler at
    cdx/control_pppoe.c:89, so callers pass it host-endian here.
    """
    return (
        struct.pack("<HH", action, session_id)
        + mac.ljust(6, b"\x00")[:6]
        + phy_intf.ljust(IF_NAME_SIZE, b"\x00")[:IF_NAME_SIZE]
        + log_intf.ljust(IF_NAME_SIZE, b"\x00")[:IF_NAME_SIZE]
        + struct.pack("<H", mode)
    )
