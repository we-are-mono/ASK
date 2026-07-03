"""Shared IPsec FCI helpers.

Wire layouts come from cdx/control_ipsec.h:69-216 and cdx/cdx_cmdhandler.h:208-224.
Unlike PPPoE's single-step REGISTER, an IPsec SA install requires four FCI
calls in sequence: CREATE, SET_KEYS, optional SET_NATT or SET_TUNNEL, and
SET_STATE. The orchestrator at the bottom of this module factors that out.

Sizes (validated against `gcc -c` of the actual struct definitions; ARM64
and x86_64 produce identical sizes for these layouts):

  CommandIPSecCreateSA  48 B   (struct definition: control_ipsec.h:96-100)
  CommandIPSecDeleteSA   4 B   (control_ipsec.h:102-105)
  CommandIPSecSetKey   144 B   (control_ipsec.h:107-113)
  CommandIPSecSetNatt    8 B   (control_ipsec.h:115-120)
  CommandIPSecSetState   8 B   (control_ipsec.h:122-127)
  SAQueryCommand       252 B   (control_ipsec.h:165-216, __packed)
                                 — the IPv6 union member dominates the
                                 tnl union at 36 B; ipv4 case is 12 B.
                                 Total = 184 + 36 + 4×8 = 252.

Two surprises worth pinning here so tests don't get blindsided:

  1. The H5 NAT-T SPI bounds check at cdx_dpa_ipsec.c:2369 fires inside
     cdx_ipsec_process_udp_classification_table_entry, which is called
     from ipsec_push_sa_to_fast_path (control_ipsec.c:720) — and that
     caller DISCARDS the return value. So a 17th NAT-T SA in the same
     flow returns NO_ERR to user-space even though the bounds check
     prevented an OOB write internally. The regression detector for H5
     is therefore splat_window/KASAN, not reply_rc.

  2. SA_SET_KEYS dereferences sa before the NULL check (control_ipsec.c:617
     vs the check at :619). Sending SET_KEYS for a sagd that doesn't exist
     panics. Tests that exercise SET_KEYS must ensure CREATE succeeded
     first.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass


# ---------------------------------------------------------------- command codes
CMD_IPSEC_SA_CREATE         = 0x0A01
CMD_IPSEC_SA_DELETE         = 0x0A02
CMD_IPSEC_SA_SET_KEYS       = 0x0A04
CMD_IPSEC_SA_SET_TUNNEL     = 0x0A05
CMD_IPSEC_SA_SET_NATT       = 0x0A06
CMD_IPSEC_SA_SET_STATE      = 0x0A07
CMD_IPSEC_SA_ACTION_QUERY   = 0x0A0A
CMD_IPSEC_SA_ACTION_QUERY_CONT = 0x0A0B

# ---------------------------------------------------------------- actions
ACTION_REGISTER   = 0
ACTION_DEREGISTER = 1
ACTION_QUERY      = 6
ACTION_QUERY_CONT = 7

# ---------------------------------------------------------------- protocol enums
PROTO_FAMILY_IPV4 = 2
PROTO_FAMILY_IPV6 = 10

SA_TYPE_ESP = 50
SA_TYPE_AH  = 51

SA_MODE_TRANSPORT = 0x0
SA_MODE_TUNNEL    = 0x1

NLKEY_SAFLAGS_ESN     = 0x1
NLKEY_SAFLAGS_INBOUND = 0x2

# SA states (control_ipsec.h:308-312)
SA_STATE_INIT    = 0x1
SA_STATE_VALID   = 0x2
SA_STATE_DEAD    = 0x3
SA_STATE_EXPIRED = 0x4
SA_STATE_DYING   = 0x5

# XFRM_STATE_VALID is the user-space-side state code that triggers fast-path
# push inside SET_STATE (control_ipsec.c:821 — distinct from SA_STATE_VALID).
# Cross-reference linux/include/net/xfrm.h: VOID=0, ACQ=1, VALID=2, ERROR=3,
# EXPIRED=4, DEAD=5. Sending anything other than VALID hits the else-branch
# at control_ipsec.c:851 which deletes the SA — verified empirically.
XFRM_STATE_VALID = 2

# ---------------------------------------------------------------- algorithms
# AES-CBC + HMAC-SHA2-256 chosen as a non-AEAD pair so cipher and auth key
# buffers each exercise distinct allocator paths inside
# cdx_ipsec_sec_sa_context_alloc. AES-GCM (algos 18-20) is also supported
# but is AEAD — auth_key buffer would be ignored, masking any auth-side
# allocator regression.
SADB_X_EALG_AESCBC          = 12   # control_ipsec.h:53
SADB_X_AALG_SHA2_256HMAC    = 5    # control_ipsec.h:38
SADB_X_AALG_NULL            = 251  # control_ipsec.h:43

# IPsec_key_desc.key_type: 1 = cipher, 0 = auth (control_ipsec.c:627)
KEY_TYPE_CIPHER = 1
KEY_TYPE_AUTH   = 0

# Limits
IPSEC_MAX_KEY_SIZE = 64    # control_ipsec.h:24
IPSEC_MAX_NUM_KEYS = 2     # control_ipsec.h:25
MAX_SPI_PER_FLOW   = 16    # sdk_fman/inc/Peripherals/fm_ehash.h:187
SAGD_BASE          = 0xF000  # synthetic-test sagd range; cmm is passive
                              # (cmm/src/module_ipsec.c:103,278) so collision
                              # risk is zero.

# ---------------------------------------------------------------- error codes
NO_ERR                  = 0
ERR_UNKNOWN_COMMAND     = 1
ERR_WRONG_COMMAND_SIZE  = 2
ERR_NOT_ENOUGH_MEMORY   = 6
ERR_CREATION_FAILED     = 7
ERR_SA_DUPLICATED        = 904
ERR_SA_DUPLICATED_HANDLE = 905
ERR_SA_UNKNOWN           = 906
ERR_SA_INVALID_CIPHER_KEY = 907
ERR_SA_INVALID_DIGEST_KEY = 908
ERR_SA_ENTRY_NOT_FOUND   = 909

# ---------------------------------------------------------------- leak filter
# Each name verified against cdx/control_ipsec.c + cdx/cdx_dpa_ipsec.c via
# grep. Anything added by analogy to other subsystems would mask real leaks
# and gets dropped on first false-positive.
IPSEC_LEAK_FILTER = [
    "M_ipsec_cmdproc",                                  # control_ipsec.c:1140
    "M_ipsec_sa_cache_create",                          # SA struct allocator
    "IPsec_handle_CREATE_SA",                           # control_ipsec.c:460
    "IPsec_handle_SA_SET_KEYS",                         # control_ipsec.c:600
    "IPsec_handle_SA_SET_NATT",                         # control_ipsec.c:685
    "IPsec_handle_SA_SET_STATE",                        # control_ipsec.c:798
    "ipsec_create_sa_handle",                           # dispatch wrapper
    "ipsec_set_keys_handle",                            # dispatch wrapper
    "ipsec_push_sa_to_fast_path",                       # control_ipsec.c:716
    "cdx_ipsec_sec_sa_context_alloc",                   # cdx_dpa_ipsec.c:429
    "cdx_ipsec_sec_sa_context_free",                    # cdx_dpa_ipsec.c:240
    "cdx_ipsec_create_shareddescriptor",                # cdx_dpa_ipsec.c:1938
    "cdx_ipsec_add_classification_table_entry",         # cdx_dpa_ipsec.c:2397
    "cdx_ipsec_process_udp_classification_table_entry", # cdx_dpa_ipsec.c:2325
]

# Extension for the dma-balance test — kmemleak will surface DMA leaks
# under these symbol prefixes if the H3 unwind regresses.
IPSEC_DMA_LEAK_FILTER = IPSEC_LEAK_FILTER + [
    "dma_alloc_coherent",
    "dma_map_single",
    "__dma_alloc_pages",
]


# ---------------------------------------------------------------- payload builders

def create_sa(
    sagd: int,
    spi: int,
    dst_ip: int,
    *,
    src_ip: int = 0,
    sa_type: int = SA_TYPE_ESP,
    family: int = PROTO_FAMILY_IPV4,
    replay_window: int = 0,
    flags: int = NLKEY_SAFLAGS_INBOUND,
    mtu: int = 1500,
    dev_mtu: int = 1500,
) -> bytes:
    """Build a 50-byte CommandIPSecCreateSA wire payload.

    Layout: sagd(U16) rsvd(U16) + IPSec_said{spi(U32) sa_type(U8)
    proto_family(U8) replay_window(U8) flags(U8) dst_ip[4](U32)
    src_ip[4](U32) mtu(U16) dev_mtu(U16)}.

    dst_ip / src_ip are passed as a single u32 (the v4 case populates
    dst_ip[0]; tests that need v6 should call create_sa_v6 instead — not
    yet provided since slice-1 v4 coverage is enough).
    """
    return (
        struct.pack("<HH", sagd & 0xFFFF, 0)
        + struct.pack("<I", spi & 0xFFFFFFFF)
        + struct.pack("<BBBB", sa_type, family, replay_window, flags & 0xFF)
        + struct.pack("<IIII", dst_ip & 0xFFFFFFFF, 0, 0, 0)
        + struct.pack("<IIII", src_ip & 0xFFFFFFFF, 0, 0, 0)
        + struct.pack("<HH", mtu, dev_mtu)
    )


def delete_sa(sagd: int) -> bytes:
    """Build a 4-byte CommandIPSecDeleteSA payload."""
    return struct.pack("<HH", sagd & 0xFFFF, 0)


def _key_desc(key_alg: int, key_type: int, key: bytes) -> bytes:
    """One IPSec_key_desc (68 B): key_bits(U16) key_alg(U8) key_type(U8) key[64]."""
    if len(key) > IPSEC_MAX_KEY_SIZE:
        raise ValueError(f"key too long: {len(key)} > {IPSEC_MAX_KEY_SIZE}")
    return (
        struct.pack("<HBB", len(key) * 8, key_alg, key_type)
        + key.ljust(IPSEC_MAX_KEY_SIZE, b"\x00")
    )


def set_keys(
    sagd: int,
    *,
    cipher_alg: int = SADB_X_EALG_AESCBC,
    cipher_key: bytes = b"\xA5" * 16,
    auth_alg: int = SADB_X_AALG_SHA2_256HMAC,
    auth_key: bytes = b"\x5A" * 32,
) -> bytes:
    """Build a 144-byte CommandIPSecSetKey payload.

    Layout: sagd(U16) rsvd(U16) num_keys(U16) rsvd2(U16) keys[2] (each 68B).
    Cipher key first (key_type=1), auth key second (key_type=0) — matches
    the order IPsec_handle_SA_SET_KEYS iterates and the algorithm-id
    switch in M_ipsec_sa_set_cipher_key / M_ipsec_sa_set_digest_key.

    Recognizable byte patterns (0xA5 cipher, 0x5A auth) so the H2
    key-zeroing regression test can detect surviving cipher key bytes
    in the post-kfree_sensitive slab snapshot — see
    test_ipsec_key_zeroing.py.
    """
    return (
        struct.pack("<HH", sagd & 0xFFFF, 0)
        + struct.pack("<HH", IPSEC_MAX_NUM_KEYS, 0)
        + _key_desc(cipher_alg, KEY_TYPE_CIPHER, cipher_key)
        + _key_desc(auth_alg,   KEY_TYPE_AUTH,   auth_key)
    )


def set_natt(sagd: int, sport: int, dport: int = 4500) -> bytes:
    """Build an 8-byte CommandIPSecSetNatt payload."""
    return struct.pack("<HHHH", sagd & 0xFFFF, sport & 0xFFFF, dport & 0xFFFF, 0)


def set_state(sagd: int, state: int = XFRM_STATE_VALID) -> bytes:
    """Build an 8-byte CommandIPSecSetState payload."""
    return struct.pack("<HHHH", sagd & 0xFFFF, 0, state & 0xFFFF, 0)


def query_sa(action: int = ACTION_QUERY) -> bytes:
    """Build a 252-byte SAQueryCommand payload.

    The kernel populates most fields on response; we only need to set the
    `action` field to enter the query cursor. The QUERY entry path
    (control_ipsec.c QUERY handler) does not validate other fields before
    walking sa_cache, so an all-zeros payload after the action word is
    safe — verified empirically at slice-1 implementation time. If a
    future kernel change starts validating proto_family or sa_type before
    the cursor walk, tighten this to set the minimal required fields.
    """
    return struct.pack("<H", action & 0xFFFF) + b"\x00" * 250


# ---------------------------------------------------------------- orchestrator

@dataclass
class InstallResult:
    """Per-step outcomes for a 4-step SA install.

    `replies[step_name]` is the agent's reply dict for that FCI call;
    `infra_skip_reason` is set iff CREATE failed with an infra-class
    error (so the test should pytest.skip rather than fail). If a later
    step (set_keys/set_natt/set_state) fails, `infra_skip_reason` stays
    None — the test should fail loudly because it's a wire-format bug,
    not infra.
    """
    replies: dict[str, dict]
    infra_skip_reason: str | None


# Returned by CREATE when CAAM/DPAA infra isn't ready. Empirical — the
# specific code may need adjustment once we observe slice-1 reality.
# ERR_CREATION_FAILED comes from M_ipsec_sa_cache_create returning false,
# which on this build means the SA cache pool is empty or DPAA isn't up.
INFRA_CREATE_RC_SET = {ERR_CREATION_FAILED, ERR_NOT_ENOUGH_MEMORY}


async def install_sa_inbound(
    target_agent,
    aiohttp_session,
    sagd: int,
    *,
    spi: int,
    dst_ip: int,
    natt: bool = False,
    natt_sport: int = 0,
    natt_dport: int = 4500,
    failslab_step: str | None = None,
    failslab_times: int | None = None,
    timeout_ms: int = 3000,
) -> InstallResult:
    """Drive the 4-step SA install: CREATE → SET_KEYS → [SET_NATT] → SET_STATE.

    `failslab_step` selects which step is armed with `failslab_times`
    fail-Nth on the kernel side. Subsequent steps run unencumbered so
    we can observe whether the failed step's err-path unwound cleanly.
    """
    replies: dict[str, dict] = {}

    async def _send(step: str, fcode: int, payload: bytes) -> dict:
        kwargs = {}
        if step == failslab_step and failslab_times is not None:
            kwargs["failslab_times"] = failslab_times
        r = await target_agent.fci_send(
            aiohttp_session, fcode=fcode,
            length=len(payload), payload=payload,
            timeout_ms=timeout_ms, **kwargs,
        )
        replies[step] = r
        return r

    r = await _send("create", CMD_IPSEC_SA_CREATE, create_sa(sagd, spi, dst_ip))
    if r.get("reply_rc") in INFRA_CREATE_RC_SET and step_failed_unencumbered("create", failslab_step):
        return InstallResult(
            replies=replies,
            infra_skip_reason=(
                f"CREATE returned reply_rc={r.get('reply_rc')!r} unencumbered "
                f"— CAAM/DPAA infra likely not ready. send_error={r.get('send_error')!r}"
            ),
        )
    # If CREATE was the failslab step, a NULL allocation is expected; bail
    # without continuing so the caller sees the fault outcome cleanly.
    if r.get("reply_rc") != NO_ERR:
        return InstallResult(replies=replies, infra_skip_reason=None)

    r = await _send("set_keys", CMD_IPSEC_SA_SET_KEYS, set_keys(sagd))
    if r.get("reply_rc") != NO_ERR:
        return InstallResult(replies=replies, infra_skip_reason=None)

    if natt:
        r = await _send("set_natt", CMD_IPSEC_SA_SET_NATT,
                        set_natt(sagd, sport=natt_sport, dport=natt_dport))
        if r.get("reply_rc") != NO_ERR:
            return InstallResult(replies=replies, infra_skip_reason=None)

    await _send("set_state", CMD_IPSEC_SA_SET_STATE, set_state(sagd))
    return InstallResult(replies=replies, infra_skip_reason=None)


def step_failed_unencumbered(step: str, failslab_step: str | None) -> bool:
    """True iff `step` ran without failslab armed (i.e. its failure is
    interpretable as infra-class rather than fault-injection-induced)."""
    return failslab_step != step


async def cleanup_sa(target_agent, aiohttp_session, sagd: int) -> None:
    """Best-effort DELETE; ignore reply_rc. Tests use this in finally blocks
    to keep the SA cache clean between iterations."""
    await target_agent.fci_send(
        aiohttp_session, fcode=CMD_IPSEC_SA_DELETE,
        length=4, payload=delete_sa(sagd), timeout_ms=2000,
    )
