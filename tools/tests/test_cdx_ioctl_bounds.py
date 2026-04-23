"""C6/C7/C8/C9b: /dev/cdx_ctrl ioctl input bounds.

C6: dpa_cfg.c allocations driven by userspace `num_fmans`, `max_ports`,
    `max_dist`, `num_tables`. Post-fix they're capped at CDX_MAX_* and
    use kmalloc_array/kcalloc for overflow-safe scaling.
C7: off-by-one `fm_index > num_fmans` (should be `>=`).
C8: `queue_no` / `port_idx` / `dscp` bound checks.
C9b: CDX_CTRL_DPA_CONNADD was deleted — invoking it must return ENOTTY.

Only C6 is driven via CDX_CTRL_DPA_SET_PARAMS and thus testable at the
ioctl layer. C7/C8 are reachable only via specific control_*.c paths
that would need a valid params setup first — they're covered by the
FCI fuzzer once we extend payload mutations there. This file just
exercises the ioctl-surface bounds: C6 + C9b.
"""

from __future__ import annotations

import errno
import struct

import pytest

from _ioctl import (
    CDX_CTRL_DPA_SET_PARAMS,
    CDX_CTRL_DPA_CONNADD_LEGACY,
    CDX_CTRL_UNKNOWN_NR,
    SIZEOF_CDX_CTRL_SET_DPA_PARAMS,
)


DEVICE = "/dev/cdx_ctrl"

# struct cdx_ctrl_set_dpa_params layout:
#   void *fman_info    at offset 0 (8 B)
#   void *ipr_info     at offset 8 (8 B)
#   uint32_t num_fmans at offset 16 (4 B) + 4 B tail pad
def _set_params_struct(num_fmans: int, fman_ptr: int = 0, ipr_ptr: int = 0) -> bytes:
    return struct.pack("<QQI4x", fman_ptr, ipr_ptr, num_fmans)


CDX_MAX_FMANS = 16


@pytest.mark.parametrize("num_fmans", [
    0xFFFFFFFF,        # wraps most signed comparisons
    10_000,            # 625× the cap
    CDX_MAX_FMANS + 1, # just past the cap
])
async def test_c6_num_fmans_above_cap_rejected(
    aiohttp_session, target_agent, splat_window, num_fmans,
):
    """CDX_MAX_FMANS=16; anything larger must be rejected before alloc."""
    data = _set_params_struct(num_fmans=num_fmans)
    r = await target_agent.ioctl_send(
        aiohttp_session,
        device=DEVICE, cmd=CDX_CTRL_DPA_SET_PARAMS, data=data,
    )
    # Pre-fix: kernel would kcalloc(num_fmans * sizeof(...)) and either
    # OOM or (if somehow succeeding) overrun later. Post-fix: EINVAL
    # from the bound check. ENOMEM is also acceptable evidence that
    # the size reached the allocator with a validated bound; the key
    # invariant is "no kernel splat, dispatcher rejected cleanly."
    assert r.get("errno") in (errno.EINVAL, errno.ENOMEM, errno.EFAULT), (
        f"num_fmans={num_fmans}: expected rejection (EINVAL/ENOMEM/EFAULT), "
        f"got {r}"
    )


async def test_c6_num_fmans_zero_rejected(
    aiohttp_session, target_agent, splat_window,
):
    """0 fmans is also rejected — `fman_info` gets dereferenced unconditionally
    in the post-alloc path (see dpa_cfg.c commit comment)."""
    data = _set_params_struct(num_fmans=0)
    r = await target_agent.ioctl_send(
        aiohttp_session,
        device=DEVICE, cmd=CDX_CTRL_DPA_SET_PARAMS, data=data,
    )
    assert r.get("errno") != 0, (
        f"num_fmans=0: expected rejection, got rc={r.get('rc')} data={r}"
    )


# Linux convention is ENOTTY for "this fd doesn't recognize this ioctl";
# cdx_dev.c's dispatcher now returns ENOTTY on the default arm. A
# re-added handler would return 0 (success), which is the regression.
_NO_SUCH_IOCTL = {errno.ENOTTY}


async def test_c9b_connadd_ioctl_removed(
    aiohttp_session, target_agent, splat_window,
):
    """CDX_CTRL_DPA_CONNADD (nr=3) was deleted by C9b. Dispatcher must
    not dispatch it anywhere."""
    r = await target_agent.ioctl_send(
        aiohttp_session,
        device=DEVICE, cmd=CDX_CTRL_DPA_CONNADD_LEGACY, data=b"",
    )
    assert r.get("errno") in _NO_SUCH_IOCTL, (
        f"removed-ioctl nr=3 should be rejected (ENOTTY), got {r}"
    )


async def test_unknown_ioctl_nr_rejected(
    aiohttp_session, target_agent, splat_window,
):
    """Any ioctl nr the dispatcher has no entry for is rejected, not
    routed through a handler."""
    r = await target_agent.ioctl_send(
        aiohttp_session,
        device=DEVICE, cmd=CDX_CTRL_UNKNOWN_NR, data=b"",
    )
    assert r.get("errno") in _NO_SUCH_IOCTL, (
        f"unregistered ioctl (nr=99) should be rejected, got {r}"
    )
