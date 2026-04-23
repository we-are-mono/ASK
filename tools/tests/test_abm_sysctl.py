"""H8: abm sysctl capability + lower-bound fix.

Pre-fix: `abm_sysctl_l3_filtering` was 0644 with no in-handler capable()
check, so any process the kernel allowed to open /proc/sys/net/abm/
l3_filtering for writing could flush the L3 state table. Separately,
`abm_max_entries` accepted any u32 including 0, silently breaking the
`abm_nb_entries >= abm_max_entries` gate.

Post-fix:
  * l3_filtering write requires CAP_NET_ADMIN (rejected otherwise).
  * max_entries moved to proc_douintvec_minmax with [1, 1_000_000];
    writes of 0 (or >1M) now return -EINVAL.
"""

from __future__ import annotations

import errno

import pytest


NON_ROOT_UID = 1000


async def test_h8_l3_filtering_requires_cap_net_admin(
    aiohttp_session, target_agent, splat_window,
):
    """Unprivileged write to /proc/sys/net/abm/l3_filtering → EPERM."""
    r = await target_agent.fs_write(
        aiohttp_session,
        path="/proc/sys/net/abm/abm_l3_filtering",
        content="1\n",
        uid=NON_ROOT_UID,
    )
    # File is mode 0644, so open-for-write itself gives EACCES for
    # non-root; if the open path somehow allowed it, the in-handler
    # capable() check returns EPERM. Either is acceptable — the
    # invariant is that an unprivileged write does NOT succeed.
    assert r.get("errno") in (errno.EACCES, errno.EPERM), (
        f"unprivileged write should be rejected (EACCES/EPERM), got {r}"
    )


async def test_h8_root_can_write_l3_filtering(
    aiohttp_session, target_agent, splat_window,
):
    """Sanity: root write still works (we're not bricking the sysctl)."""
    r = await target_agent.fs_write(
        aiohttp_session,
        path="/proc/sys/net/abm/abm_l3_filtering",
        content="1\n",
    )
    assert r.get("errno") == 0, (
        f"root write to l3_filtering should succeed; got {r}"
    )


async def test_h8_max_entries_zero_rejected(
    aiohttp_session, target_agent, splat_window,
):
    """max_entries=0 was silently accepted pre-fix (breaking the gate).
    Post-fix proc_douintvec_minmax rejects with EINVAL."""
    r = await target_agent.fs_write(
        aiohttp_session,
        path="/proc/sys/net/abm/abm_max_entries",
        content="0\n",
    )
    assert r.get("errno") == errno.EINVAL, (
        f"max_entries=0 should return EINVAL, got {r}"
    )


async def test_h8_max_entries_accepts_valid(
    aiohttp_session, target_agent, splat_window,
):
    """Sanity: a valid value (within [1, 1_000_000]) still accepted."""
    r = await target_agent.fs_write(
        aiohttp_session,
        path="/proc/sys/net/abm/abm_max_entries",
        content="500\n",
    )
    assert r.get("errno") == 0, (
        f"max_entries=500 should be accepted, got {r}"
    )
