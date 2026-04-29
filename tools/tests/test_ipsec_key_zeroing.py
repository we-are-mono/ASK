"""H2 regression — IPsec SA key material zeroed on free.

PARKED — kernel-side observability gap. See ISSUES.md A14.

The H2 fix (613efa3) replaced kfree on the cipher_key/auth_key/split_key
fields with kfree_sensitive in cdx_ipsec_sec_sa_context_free. That
zeroes the key bytes BEFORE handing the slab back. There is no
user-space-observable surface that tells us whether the freed slab
still contains the original key bytes:

  - kmemleak only reports references to leaked OBJECTS, not the
    contents of freed memory.
  - KASAN poisons freed slab to prevent UAF reads, but the poison
    pattern is internal and not exposed; we can't read freed memory
    from user space anyway.
  - Allocating again to land in the same slab and inspecting bytes is
    racy and the slab allocator may reuse without zero-fill of its
    own — false negatives both ways.

Until a kernel-side debug probe (a debugfs file or trace event that
samples freed-but-not-yet-reused key slab contents) lands, this
regression test cannot be written cleanly. Documented in ISSUES.md
A14; this file marks the parked location so future kernel work
unlocks it without re-discovering the gap.
"""

from __future__ import annotations

import pytest


@pytest.mark.skip(reason="A14: H2 key-zeroing regression requires kernel-side observability probe")
async def test_ipsec_key_zeroing_after_free():
    pass
