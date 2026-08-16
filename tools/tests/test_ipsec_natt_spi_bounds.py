"""H5 regression — NAT-T per-flow SPI array bound is `>=` not `>`.

PARKED — synthetic-SA can't reach the H5 bounds-check site (needs a
real-peer fixture). The A18 NULL-deref that once blocked this is fixed.

The H5 fix (613efa3) flipped the bounds check at
cdx/cdx_dpa_ipsec.c from `> MAX_SPI_PER_FLOW` to
`>= MAX_SPI_PER_FLOW` so arr_index = MAX_SPI_PER_FLOW (one past array
end) is correctly rejected.

Reaching that bounds check requires:
  - A first NAT-T SA in a given flow successfully pushes through
    SET_STATE so cdx_ipsec_process_udp_classification_table_entry's
    `else` branch (which establishes sa->ct) completes — but for
    synthetic SAs cdx_ipsec_add_classification_table_entry fails to
    populate sa->ct (no real iface/route) and now returns
    ERR_CREATION_FAILED cleanly — the former A18 NULL-deref and the
    discarded return are both fixed.
  - A second-onward NAT-T SA in the same flow then hits the if-branch
    where the bounds check sits.

The bounds-check failure now propagates as ERR_CREATION_FAILED
(ipsec_push_sa_to_fast_path, control_ipsec.c:663), so reply_rc is a
usable oracle for it — but reaching the site still needs a real-peer
SA install flowing through the fast-path push, ideally under KASAN so
an OOB write (if `>=` regressed back to `>`) is caught too.

Deferred until a real-peer fixture exists.
"""

from __future__ import annotations

import pytest


@pytest.mark.skip(reason="synthetic-SA can't reach the H5 bounds-check site (NAT-T fast-path push needs a real iface/route); needs a real-peer fixture under KASAN")
async def test_ipsec_natt_spi_at_max():
    pass


@pytest.mark.skip(reason="same as test_ipsec_natt_spi_at_max — needs a real-peer fixture under KASAN")
async def test_ipsec_natt_spi_over_max():
    pass
