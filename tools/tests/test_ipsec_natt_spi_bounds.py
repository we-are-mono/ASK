"""H5 regression — NAT-T per-flow SPI array bound is `>=` not `>`.

PARKED — synthetic-SA can't reach the H5 fix site. See ISSUES.md A18.

The H5 fix (613efa3) flipped the bounds check at
cdx/cdx_dpa_ipsec.c from `> MAX_SPI_PER_FLOW` to
`>= MAX_SPI_PER_FLOW` so arr_index = MAX_SPI_PER_FLOW (one past array
end) is correctly rejected.

Reaching that bounds check requires:
  - A first NAT-T SA in a given flow successfully pushes through
    SET_STATE so cdx_ipsec_process_udp_classification_table_entry's
    `else` branch (which establishes sa->ct) completes — but for
    synthetic SAs it triggers A18 (NULL deref because
    cdx_ipsec_add_classification_table_entry fails to populate sa->ct
    yet ipsec_push_sa_to_fast_path discards its return value).
  - A second-onward NAT-T SA in the same flow then hits the if-branch
    where the bounds check sits.

Even if A18 is fixed, the bounds-check failure return is silently
discarded by ipsec_push_sa_to_fast_path (control_ipsec.c:720), so
reply_rc stays NO_ERR — the only effective oracle is splat_window /
KASAN catching the OOB write that would happen if `>=` regressed back
to `>`. That requires KASAN-enabled images and real-peer SA install
flowing through the fast-path push successfully.

Deferred to slice 2's real-peer fixture under KASAN.
"""

from __future__ import annotations

import pytest


@pytest.mark.skip(reason="A18: synthetic-SA can't reach H5 bounds-check site (NAT-T fast-path push NULL-derefs without real iface/route); needs slice-2 real-peer fixture under KASAN")
async def test_ipsec_natt_spi_at_max():
    pass


@pytest.mark.skip(reason="A18: same as test_ipsec_natt_spi_at_max — needs slice-2 real-peer fixture under KASAN")
async def test_ipsec_natt_spi_over_max():
    pass
