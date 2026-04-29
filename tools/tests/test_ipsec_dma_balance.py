"""H3 regression — DMA mappings unwound on partial-init failure.

PARKED — synthetic-SA can't reach the H3 fix site. See ISSUES.md A18.

The H3 fix (613efa3) added a two-label unwind in
cdx_ipsec_create_shareddescriptor (cdx/cdx_dpa_ipsec.c err_unmap_crypto
+ err_unmap_auth) plus SA_SH_DESC_BUILT rollback in
cdx_ipsec_add_classification_table_entry — both reached via
ipsec_push_sa_to_fast_path during CMD_IPSEC_SA_SET_STATE.

Reaching either site requires the SA's fast-path push to succeed past
sa->ct allocation. For synthetic SAs (no real iface bound to dst_ip,
no realistic netdev/route), cdx_ipsec_add_classification_table_entry
fails earlier at dpa_get_iface_info_by_ipaddress — and on the NAT-T
variant the failure path NULL-derefs sa->ct (A18, separate bug). The
non-NAT-T path returns ERR_CREATION_FAILED cleanly but never reaches
the DMA-map kmalloc inside cdx_ipsec_create_shareddescriptor.

This regression test is therefore deferred to slice 2's real-peer
fixture, where the SA install completes the fast-path push and
failslab can fault inside the DMA-map kmalloc to exercise the H3
unwind. The kmemleak filter is already extended in
_ipsec_helpers.IPSEC_DMA_LEAK_FILTER for that future use.
"""

from __future__ import annotations

import pytest


@pytest.mark.skip(reason="A18: synthetic-SA can't reach H3 DMA-map site without crashing or short-circuiting; needs slice-2 real-peer fixture")
async def test_ipsec_set_state_dma_balance():
    pass
