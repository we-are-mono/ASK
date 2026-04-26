"""Phase 2 item 4d: netfilter / netlink hook coverage — DEFERRED.

The test would assert that abm_br_event(BREVENT_FDB_UPDATE) fires the
L2FLOW_ENTRY_NEW/UPDATE/DEL netlink notifications via
abm_do_work_send_msg → abm_nl_send_l2flow_msg, observable on
NETLINK_L2FLOW (protocol 33) multicast group L2FLOW_NL_GRP=1.

The Phase 2 plan made shipping 4d conditional on either
  (a) `ip monitor` (or another already-allowlisted tool) being able
      to capture these notifications, or
  (b) ≤30 LOC of new agent code.

Assessment:
  (a) Ruled out — `ip monitor` listens on NETLINK_ROUTE (protocol 0)
      only; abm uses its own protocol 33. `bridge monitor` similarly
      listens on NETLINK_ROUTE.
  (b) A minimal listener endpoint (open AF_NETLINK socket, bind, join
      group, recv with timeout, return hex-serialised messages) plus
      a client method clocks in at roughly 35 LOC across two files —
      just over the threshold. The test itself would add another
      ~80 LOC of capture-and-assert logic.

Per the plan's strict reading of the criteria, this defers to Phase 4
("system-level lifecycle"), where the netlink listener primitive
becomes shared infrastructure for both the abm netlink path and any
other netlink notifier coverage that phase needs. Implementing it
here would mean accepting an over-budget primitive for one test;
deferring lets it earn its keep across multiple consumers.
"""

import pytest


@pytest.mark.skip(
    reason="Phase 2 item 4d deferred to Phase 4 — see file docstring "
           "for the cost/benefit assessment per plan criteria."
)
def test_abm_netfilter_hook_deferred():
    """Tracking placeholder for the deferred test. Skipped intentionally."""
