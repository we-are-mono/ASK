/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef CDX_FLOWTABLE_HW_H
#define CDX_FLOWTABLE_HW_H

#include "cdx_flowtable_backend.h"

/* One statistics record held by the adapter rather than by a registered
 * interface. The legacy owner reaches a record through an interface it
 * registered and looks the indices up by interface id; this ownership mode
 * registers none, so it holds the record and its indices directly. Staying off
 * every list the legacy code walks is what keeps remove_onif_by_index()'s
 * conntrack and route-cache sweep away from it.
 *
 * The indices are what the header manipulations carry, in the units of their
 * own pool's record, with STATS_WITH_TS set for a timestamped one. Zero is
 * never a valid index -- a timestamped one always has that bit set and a plain
 * one starts past the timestamped pool -- so zero can mean "no slot" wherever
 * an index is passed on.
 */
struct cdx_ft_stats_slot {
	void *record;
	enum cdx_ft_stats_kind kind;
	u8 rx_index;
	u8 tx_index;
};

/* Implemented beside the free lists in cdx_ifstats.c, exported by the backend.
 * Both take dpa_statslist_lock, which is a process-context discipline. */
int cdx_ft_ifstats_alloc(enum cdx_ft_stats_kind kind, struct cdx_ft_stats_slot **slot);
void cdx_ft_ifstats_free(struct cdx_ft_stats_slot **slot);
void cdx_ft_ifstats_read(const struct cdx_ft_stats_slot *slot,
			 struct cdx_ft_stats *rx, struct cdx_ft_stats *tx);

/* CDX-internal firmware encoder. Only the backend and final CDX shutdown
 * call these operations, with cdx_info->ctrl.mutex held. */
int cdx_ft_hw_add(const struct cdx_ft_rule *rule,
		  const struct cdx_ft_stats_binding *stats,
		  struct cdx_ft_hw **result);
void cdx_ft_hw_stats(struct cdx_ft_hw *hw, struct cdx_ft_counters *stats);
/* Always consumes *hw. 0: removed and synchronized. -EAGAIN: unlinked but
 * quarantined. -EIO: removal unproven; caller must stop further admission and
 * quiesce the datapath. The backend retains failed deletions without allocating
 * new storage. A repeated delete with *hw == NULL does not erase prior errors. */
int cdx_ft_hw_del(struct cdx_ft_hw **hw);
unsigned int cdx_ft_hw_pending(void);
int cdx_ft_hw_retry(void);
/* Only after dpa_cfg_quiesce has succeeded; requires the control mutex. */
void cdx_ft_hw_quiesced(void);

#endif
