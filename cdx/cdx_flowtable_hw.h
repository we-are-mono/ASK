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
	/* Where dev_get_stats() folds the record, or an empty list head when it
	 * is published nowhere. The overheads are per packet, in bytes; see
	 * cdx_ft_stats_publish(). */
	struct list_head published;
	int ifindex;
	unsigned int rx_overhead;
	unsigned int tx_overhead;
};

/* Implemented beside the free lists in cdx_ifstats.c, exported by the backend.
 * All take dpa_statslist_lock, which is a process-context discipline; the fold
 * runs from dev_get_stats(), which is process context under RCU or RTNL. */
int cdx_ft_ifstats_alloc(enum cdx_ft_stats_kind kind, struct cdx_ft_stats_slot **slot);
void cdx_ft_ifstats_free(struct cdx_ft_stats_slot **slot);
void cdx_ft_ifstats_read(const struct cdx_ft_stats_slot *slot,
			 struct cdx_ft_stats *rx, struct cdx_ft_stats *tx);
void cdx_ft_ifstats_publish(struct cdx_ft_stats_slot *slot, int ifindex,
			    unsigned int rx_overhead, unsigned int tx_overhead);
void cdx_ft_ifstats_unpublish(struct cdx_ft_stats_slot *slot);
void cdx_ft_ifstats_fold(const struct net_device *dev, struct rtnl_link_stats64 *storage);
/* One record folded into a device's counters in that device's units: the
 * per-packet overhead comes off the byte count, saturating at zero, because
 * padding on a minimum-size frame is counted by the firmware and cannot be
 * told apart from payload afterwards. Shared with the registered-interface
 * fold in devman.c so the two owners restate a port's record the same way. */
void cdx_ifstats_fold(struct rtnl_link_stats64 *storage,
		      u64 rx_bytes, u64 rx_packets, u64 tx_bytes, u64 tx_packets,
		      unsigned int rx_overhead, unsigned int tx_overhead);
/* A registered interface's record, read the way a slot's is: bytes as the
 * firmware keeps them and packets carried past its 32 bits, so the fold adds a
 * total that never steps back. Zeroes for NULL, and for any record once the
 * carve is gone. */
void cdx_ifstats_read(const void *record, struct cdx_ft_stats *rx,
		      struct cdx_ft_stats *tx);
/* What a physical port's own receive counter leaves out and the firmware's
 * record includes: the Ethernet header, which the driver's rx_bytes counts
 * skb->len after eth_type_trans() has pulled. Transmit needs no correction --
 * the driver counts the whole frame it was handed, tags included, and so does
 * the firmware. */
#define CDX_IFSTATS_PORT_RX_OVERHEAD ETH_HLEN

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
