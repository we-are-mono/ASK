/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef CDX_FLOWTABLE_HW_H
#define CDX_FLOWTABLE_HW_H

#include "cdx_flowtable_backend.h"

/* One statistics record held by the adapter rather than by a registered
 * interface. A registered interface's record is reached through the interface,
 * its indices looked up by interface id; the adapter registers none for these,
 * so it holds the record and its indices directly.
 *
 * The indices are what the header manipulations carry, in the units of their
 * own pool's record, with STATS_WITH_TS set for a timestamped one. Zero is
 * never a valid index -- a timestamped one always has that bit set and a plain
 * one starts past the timestamped pool -- so zero can mean "no slot" wherever
 * an index is passed on.
 *
 * The record goes back to its pool only when nothing names it any more. The
 * adapter holds it from allocation until it frees the slot, and every hardware
 * entry whose opcodes carry one of its indices holds it until that entry is
 * proven gone: the microcode writes the record each time it runs those opcodes
 * after a hit, and a retired entry may still be walked. A record on a free
 * list has its first word overwritten with the list's link, and the next
 * device to be handed it would count what the old entry still adds.
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
	/* The adapter's hold and one per hardware entry naming the record.
	 * retained is set when the adapter lets go while an entry still holds
	 * it, and is what the last put answers for. Both change only under the
	 * control mutex, which every flowtable caller holds. */
	unsigned int holds;
	bool retained;
};

/* Implemented beside the free lists in cdx_ifstats.c, exported by the backend.
 * Allocation, free, read, publication, withdrawal and the fold take
 * dpa_statslist_lock, which is a process-context discipline; the fold runs
 * from dev_get_stats(), which is process context under RCU or RTNL. A put
 * takes it only when it is the last and returns the record; the hold and the
 * retention count take no lock of their own. Allocation, free, hold, put and
 * the retention count are called with the control mutex held, which is what
 * serializes the holds. */
int cdx_ft_ifstats_alloc(enum cdx_ft_stats_kind kind, struct cdx_ft_stats_slot **slot);
/* The adapter's release: the publication is withdrawn at once, the record
 * goes back with the last hold. */
void cdx_ft_ifstats_free(struct cdx_ft_stats_slot **slot);
/* A hardware entry's hold, taken once its key is linked and given back only
 * after a barrier, or the stopped datapath, proves nothing walks the entry.
 * Never under dpa_statslist_lock or a caller's own spinlock: the last put
 * returns the record, which takes the former. */
void cdx_ft_ifstats_hold(struct cdx_ft_stats_slot *slot);
void cdx_ft_ifstats_put(struct cdx_ft_stats_slot *slot);
/* Slots the adapter has freed that an unproven entry still holds, and how many
 * of its frees have had to wait on one since CDX loaded. */
void cdx_ft_ifstats_retention(unsigned int *retained, u64 *deferred);
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
 * stop the datapath. The backend retains failed deletions without allocating
 * new storage, and a retained entry keeps its holds on the statistics records
 * it names until the same proof releases it. A repeated delete with
 * *hw == NULL does not erase prior errors. */
int cdx_ft_hw_del(struct cdx_ft_hw **hw);
/* The same without the barrier: 0 once the key is unlinked, its owner retained
 * as an unsynced retirement owed to cdx_ft_hw_settle(); -EIO as above. */
int cdx_ft_hw_unlink(struct cdx_ft_hw **hw);
unsigned int cdx_ft_hw_pending(void);
/* The retirements cdx_ft_hw_unlink() left owed and no settle has failed. */
unsigned int cdx_ft_hw_owed(void);
/* One barrier for every owed unlink. 0: none owed, or every one proven and
 * released. -EAGAIN: the barrier failed; *unproven owed owners are now
 * ordinary unproven retirements, as a delete whose own barrier failed
 * leaves, owed nothing more. */
int cdx_ft_hw_settle(unsigned int *unproven);
/* One barrier for every unproven unlink, CDX's parked backlog included; see
 * the definition for what the return value does and does not cover. */
int cdx_ft_hw_retry(void);
/* Only once dpa_cfg_stop() or dpa_cfg_quiesce() has found every classifier
 * port stopped and idle, and a PCD barrier has completed after that; requires
 * the control mutex. Frees what is unlinked and records what may not be
 * (cdx_ehash_abandon()). */
void cdx_ft_hw_quiesced(void);
/* When neither can be had for good: keeps every retired entry allocated with
 * its holds, recorded as possibly linked; requires the control mutex. */
void cdx_ft_hw_strand(void);

#endif
