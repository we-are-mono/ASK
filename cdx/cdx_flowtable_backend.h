/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef CDX_FLOWTABLE_BACKEND_H
#define CDX_FLOWTABLE_BACKEND_H

#include <linux/types.h>
#include <linux/if_ether.h>

struct net_device;
struct cdx_ft_hw;

/* Private in-repository interface. No CDX, firmware or borrowed Netfilter
 * objects cross it. Addresses and ports are in network byte order. The adapter
 * pins both devices until the installed direction has been retired.
 */
struct cdx_ft_rule {
	struct net_device *in;
	struct net_device *out;
	__be32 src, dst;
	__be16 sport, dport;
	u8 proto;
	u8 src_mac[ETH_ALEN];
	u8 dst_mac[ETH_ALEN];
	u16 mtu;
};

struct cdx_ft_counters {
	u64 packets;
	u64 bytes;
	u32 lastused;
};

/* Process-context transactions serialize adapter state with CDX hardware
 * operations. They intentionally retain the existing control-lock ordering.
 * No backend operation calls the adapter. Never flush Netfilter work inside a
 * transaction; release it first, since callbacks need their own transaction.
 * Atomic notifiers must use adapter-owned spinlocks and defer backend work.
 */
void cdx_ft_begin(void);
void cdx_ft_end(void);
void cdx_ft_assert_held(void);

/* All operations below require a transaction unless explicitly stated.
 * Claim is exclusive and available only in the per-boot flowtable owner mode.
 * Release requires zero live directions, but CDX keeps any retired hardware
 * storage and its terminal failure state. Neither operation resets hardware.
 */
int cdx_ft_claim(void);
int cdx_ft_release(void);
bool cdx_ft_failed(void);
unsigned int cdx_ft_pending(void);

/* Admission also excludes network configuration. Call outside RTNL; begin
 * only tries RTNL and leaves the transaction held on failure. Balance each
 * successful begin with end before ending the transaction. Add requires RTNL.
 * Port checks during bind are provisional; admission rechecks under RTNL.
 */
int cdx_ft_admission_begin(void);
void cdx_ft_admission_end(void);
bool cdx_ft_port_supported(struct net_device *dev);
int cdx_ft_add(const struct cdx_ft_rule *rule, struct cdx_ft_hw **result);
void cdx_ft_stats(struct cdx_ft_hw *hw, struct cdx_ft_counters *stats);
/* Always consumes *hw. -EAGAIN: unlinked storage awaits a barrier. -EIO:
 * unlink is unproven; CDX latches a terminal failure and must quiesce hardware.
 * Both errors require the adapter to stop admission and start global recovery.
 */
int cdx_ft_del(struct cdx_ft_hw **hw);
/* Retry retired storage; after terminal failure, first try to quiesce the
 * datapath. -EAGAIN means retry later. Success never clears terminal failure.
 * Never report software fallback ready before this operation succeeds.
 */
int cdx_ft_recover(void);

/* Immutable per-load options; no transaction required. */
bool cdx_ft_observing(void);

#endif
