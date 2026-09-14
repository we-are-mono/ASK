/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef CDX_FLOWTABLE_HW_H
#define CDX_FLOWTABLE_HW_H

#include <linux/types.h>
#include <linux/if_ether.h>

struct net_device;
struct cdx_ft_hw;

/* All addresses and ports are in network byte order. No borrowed Linux flow
 * object or cookie crosses this boundary. The caller pins both netdevices and
 * serializes operations with cdx_info->ctrl.mutex. */
struct cdx_ft_rule {
	struct net_device *in;
	struct net_device *out;
	__be32 src, dst;
	__be16 sport, dport;
	u8 src_mac[ETH_ALEN];
	u8 dst_mac[ETH_ALEN];
	u16 mtu;
};

struct cdx_ft_counters {
	u64 packets;
	u64 bytes;
	u32 lastused;
};

int cdx_ft_hw_add(const struct cdx_ft_rule *rule, struct cdx_ft_hw **result);
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
