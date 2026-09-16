/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef CDX_FLOWTABLE_BACKEND_H
#define CDX_FLOWTABLE_BACKEND_H

#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>

struct net_device;
struct cdx_ft_hw;

/* Netfilter describes at most NF_FLOW_TABLE_ENCAP_MAX encapsulations per
 * direction. ask_flowtable.c asserts that the two bounds agree. */
#define CDX_FT_VLAN_MAX 2

/* One 802.1Q tag. proto is the TPID in network byte order and id the 12-bit
 * VID. A flowtable rule describes neither priority nor DEI, so neither is
 * imposed and both are zero on the wire. */
struct cdx_ft_vlan {
	__be16 proto;
	u16 id;
};

/* Private in-repository interface. No CDX, firmware or borrowed Netfilter
 * objects cross it; the address union is a plain UAPI value type shared with
 * conntrack so no tuple has to be transcribed. Addresses and ports are in
 * network byte order. family selects the arm of every address, and the unused
 * bytes of each are always zero, so whole rules compare bytewise. The adapter
 * pins every device until the installed direction has been retired.
 */
struct cdx_ft_rule {
	/* in and out are always physical ports; in_logical and out_logical are
	 * the netdevs Linux actually routed through, and are the same objects
	 * when no tag is present. Neighbours, MTU and route validity belong to
	 * the logical device; hardware belongs to the physical one. */
	struct net_device *in;
	struct net_device *out;
	struct net_device *in_logical;
	struct net_device *out_logical;
	/* The bridge each logical device reaches its physical port through, or
	 * NULL when the path has none. Adapter state: the backend needs only
	 * the ports and the tag stacks, but the bridge is a dependency of its
	 * own, because the FDB entry (bridge, dst_mac, out_bridge_vid) is what
	 * chose out. A vid of zero means the bridge does not filter by VLAN,
	 * which is also the key its FDB lookup used. */
	struct net_device *in_bridge;
	struct net_device *out_bridge;
	u16 in_bridge_vid;
	u16 out_bridge_vid;
	union nf_inet_addr src, dst;
	__be16 sport, dport;
	/* Complete tuple after translation; identical to the match without NAT. */
	union nf_inet_addr new_src, new_dst;
	__be16 new_sport, new_dport;
	/* VLAN stacks between each logical device and its physical port,
	 * outermost first: the order the wire carries them and the order
	 * Netfilter emits VLAN_PUSH in. in_vlan is stripped on ingress and
	 * out_vlan pushed on egress. No tag reaches the classifier key, which
	 * is physical port plus 5-tuple, so the ingress stack is validated by
	 * the header manipulation rather than by the lookup. */
	struct cdx_ft_vlan in_vlan[CDX_FT_VLAN_MAX];
	struct cdx_ft_vlan out_vlan[CDX_FT_VLAN_MAX];
	u8 in_vlans;
	u8 out_vlans;
	u8 family;
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
