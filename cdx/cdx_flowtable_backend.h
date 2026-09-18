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

/* How many devices one flowtable may be bound to at once.
 *
 * A binding is a device reference and a rule callback; it reserves nothing in
 * hardware, and admission already refuses a second binding for a device it
 * holds. So the ceiling is however many devices can pass
 * cdx_ft_port_supported(), which admits only a physical Ethernet onif --
 * cdx_add_eth_onif() is the sole creator of one and it takes a phy_port slot
 * first, of which there are MAX_PHY_PORTS. A bound flowtable can therefore
 * never reach this number, and the adapter sizes its drain snapshot by it.
 * cdx_flowtable_backend.c asserts that the two bounds agree.
 *
 * A gateway needs more than a pair: PPPoE on the WAN with br-lan, br-guest
 * and br-iot below it is four. The pair this replaced was the proof of
 * concept's own acceptance limit, carried along unexamined ever since.
 */
#define CDX_FT_MAX_BINDINGS 40

/* One 802.1Q tag. proto is the TPID in network byte order and id the 12-bit
 * VID. A flowtable rule describes neither priority nor DEI, so neither is
 * imposed and both are zero on the wire. */
struct cdx_ft_vlan {
	__be16 proto;
	u16 id;
};

/* One PPPoE session on a direction's path. present says the direction carries
 * one; id and mac describe it, and are recorded for either direction because
 * both come from the same path walk. Only an egress session reaches the
 * hardware: the ingress side is a strip, and a strip validates nothing -- it
 * removes whatever session header the frame arrived with. A session occupies
 * one of the encapsulation slots a direction has, so it bounds the tag stack
 * that can accompany it. */
struct cdx_ft_session {
	u8 mac[ETH_ALEN];
	u16 id;
	/* The device the session runs over, as an index. Nothing in the
	 * backend uses it; it completes the identity for a caller that needs
	 * to tell two sessions apart, because an id is unique only per
	 * concentrator and per client. */
	int lower_ifindex;
	bool present;
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
	/* The PPPoE session each direction crosses, inside every tag above it.
	 * in_session is stripped on ingress and out_session inserted on egress.
	 * An egress session also decides dst_mac: a ppp device has no Ethernet
	 * address and no neighbour, so the concentrator named here is the only
	 * destination such a direction has. */
	struct cdx_ft_session in_session;
	struct cdx_ft_session out_session;
	u8 in_vlans;
	u8 out_vlans;
	u8 family;
	u8 proto;
	u8 src_mac[ETH_ALEN];
	u8 dst_mac[ETH_ALEN];
	u16 mtu;
	/* Class, already decoded from the conntrack mark: low nibble is the
	 * CEETM class queue, second nibble the channel (zero means the port's
	 * own least-priority channel), third nibble the ingress policer
	 * profile, then a flag and six bits of DSCP to remark egress frames
	 * with. Deliberately absent from ft_same_key(), because two marks
	 * describe one flow rather than two; present in the whole-rule
	 * comparison, so a reclassified flow is reinstalled rather than left on
	 * its old queue.
	 *
	 * Nineteen bits wide, so u32: a u16 would silently drop the codepoint.
	 */
	u32 qos;
	/* The offloaded SA this direction's frames are encrypted by, or zero.
	 *
	 * A handle rather than the opaque owner, because this is what the
	 * hardware works in: the classifier entry names the SA by handle and
	 * SEC stamps the same number into a decrypted frame. Zero means the
	 * direction carries no SA, which is every flow that is not tunnelled.
	 *
	 * Only an outbound SA appears here; the inbound one has a field of its
	 * own below, because the two act on opposite ends of the direction and
	 * a direction can hold both.
	 */
	u16 sa_handle;
	/* The offloaded SA this direction's frames arrive decrypted from, or
	 * zero.
	 *
	 * An inbound SA is not the mirror of an outbound one. Its frames reach
	 * the port as ESP and are classified on the SPI, by the SA's own
	 * classifier entry, so they never match this tuple on the way in. What
	 * they match is this entry *after* SEC has decrypted them -- and a
	 * decrypted frame re-enters classification on the offline port rather
	 * than on the physical port it arrived by. So naming the SA here is
	 * not decoration: it is what moves the entry into the offline port's
	 * table and puts that port's id in its key. Without it the entry is
	 * installed on the physical port, is counted, and never matches a
	 * single frame.
	 *
	 * Zero means the direction's frames arrive in the clear, which is
	 * every direction of every flow that is not the receiving half of a
	 * tunnel.
	 */
	u16 in_sa_handle;
};

/* Layout of cdx_ft_rule.qos. Stated here rather than in the adapter because
 * this header is where the rule's meaning is agreed, and the adapter must not
 * reach into CEETM headers to learn it.
 *
 * The channel nibble is valid over 0..CDX_FT_QOS_MAX_CHANNEL inclusive: zero
 * selects the egress port's least-priority channel rather than naming channel
 * zero, and 1..8 name a channel directly, which is the numbering
 * ceetm_get_egressfq() expects. CDX_FT_QOS_MAX_CHANNEL therefore equals
 * CDX_CEETM_MAX_CHANNELS, and a static assertion in cdx_ceetm_app.c — where
 * that count is owned — fails the build if the two ever drift.
 *
 * The policer nibble does NOT number that way, and the difference is worth
 * stating because the symmetry is tempting. It is the RFC-2698 profile number
 * directly, 0..CDX_FT_QOS_MAX_POLICER.
 *
 * There is no sentinel because there is no absence to express. The hardware
 * encoder starts from profile 0 and only an iqid-carrying mark moves it
 * (`quenum` in create_entry_in_classif_table_hm), so profile 0 is what every
 * flow that says nothing has always metered against — it is the default
 * profile, which CMM spells `set qm ingress queue default`. A nibble reserved
 * to mean "no policer" would therefore select profile 0 anyway, and collide
 * with the nibble that names it.
 *
 * Naming a profile no control plane has configured is inert rather than a
 * silent drop: cdx_get_policer_profile_id() answers zero unless that profile
 * is enabled, and the encoder then leaves PREEMPT_POLICE_PKT clear.
 *
 * The remark is the one field with a flag of its own, and it needs one: every
 * other field has a value that means "say nothing" -- class queue zero is a
 * real default, channel zero means "this port's own", policer zero is the
 * default meter -- but DSCP zero is a real codepoint. CS0 is the one an
 * operator remarks *to* when they want best effort, so "remark to zero" and
 * "do not remark" cannot be the same bit pattern. The flag distinguishes them,
 * which is also exactly how the hardware carries it: dscp_mark_flag beside
 * dscp_mark_value in union ctentry_qosmark.
 */
#define CDX_FT_QOS_QUEUE_MASK	0x00000fu
#define CDX_FT_QOS_CHANNEL_MASK	0x0000f0u
#define CDX_FT_QOS_CHANNEL_SHIFT 4
#define CDX_FT_QOS_MAX_CHANNEL	8
#define CDX_FT_QOS_POLICER_MASK	0x000f00u
#define CDX_FT_QOS_POLICER_SHIFT 8
#define CDX_FT_QOS_MAX_POLICER	7	/* highest profile number, inclusive */
#define CDX_FT_QOS_REMARK_MASK	0x001000u
#define CDX_FT_QOS_REMARK_SHIFT	12
#define CDX_FT_QOS_DSCP_MASK	0x07e000u
#define CDX_FT_QOS_DSCP_SHIFT	13
#define CDX_FT_QOS_MAX_DSCP	63	/* six bits, every codepoint */
/* Every bit the encoding defines, so the adapter can reject a mark that names
 * anything outside it rather than truncating it into a different class. */
#define CDX_FT_QOS_MASK		(CDX_FT_QOS_QUEUE_MASK | \
				 CDX_FT_QOS_CHANNEL_MASK | \
				 CDX_FT_QOS_POLICER_MASK | \
				 CDX_FT_QOS_REMARK_MASK | \
				 CDX_FT_QOS_DSCP_MASK)
/* The part that names an egress destination, which is all the Tx path may use
 * to index its class table. The policer nibble selects an ingress meter and the
 * remark changes a header rather than a queue; neither says anything about
 * where a frame leaves, so a flow that names one must not land on a different
 * queue for it — and must not reach past a table sized for the egress class
 * alone. Widening the class to nineteen bits made that masking load-bearing
 * rather than merely correct: unmasked, a remark of CS7 would index 508 entries
 * past a 256-entry table. */
#define CDX_FT_QOS_EGRESS_MASK	(CDX_FT_QOS_QUEUE_MASK | \
				 CDX_FT_QOS_CHANNEL_MASK)

struct cdx_ft_counters {
	u64 packets;
	u64 bytes;
	u32 lastused;
};

/* One direction of an interface-level counter pair, as the firmware keeps it.
 * Packets are 32 bits in the firmware record and are widened here. */
struct cdx_ft_stats {
	u64 bytes;
	u64 packets;
};

struct cdx_ft_stats_slot;

/* Which statistics pool a slot comes from. The firmware keeps two, differing
 * only in whether a record carries a timestamp, and the header manipulation
 * that reaches a record has to agree with the pool it came from. Naming the
 * record shape rather than the feature is what lets a VLAN ask for a slot with
 * the same call: interface statistics are one design, per item 9 of the
 * retirement roadmap, not one design per encapsulation. */
enum cdx_ft_stats_kind {
	CDX_FT_STATS_TIMESTAMPED,	/* what a PPPoE session's insert/strip read */
	CDX_FT_STATS_PLAIN,		/* what a VLAN's would */
};

/* The statistics slots a direction's encapsulation counts into. One session
 * has a single slot serving both of its directions: the direction that
 * inserts the header counts into that slot's transmit half and the direction
 * that strips one counts into its receive half, so the two halves describe
 * the session between them rather than either flow. NULL is a direction whose
 * session has no slot, and the encoder then emits no pointer at all -- which
 * is not the same as emitting zero by accident, because the unallocated index
 * zero belongs to another record. */
struct cdx_ft_stats_binding {
	struct cdx_ft_stats_slot *in_session;
	struct cdx_ft_stats_slot *out_session;
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
/* stats names the slots this direction counts into and is never NULL; a
 * direction with no session, or whose session has no slot, passes one holding
 * NULLs. It is separate from the rule because it is a resource the adapter
 * attached rather than a property of the flow, and the rule is compared
 * bytewise against a stored one to decide whether anything changed. */
int cdx_ft_add(const struct cdx_ft_rule *rule,
	       const struct cdx_ft_stats_binding *stats,
	       struct cdx_ft_hw **result);
/* Interface-level byte counters live in a small fixed firmware area, four
 * timestamped records and the rest plain, shared with the legacy owner.
 * Allocation is therefore expected to fail, and failing is not fatal:
 * counters are observability and forwarding is the product, so a caller that
 * cannot have a slot must still install its flow. -ENOSPC says exactly that.
 * A slot outlives no adapter: free every one before unload.
 */
int cdx_ft_stats_alloc(enum cdx_ft_stats_kind kind, struct cdx_ft_stats_slot **slot);
void cdx_ft_stats_free(struct cdx_ft_stats_slot **slot);
/* Reads the firmware's own record. Either pointer may be NULL to skip it; a
 * NULL slot reports zeroes, which is what a caller without one should show. */
void cdx_ft_stats_read(const struct cdx_ft_stats_slot *slot,
		       struct cdx_ft_stats *rx, struct cdx_ft_stats *tx);
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
