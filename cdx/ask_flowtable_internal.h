/* SPDX-License-Identifier: GPL-2.0-or-later */
/* State and helpers the ask_flowtable objects share. Private to the module. */
#ifndef ASK_FLOWTABLE_INTERNAL_H
#define ASK_FLOWTABLE_INTERNAL_H

#include <crypto/aead.h>
#include <linux/delay.h>
#include <linux/etherdevice.h>
#include <linux/hashtable.h>
#include <linux/if_arp.h>
#include <linux/if_bridge.h>
#include <linux/if_pppox.h>
#include <linux/if_vlan.h>
#include <linux/igmp.h>
#include <linux/inetdevice.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/jhash.h>
#include <linux/module.h>
#include <linux/mroute.h>
#include <linux/mroute6.h>
#include <linux/netfilter_bridge.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/proc_fs.h>
#include <linux/once.h>
#include <linux/random.h>
#include <linux/seq_file.h>
#include <linux/siphash.h>
#include <linux/spinlock.h>
#include <linux/tc_act/tc_csum.h>
#include <linux/workqueue.h>
#include <net/addrconf.h>
#include <net/arp.h>
#include <net/fib_notifier.h>
#include <net/fib_rules.h>
#include <net/flow_offload.h>
#include <net/if_inet6.h>
#include <net/ip6_route.h>
#include <net/ip6_tunnel.h>
#include <net/ip_tunnels.h>
#include <net/ipv6.h>
#include <net/ndisc.h>
#include <net/netevent.h>
#include <net/nexthop.h>
#include <net/pkt_cls.h>
#include <net/route.h>
#include <net/sch_generic.h>
#include <net/tcp.h>
#include <net/tcx.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_flow_table.h>
#include <net/netfilter/nf_port_probe.h>
#include <net/netfilter/nf_tables.h>
#include <net/switchdev.h>
#include <net/l3mdev.h>
#include <net/xfrm.h>
#include <net/cfg80211.h>
#include <dpaa_eth_common.h>
#include "cdx_flowtable_backend.h"
#include "cdx_mcast_backend.h"
#include "cdx_flowtable.h"
#include "cdx_ipsec_backend.h"
#include "cdx_wifi_backend.h"
#include "cdx_police.h"

#if !defined(FLOW_CLS_HAS_NF_CONTEXT) || FLOW_CLS_HAS_NF_CONTEXT < 12
#error "CDX flowtable requires kernel flowtable context version 12 or later"
#endif

/* The bridge FDB pins a bridged flow's egress port, and this is the only
 * chain a plain bridge reports FDB and VLAN-membership changes on. Building
 * without it would offload bridged flows and never retire a stale one, which
 * is a silent misforward rather than a missing feature. */
#if !IS_ENABLED(CONFIG_NET_SWITCHDEV)
#error "CDX flowtable requires CONFIG_NET_SWITCHDEV for bridge FDB invalidation"
#endif

/* A rule must be able to describe every encapsulation a tuple can carry;
 * otherwise a stack Netfilter admits would be silently truncated here. */
static_assert(CDX_FT_VLAN_MAX == NF_FLOW_TABLE_ENCAP_MAX);

struct cdx_ft_binding {
	struct list_head list;
	struct net_device *dev;
	struct nf_flowtable *table; /* retained as identity; borrowed in bind only */
	/* Bound while an invalidation was latched: counted and watched like any
	 * other binding, but every flow it is offered stays in software until
	 * ft_rearm() makes it live. Changed only under the backend transaction,
	 * which is also what its reader, the rule callback, holds. */
	bool parked;
	/* Bound with ft_passive_callback: never on ft_bindings, no device
	 * reference, no entries -- only what ft_release() and the unload drain
	 * need. It shares ft_release() with a real binding because Netfilter
	 * unwinds indirect callbacks by their release function alone
	 * (flow_indr_dev_unregister()); one with a release of its own stayed on
	 * the indirect list after the drain freed it. */
	bool passive;
};

/* One logical device's interface counters: the record its encapsulation counts
 * into, which dev_get_stats() folds into the device's own counters -- so
 * `ip -s link` and /proc/net/dev show traffic that never reached the CPU. A
 * VLAN device's record is a plain one that its tag's two opcodes name; a ppp
 * device's is a timestamped one that its session's two opcodes name. Both are
 * keyed on the device, because that is what the reader names: a ppp device
 * carries one session at a time, and a session renegotiated under a device
 * that stays is still that device's traffic. The identity the walk derived for
 * the session is kept alongside, for the /proc row to be joined with the flow
 * rows, and follows the last direction admitted.
 *
 * Held for the device's lifetime rather than its flows': a slot returned to
 * the pool is zeroed when handed out again, so a record that came and went
 * with the flows would drop the device's counters back to zero every time it
 * went idle. refs counts the hardware directions whose opcodes name the
 * record's indices: the device can unregister while an entry naming the record
 * is still being retired. gone marks the device as unregistered. The record is
 * freed by whichever comes last, the unregistration or the last release, and a
 * gone record is never found by index again, so a device that reuses the index
 * starts a record of its own. Freeing it releases only this module's hold on
 * the slot; an entry CDX retired without proof holds the slot itself.
 *
 * slot is NULL for a device admitted while its pool was empty: its flows
 * forward without counting, and the row in /proc/cdx_flowtable says so. The
 * answer a device got is the answer it keeps, so a live connection's counters
 * never begin halfway through its life.
 */
struct cdx_ft_dev_stats {
	struct list_head list;
	int ifindex;
	enum cdx_ft_stats_kind kind;
	unsigned int refs;
	bool gone;
	struct cdx_ft_stats_slot *slot;
	struct cdx_ft_session session;
	/* A tunnel device's record is a plain one, like a VLAN device's; this
	 * is what tells the two apart in the read-back and carries the
	 * identity the flow rows print, following the last direction admitted
	 * exactly as a session's does. */
	struct cdx_ft_tunnel tunnel;
};

/* Per side: a device under a tunnel and one under a session, and every tag's
 * device. Fewer are ever distinct, since most of these are the same device
 * seen from two hops or a device the rule already names. */
#define CDX_FT_CROSSED_MAX (2 * (CDX_FT_VLAN_MAX + 2))

/* What a device is to the installed flows, weakest first: nothing; a device
 * paths only cross on their way down to a port; some direction's own logical
 * device or bridge; a port -- bound, or some direction's physical ingress or
 * egress. How far a change to it reaches follows from which. */
enum ft_device_role { FT_DEV_UNUSED, FT_DEV_CROSSED, FT_DEV_NAMED, FT_DEV_PORT };

struct cdx_ft_entry {
	struct list_head list;
	struct hlist_node cookie_node;
	struct hlist_node key_node;
	struct list_head neigh_list;
	/* In ft_fdb_watch when it leaves by a bridge, and in ft_neigh_watch
	 * when it holds a neighbour; published and unpublished with neigh_list. */
	struct hlist_node fdb_node;
	struct hlist_node neigh_node;
	struct neighbour *neigh;
	struct nf_flow_offload_handle *handle;
	union nf_inet_addr next_hop;
	struct cdx_ft_binding *binding;
	/* The ppp device record each half of this direction's session counts
	 * into, or NULL. Held on the entry rather than in the rule: a rule is
	 * compared bytewise against a stored one to decide whether anything
	 * changed, and an attached resource is not part of that description. */
	struct cdx_ft_dev_stats *in_stats;
	struct cdx_ft_dev_stats *out_stats;
	/* And the VLAN device record each tag counts into, indexed like the
	 * rule's stacks; NULL for a tag with no device or no record. */
	struct cdx_ft_dev_stats *in_vlan_stats[CDX_FT_VLAN_MAX];
	struct cdx_ft_dev_stats *out_vlan_stats[CDX_FT_VLAN_MAX];
	/* And the tunnel device's, held the same way. */
	struct cdx_ft_dev_stats *in_tunnel_stats;
	struct cdx_ft_dev_stats *out_tunnel_stats;
	/* The devices each side's frames cross that the rule names only by
	 * index: a VLAN device between the logical device and the port, and
	 * the ppp device a tunnel runs over. The walk that admitted the
	 * direction required each of them -- up, carrying the port's address,
	 * stacked exactly so -- so each is held and watched like the devices
	 * the rule does name. Kept on the entry for the reason the records
	 * above are. */
	struct net_device *crossed[CDX_FT_CROSSED_MAX];
	unsigned int ncrossed;
	unsigned long cookie;
	struct cdx_ft_rule rule;
	struct cdx_ft_hw *hw;
	struct cdx_ft_counters reported;
};

/* Admission budget, not a firmware maximum. Directions consume slots
 * independently without eviction. The deployed TCP/UDP classifiers each have
 * 32768 buckets and dynamically allocated entries, one pair per family, so
 * this single budget is the more conservative bound once both are in use.
 * Keep software indexes at a maximum average load of two; dependency
 * invalidation remains a bounded walk because a single route/device/neighbour
 * event can affect every flow.
 */
#define CDX_FT_MAX_ENTRIES 32768U
#define CDX_FT_HASH_BITS 14
/* The most entries one transaction retires, and the most unlinks one barrier
 * settles: a full table goes in batches that each hold the transaction for
 * milliseconds, not one walk that held it for 13 seconds (A327). */
#define FT_RETIRE_BATCH 64U

/* What an MFC entry routed through a bridge contributes to the bridged group
 * carrying its stream.
 *
 * Owned by the routed group, which allocates it on first publication and frees
 * it after withdrawing it. The description is written under ft_mc_lock and
 * holds a reference on every device it names, so the bridged learner can build
 * a group from it and drop what a departing device takes with it. What the
 * bridged learner reports back is written under ft_mc_route_lock, a leaf, so
 * the routed learner can read it while holding its own lock. */
struct ft_mc_route {
	struct list_head list;
	bool linked;
	/* Where the parent VIF receives the stream: the bridge, and either the
	 * VLAN whose 802.1Q device the VIF is (`tagged`), or every VLAN the
	 * bridge's own membership leaves untagged, which surfaces on the bridge
	 * device itself. */
	struct net_device *bridge;
	u16 vid;
	bool tagged;
	u8 family;
	union nf_inet_addr src;
	union nf_inet_addr dst;
	/* The routed copies, and the smallest MTU any of them leaves by: the
	 * bound the bridged group holds against the port the stream actually
	 * arrives on, which only that group knows. */
	struct cdx_mc_listener listener[CDX_MC_MAX_LISTENERS];
	u8 listeners;
	u32 mtu;
	/* Whether the bridge handed its streams to the host at the last
	 * publication, which is when the route names its stream's flow into
	 * existence: see ft_mc_route_learns(). A bridge turning promiscuous
	 * raises no event at all, so each publication -- one per refresh of
	 * the routed learner -- compares. Under ft_mc_lock. */
	bool learns;
	/* Reported back. `in_tags` is the ingress framing the counters include,
	 * which the fold into the MFC's counters takes off again. */
	bool carried;
	u8 in_tags;
	struct cdx_ft_counters stats;
	/* Which run of `stats` this is: moved each time the count starts from
	 * zero again -- the route linked, or withdrawn -- and at no other time,
	 * so the owner folding it can tell a count that went back to zero from
	 * one it has already taken part of. */
	u32 series;
};

/* A VIF on a bridge, in an ft_mc_route's terms: the host receives that bridge
 * VLAN's frames there, and ipmr sees them whether or not it has a route. */
struct ft_mc_tap {
	struct net_device *bridge;
	u16 vid;
	bool tagged;
	u8 family;
};

/* A gateway has one or two. Past this the table stops naming them and every
 * bridge VLAN counts as one the host routes, which keeps groups in software
 * rather than starving a VIF nothing recorded. */
#define FT_MC_TAPS	8

/* How many ports one membership keeps a record of: more than a board has.
 *
 * A membership's ports say only that it stands -- which ports a flow's frames
 * go to is the bridge's answer, not this list -- so a join past the last slot
 * is simply not recorded. The cost is bounded and safe: the membership may
 * retire while that port still holds it, which takes its flows back to the
 * bridge in software rather than carrying them for a set missing somebody.
 */
#define FT_MC_MAX_MEMBERS	(CDX_MC_MAX_LISTENERS + 1)

/* The shape a flow's frames arrive in: their own Ethernet pair, and whether
 * they carry the group's VLAN as a tag. The rest of a bridged entry's key --
 * the port, the source and the group -- is the flow's identity; this is what
 * can change under it. */
struct ft_mc_stream {
	u8 dst_mac[ETH_ALEN];
	u8 src_mac[ETH_ALEN];
	bool tagged;
};

/* A membership the bridge has told us about.
 *
 * Keyed on (bridge, br_ip), which is what the MDB itself is keyed on: the
 * group address, the VLAN, the address family, and -- for a source-specific
 * membership -- the source. It installs nothing. It says which flows are
 * worth learning and keeping, and a change to it says which flows to ask the
 * bridge about again.
 */
struct ft_mc_group {
	struct list_head list;
	/* In ft_mc_group_index by (bridge, VLAN, group), whatever source. */
	struct hlist_node index;
	struct net_device *bridge;
	struct br_ip addr;
	/* The ports holding the membership, each pinned. */
	struct net_device *port[FT_MC_MAX_MEMBERS];
	u8 ports;
	/* The bridge itself has joined. The flows this membership names hear
	 * the same from the bridge's answer, and are refused rather than
	 * carried: a hardware entry replicates to ports and the frame never
	 * reaches the CPU, which would starve a local listener silently. Kept
	 * here because it keeps the membership: br_multicast_host_join() emits
	 * it before any port group. */
	bool host;
};

/* A flow: one source's frames of a group as they arrive on one bridge port,
 * which is exactly what one classifier entry matches, and so what the
 * hardware carries. Learned from traffic -- see the traffic half below -- and
 * kept while a membership or a route names it.
 *
 * `addr` is the group, its VLAN and family, and the source; `in` the port.
 * Two sources of a group are two flows, and so is one source arriving on two
 * ports: the bridge forwards each frame on its own, and so does each entry.
 */
struct ft_mc_flow {
	struct list_head list;
	struct net_device *bridge;
	struct br_ip addr;
	struct net_device *in;
	/* The frames' own Ethernet pair, which a bridged entry is keyed on and
	 * every bridged copy is rebuilt with, and whether they carry the
	 * group's VLAN as a tag or arrive untagged on the port's PVID, which
	 * is the one shape the root accepts. */
	u8 dst_mac[ETH_ALEN];
	u8 src_mac[ETH_ALEN];
	bool in_tagged;
	struct cdx_mc_group *hw;
	/* `hw` drops what it matches rather than replicating it: the bridge
	 * forwards the flow nowhere; see ft_mc_discardable(). It names no port
	 * and so no port's queues, which is what keeps it out of an egress
	 * rebuild, and it ages at the first refresh that counts nothing. */
	bool hw_discard;
	/* The flow in another shape reached the CPU while an entry was
	 * installed -- the only way it can, because the entry's own frames
	 * never do: a sender whose MAC changed, a tag the port now carries. It
	 * takes over the key once the installed one has gone idle, and not
	 * while that one is still carrying traffic, so two live senders do not
	 * trade one entry back and forth. */
	struct ft_mc_stream next;
	bool has_next;
	/* What the classifier had counted at the last refresh, and whether it
	 * has counted nothing since. An idle entry is how `next` takes over.
	 * `count_suspect` is a sample below the baseline just seen; see
	 * ft_mc_count_delta(). */
	u64 hw_packets;
	u64 hw_bytes;
	bool count_suspect;
	bool idle;
	/* What the entry counted between the last two refreshes, or U64_MAX
	 * until two refreshes have counted it -- the first sample after an add
	 * covers only the part of an interval since the add: how much a discard
	 * saves, which is what it is ranked by when a stream somebody wants
	 * needs its group id. `interval_whole` is set by the first sample, from
	 * when the next covers a whole interval. See ft_mc_evict_discard(). */
	u64 interval_packets;
	bool interval_whole;
	/* When the entry last counted a frame, or was added, and how long it
	 * may then count nothing before the stream is taken to have stopped:
	 * the bridge's group membership interval for the flow's VLAN, read at
	 * each derivation, so the entry ages on the clock the bridge ages its
	 * memberships by. Zero never ages. */
	unsigned long active;
	unsigned long age;
	/* What the bridge would do with the flow's frames, asked under RTNL at
	 * the last derivation; see ft_mc_flow_derive(). `port` holds the
	 * bridged copies with the tags each leaves with, every device pinned;
	 * `local` the BR_MCAST_TO_HOST_* reasons the bridge also hands a frame
	 * up; `error` what the bridge said instead of a port set, or
	 * -EOPNOTSUPP for a port the hardware cannot carry, which refuses the
	 * whole flow: a matched frame never reaches the bridge, so a port left
	 * out of the hardware set would not fall back to software, it would
	 * stop receiving. */
	struct cdx_mc_listener port[CDX_MC_MAX_LISTENERS];
	u8 ports;
	unsigned int local;
	int error;
	bool derived;
	/* tc runs something in software where the flow's frames arrive, where a
	 * copy of them leaves, or where the bridge hands them up; and a netdev
	 * chain there could tell its streams apart, or any netfilter hook sees
	 * what the bridge hands up. Asked with the rest of the answer; see what
	 * runs in software on a bridged flow's ports. */
	bool tc_soft;
	bool nf_hooked;
	/* The routed half of the flow's stream; see the section on the
	 * learners' streams above. `route` is the published route whose
	 * source and bridge VLAN are this flow's, matched by the worker and
	 * never owned: the routed learner withdraws a route before freeing
	 * it, which clears every pointer to it here. `carried_route` is the
	 * one the installed entry was built with, which is what tells the
	 * routed learner its copies are in hardware. `routed_host` says the
	 * bridge hands the flow's frames to a VIF, so the host routes them and
	 * the flow is carried only together with its route. */
	struct ft_mc_route *route;
	struct ft_mc_route *carried_route;
	bool routed_host;
	/* Another flow has the same classifier key -- the same port, sender
	 * and source, on another VLAN of the bridge -- so neither may be
	 * installed: the key names no VLAN, and one root validates one tag. */
	bool contested;
	/* The derivation is due (`dirty`); an answer changed and the hardware
	 * has not caught up (`stale`); the flow cannot exist any more -- its
	 * ingress went, left the bridge, or no longer resolves to its VLAN --
	 * and the worker is to take it out (`gone`). */
	bool dirty;
	bool stale;
	bool gone;
	/* The worker has picked the flow and not yet recorded what it built.
	 * Until it has, the entry is the worker's alone -- after a swap it is
	 * already deleted -- and nothing else takes it away. Under
	 * ft_mc_lock. */
	bool busy;
	/* The chain `hw` was built from, whole -- the routed copies riding it
	 * included -- recorded with `hw` inside the transaction that built it,
	 * and what the egress drain replaces it with. It holds a reference on
	 * every device it names (ft_mc_chain_record()); a device going away
	 * empties it (ft_mc_device_gone()). No listeners means none is
	 * recorded, and nothing held. */
	struct cdx_mc_group_spec hw_spec;
	/* The installed chain may hold an entry built before an egress change
	 * on a port it copies out of -- an HTB tree, the DSCP map -- naming the
	 * queue, or reading the map, of the state before it. Unlike `stale`,
	 * which a pass consumes when it picks the flow, it is cleared only by a
	 * build that started after the last change (ft_egress_changes), since
	 * a caller waiting for the change to reach the hardware reads it. */
	bool egress_stale;
	/* A source of the group was turned away at FT_MC_MAX_FLOWS while this
	 * flow held its place, and counted in mcast_refused. The next one is
	 * not counted again until the group's flows change: a group every host
	 * sends to would otherwise count one on every frame the dedup slots
	 * could not hold. */
	bool turned;
	/* When a frame of it was last drained, or it last asked for one; and
	 * whether it is asking, which its next frame answers. Only a flow
	 * nothing carries is asked; see ft_mc_flow_probe(). */
	unsigned long seen_at;
	bool probing;
	/* Consecutive failed installs. A failure is not permanent -- a port
	 * that lost carrier gets it back -- but retrying on every frame of a
	 * live stream would spin the worker against a flow that cannot be
	 * carried, so it is bounded and then reported. */
	u8 retries;
};

/* Sources one group may have in hardware on one bridge. An IPTV channel has
 * one; a group every host on a LAN sends to -- SSDP's 239.255.255.250 is the
 * common one -- has as many as there are hosts, and each would take an entry
 * the table is short of. Past this a source is left to the bridge. */
#define FT_MC_MAX_FLOWS	8

/* Flows arriving on one port, and flows in all. Every source of every group a
 * membership names would otherwise be a flow, and memberships are as many as
 * the bridge keeps: a sender choosing both made thousands, each asked of the
 * bridge under RTNL at every refresh. The hardware holds 512 groups per family
 * between both learners; one port is held to half of the total, so its
 * senders cannot take every place. A source past either is turned away as one
 * past FT_MC_MAX_FLOWS is. Installed discards count toward neither: each holds
 * a group id, which bounds them, and gives it up to a wanted stream. */
#define FT_MC_MAX_PORT_FLOWS	256
#define FT_MC_MAX_TOTAL_FLOWS	512

/* How often an installed flow's entry is asked what it has counted, and every
 * flow's answer is asked of the bridge again. The routed learner's fold and
 * re-derivation run at the same pace, for the same reason: some of what the
 * bridge decides by -- a querier appearing or timing out -- changes with no
 * notification at all. */
#define FT_MC_REFRESH_INTERVAL	(5 * HZ)

struct ft_mc_seen {
	int bridge_ifindex;
	int in_ifindex;
	struct br_ip addr;
	union nf_inet_addr src;
	/* The frame's own Ethernet pair, which a bridged group is keyed on and
	 * which every copy is rebuilt with; see the bridged multicast tables in
	 * cdx_ioctl.h. */
	u8 dst_mac[ETH_ALEN];
	u8 src_mac[ETH_ALEN];
	/* The frame carried the group's VLAN as an 802.1Q tag, rather than
	 * arriving untagged and being given it by the port's PVID. The root
	 * accepts exactly one of the two shapes, and it has to be the one the
	 * stream has. */
	bool tagged;
};

/* Deep enough to absorb the few frames between an observation and the worker
 * installing its entry, and no deeper: past that the stream is either
 * offloaded or its flow was refused, and in both cases further observations
 * describe nothing new. Overflow drops the newest, which costs a retry on the
 * next frame rather than anything permanent. */
#define FT_MC_RING 16

/* One name per oif, and an oif produces at least one listener, so the listener
 * ceiling bounds the count. */
#define FT_MR_OIF_TEXT		(CDX_MC_MAX_LISTENERS * (IFNAMSIZ + 1))

enum ft_mr_state {
	/* Eligible, and the worker has not installed it yet. */
	FT_MR_PENDING,
	FT_MR_INSTALLED,
	/* Eligible and routed through a bridge, and the bridged group that
	 * would carry its copies is not in hardware: waiting for its stream,
	 * or refused for a reason its own /proc row names. */
	FT_MR_BRIDGED,
	/* Eligible, and Linux has not yet been seen forwarding it to every
	 * oif under the ruleset as it stands; see the section on what Linux
	 * itself forwarded. */
	FT_MR_UNCONFIRMED,
	/* Everything from here down is a refusal, in the order the contract
	 * tests them. ft_mr_refusal() depends on the four above staying below
	 * the first of them. */
	FT_MR_REFUSED_TABLE,
	/* Multicast acceleration is switched off; see ft_mc_enabled. */
	FT_MR_REFUSED_PAUSED,
	FT_MR_REFUSED_POLICY,
	FT_MR_REFUSED_WILDCARD,
	FT_MR_REFUSED_SCOPE,
	FT_MR_REFUSED_INGRESS,
	FT_MR_REFUSED_HOST,
	FT_MR_REFUSED_THRESHOLD,
	FT_MR_REFUSED_LISTENER,
	FT_MR_REFUSED_MTU,
	/* An XFRM output policy governs an IPv4 copy; see ft_mr_xfrm_plain(). */
	FT_MR_REFUSED_XFRM,
	/* A copy leaves through a bridge whose own output hooks would see it,
	 * or a hook nothing reads could judge it; see ft_mr_admit(). */
	FT_MR_REFUSED_FILTER,
	/* tc runs something in software on the stream's way in or a copy's way
	 * out; see what tc does to a group's packets. */
	FT_MR_REFUSED_TC,
	/* The ruleset may judge the group's packets apart from the copies that
	 * confirmed it -- by their ports, first of all; see ft_mr_ports_matter().
	 * The first for iptables-legacy's tables, which are asked first, the
	 * second for nftables'. */
	FT_MR_REFUSED_XTABLES,
	FT_MR_REFUSED_PORTS,
	FT_MR_REFUSED_CONTESTED,
	FT_MR_REFUSED_FAILED,
	FT_MR_REFUSED_RESYNC,
};

/* One routed group: an MFC entry this learner has an opinion about.
 *
 * Keyed on the mfc pointer, which is exact -- ipmr emits ENTRY_REPLACE against
 * the same pointer when thresholds or the parent change, ENTRY_ADD for a new
 * one, and ENTRY_DEL for that one -- and safe, because the reference taken
 * with mr_cache_hold() keeps the object from being freed and its address from
 * being reused underneath us.
 *
 * `in` and `listener[]` are what the last successful derivation installed,
 * each pinned for as long as the hardware entry names it. They are what /proc
 * reports, so they describe the hardware rather than the intent -- except for
 * a group routed through a bridge, whose set is what it published, and whose
 * state says whether the bridged group carries it.
 */
struct ft_mr_group {
	struct list_head list;
	struct mr_mfc *mfc;
	u32 table;
	u8 family;
	union nf_inet_addr src;
	union nf_inet_addr dst;
	struct net_device *in;
	/* The tags the stream arrives with on `in`, outermost first: what the
	 * root validates, and what the counter fold takes off each frame. */
	struct cdx_ft_vlan in_vlan[CDX_FT_VLAN_MAX];
	u8 in_tags;
	/* For a parent VIF on a bridge, in place of `in`: the bridge, pinned,
	 * and where on it the VIF receives -- see struct ft_mc_route. `mtu` is
	 * the narrowest path a copy leaves by, which the bridged group bounds
	 * against the port the stream arrives on. */
	struct net_device *via;
	u16 via_vid;
	bool via_tagged;
	u32 mtu;
	struct cdx_mc_listener listener[CDX_MC_MAX_LISTENERS];
	u8 listeners;
	char oifs[FT_MR_OIF_TEXT];
	struct cdx_mc_group *hw;
	/* The ingress `hw` was added with, held from the add to the delete.
	 * The backend borrows it and unsubscribes the port's multicast address
	 * through it when the entry is deleted, so it has to outlive `in`,
	 * which a device going away releases at once. Only the worker and
	 * teardown add or delete an entry, and only they touch this. */
	struct net_device *hw_in;
	/* What a group routed through a bridge publishes; allocated at its
	 * first publication and freed with the group. */
	struct ft_mc_route *route;
	/* Which of its oifs Linux has been seen forwarding it to; see the
	 * section on what Linux itself forwarded. Replaced by the worker when
	 * the oifs change, under ft_mr_lock as well as the table's own lock,
	 * so /proc may read it under either. */
	struct ft_mr_watch *watch;
	/* How much of the hardware's count the MFC entry already holds, raw as
	 * it is reported: `hw`'s own, which a group the worker has just added
	 * counts from zero again, or for a group routed through a bridge the
	 * route's, which only ever grows. `fold_suspect` is a sample below it
	 * just seen; see ft_mc_count_delta(). `folded_series` is the run of the
	 * route's count the baseline was taken from, and 0 while it is `hw`'s.
	 */
	u64 folded_packets;
	u64 folded_bytes;
	u32 folded_series;
	bool fold_suspect;
	/* How many entries of its own the group has had added: its first
	 * install, and each time it left hardware and came back. A chain swap
	 * adds none. /proc reports it per group, which is what tells a swap
	 * from a withdrawal and re-add where the row otherwise ends the same:
	 * mroute_refused counts every group's refusals, related or not. A group
	 * routed through a bridge has no entry of its own and adds none. */
	u32 adds;
	enum ft_mr_state state;
	/* MFC_OFFLOAD is set on the kernel's entry. */
	bool offloaded;
	bool dirty;
	/* The worker has picked the group and not yet recorded the outcome.
	 * `hw` and the installed set stay the group's meanwhile: the worker
	 * builds and records inside one transaction (ft_mr_record()), so
	 * nothing else that takes the transaction sees them half-changed. */
	bool busy;
	/* The installed listener chain may hold an entry built before an
	 * egress change on a port it copies out of -- an HTB tree, the DSCP
	 * map -- naming the queue, or reading the map, of the state before it.
	 * The next pass replaces the chain even when the plan has not changed.
	 * Cleared only by a rebuild that started after the last change
	 * (ft_egress_changes), because a caller waiting for the change reads it
	 * (ft_mr_egress_drain()). */
	bool egress_stale;
	/* The spec `hw` was built from, whole -- ingress tags included -- and
	 * what the egress drain replaces it with. It borrows the installed
	 * set's pinned devices, and goes with that set (ft_mr_release_set()).
	 * No listeners means none is recorded. */
	struct cdx_mc_group_spec hw_spec;
	/* The kernel deleted the entry; retire and forget it. */
	bool gone;
	bool seen;
	u8 retries;
};

/* What one derivation produced, with a reference of its own on every device in
 * it. Either the group adopts the whole thing or ft_mr_plan_put() returns it;
 * there is no half-adopted state, because the backend borrows exactly these
 * pointers and a group that owned some of them would name one it did not. */
struct ft_mr_plan {
	struct cdx_mc_group_spec spec;
	char oifs[FT_MR_OIF_TEXT];
	u8 in_tags;
	/* A parent VIF on a bridge: `spec.in` is empty and these say where the
	 * stream is received instead; the copies are published, not installed. */
	struct net_device *via;
	u16 via_vid;
	bool via_tagged;
	u32 mtu;
	/* The MFC oifs by ifindex, which is what a copy is seen leaving by at
	 * POST_ROUTING, and the parent VIF's, which is what it arrived by:
	 * listed by every derivation past the table, whatever it then decides,
	 * so a refused group still gathers its confirmations. No references:
	 * an index names, it does not hold. `out_bridged` says a copy leaves
	 * through a bridge. */
	int oif[MAXVIFS];
	int parent;
	u8 oif_count;
	bool oifs_known;
	bool out_bridged;
	/* The XFRM policy generation the derivation judged the oifs under;
	 * rechecked in the transaction, as the switch is. */
	u64 xfrm_genid;
};

/* One group's confirmations, in a table the hook reads under RCU. */
struct ft_mr_watch {
	struct hlist_node node;
	struct rcu_head rcu;
	u8 family;
	union nf_inet_addr src;
	union nf_inet_addr dst;
	/* The MFC oifs by ifindex, and bit i of `seen` for oif[i] seen leaving
	 * under the ruleset the table is armed for, by a copy that arrived by
	 * the parent VIF `parent`. The lists are fixed once published -- a
	 * changed one is a new watch -- so a reader never sees half of one. */
	u8 oifs;
	int oif[MAXVIFS];
	int parent;
	unsigned long seen;
	/* Every oif seen, and the worker not told yet. */
	bool news;
};

/* How soon a rule added under a carried group takes effect: the ruleset is
 * looked at this often while any group exists. Two loads. */
#define FT_MR_RULESET_INTERVAL	HZ

/* How long a ruleset has to stand still before copies confirm under it: the
 * software episode every commit costs a carried group, less the first copy
 * of it after that. And how soon to look again at one whose commit is still
 * being applied after that. */
#define FT_MR_RULESET_SETTLE	HZ
#define FT_MR_RULESET_APPLYING	(HZ / 10)

/* ask_flowtable_core.c */
#ifdef CDX_DEBUG_FLOWTABLE
extern unsigned int ft_init_fail_stage;
#endif
extern struct list_head ft_bindings;
extern struct list_head ft_entries;
extern struct hlist_head ft_cookies[1 << (CDX_FT_HASH_BITS)];
extern u32 ft_hash_seed;
extern struct list_head ft_neigh_entries;
extern struct hlist_head ft_fdb_watch[1 << (CDX_FT_HASH_BITS)];
extern struct hlist_head ft_neigh_watch[1 << (CDX_FT_HASH_BITS)];
extern spinlock_t ft_watch_lock;
extern struct list_head ft_block_list;
extern struct list_head ft_dev_stats;
extern unsigned int ft_bound, ft_count;
extern unsigned int ft_parked;
extern unsigned int ft_passive;
extern unsigned int ft_neighbour_refs;
extern unsigned int ft_handle_refs;
extern atomic64_t ft_neigh_invalidations;
extern atomic64_t ft_route_invalidations;
extern atomic64_t ft_mtu_invalidations;
extern atomic64_t ft_link_invalidations;
extern atomic64_t ft_mac_invalidations;
extern atomic64_t ft_fdb_invalidations;
extern atomic64_t ft_stp_invalidations;
extern atomic64_t ft_qos_invalidations;
extern atomic64_t ft_admission_invalidations;
extern atomic64_t ft_destroy_deferrals;
extern atomic64_t ft_ipsec_invalidations;
extern atomic64_t ft_ipsec_genid;
extern atomic64_t ft_ipsec_policy_invalidations;
extern u64 ft_installs, ft_deletes, ft_rejects, ft_errors, ft_validated, ft_busy;
extern u64 ft_rearms;
extern bool ft_ready, ft_stopping;
extern atomic_t ft_invalid;
extern bool ft_invalid_done;
extern atomic_t ft_invalid_seq;
extern int ft_done_seq;
extern struct proc_dir_entry *ft_proc;
extern struct delayed_work ft_work;
extern struct work_struct ft_retire_work;
extern struct work_struct ft_settle_work;
extern struct delayed_work ft_rearm_work;
extern struct work_struct ft_dev_stats_work;
void ft_invalidate(void);
void ft_handle_invalidate(struct nf_flow_offload_handle *handle,
			  atomic64_t *counter);
void ft_neigh_invalidate(struct cdx_ft_entry *entry);
bool ft_rule_names(const struct cdx_ft_rule *rule, const struct net_device *dev);
void ft_dev_stats_gone(const struct net_device *dev);
void ft_dev_stats_drop_all(void);
void ft_deferred_destroys_drop(void);
int ft_unlink(struct cdx_ft_entry *entry);
int ft_settle(void);
int ft_remove(struct cdx_ft_entry *entry);
bool ft_retire_batch(bool (*match)(const struct cdx_ft_entry *entry, const void *arg),
		     const void *arg);
struct net_device *ft_vlan_lower(struct net_device *dev);
int ft_bridge_vlan(struct net_device *bridge, struct net_device *port,
		   struct cdx_ft_vlan *stack, unsigned int *count);
bool ft_tunnel_dev(const struct net_device *dev);
u32 ft_port_arriving(const struct net_device *port);
bool ft_invalid_complete(void);
bool ft_can_rearm(void);
void ft_rearm(void);
void ft_release(void *priv);
int ft_bind(struct net_device *dev, struct Qdisc *sch, void *priv,
	    enum tc_setup_type type, void *data, void *table,
	    void (*cleanup)(struct flow_block_cb *));

/* ask_flowtable_watch.c */
extern struct work_struct ft_stopped_work;
extern atomic64_t ft_mr_xfrm_changes;
extern const struct cdx_ft_egress_ops ft_egress_ops;
bool ft_neigh_check(u8 family, struct net_device *dev,
		    const union nf_inet_addr *dst, const u8 *mac);
bool ft_neigh_moved(u8 family, struct net_device *dev,
		    const union nf_inet_addr *dst, const u8 *mac);
bool ft_nexthop_usable(u8 family, const union nf_inet_addr *next_hop);
int ft_neigh_attach(struct cdx_ft_entry *entry);
void ft_neigh_detach(struct cdx_ft_entry *entry);
bool ft_neigh_used(struct cdx_ft_entry *entry, bool active);
void ft_invalidate_work(struct work_struct *work);
bool ft_entry_uses(const struct cdx_ft_entry *entry, const struct net_device *dev);
int ft_netdev_event(struct notifier_block *nb, unsigned long event, void *ptr);
int ft_neigh_event(struct notifier_block *nb, unsigned long event, void *ptr);
int ft_fib_event(struct notifier_block *nb, unsigned long event, void *ptr);
int ft_nexthop_event(struct notifier_block *nb, unsigned long event, void *ptr);
int ft_fdb_event(struct notifier_block *nb, unsigned long event, void *ptr);
int ft_swdev_event(struct notifier_block *nb, unsigned long event, void *ptr);

/* ask_flowtable_ipsec.c */
extern atomic64_t ft_ipsec_next_hop_updates;
extern atomic64_t ft_egress_changes;
extern struct work_struct ft_ipsec_follow;
extern struct delayed_work ft_ipsec_stats;
extern struct work_struct ft_ipsec_retire;
bool ft_policy_covers(const struct xfrm_policy *pol,
		      const struct cdx_ft_rule *rule);
bool ft_ipsec_handle(const struct flow_cls_offload *cls,
		     struct cdx_ft_rule *rule, struct net_device *out,
		     struct net_device *in);
void ft_ipsec_neigh_moved(struct neighbour *neigh);
void ft_ipsec_route_moved(u8 family, const void *dst, __be32 mask,
			  unsigned int prefixlen);
void ft_ipsec_all_moved(void);
void ft_ipsec_device_moved(const struct net_device *dev);
void ft_ipsec_egress_changed(const struct net_device *dev);
bool ft_ipsec_rebuild_pending(const struct net_device *dev);
void ft_ipsec_watch_flush(void);
bool ft_ipsec_retire_pending(void);
void ft_sec_refusals_fold(void);
void ft_ipsec_forget_all(void);
void ft_ipsec_attach(struct net_device *dev);
void ft_ipsec_detach(struct net_device *dev);
void ft_ipsec_detach_all(void);
void ft_sec_refusal_rows(struct seq_file *seq);

/* ask_flowtable_mc.c */
extern struct list_head ft_mc_groups;
extern struct list_head ft_mc_flows;
extern struct mutex ft_mc_lock;
extern unsigned int ft_mc_count, ft_mc_flow_count, ft_mc_installed;
extern unsigned int ft_mc_discarding;
extern u64 ft_mc_discards_evicted;
extern u64 ft_mc_refused, ft_mc_install_errors;
extern u64 ft_mc_port_probe_errors;
extern atomic64_t ft_mc_egress_rebuilds;
extern struct work_struct ft_mc_work;
extern bool ft_mc_stopping;
extern bool ft_mc_enabled;
extern bool ft_mc_recheck;
extern bool ft_mc_filtered;
extern struct list_head ft_mc_routes;
u32 ft_mc_link_mtu(const struct net_device *dev, u8 family);
void ft_mc_kick_all(void);
bool ft_mc_link_local(const struct br_ip *addr);
bool ft_mc_same_vlan_group(const struct br_ip *a, const struct br_ip *b);
void ft_mc_drop_next(struct ft_mc_flow *f);
bool ft_mc_route_publish(struct ft_mc_route *r,
			 const struct ft_mc_route *want);
bool ft_mc_route_withdraw(struct ft_mc_route *r,
			  struct cdx_ft_counters *last, u8 *in_tags,
			  u32 *series);
bool ft_mc_route_state(struct ft_mc_route *r,
		       struct cdx_ft_counters *stats, u8 *in_tags,
		       u32 *series);
void ft_mc_taps_publish(const struct ft_mc_tap *taps, unsigned int n,
			bool overflow);
bool ft_mc_route_reaches(const struct ft_mc_route *r,
			 const struct net_device *bridge,
			 const struct br_ip *addr);
bool ft_mc_host_wants(const struct ft_mc_flow *f);
bool ft_mc_evict_discard(u8 family);
bool ft_mc_count_delta(u64 *base_packets, u64 *base_bytes,
		       bool *suspect, const struct cdx_ft_counters *c,
		       u64 *packets, u64 *bytes);
bool ft_mc_swdev_obj(unsigned long event,
		     struct switchdev_notifier_port_obj_info *obj);
void ft_mc_replay(void);
void ft_mc_device_gone(struct net_device *dev, bool unregistering);
void ft_mc_bridge_changed(struct net_device *dev);
void ft_mc_port_moved(struct net_device *dev, struct net_device *left);
unsigned int ft_mc_egress_mark(const struct net_device *dev);
int ft_mc_egress_drain(const struct net_device *dev);
void ft_mc_exit(void);
void ft_mc_rows(struct seq_file *seq);

/* ask_flowtable_mc_hook.c */
extern struct ft_mc_seen ft_mc_ring[FT_MC_RING];
extern unsigned int ft_mc_ring_head, ft_mc_ring_tail;
extern spinlock_t ft_mc_ring_lock;
extern u64 ft_mc_observed, ft_mc_dropped, ft_mc_deferred, ft_mc_hook_errors;
extern u64 ft_mc_passes;
extern bool ft_mc_hooked;
void ft_mc_forget_seen(void);
void ft_mc_supersede(const struct ft_mc_seen *seen);
void ft_mc_flow_seen(const struct ft_mc_flow *f,
		     const struct ft_mc_stream *shape,
		     struct ft_mc_seen *seen);
bool ft_bridge_hooked(unsigned int hooks);
bool ft_dev_nf_ingress_hooked(const struct net_device *dev);
bool ft_mc_bridge_filtered(void);
void ft_mc_hook_sync(bool wanted);
bool ft_mc_same_key(const struct ft_mc_flow *a, const struct ft_mc_flow *b);
void ft_mc_observe(const struct ft_mc_seen *seen);
void ft_mc_adopt_next(struct ft_mc_flow *f);
bool ft_mc_shape_resolves(struct net_device *bridge,
			  struct net_device *in, bool tagged, u16 vid);
bool ft_mc_listeners_same(const struct cdx_mc_listener *a,
			  const struct cdx_mc_listener *b, u8 n);

/* ask_flowtable_mr.c */
extern struct mutex ft_mr_lock;
extern unsigned int ft_mr_count, ft_mr_installed;
extern u64 ft_mr_capped_entries;
extern unsigned int ft_mr_policy[2];
extern u64 ft_mr_refused, ft_mr_install_errors, ft_mr_lost;
extern bool ft_mr_stopping;
extern bool ft_mr_ready;
extern unsigned long ft_mr_resync_pending;
extern struct work_struct ft_mr_work;
unsigned int ft_mr_idx(u8 family);
void ft_mr_kick(void);
int ft_mr_fib_event(unsigned long event, struct fib_notifier_info *info);
void ft_mr_device_gone(struct net_device *dev);
int ft_mr_egress_drain(const struct net_device *dev);
void ft_mr_exit(void);
void ft_mc_switched(void);
void ft_mr_rows(struct seq_file *seq);
void ft_mc_egress_changed(const struct net_device *dev);

/* ask_flowtable_mr_probe.c */
extern bool ft_mr_gen_open;
extern u64 ft_mr_ruleset_changes, ft_mr_confirm_errors;
extern u64 ft_mr_port_probe_errors;
extern unsigned int ft_mr_xt_seen;
extern u64 ft_mr_xtables_changes;
extern bool ft_mr_probe_again;
extern struct delayed_work ft_mr_ruleset;
void ft_mr_confirm_sync(void);
bool ft_mr_ruleset_sync(void);
unsigned long ft_mr_ruleset_wait(void);
void ft_mr_watch_arm(struct ft_mr_group *g, const struct ft_mr_plan *plan);
void ft_mr_watch_drop(struct ft_mr_group *g);
bool ft_dev_tc_soft(struct net_device *dev, bool ingress);
bool ft_dev_stack_tc_soft(struct net_device *dev, bool ingress);
enum ft_mr_state ft_mr_admit(struct ft_mr_group *g,
			     const struct ft_mr_plan *plan);

/* ask_flowtable_wifi.c */
extern unsigned int ft_wifi_registered;
extern atomic64_t ft_wifi_refusals;
void ft_wifi_reconsider(struct net_device *dev);
void ft_wifi_address_changed(struct net_device *dev);
void ft_wifi_device_gone(struct net_device *dev);
void ft_wifi_exit(void);

/* ask_flowtable_main.c */
extern unsigned int ft_qos_mark_mask;
bool ft_qos_class_valid(unsigned int class);
u32 ft_qos_class(u32 mark);

#endif
