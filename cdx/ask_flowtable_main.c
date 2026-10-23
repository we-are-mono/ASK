// SPDX-License-Identifier: GPL-2.0-or-later
/* Egress QoS classification, /proc/ask_flowtable, and module init and exit.
 */
#include "ask_flowtable_internal.h"

/* Egress QoS classification. The conntrack mark is the only key the software
 * and hardware paths can share: an offloaded flow produces no skb, so nothing
 * a tc filter decides can reach it. Reading it here keeps one source of truth.
 *
 * Both are boot-immutable because a mask that changed
 * under live flows would leave already-installed entries encoding a layout
 * nothing else still agrees with.
 *
 * A zero mask disables classification entirely and restores the historical
 * contract exactly: any nonzero mark refuses admission, so a mark meant for
 * policy routing is never silently reinterpreted as a queue. The controller
 * reads the mask from this parameter and renders its own admission test from
 * it rather than restating this one.
 *
 * A masked value of zero is indistinguishable from an unmarked flow, as with
 * every other fwmark scheme; that case takes the default class rather than
 * naming class zero.
 */
unsigned int ft_qos_mark_mask;
static unsigned int ft_qos_default_class;
module_param_named(qos_mark_mask, ft_qos_mark_mask, uint, 0444);
MODULE_PARM_DESC(qos_mark_mask, "Conntrack mark bits holding the class; 0 disables classification");
module_param_named(qos_default_class, ft_qos_default_class, uint, 0444);
MODULE_PARM_DESC(qos_default_class, "Class for flows whose masked mark is zero: nibbles low to high are class queue, channel, ingress policer profile, then a remark flag and six bits of DSCP");

/* Conntrack mark bits that select a route at a connection's creation and are
 * read by nothing after it: mwan3's, pbr's, a VPN client's policy routing.
 * Linux resolved the route those bits chose when it created the flow, and the
 * flow keeps it on either fast path, so a mark inside them refuses nothing.
 * By naming them the operator states that nothing else reads them once the
 * connection exists -- no forward or postrouting rule, no tc filter, connmark
 * or ctinfo action, no re-marking expected to re-route a live connection --
 * which Linux's own software flowtable assumes of a flow too, since none of
 * those see its packets either. IPsec policy is the exception the adapter
 * enforces itself: under a policy such a direction stays in software
 * (ft_ipsec_handle()). Bits inside qos_mark_mask stay the class's, and the
 * two masks may not overlap. Zero, the default, keeps the contract above.
 *
 * Boot-immutable like the class mask, for the controller's sake: it renders
 * its admission guard from both masks when it applies a policy, and a change
 * it did not see would leave that guard offering what the adapter refuses,
 * or refusing what it would take. */
unsigned int ft_route_mark_mask;
module_param_named(route_mark_mask, ft_route_mark_mask, uint, 0444);
MODULE_PARM_DESC(route_mark_mask, "Conntrack mark bits that only select a route at connection creation (mwan3, pbr); a mark within them is admitted");

/* Reject a class the hardware cannot express rather than truncating it into a
 * different queue, which would accelerate the flow onto a queue nobody asked
 * for instead of declining it. */
bool ft_qos_class_valid(unsigned int class)
{
	return !(class & ~CDX_FT_QOS_MASK) &&
		((class & CDX_FT_QOS_CHANNEL_MASK) >> CDX_FT_QOS_CHANNEL_SHIFT) <=
			CDX_FT_QOS_MAX_CHANNEL &&
		((class & CDX_FT_QOS_POLICER_MASK) >> CDX_FT_QOS_POLICER_SHIFT) <=
			CDX_FT_QOS_MAX_POLICER;
}

/* Map a conntrack mark onto a class. The masked bits are shifted down to their
 * own base so an operator can place the field anywhere in the word and share
 * the rest with policy routing or a VPN's own marks.
 *
 * Nineteen bits are spoken for — four each for class queue, channel and ingress
 * policer, then a flag and six bits of DSCP to remark with — leaving thirteen
 * of a 32-bit mark to the operator. A mask narrower than the fields an operator
 * uses is not an error: the bits it does not cover read zero, which is this
 * encoding's "unspecified" in every position, including a clear remark flag. */
u32 ft_qos_class(u32 mark)
{
	if (!ft_qos_mark_mask)
		return 0;
	mark = (mark & ft_qos_mark_mask) >> __ffs(ft_qos_mark_mask);
	return mark ? mark : ft_qos_default_class;
}

/* Whether any class this decode can produce carries a remark: a bit of the
 * mark that shifts onto the remark flag, or a default class with one. Fixed
 * for the module's life, since both parameters are. */
static bool ft_qos_remarks(void)
{
	if (!ft_qos_mark_mask)
		return false;
	return ((ft_qos_mark_mask >> __ffs(ft_qos_mark_mask)) & CDX_FT_QOS_REMARK_MASK) ||
	       (ft_qos_default_class & CDX_FT_QOS_REMARK_MASK);
}

/* The class of the connection an IP packet belongs to, for cdx's software Tx
 * path (cdx_ft_qos_class_fn): the decode above, applied to the same mark the
 * flow's hardware rule was given its class from.
 *
 * The conntrack an skb carries answers for its own header. A frame reaches the
 * port without it when a scrub took it -- ppp_start_xmit() and the IP tunnels
 * drop it, and the ingress index with it -- and a packet an IP-in-IP frame
 * carries never had one on this skb at all. Conntrack is then asked by the
 * packet's tuple. The port sees a packet after NAT, which makes its tuple the
 * inverse of the tuple the other direction is keyed on, so the inverse is
 * what is looked up; for an untranslated packet it is the reply tuple, which
 * finds the same entry. Only the default zone is searched.
 *
 * Not looked up: a frame untracked on purpose (_nfct without a conntrack is
 * IP_CT_UNTRACKED), and one still carrying its ingress index, which crossed no
 * scrub and so kept whatever it had. Nor while interrupts are off, as netpoll
 * sends: the reference dropped below could be the last, and freeing a
 * conntrack takes locks that must not be taken there. With no mask every
 * class is zero, and no lookup can change that. */
static bool ft_qos_flow_class(const struct sk_buff *skb, unsigned int nhoff,
			      u8 family, bool own, u32 *class)
{
	struct nf_conntrack_tuple tuple, inverse;
	struct nf_conntrack_tuple_hash *h;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct net *net;
	u32 mark;

	if (own) {
		ct = nf_ct_get(skb, &ctinfo);
		if (ct) {
			*class = ft_qos_class(READ_ONCE(ct->mark));
			return true;
		}
		if (skb->_nfct || skb->skb_iif)
			return false;
	}
	if (!family || !ft_qos_mark_mask || irqs_disabled() || !skb->dev)
		return false;
	net = dev_net(skb->dev);
	if (!nf_ct_get_tuplepr(skb, nhoff, family == AF_INET6 ? NFPROTO_IPV6 : NFPROTO_IPV4,
			       net, &tuple) ||
	    !nf_ct_invert_tuple(&inverse, &tuple))
		return false;
	h = nf_conntrack_find_get(net, &nf_ct_zone_dflt, &inverse);
	if (!h)
		return false;
	ct = nf_ct_tuplehash_to_ctrack(h);
	mark = READ_ONCE(ct->mark);
	nf_ct_put(ct);
	*class = ft_qos_class(mark);
	return true;
}

static struct notifier_block ft_netdev_nb = { .notifier_call = ft_netdev_event };
static struct notifier_block ft_fdb_nb = { .notifier_call = ft_fdb_event };
static struct notifier_block ft_swdev_nb = { .notifier_call = ft_swdev_event };
static struct notifier_block ft_neigh_nb = { .notifier_call = ft_neigh_event };
static struct notifier_block ft_fib_nb = { .notifier_call = ft_fib_event };
static struct notifier_block ft_nexthop_nb = { .notifier_call = ft_nexthop_event };

/* /proc/ask_flowtable; docs/flowtable/procfs.md is the reference for what each
 * file holds and why.
 *
 * The flows and l2 files are paged: seq_file holds the transaction for one
 * buffer of rows and resumes by position once it has let it go, so a reader
 * taking several reads must tolerate the table changing between them. A
 * position is the hash bucket in the upper word and the row's offset within
 * that bucket in the lower, so resuming walks only its own bucket rather than
 * every row before it, and no row pointer survives the transaction between
 * reads. */
static void *ft_flow_at(loff_t *pos)
{
	unsigned int bucket = *pos >> 32, skip = (u32)*pos;
	struct cdx_ft_entry *entry;

	for (; bucket < HASH_SIZE(ft_cookies); bucket++) {
		hlist_for_each_entry(entry, &ft_cookies[bucket], cookie_node) {
			if (skip) {
				skip--;
				continue;
			}
			return entry;
		}
		*pos = (loff_t)(bucket + 1) << 32;
		skip = 0;
	}
	return NULL;
}

static void *ft_flows_start(struct seq_file *seq, loff_t *pos)
{
	cdx_ft_begin();
	return ft_flow_at(pos);
}

static void *ft_flows_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct cdx_ft_entry *entry = v;

	if (entry->cookie_node.next) {
		(*pos)++;
		return hlist_entry(entry->cookie_node.next, struct cdx_ft_entry,
				   cookie_node);
	}
	*pos = ((*pos >> 32) + 1) << 32;
	return ft_flow_at(pos);
}

/* The bridged pairs' rows, addressed the same way over ft_l2_pairs. */
static void *ft_l2_at(loff_t *pos)
{
	unsigned int bucket = *pos >> 32, skip = (u32)*pos;
	struct list_head *row;

	for (; bucket < ft_l2_row_buckets(); bucket++) {
		row = ft_l2_row(bucket, &skip);
		if (row)
			return row;
		*pos = (loff_t)(bucket + 1) << 32;
		skip = 0;
	}
	return NULL;
}

static void *ft_l2_start(struct seq_file *seq, loff_t *pos)
{
	cdx_ft_begin();
	return ft_l2_at(pos);
}

static void *ft_l2_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct list_head *row = ft_l2_row_next(v);

	if (row) {
		(*pos)++;
		return row;
	}
	*pos = ((*pos >> 32) + 1) << 32;
	return ft_l2_at(pos);
}

static void ft_rows_stop(struct seq_file *seq, void *v)
{
	cdx_ft_end();
}

/* Outermost first, dot separated, "-" when the direction carries no tag. One
 * whitespace-free token per direction keeps the row parseable. */
static void ft_vlan_text(const struct cdx_ft_vlan *stack, u8 count, char *text, size_t size)
{
	unsigned int at = 0;
	u8 i;

	if (!count) {
		strscpy(text, "-", size);
		return;
	}
	for (i = 0; i < count; i++)
		at += scnprintf(text + at, size - at, i ? ".%u" : "%u", stack[i].id);
}

/* The name a record's device has now, or "-" once it has left this namespace
 * and the record is waiting on the last direction naming it. gone is written
 * by the notifier under its own lock, which this walk, under the transaction,
 * does not take. */
static const char *ft_dev_stats_name(const struct cdx_ft_dev_stats *record, char *name)
{
	struct net_device *dev;

	rcu_read_lock();
	dev = READ_ONCE(record->gone) ? NULL :
		dev_get_by_index_rcu(&init_net, record->ifindex);
	strscpy(name, dev ? netdev_name(dev) : "-", IFNAMSIZ);
	rcu_read_unlock();
	return name;
}

/* One row per device with a record of the given kind, whether or not the pool
 * had a slot for it: a device without one is the visible face of an exhausted
 * pool -- the flows forward either way, and this is what says which of them
 * are being counted. The counts are the firmware's own totals, whole frames,
 * with packets carried past the 32 bits the firmware keeps exactly as the fold
 * carries them; the device's `ip -s link` shows the same records restated in
 * its units, so the two differ by exactly the framing and nothing else. A ppp
 * device's row also carries the session its last admitted direction named, in
 * the form the flow rows use in in_ppp=/out_ppp=, so the two can be joined.
 * The devices file renders them as one record rather than paging them as the
 * flows are, because there is one per device, which is the number of uplinks
 * and VLANs rather than the number of connections. */
static void ft_tunnel_text(const struct cdx_ft_tunnel *tunnel, char *text, size_t size);

static void ft_dev_rows(struct seq_file *seq, enum cdx_ft_stats_kind kind, bool tunnel)
{
	struct cdx_ft_dev_stats *record;
	struct cdx_ft_stats rx, tx;
	char name[IFNAMSIZ], tnl[IFNAMSIZ + 100];

	list_for_each_entry(record, &ft_dev_stats, list) {
		if (record->kind != kind || record->tunnel.present != tunnel)
			continue;
		cdx_ft_stats_read(record->slot, &rx, &tx);
		if (kind == CDX_FT_STATS_TIMESTAMPED)
			seq_printf(seq,
				   "session dev=%s ifindex=%d pppoe=%u@%pM lower=%d refs=%u slot=%s rx_packets=%llu rx_bytes=%llu tx_packets=%llu tx_bytes=%llu\n",
				   ft_dev_stats_name(record, name), record->ifindex,
				   record->session.id, record->session.mac,
				   record->session.lower_ifindex, record->refs,
				   record->slot ? "yes" : "none",
				   rx.packets, rx.bytes, tx.packets, tx.bytes);
		else if (tunnel) {
			/* The same identity the flow rows carry, so the two can
			 * be joined, plus the device the outer packet leaves by. */
			ft_tunnel_text(&record->tunnel, tnl, sizeof(tnl));
			seq_printf(seq,
				   "tunnel dev=%s ifindex=%d tnl=%s lower=%d refs=%u slot=%s rx_packets=%llu rx_bytes=%llu tx_packets=%llu tx_bytes=%llu\n",
				   ft_dev_stats_name(record, name), record->ifindex, tnl,
				   record->tunnel.lower_ifindex, record->refs,
				   record->slot ? "yes" : "none",
				   rx.packets, rx.bytes, tx.packets, tx.bytes);
		} else
			seq_printf(seq,
				   "vlan dev=%s ifindex=%d refs=%u slot=%s rx_packets=%llu rx_bytes=%llu tx_packets=%llu tx_bytes=%llu\n",
				   ft_dev_stats_name(record, name), record->ifindex, record->refs,
				   record->slot ? "yes" : "none",
				   rx.packets, rx.bytes, tx.packets, tx.bytes);
	}
}

/* The PPPoE session, as the id and the concentrator the path walk resolved.
 * Both are shown for either direction even though only an egress session is
 * inserted: the two come from the same walk, so a direction that strips and
 * one that inserts naming the same pair is what shows the connection agrees
 * with itself. Both match one line of /proc/net/pppoe, which is where the
 * negotiated session can be read back independently. */
static void ft_session_text(const struct cdx_ft_session *session, char *text,
			    size_t size)
{
	if (!session->present)
		strscpy(text, "-", size);
	else
		scnprintf(text, size, "%u@%pM", session->id, session->mac);
}

/* The tunnel as the device, the mode and the outer endpoints local first,
 * which is how `ip -d link show` describes the device too. Shown for either
 * direction, because both come from the same walk and the strip side naming
 * the same tunnel as the insert side is what shows the connection agrees with
 * itself. An IPv6 endpoint is bracketed, as the row's other addresses are, so
 * the whole stays one whitespace-free token. */
static void ft_tunnel_text(const struct cdx_ft_tunnel *tunnel, char *text, size_t size)
{
	struct net_device *dev;
	const char *mode = tunnel->mode == CDX_FT_TUNNEL_6O4 ? "6o4" : "4o6";
	char name[IFNAMSIZ];

	if (!tunnel->present) {
		strscpy(text, "-", size);
		return;
	}
	/* By index and under RCU rather than by a pinned pointer: the record
	 * rows outlive the flows that pinned the device. */
	rcu_read_lock();
	dev = dev_get_by_index_rcu(&init_net, tunnel->ifindex);
	strscpy(name, dev ? dev->name : "?", sizeof(name));
	rcu_read_unlock();
	if (tunnel->family == AF_INET6)
		scnprintf(text, size, "%s/%s:[%pI6c]>[%pI6c]", name, mode,
			  &tunnel->local.in6, &tunnel->remote.in6);
	else
		scnprintf(text, size, "%s/%s:%pI4>%pI4", name, mode,
			  &tunnel->local.ip, &tunnel->remote.ip);
}

/* The bridge, and the VID its FDB lookup was keyed on. That VID is not always
 * one of the tags: on an untagged egress port the frame carries none at all,
 * which is exactly the configuration a vlan-aware bridge ships with. */
static void ft_bridge_text(const struct net_device *bridge, u16 vid, char *text,
			   size_t size)
{
	if (!bridge)
		strscpy(text, "-", size);
	else if (vid)
		scnprintf(text, size, "%s.%u", bridge->name, vid);
	else
		strscpy(text, bridge->name, size);
}

static int ft_flows_show(struct seq_file *seq, void *v)
{
	struct cdx_ft_entry *entry = v;
	struct cdx_ft_counters stats;
	char in_vlan[16], out_vlan[16];
	char in_br[IFNAMSIZ + 8], out_br[IFNAMSIZ + 8];
	char in_ppp[26], out_ppp[26];
	char in_tnl[IFNAMSIZ + 100], out_tnl[IFNAMSIZ + 100];
	char nexthop[sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")];

	cdx_ft_stats(entry->hw, &stats);
	ft_tunnel_text(&entry->rule.in_tunnel, in_tnl, sizeof(in_tnl));
	ft_tunnel_text(&entry->rule.out_tunnel, out_tnl, sizeof(out_tnl));
	ft_vlan_text(entry->rule.in_vlan, entry->rule.in_vlans, in_vlan, sizeof(in_vlan));
	ft_vlan_text(entry->rule.out_vlan, entry->rule.out_vlans, out_vlan, sizeof(out_vlan));
	ft_bridge_text(entry->rule.in_bridge, entry->rule.in_bridge_vid, in_br, sizeof(in_br));
	ft_bridge_text(entry->rule.out_bridge, entry->rule.out_bridge_vid, out_br,
		       sizeof(out_br));
	ft_session_text(&entry->rule.in_session, in_ppp, sizeof(in_ppp));
	ft_session_text(&entry->rule.out_session, out_ppp, sizeof(out_ppp));
	/* In its own family, which is not the row's for a flow encrypted by an
	 * SA of the other family. */
	if (entry->rule.next_hop_family == AF_INET6)
		snprintf(nexthop, sizeof(nexthop), "%pI6c", &entry->next_hop.in6);
	else
		snprintf(nexthop, sizeof(nexthop), "%pI4", &entry->next_hop.ip);
	/* One row shape per family. Brackets keep an IPv6 address and its port
	 * a single whitespace-free token, as the IPv4 rows already are. */
	if (entry->rule.family == AF_INET6)
		seq_printf(seq, "flow cookie=%lx in=%s out=%s in_vlan=%s out_vlan=%s in_br=%s out_br=%s in_ppp=%s out_ppp=%s in_tnl=%s out_tnl=%s family=6 src=[%pI6c]:%u dst=[%pI6c]:%u new_src=[%pI6c]:%u new_dst=[%pI6c]:%u proto=%u mtu=%u qos=%05x sa=%u in_sa=%u detour=%u nexthop=%s packets=%llu bytes=%llu lastused=%u\n",
			   entry->cookie, entry->rule.in->name, entry->rule.out->name,
			   in_vlan, out_vlan, in_br, out_br, in_ppp, out_ppp,
			   in_tnl, out_tnl,
			   &entry->rule.src.in6, ntohs(entry->rule.sport),
			   &entry->rule.dst.in6, ntohs(entry->rule.dport),
			   &entry->rule.new_src.in6, ntohs(entry->rule.new_sport),
			   &entry->rule.new_dst.in6, ntohs(entry->rule.new_dport),
			   entry->rule.proto, entry->rule.mtu, entry->rule.qos,
			   entry->rule.sa_handle, entry->rule.in_sa_handle,
			   entry->rule.detour,
			   nexthop, stats.packets, stats.bytes, stats.lastused);
	else
		seq_printf(seq, "flow cookie=%lx in=%s out=%s in_vlan=%s out_vlan=%s in_br=%s out_br=%s in_ppp=%s out_ppp=%s in_tnl=%s out_tnl=%s family=4 src=%pI4:%u dst=%pI4:%u new_src=%pI4:%u new_dst=%pI4:%u proto=%u mtu=%u qos=%05x sa=%u in_sa=%u detour=%u nexthop=%s packets=%llu bytes=%llu lastused=%u\n",
			   entry->cookie, entry->rule.in->name, entry->rule.out->name,
			   in_vlan, out_vlan, in_br, out_br, in_ppp, out_ppp,
			   in_tnl, out_tnl,
			   &entry->rule.src.ip, ntohs(entry->rule.sport),
			   &entry->rule.dst.ip, ntohs(entry->rule.dport),
			   &entry->rule.new_src.ip, ntohs(entry->rule.new_sport),
			   &entry->rule.new_dst.ip, ntohs(entry->rule.new_dport),
			   entry->rule.proto, entry->rule.mtu, entry->rule.qos,
			   entry->rule.sa_handle, entry->rule.in_sa_handle,
			   entry->rule.detour,
			   nexthop, stats.packets, stats.bytes, stats.lastused);
	return 0;
}

static int ft_l2_show(struct seq_file *seq, void *v)
{
	ft_l2_show_row(seq, v);
	return 0;
}

/* A status or stats line, laid out as /proc/meminfo lays out its own: the name
 * and its colon padded to FT_KEY_COLUMNS, then the value right-aligned in the
 * FT_VALUE_COLUMNS after. At least one space always follows the colon, so a
 * key too long for the column, or a value too wide for its own, still parses
 * by splitting at the colon. */
#define FT_KEY_COLUMNS		36
#define FT_VALUE_COLUMNS	12

void ft_kv(struct seq_file *seq, const char *key, u64 value)
{
	int pad = FT_KEY_COLUMNS - 1 - (int)strlen(key);

	seq_printf(seq, "%s:%*s%*llu\n", key, pad < 1 ? 1 : pad, "", FT_VALUE_COLUMNS,
		   (unsigned long long)value);
}

/* What the backend holds now, and its latches: levels, which go down as well
 * as up. Read under the transaction, which the latch machinery's accessors
 * require and which makes the whole file one consistent reading; it walks no
 * flow or group, so the hold is short. This is what the controller's health
 * probe and its drain wait read. */
static int ft_status_show(struct seq_file *seq, void *v)
{
	unsigned int session_records = 0, session_slots = 0, vlan_records = 0, vlan_slots = 0;
	unsigned int tunnel_records = 0, tunnel_slots = 0, stats_retained;
	unsigned int ids4, ids6, id_slots;
	struct cdx_ft_dev_stats *record;
	struct cdx_detour_counters detour;
	u64 stats_deferred;

	cdx_ft_begin();
	list_for_each_entry(record, &ft_dev_stats, list) {
		if (record->kind == CDX_FT_STATS_TIMESTAMPED) {
			session_records++;
			session_slots += !!record->slot;
		} else if (record->tunnel.present) {
			tunnel_records++;
			tunnel_slots += !!record->slot;
		} else {
			vlan_records++;
			vlan_slots += !!record->slot;
		}
	}
	ft_kv(seq, "entries", ft_count);
	ft_kv(seq, "max_entries", CDX_FT_MAX_ENTRIES);
	ft_kv(seq, "bindings", ft_bound);
	ft_kv(seq, "passive", ft_passive);
	ft_kv(seq, "parked", ft_parked);
	ft_kv(seq, "neighbour_refs", ft_neighbour_refs);
	ft_kv(seq, "handle_refs", ft_handle_refs);
	ft_kv(seq, "invalidated", atomic_read(&ft_invalid));
	ft_kv(seq, "invalidation_done", ft_invalid_complete());
	/* fatal is CDX's latch, held from a deletion it could not prove until
	 * it has restarted the datapath; bypassed says the classifier ports run
	 * past the classifier meanwhile, the datapath forwarding in software,
	 * restarts counts the restarts done, and resume_failures the classifier
	 * ports they could not start again. What a restart waits for is CDX's
	 * flowtable_degraded_reason. */
	ft_kv(seq, "fatal", cdx_ft_failed());
	/* Retirements whose barrier failed, or that wait on CDX's own proof;
	 * one merely owed a barrier is counted apart, and for no longer than
	 * until its retirement's last batch, the FT_SETTLE_BOUND-th unlink owed
	 * or ft_settle_work. */
	ft_kv(seq, "quarantine", cdx_ft_pending() - cdx_ft_owed());
	ft_kv(seq, "owed", cdx_ft_owed());
	ft_kv(seq, "rearm_ready", ft_can_rearm());
	ft_kv(seq, "bypassed", cdx_ft_bypassed());
	ft_kv(seq, "restarts", cdx_ft_restarts());
	ft_kv(seq, "resume_failures", cdx_ft_resume_failures());
	/* The SAs this adapter installed, and every SA cdx's cache holds: an
	 * install refused part-way has to leave both where they were. */
	ft_kv(seq, "ipsec_sas", cdx_ipsec_sa_count());
	ft_kv(seq, "ipsec_sa_cache", cdx_ipsec_sa_cache_entries());
	/* Device records this module has let go that stay out of the pool
	 * because a retired entry naming them is not yet proven gone, of any
	 * kind; and how many releases have had to wait that way since CDX
	 * loaded. The first returns to zero with every completed retirement,
	 * so one that stays up is a slot recovery never gave back. */
	cdx_ft_stats_retention(&stats_retained, &stats_deferred);
	ft_kv(seq, "stats_retained", stats_retained);
	ft_kv(seq, "stats_deferred", stats_deferred);
	/* The device records of each kind, and how many of them the pool had a
	 * hardware counter slot for; the devices file names them. */
	ft_kv(seq, "session_records", session_records);
	ft_kv(seq, "session_slots", session_slots);
	ft_kv(seq, "vlan_records", vlan_records);
	ft_kv(seq, "vlan_slots", vlan_slots);
	ft_kv(seq, "tunnel_records", tunnel_records);
	ft_kv(seq, "tunnel_slots", tunnel_slots);
	/* The offline-port detour (cdx_detour.c): whether it is up, and the
	 * directions it carries. */
	cdx_detour_counters(&detour);
	ft_kv(seq, "detour", cdx_ft_detour_ready());
	ft_kv(seq, "detour_flows", detour.flows);
	/* Memberships the bridge reported, and the flows learned from traffic
	 * that they and the routed learner's routes name; `installed` counts
	 * flows, each one classifier entry. Of those installed, `discarding`
	 * are the flows the bridge forwards nowhere, whose entries drop their
	 * stream rather than hand it to the CPU, and `parked` the ones still
	 * named, waiting outside the caps for an id (A315). */
	ft_kv(seq, "mcast_hooked", READ_ONCE(ft_mc_hooked));
	ft_kv(seq, "mcast_groups", READ_ONCE(ft_mc_count));
	ft_kv(seq, "mcast_flows", READ_ONCE(ft_mc_flow_count));
	ft_kv(seq, "mcast_installed", READ_ONCE(ft_mc_installed));
	ft_kv(seq, "mcast_discarding", READ_ONCE(ft_mc_discarding));
	ft_kv(seq, "mcast_parked", ft_mc_parked());
	/* The group ids both learners' groups hold, per family, and how many
	 * each family has -- the same number for both: what a group that finds
	 * none left, and reads refused-failed, ran out of. */
	ids4 = cdx_mc_group_ids(AF_INET, &id_slots);
	ids6 = cdx_mc_group_ids(AF_INET6, NULL);
	ft_kv(seq, "mcast_group_ids4", ids4);
	ft_kv(seq, "mcast_group_ids6", ids6);
	ft_kv(seq, "mcast_group_id_slots", id_slots);
	/* The routed learner's groups and what of them is in hardware.
	 * policy_rules is the one an operator is most likely to need: a single
	 * non-default ipmr rule keeps every group of that family in software,
	 * and nothing else on the box would say so. ruleset_settled is whether
	 * the ruleset has stood still long enough since its last commit for
	 * copies to confirm under it -- followed only while a routed group
	 * exists, so with none it is the last value read, which may predate a
	 * commit. */
	ft_kv(seq, "mroute_groups", READ_ONCE(ft_mr_count));
	ft_kv(seq, "mroute_installed", READ_ONCE(ft_mr_installed));
	ft_kv(seq, "mroute_policy_rules", READ_ONCE(ft_mr_policy[0]) + READ_ONCE(ft_mr_policy[1]));
	ft_kv(seq, "mroute_ruleset_settled", READ_ONCE(ft_mr_gen_open));
	ft_l2_status(seq);
	/* How many AP-mode devices this module currently has registered. With
	 * wifi_refused, it separates "no Wi-Fi offload because nothing asked"
	 * from "no Wi-Fi offload because the registration failed", which are
	 * otherwise the same absence: the per-VAP sysfs file under
	 * /sys/class/vwd/ appears only on success. */
	ft_kv(seq, "wifi_vaps", READ_ONCE(ft_wifi_registered));
	cdx_ft_end();
	return 0;
}

/* What has happened since the module loaded: counters, which only grow. Read
 * without the transaction. Each is written under its own lock, a whole word
 * at a time, and loaded here once, marked; a reader taking deltas needs
 * nothing more, and one polling this never waits behind the backend. */
static int ft_stats_show(struct seq_file *seq, void *v)
{
	struct cdx_detour_counters detour;

	ft_kv(seq, "installs", READ_ONCE(ft_installs));
	ft_kv(seq, "deletes", READ_ONCE(ft_deletes));
	ft_kv(seq, "rejects", READ_ONCE(ft_rejects));
	ft_kv(seq, "errors", READ_ONCE(ft_errors));
	ft_kv(seq, "validated", READ_ONCE(ft_validated));
	ft_kv(seq, "busy", READ_ONCE(ft_busy));
	ft_kv(seq, "rearms", READ_ONCE(ft_rearms));
	/* The non-empty last deltas directions reported through their flow's
	 * handle as they left the hardware, for whatever reason they left;
	 * counted whether or not the table counts, which decides only whether
	 * conntrack takes them. */
	ft_kv(seq, "finals", READ_ONCE(ft_finals));
	/* The counter passes that reached every entry (ft_stats_workfn()), and
	 * the requests Netfilter made for a flow's counters itself, which a
	 * pass keeps it from making. */
	ft_kv(seq, "stats_passes", READ_ONCE(ft_stats_passes));
	ft_kv(seq, "stats_requests", READ_ONCE(ft_stats_requests));
	/* Linux's deletions that found the transaction held and left what
	 * they named, if anything was in hardware, to the retirement worker. */
	ft_kv(seq, "destroy_deferrals", atomic64_read(&ft_destroy_deferrals));
	ft_kv(seq, "neighbour_invalidations", atomic64_read(&ft_neigh_invalidations));
	ft_kv(seq, "route_invalidations", atomic64_read(&ft_route_invalidations));
	ft_kv(seq, "mtu_invalidations", atomic64_read(&ft_mtu_invalidations));
	ft_kv(seq, "link_invalidations", atomic64_read(&ft_link_invalidations));
	ft_kv(seq, "mac_invalidations", atomic64_read(&ft_mac_invalidations));
	ft_kv(seq, "fdb_invalidations", atomic64_read(&ft_fdb_invalidations));
	ft_kv(seq, "stp_invalidations", atomic64_read(&ft_stp_invalidations));
	ft_kv(seq, "qos_invalidations", atomic64_read(&ft_qos_invalidations));
	ft_kv(seq, "admission_invalidations", atomic64_read(&ft_admission_invalidations));
	ft_kv(seq, "ipsec_invalidations", atomic64_read(&ft_ipsec_invalidations));
	ft_kv(seq, "ipsec_policy_invalidations", atomic64_read(&ft_ipsec_policy_invalidations));
	ft_kv(seq, "ipsec_next_hop_updates", atomic64_read(&ft_ipsec_next_hop_updates));
	/* Frames the software path forwarded unchanged because their header
	 * could not be made writable for the remark their class asks for, and
	 * control frames sent as unclassified traffic because their port's
	 * control budget was spent. */
	ft_kv(seq, "qos_remark_failures", cdx_ft_qos_remark_failures());
	ft_kv(seq, "qos_control_overruns", cdx_ft_qos_control_overruns());
	ft_sec_refusal_stats(seq);
	/* What the offline port handed back: given to Linux, with no direction
	 * to give it to, not copied, or in error. */
	cdx_detour_counters(&detour);
	ft_kv(seq, "detour_delivered", detour.delivered);
	ft_kv(seq, "detour_unknown", detour.unknown);
	ft_kv(seq, "detour_failed", detour.failed);
	ft_kv(seq, "detour_errors", detour.errors);
	/* The bridged learner. deferred counts frames whose set of dedup slots
	 * had none to give them yet, which their next frame asks for again;
	 * passes the bridged worker's runs, each of which takes the
	 * transaction; forgets the times every slot was forgotten, each making
	 * every stream news once more (ft_mc_record()). port_probe_errors are
	 * flows whose ports' netdev chains could not be judged
	 * (ft_mc_netdev_dependent()); discards_evicted the discarding entries
	 * that gave their group id up to a stream somebody wants;
	 * egress_rebuilds the installed groups of either learner marked for a
	 * rebuild because a port they copy out of changed its egress -- its
	 * queues or its DSCP map (ft_mc_egress_changed()). */
	ft_kv(seq, "mcast_refused", READ_ONCE(ft_mc_refused));
	ft_kv(seq, "mcast_install_errors", READ_ONCE(ft_mc_install_errors));
	ft_kv(seq, "mcast_observed", READ_ONCE(ft_mc_observed));
	ft_kv(seq, "mcast_dropped", READ_ONCE(ft_mc_dropped));
	ft_kv(seq, "mcast_hook_errors", READ_ONCE(ft_mc_hook_errors));
	ft_kv(seq, "mcast_deferred", READ_ONCE(ft_mc_deferred));
	ft_kv(seq, "mcast_passes", READ_ONCE(ft_mc_passes));
	ft_kv(seq, "mcast_forgets", READ_ONCE(ft_mc_forgets));
	ft_kv(seq, "mcast_port_probe_errors", READ_ONCE(ft_mc_port_probe_errors));
	ft_kv(seq, "mcast_discards_evicted", READ_ONCE(ft_mc_discards_evicted));
	ft_kv(seq, "mcast_egress_rebuilds", atomic64_read(&ft_mc_egress_rebuilds));
	/* The routed learner. lost counts chain events dropped for want of
	 * memory, which is the only way this learner's view can be behind the
	 * kernel's; capped the entries the per-family group cap turned away
	 * (A309); xfrm_changes the XFRM policy changes every routed group was
	 * asked again for -- an IPv4 group a policy governs reads
	 * refused-xfrm; ruleset_changes the nftables commits that took every
	 * routed group back to software to be confirmed again; confirm_errors
	 * how often the forwarding check could not be registered or a group's
	 * watch allocated, which keeps groups in software with nothing else to
	 * say why; port_probe_errors how often a confirmed group's ruleset was
	 * too much for a port probe to judge, which reads refused-ports or
	 * refused-xtables all the same; and xtables_changes how many times an
	 * iptables-legacy table changed while a routed group existed, each of
	 * which asked every group again. */
	ft_kv(seq, "mroute_refused", READ_ONCE(ft_mr_refused));
	ft_kv(seq, "mroute_install_errors", READ_ONCE(ft_mr_install_errors));
	ft_kv(seq, "mroute_lost", READ_ONCE(ft_mr_lost));
	ft_kv(seq, "mroute_capped", READ_ONCE(ft_mr_capped_entries));
	ft_kv(seq, "mroute_xfrm_changes", atomic64_read(&ft_mr_xfrm_changes));
	ft_kv(seq, "mroute_ruleset_changes", READ_ONCE(ft_mr_ruleset_changes));
	ft_kv(seq, "mroute_confirm_errors", READ_ONCE(ft_mr_confirm_errors));
	ft_kv(seq, "mroute_port_probe_errors", READ_ONCE(ft_mr_port_probe_errors));
	ft_kv(seq, "mroute_xtables_changes", READ_ONCE(ft_mr_xtables_changes));
	ft_l2_stats(seq);
	ft_kv(seq, "wifi_refused", atomic64_read(&ft_wifi_refusals));
	return 0;
}

/* One row per device whose encapsulation the hardware carries, under the
 * transaction the record slots are read under. */
static int ft_devices_show(struct seq_file *seq, void *v)
{
	cdx_ft_begin();
	ft_dev_rows(seq, CDX_FT_STATS_TIMESTAMPED, false);
	ft_dev_rows(seq, CDX_FT_STATS_PLAIN, false);
	ft_dev_rows(seq, CDX_FT_STATS_PLAIN, true);
	cdx_ft_end();
	return 0;
}

/* The multicast learners' rows. Each learner's lock is taken inside the
 * transaction, the order every path that takes both keeps. */
static int ft_mcast_show(struct seq_file *seq, void *v)
{
	cdx_ft_begin();
	ft_mc_rows(seq);
	cdx_ft_end();
	return 0;
}

static int ft_mroute_show(struct seq_file *seq, void *v)
{
	cdx_ft_begin();
	ft_mr_rows(seq);
	cdx_ft_end();
	return 0;
}

static const struct seq_operations ft_flows_ops = {
	.start = ft_flows_start,
	.next = ft_flows_next,
	.stop = ft_rows_stop,
	.show = ft_flows_show,
};

static const struct seq_operations ft_l2_ops = {
	.start = ft_l2_start,
	.next = ft_l2_next,
	.stop = ft_rows_stop,
	.show = ft_l2_show,
};

/* What a multicast record takes: a row for each bridged flow, each bridged
 * membership waiting for one and each routed group, of about this length --
 * 215 bytes on average at the caps; one with long port lists runs to some
 * 750, and a record that outgrows the guess doubles as before. Never more
 * than FT_RECORD_MAX up front. */
#define FT_ROW_BYTES		320
#define FT_RECORD_MAX		(4U << 20)

/* Room for the whole record in one go. seq_file starts from a page and
 * doubles, rendering the record again from the start each time, and each
 * render is a hold of the transaction of its own: six for the 517 rows a
 * family's multicast caps make, any of which could wait behind a batch of a
 * learner's retirement (A312). Counted without the learners' locks: a record
 * that has outgrown the guess by the time it is read is doubled as before. */
static int ft_open_sized(struct file *file, int (*show)(struct seq_file *, void *),
			 size_t rows)
{
	size_t size = min_t(size_t, FT_RECORD_MAX, PAGE_SIZE + FT_ROW_BYTES * rows);
	struct seq_file *seq;
	int rc;

	rc = single_open(file, show, NULL);
	if (rc)
		return rc;
	if (size > PAGE_SIZE) {
		seq = file->private_data;
		seq->buf = kvmalloc(size, GFP_KERNEL_ACCOUNT | __GFP_NOWARN);
		if (seq->buf)
			seq->size = size;
	}
	return 0;
}

static int ft_mcast_open(struct inode *inode, struct file *file)
{
	return ft_open_sized(file, ft_mcast_show,
			     (size_t)READ_ONCE(ft_mc_flow_count) + READ_ONCE(ft_mc_count));
}

static int ft_mroute_open(struct inode *inode, struct file *file)
{
	return ft_open_sized(file, ft_mroute_show, READ_ONCE(ft_mr_count));
}

static const struct proc_ops ft_mcast_proc_ops = {
	.proc_open = ft_mcast_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static const struct proc_ops ft_mroute_proc_ops = {
	.proc_open = ft_mroute_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

/* The directory and its files, or nothing: a file that could not be made
 * takes the directory, and every file made in it, back with it. */
static int ft_proc_init(void)
{
	struct proc_dir_entry *dir;

	dir = proc_mkdir("ask_flowtable", NULL);
	if (!dir)
		return -ENOMEM;
	if (!proc_create_single("status", 0400, dir, ft_status_show) ||
	    !proc_create_single("stats", 0400, dir, ft_stats_show) ||
	    !proc_create_single("devices", 0400, dir, ft_devices_show) ||
	    !proc_create_seq("flows", 0400, dir, &ft_flows_ops) ||
	    !proc_create_seq("l2", 0400, dir, &ft_l2_ops) ||
	    !proc_create("mcast", 0400, dir, &ft_mcast_proc_ops) ||
	    !proc_create("mroute", 0400, dir, &ft_mroute_proc_ops)) {
		proc_remove(dir);
		return -ENOMEM;
	}
	ft_proc = dir;
	return 0;
}

/* Give back the callbacks Netfilter is still holding.
 *
 * A bind installs a flow_block_cb into the flowtable's own block, and
 * Netfilter keeps it until something unbinds. flow_indr_dev_unregister()
 * unwinds the *indirect* binds for us and knows nothing about the direct
 * ones -- which is every bind since the driver grew an ndo_setup_tc, because
 * that is what nf_flow_table_offload_setup() prefers once it exists. Left
 * behind, the callback still points into this module's text, and the next
 * queued offload calls it: flow_offload_work_handler faulting on freed text
 * with the flowtable itself perfectly healthy. Both exit and a load that
 * fails after opening a route owe this.
 *
 * Any callback still on the driver list belongs to a table that is still
 * live, because a table on its way out unbinds first. Its lock is therefore
 * safe to take, and taking it for write is also what waits out a callback
 * already running on nf_flow_offload_tuple()'s read side -- so no caller is
 * inside this text by the time it goes.
 */
static void ft_block_drain(void)
{
	struct flow_block_cb *cb, *next;
	struct nf_flowtable *table;

	list_for_each_entry_safe(cb, next, &ft_block_list, driver_list) {
		/* Passive or real alike: both carry their table. */
		table = ((struct cdx_ft_binding *)cb->cb_priv)->table;
		down_write(&table->flow_block_lock);
		list_del(&cb->list);
		up_write(&table->flow_block_lock);
		list_del(&cb->driver_list);
		/* Runs ft_release(), which retires this binding's entries and
		 * drops its device reference, exactly as an unbind would. */
		flow_block_cb_free(cb);
	}
}

/* Every deletion left unproven, proven: a barrier completes, or -- after one
 * that may have left its key linked -- no port walks the tables any more, as
 * the backend requires of an -EIO. Both unload and a load unwinding its own
 * failure owe this before the device records go and the claim is released,
 * and neither can count on the invalidation worker for it: ft_invalidate()
 * does nothing once ft_stopping is set. It cannot fail, so it waits,
 * releasing the transaction between attempts so configuration and other
 * kernel work can progress. A latch stays in CDX: a later load is refused
 * until CDX has restarted the datapath. */
static void ft_hw_settle(void)
{
	int rc;

	for (;;) {
		cdx_ft_begin();
		rc = cdx_ft_recover();
		cdx_ft_end();
		if (!rc)
			return;
		pr_warn_ratelimited("ask_flowtable: waiting for safe hardware retirement before releasing CDX\n");
		msleep(1000);
	}
}

static bool ft_init_fault(unsigned int stage)
{
#ifdef CDX_DEBUG_FLOWTABLE
	return ft_init_fail_stage == stage;
#else
	return false;
#endif
}

static int __init ask_flowtable_init(void)
{
	int rc;

	/* Refuse a classification the adapter would have to truncate. Both
	 * values are boot-immutable, so checking once here is the only chance
	 * to say so out loud; silently narrowing them would accelerate flows
	 * onto queues the operator never named. */
	if (ft_qos_mark_mask &&
	    (ft_qos_mark_mask >> __ffs(ft_qos_mark_mask)) > CDX_FT_QOS_MASK) {
		pr_err("cdx flowtable: qos_mark_mask %#x spans more than the %u bits of a class\n",
		       ft_qos_mark_mask, (unsigned int)fls(CDX_FT_QOS_MASK));
		return -EINVAL;
	}
	if (ft_qos_mark_mask & ft_route_mark_mask) {
		pr_err("cdx flowtable: route_mark_mask %#x overlaps qos_mark_mask %#x\n",
		       ft_route_mark_mask, ft_qos_mark_mask);
		return -EINVAL;
	}
	if (!ft_qos_class_valid(ft_qos_default_class)) {
		pr_err("cdx flowtable: qos_default_class %#x names no CEETM queue\n",
		       ft_qos_default_class);
		return -EINVAL;
	}
	ft_hash_seed = get_random_u32();
	/* Exported symbol dependencies pin a fully initialized CDX throughout
	 * this module's lifetime, including failed initialization and exit. */
	cdx_ft_begin();
	rc = cdx_ft_claim();
	/* What SEC refused before this module existed is not its to count:
	 * this reading is where its counting starts. */
	if (!rc)
		ft_sec_refusals_fold();
	cdx_ft_end();
	if (rc)
		return rc;
	rc = ft_init_fault(1) ? -ENOMEM : ft_proc_init();
	if (rc)
		goto release;
	/* Be told when a port's egress changes under its entries -- before
	 * anything can build one. The netdev replay below attaches the ports
	 * an SA is installed through, and a flow needs the binds after it; an
	 * entry built before this, from egress that changed before it too,
	 * would never be re-installed. */
	rc = ft_init_fault(11) ? -EBUSY : cdx_register_ft_egress(&ft_egress_ops);
	if (rc)
		goto proc;
	rc = ft_init_fault(2) ? -ENOMEM : register_netdevice_notifier(&ft_netdev_nb);
	if (rc)
		goto egress;
	rc = ft_init_fault(3) ? -ENOMEM : register_netevent_notifier(&ft_neigh_nb);
	if (rc)
		goto netdev;
	rc = ft_init_fault(4) ? -ENOMEM : register_fib_notifier(&init_net, &ft_fib_nb, NULL, NULL);
	if (rc)
		goto neigh;
	/* A registration retry can replay the same rules more than once.
	 * Replace its queued multicast mirror before authorizing hardware. */
	set_bit(0, &ft_mr_resync_pending);
	set_bit(1, &ft_mr_resync_pending);
	/* The x_tables tables as they stand are what the first groups are
	 * judged against, and no change to count. */
	ft_mr_xt_seen = nf_xt_seq(&init_net);
	smp_store_release(&ft_mr_ready, true);
	schedule_work(&ft_mr_work);
	rc = ft_init_fault(6) ? -ENOMEM : register_nexthop_notifier(&init_net, &ft_nexthop_nb, NULL);
	if (rc)
		goto fib;
	rc = ft_init_fault(7) ? -ENOMEM : register_switchdev_notifier(&ft_fdb_nb);
	if (rc)
		goto nexthop;
	rc = ft_init_fault(8) ? -ENOMEM : register_switchdev_blocking_notifier(&ft_swdev_nb);
	if (rc)
		goto fdb;
	/* The chain replays nothing on registration; the memberships already
	 * standing are asked for instead. */
	ft_mc_replay();
	WRITE_ONCE(ft_ready, true);
	/* The multicast switch wakes both learners only from here on; one
	 * flipped while they were starting is answered by this wake. */
	ft_mc_switched();
	/* The bridged unicast learner's hook, once every event that retires a
	 * pair it installs can arrive. */
	ft_l2_init();
	rc = ft_init_fault(5) ? -ENOMEM : flow_indr_dev_register(ft_bind, NULL);
	if (rc)
		goto not_ready;
	/* Both routes stay registered. Which one Netfilter uses is the driver's
	 * choice, not ours, and a kernel without the ndo has only the indirect
	 * one -- so the adapter has to serve whichever arrives. The direct route
	 * arrives through CDX, which holds the driver's single ndo_setup_tc slot
	 * because it also serves the hardware qdisc on the same callback. */
	rc = ft_init_fault(9) ? -EBUSY : cdx_register_ft_setup_tc(cdx_ft_setup_tc);
	if (rc)
		goto indirect;
	/* Hand the classifier over too, so a frame the software path sends
	 * takes the class this same decode gave the flow's hardware rule. */
	rc = ft_init_fault(10) ? -EBUSY :
	     cdx_register_ft_qos_class(ft_qos_flow_class, ft_qos_remarks());
	if (!rc)
		return 0;
	cdx_unregister_ft_setup_tc();
indirect:
	/* A route was open, so binds may have arrived and be carrying flows,
	 * with work queued on their behalf. Unwind them the way exit does:
	 * stop new binds and requeueing, and exclude Linux's cached lookups,
	 * in one transaction; give the indirect binds back, then drain the
	 * direct ones, which Netfilter would otherwise keep pointing into
	 * text about to go. */
	cdx_ft_begin();
	WRITE_ONCE(ft_stopping, true);
	{
		struct cdx_ft_entry *entry;

		list_for_each_entry(entry, &ft_entries, list)
			nf_flow_offload_handle_invalidate(entry->handle);
	}
	cdx_ft_end();
	flow_indr_dev_unregister(ft_bind, NULL, ft_release);
	ft_block_drain();
not_ready:
	/* ft_rearm() reads ft_ready under the transaction, so clearing it
	 * there means no pass that starts later requeues a parked retry. The
	 * works themselves are cancelled below, once CDX's egress hook, which
	 * can queue retirement, is closed too. */
	cdx_ft_begin();
	WRITE_ONCE(ft_ready, false);
	cdx_ft_end();
	unregister_switchdev_blocking_notifier(&ft_swdev_nb);
	/* A port may have stopped since the chain was registered: its sweep
	 * runs this module's code, so it finishes before the text goes. */
	flush_work(&ft_stopped_work);
fdb:
	unregister_switchdev_notifier(&ft_fdb_nb);
nexthop:
	unregister_nexthop_notifier(&init_net, &ft_nexthop_nb);
fib:
	unregister_fib_notifier(&init_net, &ft_fib_nb);
neigh:
	unregister_netevent_notifier(&ft_neigh_nb);
netdev:
	unregister_netdevice_notifier(&ft_netdev_nb);
	/* Before the work below is cancelled, as on unload: the hook marks
	 * entries and SAs and queues the passes that act on them. */
	cdx_unregister_ft_egress();
	/* A route may have been open, with work queued on a binding's behalf.
	 * With ft_stopping set nothing requeues retirement or the installer,
	 * with ft_ready clear nothing requeues a parked retry, and with every
	 * binding gone and the notifiers and the egress hook closed nothing is
	 * left to queue any of them, so these cancels are final. */
	cancel_work_sync(&ft_retire_work);
	cancel_work_sync(&ft_settle_work);
	ft_deferred_destroys_drop();
	cancel_delayed_work_sync(&ft_work);
	cancel_delayed_work_sync(&ft_rearm_work);
	/* Both chains are unregistered above, so nothing can add a membership
	 * or an MFC entry while these drain. What already existed was replayed
	 * at registration -- the FIB notifier dumps every VIF and MFC entry,
	 * and ft_mc_replay() asks every bridge port for its port groups -- so a
	 * failure after those points has memberships, flows, hardware entries
	 * and pinned devices to give back, and a worker holding a pointer into
	 * text about to go. */
	ft_mc_exit();
	ft_mr_exit();
	ft_l2_exit();
	/* The notifier's registration replayed NETDEV_REGISTER and attached
	 * every port, so a failure after that point has ports to give back.
	 * No SA can have been installed through them: xfrm_dev_ops_get()
	 * hands out the ops of a module only once it is live, so xfrm offers
	 * this one no state or policy until init has returned. */
	ft_ipsec_detach_all();
	/* The same replay could have registered a VAP for an AP interface that
	 * already existed, so this failure path owes them back too. */
	ft_wifi_exit();
	/* Idle for that reason, and drained anyway: each costs nothing when
	 * there is nothing queued, and none may outlive this text. */
	flush_work(&ft_ipsec_retire);
	ft_ipsec_forget_all();
	cancel_delayed_work_sync(&ft_ipsec_stats);
	/* Disabled rather than cancelled: a write of stats_ms, which sysfs
	 * still takes until the module is freed, queues nothing after this. */
	disable_delayed_work_sync(&ft_stats_work);
	cancel_work_sync(&ft_ipsec_follow);
	ft_ipsec_watch_flush();
	/* The drain above deleted whatever the binds had installed, and a
	 * delete it could not prove queued no recovery: this proves it, or
	 * stops the datapath after an -EIO, before the records the entries
	 * named are dropped and the claim goes. */
	ft_hw_settle();
	/* A flow admitted through the indirect bind before the failure claimed
	 * device records, and those outlive their flows by design, so the
	 * unwind has to drop them: left behind, their slots would stay
	 * published against live devices from memory about to be unmapped. The
	 * notifier that could queue the reaper is already unregistered above. */
	cancel_work_sync(&ft_dev_stats_work);
	ft_dev_stats_drop_all();
	goto proc;
egress:
	/* Nothing the hook could mark exists before the netdev replay. */
	cdx_unregister_ft_egress();
proc:
	proc_remove(ft_proc);
	ft_proc = NULL;
release:
	cdx_ft_begin();
	WARN_ON_ONCE(cdx_ft_release());
	cdx_ft_end();
	return rc;
}

static void __exit ask_flowtable_exit(void)
{
	struct cdx_ft_entry *entry;

	proc_remove(ft_proc);
	ft_proc = NULL;
	/* Exclude cached Linux lookup before draining hardware. Unregistering
	 * indirect blocks then performs native flow cleanup and excludes all
	 * callbacks before releasing their binding storage. */
	cdx_ft_begin();
	WRITE_ONCE(ft_stopping, true);
	list_for_each_entry(entry, &ft_entries, list)
		nf_flow_offload_handle_invalidate(entry->handle);
	cdx_ft_end();
	unregister_switchdev_blocking_notifier(&ft_swdev_nb);
	/* After the chain that queues it, and while the rule callbacks its
	 * native cleanup flushes are still registered: a port that stopped
	 * forwarding just before unload still has its software flows taken
	 * away, and the work's text outlives it. */
	flush_work(&ft_stopped_work);
	unregister_switchdev_notifier(&ft_fdb_nb);
	unregister_nexthop_notifier(&init_net, &ft_nexthop_nb);
	unregister_fib_notifier(&init_net, &ft_fib_nb);
	unregister_netevent_notifier(&ft_neigh_nb);
	unregister_netdevice_notifier(&ft_netdev_nb);
	/* CDX's egress hook is the other thing that marks entries and SAs, and
	 * no notifier above is what excludes it. Close it with them, before
	 * any of the work it queues is cancelled below; this also waits out a
	 * call already inside it. */
	cdx_unregister_ft_egress();
	/* After the switchdev chain is gone, so nothing can add a membership
	 * while the groups drain, and before the module's text does -- the
	 * worker holds a pointer into it. */
	ft_mc_exit();
	/* And after the FIB chain, for the same reason one family over: the
	 * routed learner's events arrive there. It goes second so that a key
	 * the bridged learner hands back cannot wake a worker this has already
	 * stopped -- ft_mr_kick() answers to ft_mr_stopping either way, but
	 * the order makes that a property rather than a coincidence. */
	ft_mr_exit();
	/* And the bridged unicast pairs, whose events arrive on the chains
	 * closed above: the hook goes, then the worker, then every entry. */
	ft_l2_exit();
	/* Likewise for the VAPs, and before the module's text goes: the
	 * reconciling worker holds a pointer into it. */
	ft_wifi_exit();
	/* Unregistration replays nothing, so the ops this module planted on
	 * each port have to be taken back by hand -- they point into text
	 * that is about to go away. */
	ft_ipsec_detach_all();
	/* Detaching stops new retirements being queued; this drains the ones
	 * already queued. Both are needed before the work item's own code can
	 * be unmapped, and this order is the only one that ends with an empty
	 * list. What the retirements kept for a re-add goes with them: no SA
	 * can be added through this module again. */
	flush_work(&ft_ipsec_retire);
	ft_ipsec_forget_all();
	/* The accounting pass requeues itself only while an SA is owned, and
	 * none is by now: every offloaded state pins this module through its
	 * ops, and xfrm deletes a state before it lets it go. */
	cancel_delayed_work_sync(&ft_ipsec_stats);
	/* Disabled rather than cancelled: a write of stats_ms, which sysfs
	 * still takes until the module is freed, queues nothing after this. */
	disable_delayed_work_sync(&ft_stats_work);
	/* The last SA's retirement counted what SEC had refused by then; this
	 * counts whatever SEC finished refusing after it, the last this module
	 * will. */
	cdx_ft_begin();
	ft_sec_refusals_fold();
	cdx_ft_end();
	/* The notifiers that mark a watch are gone above, so nothing can queue
	 * this again; stop the pass in flight and drop the watches it walked,
	 * which are this module's memory rather than the kernel's. */
	cancel_work_sync(&ft_ipsec_follow);
	ft_ipsec_watch_flush();
	cancel_work_sync(&ft_retire_work);
	/* An unlink it would have settled stays counted as pending, which
	 * ft_hw_settle() below proves before CDX is released. */
	cancel_work_sync(&ft_settle_work);
	cancel_delayed_work_sync(&ft_work);
	/* ft_stopping, set above, already stops a parked rearm requeueing
	 * itself; this waits out the pass in flight. */
	cancel_delayed_work_sync(&ft_rearm_work);
	/* Direct first: it is the route a DPAA port actually takes, so closing
	 * it stops new binds before the indirect one is torn down. The
	 * classifier goes with it, and waits out the frames inside it. */
	cdx_unregister_ft_setup_tc();
	cdx_unregister_ft_qos_class();
	flow_indr_dev_unregister(ft_bind, NULL, ft_release);
	/* Indirect binds are gone with the line above; the direct ones are
	 * still Netfilter's, and nothing else will ever hand them back. */
	ft_block_drain();
	/* The retirement work is cancelled above and the bindings are gone,
	 * so nothing retires or records a deferred deletion any more. */
	ft_deferred_destroys_drop();
	WRITE_ONCE(ft_ready, false);
	/* Exit cannot fail. Complete every barrier, or prove hardware stopped,
	 * before releasing CDX. The drain above removed every direction and
	 * nothing is left that could add one, so the release finds none. */
	ft_hw_settle();
	cdx_ft_begin();
	WARN_ON_ONCE(cdx_ft_release());
	cdx_ft_end();
	/* The device records are held by their devices, which are still here,
	 * so the list does not drain on its own; the release above proved that
	 * nothing references them. The notifier that could queue the reaper is
	 * already unregistered above. */
	cancel_work_sync(&ft_dev_stats_work);
	ft_dev_stats_drop_all();
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ASK Linux flowtable adapter using the CDX hardware backend");
MODULE_IMPORT_NS(ASK_CDX_FLOWTABLE);
module_init(ask_flowtable_init);
module_exit(ask_flowtable_exit);
