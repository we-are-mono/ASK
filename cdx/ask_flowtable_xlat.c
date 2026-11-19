// SPDX-License-Identifier: GPL-2.0-or-later
/* Translated sessions (NAT64, SIIT): the admission source a translator offers
 * them through (ask_xlat.h), beside Netfilter's.
 *
 * A session's two directions are decided together and installed together, or
 * neither, through the install every source shares (ft_install()), and are
 * owned by one refcounted owner. Once installed they are flowtable entries
 * like any other: on ft_entries and the watch list, in the cookie and key
 * indexes, counted in the one budget, retired by the same route, neighbour,
 * device, FDB, tc and invalidation events, reported by the same counter pass,
 * and drained by the same batched retirement and barriers. What they lack is
 * a binding and a Netfilter handle, and the rest of this file is what stands
 * in for those:
 *
 * - The owner (struct ft_xlat_owner) takes the place of the handle: valid and
 *   invalidate are a flag, set for good; account and used turn the counter
 *   pass's deltas into the translator's keepalive; release counts the
 *   entries out. A session offered again after its owner was invalidated
 *   gets a fresh owner.
 * - ft_xlat_list stands in for a binding's entries: every translated entry is
 *   on it by its binding_node, so ft_unlink() takes it off as it would a
 *   binding's, and unregistration and unload drain by it as a binding's
 *   release drains its own. The entry holds its ingress port itself, which a
 *   binding would have pinned. A withdrawn session's entries are found by
 *   cookie (ft_cookies, under no binding) and retired directly, as a deferred
 *   Netfilter deletion's are, never by walking the table.
 * - The queue stands in for Netfilter's offer: a translator calls from
 *   softirq, so an offer is copied into a bounded ring and decided by a
 *   worker under the backend transaction and RTNL taken without waiting, as
 *   the bridged learner decides its pairs (ask_flowtable_l2.c). One RTNL lost
 *   requeues it.
 *
 * Each session the translator offers is answered by exactly one `expired',
 * unless it withdraws it first (ask_xlat.h), and at any moment exactly one
 * thing owes that answer: the offer that stands for the session -- queued, or
 * in the worker's hands -- or, once the offer has installed the session, its
 * owner. Everything below keeps it so:
 *
 * - An offer of a session something already stands for is folded into it:
 *   into a live owner, into the offer in the worker's hands, into the queued
 *   one (which it replaces). Only a session nothing stands for is queued
 *   afresh, and queueing it takes the answer from every owner of it still on
 *   its way out of the hardware (`answers' cleared): the offer's outcome is
 *   what is said.
 * - An offer that installs the session hands the answer to its owner. One
 *   refused hands it back to an owner of the session still leaving the
 *   hardware, if there is one, so the session is not said gone while entries
 *   of it still forward; and says it itself only when there is none.
 * - An owner that leaves with the answer hands it to another owner of the
 *   session still leaving, if there is one; the last says it.
 * - A withdrawal takes the answer from everything; and an answer already being
 *   said when one lands -- decided, its call under way -- is reported to the
 *   withdrawal, so the translator knows one more `expired' of the old session
 *   is coming. Nothing standing for a session is forgotten until its answer
 *   has been said, which is how a withdrawal can know.
 *
 * Path resolution is the decoder's, for routes looked up here: the egress
 * route for the translated destination, in the translated family, as the
 * translator routes its own packets; its next hop and neighbour; the physical
 * port the kernel's own forwarding-path walk reaches; and the tags, bridge and
 * session ft_path_stack() derives from it. A direction arrives with the
 * physical port, tags and session its sibling leaves with, so the two paths
 * resolved are each direction's egress and the other's ingress, and the
 * translator's ingress device has to be the one the sibling leaves by.
 *
 * Locks: ft_xlat_lock, a spinlock taken with bottom halves off, guards the
 * ring, the in-flight batch's state, the owners' index, their answer and
 * withdrawal state, the direct retirement queue and the client pointer. It
 * nests inside the backend transaction and never around it, and takes nothing
 * itself but what queueing the worker takes. No callback is made with it held.
 */
#include "ask_flowtable_internal.h"
#include "ask_xlat.h"

static_assert(ASK_XLAT_TOS_COPY == CDX_FT_XLAT_TOS_COPY);

/* Offers queued and not yet decided: enough for a burst of new sessions
 * between two runs of the worker. An offer of a session already queued
 * replaces it rather than taking a slot. */
#define FT_XLAT_RING		64
/* Sessions decided per hold of the transaction and RTNL: each installs two
 * entries, a host-command round trip apiece, so a run holds both for eight
 * adds at most -- the order of a multicast learner's batch of deletes
 * (FT_MC_RETIRE_BATCH), which /proc and every admission wait out as well --
 * and lets them go before the next. */
#define FT_XLAT_BATCH		4
/* Translated directions in the hardware at once: half the budget every
 * source shares, so translation cannot starve the flowtable of it. */
#define FT_XLAT_MAX_ENTRIES	(CDX_FT_MAX_ENTRIES / 2)
/* How soon an offer that lost RTNL is tried again. */
#define FT_XLAT_RETRY		(HZ / 20)
#define FT_XLAT_HASH_BITS	10

/* A session in the hardware, or being put there, on its translator's behalf;
 * see the file's head. */
struct ft_xlat_owner {
	struct ft_owner owner;
	/* In ft_xlat_owners by cookie, from before its first direction is
	 * installed until its last reference goes and, if it owed the answer,
	 * that answer has been said. Under ft_xlat_lock. */
	struct hlist_node node;
	/* On ft_xlat_retiring while its entries wait to be retired directly: a
	 * withdrawal's, a restart's. Under ft_xlat_lock. */
	struct list_head retiring;
	u64 cookie;
	/* One per direction holding it, and the admission's own while it
	 * installs them. Under the transaction. */
	unsigned int refs;
	atomic_t invalid;
	/* Under ft_xlat_lock: the translator withdrew it, and nothing is said
	 * about it; it owes the session's answer, said when it leaves (see the
	 * file's head); and that answer is being said now. */
	bool withdrawn;
	bool answers;
	bool saying;
	/* The keepalive, under the transaction (ft_xlat_owner_used()): a
	 * direction counted packets since the session was last said used; the
	 * direction just accounted for did; the latest last use among those;
	 * and the counter pass that last said it. */
	bool moved;
	bool fresh;
	unsigned long lastused;
	u32 said;
};

/* One offer, as the translator made it, in the ring or in the worker's hands.
 * Under ft_xlat_lock: withdrawn first; refused, its answer being said; and
 * decided, so it stands for the session no more. */
struct ft_xlat_offer {
	struct ask_xlat_flow flow;
	bool cancelled;
	bool answering;
	bool done;
};

/* One direction's egress, resolved from its route: everything a rule takes
 * of it, and the destination, held until the recheck after publication. Its
 * sibling arrives this way, so it is that one's ingress too. */
struct ft_xlat_path {
	struct dst_entry *dst;
	u32 cookie;
	struct net_device *logical;
	struct net_device *port;
	struct net_device *bridge;
	struct net_device *source;
	struct cdx_ft_vlan vlan[CDX_FT_VLAN_MAX];
	u8 vlans;
	u16 bridge_vid;
	struct cdx_ft_session session;
	union nf_inet_addr next_hop;
	u8 mac[ETH_ALEN];
	u32 mtu;
	bool mtu_follows_dev;
};

/* What one admission works on: both directions' paths and rules, and the
 * forwarding-path walk a port is found by -- more than a worker's stack takes
 * under KASAN, which pads every one of them. Admission is the worker's alone,
 * under the backend transaction, which is what this is guarded by. */
static struct {
	struct ft_xlat_path path[2];
	struct cdx_ft_rule rule[2];
	struct net_device_path_stack walk;
} ft_xlat_scratch;

static DEFINE_SPINLOCK(ft_xlat_lock);
/* The registered client, and whether it is unregistering: written under the
 * transaction and ft_xlat_lock both, so either one makes a read stable. */
static const struct ask_xlat_ops *ft_xlat_client;
static bool ft_xlat_closing;
static struct ft_xlat_offer ft_xlat_ring[FT_XLAT_RING];
static unsigned int ft_xlat_head, ft_xlat_tail;
/* What the worker has taken off the ring and not yet decided, so that a
 * withdrawal and an offer of the same session find it there too. Only the
 * worker, or an unregistration with the worker stopped, writes the flows; the
 * flags and the count are ft_xlat_lock's. */
static struct ft_xlat_offer ft_xlat_inflight[FT_XLAT_BATCH];
static unsigned int ft_xlat_ninflight;
static DEFINE_HASHTABLE(ft_xlat_owners, FT_XLAT_HASH_BITS);
static LIST_HEAD(ft_xlat_retiring);
bool ft_xlat_active;
unsigned int ft_xlat_count;
LIST_HEAD(ft_xlat_list);
/* Owners alive, under the transaction. */
static unsigned int ft_xlat_sessions;
/* Counters for /proc: offers queued or folded, and turned away for a full
 * ring, under ft_xlat_lock; installs, refusals, lost RTNL, expired and used
 * said, under the transaction; offers turned away for an MTU certain to refuse
 * them, withdrawals and restart retirements, as atomics. */
static u64 ft_xlat_offers, ft_xlat_dropped;
static u64 ft_xlat_installs, ft_xlat_refused, ft_xlat_busy, ft_xlat_expired, ft_xlat_used;
static atomic64_t ft_xlat_mtu_refusals = ATOMIC64_INIT(0);
static atomic64_t ft_xlat_withdrawals = ATOMIC64_INIT(0);
static atomic64_t ft_xlat_restart_invalidations = ATOMIC64_INIT(0);
static void ft_xlat_workfn(struct work_struct *work);
static DECLARE_DELAYED_WORK(ft_xlat_work, ft_xlat_workfn);

/* ---------------------------------------------------------------- owner */

static struct ft_xlat_owner *ft_xlat_of(struct ft_owner *owner)
{
	return container_of(owner, struct ft_xlat_owner, owner);
}

static bool ft_xlat_owner_valid(const struct ft_owner *owner)
{
	return !atomic_read(&container_of_const(owner, struct ft_xlat_owner, owner)->invalid);
}

static bool ft_xlat_owner_invalidate(struct ft_owner *owner)
{
	return !atomic_xchg(&ft_xlat_of(owner)->invalid, 1);
}

/* The answer said. Under the transaction, with ft_xlat_lock not held: the
 * client takes locks of its own, which it may hold while it calls in. */
static void ft_xlat_expire(u64 cookie)
{
	ft_xlat_expired++;
	if (ft_xlat_client)
		ft_xlat_client->expired(cookie);
}

/* A direction's delta, bytes and all: only whether it moved matters here, the
 * translator counting its sessions by their timers rather than their bytes.
 * The last delta a direction reports as it leaves comes here too, and counts
 * toward the next keepalive. */
static void ft_xlat_owner_account(struct ft_owner *owner, u8 dir, u64 packets, u64 bytes)
{
	if (packets)
		ft_xlat_of(owner)->fresh = true;
}

/* After each direction's account, in the counter pass. A session whose
 * directions moved is said used at most once a pass, with the later of their
 * last uses: what its sibling moved after that in the same pass is said by
 * the next one. */
static void ft_xlat_owner_used(struct ft_owner *owner, unsigned long lastused)
{
	struct ft_xlat_owner *o = ft_xlat_of(owner);

	if (o->fresh) {
		if (!o->moved || time_after(lastused, o->lastused))
			o->lastused = lastused;
		o->moved = true;
		o->fresh = false;
	}
	if (!o->moved || o->said == ft_stats_pass)
		return;
	o->moved = false;
	o->said = ft_stats_pass;
	ft_xlat_used++;
	if (ft_xlat_client)
		ft_xlat_client->used(o->cookie, o->lastused);
}

/* An owner of @cookie other than @except still leaving the hardware, which an
 * answer can wait for: not withdrawn and not saying an answer already. Under
 * ft_xlat_lock. */
static struct ft_xlat_owner *ft_xlat_heir(u64 cookie, const struct ft_xlat_owner *except)
{
	struct ft_xlat_owner *o;

	hash_for_each_possible(ft_xlat_owners, o, node, cookie)
		if (o != except && o->cookie == cookie && !o->withdrawn && !o->saying)
			return o;
	return NULL;
}

/* A reference given back. The last one takes the owner out of the index and
 * the direct retirement queue, and if it owed the answer, hands it to an owner
 * of the session still leaving or, with none, says it. Under the
 * transaction. */
static void ft_xlat_put(struct ft_xlat_owner *o)
{
	struct ft_xlat_owner *heir;
	bool say = false;

	cdx_ft_assert_held();
	if (--o->refs)
		return;
	spin_lock_bh(&ft_xlat_lock);
	list_del_init(&o->retiring);
	if (o->answers && !o->withdrawn) {
		heir = ft_xlat_heir(o->cookie, o);
		if (heir)
			heir->answers = true;
		else
			say = o->saying = true;
	}
	/* One saying stays findable until it has said it, so a withdrawal
	 * landing meanwhile learns it came too late. */
	if (!say)
		hash_del(&o->node);
	spin_unlock_bh(&ft_xlat_lock);
	ft_xlat_sessions--;
	if (say) {
		ft_xlat_expire(o->cookie);
		spin_lock_bh(&ft_xlat_lock);
		hash_del(&o->node);
		spin_unlock_bh(&ft_xlat_lock);
	}
	kfree(o);
}

/* A direction's reference, as ft_owner_release() gives it back: each was
 * counted in ft_xlat_count when it was attached. */
static void ft_xlat_owner_release(struct ft_owner *owner)
{
	ft_xlat_count--;
	ft_xlat_put(ft_xlat_of(owner));
}

static const struct ft_owner_ops ft_xlat_owner_ops = {
	.valid = ft_xlat_owner_valid,
	.invalidate = ft_xlat_owner_invalidate,
	.account = ft_xlat_owner_account,
	.used = ft_xlat_owner_used,
	.release = ft_xlat_owner_release,
};

/* Mark an owner retired and queue its entries for direct retirement, found by
 * cookie rather than by walking the table. True when this marked it. Under
 * ft_xlat_lock. */
static bool ft_xlat_retire(struct ft_xlat_owner *o)
{
	bool marked = ft_owner_mark(&o->owner);

	if (list_empty(&o->retiring))
		list_add_tail(&o->retiring, &ft_xlat_retiring);
	if (!ft_xlat_closing)
		mod_delayed_work(system_unbound_wq, &ft_xlat_work, 0);
	return marked;
}

/* ---------------------------------------------------------------- offers */

/* One side of a direction a hardware entry can be keyed on, or translate to:
 * a unicast pair the two ports route between, with both ports. */
static bool ft_xlat_tuple_valid(const struct ask_xlat_tuple *t)
{
	return (t->family == AF_INET || t->family == AF_INET6) &&
	       ft_endpoint(t->family, &t->src) && ft_endpoint(t->family, &t->dst) &&
	       t->sport && t->dport;
}

/* What an offer has to be before it is queued, decided from the offer alone. */
static bool ft_xlat_flow_valid(const struct ask_xlat_flow *flow)
{
	unsigned int d;

	if (!net_eq(flow->net, &init_net) ||
	    (flow->proto != IPPROTO_TCP && flow->proto != IPPROTO_UDP))
		return false;
	for (d = 0; d < ARRAY_SIZE(flow->dir); d++) {
		const struct ask_xlat_dir *dir = &flow->dir[d];

		if (!ft_xlat_tuple_valid(&dir->match) || !ft_xlat_tuple_valid(&dir->xlat) ||
		    dir->match.family == dir->xlat.family || dir->ifindex <= 0)
			return false;
	}
	/* The sibling translates the other way between the same two. */
	return flow->dir[0].match.family == flow->dir[1].xlat.family;
}

/* The unused words of an IPv4 address zeroed, as everything a rule is built
 * from has them: rules and keys compare and hash all four. */
static void ft_xlat_tuple_clean(struct ask_xlat_tuple *t)
{
	if (t->family == AF_INET) {
		t->src = (union nf_inet_addr){ .ip = t->src.ip };
		t->dst = (union nf_inet_addr){ .ip = t->dst.ip };
	}
}

/* The route the translator sends a direction's translated packets by, looked
 * up as it looks its own up -- an output route, from the translated source,
 * any source allowed (SIIT's needs not be local), with no xfrm lookup -- held
 * with the cookie it was selected under. Any context: both lookups take RCU
 * themselves. */
static struct dst_entry *ft_xlat_route(const struct ask_xlat_tuple *x, u8 proto, u32 *cookie)
{
	struct dst_entry *dst;

	*cookie = 0;
	if (x->family == AF_INET6) {
		struct flowi6 fl6 = {
			.daddr = x->dst.in6,
			.saddr = x->src.in6,
			.flowi6_proto = proto,
			.fl6_sport = x->sport,
			.fl6_dport = x->dport,
		};

		dst = ip6_route_output(&init_net, NULL, &fl6);
		if (dst->error) {
			dst_release(dst);
			return NULL;
		}
		*cookie = rt6_get_cookie(dst_rt6_info(dst));
		return dst;
	} else {
		struct flowi4 fl4 = {
			.daddr = x->dst.ip,
			.saddr = x->src.ip,
			.flowi4_proto = proto,
			.flowi4_flags = FLOWI_FLAG_ANYSRC,
			.fl4_sport = x->sport,
			.fl4_dport = x->dport,
		};
		struct rtable *rt = __ip_route_output_key(&init_net, &fl4);

		return IS_ERR(rt) ? NULL : &rt->dst;
	}
}

/* Whether a direction is certain to be refused on its MTU (ft_mtu_carried()),
 * decided from its route alone, before it is queued. The default NAT64 shape
 * is refused so -- a 1500-byte IPv4 uplink's packets are 1520 bytes as IPv6 on
 * a 1500-byte LAN -- and a translator offers such a session again as long as
 * it translates it; answering each offer from the queue would take RTNL and
 * the transaction every time to say the same. The answer read from the route
 * as it stands now needs no cache to go stale: each offer reads it again.
 *
 * Only a refusal the worker would certainly make is made here. What a port
 * delivers whole is never less than a full Ethernet payload
 * (ft_port_arriving()), less what the most an ingress strips takes off -- a
 * session, a tunnel being refused anyway -- and the entry's MTU is never more
 * than the route's. The directions the bound applies to are UDP, and TCP into
 * IPv4 (ft_mtu_carried()). */
static bool ft_xlat_mtu_refused(const struct ask_xlat_dir *dir, u8 proto)
{
	u32 least = ETH_DATA_LEN - PPPOE_SES_HLEN, cookie;
	struct dst_entry *dst;
	bool refused;

	if (proto == IPPROTO_TCP && dir->xlat.family == AF_INET6)
		return false;
	least = dir->xlat.family == AF_INET6 ? least + FT_XLAT_GROWTH : least - FT_XLAT_GROWTH;
	dst = ft_xlat_route(&dir->xlat, proto, &cookie);
	if (!dst)
		return false;
	refused = least > dst_mtu(dst);
	dst_release(dst);
	return refused;
}

/* Whatever already stands for the offer's session, under ft_xlat_lock: an
 * owner that is valid, an offer in the worker's hands, or one queued, which
 * this offer replaces; true when the offer is folded into one of them. An
 * answer being said for the session refuses the offer instead (-EBUSY): it
 * answers what came before, and the translator offers again after it. */
static int ft_xlat_fold(const struct ft_xlat_offer *offer)
{
	u64 cookie = offer->flow.cookie;
	struct ft_xlat_owner *o;
	unsigned int i;

	hash_for_each_possible(ft_xlat_owners, o, node, cookie) {
		if (o->cookie != cookie || o->withdrawn)
			continue;
		if (o->saying)
			return -EBUSY;
		if (ft_xlat_owner_valid(&o->owner))
			return 1;
	}
	for (i = 0; i < ft_xlat_ninflight; i++) {
		const struct ft_xlat_offer *held = &ft_xlat_inflight[i];

		if (held->flow.cookie != cookie || held->cancelled || held->done)
			continue;
		return held->answering ? -EBUSY : 1;
	}
	for (i = ft_xlat_tail; i != ft_xlat_head; i++) {
		struct ft_xlat_offer *slot = &ft_xlat_ring[i % FT_XLAT_RING];

		if (!slot->cancelled && slot->flow.cookie == cookie) {
			*slot = *offer;
			return 1;
		}
	}
	return 0;
}

bool ask_xlat_offer(const struct ask_xlat_flow *flow)
{
	struct ft_xlat_offer offer = { .flow = *flow };
	struct ft_xlat_owner *o;
	bool queued = false;
	unsigned int d;
	int folded;

	if (!ft_xlat_flow_valid(flow) || !READ_ONCE(ft_xlat_client))
		return false;
	for (d = 0; d < ARRAY_SIZE(flow->dir); d++)
		if (ft_xlat_mtu_refused(&flow->dir[d], flow->proto)) {
			atomic64_inc(&ft_xlat_mtu_refusals);
			return false;
		}
	/* Only the initial namespace is offloaded, which the checks above
	 * proved: nothing below follows the pointer. */
	offer.flow.net = NULL;
	for (d = 0; d < ARRAY_SIZE(offer.flow.dir); d++) {
		ft_xlat_tuple_clean(&offer.flow.dir[d].match);
		ft_xlat_tuple_clean(&offer.flow.dir[d].xlat);
	}
	spin_lock_bh(&ft_xlat_lock);
	if (!ft_xlat_client || ft_xlat_closing)
		goto out;
	folded = ft_xlat_fold(&offer);
	if (folded < 0)
		goto out;
	if (!folded) {
		if (ft_xlat_head - ft_xlat_tail >= FT_XLAT_RING) {
			ft_xlat_dropped++;
			goto out;
		}
		ft_xlat_ring[ft_xlat_head++ % FT_XLAT_RING] = offer;
		/* The offer stands for the session now: what any owner of it
		 * still leaving the hardware would have said, its outcome says. */
		hash_for_each_possible(ft_xlat_owners, o, node, offer.flow.cookie)
			if (o->cookie == offer.flow.cookie)
				o->answers = false;
	}
	queued = true;
	ft_xlat_offers++;
	/* Queued under the lock unregistration closes the queue under, so
	 * nothing queues the worker once that has cancelled it. */
	mod_delayed_work(system_unbound_wq, &ft_xlat_work, 0);
out:
	spin_unlock_bh(&ft_xlat_lock);
	return queued;
}
EXPORT_SYMBOL_NS_GPL(ask_xlat_offer, "ASK_XLAT");

bool ask_xlat_withdraw(u64 cookie)
{
	struct ft_xlat_owner *o;
	bool late = false;
	unsigned int i;
	u64 marked = 0;

	spin_lock_bh(&ft_xlat_lock);
	for (i = ft_xlat_tail; i != ft_xlat_head; i++)
		if (ft_xlat_ring[i % FT_XLAT_RING].flow.cookie == cookie)
			ft_xlat_ring[i % FT_XLAT_RING].cancelled = true;
	for (i = 0; i < ft_xlat_ninflight; i++) {
		struct ft_xlat_offer *held = &ft_xlat_inflight[i];

		if (held->flow.cookie != cookie)
			continue;
		late |= held->answering && !held->done;
		held->cancelled = true;
	}
	/* Every owner of it, a retiring one included: none says anything now,
	 * and each one's entries are retired directly. */
	hash_for_each_possible(ft_xlat_owners, o, node, cookie) {
		if (o->cookie != cookie)
			continue;
		if (o->saying) {
			late = true;
			continue;
		}
		if (o->withdrawn)
			continue;
		o->withdrawn = true;
		o->answers = false;
		marked += ft_xlat_retire(o);
	}
	spin_unlock_bh(&ft_xlat_lock);
	atomic64_add(marked, &ft_xlat_withdrawals);
	return !late;
}
EXPORT_SYMBOL_NS_GPL(ask_xlat_withdraw, "ASK_XLAT");

/* ------------------------------------------------------------ resolution */

/* The physical port the kernel's own forwarding-path walk reaches from
 * @logical for frames addressed to @mac -- down VLAN devices, through a bridge
 * by its FDB, under a PPPoE session -- and the session, if the walk crossed
 * one. Anything else on the way, a tunnel among it, is refused: the opcode
 * replaces the first IP header, which a tunnel's would be. The walk is only
 * where the port is found; ft_path_stack() derives the tags, bridge and session
 * again from the devices and checks them, as for any offer. Under the
 * transaction, and RTNL, which keeps the devices the walk names. */
static struct net_device *ft_xlat_port(struct net_device *logical, const u8 *mac,
				       struct nf_flow_session *session)
{
	struct net_device_path_stack *stack = &ft_xlat_scratch.walk;
	struct net_device *port = NULL;
	int i;

	rcu_read_lock();
	if (dev_fill_forward_path(logical, mac, stack) < 0 || !stack->num_paths ||
	    stack->path[stack->num_paths - 1].type != DEV_PATH_ETHERNET)
		goto out;
	for (i = 0; i < stack->num_paths - 1; i++) {
		const struct net_device_path *path = &stack->path[i];

		switch (path->type) {
		case DEV_PATH_VLAN:
		case DEV_PATH_BRIDGE:
			break;
		case DEV_PATH_PPPOE:
			/* A session is outermost: the ppp device is the logical
			 * one, and what the walk went on to is its lower. */
			if (i)
				goto out;
			session->id = path->encap.id;
			ether_addr_copy(session->h_dest, path->encap.h_dest);
			session->lower_ifindex = stack->path[i + 1].dev->ifindex;
			break;
		default:
			goto out;
		}
	}
	port = (struct net_device *)stack->path[stack->num_paths - 1].dev;
out:
	rcu_read_unlock();
	return port;
}

/* One direction's egress, from the route to its translated destination.
 * Under the transaction and RTNL. */
static int ft_xlat_path(const struct ask_xlat_dir *dir, u8 proto, struct ft_xlat_path *path)
{
	const struct ask_xlat_tuple *x = &dir->xlat;
	struct nf_flow_session session = {};
	struct nf_flow_tunnel tunnel = {};
	struct cdx_ft_tunnel no_tunnel;
	struct net_device *dev, *port;
	u32 dev_mtu;
	int vlans;

	memset(path, 0, sizeof(*path));
	path->dst = ft_xlat_route(x, proto, &path->cookie);
	if (!path->dst)
		return -EOPNOTSUPP;
	dev = path->dst->dev;
	/* An encapsulation or a tunnel would put a header of its own before the
	 * one the opcode replaces; a WireGuard egress is not proven to take a
	 * translated frame. No transform can be on the route: the lookup, like
	 * the translator's own, does none, and a policy change retires the
	 * session anyway (ft_policy_covers()). */
	if (!dev || !net_eq(dev_net(dev), &init_net) || path->dst->lwtstate ||
	    ft_tunnel_dev(dev) || cdx_ft_wg_dev(dev) ||
	    !ft_route_next_hop(path->dst, x->family, &x->dst, &path->next_hop))
		return -EOPNOTSUPP;
	path->logical = dev;
	path->mtu = dst_mtu(path->dst);
	dev_mtu = READ_ONCE(dev->mtu);
	/* A route's MTU set above its device's, which the device's own sends
	 * are bounded by, refuses the direction, as the decoder refuses a
	 * flow's (ft_parse()). */
	if (path->mtu > dev_mtu)
		return -EOPNOTSUPP;
	/* As the decoder takes it: an unlocked IPv6 route's MTU is its device's
	 * IPv6 MTU (ft_egress_mtu_current()). In the egress family. */
	path->mtu_follows_dev = x->family == AF_INET6 && !dst_metric_locked(path->dst, RTAX_MTU);
	/* A ppp device resolves no neighbour: below it the frame goes to the
	 * session's concentrator, which the walk names. */
	if (dev->type != ARPHRD_PPP &&
	    !ft_neigh_resolve(x->family, dev, &path->next_hop, path->mac))
		return -EOPNOTSUPP;
	port = ft_xlat_port(dev, path->mac, &session);
	if (!port)
		return -EOPNOTSUPP;
	vlans = ft_path_stack(dev, port, &session, &tunnel, path->vlan, &path->bridge,
			      &path->bridge_vid, &path->session, &no_tunnel, &path->source);
	if (vlans < 0)
		return vlans;
	path->vlans = vlans;
	path->port = port;
	if (path->session.present)
		ether_addr_copy(path->mac, path->session.mac);
	if (!path->source || !is_valid_ether_addr(path->source->dev_addr))
		return -EOPNOTSUPP;
	return 0;
}

/* Direction @d's rule: its own egress path, and its sibling's as its ingress.
 * The checks are the decoder's, each asked of the rule as the recheck of an
 * installed direction will find it (ft_entry_bounded()). Under the
 * transaction and RTNL. */
static int ft_xlat_rule(const struct ask_xlat_flow *flow, unsigned int d,
			const struct ft_xlat_path *path, struct cdx_ft_rule *rule)
{
	const struct ask_xlat_dir *dir = &flow->dir[d];
	const struct ft_xlat_path *out = &path[d], *in = &path[!d];
	u8 policer;
	u32 mtu;

	/* The translator received the direction on the device its sibling
	 * leaves by, or the port and tags the hardware would key it on are not
	 * the ones its frames arrive with. */
	if (in->logical->ifindex != dir->ifindex)
		return -EOPNOTSUPP;
	memset(rule, 0, sizeof(*rule));
	rule->family = dir->match.family;
	rule->xlat_family = dir->xlat.family;
	rule->xlat_tos = flow->tos;
	rule->proto = flow->proto;
	rule->src = dir->match.src;
	rule->dst = dir->match.dst;
	rule->sport = dir->match.sport;
	rule->dport = dir->match.dport;
	rule->new_src = dir->xlat.src;
	rule->new_dst = dir->xlat.dst;
	rule->new_sport = dir->xlat.sport;
	rule->new_dport = dir->xlat.dport;
	rule->in = in->port;
	rule->in_logical = in->logical;
	rule->in_bridge = in->bridge;
	rule->in_bridge_vid = in->bridge_vid;
	memcpy(rule->in_vlan, in->vlan, sizeof(rule->in_vlan));
	rule->in_vlans = in->vlans;
	rule->in_session = in->session;
	rule->out = out->port;
	rule->out_logical = out->logical;
	rule->out_bridge = out->bridge;
	rule->out_bridge_vid = out->bridge_vid;
	memcpy(rule->out_vlan, out->vlan, sizeof(rule->out_vlan));
	rule->out_vlans = out->vlans;
	rule->out_session = out->session;
	rule->next_hop_family = dir->xlat.family;
	ether_addr_copy(rule->dst_mac, out->mac);
	ether_addr_copy(rule->src_mac, out->source->dev_addr);
	/* Both ends DPAA ports: a translated frame into a VAP or out of one is
	 * not proven on the wire. */
	if (!cdx_ft_port_supported(rule->in) || !cdx_ft_port_supported(rule->out))
		return -EOPNOTSUPP;
	/* No conntrack, so no mark: the default class. */
	rule->qos = ft_qos_class(0);
	if (!ft_qos_class_valid(rule->qos) || ft_bridge_egress_filtered(rule) ||
	    ft_rule_tc_soft(rule))
		return -EOPNOTSUPP;
	/* The route's MTU, and no more than the port carries (ft_port_mtu()).
	 * The backend adds the opcode's slack itself (CDX_NATPT_SLACK). */
	mtu = min_t(u32, out->mtu, ft_port_mtu(rule));
	if (mtu < (rule->xlat_family == AF_INET6 ? IPV6_MIN_MTU : 68) || mtu > U16_MAX)
		return -EOPNOTSUPP;
	rule->mtu = mtu;
	rule->mtu_follows_dev = out->mtu_follows_dev;
	if (!ft_mtu_carried(rule, mtu) || !ft_egress_mtu_current(rule))
		return -EOPNOTSUPP;
	/* Last, as the decoder asks it: a police filter matches the finished
	 * tuple, the one the direction arrives with. */
	policer = cdx_police_lookup(rule);
	if (policer)
		rule->qos = (rule->qos & ~CDX_FT_QOS_POLICER_MASK) |
			    (policer << CDX_FT_QOS_POLICER_SHIFT);
	return 0;
}

/* Whether anything at all may be admitted now: the latches every offer is
 * refused under. Under the transaction. */
static bool ft_xlat_admissible(void)
{
	return !cdx_ft_observing() && !atomic_read(&ft_invalid) && !ft_stopping &&
	       !cdx_ft_failed();
}

/* The two keys a session takes, free: one an entry already holds whose owner
 * is retired goes now, its retirement merely not yet run -- the previous
 * generation of the same session among them, which a re-offer meets first --
 * and one held for a live owner refuses the session. A Netfilter offer meets
 * a translated key the same way (ft_replace()). What this unlinks, the
 * worker's run settles. Under the transaction. */
static int ft_xlat_keys_free(const struct cdx_ft_rule *rule)
{
	struct cdx_ft_entry *holder;
	unsigned int d;

	for (d = 0; d < 2; d++) {
		holder = ft_key_holder(&rule[d]);
		if (!holder)
			continue;
		if (ft_owner_valid(holder->owner))
			return -EEXIST;
		ft_unlink(holder);
	}
	return 0;
}

/* Decide one offer and, if it is admitted, install both its directions: 0
 * for a session installed or one something live already stands for, -EAGAIN
 * to try again later, -ECANCELED for one withdrawn meanwhile, and any other
 * error for a refusal. Under the transaction and RTNL. */
static int ft_xlat_admit(struct ft_xlat_offer *offer)
{
	const struct ask_xlat_flow *flow = &offer->flow;
	struct ft_xlat_path *path = ft_xlat_scratch.path;
	struct cdx_ft_rule *rule = ft_xlat_scratch.rule;
	struct cdx_ft_entry *entry[2] = {};
	struct ft_xlat_owner *o;
	bool held = false, cancelled;
	unsigned int d;
	int rc;

	/* What tc runs on each device decides admission, and with no sample
	 * nothing is known yet: a moment will tell (ask_flowtable_tc.c). */
	if (!ft_tc_known()) {
		ft_tc_kick();
		return -EAGAIN;
	}
	/* A live owner of the session already stands for it. Queueing folds
	 * every offer of a session into one, so none ought to be; were one, the
	 * answer is its own. */
	spin_lock_bh(&ft_xlat_lock);
	hash_for_each_possible(ft_xlat_owners, o, node, flow->cookie)
		if (o->cookie == flow->cookie && !o->withdrawn && ft_xlat_owner_valid(&o->owner))
			held = true;
	spin_unlock_bh(&ft_xlat_lock);
	if (held)
		return 0;
	/* Nothing held from the last admission: what `out' releases is this
	 * one's. */
	memset(path, 0, sizeof(ft_xlat_scratch.path));
	for (d = 0; d < 2; d++) {
		rc = ft_xlat_path(&flow->dir[d], flow->proto, &path[d]);
		if (rc)
			goto out;
	}
	for (d = 0; d < 2; d++) {
		rc = ft_xlat_rule(flow, d, path, &rule[d]);
		if (rc)
			goto out;
	}
	rc = ft_xlat_keys_free(rule);
	if (rc)
		goto out;
	if (ft_count + 2 > CDX_FT_MAX_ENTRIES || ft_xlat_count + 2 > FT_XLAT_MAX_ENTRIES) {
		rc = -ENOSPC;
		goto out;
	}
	/* The backend admits nothing while a retirement is unproven, and one
	 * whose barrier is merely owed is that until it is asked for. */
	if (ft_settle()) {
		rc = -EAGAIN;
		goto out;
	}
	o = kzalloc(sizeof(*o), GFP_KERNEL);
	if (!o) {
		rc = -ENOMEM;
		goto out;
	}
	o->owner.ops = &ft_xlat_owner_ops;
	INIT_LIST_HEAD(&o->retiring);
	o->cookie = flow->cookie;
	o->refs = 1;
	/* Published before anything is installed, so a withdrawal from here on
	 * finds the owner; one before this marked the offer. It owes nothing
	 * until both directions are in: the offer does. */
	spin_lock_bh(&ft_xlat_lock);
	cancelled = offer->cancelled;
	if (!cancelled)
		hash_add(ft_xlat_owners, &o->node, o->cookie);
	spin_unlock_bh(&ft_xlat_lock);
	if (cancelled) {
		kfree(o);
		rc = -ECANCELED;
		goto out;
	}
	ft_xlat_sessions++;
	for (d = 0; d < 2; d++) {
		struct cdx_ft_entry *e = ft_entry_alloc(&rule[d], &path[d].next_hop,
							(unsigned long)flow->cookie, d);

		if (!e) {
			rc = -ENOMEM;
			break;
		}
		o->refs++;
		ft_xlat_count++;
		ft_owner_attach(e, &o->owner);
		rc = ft_install(e, &ft_xlat_list);
		if (rc)
			break;
		entry[d] = e;
	}
	if (!rc) {
		/* A route can change between its lookup and publication with
		 * nothing to retire yet: IPv6 commits them from softirq without
		 * RTNL. Watched now, the entries are rechecked against both, as
		 * a Netfilter offer's are, and a latch or a withdrawal that
		 * landed during the insertion retires them here -- taken out
		 * below, so nothing need walk the table for them. */
		for (d = 0; d < 2; d++)
			if (!ft_dst_current(path[d].dst, path[d].cookie) &&
			    ft_owner_mark(&o->owner))
				atomic64_inc(&ft_route_invalidations);
		if (!ft_install_current(entry[0]))
			rc = -EIO;
	}
	if (rc) {
		/* Neither direction stays without the other. */
		for (d = 0; d < 2; d++)
			if (entry[d])
				ft_unlink(entry[d]);
		spin_lock_bh(&ft_xlat_lock);
		if (offer->cancelled || o->withdrawn)
			rc = -ECANCELED;
		spin_unlock_bh(&ft_xlat_lock);
	} else {
		/* Installed: the owner stands for the session from here, and
		 * the offer no more. */
		spin_lock_bh(&ft_xlat_lock);
		o->answers = !o->withdrawn;
		offer->done = true;
		spin_unlock_bh(&ft_xlat_lock);
		ft_xlat_installs++;
	}
	ft_xlat_put(o);
out:
	for (d = 0; d < 2; d++) {
		if (path[d].dst)
			dst_release(path[d].dst);
		path[d].dst = NULL;
	}
	return rc;
}

/* ---------------------------------------------------------------- worker */

/* An offer that has to wait, back in the ring for the next run: 0 when it
 * waits there, -ECANCELED when it was withdrawn meanwhile, -ENOSPC when the
 * ring has filled behind it. */
static int ft_xlat_requeue(struct ft_xlat_offer *offer)
{
	int rc = 0;

	spin_lock_bh(&ft_xlat_lock);
	if (offer->cancelled) {
		rc = -ECANCELED;
	} else if (ft_xlat_head - ft_xlat_tail < FT_XLAT_RING) {
		ft_xlat_ring[ft_xlat_head++ % FT_XLAT_RING] = *offer;
		offer->done = true;
	} else {
		rc = -ENOSPC;
	}
	spin_unlock_bh(&ft_xlat_lock);
	return rc;
}

/* An offer refused. Withdrawn first, nothing is said. With an owner of the
 * session still leaving the hardware, the answer waits for it to have left
 * (ft_xlat_put()); with none, it is said now, the offer findable until it has
 * been so a withdrawal meanwhile learns it came too late. Under the
 * transaction. */
static void ft_xlat_refuse(struct ft_xlat_offer *offer)
{
	struct ft_xlat_owner *heir;
	bool say = false;

	spin_lock_bh(&ft_xlat_lock);
	if (!offer->cancelled && !offer->done) {
		ft_xlat_refused++;
		heir = ft_xlat_heir(offer->flow.cookie, NULL);
		if (heir)
			heir->answers = true;
		else
			say = offer->answering = true;
	}
	if (!say)
		offer->done = true;
	spin_unlock_bh(&ft_xlat_lock);
	if (!say)
		return;
	ft_xlat_expire(offer->flow.cookie);
	spin_lock_bh(&ft_xlat_lock);
	offer->done = true;
	spin_unlock_bh(&ft_xlat_lock);
}

/* The entry of @owner -- a translated one, keyed in ft_cookies under no
 * binding by its session's @cookie -- if one is left. @owner is compared,
 * never followed: it goes with its last entry. Under the transaction. */
static struct cdx_ft_entry *ft_xlat_entry_of(u64 cookie, const struct ft_owner *owner)
{
	struct cdx_ft_entry *entry;

	hash_for_each_possible(ft_cookies, entry, cookie_node, (unsigned long)cookie)
		if (!entry->binding && entry->owner == owner)
			return entry;
	return NULL;
}

/* The owners queued for direct retirement, their entries unlinked, at most
 * FT_RETIRE_BATCH of them a run; true when owners are left for the next.
 * Settled by the run, as everything it unlinks. Under the transaction. */
static bool ft_xlat_retire_queued(void)
{
	const struct ft_owner *owner;
	struct ft_xlat_owner *o;
	struct cdx_ft_entry *e;
	unsigned int n = 0;
	bool more;
	u64 cookie;

	for (;;) {
		spin_lock_bh(&ft_xlat_lock);
		o = list_first_entry_or_null(&ft_xlat_retiring, struct ft_xlat_owner, retiring);
		if (o && n < FT_RETIRE_BATCH)
			list_del_init(&o->retiring);
		more = o && n >= FT_RETIRE_BATCH;
		spin_unlock_bh(&ft_xlat_lock);
		if (!o || more)
			return more;
		/* Taken now: the owner goes with its last entry. */
		cookie = o->cookie;
		owner = &o->owner;
		while ((e = ft_xlat_entry_of(cookie, owner))) {
			ft_unlink(e);
			n++;
		}
	}
}

static void ft_xlat_workfn(struct work_struct *work)
{
	unsigned int n = 0, i, retry = 0;
	bool more, retiring, rtnl = false;
	int rc;

	spin_lock_bh(&ft_xlat_lock);
	while (ft_xlat_tail != ft_xlat_head && n < FT_XLAT_BATCH) {
		const struct ft_xlat_offer *slot = &ft_xlat_ring[ft_xlat_tail++ % FT_XLAT_RING];

		if (!slot->cancelled)
			ft_xlat_inflight[n++] = *slot;
	}
	ft_xlat_ninflight = n;
	more = ft_xlat_tail != ft_xlat_head;
	spin_unlock_bh(&ft_xlat_lock);
	cdx_ft_begin();
	retiring = ft_xlat_retire_queued();
	/* A latch refuses everything without RTNL. */
	if (n && ft_xlat_admissible())
		rtnl = !cdx_ft_admission_begin();
	for (i = 0; i < n; i++) {
		struct ft_xlat_offer *offer = &ft_xlat_inflight[i];

		if (!ft_xlat_admissible())
			rc = -EOPNOTSUPP;
		else
			rc = rtnl ? ft_xlat_admit(offer) : -EAGAIN;
		if (rc == -EAGAIN) {
			ft_xlat_busy++;
			rc = ft_xlat_requeue(offer);
			if (!rc) {
				retry++;
				continue;
			}
		}
		if (rc && rc != -ECANCELED) {
			ft_xlat_refuse(offer);
		} else {
			spin_lock_bh(&ft_xlat_lock);
			offer->done = true;
			spin_unlock_bh(&ft_xlat_lock);
		}
	}
	if (rtnl)
		cdx_ft_admission_end();
	/* What the run unlinked -- retired holders, a pair taken back, the
	 * queued owners -- is proven before the transaction goes. */
	ft_settle();
	spin_lock_bh(&ft_xlat_lock);
	ft_xlat_ninflight = 0;
	if (!ft_xlat_closing && (more || retry || retiring))
		mod_delayed_work(system_unbound_wq, &ft_xlat_work, retry ? FT_XLAT_RETRY : 0);
	spin_unlock_bh(&ft_xlat_lock);
	cdx_ft_end();
}

/* -------------------------------------------------------- registration */

int ask_xlat_register(const struct ask_xlat_ops *ops)
{
	int rc = 0;

	if (!ops || !ops->expired || !ops->used)
		return -EINVAL;
	cdx_ft_begin();
	if (!ft_ready || ft_stopping) {
		rc = -ENODEV;
	} else {
		spin_lock_bh(&ft_xlat_lock);
		if (ft_xlat_client || READ_ONCE(ft_xlat_active))
			rc = -EBUSY;
		else
			ft_xlat_client = ops;
		spin_unlock_bh(&ft_xlat_lock);
	}
	if (!rc) {
		WRITE_ONCE(ft_xlat_active, true);
		/* An invalidation latched while nothing was bound waits for a
		 * bind to clear it, and now for this client too. */
		ft_rearm();
		/* And the tc sample, which runs only while something wants it. */
		ft_tc_kick();
	}
	cdx_ft_end();
	return rc;
}
EXPORT_SYMBOL_NS_GPL(ask_xlat_register, "ASK_XLAT");

/* The next offer still queued, moved into the worker's hands -- the worker
 * is stopped -- so it is refused as the worker refuses: what an
 * unregistration owes each. */
static struct ft_xlat_offer *ft_xlat_unqueue(void)
{
	struct ft_xlat_offer *offer = NULL;

	spin_lock_bh(&ft_xlat_lock);
	while (!offer && ft_xlat_tail != ft_xlat_head) {
		const struct ft_xlat_offer *slot = &ft_xlat_ring[ft_xlat_tail++ % FT_XLAT_RING];

		if (slot->cancelled)
			continue;
		ft_xlat_inflight[0] = *slot;
		ft_xlat_ninflight = 1;
		offer = &ft_xlat_inflight[0];
	}
	spin_unlock_bh(&ft_xlat_lock);
	return offer;
}

int ask_xlat_unregister(const struct ask_xlat_ops *ops)
{
	struct ft_xlat_offer *offer;
	struct ft_xlat_owner *o;
	unsigned int bkt;

	spin_lock_bh(&ft_xlat_lock);
	if (!ops || ft_xlat_client != ops) {
		spin_unlock_bh(&ft_xlat_lock);
		return -EINVAL;
	}
	if (ft_xlat_closing) {
		spin_unlock_bh(&ft_xlat_lock);
		return -EBUSY;
	}
	ft_xlat_closing = true;
	spin_unlock_bh(&ft_xlat_lock);
	/* Nothing queues the worker once the queue is closed. */
	cancel_delayed_work_sync(&ft_xlat_work);
	cdx_ft_begin();
	while ((offer = ft_xlat_unqueue())) {
		ft_xlat_refuse(offer);
		spin_lock_bh(&ft_xlat_lock);
		ft_xlat_ninflight = 0;
		spin_unlock_bh(&ft_xlat_lock);
	}
	/* Every session retired here rather than by the retirement worker, a
	 * batch at a time, each said expired as its last direction leaves. */
	spin_lock_bh(&ft_xlat_lock);
	hash_for_each(ft_xlat_owners, bkt, o, node)
		ft_owner_mark(&o->owner);
	spin_unlock_bh(&ft_xlat_lock);
	while (ft_retire_list(&ft_xlat_list)) {
		cdx_ft_end();
		cond_resched();
		cdx_ft_begin();
	}
	cdx_ft_end();
	/* Out of the hardware's reach, proven, before the translator is told
	 * nothing more: it may hand a session's ports to another next. */
	ft_hw_settle();
	cdx_ft_begin();
	spin_lock_bh(&ft_xlat_lock);
	ft_xlat_client = NULL;
	ft_xlat_closing = false;
	spin_unlock_bh(&ft_xlat_lock);
	WRITE_ONCE(ft_xlat_active, false);
	cdx_ft_end();
	return 0;
}
EXPORT_SYMBOL_NS_GPL(ask_xlat_unregister, "ASK_XLAT");

/* CDX restarted the datapath (ft_egress_restarted()): every translated
 * session is retired directly, and said expired as it leaves. Takes no lock
 * of CDX's; it only marks and queues the worker. */
void ft_xlat_restarted(void)
{
	struct ft_xlat_owner *o;
	unsigned int bkt;
	u64 marked = 0;

	spin_lock_bh(&ft_xlat_lock);
	hash_for_each(ft_xlat_owners, bkt, o, node)
		if (!o->withdrawn && !o->saying)
			marked += ft_xlat_retire(o);
	spin_unlock_bh(&ft_xlat_lock);
	atomic64_add(marked, &ft_xlat_restart_invalidations);
}

/* Unload, with ft_stopping set and every owner already marked: no client is
 * registered, since one pins the module. The worker is stopped, and what a
 * client left -- nothing, unless it never unregistered -- is retired, as a
 * binding's release retires its own. */
void ft_xlat_exit(void)
{
	spin_lock_bh(&ft_xlat_lock);
	ft_xlat_closing = true;
	ft_xlat_tail = ft_xlat_head;
	spin_unlock_bh(&ft_xlat_lock);
	cancel_delayed_work_sync(&ft_xlat_work);
	cdx_ft_begin();
	while (ft_retire_list(&ft_xlat_list)) {
		cdx_ft_end();
		cond_resched();
		cdx_ft_begin();
	}
	cdx_ft_end();
}

/* -------------------------------------------------------------- /proc */

/* Levels, under the transaction ft_status_show() holds. */
void ft_xlat_status(struct seq_file *seq)
{
	unsigned int pending;

	spin_lock_bh(&ft_xlat_lock);
	pending = ft_xlat_head - ft_xlat_tail;
	spin_unlock_bh(&ft_xlat_lock);
	ft_kv(seq, "xlat_registered", !!ft_xlat_client);
	ft_kv(seq, "xlat_sessions", ft_xlat_sessions);
	ft_kv(seq, "xlat_entries", ft_xlat_count);
	ft_kv(seq, "xlat_max_entries", FT_XLAT_MAX_ENTRIES);
	ft_kv(seq, "xlat_pending", pending);
}

/* Counts, without the transaction, each loaded once. */
void ft_xlat_stats(struct seq_file *seq)
{
	ft_kv(seq, "xlat_offers", READ_ONCE(ft_xlat_offers));
	ft_kv(seq, "xlat_dropped", READ_ONCE(ft_xlat_dropped));
	ft_kv(seq, "xlat_mtu_refused", atomic64_read(&ft_xlat_mtu_refusals));
	ft_kv(seq, "xlat_installs", READ_ONCE(ft_xlat_installs));
	ft_kv(seq, "xlat_refused", READ_ONCE(ft_xlat_refused));
	ft_kv(seq, "xlat_busy", READ_ONCE(ft_xlat_busy));
	ft_kv(seq, "xlat_withdrawals", atomic64_read(&ft_xlat_withdrawals));
	ft_kv(seq, "xlat_expired", READ_ONCE(ft_xlat_expired));
	ft_kv(seq, "xlat_used", READ_ONCE(ft_xlat_used));
	ft_kv(seq, "xlat_restart_invalidations", atomic64_read(&ft_xlat_restart_invalidations));
}
