/* A port joining a flowtable, compiled from the kernel: the route carrying
 * the port a walk found unlisted into the flow (flow_offload_route_init()),
 * nf_tables publishing an update's hooks (nft_flowtable_hooks_publish()), the
 * flowtable retiring the flows that walked to the port while it was unlisted
 * (nf_flow_table_listed(), over the real nf_flow_table_iterate()), the check a
 * flow added after its walk makes against the list
 * (nft_flow_offload_check_unlisted()), and a device going down retiring the
 * flows that recorded it (nf_flow_table_do_cleanup()). The flowtable's types,
 * the flow and its tuples, the route and nf_tables' hook and flowtable are the
 * kernel's own declarations; the rhashtable walk, the lists, the barrier and
 * the teardown are simulated.
 *
 * The LAN port is eth3, the WAN port eth4; eth5 joins beside eth3. A client
 * sits behind a VLAN or a bridge on eth3, a PPPoE session runs over eth4, and
 * a Wi-Fi interface the flowtable never lists is bridged as well. */
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint16_t __be16;
typedef uint32_t __be32;

#define ETH_ALEN 6
#define NF_FLOW_TABLE_ENCAP_MAX 2
#define NFPROTO_IPV4 2
#define NFPROTO_IPV6 10
#define BIT(n) (1UL << (n))
#define likely(x) (x)
#define ____cacheline_aligned
#define WARN_ON_ONCE(c) ({ bool __warn = (c); assert(!__warn); __warn; })
#define container_of(ptr, type, member) \
	((type *)((char *)(ptr) - offsetof(type, member)))
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define PTR_ERR(p) ((long)(intptr_t)(p))
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

enum ip_conntrack_dir { IP_CT_DIR_ORIGINAL, IP_CT_DIR_REPLY, IP_CT_DIR_MAX };
#define FLOW_OFFLOAD_DIR_MAX IP_CT_DIR_MAX

struct list_head { struct list_head *next, *prev; };
struct rcu_head { int unused; };
struct rhash_head { int unused; };
struct net { int id; };
struct net_device { int ifindex; struct net *net; };
struct nf_conn { struct net *net; };
struct dst_entry { int unused; };
struct nf_flowtable;
struct flow_offload;
struct nf_flow_offload_handle;
struct nf_flow_rule;
struct module;
struct nft_table;
struct sk_buff;
struct nf_hook_state;
typedef unsigned int nf_hookfn(void *priv, struct sk_buff *skb,
			       const struct nf_hook_state *state);
enum flow_block_command { FLOW_BLOCK_BIND, FLOW_BLOCK_UNBIND };
union nf_inet_addr { __be32 all[4]; struct in6_addr in6; };
struct nf_hook_ops { struct net_device *dev; };
struct delayed_work { int unused; };
struct flow_block { struct list_head cb_list; };
struct rw_semaphore { int unused; };
typedef struct { struct net *net; } possible_net_t;

/* The table holds each flow's two directions in insertion order. A walk that
 * meets a resize starts again from the first entry of the new table, as the
 * kernel's does after -EAGAIN, and so shows what it already showed again. */
struct rhashtable {
	struct flow_offload_tuple_rhash *entries[32];
	unsigned int count;
	/* After how many entries a walk meets the resize; none if zero. */
	unsigned int resize_after;
	bool resized;
};
struct rhashtable_iter {
	struct rhashtable *ht;
	unsigned int slot;
};

#include "listed_types.inc"

/* A tuple's lookup key ends at __hash; the port recorded unlisted must never
 * widen it, nor share the union a NEIGH tuple spends on its destination. */
_Static_assert(offsetof(struct flow_offload_tuple, unlisted_iifidx) >=
	       offsetof(struct flow_offload_tuple, __hash), "inside the key");
_Static_assert(offsetof(struct flow_offload_tuple, unlisted_iifidx) + sizeof(int) <=
	       offsetof(struct flow_offload_tuple, dst_cache), "inside the union");

static int rcu_depth;
static void rhashtable_walk_enter(struct rhashtable *ht, struct rhashtable_iter *iter)
{
	iter->ht = ht;
	iter->slot = 0;
}
static void rhashtable_walk_start(struct rhashtable_iter *iter)
{
	rcu_depth++;
}
static void *rhashtable_walk_next(struct rhashtable_iter *iter)
{
	struct rhashtable *ht = iter->ht;

	assert(rcu_depth > 0);
	if (ht->resize_after && !ht->resized && iter->slot == ht->resize_after) {
		ht->resized = true;
		iter->slot = 0;
		return ERR_PTR(-EAGAIN);
	}
	if (iter->slot == ht->count)
		return NULL;
	return ht->entries[iter->slot++];
}
static void rhashtable_walk_stop(struct rhashtable_iter *iter)
{
	assert(rcu_depth > 0);
	rcu_depth--;
}
static void rhashtable_walk_exit(struct rhashtable_iter *iter)
{
	iter->ht = NULL;
}

/* What happened, in order: a hook published on a flowtable's list, a full
 * barrier, the flowtable told of a device, a hook list read under RCU. */
enum event { PUBLISH, BARRIER, LISTED, READ };
static struct {
	enum event what;
	const struct net_device *dev;
} events[32];
static unsigned int nevents;

static void record(enum event what, const struct net_device *dev)
{
	assert(nevents < ARRAY_LEN(events));
	events[nevents].what = what;
	events[nevents++].dev = dev;
}
static void smp_mb(void)
{
	record(BARRIER, NULL);
}

static void INIT_LIST_HEAD(struct list_head *head)
{
	head->next = head->prev = head;
}
static bool list_empty(const struct list_head *head)
{
	return head->next == head;
}
static void list_add_tail(struct list_head *new, struct list_head *head)
{
	new->prev = head->prev;
	new->next = head;
	head->prev->next = new;
	head->prev = new;
}
static void list_del(struct list_head *entry)
{
	entry->prev->next = entry->next;
	entry->next->prev = entry->prev;
	entry->next = entry->prev = (struct list_head *)0x100;
}
/* Only hooks are published here. */
static void list_add_rcu(struct list_head *new, struct list_head *head)
{
	new->next = head->next;
	new->prev = head;
	head->next->prev = new;
	head->next = new;
	record(PUBLISH, container_of(new, struct nft_hook, list)->ops.dev);
}
/* Every walk of a hook list the production code makes is a read of it. */
#define list_for_each_entry_rcu(pos, head, member)				\
	for (record(READ, NULL),						\
	     pos = container_of((head)->next, typeof(*pos), member);		\
	     &pos->member != (head);						\
	     pos = container_of(pos->member.next, typeof(*pos), member))
#define list_for_each_entry_safe(pos, n, head, member)				\
	for (pos = container_of((head)->next, typeof(*pos), member),		\
	     n = container_of(pos->member.next, typeof(*pos), member);		\
	     &pos->member != (head);						\
	     pos = n, n = container_of(n->member.next, typeof(*n), member))

static struct net *nf_ct_net(const struct nf_conn *ct)
{
	return ct->net;
}
static struct net *dev_net(const struct net_device *dev)
{
	return dev->net;
}
static bool net_eq(const struct net *a, const struct net *b)
{
	return a == b;
}

/* A teardown marks the flow for the GC, once. */
static unsigned int teardowns;
static void flow_offload_teardown(struct flow_offload *flow)
{
	if (!(flow->flags & BIT(NF_FLOW_TEARDOWN)))
		teardowns++;
	flow->flags |= BIT(NF_FLOW_TEARDOWN);
}
static bool torn(const struct flow_offload *flow)
{
	return flow->flags & BIT(NF_FLOW_TEARDOWN);
}

static unsigned int ip_dst_mtu_maybe_forward(const struct dst_entry *dst, bool fwd)
{
	return 1500;
}
static unsigned int ip6_dst_mtu_maybe_forward(const struct dst_entry *dst, bool fwd)
{
	return 1500;
}
static u32 flow_offload_dst_cookie(struct flow_offload_tuple *flow_tuple)
{
	return 0;
}
static void dst_release(struct dst_entry *dst)
{
	assert(!"a NEIGH route keeps its destination");
}

#include "listed_production.inc"

/* Device indices; the VLAN, the bridge and the ppp device only ever appear
 * as the device a flow is cached on. */
enum { ETH3 = 3, ETH4 = 4, ETH5 = 5, WLAN = 8, VLAN = 30, BRIDGE = 40, PPP = 50 };
static struct net net_a = { 1 }, net_b = { 2 };
static struct net_device eth3 = { ETH3, &net_a }, eth4 = { ETH4, &net_a },
	eth5 = { ETH5, &net_a };
static struct nf_conn ct_a = { &net_a }, ct_b = { &net_b };
static struct dst_entry dst;

/* The flowtable nf_tables owns, with the ports it lists and the flows it
 * holds. */
static struct nft_flowtable ft;
static struct nft_hook hooks[4];
static const struct nf_flowtable_type listed_type = { .listed = nf_flow_table_listed };
/* act_ct's type, say, which has no use for the op. */
static const struct nf_flowtable_type plain_type = { .listed = NULL };

static void table(const struct nf_flowtable_type *type, struct net_device *const *listed,
		  size_t n)
{
	memset(&ft, 0, sizeof(ft));
	ft.data.type = type;
	INIT_LIST_HEAD(&ft.hook_list);
	for (size_t i = 0; i < n; i++) {
		memset(&hooks[i], 0, sizeof(hooks[i]));
		hooks[i].ops.dev = listed[i];
		list_add_tail(&hooks[i].list, &ft.hook_list);
	}
	nevents = teardowns = 0;
}

/* A flow as nft_flow_offload_eval() builds it from its route: direction d
 * arrives on iif[d], and on the port unlisted[d] below it if the walk reached
 * one the table did not list. */
static void build(struct flow_offload *flow, struct nf_conn *ct, const int iif[2],
		  const int unlisted[2])
{
	struct nf_flow_route route;

	memset(flow, 0, sizeof(*flow));
	memset(&route, 0, sizeof(route));
	flow->ct = ct;
	for (int d = 0; d < 2; d++) {
		flow->tuplehash[d].tuple.dir = d;
		flow->tuplehash[d].tuple.l3proto = NFPROTO_IPV4;
		route.tuple[d].dst = &dst;
		route.tuple[d].in.ifindex = iif[d];
		route.tuple[d].in.unlisted_ifindex = unlisted[d];
		route.tuple[d].xmit_type = FLOW_OFFLOAD_XMIT_NEIGH;
	}
	flow_offload_route_init(flow, &route);
	for (int d = 0; d < 2; d++) {
		assert(flow->tuplehash[d].tuple.iifidx == iif[d]);
		assert(flow->tuplehash[d].tuple.unlisted_iifidx == unlisted[d]);
	}
}

/* Into the table as flow_offload_add() puts it: the original direction, the
 * one the GC and the sweep visit, last. */
static void add(struct flow_offload *flow)
{
	struct rhashtable *ht = &ft.data.rhashtable;

	assert(ht->count + 2 <= ARRAY_LEN(ht->entries));
	ht->entries[ht->count++] = &flow->tuplehash[FLOW_OFFLOAD_DIR_REPLY];
	ht->entries[ht->count++] = &flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL];
}

/* The harness's own look at the list, which records nothing. */
static bool on_list(const struct net_device *dev)
{
	for (struct list_head *pos = ft.hook_list.next; pos != &ft.hook_list;
	     pos = pos->next)
		if (container_of(pos, struct nft_hook, list)->ops.dev == dev)
			return true;
	return false;
}

/* Exactly these events happened, in this order. */
static void happened(const enum event *seq, size_t n)
{
	assert(nevents == n);
	for (size_t i = 0; i < n; i++)
		assert(events[i].what == seq[i]);
}
#define HAPPENED(...) \
	happened((const enum event[]){ __VA_ARGS__ }, \
		 sizeof((const enum event[]){ __VA_ARGS__ }) / sizeof(enum event))

/* The flowtable is told of a device only once a walk can find it, and only
 * of the device it is told of: the hooks behind it are not published yet. */
static const struct net_device *expect_later;
static void recording_listed(struct nf_flowtable *flowtable, const struct net_device *dev)
{
	assert(flowtable == &ft.data && on_list(dev));
	assert(!expect_later || expect_later == dev || !on_list(expect_later));
	record(LISTED, dev);
	nf_flow_table_listed(flowtable, dev);
}
static const struct nf_flowtable_type recording_type = { .listed = recording_listed };

/* The flows the sweep is shown, each with the port it recorded, if any. */
static struct flow_offload flows[7];
enum {
	VLAN_CLIENT,	/* the reply arrives on the VLAN above eth3 */
	BRIDGE_CLIENT,	/* the original direction arrives on br-lan above eth3 */
	LISTED_PORTS,	/* walked to eth3 and eth4 while both were listed */
	PORT_CLIENT,	/* on eth3 itself while it was unlisted */
	WIFI_CLIENT,	/* on the bridged Wi-Fi interface */
	PPPOE,		/* a session over eth4 while it was unlisted */
	OTHER_NET,	/* another namespace's port with eth3's index */
};

static void populate(void)
{
	build(&flows[VLAN_CLIENT], &ct_a, (int[]){ ETH4, VLAN }, (int[]){ 0, ETH3 });
	build(&flows[BRIDGE_CLIENT], &ct_a, (int[]){ BRIDGE, ETH4 }, (int[]){ ETH3, 0 });
	build(&flows[LISTED_PORTS], &ct_a, (int[]){ ETH3, ETH4 }, (int[]){ 0, 0 });
	build(&flows[PORT_CLIENT], &ct_a, (int[]){ ETH3, ETH4 }, (int[]){ 0, 0 });
	build(&flows[WIFI_CLIENT], &ct_a, (int[]){ BRIDGE, ETH4 }, (int[]){ WLAN, 0 });
	build(&flows[PPPOE], &ct_a, (int[]){ VLAN, PPP }, (int[]){ 0, ETH4 });
	build(&flows[OTHER_NET], &ct_b, (int[]){ ETH4, VLAN }, (int[]){ 0, ETH3 });
	for (size_t i = 0; i < ARRAY_LEN(flows); i++)
		add(&flows[i]);
}

/* eth3 joining retires exactly the flows that recorded it, in its own
 * namespace, whichever direction recorded it; a resize in the middle of the
 * sweep shows some flows twice and loses none. eth4 joining then retires the
 * session over it. */
static void sweep_cases(void)
{
	/* After how many of the 14 entries the walk meets a resize. */
	static const unsigned int resizes[] = { 0, 1, 5, 10, 13, 14 };

	for (size_t r = 0; r < ARRAY_LEN(resizes); r++) {
		struct net_device *listed[] = { &eth4 };

		table(&listed_type, listed, ARRAY_LEN(listed));
		populate();
		assert(ft.data.rhashtable.count == 2 * ARRAY_LEN(flows));
		ft.data.rhashtable.resize_after = resizes[r];
		nf_flow_table_listed(&ft.data, &eth3);
		assert(!rcu_depth);
		assert(!resizes[r] || ft.data.rhashtable.resized);
		for (size_t i = 0; i < ARRAY_LEN(flows); i++)
			assert(torn(&flows[i]) == (i == VLAN_CLIENT || i == BRIDGE_CLIENT));
		assert(teardowns == 2);

		nf_flow_table_listed(&ft.data, &eth4);
		assert(torn(&flows[PPPOE]) && teardowns == 3);
		/* The Wi-Fi interface never joins; a device of the other
		 * namespace with eth3's index would have to. */
		assert(!torn(&flows[WIFI_CLIENT]) && !torn(&flows[OTHER_NET]));
	}
	printf("flowtable listed sweep checks passed\n");
}

/* The update's hooks go where list_splice_rcu() put them -- at the front of
 * the list, in the transaction's order -- one at a time, each followed by a
 * full barrier and the flowtable's sweep for that device, and the
 * transaction is left with none. A type without the op is only published. */
static void publish_cases(void)
{
	static const enum event told[] = { PUBLISH, BARRIER, LISTED, PUBLISH, BARRIER,
					   LISTED };
	struct net_device *const joining[] = { &eth3, &eth5 };
	struct net_device *listed[] = { &eth4 };
	struct list_head trans;

	for (int with_op = 0; with_op < 2; with_op++) {
		table(with_op ? &recording_type : &plain_type, listed, ARRAY_LEN(listed));
		populate();
		INIT_LIST_HEAD(&trans);
		for (size_t i = 0; i < ARRAY_LEN(joining); i++) {
			memset(&hooks[1 + i], 0, sizeof(hooks[1 + i]));
			hooks[1 + i].ops.dev = joining[i];
			list_add_tail(&hooks[1 + i].list, &trans);
		}
		expect_later = &eth5;
		nft_flowtable_hooks_publish(&ft, &trans);
		expect_later = NULL;

		assert(list_empty(&trans));
		/* eth3, eth5, eth4, whichever way a reader goes. */
		assert(ft.hook_list.next == &hooks[1].list);
		assert(hooks[1].list.next == &hooks[2].list);
		assert(hooks[2].list.next == &hooks[0].list);
		assert(hooks[0].list.next == &ft.hook_list);
		assert(ft.hook_list.prev == &hooks[0].list);
		assert(hooks[0].list.prev == &hooks[2].list);
		assert(hooks[2].list.prev == &hooks[1].list);
		assert(hooks[1].list.prev == &ft.hook_list);

		if (with_op) {
			assert(nevents == ARRAY_LEN(told));
			for (size_t i = 0; i < nevents; i++) {
				assert(events[i].what == told[i]);
				assert(told[i] == BARRIER ||
				       events[i].dev == joining[i / 3]);
			}
			assert(torn(&flows[VLAN_CLIENT]) && torn(&flows[BRIDGE_CLIENT]));
			assert(teardowns == 2);
		} else {
			assert(nevents == 2);
			assert(events[0].what == PUBLISH && events[0].dev == &eth3);
			assert(events[1].what == PUBLISH && events[1].dev == &eth5);
			assert(!teardowns);
		}
	}
	printf("flowtable listed publish checks passed\n");
}

/* A flow added after its walk looks at the list again only if it recorded a
 * port, behind a full barrier, and retires itself if the port is listed now
 * -- a hook a pending deletion has flagged included, as the walk counts it. */
static void check_cases(void)
{
	struct net_device *listed[] = { &eth3, &eth4 };
	struct net_device *wan_only[] = { &eth4 };
	struct flow_offload flow;

	/* Nothing recorded: no barrier, no list read, nothing retired. */
	table(&listed_type, listed, ARRAY_LEN(listed));
	build(&flow, &ct_a, (int[]){ ETH3, ETH4 }, (int[]){ 0, 0 });
	nft_flow_offload_check_unlisted(&ft, &flow);
	assert(!nevents && !torn(&flow));

	/* Still unlisted: the barrier, then the read, and the flow stays. */
	table(&listed_type, wan_only, ARRAY_LEN(wan_only));
	build(&flow, &ct_a, (int[]){ ETH4, VLAN }, (int[]){ 0, ETH3 });
	nft_flow_offload_check_unlisted(&ft, &flow);
	HAPPENED(BARRIER, READ);
	assert(!torn(&flow));

	/* Listed since the walk, from either direction. */
	for (int d = 0; d < 2; d++) {
		int iif[2] = { ETH4, ETH4 }, unlisted[2] = { 0, 0 };

		iif[d] = VLAN;
		unlisted[d] = ETH3;
		table(&listed_type, listed, ARRAY_LEN(listed));
		build(&flow, &ct_a, iif, unlisted);
		nft_flow_offload_check_unlisted(&ft, &flow);
		HAPPENED(BARRIER, READ);
		assert(torn(&flow));
	}

	/* Both directions recorded a port, the client's eth3 and the
	 * session's eth4, and only eth4 is back: one barrier before both
	 * reads. */
	table(&listed_type, wan_only, ARRAY_LEN(wan_only));
	build(&flow, &ct_a, (int[]){ VLAN, PPP }, (int[]){ ETH3, ETH4 });
	nft_flow_offload_check_unlisted(&ft, &flow);
	HAPPENED(BARRIER, READ, READ);
	assert(torn(&flow));

	/* Listed but flagged by a deletion not committed yet. */
	table(&listed_type, listed, ARRAY_LEN(listed));
	hooks[0].flags |= NFT_HOOK_REMOVE;
	build(&flow, &ct_a, (int[]){ ETH4, VLAN }, (int[]){ 0, ETH3 });
	nft_flow_offload_check_unlisted(&ft, &flow);
	HAPPENED(BARRIER, READ);
	assert(torn(&flow));

	/* Ports are listed, but not the one recorded. */
	table(&listed_type, listed, ARRAY_LEN(listed));
	build(&flow, &ct_a, (int[]){ BRIDGE, ETH4 }, (int[]){ WLAN, 0 });
	nft_flow_offload_check_unlisted(&ft, &flow);
	HAPPENED(BARRIER, READ);
	assert(!torn(&flow));
	printf("flowtable listed check checks passed\n");
}

/* The race the two barriers close, both ways round. The walk found eth3
 * unlisted; eth3 joins before the flow is in the table, so the sweep cannot
 * see it, and the flow's own check retires it. Or the flow is in the table
 * first, its check finds eth3 unlisted, and the sweep retires it. */
static void race_cases(void)
{
	struct net_device *listed[] = { &eth4 };
	struct flow_offload flow;
	struct list_head trans;

	for (int added_first = 0; added_first < 2; added_first++) {
		table(&listed_type, listed, ARRAY_LEN(listed));
		build(&flow, &ct_a, (int[]){ ETH4, VLAN }, (int[]){ 0, ETH3 });
		INIT_LIST_HEAD(&trans);
		memset(&hooks[1], 0, sizeof(hooks[1]));
		hooks[1].ops.dev = &eth3;
		list_add_tail(&hooks[1].list, &trans);

		if (added_first) {
			add(&flow);
			nft_flow_offload_check_unlisted(&ft, &flow);
			assert(!torn(&flow));
			nft_flowtable_hooks_publish(&ft, &trans);
		} else {
			nft_flowtable_hooks_publish(&ft, &trans);
			assert(!torn(&flow));
			add(&flow);
			nft_flow_offload_check_unlisted(&ft, &flow);
		}
		assert(torn(&flow) && teardowns == 1);
	}
	printf("flowtable listed race checks passed\n");
}

/* A device going down -- nf_flow_table_gc_cleanup()'s pass, on NETDEV_DOWN --
 * retires the flows that arrive on it and those that recorded it unlisted, in
 * its own namespace. Otherwise a port unregistered and registered again, as a
 * driver rebind does, comes back under another index, its joining the table
 * sweeps for that one, and a flow that recorded the old one stays where it
 * is. Without a device, every flow goes. */
static void cleanup_cases(void)
{
	struct net_device *listed[] = { &eth4 };
	struct net_device eth3_again = { 12, &net_a };

	table(&listed_type, listed, ARRAY_LEN(listed));
	populate();
	nf_flow_table_iterate(&ft.data, nf_flow_table_do_cleanup, &eth3);
	for (size_t i = 0; i < ARRAY_LEN(flows); i++)
		assert(torn(&flows[i]) == (i == VLAN_CLIENT || i == BRIDGE_CLIENT ||
					   i == LISTED_PORTS || i == PORT_CLIENT));
	assert(teardowns == 4);
	/* Back under index 12 and listed: nothing recorded it. */
	nf_flow_table_listed(&ft.data, &eth3_again);
	assert(teardowns == 4);

	/* eth4 going down takes the session that recorded it and the Wi-Fi
	 * client's flow, which arrives on it; not the other namespace's. */
	nf_flow_table_iterate(&ft.data, nf_flow_table_do_cleanup, &eth4);
	assert(torn(&flows[PPPOE]) && torn(&flows[WIFI_CLIENT]));
	assert(!torn(&flows[OTHER_NET]) && teardowns == 6);

	nf_flow_table_iterate(&ft.data, nf_flow_table_do_cleanup, NULL);
	assert(torn(&flows[OTHER_NET]) && teardowns == 7);
	assert(!rcu_depth);
	printf("flowtable listed cleanup checks passed\n");
}

int main(void)
{
	sweep_cases();
	publish_cases();
	check_cases();
	race_cases();
	cleanup_cases();
	return 0;
}
