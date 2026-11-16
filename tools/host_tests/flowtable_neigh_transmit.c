/* The software flowtable's transmit of a NEIGH flow's frame is production
 * code: nf_flow_offload_ip_hook() and nf_flow_offload_ipv6_hook(), from the
 * tuple lookup's result on, with every helper of their file they call. The
 * lookup and the forward step before the transmit, and the device, route and
 * neighbour layers under it, are the simulated boundary.
 *
 * The next hop's entry the hooks find may be one the neighbour layer has not
 * confirmed: created empty by the lookup after a flush, a link flap or the
 * neighbour GC (NUD_NONE), resolving (NUD_INCOMPLETE), failed, or stale and
 * due a probe. Its address is all zeroes or unconfirmed, so such a frame goes
 * out through the neighbour's own output, which queues it until the entry
 * resolves, restarts a failed one and probes a stale one: on a line whose
 * hooks hand every frame to neigh_xmit() that is where it goes, and on one
 * whose hooks write the header themselves only a confirmed entry's address is
 * written, read whole under the entry's lock. */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint16_t __be16;
typedef uint32_t __be32;

#define READ_ONCE(x) (x)
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define container_of(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))
#define IS_ERR(ptr) ((unsigned long)(ptr) >= (unsigned long)-4095)
static unsigned int warnings;
#define WARN_ON_ONCE(condition) ({ int __ret = !!(condition); warnings += __ret; __ret; })

#define ETH_ALEN 6
#define MAX_ADDR_LEN 32
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define NF_DROP 0
#define NF_ACCEPT 1
#define NF_STOLEN 2
#define IPSKB_FORWARDED 1
#define IP6SKB_FORWARDED 2
enum { NEIGH_ARP_TABLE = 0, NEIGH_ND_TABLE = 1 };
enum flow_offload_tuple_dir { FLOW_OFFLOAD_DIR_ORIGINAL, FLOW_OFFLOAD_DIR_REPLY };
enum flow_offload_xmit_type {
	FLOW_OFFLOAD_XMIT_UNSPEC, FLOW_OFFLOAD_XMIT_NEIGH, FLOW_OFFLOAD_XMIT_XFRM,
	FLOW_OFFLOAD_XMIT_DIRECT, FLOW_OFFLOAD_XMIT_TC,
};

struct net { int id; };
struct header_ops { int unused; };
struct net_device {
	int ifindex;
	const struct header_ops *header_ops;
	unsigned short hard_header_len, needed_headroom;
	unsigned char addr_len;
	unsigned char dev_addr[MAX_ADDR_LEN];
};
struct dst_entry { struct net_device *dev; };
struct rtable { struct dst_entry dst; __be32 rt_gw4; };
struct rt6_info { struct dst_entry dst; struct in6_addr rt6i_gateway; };
struct sk_buff {
	struct net_device *dev;
	__be16 protocol;
	unsigned int len, headroom;
	struct dst_entry *dst;
	char cb[48];
};
struct inet_skb_parm { int iif; u16 flags; };
struct inet6_skb_parm { int iif; u16 flags; };
#define IPCB(skb) ((struct inet_skb_parm *)((skb)->cb))
#define IP6CB(skb) ((struct inet6_skb_parm *)((skb)->cb))
typedef struct { unsigned int sequence; } seqlock_t;
struct neighbour {
	struct net_device *dev;
	u8 nud_state;
	seqlock_t ha_lock;
	unsigned char ha[MAX_ADDR_LEN];
	int (*output)(struct neighbour *, struct sk_buff *);
};
struct nf_hook_state { struct net_device *in; struct net *net; };
struct nf_flowtable { bool use_hw_handles; unsigned int flags; };
struct flow_offload_tuple {
	union {
		struct in_addr src_v4;
		struct in6_addr src_v6;
	};
	u8 dir, xmit_type;
	struct dst_entry *dst_cache;
	u32 ifidx;
	struct {
		u32 ifidx;
		u8 h_source[ETH_ALEN], h_dest[ETH_ALEN];
	} out;
};
struct flow_offload_tuple_rhash { struct flow_offload_tuple tuple; };
struct flow_offload {
	struct flow_offload_tuple_rhash tuplehash[2];
	unsigned long flags;
	unsigned int torn_down;
};
/* What a frame the hooks give back to the stack asks of a closing flow
 * (nf_flow_bypass(), where the line has it). */
enum { NF_FLOW_CLOSING = 3 };
static inline bool test_bit(unsigned int nr, const unsigned long *addr)
{
	return (*addr >> nr) & 1;
}

/* NUD_* and LL_RESERVED_SPACE() as the tree defines them, and the hooks' own
 * context and transmit structures. */
#include "flowtable_neigh_transmit_types.inc"

/* What the device, route and neighbour layers were asked for. */
static struct {
	unsigned int hard_headers, queued, resolved, neigh_xmits, snapshots;
	struct net_device *header_dev, *queued_dev, *resolve_dev, *xmit_dev;
	unsigned short header_type;
	const void *header_dest;
	u8 dest[ETH_ALEN];
	struct sk_buff *queued_skb, *resolve_skb, *xmit_skb;
	struct dst_entry *resolve_dst, *xmit_dst;
	struct neighbour *resolve_neigh;
	unsigned int resolve_headroom;
	int xmit_table;
	u8 xmit_addr[16];
} seen;

static struct net net;
static const struct header_ops eth_header_ops;
static struct net_device lan = {
	3, &eth_header_ops, 14, 0, ETH_ALEN, { 0x02, 0, 0, 0, 0x03, 0x01 },
};
static struct net_device wan = {
	4, &eth_header_ops, 14, 0, ETH_ALEN, { 0x02, 0, 0, 0, 0x04, 0x01 },
};
static struct dst_entry input_dst = { &lan };
static struct rtable rt4 = { { &wan }, 0 };
static struct rt6_info rt6 = { { &wan }, { { { 0xfe, 0x80, [15] = 0x01 } } } };
static struct neighbour neigh;
static struct flow_offload flow;

/* The device, route and neighbour layers, inline: which of them a line's
 * hooks call differs. */
static inline unsigned int read_seqbegin(const seqlock_t *lock)
{
	seen.snapshots++;
	return lock->sequence;
}

static inline int read_seqretry(const seqlock_t *lock, unsigned int start)
{
	return lock->sequence != start;
}

static inline bool secpath_exists(const struct sk_buff *skb)
{
	return false;
}

static inline bool xfrm_flowtable_enabled(const struct net *net)
{
	return true;
}

/* The tuple lookup finds the flow's original direction, and the forward step
 * takes the packet. */
static struct flow_offload_tuple_rhash *nf_flow_offload_lookup(struct nf_flowtable_ctx *ctx,
							       struct nf_flowtable *flow_table,
							       struct sk_buff *skb)
{
	return &flow.tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL];
}

static struct flow_offload_tuple_rhash *nf_flow_offload_ipv6_lookup(struct nf_flowtable_ctx *ctx,
								    struct nf_flowtable *flow_table,
								    struct sk_buff *skb)
{
	return &flow.tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL];
}

static int nf_flow_offload_forward(struct nf_flowtable_ctx *ctx, struct nf_flowtable *flow_table,
				   struct flow_offload_tuple_rhash *tuplehash, struct sk_buff *skb)
{
	return 1;
}

static int nf_flow_offload_ipv6_forward(struct nf_flowtable_ctx *ctx,
					struct nf_flowtable *flow_table,
					struct flow_offload_tuple_rhash *tuplehash,
					struct sk_buff *skb)
{
	return 1;
}

static unsigned int nf_flow_xmit_xfrm(struct sk_buff *skb, const struct nf_hook_state *state,
				      struct dst_entry *dst)
{
	abort();
}

static inline void flow_offload_teardown(struct flow_offload *teardown)
{
	teardown->torn_down++;
}

static inline struct net_device *dev_get_by_index_rcu(struct net *in, int ifindex)
{
	return ifindex == wan.ifindex ? &wan : ifindex == lan.ifindex ? &lan : NULL;
}

static inline struct rtable *dst_rtable(const struct dst_entry *dst)
{
	return container_of(dst, struct rtable, dst);
}

static inline struct rt6_info *dst_rt6_info(const struct dst_entry *dst)
{
	return container_of(dst, struct rt6_info, dst);
}

static inline __be32 rt_nexthop(const struct rtable *rt, __be32 daddr)
{
	return rt->rt_gw4 ? rt->rt_gw4 : daddr;
}

static inline const struct in6_addr *rt6_nexthop(const struct rt6_info *rt,
						 const struct in6_addr *daddr)
{
	return &rt->rt6i_gateway;
}

/* The entry for the next hop on the device, created if missing, whatever its
 * state. */
static inline struct neighbour *ip_neigh_gw4(struct net_device *dev, __be32 gw)
{
	return dev == neigh.dev && gw == rt4.rt_gw4 ? &neigh : NULL;
}

static inline struct neighbour *ip_neigh_gw6(struct net_device *dev, const void *gw)
{
	return dev == neigh.dev && !memcmp(gw, &rt6.rt6i_gateway, sizeof(rt6.rt6i_gateway)) ?
	       &neigh : NULL;
}

static inline void skb_dst_drop(struct sk_buff *skb)
{
	skb->dst = NULL;
}

static inline void skb_dst_set_noref(struct sk_buff *skb, struct dst_entry *dst)
{
	skb->dst = dst;
}

static inline unsigned int skb_headroom(const struct sk_buff *skb)
{
	return skb->headroom;
}

static inline struct sk_buff *skb_expand_head(struct sk_buff *skb, unsigned int headroom)
{
	if (skb->headroom < headroom)
		skb->headroom = headroom;
	return skb;
}

static inline int skb_cow_head(struct sk_buff *skb, unsigned int headroom)
{
	skb_expand_head(skb, headroom);
	return 0;
}

static inline int dev_hard_header(struct sk_buff *skb, struct net_device *dev, unsigned short type,
			   const void *daddr, const void *saddr, unsigned int len)
{
	seen.hard_headers++;
	seen.header_dev = dev;
	seen.header_type = type;
	seen.header_dest = daddr;
	if (daddr)
		memcpy(seen.dest, daddr, ETH_ALEN);
	return 0;
}

static inline int dev_queue_xmit(struct sk_buff *skb)
{
	seen.queued++;
	seen.queued_skb = skb;
	seen.queued_dev = skb->dev;
	return 0;
}

static inline int neigh_xmit(int index, struct net_device *dev, const void *addr,
			     struct sk_buff *skb)
{
	seen.neigh_xmits++;
	seen.xmit_table = index;
	seen.xmit_dev = dev;
	seen.xmit_skb = skb;
	seen.xmit_dst = skb->dst;
	memcpy(seen.xmit_addr, addr, index == NEIGH_ARP_TABLE ? 4 : 16);
	return 0;
}

/* The neighbour's output: neigh_resolve_output() for an entry not connected,
 * which queues the frame, starts or restarts resolution and writes the
 * header once the entry is resolved. */
static int resolve_output(struct neighbour *n, struct sk_buff *skb)
{
	seen.resolved++;
	seen.resolve_neigh = n;
	seen.resolve_skb = skb;
	seen.resolve_dev = skb->dev;
	seen.resolve_dst = skb->dst;
	seen.resolve_headroom = skb->headroom;
	return 0;
}

#include "flowtable_neigh_transmit_production.inc"

static const u8 zero[ETH_ALEN];
/* The address the entry held before it went stale: the next hop since
 * replaced, or not answering. */
static const u8 old_mac[ETH_ALEN] = { 0x02, 0, 0, 0, 0x0a, 0x01 };
static const u8 next_hop_mac[ETH_ALEN] = { 0x02, 0, 0, 0, 0x0b, 0x02 };

static const struct {
	const char *name;
	u8 nud;
	const u8 *ha;
} states[] = {
	/* The entries the neighbour layer has not confirmed... */
	{ "NUD_NONE", NUD_NONE, zero },
	{ "NUD_INCOMPLETE", NUD_INCOMPLETE, zero },
	{ "NUD_FAILED", NUD_FAILED, zero },
	{ "NUD_STALE", NUD_STALE, old_mac },
	{ "NUD_DELAY", NUD_DELAY, old_mac },
	{ "NUD_PROBE", NUD_PROBE, old_mac },
	/* ...and those it has. */
	{ "NUD_REACHABLE", NUD_REACHABLE, next_hop_mac },
	{ "NUD_PERMANENT", NUD_PERMANENT, next_hop_mac },
	{ "NUD_NOARP", NUD_NOARP, next_hop_mac },
};

static unsigned int failures;
static char context[96];

#define expect(condition, ...) do {						\
	if (!(condition)) {							\
		fprintf(stderr, "%s: ", context);				\
		fprintf(stderr, __VA_ARGS__);					\
		fputc('\n', stderr);						\
		failures++;							\
		return;								\
	}									\
} while (0)

static inline const char *mac(const u8 *addr)
{
	static char text[18];

	snprintf(text, sizeof(text), "%02x:%02x:%02x:%02x:%02x:%02x",
		 addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	return text;
}

static void transmit(bool ipv6, unsigned int s)
{
	struct dst_entry *route = ipv6 ? &rt6.dst : &rt4.dst;
	struct nf_hook_state hook_state = { &lan, &net };
	struct nf_flowtable table = { false, 0 };
	struct sk_buff skb = {
		.dev = &lan,
		.protocol = htons(ipv6 ? ETH_P_IPV6 : ETH_P_IP),
		.len = 1400,
		/* Less than the device's header: the frame came in with its
		 * own pulled. */
		.headroom = 2,
		.dst = &input_dst,
	};
	unsigned int ret;

	snprintf(context, sizeof(context), "IPv%d, next hop's entry %s", ipv6 ? 6 : 4,
		 states[s].name);
	memset(&seen, 0, sizeof(seen));
	memset(&neigh, 0, sizeof(neigh));
	neigh.dev = &wan;
	neigh.nud_state = states[s].nud;
	neigh.output = resolve_output;
	memcpy(neigh.ha, states[s].ha, ETH_ALEN);
	memset(&flow, 0, sizeof(flow));
	flow.tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple = (struct flow_offload_tuple){
		.dir = FLOW_OFFLOAD_DIR_ORIGINAL,
		.xmit_type = FLOW_OFFLOAD_XMIT_NEIGH,
		.dst_cache = route,
		.ifidx = wan.ifindex,
	};
	/* The reply's source, the original direction's destination: a host
	 * beyond the routed next hop. */
	if (ipv6)
		inet_pton(AF_INET6, "2001:db8::10",
			  &flow.tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.src_v6);
	else
		flow.tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.src_v4.s_addr = htonl(0xc6336410);

	ret = ipv6 ? nf_flow_offload_ipv6_hook(&table, &skb, &hook_state)
		   : nf_flow_offload_ip_hook(&table, &skb, &hook_state);

	expect(ret == NF_STOLEN, "the hook answered %u, not NF_STOLEN", ret);
	expect(!flow.torn_down, "the flow was torn down");
	expect(!warnings, "the hook warned");
#ifdef NEIGH_XMIT_BY_DST
	/* neigh_xmit() looks the entry up and sends through its output,
	 * whatever its state: that resolves it. */
	expect(seen.neigh_xmits == 1, "neigh_xmit() was called %u times", seen.neigh_xmits);
	expect(seen.xmit_table == (ipv6 ? NEIGH_ND_TABLE : NEIGH_ARP_TABLE),
	       "neigh_xmit() was given table %d", seen.xmit_table);
	expect(seen.xmit_dev == route->dev && seen.xmit_skb == &skb && skb.dev == route->dev,
	       "neigh_xmit() was not given the frame on the route's device");
	expect(seen.xmit_dst == route, "the frame reached neigh_xmit() without the route");
	expect(!memcmp(seen.xmit_addr, ipv6 ? (const void *)&rt6.rt6i_gateway : (const void *)&rt4.rt_gw4,
		       ipv6 ? 16 : 4), "neigh_xmit() was not given the route's next hop");
	expect(!seen.hard_headers && !seen.queued && !seen.resolved,
	       "the frame was also sent another way");
#else
	if (!(states[s].nud & NUD_CONNECTED)) {
		expect(!seen.hard_headers,
		       "the frame was sent through dev_hard_header() to %s, the entry's %s address, "
		       "not through the neighbour's output", mac(seen.dest),
		       memcmp(seen.dest, zero, ETH_ALEN) ? "unconfirmed" : "all-zero");
		expect(!seen.queued, "the frame was queued to the device without a header of its own");
		expect(seen.resolved == 1, "the neighbour's output was called %u times", seen.resolved);
		expect(seen.resolve_neigh == &neigh && seen.resolve_skb == &skb,
		       "the neighbour's output was not given this entry and frame");
		expect(seen.resolve_dev == route->dev,
		       "the frame reached the neighbour's output on ifindex %d, not the route's device",
		       seen.resolve_dev ? seen.resolve_dev->ifindex : 0);
		expect(seen.resolve_dst == route, "the frame reached the neighbour's output without the route");
		expect(seen.resolve_headroom >= route->dev->hard_header_len,
		       "the frame reached the neighbour's output with %u bytes of headroom, "
		       "short of the device's %u-byte header", seen.resolve_headroom,
		       route->dev->hard_header_len);
	} else {
		expect(!seen.resolved, "a confirmed entry's frame went through the neighbour's output");
		expect(seen.hard_headers == 1, "dev_hard_header() was called %u times", seen.hard_headers);
		expect(seen.header_dev == &wan && seen.header_type == (ipv6 ? ETH_P_IPV6 : ETH_P_IP),
		       "the header was not written for the route's device and the frame's protocol");
		expect(seen.header_dest, "the header was written with no destination");
		expect(memcmp(seen.dest, zero, ETH_ALEN), "the header was written to an all-zero destination");
		expect(!memcmp(seen.dest, next_hop_mac, ETH_ALEN),
		       "the header was written to %s, not the entry's address", mac(seen.dest));
		expect(seen.header_dest != (const void *)neigh.ha && seen.snapshots,
		       "the header was written straight from the entry's address, which "
		       "neigh_update() rewrites under ha_lock meanwhile, not from a copy "
		       "read whole under it (neigh_ha_snapshot())");
		expect(seen.queued == 1 && seen.queued_skb == &skb && seen.queued_dev == &wan,
		       "the frame was not queued to the route's device");
	}
#endif
}

int main(void)
{
	unsigned int cases = 0;

	inet_pton(AF_INET, "203.0.113.1", &rt4.rt_gw4);
	for (int ipv6 = 0; ipv6 <= 1; ipv6++)
		for (unsigned int s = 0; s < sizeof(states) / sizeof(states[0]); s++, cases++)
			transmit(ipv6, s);
	if (failures) {
		fprintf(stderr, "%u of %u NEIGH transmits went wrong\n", failures, cases);
		return 1;
	}
	printf("%u NEIGH transmits, each next hop resolved before its address was written\n", cases);
	return 0;
}
