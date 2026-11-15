/* The WireGuard raw forward's use of the next hop is production code:
 * nf_flow_offload_ip_raw(), with every helper of its file it calls, and the
 * neighbour layer's inline helpers as the tree defines them
 * (neigh_ha_snapshot(), neigh_event_send()). The tuple lookup, the route,
 * the device, conntrack and the neighbour table and its state machine under
 * them are the simulated boundary.
 *
 * WireGuard forwards a tunnel's packet where it decrypted it, and for a flow
 * this path takes, it is the only one the flow's packets take: the stack's
 * output, which would tell the neighbour layer the next hop's entry is in
 * use, never sees them. An entry with no valid address gives the packet back
 * to the stack, whose output resolves it. A valid one the neighbour layer has
 * not confirmed (stale, delay, probe) is still sent to at its address, as the
 * stack's own output does, but only with the layer told (neigh_event_send()):
 * that marks the entry used and moves a stale one on to DELAY and PROBE,
 * which confirms its address or learns the new one. Untold, the entry stays
 * stale, and a next hop that changed its address unannounced is sent to at
 * the old one for as long as the flow lives. */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
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

#define __force
#ifndef __always_inline
#define __always_inline inline __attribute__((__always_inline__))
#endif
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, val) ((x) = (val))
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define container_of(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))

#define ETH_ALEN 6
#define MAX_ADDR_LEN 32
#define IP_OFFSET 0x1FFF
enum flow_offload_tuple_dir { FLOW_OFFLOAD_DIR_ORIGINAL, FLOW_OFFLOAD_DIR_REPLY };
enum flow_offload_xmit_type {
	FLOW_OFFLOAD_XMIT_UNSPEC, FLOW_OFFLOAD_XMIT_NEIGH, FLOW_OFFLOAD_XMIT_XFRM,
	FLOW_OFFLOAD_XMIT_DIRECT, FLOW_OFFLOAD_XMIT_TC,
};
enum nf_flow_flags { NF_FLOW_SNAT, NF_FLOW_DNAT };
enum nf_flowtable_flags { NF_FLOWTABLE_HW_OFFLOAD = 0x1, NF_FLOWTABLE_COUNTER = 0x2 };

struct net { int id; };
struct net_device {
	int ifindex;
	unsigned char addr_len;
	unsigned char dev_addr[MAX_ADDR_LEN];
};
struct dst_entry { struct net_device *dev; u32 cookie; };
struct rtable { struct dst_entry dst; __be32 rt_gw4; };
/* neigh_event_send()'s frame to queue: the raw path has none. */
struct sk_buff;
typedef struct { unsigned int sequence; } seqlock_t;
struct neighbour {
	struct net_device *dev;
	__be32 key;
	u8 nud_state;
	unsigned long used;
	seqlock_t ha_lock;
	unsigned char ha[MAX_ADDR_LEN];
};
struct nf_conn { u64 packets[2], bytes[2]; unsigned int seen_reply; };
struct nf_flowtable { bool use_hw_handles, use_neigh; unsigned int flags; };
struct flow_offload_tuple {
	struct in_addr src_v4, dst_v4;
	__be16 src_port, dst_port;
	int iifidx;
	u8 l3proto, l4proto;
	u8 dir, xmit_type, encap_num;
	u16 mtu;
	struct { int lower_ifindex; } session, tunnel;
	struct dst_entry *dst_cache;
	u32 dst_cookie;
};
struct flow_offload_tuple_rhash { struct flow_offload_tuple tuple; };
struct flow_offload {
	struct flow_offload_tuple_rhash tuplehash[2];
	unsigned long flags;
	struct nf_conn *ct;
	unsigned int torn_down;
};

/* NUD_* as the tree defines them, and the raw path's own description of the
 * transmit. */
#include "flowtable_raw_neigh_types.inc"

/* What the route, conntrack and neighbour layers were asked for. */
static struct {
	unsigned int lookups, event_sends, refreshes;
	const struct net_device *egress_dev;
	struct neighbour *event_neigh;
	struct sk_buff *event_skb;
	u8 event_state;
} seen;

/* Now, a minute (at HZ 1000) after the entry was last used. */
#define NOW 300000UL
#define LAST_USED (NOW - 60000)
static unsigned long jiffies = NOW;

static struct net net;
static struct net_device wg = { 5, 0, { 0 } };
static struct net_device wan = { 4, ETH_ALEN, { 0x02, 0, 0, 0, 0x04, 0x01 } };
static struct rtable rt4 = { { &wan, 0x5eed }, 0 };
static struct neighbour neigh;
static struct nf_conn conntrack;
static struct flow_offload flow;

static inline bool test_bit(long nr, const unsigned long *addr)
{
	return *addr >> nr & 1;
}

static inline struct net *dev_net(const struct net_device *dev)
{
	return &net;
}

static inline bool xfrm_flowtable_enabled(struct net *in)
{
	return true;
}

/* The flow's original direction, for its own tuple only. */
static inline struct flow_offload_tuple_rhash *flow_offload_lookup(struct nf_flowtable *flow_table,
								    struct flow_offload_tuple *tuple)
{
	const struct flow_offload_tuple *key = &flow.tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple;

	if (tuple->src_v4.s_addr != key->src_v4.s_addr || tuple->dst_v4.s_addr != key->dst_v4.s_addr ||
	    tuple->src_port != key->src_port || tuple->dst_port != key->dst_port ||
	    tuple->l3proto != key->l3proto || tuple->l4proto != key->l4proto ||
	    tuple->iifidx != key->iifidx)
		return NULL;
	return &flow.tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL];
}

static inline void flow_offload_teardown(struct flow_offload *teardown)
{
	teardown->torn_down++;
}

static inline void flow_offload_refresh(struct nf_flowtable *flow_table,
					struct flow_offload *refresh, bool force)
{
	seen.refreshes++;
}

static inline struct dst_entry *dst_check(struct dst_entry *dst, u32 cookie)
{
	return cookie == dst->cookie ? dst : NULL;
}

static inline struct rtable *dst_rtable(const struct dst_entry *dst)
{
	return container_of(dst, struct rtable, dst);
}

static inline __be32 rt_nexthop(const struct rtable *rt, __be32 daddr)
{
	return rt->rt_gw4 ? rt->rt_gw4 : daddr;
}

/* The next hop's entry on the device, whatever its state; none is created. */
static inline struct neighbour *__ipv4_neigh_lookup_noref(struct net_device *dev, u32 key)
{
	seen.lookups++;
	return dev == neigh.dev && key == neigh.key ? &neigh : NULL;
}

static inline unsigned int read_seqbegin(const seqlock_t *lock)
{
	return lock->sequence;
}

static inline int read_seqretry(const seqlock_t *lock, unsigned int start)
{
	return lock->sequence != start;
}

static inline void ether_addr_copy(u8 *dst, const u8 *src)
{
	memcpy(dst, src, ETH_ALEN);
}

static inline bool ip_is_fragment(const struct iphdr *iph)
{
	return (iph->frag_off & htons(IP_MF | IP_OFFSET)) != 0;
}

static inline int ip_decrease_ttl(struct iphdr *iph)
{
	return --iph->ttl;
}

static inline void nf_ct_acct_update(struct nf_conn *ct, u32 dir, unsigned int bytes)
{
	ct->packets[dir]++;
	ct->bytes[dir] += bytes;
}

static inline void nf_flow_ct_seen_reply(struct nf_conn *ct)
{
	ct->seen_reply++;
}

/* The neighbour layer's state machine behind neigh_event_send(): a stale
 * entry moves on to DELAY, whose timer probes it unless it is confirmed
 * meanwhile, and one not valid starts resolving. */
static inline int __neigh_event_send(struct neighbour *n, struct sk_buff *skb,
				     const bool immediate_ok)
{
	seen.event_sends++;
	seen.event_neigh = n;
	seen.event_skb = skb;
	seen.event_state = n->nud_state;
	if (n->nud_state & (NUD_CONNECTED | NUD_DELAY | NUD_PROBE))
		return 0;
	if (n->nud_state & NUD_STALE) {
		n->nud_state = NUD_DELAY;
		return 0;
	}
	n->nud_state = NUD_INCOMPLETE;
	return 1;
}

static bool egress_ok(const struct net_device *dev)
{
	seen.egress_dev = dev;
	return true;
}

#include "flowtable_raw_neigh_production.inc"

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
	/* The entries with no address to send to... */
	{ "NUD_NONE", NUD_NONE, zero },
	{ "NUD_INCOMPLETE", NUD_INCOMPLETE, zero },
	{ "NUD_FAILED", NUD_FAILED, zero },
	/* ...those with one the neighbour layer has to confirm again... */
	{ "NUD_STALE", NUD_STALE, old_mac },
	{ "NUD_DELAY", NUD_DELAY, old_mac },
	{ "NUD_PROBE", NUD_PROBE, old_mac },
	/* ...and those it has confirmed, or needs not. */
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

static void forward(unsigned int s)
{
	struct nf_flowtable table = { false, false, NF_FLOWTABLE_COUNTER };
	struct nf_flow_raw_xmit xmit;
	struct {
		struct iphdr ip;
		struct udphdr udp;
		u8 payload[100];
	} packet = { 0 };
	unsigned int len = sizeof(packet);
	u8 before;
	int ret;

	snprintf(context, sizeof(context), "next hop's entry %s", states[s].name);
	memset(&seen, 0, sizeof(seen));
	memset(&xmit, 0, sizeof(xmit));
	memset(&neigh, 0, sizeof(neigh));
	neigh.dev = &wan;
	neigh.key = rt4.rt_gw4;
	neigh.nud_state = states[s].nud;
	neigh.used = LAST_USED;
	memcpy(neigh.ha, states[s].ha, ETH_ALEN);
	memset(&conntrack, 0, sizeof(conntrack));

	/* A packet out of the tunnel, from a host behind the peer to one
	 * beyond the routed next hop. */
	packet.ip.version = 4;
	packet.ip.ihl = 5;
	packet.ip.ttl = 64;
	packet.ip.protocol = IPPROTO_UDP;
	packet.ip.tot_len = htons(len);
	inet_pton(AF_INET, "10.0.0.2", &packet.ip.saddr);
	inet_pton(AF_INET, "198.51.100.16", &packet.ip.daddr);
	packet.udp.source = htons(40000);
	packet.udp.dest = htons(5201);

	/* Routed, not translated, not encapsulated. */
	memset(&flow, 0, sizeof(flow));
	flow.ct = &conntrack;
	flow.tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple = (struct flow_offload_tuple){
		.src_v4.s_addr = packet.ip.saddr,
		.dst_v4.s_addr = packet.ip.daddr,
		.src_port = packet.udp.source,
		.dst_port = packet.udp.dest,
		.iifidx = wg.ifindex,
		.l3proto = AF_INET,
		.l4proto = IPPROTO_UDP,
		.dir = FLOW_OFFLOAD_DIR_ORIGINAL,
		.xmit_type = FLOW_OFFLOAD_XMIT_NEIGH,
		.mtu = 1500,
		.dst_cache = &rt4.dst,
		.dst_cookie = rt4.dst.cookie,
	};
	flow.tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple = (struct flow_offload_tuple){
		.src_v4.s_addr = packet.ip.daddr,
		.dst_v4.s_addr = packet.ip.saddr,
		.src_port = packet.udp.dest,
		.dst_port = packet.udp.source,
		.iifidx = wan.ifindex,
		.l3proto = AF_INET,
		.l4proto = IPPROTO_UDP,
		.dir = FLOW_OFFLOAD_DIR_REPLY,
		.xmit_type = FLOW_OFFLOAD_XMIT_NEIGH,
		.mtu = 1500,
	};
	before = packet.ip.ttl;

	ret = nf_flow_offload_ip_raw(&table, &wg, &packet.ip, len, egress_ok, &xmit);

	expect(!flow.torn_down, "the flow was torn down (%d)", ret);
	expect(seen.egress_dev == &wan, "the route's device was not offered to can_xmit()");
	expect(seen.lookups == 1, "the next hop's entry was looked up %u times", seen.lookups);
	if (!(states[s].nud & NUD_VALID)) {
		/* The stack's output resolves it, with the packet queued. */
		expect(ret == -EHOSTUNREACH, "the raw path answered %d, not -EHOSTUNREACH", ret);
		expect(packet.ip.ttl == before && !seen.refreshes && !xmit.dev,
		       "the packet was refused, but not untouched");
		expect(!seen.event_sends,
		       "resolution was started here (__neigh_event_send()) for a packet given "
		       "back to the stack, whose output starts it with the packet queued");
		return;
	}
	expect(ret == 0, "the raw path answered %d, not 0: an entry with a valid address "
	       "carries the packet, as the stack's own output does", ret);
	expect(xmit.dev == &wan, "the packet goes out on ifindex %d, not the route's device",
	       xmit.dev ? xmit.dev->ifindex : 0);
	expect(!memcmp(xmit.h_source, wan.dev_addr, ETH_ALEN),
	       "the packet goes out from %s, not the device's address", mac(xmit.h_source));
	expect(!memcmp(xmit.h_dest, states[s].ha, ETH_ALEN),
	       "the packet goes out to %s, not the entry's address", mac(xmit.h_dest));
	expect(packet.ip.ttl == before - 1 && seen.refreshes == 1,
	       "the forwarded packet's TTL or the flow's refresh is wrong");
	if (states[s].nud & NUD_CONNECTED) {
		expect(!seen.event_sends,
		       "a confirmed entry was handed to the neighbour layer's state machine "
		       "(__neigh_event_send())");
		return;
	}
	/* Not confirmed: the neighbour layer is told, as the stack's output
	 * (neigh_resolve_output()) tells it through neigh_event_send(). */
	if (states[s].nud & NUD_STALE) {
		expect(seen.event_sends == 1,
		       "the stale entry was handed to the neighbour layer's state machine "
		       "(__neigh_event_send()) %u times, not once: it never moves on to DELAY and "
		       "PROBE, so its address %s is never confirmed again", seen.event_sends,
		       mac(xmit.h_dest));
		expect(seen.event_neigh == &neigh && seen.event_state == NUD_STALE,
		       "the neighbour layer was told about another entry");
		expect(!seen.event_skb,
		       "the neighbour layer was given a frame to queue, which the raw path "
		       "forwards itself");
		expect(neigh.nud_state == NUD_DELAY, "the entry was left in state %#x, not NUD_DELAY",
		       neigh.nud_state);
	}
	expect(neigh.used == jiffies,
	       "the packet went to %s, an address not confirmed, without telling the neighbour "
	       "layer the entry is in use (neigh_event_send()): its last use stays %lu jiffies old",
	       mac(xmit.h_dest), jiffies - neigh.used);
}

int main(void)
{
	unsigned int cases = sizeof(states) / sizeof(states[0]);

	inet_pton(AF_INET, "203.0.113.1", &rt4.rt_gw4);
	for (unsigned int s = 0; s < cases; s++)
		forward(s);
	if (failures) {
		fprintf(stderr, "%u of %u raw forwards went wrong\n", failures, cases);
		return 1;
	}
	printf("%u raw forwards, each unconfirmed next hop told to the neighbour layer\n", cases);
	return 0;
}
