/* The adapter's end of the software Tx path's classification: the class of the
 * connection an IP packet belongs to, for a frame that may have lost its
 * conntrack on the way to the port.
 *
 * ft_qos_class() and ft_qos_flow_class() are compiled from the adapter; the
 * conntrack table is a stub that records what it was asked and hands out
 * references it counts, so a lookup that takes one and does not give it back
 * fails here rather than leaking an entry on the board.
 */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint16_t u_int16_t;

#define READ_ONCE(x)	(x)
#define AF_INET		2
#define AF_INET6	10
#define NFPROTO_IPV4	2
#define NFPROTO_IPV6	10
#define NFCT_INFOMASK	7UL
/* The kernel's view of the enum below, which has IP_CT_UNTRACKED. */
#define __KERNEL__
static unsigned long __ffs(unsigned long word) { return (unsigned long)__builtin_ctzl(word); }

#include "qos_flow_class_types.inc"

struct net { int id; };
static struct net init_net;
struct net_device { struct net *net; };
#define dev_net(d)	((d)->net)
struct nf_conntrack_zone { int id; };
static const struct nf_conntrack_zone nf_ct_zone_dflt;
/* Two endpoints, which is all an inversion swaps. */
struct nf_conntrack_tuple { u32 src, dst; };
struct nf_conntrack_tuple_hash { struct nf_conntrack_tuple tuple; };
struct nf_conn {
	struct nf_conntrack_tuple_hash tuplehash[2];
	u32 mark;
	int refs;
};
struct sk_buff {
	unsigned long _nfct;
	int skb_iif;
	struct net_device *dev;
	/* What conntrack would build from the packet at the offset it is
	 * asked about, or nothing for a packet it cannot parse. */
	bool unparsable;
	struct nf_conntrack_tuple tuple;
};

static struct nf_conn *nf_ct_get(const struct sk_buff *skb, enum ip_conntrack_info *ctinfo)
{
	*ctinfo = skb->_nfct & NFCT_INFOMASK;
	return (struct nf_conn *)(skb->_nfct & ~NFCT_INFOMASK);
}

/* The table: one translated connection, a LAN host (1) to a remote one (2)
 * masqueraded behind the gateway's WAN address (3). Its original tuple is as
 * the LAN host sent it, its reply tuple as the remote one answers. */
enum { LAN = 1, REMOTE = 2, WAN = 3 };
static struct nf_conn entry = { .tuplehash = { { { LAN, REMOTE } }, { { REMOTE, WAN } } } };
static unsigned tuples, lookups, last_nhoff;
static u16 last_l3num;
static bool irqs_off;
static bool irqs_disabled(void) { return irqs_off; }

static bool nf_ct_get_tuplepr(const struct sk_buff *skb, unsigned int nhoff,
			      u_int16_t l3num, struct net *net,
			      struct nf_conntrack_tuple *tuple)
{
	assert(net == &init_net);
	tuples++;
	last_nhoff = nhoff;
	last_l3num = l3num;
	if (skb->unparsable)
		return false;
	*tuple = skb->tuple;
	return true;
}
static bool nf_ct_invert_tuple(struct nf_conntrack_tuple *inverse,
			       const struct nf_conntrack_tuple *orig)
{
	inverse->src = orig->dst;
	inverse->dst = orig->src;
	return true;
}
static struct nf_conntrack_tuple_hash *
nf_conntrack_find_get(struct net *net, const struct nf_conntrack_zone *zone,
		      const struct nf_conntrack_tuple *tuple)
{
	assert(net == &init_net && zone == &nf_ct_zone_dflt);
	lookups++;
	for (unsigned dir = 0; dir < 2; dir++)
		if (entry.tuplehash[dir].tuple.src == tuple->src &&
		    entry.tuplehash[dir].tuple.dst == tuple->dst) {
			entry.refs++;
			return &entry.tuplehash[dir];
		}
	return NULL;
}
static struct nf_conn *nf_ct_tuplehash_to_ctrack(const struct nf_conntrack_tuple_hash *h)
{
	return &entry;
}
static void nf_ct_put(struct nf_conn *ct)
{
	assert(ct == &entry && ct->refs > 0);
	ct->refs--;
}

static unsigned int ft_qos_mark_mask = 0xf0, ft_qos_default_class;

#include "qos_flow_class_production.inc"

int main(void)
{
	struct net_device port = { .net = &init_net };
	struct nf_conn attached = { .mark = 0x70 };
	u32 class;

	/* A frame that kept its conntrack: that conntrack's class, and no
	 * lookup. */
	struct sk_buff kept = { ._nfct = (unsigned long)&attached | IP_CT_ESTABLISHED,
				.skb_iif = 3, .dev = &port };
	class = 0xdead;
	assert(ft_qos_flow_class(&kept, 14, AF_INET, true, &class) && class == 0x7);
	assert(!tuples && !lookups);
	/* Even with no IP header found: the conntrack speaks for the frame. */
	assert(ft_qos_flow_class(&kept, 0, 0, true, &class) && class == 0x7);
	/* But not for a header the frame carries inside it. That one is looked
	 * up by its own tuple, which is the reply direction's inverse. */
	entry.mark = 0x50;
	kept.tuple = (struct nf_conntrack_tuple){ WAN, REMOTE };
	assert(ft_qos_flow_class(&kept, 34, AF_INET6, false, &class) && class == 0x5);
	assert(tuples == 1 && last_nhoff == 34 && last_l3num == NFPROTO_IPV6);
	assert(lookups == 1 && !entry.refs);

	/* A frame a scrub took the conntrack and the ingress index from --
	 * ppp_start_xmit()'s -- is looked up at the offset it is handed. It
	 * left translated, from the WAN address: a tuple the table does not
	 * hold, whose inverse is the reply direction's. The reference the
	 * lookup takes is given back. */
	struct sk_buff scrubbed = { .dev = &port, .tuple = { WAN, REMOTE } };
	tuples = lookups = 0;
	assert(ft_qos_flow_class(&scrubbed, 22, AF_INET, true, &class) && class == 0x5);
	assert(tuples == 1 && last_nhoff == 22 && last_l3num == NFPROTO_IPV4);
	assert(lookups == 1 && !entry.refs);
	/* A frame of the other direction, on its way to the LAN host after
	 * the translation was undone, inverts to the original direction's
	 * tuple, and finds the same entry. */
	scrubbed.tuple = (struct nf_conntrack_tuple){ REMOTE, LAN };
	assert(ft_qos_flow_class(&scrubbed, 22, AF_INET, true, &class) && class == 0x5);
	/* A masked mark of zero takes the default class, as it did at
	 * admission. */
	entry.mark = 0x0f;
	ft_qos_default_class = 0x3;
	assert(ft_qos_flow_class(&scrubbed, 22, AF_INET, true, &class) && class == 0x3);
	ft_qos_default_class = 0;
	/* Nothing in the table for it: no class, and nothing written. */
	scrubbed.tuple = (struct nf_conntrack_tuple){ WAN, 9 };
	class = 0xdead;
	assert(!ft_qos_flow_class(&scrubbed, 22, AF_INET, true, &class) && class == 0xdead);
	/* Nor for a packet conntrack cannot build a tuple from. */
	scrubbed.unparsable = true;
	lookups = 0;
	assert(!ft_qos_flow_class(&scrubbed, 22, AF_INET, true, &class) && !lookups);
	scrubbed.unparsable = false;

	/* Not looked up: a frame untracked on purpose, one that still has its
	 * ingress index and so crossed no scrub, one with no IP header, one
	 * sent with interrupts off, and anything while classification is off. */
	scrubbed.tuple = (struct nf_conntrack_tuple){ WAN, REMOTE };
	tuples = lookups = 0;
	struct sk_buff untracked = { ._nfct = IP_CT_UNTRACKED, .dev = &port,
				     .tuple = { WAN, REMOTE } };
	assert(!ft_qos_flow_class(&untracked, 14, AF_INET, true, &class));
	struct sk_buff bridged = { .skb_iif = 4, .dev = &port, .tuple = { WAN, REMOTE } };
	assert(!ft_qos_flow_class(&bridged, 14, AF_INET, true, &class));
	assert(!ft_qos_flow_class(&scrubbed, 0, 0, true, &class));
	irqs_off = true;
	assert(!ft_qos_flow_class(&scrubbed, 22, AF_INET, true, &class));
	irqs_off = false;
	ft_qos_mark_mask = 0;
	assert(!ft_qos_flow_class(&scrubbed, 22, AF_INET, true, &class));
	assert(!tuples && !lookups);
	/* A conntrack the frame kept still answers, with the class every mark
	 * has while classification is off. */
	assert(ft_qos_flow_class(&kept, 14, AF_INET, true, &class) && class == 0);
	ft_qos_mark_mask = 0xf0;
	assert(!entry.refs);
	return 0;
}
