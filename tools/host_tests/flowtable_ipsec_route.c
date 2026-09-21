/* The route builder is production code; FIB and device-path lookups are the
 * simulated boundaries. A logical LAN route resolves to one physical port
 * and VLAN, while the transformed WAN route must retain its XFRM contract. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>

#define READ_ONCE(x) (x)
#define NFPROTO_IPV4 2
#define NFPROTO_IPV6 10
#define INET_DSCP_MASK 0xfc
#define FLOWI_FLAG_ANYSRC 1
#define FLOWI_FLAG_NO_OIF_FALLBACK 2
enum ip_conntrack_dir { IP_CT_DIR_ORIGINAL, IP_CT_DIR_REPLY };
enum flow_offload_xmit_type {
	FLOW_OFFLOAD_XMIT_NEIGH, FLOW_OFFLOAD_XMIT_XFRM, FLOW_OFFLOAD_XMIT_DIRECT
};
struct net_device { int ifindex; };
struct dst_entry {
	struct net_device *dev;
	bool xfrm;
	int refs;
};
struct sk_buff { struct dst_entry *dst; uint32_t mark; };
struct nft_pktinfo { struct sk_buff *skb; struct net_device *in; int family; };
struct nf_conn {
	struct { struct { struct { union {
		uint32_t ip;
		struct in6_addr in6;
	} u3; } src; } tuple; } tuplehash[2];
};
struct flowi {
	union {
		struct {
			uint32_t daddr, saddr, flowi4_mark;
			int flowi4_oif, flowi4_iif, flowi4_tos, flowi4_flags;
		} ip4;
		struct {
			struct in6_addr daddr, saddr;
			uint32_t flowlabel, flowi6_mark;
			int flowi6_oif, flowi6_iif, flowi6_flags;
		} ip6;
	} u;
};
struct nf_flow_route {
	struct {
		struct { int ifindex, num_encaps, vlan; } in;
		struct dst_entry *dst;
		enum flow_offload_xmit_type xmit_type;
	} tuple[2];
};
struct nft_flowtable { struct { bool use_neigh; } data; };
struct iphdr { int tos; };
static struct iphdr header;
static struct dst_entry *reverse_dst;
static int walks[2];
static struct net_device logical_lan = { 281 }, physical_lan = { 3 }, wan = { 4 };

#define dst_xfrm(dst) ((dst)->xfrm)
#define skb_dst(skb) ((skb)->dst)
#define nft_pf(pkt) ((pkt)->family)
#define nft_in(pkt) ((pkt)->in)
#define nft_net(pkt) NULL
#define ip_hdr(skb) (&header)
#define ipv6_hdr(skb) NULL
#define ip6_flowinfo(hdr) 0

static bool dst_hold_safe(struct dst_entry *dst)
{
	dst->refs++;
	return true;
}
static void dst_release(struct dst_entry *dst) { dst->refs--; }
static void nf_route(void *net, struct dst_entry **dst, struct flowi *fl,
		     bool strict, int family)
{
	*dst = reverse_dst;
	if (*dst)
		(*dst)->refs++;
}
static void nft_dev_forward_path(struct nf_flow_route *route,
				 const struct nf_conn *ct,
				 enum ip_conntrack_dir dir,
				 struct nft_flowtable *ft)
{
	/* Generic neighbour walking cannot resolve an XFRM outer peer from the
	 * inner tuple. Calling it on that direction is itself a regression. */
	assert(route->tuple[dir].xmit_type == FLOW_OFFLOAD_XMIT_NEIGH);
	walks[dir]++;
	if (route->tuple[dir].dst->dev == &logical_lan) {
		route->tuple[!dir].in.ifindex = physical_lan.ifindex;
		route->tuple[!dir].in.num_encaps = 1;
		route->tuple[!dir].in.vlan = 281;
	}
	if (!ft->data.use_neigh)
		route->tuple[dir].xmit_type = FLOW_OFFLOAD_XMIT_DIRECT;
}

#include "route_production.inc"

static void check_route(int family, enum ip_conntrack_dir dir,
			bool use_neigh, bool this_xfrm, bool other_xfrm)
{
	struct dst_entry here = { &wan, this_xfrm, 1 };
	struct dst_entry there = { &logical_lan, other_xfrm, 1 };
	struct sk_buff skb = { &here, 0 };
	struct nft_pktinfo pkt = { &skb, &logical_lan, family };
	struct nft_flowtable ft = { { use_neigh } };
	struct nf_conn ct = {};
	struct nf_flow_route route = {};
	bool any_xfrm = this_xfrm || other_xfrm;

	memset(walks, 0, sizeof(walks));
	reverse_dst = &there;
	assert(nft_flow_route(&pkt, &ct, &route, dir, &ft) == 0);
	assert(route.tuple[dir].dst == &here && route.tuple[!dir].dst == &there);
	assert(here.refs == 2 && there.refs == 2);
	assert(walks[dir] == (!this_xfrm && (use_neigh || !any_xfrm)));
	assert(walks[!dir] == (!other_xfrm && (use_neigh || !any_xfrm)));
	if (walks[!dir]) {
		assert(route.tuple[dir].in.ifindex == physical_lan.ifindex);
		assert(route.tuple[dir].in.num_encaps == 1);
		assert(route.tuple[dir].in.vlan == 281);
	} else {
		assert(route.tuple[dir].in.ifindex == logical_lan.ifindex);
		assert(route.tuple[dir].in.num_encaps == 0);
	}
	assert(route.tuple[!dir].in.ifindex == wan.ifindex);
	assert(route.tuple[dir].xmit_type == (this_xfrm ? FLOW_OFFLOAD_XMIT_XFRM :
		walks[dir] && !use_neigh ? FLOW_OFFLOAD_XMIT_DIRECT : FLOW_OFFLOAD_XMIT_NEIGH));
	assert(route.tuple[!dir].xmit_type == (other_xfrm ? FLOW_OFFLOAD_XMIT_XFRM :
		walks[!dir] && !use_neigh ? FLOW_OFFLOAD_XMIT_DIRECT : FLOW_OFFLOAD_XMIT_NEIGH));
	dst_release(route.tuple[dir].dst);
	dst_release(route.tuple[!dir].dst);
	assert(here.refs == 1 && there.refs == 1);

	/* A failed reverse route must release its borrowed forward reference. */
	reverse_dst = NULL;
	assert(nft_flow_route(&pkt, &ct, &route, dir, &ft) == -ENOENT);
	assert(here.refs == 1 && there.refs == 1);
}

int main(void)
{
	for (int family = 0; family < 2; family++)
		for (int dir = 0; dir < 2; dir++)
			for (int use_neigh = 0; use_neigh < 2; use_neigh++)
				for (int a = 0; a < 2; a++)
					for (int b = 0; b < 2; b++)
						check_route(family ? NFPROTO_IPV6 : NFPROTO_IPV4,
							    dir, use_neigh, a, b);
	puts("flowtable route direction and transform checks passed");
	return 0;
}
