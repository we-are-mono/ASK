/* The forward-path walk and the route builder around it are production code
 * (nft_flow_offload.c, from nft_xmit_type to nft_flow_offload_skip), and so
 * are the walker and the hooks it calls: dev_fill_forward_path() and the VLAN,
 * bridge, sit and ip6_tnl hooks. The FIB, the neighbour table and the bridge's
 * FDB, port and VLAN state are the simulated boundaries, and a PPPoE hop is
 * simulated whole. A LAN client sits behind VLAN 284 on eth3 or behind br-lan
 * on eth3; the WAN is eth4, which an IPv6-in-IPv4 and an IPv4-in-IPv6 tunnel
 * also leave by. The flowtable hooks the two ports.
 *
 * A flow's first packet can meet a hop that has not resolved yet: the
 * client's neighbour on a VLAN just created again, a tunnel's outer next hop
 * or route after the WAN link flapped, the client's FDB entry after it aged
 * out. Or it can reach a port the flowtable does not list, as one that lost
 * carrier before the table follows it back. Each group of cases can run
 * alone (argv[1]: neighbour, tunnel, bridge, controls, unlisted); no argument
 * runs them all. */
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

typedef uint8_t u8;
typedef uint16_t u16, __u16;
typedef uint32_t u32;
typedef uint16_t __be16;
typedef uint32_t __be32;
typedef struct { unsigned int val; } kuid_t;

#define ETH_ALEN 6
#define ETH_P_8021Q 0x8100
#define ETH_P_PPP_SES 0x8864
#define ARPHRD_ETHER 1
#define ARPHRD_PPP 512
#define ARPHRD_TUNNEL6 769
#define ARPHRD_SIT 776
#define IFF_LOOPBACK 0x8
#define IFF_ISATAP (1 << 15)
#define BIT(n) (1U << (n))
#define READ_ONCE(x) (x)
#define WARN_ON_ONCE(c) ({ bool __warn = (c); assert(!__warn); __warn; })
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define container_of(ptr, type, member) \
	((type *)((char *)(ptr) - offsetof(type, member)))
#define NF_FLOW_TABLE_ENCAP_MAX 2
#define NET_DEVICE_PATH_STACK_MAX 5
#define NET_DEVICE_PATH_VLAN_MAX 2
#define NFPROTO_IPV4 2
#define NFPROTO_IPV6 10
#define INET_DSCP_MASK 0xfc
#define FLOWI_FLAG_ANYSRC 1
#define FLOWI_FLAG_NO_OIF_FALLBACK 2
#define RT_SCOPE_UNIVERSE 0
#define RTN_UNICAST 1
#define IP_DF 0x4000
#define RTF_GATEWAY 0x0002
#define RTF_REJECT 0x0200
#define RTF_ANYCAST 0x00100000
#define RTF_LOCAL 0x80000000
#define IP6_TNL_F_IGN_ENCAP_LIMIT 0x1
#define IP6_TNL_F_USE_ORIG_TCLASS 0x2
#define IP6_TNL_F_RCV_DSCP_COPY 0x10
#define IP6_TNL_F_USE_ORIG_FWMARK 0x20
#define IP6_TNL_F_CAP_XMIT 0x10000
#define TUNNEL_ENCAP_NONE 0
#define IPV6_FLOWLABEL_MASK htonl(0x000FFFFF)
#define DEV_PATH_TUNNEL_F_INHERIT_TOS BIT(0)
#define DEV_PATH_TUNNEL_F_DF BIT(1)
#define DEV_PATH_TUNNEL_F_ENCAP_LIMIT BIT(2)
#define DEV_PATH_TUNNEL_F_DSCP_COPY BIT(3)

/* include/net/neighbour.h */
#define NUD_NONE 0x00
#define NUD_INCOMPLETE 0x01
#define NUD_REACHABLE 0x02
#define NUD_STALE 0x04
#define NUD_DELAY 0x08
#define NUD_PROBE 0x10
#define NUD_FAILED 0x20
#define NUD_NOARP 0x40
#define NUD_PERMANENT 0x80
#define NUD_VALID (NUD_PERMANENT | NUD_NOARP | NUD_REACHABLE | NUD_PROBE | \
		   NUD_STALE | NUD_DELAY)

struct list_head { struct list_head *next, *prev; };
#define list_for_each_entry_rcu(pos, head, member)				\
	for (pos = container_of((head)->next, typeof(*pos), member);		\
	     &pos->member != (head);						\
	     pos = container_of(pos->member.next, typeof(*pos), member))

enum ip_conntrack_dir { IP_CT_DIR_ORIGINAL, IP_CT_DIR_REPLY };
enum flow_offload_xmit_type {
	FLOW_OFFLOAD_XMIT_UNSPEC = 0,
	FLOW_OFFLOAD_XMIT_NEIGH,
	FLOW_OFFLOAD_XMIT_XFRM,
	FLOW_OFFLOAD_XMIT_DIRECT,
	FLOW_OFFLOAD_XMIT_TC,
};

enum net_device_path_type {
	DEV_PATH_ETHERNET = 0,
	DEV_PATH_VLAN,
	DEV_PATH_BRIDGE,
	DEV_PATH_PPPOE,
	DEV_PATH_DSA,
	DEV_PATH_MTK_WDMA,
	DEV_PATH_TUNNEL,
};

struct net_device;
struct net_device_path {
	enum net_device_path_type type;
	const struct net_device *dev;
	union {
		struct {
			u16 id;
			__be16 proto;
			u8 h_dest[ETH_ALEN];
		} encap;
		struct {
			enum {
				DEV_PATH_BR_VLAN_KEEP,
				DEV_PATH_BR_VLAN_TAG,
				DEV_PATH_BR_VLAN_UNTAG,
				DEV_PATH_BR_VLAN_UNTAG_HW,
			} vlan_mode;
			u16 vlan_id;
			__be16 vlan_proto;
		} bridge;
		struct {
			u8 family, proto, ttl, tos, flags;
			u8 h_dest[ETH_ALEN];
			__be32 flowlabel;
			__be32 saddr[4], daddr[4], nexthop[4];
		} tunnel;
	};
};
struct net_device_path_stack {
	int num_paths;
	struct net_device_path path[NET_DEVICE_PATH_STACK_MAX];
};
struct net_device_path_ctx {
	const struct net_device *dev;
	u8 daddr[ETH_ALEN];
	int num_vlans;
	struct {
		u16 id;
		__be16 proto;
	} vlan[NET_DEVICE_PATH_VLAN_MAX];
};
struct net_device_ops {
	int (*ndo_fill_forward_path)(struct net_device_path_ctx *ctx,
				     struct net_device_path *path);
};
struct net_device {
	int ifindex;
	unsigned int flags, priv_flags;
	unsigned short type;
	unsigned char addr_len;
	u8 dev_addr[ETH_ALEN];
	const struct net_device_ops *netdev_ops;
	void *priv;
	bool bridge_port;
	/* The simulation's own: walks started from this device. */
	int walks;
};

struct neighbour {
	int lock;
	u8 nud_state;
	u8 ha[ETH_ALEN];
	int refs;
	int kicks;
};
struct dst_entry {
	struct net_device *dev;
	bool xfrm;
	int refs;
	/* The neighbour dst_neigh_lookup() finds or creates; none fails it. */
	struct neighbour *neigh;
	int error;
	void *lwtstate;
};
struct rtable {
	struct dst_entry dst;
	u16 rt_type;
	u8 rt_gw_family;
	__be32 rt_gw4;
};
struct rt6_info {
	struct dst_entry dst;
	u32 rt6i_flags;
	struct in6_addr rt6i_gateway;
};

struct sk_buff { struct dst_entry *dst; uint32_t mark; };
struct nft_pktinfo { struct sk_buff *skb; struct net_device *in; int family; };
struct nf_conn {
	struct { struct { struct { union {
		uint32_t ip;
		struct in6_addr in6;
	} u3; } src; } tuple; } tuplehash[2];
};
struct flowi4 {
	__be32 daddr, saddr;
	u32 flowi4_mark;
	int flowi4_oif, flowi4_iif, flowi4_tos, flowi4_flags, flowi4_proto;
};
struct flowi6 {
	struct in6_addr daddr, saddr;
	__be32 flowlabel;
	u32 flowi6_mark;
	int flowi6_oif, flowi6_iif, flowi6_flags, flowi6_proto;
	kuid_t flowi6_uid;
};
struct flowi { union { struct flowi4 ip4; struct flowi6 ip6; } u; };
union nf_inet_addr { __be32 all[4]; struct in6_addr in6; };
struct nf_flow_session {
	int lower_ifindex;
	u16 id;
	u8 h_dest[ETH_ALEN];
};
struct nf_flow_tunnel {
	int lower_ifindex;
	u8 family, proto, ttl, tos, flags;
	u8 h_dest[ETH_ALEN];
	__be32 flowlabel;
	union nf_inet_addr saddr, daddr, nexthop;
};
struct nf_flow_route {
	struct {
		struct dst_entry *dst;
		struct {
			u32 ifindex;
			u32 unlisted_ifindex;
			struct {
				u16 id;
				__be16 proto;
			} encap[NF_FLOW_TABLE_ENCAP_MAX];
			u8 num_encaps:2, ingress_vlans:2;
		} in;
		struct {
			u32 ifindex, hw_ifindex;
			u8 h_source[ETH_ALEN];
			u8 h_dest[ETH_ALEN];
		} out;
		struct nf_flow_session session;
		struct nf_flow_tunnel tunnel;
		enum flow_offload_xmit_type xmit_type;
	} tuple[2];
};
struct nf_flowtable { bool use_neigh, hw; };
struct nft_hook { struct list_head list; struct { struct net_device *dev; } ops; };
struct nft_flowtable { struct nf_flowtable data; struct list_head hook_list; };

struct iphdr { u8 tos, ttl; __be16 frag_off; __be32 saddr, daddr; };
struct ip_tunnel {
	struct { int link; struct iphdr iph; } parms;
	u32 fwmark;
	void *net;
};
struct __ip6_tnl_parm {
	struct in6_addr laddr, raddr;
	u8 proto, hop_limit;
	bool collect_md;
	u32 flags, fwmark;
	__be32 flowinfo;
};
struct ip6_tnl {
	struct __ip6_tnl_parm parms;
	struct { int type; } encap;
	struct flowi fl;
};
struct vlan_dev_priv {
	u16 vlan_id;
	__be16 vlan_proto;
	struct net_device *real_dev;
};
struct net_bridge;
struct net_bridge_port {
	struct net_bridge *br;
	struct net_device *dev;
	bool forwarding;
};
struct net_bridge_fdb_entry {
	struct net_bridge_port *dst;
	u8 addr[ETH_ALEN];
};
struct net_bridge {
	struct net_device *dev;
	/* The one entry the FDB holds, or none. */
	struct net_bridge_fdb_entry *fdb;
};

/* What one case routes over. */
struct setup {
	struct nft_flowtable ft;
	struct nft_hook hooks[2];
	struct neighbour lan_neigh, wan_neigh, outer_neigh;
	struct dst_entry lan_dst, wan_dst;
	struct rtable outer4;
	struct rt6_info outer6;
	struct net_bridge_port port;
	struct net_bridge_fdb_entry fdb;
	struct sk_buff skb;
	struct nft_pktinfo pkt;
	struct nf_conn ct;
	struct nf_flow_route route;
	/* The outer IPv4 route lookup's error, and whether the outer IPv6
	 * route's transform lookup fails; the IPv6 route's own error is its
	 * dst's. */
	int outer4_error;
	bool xfrm_error;
};
static struct setup *cur;

static struct iphdr header;
static struct dst_entry *reverse_dst;

#define dst_xfrm(dst) ((dst)->xfrm)
#define skb_dst(skb) ((skb)->dst)
#define nft_pf(pkt) ((pkt)->family)
#define nft_in(pkt) ((pkt)->in)
#define nft_net(pkt) NULL
#define ip_hdr(skb) (&header)
#define ipv6_hdr(skb) NULL
#define ip6_flowinfo(hdr) 0
#define read_lock_bh(l) ((*(l))++)
#define read_unlock_bh(l) ((*(l))--)
#define dev_net(dev) NULL
#define flowi6_to_flowi(fl6) ((struct flowi *)(fl6))
#define dst_rt6_info(dst) container_of(dst, struct rt6_info, dst)

static inline bool is_zero_ether_addr(const u8 *a)
{
	static const u8 zero[ETH_ALEN];

	return !memcmp(a, zero, ETH_ALEN);
}
static inline bool is_valid_ether_addr(const u8 *a)
{
	return !(a[0] & 1) && !is_zero_ether_addr(a);
}
static inline void ether_addr_copy(u8 *dst, const u8 *src)
{
	memcpy(dst, src, ETH_ALEN);
}
static inline bool nf_flowtable_hw_offload(struct nf_flowtable *ft)
{
	return ft->hw;
}
static inline void *netdev_priv(const struct net_device *dev)
{
	return dev->priv;
}
static inline bool dst_hold_safe(struct dst_entry *dst)
{
	dst->refs++;
	return true;
}
static inline void dst_release(struct dst_entry *dst)
{
	assert(dst->refs > 0);
	dst->refs--;
}
static inline struct neighbour *dst_neigh_lookup(const struct dst_entry *dst,
						 const void *daddr)
{
	if (dst->neigh)
		dst->neigh->refs++;
	return dst->neigh;
}
static inline void neigh_release(struct neighbour *n)
{
	assert(n->refs > 0);
	n->refs--;
}
static inline int neigh_event_send(struct neighbour *n, struct sk_buff *skb)
{
	/* Only ever asked for with the reference still held, and with no
	 * packet to queue: the one being routed is not the neighbour's. */
	assert(n->refs > 0 && !skb && !n->lock);
	n->kicks++;
	return 1;
}
static inline void nf_route(void *net, struct dst_entry **dst, struct flowi *fl,
			    bool strict, int family)
{
	*dst = reverse_dst;
	if (*dst)
		(*dst)->refs++;
}

/* The tunnels' outer routes. */
static inline kuid_t sock_net_uid(void *net, void *sk)
{
	return (kuid_t){ 0 };
}
static inline void flowi4_init_output(struct flowi4 *fl4, int oif, u32 mark,
				      u8 tos, u8 scope, u8 proto, u8 flags,
				      __be32 daddr, __be32 saddr, __be16 dport,
				      __be16 sport, kuid_t uid)
{
	memset(fl4, 0, sizeof(*fl4));
	fl4->flowi4_oif = oif;
	fl4->flowi4_mark = mark;
	fl4->flowi4_tos = tos;
	fl4->flowi4_proto = proto;
	fl4->daddr = daddr;
	fl4->saddr = saddr;
}
static inline struct rtable *ip_route_output_flow(void *net, struct flowi4 *fl4,
						  void *sk)
{
	if (cur->outer4_error)
		return ERR_PTR(cur->outer4_error);
	cur->outer4.dst.refs++;
	return &cur->outer4;
}
static inline void ip_rt_put(struct rtable *rt)
{
	dst_release(&rt->dst);
}
static inline __be32 rt_nexthop(const struct rtable *rt, __be32 daddr)
{
	return rt->rt_gw_family == AF_INET ? rt->rt_gw4 : daddr;
}
static inline struct dst_entry *ip6_route_output(void *net, void *sk,
						 struct flowi6 *fl6)
{
	cur->outer6.dst.refs++;
	return &cur->outer6.dst;
}
/* A failed lookup releases the route it was given, as the kernel's does. */
static inline struct dst_entry *xfrm_lookup(void *net, struct dst_entry *dst,
					    struct flowi *fl, void *sk, int flags)
{
	if (!cur->xfrm_error)
		return dst;
	dst_release(dst);
	return ERR_PTR(-EPERM);
}
static inline const struct in6_addr *rt6_nexthop(const struct rt6_info *rt,
						 const struct in6_addr *daddr)
{
	return rt->rt6i_flags & RTF_GATEWAY ? &rt->rt6i_gateway : daddr;
}
static inline bool ipv6_addr_any(const struct in6_addr *a)
{
	return IN6_IS_ADDR_UNSPECIFIED(a);
}
static inline u8 ip6_tclass(__be32 flowinfo)
{
	return (ntohl(flowinfo) >> 20) & 0xff;
}

/* The VLAN device and the bridge. */
static inline struct vlan_dev_priv *vlan_dev_priv(const struct net_device *dev)
{
	return dev->priv;
}
static inline bool netif_is_bridge_port(const struct net_device *dev)
{
	return dev->bridge_port;
}
static inline void br_vlan_fill_forward_path_pvid(struct net_bridge *br,
						  struct net_device_path_ctx *ctx,
						  struct net_device_path *path)
{
}
static inline struct net_bridge_fdb_entry *
br_fdb_find_rcu(struct net_bridge *br, const unsigned char *addr, __u16 vid)
{
	return br->fdb && !memcmp(br->fdb->addr, addr, ETH_ALEN) ? br->fdb : NULL;
}
static inline int br_vlan_fill_forward_path_mode(struct net_bridge *br,
						 struct net_bridge_port *dst,
						 struct net_device_path *path)
{
	return 0;
}
static inline bool br_port_forwarding_vid(const struct net_bridge_port *p, u16 vid)
{
	return p->forwarding;
}

#include "forward_path_devices.inc"

/* A PPPoE session over the WAN port, simulated whole. */
static u8 session_mac[ETH_ALEN] = { 0x02, 0, 0, 0, 7, 7 };
static int ppp_fill_forward_path(struct net_device_path_ctx *ctx,
				 struct net_device_path *path);

static const struct net_device_ops port_ops = {},
	vlan_ops = { vlan_dev_fill_forward_path },
	bridge_ops = { br_fill_forward_path },
	sit_ops = { ipip6_fill_forward_path },
	ip6tnl_ops = { ip6_tnl_fill_forward_path },
	ppp_ops = { ppp_fill_forward_path };
static u8 client_mac[ETH_ALEN] = { 0x02, 0, 0, 0, 0x84, 2 };
static u8 wan_mac[ETH_ALEN] = { 0x02, 0, 0, 0, 4, 1 };

#define ETHER(index, port, last, ops)					\
	.ifindex = (index), .type = ARPHRD_ETHER, .addr_len = ETH_ALEN,	\
	.dev_addr = { 0x02, 0, 0, 0, (port), (last) }, .netdev_ops = (ops)
static struct net_device eth3 = { ETHER(3, 3, 0, &port_ops) };
static struct net_device eth4 = { ETHER(4, 4, 0, &port_ops) };
/* A Wi-Fi interface br-lan can bridge, which the flowtable never lists. */
static struct net_device wlan = { ETHER(8, 8, 0, &port_ops) };
static struct vlan_dev_priv vlan_priv;
static struct net_device vlan = { ETHER(30, 3, 0, &vlan_ops), .priv = &vlan_priv };
static struct net_bridge bridge_priv;
static struct net_device bridge = {
	ETHER(40, 3, 0x40, &bridge_ops), .priv = &bridge_priv,
};
static struct net_device ppp = {
	.ifindex = 50, .type = ARPHRD_PPP, .netdev_ops = &ppp_ops,
};
static struct ip_tunnel sit_priv;
static struct net_device sit = {
	.ifindex = 60, .type = ARPHRD_SIT, .addr_len = 4, .netdev_ops = &sit_ops,
	.priv = &sit_priv,
};
static struct ip6_tnl ip6tnl_priv;
static struct net_device ip6tnl = {
	.ifindex = 70, .type = ARPHRD_TUNNEL6, .addr_len = 16,
	.netdev_ops = &ip6tnl_ops, .priv = &ip6tnl_priv,
};

/* Byte-order conversions are no constant expressions on the host. */
static void init_devices(void)
{
	static const struct in6_addr local = { { { 0x20, 0x01, 0x0d, 0xb8, [15] = 2 } } },
		remote = { { { 0x20, 0x01, 0x0d, 0xb8, [15] = 1 } } };

	vlan_priv = (struct vlan_dev_priv){ 284, htons(ETH_P_8021Q), &eth3 };
	sit_priv.parms.iph = (struct iphdr){ .ttl = 64, .saddr = htonl(0xc0000201),
					     .daddr = htonl(0xc6336401) };
	ip6tnl_priv.parms = (struct __ip6_tnl_parm){
		.laddr = local, .raddr = remote, .proto = IPPROTO_IPIP, .hop_limit = 64,
		.flags = IP6_TNL_F_CAP_XMIT | IP6_TNL_F_IGN_ENCAP_LIMIT,
	};
	ip6tnl_priv.fl.u.ip6 = (struct flowi6){ .daddr = remote, .saddr = local };
}

static int ppp_fill_forward_path(struct net_device_path_ctx *ctx,
				 struct net_device_path *path)
{
	path->type = DEV_PATH_PPPOE;
	path->encap.id = 7;
	path->encap.proto = htons(ETH_P_PPP_SES);
	memcpy(path->encap.h_dest, session_mac, ETH_ALEN);
	path->dev = ctx->dev;
	memcpy(ctx->daddr, session_mac, ETH_ALEN);
	ctx->dev = &eth4;
	return 0;
}

/* Every walk the route builder starts, counted on the device it starts from;
 * an Ethernet destination is walked from its neighbour's address. */
static int counted_fill_forward_path(const struct net_device *dev, const u8 *daddr,
				     struct net_device_path_stack *stack)
{
	((struct net_device *)dev)->walks++;
	if (dev->type == ARPHRD_ETHER)
		assert(!memcmp(daddr, dev == &eth4 ? wan_mac : client_mac, ETH_ALEN));
	return dev_fill_forward_path(dev, daddr, stack);
}
#define dev_fill_forward_path counted_fill_forward_path

#include "forward_path_production.inc"

/* A packet of direction dir, from the WAN when lan_bound, else from the LAN;
 * the LAN destination is `lan` and the WAN one `wan`. */
static void prepare(struct setup *s, bool use_neigh, struct net_device *lan,
		    u8 lan_state, struct net_device *wan, bool lan_bound,
		    int family)
{
	struct net_device *devices[] = { &eth3, &eth4, &wlan, &vlan, &bridge, &ppp, &sit,
					 &ip6tnl };

	memset(s, 0, sizeof(*s));
	cur = s;
	s->ft.data.use_neigh = use_neigh;
	s->ft.hook_list.next = &s->hooks[0].list;
	s->hooks[0].list.next = &s->hooks[1].list;
	s->hooks[1].list.next = &s->ft.hook_list;
	s->hooks[0].ops.dev = &eth3;
	s->hooks[1].ops.dev = &eth4;
	s->lan_neigh.nud_state = lan_state;
	if (lan_state & NUD_VALID)
		memcpy(s->lan_neigh.ha, client_mac, ETH_ALEN);
	s->wan_neigh.nud_state = NUD_REACHABLE;
	memcpy(s->wan_neigh.ha, wan_mac, ETH_ALEN);
	s->outer_neigh = s->wan_neigh;
	s->lan_dst = (struct dst_entry){ .dev = lan, .refs = 1, .neigh = &s->lan_neigh };
	s->wan_dst = (struct dst_entry){ .dev = wan, .refs = 1, .neigh = &s->wan_neigh };
	s->outer4 = (struct rtable){
		.dst = { .dev = &eth4, .refs = 1, .neigh = &s->outer_neigh },
		.rt_type = RTN_UNICAST, .rt_gw_family = AF_INET,
		.rt_gw4 = htonl(0xc0000202),
	};
	s->outer6 = (struct rt6_info){
		.dst = { .dev = &eth4, .refs = 1, .neigh = &s->outer_neigh },
		.rt6i_flags = RTF_GATEWAY,
		.rt6i_gateway = { { { 0xfe, 0x80, [15] = 1 } } },
	};
	s->port = (struct net_bridge_port){ &bridge_priv, &eth3, true };
	s->fdb.dst = &s->port;
	memcpy(s->fdb.addr, client_mac, ETH_ALEN);
	bridge_priv = (struct net_bridge){ &bridge, &s->fdb };
	s->skb.dst = lan_bound ? &s->lan_dst : &s->wan_dst;
	reverse_dst = lan_bound ? &s->wan_dst : &s->lan_dst;
	s->pkt = (struct nft_pktinfo){ &s->skb, lan_bound ? wan : lan, family };
	for (size_t i = 0; i < ARRAY_SIZE(devices); i++)
		devices[i]->walks = 0;
}

/* The direction a packet to the LAN takes, given the routed packet's. */
static enum ip_conntrack_dir lan_dir(enum ip_conntrack_dir dir, bool lan_bound)
{
	return lan_bound ? dir : !dir;
}

static int route(struct setup *s, enum ip_conntrack_dir dir)
{
	return nft_flow_route(&s->pkt, &s->ct, &s->route, dir, &s->ft);
}

/* Takes dev's hook off the table's list, as a port that lost carrier leaves
 * a table that follows its ports. */
static void unlist(struct setup *s, const struct net_device *dev)
{
	struct list_head *prev = &s->ft.hook_list;

	while (prev->next != &s->ft.hook_list) {
		struct nft_hook *hook = container_of(prev->next, struct nft_hook, list);

		if (hook->ops.dev == dev) {
			prev->next = hook->list.next;
			return;
		}
		prev = prev->next;
	}
	assert(!"listed");
}

/* Neither direction recorded a port the table does not list. */
static void none_unlisted(const struct setup *s)
{
	assert(!s->route.tuple[0].in.unlisted_ifindex);
	assert(!s->route.tuple[1].in.unlisted_ifindex);
}

/* Everything the walk borrowed is back, and the route holds what it says. */
static void released(struct setup *s, int held)
{
	assert(s->lan_dst.refs == 1 + held && s->wan_dst.refs == 1 + held);
	assert(s->outer4.dst.refs == 1 && s->outer6.dst.refs == 1);
	assert(!s->lan_neigh.refs && !s->wan_neigh.refs && !s->outer_neigh.refs);
	assert(!s->lan_neigh.lock && !s->wan_neigh.lock && !s->outer_neigh.lock);
}

static void drop(struct setup *s)
{
	dst_release(s->route.tuple[0].dst);
	dst_release(s->route.tuple[1].dst);
	released(s, 0);
}

static const u8 unusable[] = { NUD_NONE, NUD_INCOMPLETE, NUD_FAILED };
static const u8 usable[] = { NUD_REACHABLE, NUD_STALE, NUD_PERMANENT };

/* A neighbour this walk cannot use yet, on a destination the walk descends
 * below, caches nothing: no flow is built on the logical device, both routes
 * go back, and the neighbour is asked to resolve. Missing altogether, there is
 * nothing to ask. */
static void lan_deferred(struct net_device *lan, u8 state, bool exists,
			 enum ip_conntrack_dir dir, bool lan_bound, int family)
{
	struct setup s;

	prepare(&s, true, lan, state, &eth4, lan_bound, family);
	if (!exists)
		s.lan_dst.neigh = NULL;
	assert(route(&s, dir) == -EAGAIN);
	released(&s, 0);
	assert(s.lan_neigh.kicks == (exists ? 1 : 0));
	assert(!lan->walks);
	/* A WAN-bound packet's own direction is walked first. */
	assert(eth4.walks == !lan_bound);
}

/* A resolved neighbour walks the whole path: the LAN direction's reply
 * arrives on the port, tagged where the destination is a VLAN, and both
 * directions keep neighbour output. */
static void lan_walked(struct net_device *lan, u8 state, enum ip_conntrack_dir dir,
		       bool lan_bound, int family)
{
	enum ip_conntrack_dir to_lan = lan_dir(dir, lan_bound);
	struct setup s;

	prepare(&s, true, lan, state, &eth4, lan_bound, family);
	assert(route(&s, dir) == 0);
	released(&s, 1);
	assert(!s.lan_neigh.kicks && lan->walks == 1 && eth4.walks == 1);
	assert(s.route.tuple[!to_lan].in.ifindex == (u32)eth3.ifindex);
	if (lan == &vlan) {
		assert(s.route.tuple[!to_lan].in.num_encaps == 1);
		assert(s.route.tuple[!to_lan].in.encap[0].id == 284);
		assert(s.route.tuple[!to_lan].in.encap[0].proto == htons(ETH_P_8021Q));
	} else {
		assert(s.route.tuple[!to_lan].in.num_encaps == 0);
	}
	assert(s.route.tuple[to_lan].in.ifindex == (u32)eth4.ifindex);
	assert(s.route.tuple[to_lan].in.num_encaps == 0);
	assert(s.route.tuple[0].xmit_type == FLOW_OFFLOAD_XMIT_NEIGH);
	assert(s.route.tuple[1].xmit_type == FLOW_OFFLOAD_XMIT_NEIGH);
	none_unlisted(&s);
	drop(&s);
}

static void neighbour_cases(enum ip_conntrack_dir dir, bool lan_bound, int nf)
{
	struct net_device *uppers[] = { &vlan, &bridge };

	for (size_t u = 0; u < ARRAY_SIZE(uppers); u++) {
		for (size_t i = 0; i < sizeof(unusable); i++)
			lan_deferred(uppers[u], unusable[i], true, dir, lan_bound, nf);
		lan_deferred(uppers[u], NUD_NONE, false, dir, lan_bound, nf);
		for (size_t i = 0; i < sizeof(usable); i++)
			lan_walked(uppers[u], usable[i], dir, lan_bound, nf);
	}
}

/* A tunnel whose outer next hop has not resolved -- as after the WAN link
 * flapped and flushed it -- caches nothing for any table, and asks for it:
 * a table with neighbour output would otherwise keep the tunnel device as the
 * reply's ingress, which no driver can redirect to, and any other refuses the
 * tunnel hop and lands on that same default path once the hop resolves. */
static void tunnel_cases(enum ip_conntrack_dir dir, bool lan_bound, int nf)
{
	struct net_device *tunnels[] = { &sit, &ip6tnl };
	u8 family[] = { AF_INET, AF_INET6 };

	for (size_t t = 0; t < ARRAY_SIZE(tunnels); t++) {
		struct net_device *tun = tunnels[t];
		enum ip_conntrack_dir to_lan = lan_dir(dir, lan_bound);
		struct setup s;

		for (int use_neigh = 0; use_neigh < 2; use_neigh++) {
			for (size_t i = 0; i <= sizeof(unusable); i++) {
				prepare(&s, use_neigh, &vlan, NUD_REACHABLE, tun,
					lan_bound, nf);
				if (i < sizeof(unusable))
					s.outer_neigh.nud_state = unusable[i];
				else
					s.outer4.dst.neigh = s.outer6.dst.neigh = NULL;
				assert(route(&s, dir) == -EAGAIN);
				released(&s, 0);
				assert(s.outer_neigh.kicks == (i < sizeof(unusable)));
				assert(tun->walks == 1);
			}

			/* Resolved, the walk crosses the tunnel to the port
			 * for a table with neighbour output, which records the
			 * hop whole; any other refuses the hop and keeps the
			 * tunnel device. */
			prepare(&s, use_neigh, &vlan, NUD_REACHABLE, tun, lan_bound, nf);
			assert(route(&s, dir) == 0);
			released(&s, 1);
			assert(!s.outer_neigh.kicks && tun->walks == 1);
			if (use_neigh) {
				assert(s.route.tuple[to_lan].in.ifindex == (u32)eth4.ifindex);
				assert(s.route.tuple[!to_lan].tunnel.lower_ifindex == eth4.ifindex);
				assert(s.route.tuple[!to_lan].tunnel.family == family[t]);
				assert(!memcmp(s.route.tuple[!to_lan].tunnel.h_dest, wan_mac,
					       ETH_ALEN));
			} else {
				assert(s.route.tuple[to_lan].in.ifindex == (u32)tun->ifindex);
				assert(!s.route.tuple[!to_lan].tunnel.lower_ifindex);
			}
			none_unlisted(&s);
			drop(&s);

			/* No outer route at all -- the WAN link down, or an
			 * outer transform that cannot be had -- is as much a
			 * hop not known yet: the transmit path cannot send the
			 * outer packet either. Nothing is cached, and there is
			 * no neighbour to ask for. */
			for (int how = 0; how < (tun == &ip6tnl ? 2 : 1); how++) {
				prepare(&s, use_neigh, &vlan, NUD_REACHABLE, tun,
					lan_bound, nf);
				if (tun == &sit)
					s.outer4_error = -ENETUNREACH;
				else if (!how)
					s.outer6.dst.error = -ENETUNREACH;
				else
					s.xfrm_error = true;
				assert(route(&s, dir) == -EAGAIN);
				released(&s, 0);
				assert(!s.outer_neigh.kicks && tun->walks == 1);
			}

			/* A reject route that carries no error of its own:
			 * IPv6 turns a unicast route through the loopback
			 * device, a common null route, into a reject route of
			 * type unicast, and that type's error is zero. It
			 * discards the outer packet all the same, so its flag
			 * alone defers the hop, as the failed lookups do. */
			if (tun != &ip6tnl)
				continue;
			prepare(&s, use_neigh, &vlan, NUD_REACHABLE, tun, lan_bound, nf);
			s.outer6.rt6i_flags = RTF_REJECT;
			assert(route(&s, dir) == -EAGAIN);
			released(&s, 0);
			assert(!s.outer_neigh.kicks && tun->walks == 1);
		}
	}
}

/* The client's FDB entry gone -- aged out under a neighbour still valid, or
 * flushed by a port flap -- leaves a bridge that cannot name the port. A table
 * with neighbour output waits for the bridge to learn it again rather than
 * cache br-lan as the reply's ingress; nothing is asked for, since the next
 * frame from the client teaches it. Any other table keeps the fallback. */
static void bridge_cases(enum ip_conntrack_dir dir, bool lan_bound, int nf)
{
	enum ip_conntrack_dir to_lan = lan_dir(dir, lan_bound);
	struct setup s;

	for (int use_neigh = 0; use_neigh < 2; use_neigh++) {
		prepare(&s, use_neigh, &bridge, NUD_REACHABLE, &eth4, lan_bound, nf);
		bridge_priv.fdb = NULL;
		if (use_neigh) {
			assert(route(&s, dir) == -EAGAIN);
			released(&s, 0);
		} else {
			assert(route(&s, dir) == 0);
			released(&s, 1);
			assert(s.route.tuple[!to_lan].in.ifindex == (u32)bridge.ifindex);
			drop(&s);
		}
		assert(bridge.walks == 1 && !s.lan_neigh.kicks);
	}

	/* An entry for the bridge's own address names no port: not a station
	 * still to be learned, so it falls back as before. */
	prepare(&s, true, &bridge, NUD_REACHABLE, &eth4, lan_bound, nf);
	s.fdb.dst = NULL;
	assert(route(&s, dir) == 0);
	assert(s.route.tuple[!to_lan].in.ifindex == (u32)bridge.ifindex);
	drop(&s);

	/* A port that is not forwarding still refuses the route outright for
	 * every table, its neighbour resolved or not. */
	for (int use_neigh = 0; use_neigh < 2; use_neigh++) {
		for (int state = 0; state < 2; state++) {
			prepare(&s, use_neigh, &bridge, state ? NUD_REACHABLE : NUD_NONE,
				&eth4, lan_bound, nf);
			s.port.forwarding = false;
			assert(route(&s, dir) == (use_neigh || state ? -EAGAIN : 0));
			if (use_neigh || state) {
				released(&s, 0);
			} else {
				assert(s.route.tuple[!to_lan].in.ifindex == (u32)bridge.ifindex);
				drop(&s);
			}
			assert(bridge.walks == state);
		}
	}
}

static void control_cases(enum ip_conntrack_dir dir, bool lan_bound, int nf)
{
	enum ip_conntrack_dir to_lan = lan_dir(dir, lan_bound);
	struct setup s;

	/* A port is its own path, so it is still the reply's ingress while its
	 * neighbour resolves: the flow is cached, and flow_offload_eth_dst()
	 * holds its rules back until then. */
	prepare(&s, true, &vlan, NUD_REACHABLE, &eth4, lan_bound, nf);
	s.wan_neigh.nud_state = NUD_INCOMPLETE;
	assert(route(&s, dir) == 0);
	released(&s, 1);
	assert(!s.wan_neigh.kicks && !eth4.walks && vlan.walks == 1);
	assert(s.route.tuple[to_lan].in.ifindex == (u32)eth4.ifindex);
	assert(s.route.tuple[!to_lan].in.ifindex == (u32)eth3.ifindex);
	drop(&s);

	/* A table without neighbour output keeps the upstream fallback: the
	 * reply's ingress is the VLAN device itself. */
	prepare(&s, false, &vlan, NUD_NONE, &eth4, lan_bound, nf);
	assert(route(&s, dir) == 0);
	released(&s, 1);
	assert(!s.lan_neigh.kicks && !vlan.walks && eth4.walks == 1);
	assert(s.route.tuple[!to_lan].in.ifindex == (u32)vlan.ifindex);
	assert(s.route.tuple[!to_lan].in.num_encaps == 0);
	/* Nothing walked, so no port was reached to record. */
	none_unlisted(&s);
	drop(&s);
	/* Resolved, it walks to the port as before. */
	prepare(&s, false, &vlan, NUD_REACHABLE, &eth4, lan_bound, nf);
	assert(route(&s, dir) == 0);
	assert(s.route.tuple[!to_lan].in.ifindex == (u32)eth3.ifindex);
	assert(s.route.tuple[!to_lan].in.encap[0].id == 284);
	drop(&s);

	/* A PPPoE destination has no neighbour of its own to wait for: the
	 * walk crosses the session to the WAN port whatever the WAN neighbour
	 * does. */
	prepare(&s, true, &vlan, NUD_REACHABLE, &ppp, lan_bound, nf);
	s.wan_neigh.nud_state = NUD_NONE;
	assert(route(&s, dir) == 0);
	released(&s, 1);
	assert(ppp.walks == 1 && !s.wan_neigh.kicks);
	assert(s.route.tuple[to_lan].in.ifindex == (u32)eth4.ifindex);
	assert(s.route.tuple[to_lan].in.encap[0].id == 7);
	assert(s.route.tuple[!to_lan].session.lower_ifindex == eth4.ifindex);
	drop(&s);
}

/* A walk that reaches a port the table does not list -- one that lost carrier,
 * before a table that follows its ports adds it back -- falls back for every
 * table: deferring would walk every packet for good past a port that never
 * joins, as the bridged Wi-Fi interface here never does. When the fallback
 * names a device above the port, the route records the port, so that the port
 * joining the table can retire the flow. A port destination names itself and
 * records nothing, and neither does a walk that ends on a listed port. */
static void unlisted_cases(enum ip_conntrack_dir dir, bool lan_bound, int nf)
{
	enum ip_conntrack_dir to_lan = lan_dir(dir, lan_bound);
	struct net_device *uppers[] = { &vlan, &bridge };
	struct net_device *tunnels[] = { &sit, &ip6tnl };
	struct setup s;

	for (int use_neigh = 0; use_neigh < 2; use_neigh++) {
		/* The client behind a VLAN or the bridge on eth3. */
		for (size_t u = 0; u < ARRAY_SIZE(uppers); u++) {
			prepare(&s, use_neigh, uppers[u], NUD_REACHABLE, &eth4,
				lan_bound, nf);
			unlist(&s, &eth3);
			assert(route(&s, dir) == 0);
			released(&s, 1);
			assert(uppers[u]->walks == 1 && eth4.walks == 1);
			assert(s.route.tuple[!to_lan].in.ifindex == (u32)uppers[u]->ifindex);
			assert(s.route.tuple[!to_lan].in.unlisted_ifindex == (u32)eth3.ifindex);
			assert(!s.route.tuple[!to_lan].in.num_encaps);
			assert(s.route.tuple[to_lan].in.ifindex == (u32)eth4.ifindex);
			assert(!s.route.tuple[to_lan].in.unlisted_ifindex);
			drop(&s);
		}

		/* The client on the bridged Wi-Fi interface. */
		prepare(&s, use_neigh, &bridge, NUD_REACHABLE, &eth4, lan_bound, nf);
		s.port.dev = &wlan;
		assert(route(&s, dir) == 0);
		released(&s, 1);
		assert(s.route.tuple[!to_lan].in.ifindex == (u32)bridge.ifindex);
		assert(s.route.tuple[!to_lan].in.unlisted_ifindex == (u32)wlan.ifindex);
		assert(!s.route.tuple[to_lan].in.unlisted_ifindex);
		drop(&s);

		/* The client on eth3 itself: the fallback is the walked path. */
		prepare(&s, use_neigh, &eth3, NUD_REACHABLE, &eth4, lan_bound, nf);
		unlist(&s, &eth3);
		assert(route(&s, dir) == 0);
		released(&s, 1);
		assert(eth3.walks == 1);
		assert(s.route.tuple[!to_lan].in.ifindex == (u32)eth3.ifindex);
		none_unlisted(&s);
		drop(&s);

		/* A PPPoE session over eth4: the session is not recorded
		 * either, as the walk's result is not taken. */
		prepare(&s, use_neigh, &vlan, NUD_REACHABLE, &ppp, lan_bound, nf);
		unlist(&s, &eth4);
		assert(route(&s, dir) == 0);
		released(&s, 1);
		assert(ppp.walks == 1);
		assert(s.route.tuple[to_lan].in.ifindex == (u32)ppp.ifindex);
		assert(s.route.tuple[to_lan].in.unlisted_ifindex == (u32)eth4.ifindex);
		assert(!s.route.tuple[to_lan].in.num_encaps);
		assert(!s.route.tuple[!to_lan].session.lower_ifindex);
		assert(s.route.tuple[!to_lan].in.ifindex == (u32)eth3.ifindex);
		assert(!s.route.tuple[!to_lan].in.unlisted_ifindex);
		drop(&s);

		/* A tunnel whose outer packet leaves by eth4. Only a table with
		 * neighbour output crosses the hop to reach the port at all;
		 * any other refuses it, which records nothing. */
		for (size_t t = 0; t < ARRAY_SIZE(tunnels); t++) {
			struct net_device *tun = tunnels[t];

			prepare(&s, use_neigh, &vlan, NUD_REACHABLE, tun, lan_bound, nf);
			unlist(&s, &eth4);
			assert(route(&s, dir) == 0);
			released(&s, 1);
			assert(tun->walks == 1);
			assert(s.route.tuple[to_lan].in.ifindex == (u32)tun->ifindex);
			assert(s.route.tuple[to_lan].in.unlisted_ifindex ==
			       (use_neigh ? (u32)eth4.ifindex : 0));
			assert(!s.route.tuple[!to_lan].tunnel.lower_ifindex);
			assert(!s.route.tuple[!to_lan].in.unlisted_ifindex);
			drop(&s);
		}
	}
}

int main(int argc, char **argv)
{
	static const struct {
		const char *name;
		void (*run)(enum ip_conntrack_dir, bool, int);
	} groups[] = {
		{ "neighbour", neighbour_cases },
		{ "tunnel", tunnel_cases },
		{ "bridge", bridge_cases },
		{ "controls", control_cases },
		{ "unlisted", unlisted_cases },
	};

	init_devices();
	for (size_t g = 0; g < ARRAY_SIZE(groups); g++) {
		if (argc > 1 && strcmp(argv[1], groups[g].name))
			continue;
		for (int family = 0; family < 2; family++)
			for (int dir = 0; dir < 2; dir++)
				for (int lan_bound = 0; lan_bound < 2; lan_bound++)
					groups[g].run(dir, lan_bound,
						      family ? NFPROTO_IPV6 : NFPROTO_IPV4);
		printf("flowtable forward-path %s checks passed\n", groups[g].name);
	}
	return 0;
}
