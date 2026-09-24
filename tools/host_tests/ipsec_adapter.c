/* The IPsec side of the adapter's decision logic, compiled from the adapter
 * against stubs for xfrm, the FIB and the SA backend.
 *
 * These are the questions a rig run answers slowly, once, and only for the
 * configuration the bench happens to be wired for: which transform covers a
 * direction, which SA a direction may name, what an xfrm_state translates to,
 * and which installed SA has to be followed when its peer moves. The datapath
 * below them stays stubbed -- nothing here encrypts anything -- but every
 * branch that decides is the adapter's own.
 *
 * Two of those are worth naming, because a hardware run cannot show either
 * cheaply. The reference discipline in ft_ipsec_resolve(): a matching policy
 * consumes the caller's reference to a borrowed destination, and getting it
 * wrong freed a destination the flowtable still used. And the ordering the SA
 * next-hop watch rests on: a watch is unlinked before its SA is queued for
 * retirement, so a re-resolution that still finds its watch knows the SA is
 * there to be rebuilt.
 */
#include <assert.h>
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

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define htons(x) ((__be16)__builtin_bswap16((uint16_t)(x)))
#else
#define htons(x) ((__be16)(x))
#endif

#define ETH_ALEN 6
#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_ESP 50
#define IPPROTO_TCP 6
#define UDP_ENCAP_ESPINUDP 2
#define EINVAL 22
#define EIO 5
#define ENOMEM 12
#define EOPNOTSUPP 95
#define EHOSTUNREACH 113
#define ENETUNREACH 101
#define XFRM_INF (~(u64)0)

struct in6_addr { u8 s6_addr[16]; };
struct in_addr { __be32 s_addr; };

union nf_inet_addr {
	u32 all[4];
	__be32 ip;
	__be32 ip6[4];
	struct in_addr in;
	struct in6_addr in6;
};

/* --- list.h, enough of it -------------------------------------------- */
struct list_head { struct list_head *next, *prev; };
#define LIST_HEAD_INIT(n) { &(n), &(n) }
#define LIST_HEAD(n) struct list_head n = LIST_HEAD_INIT(n)
static void list_add_tail(struct list_head *e, struct list_head *h)
{
	e->next = h; e->prev = h->prev; h->prev->next = e; h->prev = e;
}
static void list_del(struct list_head *e)
{
	e->prev->next = e->next; e->next->prev = e->prev;
	e->next = e->prev = e;
}
#define list_entry(ptr, type, member) \
	((type *)((char *)(ptr) - offsetof(type, member)))
#define list_for_each_entry(pos, head, member) \
	for (pos = list_entry((head)->next, __typeof__(*pos), member); \
	     &pos->member != (head); \
	     pos = list_entry(pos->member.next, __typeof__(*pos), member))
#define list_for_each_entry_safe(pos, n, head, member) \
	for (pos = list_entry((head)->next, __typeof__(*pos), member), \
	     n = list_entry(pos->member.next, __typeof__(*pos), member); \
	     &pos->member != (head); \
	     pos = n, n = list_entry(n->member.next, __typeof__(*pos), member))

#define list_first_entry_or_null(head, type, member) \
	((head)->next == (head) ? NULL : list_entry((head)->next, type, member))
static void list_move_tail(struct list_head *e, struct list_head *head)
{ list_del(e); list_add_tail(e, head); }

/* --- kernel bits ----------------------------------------------------- */
#define GFP_KERNEL 0
#define GFP_ATOMIC 1
static int fail_alloc_after = -1;
static unsigned allocation_calls;
static void *test_kzalloc(size_t size)
{
	allocation_calls++;
	if (fail_alloc_after == 0) return NULL;
	if (fail_alloc_after > 0) fail_alloc_after--;
	return calloc(1, size);
}
#define kzalloc(n, f) test_kzalloc(n)
#define kfree(p) free(p)
#define spin_lock_bh(l) ((void)(l))
#define spin_unlock_bh(l) ((void)(l))
#define spin_lock(l) ((void)(l))
#define spin_unlock(l) ((void)(l))
#define read_lock_bh(l) ((void)(l))
#define read_unlock_bh(l) ((void)(l))
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
#define THIS_MODULE NULL
#define netdev_info(dev, fmt, ...) ((void)(dev))
static unsigned warnings;
#define netdev_warn(dev, fmt, ...) do { (void)(dev); warnings++; } while (0)
#define pr_warn(...) ((void)0)
#define pr_err(...) ((void)0)
#define WARN_ON_ONCE(cond) ({ bool hit = !!(cond); assert(!hit); hit; })
#define xchg(p, value) ({ __typeof__(*(p)) old = *(p); *(p) = (value); old; })
#define ASSERT_RTNL() do { } while (0)
#define DEFINE_SPINLOCK(name) int name

typedef long long atomic64_t;
#define ATOMIC64_INIT(v) (v)
static void atomic64_inc(atomic64_t *v) { (*v)++; }
static void atomic64_inc_return_release(atomic64_t *v) { (*v)++; }
static atomic64_t ft_ipsec_genid;

static int ft_watch_lock;
static bool ether_addr_equal(const u8 *a, const u8 *b)
{
	return !memcmp(a, b, ETH_ALEN);
}
static void ether_addr_copy(u8 *dst, const u8 *src) { memcpy(dst, src, ETH_ALEN); }
static void eth_zero_addr(u8 *a) { memset(a, 0, ETH_ALEN); }
static bool is_zero_ether_addr(const u8 *a)
{
	static const u8 zero[ETH_ALEN];
	return !memcmp(a, zero, ETH_ALEN);
}

#define IS_ERR(p) ((unsigned long)(void *)(p) >= (unsigned long)-4095)
#define PTR_ERR(p) ((long)(p))
#define ERR_PTR(e) ((void *)(long)(e))

static unsigned slept;
static void msleep(unsigned ms) { (void)ms; slept++; }

static bool ipv6_prefix_equal(const void *a, const void *b, unsigned int len)
{
	const u8 *x = a, *y = b;
	unsigned int bytes = len / 8, bits = len & 7;

	if (memcmp(x, y, bytes))
		return false;
	return !bits || !((x[bytes] ^ y[bytes]) & (0xff << (8 - bits)));
}

/* --- devices --------------------------------------------------------- */
typedef u64 netdev_features_t;
#define NETIF_F_HW_ESP ((netdev_features_t)1 << 40)
struct xfrmdev_ops;
struct net_device {
	const char *name;
	int ifindex;
	unsigned int mtu;
	u8 dev_addr[ETH_ALEN];
	bool physical;
	unsigned refs;
	/* What the attachment writes: the ops, and the capability in all
	 * three feature sets, because the kernel recomputes features from
	 * them and drops a bit that is missing from any one. */
	const struct xfrmdev_ops *xfrmdev_ops;
	netdev_features_t features, hw_features, wanted_features;
};
static unsigned features_changes;
static void netdev_features_change(struct net_device *dev)
{
	(void)dev;
	features_changes++;
}
static unsigned dev_holds;
static void dev_hold(struct net_device *d) { d->refs++; dev_holds++; }
static void dev_put(struct net_device *d)
{
	assert(d->refs && dev_holds);
	d->refs--; dev_holds--;
}

/* --- neighbours ------------------------------------------------------ */
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

struct neigh_table { int key_len; };
static struct neigh_table arp_tbl = { .key_len = 4 };

struct neighbour {
	struct neigh_table *tbl;
	struct net_device *dev;
	u8 primary_key[16];
	u8 ha[ETH_ALEN];
	u8 nud_state;
	bool dead;
	int lock;
	unsigned refs;
};
static unsigned neigh_refs;
static unsigned neigh_probes;
static void neigh_release(struct neighbour *n)
{
	assert(n->refs && neigh_refs);
	n->refs--; neigh_refs--;
}
static int neigh_event_send(struct neighbour *n, void *skb)
{
	(void)skb; (void)n; neigh_probes++; return 0;
}

/* --- destinations and routes ----------------------------------------- */
struct dst_ops { u8 family; };
struct dst_entry {
	struct dst_ops *ops;
	struct net_device *dev;
	int error;
	struct xfrm_state *xfrm;
	struct dst_entry *child;
	int refs;
};
static struct xfrm_state *dst_xfrm(const struct dst_entry *d) { return d->xfrm; }
static struct dst_entry *xfrm_dst_child(const struct dst_entry *d) { return d->child; }
static struct dst_entry *xfrm_dst_path(struct dst_entry *d)
{
	while (d->xfrm) d = d->child;
	return d;
}
static void dst_hold(struct dst_entry *d) { d->refs++; }
/* Releases the whole chain, the way the kernel's does: a bundle holds the
 * destination it was built over, so dropping the bundle drops that too. */
static void dst_release(struct dst_entry *d)
{
	while (d) {
		struct dst_entry *child = d->child;

		assert(d->refs > 0);
		if (--d->refs)
			return;
		d = child;
	}
}

struct rtable { struct dst_entry dst; };
struct flowi4 { __be32 daddr, saddr; __be16 fl4_dport, fl4_sport; int flowi4_oif; };
struct flowi6 { struct in6_addr daddr, saddr; __be16 fl6_dport, fl6_sport; };
struct flowi {
	union { struct flowi4 ip4; struct flowi6 ip6; } u;
	u8 flowi_proto;
	int flowi_oif;
	int flowi_iif;
	u32 flowi_mark;
};

/* --- xfrm ------------------------------------------------------------ */
#define XFRM_MODE_TRANSPORT 0
#define XFRM_MODE_TUNNEL 1
#define XFRM_STATE_NOPMTUDISC 1
#define XFRM_STATE_ESN 128
#define XFRM_STATE_VALID 2
#define XFRM_STATE_DEAD 5
#define XFRM_DEV_OFFLOAD_UNSPECIFIED 0
#define XFRM_DEV_OFFLOAD_CRYPTO 1
#define XFRM_DEV_OFFLOAD_PACKET 2
#define XFRM_DEV_OFFLOAD_OUT 0
#define XFRM_DEV_OFFLOAD_IN 1
#define XFRM_DEV_OFFLOAD_FLAG_ACQ 1
#define XFRM_LOOKUP_KEEP_DST_REF 8

typedef union { __be32 a4; __be32 a6[4]; } xfrm_address_t;

struct xfrm_algo { u16 alg_key_len; char alg_key[128]; };
struct xfrm_algo_auth { u16 alg_key_len; char alg_key[128]; };
struct xfrm_algo_aead { u16 alg_key_len; char alg_key[128]; };
struct xfrm_encap_tmpl { u16 encap_type; __be16 encap_sport, encap_dport; };

struct xfrm_dev_offload {
	unsigned long offload_handle;
	struct net_device *dev;
	u8 type;
	u8 dir;
	u8 flags;
	bool software_policy;
};

struct xfrm_lifetime_cfg {
	u64 soft_byte_limit, hard_byte_limit;
	u64 soft_packet_limit, hard_packet_limit;
};

struct xfrm_selector { bool mismatch; };
struct xfrm_state {
	struct xfrm_selector sel;
	u32 if_id;
	struct { xfrm_address_t daddr; __be32 spi; u8 proto; } id;
	struct {
		xfrm_address_t saddr;
		u16 family;
		u8 mode;
		u8 aalgo, ealgo;
		u8 flags;
		u32 replay_window, reqid;
	} props;
	struct { u32 v; } mark;
	struct { u8 state; } km;
	struct xfrm_algo_auth *aalg;
	struct xfrm_algo *ealg;
	struct xfrm_algo_aead *aead;
	struct xfrm_encap_tmpl *encap;
	void *replay_esn;
	struct xfrm_lifetime_cfg lft;
	struct xfrm_dev_offload xso;
	u16 handle;
	unsigned refs;
};

#define XFRM_POLICY_FWD 2
#define XFRM_POLICY_TYPE_MAIN 0
#define XFRM_POLICY_ALLOW 0
#define XFRM_USERPOLICY_BLOCK 1
#define XFRM_MAX_DEPTH 6
#define IPSEC_PROTO_ANY 255
struct xfrm_tmpl {
	struct { xfrm_address_t daddr; __be32 spi; u8 proto; } id;
	xfrm_address_t saddr;
	u32 reqid, aalgos;
	u8 mode, encap_family;
	bool optional, allalgs;
};
struct sec_path {
	int len, verified_cnt;
	struct xfrm_state *xvec[XFRM_MAX_DEPTH];
};
static bool xfrm_state_kern(const struct xfrm_state *x) { (void)x; return false; }
static bool xfrm_id_proto_match(u8 proto, u8 userproto) { return proto == userproto || userproto == IPSEC_PROTO_ANY; }
static bool xfrm_selector_match(const struct xfrm_selector *s, const struct flowi *fl, u16 family)
{ (void)fl; (void)family; return !s->mismatch; }
static bool xfrm_state_addr_cmp(const struct xfrm_tmpl *t, const struct xfrm_state *x, u16 family)
{
	size_t size = family == AF_INET ? 4 : 16;
	return memcmp(&t->id.daddr, &x->id.daddr, size) || memcmp(&t->saddr, &x->props.saddr, size);
}
struct xfrm_policy {
	int lock;
	struct xfrm_dev_offload xdo;
	struct { struct list_head all; bool dead; } walk;
	struct { u32 m; } mark;
	int type, action, xfrm_nr;
	struct xfrm_tmpl xfrm_vec[XFRM_MAX_DEPTH];
	unsigned refs;
};
struct net {
	struct { struct list_head policy_all; int xfrm_policy_lock;
		int policy_default[3]; } xfrm;
};
static struct xfrm_policy *receiving_policy;
static int receiving_oif, receiving_family;
static struct flowi receiving_query;
static int receiving_error;
static struct xfrm_policy *xfrm_policy_lookup(struct net *net, const struct flowi *fl,
					    u16 family, int dir, int if_id)
{
	(void)net; (void)if_id;
	assert(dir == XFRM_POLICY_FWD);
	receiving_query = *fl;
	if (receiving_error)
		return ERR_PTR(receiving_error);
	if (!receiving_policy || family != receiving_family || fl->flowi_oif != receiving_oif)
		return NULL;
	receiving_policy->refs++;
	return receiving_policy;
}
static void xfrm_pol_put(struct xfrm_policy *pol) { assert(pol->refs); pol->refs--; }

static unsigned xfrm_state_refs;
static void xfrm_state_put(struct xfrm_state *x)
{
	assert(x->refs && xfrm_state_refs);
	x->refs--; xfrm_state_refs--;
}
/* The tunnel-reduced inner bound, which is all the adapter asks of it. */
static u16 xfrm_state_mtu(struct xfrm_state *x, unsigned int mtu)
{
	return (u16)(mtu - (x->props.mode == XFRM_MODE_TUNNEL ? 60 : 30));
}

/* The inbound half of a pair, as xfrm's own index answers it. */
static struct xfrm_state *paired_state;
/* The kernel's order is destination first, which is what makes the caller's
 * argument pair look inverted: an outbound SA's own source address is the
 * destination of the inbound half being asked for. */
static struct xfrm_state *xfrm_state_lookup_byaddr(void *net, u32 mark,
						   const xfrm_address_t *daddr,
						   const xfrm_address_t *saddr,
						   u8 proto, u16 family)
{
	(void)net; (void)mark; (void)proto; (void)family;
	if (!paired_state)
		return NULL;
	/* Mirrored endpoints: the question asked is "whose source is the peer
	 * this outbound SA sends to, and whose destination is us". */
	if (paired_state->id.daddr.a4 != daddr->a4 || paired_state->props.saddr.a4 != saddr->a4)
		return NULL;
	paired_state->refs++;
	xfrm_state_refs++;
	return paired_state;
}

/* What xfrm_lookup() should answer, keyed on the device the question named.
 *
 * One answer cannot serve a whole direction: it asks twice, once about what
 * it sends and once about what the far end sent, and those resolve through
 * different ports to different SAs. policy_error is a policy that matched and
 * resolved to nothing; no entry for an oif is no policy at all.
 */
static struct { int oif; struct dst_entry *bundle; } policy_answers[2];
static int policy_error;
static unsigned policy_lookups;

static void policy_answer(int oif, struct dst_entry *bundle)
{
	for (unsigned i = 0; i < 2; i++)
		if (!policy_answers[i].bundle || policy_answers[i].oif == oif) {
			policy_answers[i].oif = oif;
			policy_answers[i].bundle = bundle;
			return;
		}
	assert(0);
}

static struct dst_entry *xfrm_lookup(void *net, struct dst_entry *dst,
				     const struct flowi *fl, void *sk, int flags)
{
	(void)net; (void)sk;
	policy_lookups++;
	assert(flags & XFRM_LOOKUP_KEEP_DST_REF);
	if (policy_error)
		return ERR_PTR(policy_error);
	for (unsigned i = 0; i < 2; i++) {
		struct dst_entry *bundle = policy_answers[i].bundle;

		if (!bundle || policy_answers[i].oif != fl->flowi_oif)
			continue;
		/* xfrm_bundle_create() links the destination into the bundle
		 * and takes over the caller's reference to it. Modelling that
		 * transfer is the point: mismodelling it is what freed a
		 * destination the flowtable still used. */
		bundle->child = dst;
		bundle->refs++;
		return bundle;
	}
	return dst;			/* no policy: the plain destination */
}

static struct net init_net;

/* --- the SA backend -------------------------------------------------- */

/* An installed SA, as far as the adapter can see one: a handle, and the
 * framing the backend was last told to write. */
struct cdx_ipsec_sa {
	u16 handle;
	u8 dst_mac[ETH_ALEN];
	bool outbound;
	bool live;
};
static struct cdx_ipsec_sa sa_pool[4];
static unsigned sa_installed, sa_deleted;
static unsigned retirement_flows, retirement_barriers;
static int sa_add_error;
static int sa_next_hop_error;
static unsigned sa_next_hop_calls;

#include "ipsec_types.inc"

static bool cdx_ipsec_port_supported(struct net_device *dev);

static u16 cdx_ipsec_sa_handle(const struct cdx_ipsec_sa *sa)
{
	return sa ? sa->handle : 0;
}
static int cdx_ipsec_sa_add(const struct cdx_ipsec_sa_spec *spec,
			    struct xfrm_state *x, struct cdx_ipsec_sa **result)
{
	struct cdx_ipsec_sa *sa;

	(void)x;
	*result = NULL;
	/* The backend's own first check: a port the engine cannot serve is
	 * refused before anything is built. */
	if (!cdx_ipsec_port_supported(spec->dev))
		return -EOPNOTSUPP;
	if (sa_add_error)
		return sa_add_error;
	assert(sa_installed < sizeof(sa_pool) / sizeof(sa_pool[0]));
	sa = &sa_pool[sa_installed];
	sa->handle = (u16)(sa_installed + 1);
	sa->outbound = spec->dir == CDX_IPSEC_DIR_OUT;
	sa->live = true;
	ether_addr_copy(sa->dst_mac, spec->dst_mac);
	sa_installed++;
	*result = sa;
	return 0;
}
static void cdx_ipsec_sa_del(struct cdx_ipsec_sa **sa)
{
	if (!*sa)
		return;
	assert(!retirement_flows && !retirement_barriers);
	(*sa)->live = false;
	*sa = NULL;
	sa_deleted++;
}
static int cdx_ipsec_sa_set_next_hop(struct cdx_ipsec_sa *sa, const u8 *dst_mac)
{
	sa_next_hop_calls++;
	/* The invariant the watch design rests on: a rebuild is only ever
	 * handed an SA that is still installed. */
	assert(sa && sa->live && sa->outbound);
	if (sa_next_hop_error)
		return sa_next_hop_error;
	ether_addr_copy(sa->dst_mac, dst_mac);
	return 0;
}
static bool port_supported = true;
static bool cdx_ipsec_port_supported(struct net_device *dev)
{
	return dev && dev->physical && port_supported;
}

/* The control-plane transaction. The rebuild must hold it; the resolution
 * that precedes the rebuild must not. */
static int ft_transaction;
static void cdx_ft_begin(void) { assert(!ft_transaction); ft_transaction = 1; }
static void cdx_ft_end(void) { assert(ft_transaction); ft_transaction = 0; }

/* --- the rest of the adapter, stubbed -------------------------------- */
static unsigned retired_handles;
static void ft_ipsec_retire_sa(u16 handle) { if (handle) retired_handles++; }

/* Two work items, and which one was asked for matters: marking a watch must
 * not queue a teardown, and a teardown must not queue a rebuild. */
static int ft_ipsec_follow;
static int ft_ipsec_retire;
static unsigned works_scheduled, retires_scheduled;
static void schedule_work(int *work)
{
	if (work == &ft_ipsec_follow)
		works_scheduled++;
	else if (work == &ft_ipsec_retire)
		retires_scheduled++;
	else
		assert(0);
}
struct work_struct { int dummy; };

/* SAs whose state has gone and whose hardware is waiting to go with it. The
 * queue itself is not under test here; that its entries are only ever made
 * after the watch is unlinked is. */
struct ft_ipsec_retirement {
	struct list_head list;
	struct cdx_ipsec_sa *sa;
};
static LIST_HEAD(ft_ipsec_retired);
static LIST_HEAD(ft_ipsec_owned);
static DEFINE_SPINLOCK(ft_ipsec_retired_lock);

struct netlink_ext_ack { const char *_msg; };
/* The kernel's table, member for member, so that the adapter's own instance
 * of it compiles here and the attachment can be checked against it. */
struct sk_buff;
struct xfrmdev_ops {
	void *owner;
	int (*xdo_dev_state_add)(struct xfrm_state *x,
				 struct netlink_ext_ack *extack);
	void (*xdo_dev_state_delete)(struct xfrm_state *x);
	void (*xdo_dev_state_free)(struct xfrm_state *x);
	bool (*xdo_dev_offload_ok)(struct sk_buff *skb, struct xfrm_state *xs);
	int (*xdo_dev_policy_add)(struct xfrm_policy *x,
				  struct netlink_ext_ack *extack);
	void (*xdo_dev_policy_delete)(struct xfrm_policy *x);
	void (*xdo_dev_policy_free)(struct xfrm_policy *x);
};
#define NL_SET_ERR_MSG(extack, msg) do { \
	static const char __msg[] = msg; \
	struct netlink_ext_ack *__e = (extack); \
	if (__e) __e->_msg = __msg; \
} while (0)
#define NL_SET_ERR_MSG_WEAK(extack, msg) do { \
	static const char __msg[] = msg; \
	struct netlink_ext_ack *__e = (extack); \
	if (__e && !__e->_msg) __e->_msg = __msg; \
} while (0)

/* What the classifier callback borrowed for each direction. */
struct flow_cls_offload {
	struct dst_entry *nf_dst;
	struct dst_entry *nf_dst_reverse;
	const struct nf_conn { u32 mark; } *nf_ct;
	struct nf_flow_offload_handle { bool valid; } *nf_handle;
};
static atomic64_t ft_admission_invalidations, ft_ipsec_invalidations;
struct cdx_ft_entry {
	struct list_head list;
	struct { u16 sa_handle, in_sa_handle; } rule;
	struct nf_flow_offload_handle *handle;
};
static LIST_HEAD(ft_entries);
static int ft_remove(struct cdx_ft_entry *e)
{
	assert(ft_transaction && retirement_flows);
	retirement_flows--;
	list_del(&e->list);
	free(e);
	return 0;
}
static unsigned cdx_ft_pending(void) { assert(ft_transaction); return retirement_barriers; }
static int cdx_ft_recover(void)
{
	assert(ft_transaction && !retirement_flows);
	if (retirement_barriers) retirement_barriers--;
	return retirement_barriers ? -EIO : 0;
}
static void ft_handle_invalidate(struct nf_flow_offload_handle *h, atomic64_t *count)
{
	if (h->valid) { h->valid = false; (*count)++; }
}

/* The route the FIB should answer with, and the neighbour on it. */
static struct rtable *route_answer;
static int route_error;
static struct neighbour *route_neigh;
static unsigned route_lookups, route_puts;
static struct dst_ops v4_ops = { .family = AF_INET };

static struct rtable *ip_route_output_key(void *net, struct flowi4 *fl4)
{
	(void)net; (void)fl4;
	route_lookups++;
	if (route_error)
		return ERR_PTR(route_error);
	return route_answer;
}
static void ip_rt_put(struct rtable *rt) { (void)rt; route_puts++; }
static struct neighbour *dst_neigh_lookup(struct dst_entry *dst, const void *key)
{
	(void)dst; (void)key;
	if (!route_neigh)
		return NULL;
	route_neigh->refs++;
	neigh_refs++;
	return route_neigh;
}

#include "ipsec_production.inc"

/* --- the bench ------------------------------------------------------- */

static struct net_device WAN = { .name = "eth4", .ifindex = 4, .mtu = 1500,
				 .physical = true,
				 .dev_addr = { 2, 0, 0, 0, 0, 4 } };
static struct net_device LAN = { .name = "eth3", .ifindex = 3, .mtu = 1500,
				 .physical = true,
				 .dev_addr = { 2, 0, 0, 0, 0, 3 } };
static struct net_device SOFT = { .name = "gre0", .ifindex = 9, .mtu = 1400 };

static const u8 PEER_MAC[ETH_ALEN] = { 0x02, 0xaa, 0, 0, 0, 1 };
static const u8 MOVED_MAC[ETH_ALEN] = { 0x02, 0xbb, 0, 0, 0, 2 };

#define LOCAL_IP  0x0101a8c0	/* 192.168.1.1, network order on a little end */
#define PEER_IP   0x7a01a8c0	/* 192.168.1.122 */
#define V4_SLASH24 0x00ffffff	/* inet_make_mask(24) */

static struct neighbour peer_neigh = {
	.tbl = &arp_tbl, .dev = &WAN, .nud_state = NUD_REACHABLE,
	.primary_key = { 0xc0, 0xa8, 1, 122 },
	.ha = { 0x02, 0xaa, 0, 0, 0, 1 },
};
static struct rtable wan_route;

static struct xfrm_algo_auth auth_key = { .alg_key_len = 160 };
static struct xfrm_algo cipher_key = { .alg_key_len = 128 };

static struct xfrm_state *outbound_state(void)
{
	static struct xfrm_state x;

	memset(&x, 0, sizeof(x));
	x.id.daddr.a4 = PEER_IP;
	x.id.spi = 0x0a878e3e;
	x.id.proto = IPPROTO_ESP;
	x.props.saddr.a4 = LOCAL_IP;
	x.props.family = AF_INET;
	x.props.mode = XFRM_MODE_TUNNEL;
	x.props.aalgo = 2;
	x.props.ealgo = 12;
	x.km.state = XFRM_STATE_VALID;
	x.aalg = &auth_key;
	x.ealg = &cipher_key;
	x.lft.soft_byte_limit = XFRM_INF;
	x.lft.hard_byte_limit = XFRM_INF;
	x.lft.soft_packet_limit = XFRM_INF;
	x.lft.hard_packet_limit = XFRM_INF;
	x.xso.type = XFRM_DEV_OFFLOAD_PACKET;
	x.xso.dir = XFRM_DEV_OFFLOAD_OUT;
	x.xso.dev = &WAN;
	return &x;
}

static void bench_reset(void)
{
	init_net.xfrm.policy_all.next = init_net.xfrm.policy_all.prev = &init_net.xfrm.policy_all;
	memset(init_net.xfrm.policy_default, 0, sizeof(init_net.xfrm.policy_default));
	receiving_policy = NULL;
	receiving_error = 0;
	ft_admission_invalidations = 0;
	wan_route.dst.ops = &v4_ops;
	wan_route.dst.dev = &WAN;
	wan_route.dst.error = 0;
	route_answer = &wan_route;
	route_error = 0;
	route_neigh = &peer_neigh;
	route_lookups = route_puts = 0;
	peer_neigh.nud_state = NUD_REACHABLE;
	peer_neigh.dead = false;
	peer_neigh.dev = &WAN;
	peer_neigh.primary_key[3] = 122;
	ether_addr_copy(peer_neigh.ha, PEER_MAC);
	memset(policy_answers, 0, sizeof(policy_answers));
	policy_error = 0;
	policy_lookups = 0;
	paired_state = NULL;
	sa_add_error = 0;
	sa_next_hop_error = 0;
	sa_next_hop_calls = 0;
	works_scheduled = retires_scheduled = 0;
	retired_handles = 0;
	port_supported = true;
	WAN.xfrmdev_ops = NULL;
	WAN.features = WAN.hw_features = WAN.wanted_features = 0;
	features_changes = 0;
	slept = 0;
	neigh_probes = 0;
	auth_key.alg_key_len = 160;
	assert(neigh_refs == 0);
	assert(xfrm_state_refs == 0);
	assert(dev_holds == 0);
	assert(!ft_transaction);
}

/* Run the real worker so ordering and retry ownership are tested too. */
static void bench_drain_retirements(void)
{
	ft_ipsec_retire_work(NULL);
}

/* Drop every watch and every SA, so each group of cases starts level. */
static void bench_clear_sas(void)
{
	bench_drain_retirements();
	while (ft_ipsec_owned.next != &ft_ipsec_owned) {
		struct ft_ipsec_retirement *r = list_entry(ft_ipsec_owned.next, struct ft_ipsec_retirement, list);
		list_del(&r->list);
		kfree(r);
	}
	ft_ipsec_watch_flush();
	memset(sa_pool, 0, sizeof(sa_pool));
	sa_installed = 0;
	sa_deleted = 0;
	ft_ipsec_next_hop_updates = 0;
}

static void test_spec(void)
{
	struct cdx_ipsec_sa_spec spec;
	struct xfrm_state *x = outbound_state();
	/* xfrm hands the ports over in network order, and the pair is
	 * deliberately asymmetric so a swap shows too. */
	struct xfrm_encap_tmpl natt = { .encap_type = UDP_ENCAP_ESPINUDP,
					.encap_sport = htons(4500), .encap_dport = htons(61000) };
	struct netlink_ext_ack ack = { NULL };

	bench_reset();

	/* An ordinary outbound tunnel SA: endpoints, mode, algorithm
	 * identities and the resolved next hop all arrive. */
	assert(ft_ipsec_spec(x, &spec, &ack) == 0);
	assert(spec.dev == &WAN && spec.family == AF_INET);
	assert(spec.dir == CDX_IPSEC_DIR_OUT && spec.tunnel);
	assert(spec.src.ip == LOCAL_IP && spec.dst.ip == PEER_IP);
	assert(spec.auth.alg == 2 && spec.auth.bits == 160);
	assert(spec.crypt.alg == 12 && spec.crypt.bits == 128);
	assert(ether_addr_equal(spec.dst_mac, PEER_MAC));
	assert(spec.dev_mtu == 1500 && spec.mtu == 1440);
	/* Unlimited lifetimes arrive as zero rather than as XFRM_INF: the
	 * backend reads zero as "no limit", and would otherwise be given a
	 * byte count no SA reaches but every comparison still makes. */
	assert(spec.lft.hard_bytes == 0 && spec.lft.soft_packets == 0);
	/* DF is copied for an IPv4 outbound tunnel unless the state asked for
	 * no path-MTU discovery, which is asking for the opposite. */
	assert(spec.copy_df);
	x->props.flags |= XFRM_STATE_NOPMTUDISC;
	assert(ft_ipsec_spec(x, &spec, &ack) == 0 && !spec.copy_df);
	x->props.flags &= ~XFRM_STATE_NOPMTUDISC;

	/* NAT-T carries both ports, in the spec's network order, and only the
	 * encapsulation SEC knows. */
	x->encap = &natt;
	assert(ft_ipsec_spec(x, &spec, &ack) == 0);
	assert(spec.natt_sport == htons(4500) && spec.natt_dport == htons(61000));
	/* SEC builds the UDP header only on its tunnel arms: a transport SA
	 * asking for it would leave as bare ESP, so it is refused. */
	x->props.mode = XFRM_MODE_TRANSPORT;
	assert(ft_ipsec_spec(x, &spec, &ack) == -EOPNOTSUPP);
	x->props.mode = XFRM_MODE_TUNNEL;
	natt.encap_type = 0;
	assert(ft_ipsec_spec(x, &spec, &ack) == -EOPNOTSUPP);
	x->encap = NULL;

	/* A key wider than the SEC context can hold is refused rather than
	 * copied into it. */
	auth_key.alg_key_len = (CDX_IPSEC_KEY_MAX + 1) * 8;
	assert(ft_ipsec_spec(x, &spec, &ack) == -EINVAL);
	auth_key.alg_key_len = 160;

	/* An inbound SA is classified rather than transmitted, so it needs no
	 * next hop and never asks the FIB for one. */
	x->xso.dir = XFRM_DEV_OFFLOAD_IN;
	route_lookups = 0;
	assert(ft_ipsec_spec(x, &spec, &ack) == 0);
	assert(spec.dir == CDX_IPSEC_DIR_IN && route_lookups == 0);
	assert(is_zero_ether_addr(spec.dst_mac));
	x->xso.dir = XFRM_DEV_OFFLOAD_OUT;

	/* Transport mode keeps the SA's own reduced MTU and builds no outer
	 * header. */
	x->props.mode = XFRM_MODE_TRANSPORT;
	assert(ft_ipsec_spec(x, &spec, &ack) == 0);
	assert(!spec.tunnel && spec.mtu == 1470);
	x->props.mode = XFRM_MODE_TUNNEL;

	/* An outbound IPv6 SA has no resolver here yet, and one that cannot
	 * be addressed must be refused rather than installed blind. */
	x->props.family = AF_INET6;
	assert(ft_ipsec_spec(x, &spec, &ack) == -EOPNOTSUPP);
	x->props.family = AF_INET;
}

static void test_next_hop(void)
{
	struct cdx_ipsec_sa_spec spec;
	struct xfrm_state *x = outbound_state();
	struct netlink_ext_ack ack = { NULL };

	/* No route to the peer is a refusal: an outbound SA leaves SEC
	 * already addressed, so there is nothing to install without one. */
	bench_reset();
	route_error = -ENETUNREACH;
	assert(ft_ipsec_spec(x, &spec, &ack) == -ENETUNREACH);
	assert(route_lookups == 1 && route_puts == 0);

	/* A route leaving by another port is refused too. Packet offload
	 * binds a state to one device and the framing belongs to that device;
	 * accepting here would address a frame on a port it never leaves by. */
	bench_reset();
	x->xso.dev = &LAN;
	assert(ft_ipsec_spec(x, &spec, &ack) == -EOPNOTSUPP);
	assert(route_puts == 1);
	x->xso.dev = &WAN;

	/* A neighbour that has not answered is asked for and waited on, not
	 * refused outright -- a cold ARP cache is the normal state of a
	 * freshly booted gateway, and packet offload has no software path to
	 * wait in. */
	bench_reset();
	peer_neigh.nud_state = NUD_FAILED;
	assert(ft_ipsec_spec(x, &spec, &ack) == -EHOSTUNREACH);
	assert(neigh_probes > 1 && slept > 1 && neigh_refs == 0);

	/* A stale neighbour still names the address last confirmed, which is
	 * what the hardware should carry; Linux refreshes it in its own time. */
	bench_reset();
	peer_neigh.nud_state = NUD_STALE;
	assert(ft_ipsec_spec(x, &spec, &ack) == 0);
	assert(ether_addr_equal(spec.dst_mac, PEER_MAC) && slept == 0);

	/* No neighbour entry at all, with no reference left behind. */
	bench_reset();
	route_neigh = NULL;
	assert(ft_ipsec_spec(x, &spec, &ack) == -EHOSTUNREACH);
	assert(neigh_refs == 0 && route_puts == 1);
}

static void test_state_add(void)
{
	struct xfrm_state *x = outbound_state();
	struct netlink_ext_ack ack = { NULL };

	bench_reset();
	bench_clear_sas();

	/* Crypto offload leaves the stack building every ESP header, which is
	 * not what the classifier can steer. */
	x->xso.type = XFRM_DEV_OFFLOAD_CRYPTO;
	assert(ft_xdo_state_add(x, &ack) == -EOPNOTSUPP);
	assert(sa_installed == 0);
	x->xso.type = XFRM_DEV_OFFLOAD_PACKET;

	/* An acquire placeholder carries no keys and no SPI and arrives in
	 * atomic context. Accepting it without programming anything is what
	 * keeps the on-demand tunnel being negotiated alive. */
	x->xso.flags |= XFRM_DEV_OFFLOAD_FLAG_ACQ;
	assert(ft_xdo_state_add(x, &ack) == 0);
	assert(sa_installed == 0 && works_scheduled == 0);
	x->xso.flags &= ~XFRM_DEV_OFFLOAD_FLAG_ACQ;

	/* AH is not ESP, and the SEC descriptor builder speaks only ESP. */
	x->id.proto = IPPROTO_TCP;
	assert(ft_xdo_state_add(x, &ack) == -EOPNOTSUPP);
	x->id.proto = IPPROTO_ESP;

	for (int fail = 0; fail < 2; fail++) {
		fail_alloc_after = fail;
		assert(ft_xdo_state_add(x, &ack) == -ENOMEM);
		assert(!sa_installed && !x->xso.offload_handle);
		assert(ft_ipsec_owned.next == &ft_ipsec_owned);
	}
	fail_alloc_after = -1;

	/* The real thing: installed, the handle published both ways, and a
	 * watch taken so the peer can be followed. */
	assert(ft_xdo_state_add(x, &ack) == 0);
	assert(sa_installed == 1);
	assert(x->xso.offload_handle == (unsigned long)&sa_pool[0]);
	assert(x->handle == sa_pool[0].handle);
	assert(ether_addr_equal(sa_pool[0].dst_mac, PEER_MAC));

	/* Deleting retires the flows naming the handle -- while the handle
	 * still names this SA -- and queues the hardware teardown. */
	fail_alloc_after = 0;
	unsigned old_allocations = allocation_calls;
	ft_xdo_state_delete(x);
	assert(allocation_calls == old_allocations);
	fail_alloc_after = -1;
	assert(ft_ipsec_owned.next == &ft_ipsec_owned);
	assert(retired_handles == 1 && retires_scheduled == 1);
	assert(x->xso.offload_handle == 0);

	/* Model an admission that was not yet on the watch when deletion
	 * ran. The SA worker must discover it, remove it under the transaction,
	 * and complete deferred barriers before its handle can be reused. */
	struct nf_flow_offload_handle late_handle = { .valid = true };
	struct cdx_ft_entry *late = calloc(1, sizeof(*late));
	late->handle = &late_handle;
	late->rule.in_sa_handle = sa_pool[0].handle;
	list_add_tail(&late->list, &ft_entries);
	retirement_flows = 1;
	retirement_barriers = 3;
	unsigned slept_before = slept;
	bench_drain_retirements();
	assert(!late_handle.valid && !retirement_flows && !retirement_barriers);
	assert(slept == slept_before + 2 && sa_deleted == 1);

	/* A refused install leaves nothing behind: no SA, and no watch whose
	 * SA never existed. */
	bench_reset();
	bench_clear_sas();
	sa_add_error = -EIO;
	assert(ft_xdo_state_add(x, &ack) == -EIO);
	assert(sa_installed == 0);
	ft_ipsec_all_moved();
	assert(works_scheduled == 0);
	sa_add_error = 0;

	/* An inbound SA is installed without a watch: it is classified rather
	 * than transmitted, so it has no next hop that can move. */
	bench_reset();
	bench_clear_sas();
	x->xso.dir = XFRM_DEV_OFFLOAD_IN;
	assert(ft_xdo_state_add(x, &ack) == 0);
	ft_ipsec_all_moved();
	assert(works_scheduled == 0);
	x->xso.dir = XFRM_DEV_OFFLOAD_OUT;
	ft_xdo_state_delete(x);
	bench_clear_sas();
}

static void test_policy_add(void)
{
	struct xfrm_policy policy;
	struct netlink_ext_ack ack = { NULL };

	bench_reset();
	memset(&policy, 0, sizeof(policy));
	/* CDX needs nothing from a policy, but a packet-offloaded state paired
	 * with a software policy is never selected by xfrm_state_find(), so
	 * these exist only to make the pairing hold. */
	policy.xdo.type = XFRM_DEV_OFFLOAD_PACKET;
	policy.xdo.dev = &WAN;
	assert(ft_xdo_policy_add(&policy, &ack) == 0);
	assert(policy.xdo.software_policy);
	policy.xdo.dev = &SOFT;
	assert(ft_xdo_policy_add(&policy, &ack) == -EOPNOTSUPP);
	policy.xdo.dev = &WAN;
	policy.xdo.type = XFRM_DEV_OFFLOAD_CRYPTO;
	assert(ft_xdo_policy_add(&policy, &ack) == -EOPNOTSUPP);
}

/* The attachment, and what it does when there is no engine behind the port.
 *
 * A board whose device tree lacks the IPsec offline port or a SEC job ring
 * loads the module with cdx_ipsec_port_supported() false for every port,
 * and that predicate is the whole of what the adapter learns. What it must
 * then do is nothing: never attach the ops -- so the port never advertises
 * hardware ESP and strongSwan is never offered it -- and refuse a state or
 * policy that arrives regardless, leaving nothing behind.
 */
static void test_engine_unavailable(void)
{
	struct xfrm_state *x = outbound_state();
	struct xfrm_policy policy;
	struct netlink_ext_ack ack = { NULL };

	bench_reset();
	bench_clear_sas();
	port_supported = false;

	ft_ipsec_attach(&WAN);
	assert(!WAN.xfrmdev_ops);
	assert(!((WAN.features | WAN.hw_features | WAN.wanted_features) &
		 NETIF_F_HW_ESP));
	assert(features_changes == 0);

	/* Refused at admission too, should a state reach it by another
	 * door, and with no watch left for an SA that never existed. */
	assert(ft_xdo_state_add(x, &ack) == -EOPNOTSUPP);
	assert(sa_installed == 0);
	ft_ipsec_all_moved();
	assert(works_scheduled == 0);
	memset(&policy, 0, sizeof(policy));
	policy.xdo.type = XFRM_DEV_OFFLOAD_PACKET;
	policy.xdo.dev = &WAN;
	assert(ft_xdo_policy_add(&policy, &ack) == -EOPNOTSUPP);

	/* Detaching a port that was never attached is not a features event. */
	ft_ipsec_detach(&WAN);
	assert(features_changes == 0);

	/* With the engine there: attached once, the capability in all three
	 * feature sets, idempotent, and given back in full. */
	port_supported = true;
	ft_ipsec_attach(&WAN);
	assert(WAN.xfrmdev_ops == &ft_xfrmdev_ops);
	assert(WAN.features & WAN.hw_features & WAN.wanted_features &
	       NETIF_F_HW_ESP);
	assert(features_changes == 1);
	ft_ipsec_attach(&WAN);
	assert(features_changes == 1);
	ft_ipsec_detach(&WAN);
	assert(!WAN.xfrmdev_ops);
	assert(!((WAN.features | WAN.hw_features | WAN.wanted_features) &
		 NETIF_F_HW_ESP));
	assert(features_changes == 2);

	/* A port that is not CDX's at all is never attached either. */
	ft_ipsec_attach(&SOFT);
	assert(!SOFT.xfrmdev_ops && features_changes == 2);
}

static void test_offloaded(void)
{
	struct xfrm_state *x = outbound_state();
	struct dst_entry plain = { .ops = &v4_ops };
	struct dst_entry inner = { .ops = &v4_ops };
	struct dst_entry bundle = { .ops = &v4_ops, .xfrm = x, .child = &plain };
	struct dst_entry stacked = { .ops = &v4_ops, .xfrm = x, .child = &inner };

	bench_reset();
	x->xso.offload_handle = 1;

	/* A bundle of exactly one offloaded transform, on this port. */
	assert(ft_ipsec_offloaded(&bundle, &WAN) == x);
	x->km.state = XFRM_STATE_DEAD;
	assert(!ft_ipsec_offloaded(&bundle, &WAN));
	x->km.state = XFRM_STATE_VALID;

	/* Another port's SEC context is not this direction's to name. */
	assert(!ft_ipsec_offloaded(&bundle, &LAN));

	/* A state the stack is carrying in software. */
	x->xso.type = XFRM_DEV_OFFLOAD_CRYPTO;
	assert(!ft_ipsec_offloaded(&bundle, &WAN));
	x->xso.type = XFRM_DEV_OFFLOAD_PACKET;

	/* Installed as far as xfrm is concerned, with no hardware behind it. */
	x->xso.offload_handle = 0;
	assert(!ft_ipsec_offloaded(&bundle, &WAN));
	x->xso.offload_handle = 1;

	/* A plain destination names no transform. */
	assert(!ft_ipsec_offloaded(&plain, &WAN));

	/* Two transforms deep: nothing proves the opcode order a nested
	 * bundle needs, so it belongs in software whichever end asked. */
	inner.xfrm = x;
	assert(!ft_ipsec_offloaded(&stacked, &WAN));
	inner.xfrm = NULL;
}

static void test_paired_inbound(void)
{
	struct xfrm_state *out = outbound_state();
	struct xfrm_state in;
	u16 handle = 0xffff;

	bench_reset();

	/* No inbound half at all: the far end sends in the clear, which is
	 * unusual but legal, and the direction installs with no handle. */
	paired_state = NULL;
	assert(ft_ipsec_paired_inbound(out, &LAN, &handle, NULL));
	assert(handle == 0);

	/* The mirrored half, offloaded on the ingress port. */
	memset(&in, 0, sizeof(in));
	in.props.saddr.a4 = PEER_IP;
	in.id.daddr.a4 = LOCAL_IP;
	in.xso.type = XFRM_DEV_OFFLOAD_PACKET;
	in.xso.dir = XFRM_DEV_OFFLOAD_IN;
	in.xso.dev = &LAN;
	in.xso.offload_handle = (unsigned long)&sa_pool[0];
	sa_pool[0].handle = 7;
	in.km.state = XFRM_STATE_VALID;
	paired_state = &in;
	assert(ft_ipsec_paired_inbound(out, &LAN, &handle, NULL));
	assert(handle == 7);
	assert(xfrm_state_refs == 0);	/* the lookup's reference is given back */

	/* One that exists and cannot be named is a refusal, not an absence:
	 * its frames are decrypted before they could match this tuple, so an
	 * entry keyed on the physical port would be installed, counted, and
	 * never match a frame. */
	in.xso.type = XFRM_DEV_OFFLOAD_UNSPECIFIED;
	assert(!ft_ipsec_paired_inbound(out, &LAN, &handle, NULL));
	assert(handle == 0);
	in.xso.type = XFRM_DEV_OFFLOAD_PACKET;

	/* On another port, dead, or facing the wrong way is the same refusal. */
	in.xso.dev = &WAN;
	assert(!ft_ipsec_paired_inbound(out, &LAN, &handle, NULL));
	in.xso.dev = &LAN;
	in.km.state = XFRM_STATE_DEAD;
	assert(!ft_ipsec_paired_inbound(out, &LAN, &handle, NULL));
	in.km.state = XFRM_STATE_VALID;
	in.xso.dir = XFRM_DEV_OFFLOAD_OUT;
	assert(!ft_ipsec_paired_inbound(out, &LAN, &handle, NULL));

	assert(xfrm_state_refs == 0);
	paired_state = NULL;
	sa_pool[0].handle = 0;
}

static void test_resolve(void)
{
	struct xfrm_state *x = outbound_state();
	struct dst_entry plain = { .ops = &v4_ops, .refs = 1 };
	struct dst_entry bundle = { .ops = &v4_ops, .xfrm = x };
	struct flowi fl;
	u16 handle;

	bench_reset();
	memset(&fl, 0, sizeof(fl));
	fl.flowi_oif = WAN.ifindex;
	x->xso.offload_handle = (unsigned long)&sa_pool[0];
	sa_pool[0].handle = 5;

	/* No destination at all is not a refusal: a direction with nothing to
	 * ask about is a plain one. */
	assert(ft_ipsec_resolve(NULL, &fl, &WAN, NULL, &handle, NULL));
	assert(handle == 0);

	/* A carried transform must not preserve a policy that has since been
	 * removed. Resolve the current policy from its underlying route. */
	{
		struct dst_entry under = { .ops = &v4_ops, .refs = 1 };
		struct dst_entry carried = { .ops = &v4_ops, .xfrm = x,
					     .child = &under, .refs = 1 };

		assert(ft_ipsec_resolve(&carried, &fl, &WAN, NULL, &handle, NULL));
		assert(handle == 0 && policy_lookups == 1 && under.refs == 1);
		assert(carried.refs == 1);	/* borrowed, and given back */
	}

	/* No policy covers the tuple: an ordinary plain end, with the
	 * reference taken to ask handed back. */
	assert(ft_ipsec_resolve(&plain, &fl, &WAN, NULL, &handle, NULL));
	assert(handle == 0 && plain.refs == 1 && policy_lookups == 2);

	/* A policy resolving to an offloaded SA. The bundle takes over the
	 * caller's reference to the destination, and releasing the bundle has
	 * to leave the borrowed destination exactly as it was found. */
	policy_answer(WAN.ifindex, &bundle);
	bundle.refs = 0;
	assert(ft_ipsec_resolve(&plain, &fl, &WAN, NULL, &handle, NULL));
	assert(handle == 5);
	assert(plain.refs == 1 && bundle.refs == 0);

	/* A policy that matched and resolved to nothing usable is a refusal
	 * at the sending end. Installing past it would forward in hardware
	 * what the policy says to encrypt, and the policy would never get a
	 * say -- which is how fifty-nine packets went out in the clear. */
	memset(policy_answers, 0, sizeof(policy_answers));
	policy_error = -EINVAL;
	assert(!ft_ipsec_resolve(&plain, &fl, &WAN, NULL, &handle, NULL));
	assert(plain.refs == 1);

	/* The same answer at the receiving end is not a refusal: nothing has
	 * been decrypted, so nothing is arriving that this tuple could miss. */
	assert(ft_ipsec_resolve(&plain, &fl, &LAN, &LAN, &handle, NULL));
	policy_error = 0;

	/* A policy resolving to a transform the hardware cannot carry refuses
	 * the sending end for the same reason, and leaves the receiving end
	 * to install plain. */
	policy_answer(WAN.ifindex, &bundle);
	bundle.refs = 0;
	x->xso.type = XFRM_DEV_OFFLOAD_CRYPTO;
	assert(!ft_ipsec_resolve(&plain, &fl, &WAN, NULL, &handle, NULL));
	assert(plain.refs == 1 && bundle.refs == 0);
	bundle.refs = 0;
	assert(ft_ipsec_resolve(&plain, &fl, &LAN, &LAN, &handle, NULL));
	assert(handle == 0 && plain.refs == 1 && bundle.refs == 0);
	x->xso.type = XFRM_DEV_OFFLOAD_PACKET;
	sa_pool[0].handle = 0;
}

static void test_receiving_policy(void)
{
	struct flowi fl = { .flowi_oif = LAN.ifindex };
	struct xfrm_policy pol = {};
	const int families[] = { AF_INET, AF_INET6 };

	for (unsigned f = 0; f < sizeof(families) / sizeof(families[0]); f++) {
		bench_reset();
		receiving_family = families[f];
		receiving_oif = LAN.ifindex;
		assert(xfrm_flowtable_policy_check(&init_net, &fl, families[f], NULL));
		init_net.xfrm.policy_default[XFRM_POLICY_FWD] = XFRM_USERPOLICY_BLOCK;
		assert(!xfrm_flowtable_policy_check(&init_net, &fl, families[f], NULL));
		init_net.xfrm.policy_default[XFRM_POLICY_FWD] = 0;
		receiving_error = -ENOMEM;
		assert(!xfrm_flowtable_policy_check(&init_net, &fl, families[f], NULL));
		receiving_error = 0;
		memset(&pol, 0, sizeof(pol));
		receiving_policy = &pol;
		assert(xfrm_flowtable_policy_check(&init_net, &fl, families[f], NULL));
		pol.xfrm_nr = 1;
		assert(!xfrm_flowtable_policy_check(&init_net, &fl, families[f], NULL));
		pol.xfrm_vec[0].optional = true;
		assert(xfrm_flowtable_policy_check(&init_net, &fl, families[f], NULL));
		pol.xfrm_nr = XFRM_MAX_DEPTH;
		for (unsigned i = 0; i < XFRM_MAX_DEPTH; i++) pol.xfrm_vec[i].optional = true;
		assert(!xfrm_flowtable_policy_check(&init_net, &fl, families[f], NULL));
		pol.xfrm_nr = 0;
		pol.action = 1;
		assert(!xfrm_flowtable_policy_check(&init_net, &fl, families[f], NULL));
		pol.action = 0;
		pol.type = 1;
		assert(!xfrm_flowtable_policy_check(&init_net, &fl, families[f], NULL));
		assert(pol.refs == 0);
		/* A policy for a mark assigned later still excludes the fast path,
		 * even if this packet's present mark would not select it. */
		receiving_policy = NULL;
		pol.mark.m = 0xff;
		list_add_tail(&pol.walk.all, &init_net.xfrm.policy_all);
		assert(!xfrm_flowtable_policy_check(&init_net, &fl, families[f], NULL));
		pol.walk.dead = true;
		assert(xfrm_flowtable_policy_check(&init_net, &fl, families[f], NULL));
		list_del(&pol.walk.all);
	}
}

static void test_received_state_policy(void)
{
	const int families[] = { AF_INET, AF_INET6 };

	for (unsigned f = 0; f < sizeof(families) / sizeof(families[0]); f++) {
		struct flowi fl = { .flowi_oif = LAN.ifindex };
		struct xfrm_state x = { .km.state = XFRM_STATE_VALID,
			.props = { .mode = XFRM_MODE_TUNNEL, .reqid = 42 },
			.id = { .proto = IPPROTO_ESP, .spi = 123 } };
		struct xfrm_policy pol = { .xfrm_nr = 1 };

		bench_reset();
		receiving_family = families[f];
		receiving_oif = LAN.ifindex;
		assert(!xfrm_flowtable_policy_check(&init_net, &fl, families[f], &x));
		receiving_policy = &pol;
		pol.xfrm_vec[0] = (struct xfrm_tmpl){ .mode = XFRM_MODE_TUNNEL,
			.reqid = 42, .id.proto = IPPROTO_ESP, .allalgs = true };
		assert(xfrm_flowtable_policy_check(&init_net, &fl, families[f], &x));
		assert(!pol.refs);
		pol.action = 1;
		assert(!xfrm_flowtable_policy_check(&init_net, &fl, families[f], &x));
		pol.action = 0;
		pol.xfrm_vec[0].reqid++;
		assert(!xfrm_flowtable_policy_check(&init_net, &fl, families[f], &x));
		pol.xfrm_vec[0].reqid--;
		pol.xfrm_vec[0].id.spi = 456;
		assert(!xfrm_flowtable_policy_check(&init_net, &fl, families[f], &x));
		pol.xfrm_vec[0].id.spi = 123;
		x.sel.mismatch = true;
		assert(!xfrm_flowtable_policy_check(&init_net, &fl, families[f], &x));
		x.sel.mismatch = false;
		pol.xfrm_nr = 2;
		pol.xfrm_vec[1] = pol.xfrm_vec[0];
		assert(!xfrm_flowtable_policy_check(&init_net, &fl, families[f], &x));
		pol.xfrm_nr = 1;
		pol.mark.m = 0xff;
		list_add_tail(&pol.walk.all, &init_net.xfrm.policy_all);
		assert(!xfrm_flowtable_policy_check(&init_net, &fl, families[f], &x));
		list_del(&pol.walk.all);
		pol.mark.m = 0;
		assert(xfrm_flowtable_policy_check(&init_net, &fl, families[f], &x));
		x.km.state = XFRM_STATE_DEAD;
		assert(!xfrm_flowtable_policy_check(&init_net, &fl, families[f], &x));
		assert(!pol.refs);
	}
}

static void test_handle_and_flowi(void)
{
	struct xfrm_state *x = outbound_state();
	struct xfrm_state in, back;
	struct dst_entry forward = { .ops = &v4_ops, .refs = 1 };
	struct dst_entry reverse = { .ops = &v4_ops, .refs = 1 };
	struct dst_entry bundle = { .ops = &v4_ops, .xfrm = x };
	struct dst_entry back_bundle = { .ops = &v4_ops };
	struct cdx_ft_rule rule;
	struct flow_cls_offload cls;
	struct flowi fl;
	struct nf_conn ct = {};
	struct nf_flow_offload_handle handle = { .valid = true };
	struct xfrm_policy required = { .xfrm_nr = 1 };

	bench_reset();
	memset(&rule, 0, sizeof(rule));
	memset(&cls, 0, sizeof(cls));
	x->xso.offload_handle = (unsigned long)&sa_pool[0];
	sa_pool[0].handle = 5;
	rule.family = AF_INET;
	rule.proto = IPPROTO_TCP;
	rule.in = &LAN;
	rule.out = &WAN;
	rule.in_logical = &LAN;
	rule.out_logical = &WAN;
	rule.src.ip = 0x0201a8c0;
	rule.dst.ip = 0x0301a8c0;
	rule.new_src.ip = 0x0401a8c0;
	rule.new_dst.ip = 0x0501a8c0;
	rule.sport = 1000;
	rule.dport = 2000;
	rule.new_sport = 3000;
	rule.new_dport = 4000;

	/* Sending asks about the translated tuple, because that is what
	 * leaves the port and what a selector naming addresses compares
	 * against. */
	ft_ipsec_flowi(&rule, false, &WAN, &fl);
	assert(fl.u.ip4.saddr == rule.new_src.ip && fl.u.ip4.daddr == rule.new_dst.ip);
	assert(fl.u.ip4.fl4_sport == 3000 && fl.u.ip4.fl4_dport == 4000);
	assert(fl.flowi_oif == WAN.ifindex && fl.flowi_proto == IPPROTO_TCP);

	/* Receiving asks about the untranslated pair, inverted, because that
	 * is what the peer addressed. */
	ft_ipsec_flowi(&rule, true, &LAN, &fl);
	assert(fl.u.ip4.saddr == rule.dst.ip && fl.u.ip4.daddr == rule.src.ip);
	assert(fl.u.ip4.fl4_sport == 2000 && fl.u.ip4.fl4_dport == 1000);
	assert(fl.flowi_oif == LAN.ifindex);

	cls.nf_dst = &forward;
	cls.nf_dst_reverse = &reverse;
	cls.nf_ct = &ct;
	cls.nf_handle = &handle;

	/* One direction encrypted and the reverse plain: what a tunnel looks
	 * like from the direction that created the flow. Nothing covers the
	 * reversed tuple leaving the ingress port, which is a direction whose
	 * frames arrive in the clear rather than a refusal. */
	policy_answer(WAN.ifindex, &bundle);
	bundle.refs = 0;
	assert(ft_ipsec_handle(&cls, &rule, &WAN, &LAN));
	assert(rule.sa_handle == 5 && rule.in_sa_handle == 0);
	assert(forward.refs == 1 && reverse.refs == 1);

	/* A missing inbound half is NOT permission for plaintext. A receiving
	 * policy on the opposite logical egress refuses this whole generation. */
	receiving_policy = &required;
	receiving_family = AF_INET;
	receiving_oif = LAN.ifindex;
	assert(!ft_ipsec_handle(&cls, &rule, &WAN, &LAN));
	assert(!handle.valid && ft_admission_invalidations == 1 && !required.refs);
	assert(receiving_query.u.ip4.saddr == rule.new_dst.ip);
	assert(receiving_query.u.ip4.daddr == rule.new_src.ip);
	assert(receiving_query.u.ip4.fl4_sport == rule.new_dport);
	assert(receiving_query.u.ip4.fl4_dport == rule.new_sport);
	receiving_policy = NULL;
	handle.valid = true;

	/* Both halves offloaded.
	 *
	 * The receiving end's question resolves through the *ingress* port,
	 * and what it finds there is an outbound SA -- the one that would
	 * encrypt frames sent back along the same tunnel. The state that
	 * actually decrypted what arrived is that SA's inbound half, which is
	 * the mirrored pair xfrm's own index answers with. So the bench needs
	 * both, and neither is the flow's own tuple. */
	back = *x;
	back.props.saddr.a4++;
	back.id.daddr.a4++;
	back.xso.dev = &LAN;
	back.xso.offload_handle = (unsigned long)&sa_pool[2];
	sa_pool[2].handle = 11;
	back_bundle.ops = &v4_ops;
	back_bundle.xfrm = &back;
	policy_answer(LAN.ifindex, &back_bundle);

	memset(&in, 0, sizeof(in));
	in.props.saddr.a4 = back.id.daddr.a4;
	in.id.daddr.a4 = back.props.saddr.a4;
	in.xso.type = XFRM_DEV_OFFLOAD_PACKET;
	in.xso.dir = XFRM_DEV_OFFLOAD_IN;
	in.xso.dev = &LAN;
	in.xso.offload_handle = (unsigned long)&sa_pool[1];
	sa_pool[1].handle = 9;
	in.km.state = XFRM_STATE_VALID;
	paired_state = &in;
	bundle.refs = back_bundle.refs = 0;
	assert(ft_ipsec_handle(&cls, &rule, &WAN, &LAN));
	assert(rule.sa_handle == 5 && rule.in_sa_handle == 9);
	assert(forward.refs == 1 && reverse.refs == 1);

	/* An inbound SA that exists and cannot be named refuses the whole
	 * direction rather than installing an entry nothing will match: its
	 * frames are decrypted on the offline port before they could reach a
	 * rule keyed on the physical one. */
	in.xso.dev = &WAN;
	bundle.refs = back_bundle.refs = 0;
	assert(!ft_ipsec_handle(&cls, &rule, &WAN, &LAN));
	assert(forward.refs == 1 && reverse.refs == 1);

	paired_state = NULL;
	sa_pool[0].handle = sa_pool[1].handle = sa_pool[2].handle = 0;
}

/* Install one outbound SA and return the state that owns it.
 *
 * A fresh watch is published stale, to close the window the install's own
 * (possibly seconds-long) resolution leaves open. Drain that first pass here,
 * so each case starts from a settled watch and can say what its own event
 * caused. */
static struct xfrm_state *install_outbound(struct xfrm_state *x)
{
	struct netlink_ext_ack ack = { NULL };

	*x = *outbound_state();
	assert(ft_xdo_state_add(x, &ack) == 0);
	assert(works_scheduled == 1);
	ft_ipsec_follow_work(NULL);
	assert(sa_next_hop_calls == 0);	/* nothing has moved yet */
	works_scheduled = 0;
	return x;
}

static void test_watch_follows_peer(void)
{
	struct xfrm_state state;
	struct xfrm_state *x;
	struct neighbour other;

	bench_reset();
	bench_clear_sas();
	x = install_outbound(&state);
	assert(ether_addr_equal(sa_pool[0].dst_mac, PEER_MAC));

	/* An address that still matches is ordinary NUD ageing: the entry
	 * already carries it, so nothing is marked and nothing is rebuilt. */
	ft_ipsec_neigh_moved(&peer_neigh);
	assert(works_scheduled == 0);
	ft_ipsec_follow_work(NULL);
	assert(sa_next_hop_calls == 0);

	/* The peer moves. The notifier only marks -- it runs under neigh->lock
	 * and cannot take the control mutex -- and the work does the rebuild. */
	ether_addr_copy(peer_neigh.ha, MOVED_MAC);
	ft_ipsec_neigh_moved(&peer_neigh);
	assert(works_scheduled == 1 && sa_next_hop_calls == 0);
	ft_ipsec_follow_work(NULL);
	assert(sa_next_hop_calls == 1);
	assert(ether_addr_equal(sa_pool[0].dst_mac, MOVED_MAC));
	assert(ft_ipsec_next_hop_updates == 1);
	assert(dev_holds == 0 && neigh_refs == 0 && !ft_transaction);

	/* Running again settles: the watch now records what the hardware
	 * carries, so a second pass finds nothing to do. */
	ft_ipsec_follow_work(NULL);
	assert(sa_next_hop_calls == 1);

	/* A neighbour for another peer, or on another port, is not this SA's. */
	other = peer_neigh;
	other.primary_key[3] = 200;
	ether_addr_copy(other.ha, PEER_MAC);
	works_scheduled = 0;
	ft_ipsec_neigh_moved(&other);
	assert(works_scheduled == 0);
	other = peer_neigh;
	other.dev = &LAN;
	ether_addr_copy(other.ha, PEER_MAC);
	ft_ipsec_neigh_moved(&other);
	assert(works_scheduled == 0);

	ft_xdo_state_delete(x);
	bench_clear_sas();
}

static void test_watch_route_and_device(void)
{
	struct xfrm_state state;
	struct xfrm_state *x;
	__be32 peer = PEER_IP;
	__be32 elsewhere = 0x0100000a;	/* 10.0.0.1 */

	bench_reset();
	bench_clear_sas();
	x = install_outbound(&state);

	/* A route change under the peer marks the SA. Unlike a neighbour
	 * change there is nothing to compare at the notifier -- the answer is
	 * whatever the FIB now returns -- so the work re-resolves and drops
	 * the ones that did not move. */
	ft_ipsec_route_moved(AF_INET, &peer, V4_SLASH24, 24);
	assert(works_scheduled == 1);
	ft_ipsec_follow_work(NULL);
	assert(sa_next_hop_calls == 0);		/* the peer is where it was */

	/* The same event once the gateway's address really has changed. */
	ether_addr_copy(peer_neigh.ha, MOVED_MAC);
	ft_ipsec_route_moved(AF_INET, &peer, V4_SLASH24, 24);
	ft_ipsec_follow_work(NULL);
	assert(sa_next_hop_calls == 1);
	assert(ether_addr_equal(sa_pool[0].dst_mac, MOVED_MAC));

	/* A prefix that does not cover the peer is not this SA's business. */
	works_scheduled = 0;
	ft_ipsec_route_moved(AF_INET, &elsewhere, V4_SLASH24, 24);
	assert(works_scheduled == 0);

	/* An event that says only that routing changed marks everything. */
	ft_ipsec_all_moved();
	assert(works_scheduled == 1);
	ft_ipsec_follow_work(NULL);

	/* This port's own address is written into the same opcodes as the
	 * peer's, so changing it is the same silent defect — and unlike the
	 * flows on the port, which are retired and readmitted with the new
	 * address, nothing re-offers an SA. The encoder reads the port's
	 * address from its netdev, so a rebuild genuinely picks it up. */
	works_scheduled = 0;
	sa_next_hop_calls = 0;
	WAN.dev_addr[5] = 0x44;
	ft_ipsec_device_moved(&WAN);
	assert(works_scheduled == 1);
	ft_ipsec_follow_work(NULL);
	assert(sa_next_hop_calls == 1);

	/* On real hardware that rebuild fails the first time, because setting
	 * a port's address flushes its neighbour table and the peer is
	 * momentarily unresolvable. What brings it back is the neighbour
	 * returning — carrying the address it always had, so the watch has to
	 * retry on an *unchanged* neighbour when one is already waiting. */
	WAN.dev_addr[5] = 0x55;
	route_neigh = NULL;			/* the table was just flushed */
	ft_ipsec_device_moved(&WAN);
	ft_ipsec_follow_work(NULL);
	assert(sa_next_hop_calls == 1);		/* nothing to resolve against */
	route_neigh = &peer_neigh;		/* ARP answers again */
	works_scheduled = 0;
	ft_ipsec_neigh_moved(&peer_neigh);
	assert(works_scheduled == 1);
	ft_ipsec_follow_work(NULL);
	assert(sa_next_hop_calls == 2);

	/* And it settles: the watch records the address the port now has, so
	 * a second pass has nothing to do. */
	ft_ipsec_follow_work(NULL);
	assert(sa_next_hop_calls == 2);

	/* The port's egress queues changed under the SA -- an HTB tree came or
	 * went -- while neither address moved. That still takes a rebuild,
	 * which re-derives the queue the entry transmits on, and the watch
	 * settles after it like after any other. Another port's change is not
	 * this SA's business. */
	works_scheduled = 0;
	ft_ipsec_egress_changed(&LAN);
	assert(works_scheduled == 0);
	ft_ipsec_egress_changed(&WAN);
	assert(works_scheduled == 1);
	ft_ipsec_follow_work(NULL);
	assert(sa_next_hop_calls == 3);
	ft_ipsec_follow_work(NULL);
	assert(sa_next_hop_calls == 3);
	WAN.dev_addr[5] = 4;

	/* Another port's address change is not this SA's business. */
	works_scheduled = 0;
	ft_ipsec_device_moved(&LAN);
	assert(works_scheduled == 0);

	ft_xdo_state_delete(x);
	bench_clear_sas();
}

/* A neighbour that stops being usable must not be chased.
 *
 * It names nothing better to program, and marking it would be worse than
 * useless: the re-resolution probes what it finds, the probe fails, that
 * failure is itself a neighbour update, and the pair would keep each other
 * going for as long as the peer stayed down.
 */
static void test_watch_unreachable_peer(void)
{
	struct xfrm_state state;
	struct xfrm_state *x;

	bench_reset();
	bench_clear_sas();
	x = install_outbound(&state);
	ft_ipsec_follow_work(NULL);	/* drain the install's own mark */
	works_scheduled = 0;

	/* The peer goes away: incomplete, then failed, then evicted. None of
	 * them is a new address, so none is worth a rebuild or a probe. */
	peer_neigh.nud_state = NUD_INCOMPLETE;
	ft_ipsec_neigh_moved(&peer_neigh);
	peer_neigh.nud_state = NUD_FAILED;
	ft_ipsec_neigh_moved(&peer_neigh);
	peer_neigh.nud_state = NUD_REACHABLE;
	peer_neigh.dead = true;
	ft_ipsec_neigh_moved(&peer_neigh);
	assert(works_scheduled == 0);
	assert(neigh_probes == 0);

	/* And when it answers again from somewhere else, that is a real move. */
	peer_neigh.dead = false;
	ether_addr_copy(peer_neigh.ha, MOVED_MAC);
	ft_ipsec_neigh_moved(&peer_neigh);
	assert(works_scheduled == 1);
	ft_ipsec_follow_work(NULL);
	assert(ether_addr_equal(sa_pool[0].dst_mac, MOVED_MAC));

	ft_xdo_state_delete(x);
	bench_clear_sas();
}

static void test_watch_failures(void)
{
	struct xfrm_state state;
	struct xfrm_state *x;

	bench_reset();
	bench_clear_sas();
	x = install_outbound(&state);

	/* A peer that cannot be resolved right now leaves the SA on the
	 * address it has. There is nothing better to program and no fallback
	 * to degrade into, and the event that does resolve the peer brings
	 * the work straight back here. */
	ether_addr_copy(peer_neigh.ha, MOVED_MAC);
	ft_ipsec_neigh_moved(&peer_neigh);
	route_neigh = NULL;
	ft_ipsec_follow_work(NULL);
	assert(sa_next_hop_calls == 0);
	assert(ether_addr_equal(sa_pool[0].dst_mac, PEER_MAC));
	assert(dev_holds == 0 && neigh_refs == 0 && !ft_transaction);

	/* When it does resolve, the same watch is corrected. */
	route_neigh = &peer_neigh;
	ft_ipsec_neigh_moved(&peer_neigh);
	ft_ipsec_follow_work(NULL);
	assert(ether_addr_equal(sa_pool[0].dst_mac, MOVED_MAC));

	/* A rebuild the hardware refuses leaves the watch describing what the
	 * hardware actually has, so a later attempt tries again rather than
	 * believing the SA already moved. It is said out loud once, and the
	 * pass does not pick its own re-mark back up -- which is what would
	 * spin if it did. */
	ether_addr_copy(peer_neigh.ha, PEER_MAC);
	sa_next_hop_error = -EIO;
	warnings = 0;
	ft_ipsec_neigh_moved(&peer_neigh);
	ft_ipsec_follow_work(NULL);
	assert(sa_next_hop_calls == 2);
	assert(ft_ipsec_next_hop_updates == 1);	/* the failure counts nothing */
	assert(warnings == 1);

	/* A second failed pass says nothing more: one report per watch until
	 * something works again. */
	ft_ipsec_follow_work(NULL);
	assert(sa_next_hop_calls == 3 && warnings == 1);

	/* And when the hardware accepts it, the watch is corrected and its
	 * next failure is news again. */
	sa_next_hop_error = 0;
	ft_ipsec_follow_work(NULL);
	assert(sa_next_hop_calls == 4);
	assert(ether_addr_equal(sa_pool[0].dst_mac, PEER_MAC));
	sa_next_hop_error = -EIO;
	ether_addr_copy(peer_neigh.ha, MOVED_MAC);
	ft_ipsec_neigh_moved(&peer_neigh);
	ft_ipsec_follow_work(NULL);
	assert(warnings == 2);
	sa_next_hop_error = 0;

	ft_xdo_state_delete(x);
	bench_clear_sas();
}

static void test_watch_delete_ordering(void)
{
	struct xfrm_state state;
	struct xfrm_state *x;

	bench_reset();
	bench_clear_sas();
	x = install_outbound(&state);

	/* The ordering the whole design rests on. A state deleted while a
	 * re-resolution is outstanding unlinks its watch before it queues the
	 * retirement that frees the SA, so the work finds no watch for its
	 * cookie and never hands a freed SA to the backend. Without it the
	 * assertion inside the backend stub fires. */
	ether_addr_copy(peer_neigh.ha, MOVED_MAC);
	ft_ipsec_neigh_moved(&peer_neigh);
	ft_xdo_state_delete(x);
	bench_drain_retirements();
	assert(sa_deleted == 1 && !sa_pool[0].live);
	ft_ipsec_follow_work(NULL);
	assert(sa_next_hop_calls == 0);

	/* And nothing is watching an SA that is gone. */
	works_scheduled = 0;
	ft_ipsec_all_moved();
	assert(works_scheduled == 0);
	bench_clear_sas();
}

int main(void)
{
	test_spec();
	test_next_hop();
	test_state_add();
	test_policy_add();
	test_engine_unavailable();
	test_offloaded();
	test_paired_inbound();
	test_resolve();
	test_receiving_policy();
	test_received_state_policy();
	test_handle_and_flowi();
	test_watch_follows_peer();
	test_watch_route_and_device();
	test_watch_unreachable_peer();
	test_watch_failures();
	test_watch_delete_ordering();
	assert(dev_holds == 0 && neigh_refs == 0 && xfrm_state_refs == 0);
	printf("ipsec adapter: ok\n");
	return 0;
}
