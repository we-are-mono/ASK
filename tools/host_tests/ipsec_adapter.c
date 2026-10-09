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
#include <stdarg.h>
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
typedef int64_t s64;
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
#define IPPROTO_AH 51
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define UDP_ENCAP_ESPINUDP 2
#define EINVAL 22
#define EIO 5
#define EBUSY 16
#define ENOMEM 12
#define EOPNOTSUPP 95
#define EHOSTUNREACH 113
#define ENETUNREACH 101
#define EADDRNOTAVAIL 99
#define EPERM 1
#define EAFNOSUPPORT 97
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
static bool nf_inet_addr_cmp(const union nf_inet_addr *a, const union nf_inet_addr *b)
{
	return !memcmp(a->all, b->all, sizeof(a->all));
}

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
#define list_for_each_entry_reverse(pos, head, member) \
	for (pos = list_entry((head)->prev, __typeof__(*pos), member); \
	     &pos->member != (head); \
	     pos = list_entry(pos->member.prev, __typeof__(*pos), member))
#define list_for_each_entry_safe(pos, n, head, member) \
	for (pos = list_entry((head)->next, __typeof__(*pos), member), \
	     n = list_entry(pos->member.next, __typeof__(*pos), member); \
	     &pos->member != (head); \
	     pos = n, n = list_entry(n->member.next, __typeof__(*pos), member))

#define list_first_entry_or_null(head, type, member) \
	((head)->next == (head) ? NULL : list_entry((head)->next, type, member))
#define list_first_entry(head, type, member) list_entry((head)->next, type, member)
static bool list_empty(const struct list_head *h) { return h->next == h; }
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
/* A spinlock is a flag here, so a case can ask which are held: the
 * accounting pass has an order to keep between two of them, and xfrm's
 * lifetime judge wants x->lock. Taking one twice is a deadlock on hardware
 * and an assertion here. */
static void test_lock(int *lock) { assert(!*lock); *lock = 1; }
static void test_unlock(int *lock) { assert(*lock); *lock = 0; }
#define spin_lock_bh(l) test_lock(l)
#define spin_unlock_bh(l) test_unlock(l)
#define spin_lock(l) test_lock(l)
#define spin_unlock(l) test_unlock(l)
#define HZ 100
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
/* Functions rather than macros over snprintf: the kernel's u64 is unsigned
 * long long and this host's is unsigned long, one size, which the format
 * checker would object to at every call. */
static int scnprintf(char *buf, size_t size, const char *fmt, ...)
{
	va_list ap;
	int n;

	if (!size)
		return 0;
	va_start(ap, fmt);
	n = vsnprintf(buf, size, fmt, ap);
	va_end(ap);
	if (n < 0)
		return 0;
	return (size_t)n < size ? n : (int)(size - 1);
}
/* The adapter's one line about the frames SEC could not process, kept so a
 * case can read back what it said, and how often. */
static unsigned sec_fault_lines;
static char sec_fault_line[512];
static void pr_warn_ratelimited(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(sec_fault_line, sizeof(sec_fault_line), fmt, ap);
	va_end(ap);
	sec_fault_lines++;
}
/* /proc/cdx_flowtable, as far as the rows a case reads. */
struct seq_file { char buf[4096]; size_t len; };
static void seq_printf(struct seq_file *seq, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	seq->len += vsnprintf(seq->buf + seq->len, sizeof(seq->buf) - seq->len, fmt, ap);
	va_end(ap);
	assert(seq->len < sizeof(seq->buf));
}
#define WARN_ON_ONCE(cond) ({ bool hit = !!(cond); assert(!hit); hit; })
#define xchg(p, value) ({ __typeof__(*(p)) old = *(p); *(p) = (value); old; })
#define ASSERT_RTNL() do { } while (0)
#define DEFINE_SPINLOCK(name) int name

typedef long long atomic64_t;
#define ATOMIC64_INIT(v) (v)
static void atomic64_inc(atomic64_t *v) { (*v)++; }
static void atomic64_inc_return_release(atomic64_t *v) { (*v)++; }
static atomic64_t atomic64_inc_return(atomic64_t *v) { return ++*v; }
static atomic64_t atomic64_read(const atomic64_t *v) { return *v; }
static atomic64_t atomic64_read_acquire(const atomic64_t *v) { return *v; }
static atomic64_t ft_ipsec_genid;
typedef int atomic_t;
#define ATOMIC_INIT(v) (v)
static void atomic_inc(atomic_t *v) { (*v)++; }
static void atomic_dec(atomic_t *v) { assert(*v > 0); (*v)--; }
static int atomic_read(const atomic_t *v) { return *v; }

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
#define ERR_CAST(p) ((void *)(p))

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
static struct neigh_table nd_tbl = { .key_len = 16 };
static bool ipv6_addr_equal(const struct in6_addr *a, const struct in6_addr *b)
{
	return !memcmp(a, b, sizeof(*a));
}

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
/* A peer that answers the probe itself, before the prober has looked again:
 * its entry turns usable and the notifier runs, as ARP would have it. */
static bool probe_answers;
static void ft_ipsec_neigh_moved(struct neighbour *neigh);
static int neigh_event_send(struct neighbour *n, void *skb)
{
	(void)skb;
	neigh_probes++;
	if (probe_answers) {
		n->nud_state = NUD_REACHABLE;
		ft_ipsec_neigh_moved(n);
	}
	return 0;
}

/* --- destinations and routes ----------------------------------------- */
struct dst_ops { u8 family; };
#define DST_NOXFRM 0x0002
struct dst_entry {
	struct dst_ops *ops;
	struct net_device *dev;
	int error;
	struct xfrm_state *xfrm;
	struct dst_entry *child;
	int refs;
	unsigned short flags;
	/* The route's own MTU -- a learned PMTU or its metric -- or zero for
	 * its device's, as dst_mtu() answers. */
	unsigned mtu;
};
static u32 dst_mtu(const struct dst_entry *d)
{
	if (d->mtu)
		return d->mtu;
	return d->dev ? d->dev->mtu : 1500;	/* an Ethernet port's */
}
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
struct flowi4 {
	__be32 daddr, saddr;
	__be16 fl4_dport, fl4_sport;
	int flowi4_oif;
	u32 flowi4_mark;
	int flowi4_l3mdev;
	u8 flowi4_proto;
};
struct flowi6 {
	struct in6_addr daddr, saddr;
	__be16 fl6_dport, fl6_sport;
	u32 flowi6_mark;
	int flowi6_l3mdev;
	u8 flowi6_proto;
};
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
#define XFRM_STATE_NOECN 1
#define XFRM_STATE_DECAP_DSCP 2
#define XFRM_STATE_NOPMTUDISC 4
#define XFRM_STATE_ESN 128
#define XFRM_SA_XFLAG_DONT_ENCAP_DSCP 1
#define XFRM_STATE_VOID 0
#define XFRM_STATE_VALID 2
#define XFRM_STATE_EXPIRED 4
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
struct xfrm_algo_auth { u16 alg_key_len; unsigned int alg_trunc_len; char alg_key[128]; };
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
typedef long long time64_t;
struct xfrm_lifetime_cur {
	u64 bytes, packets;
	time64_t add_time, use_time;
};
/* The two shapes xfrm keeps a sequence space in: the legacy one, and the one
 * ESN -- or a window wider than 32 -- needs, member for member. */
struct xfrm_replay_state { u32 oseq, seq, bitmap; };
struct xfrm_replay_state_esn {
	unsigned int bmp_len;
	u32 oseq, seq, oseq_hi, seq_hi, replay_window;
	u32 bmp[];
};
#define U8_MAX ((u8)~0U)
#define U32_MAX ((u32)~0U)
#define U64_MAX ((u64)~0ULL)
#define lower_32_bits(n) ((u32)(n))
#define upper_32_bits(n) ((u32)((u64)(n) >> 32))

/* ESP's transform, as far as its geometry goes: what crypto_aead_blocksize()
 * and crypto_aead_authsize() answer for it. */
struct crypto_aead { unsigned int blocksize, authsize; };
static unsigned int crypto_aead_blocksize(struct crypto_aead *aead) { return aead->blocksize; }
static unsigned int crypto_aead_authsize(struct crypto_aead *aead) { return aead->authsize; }
struct xfrm_type { u8 proto; };
struct iphdr { u8 bytes[20]; };
struct ipv6hdr { u8 bytes[40]; };
#define XFRM_MODE_BEET 4
#define ALIGN(x, a) (((x) + (a) - 1) & ~((a) - 1))

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
		u32 extra_flags;
		u32 replay_window, reqid;
		struct { u32 v, m; } smark;
		int header_len;
	} props;
	const struct xfrm_type *type;
	void *data;
	struct { u32 v, m; } mark;
	struct { u8 state; u8 dying; } km;
	u8 repl_mode;
	struct { u32 replay_window, replay, integrity_failed; } stats;
	int lock;
	int mtimer;
	struct xfrm_algo_auth *aalg;
	struct xfrm_algo *ealg;
	struct xfrm_algo_aead *aead;
	struct xfrm_encap_tmpl *encap;
	struct xfrm_replay_state replay;
	struct xfrm_replay_state_esn *replay_esn;
	struct xfrm_lifetime_cfg lft;
	struct xfrm_lifetime_cur curlft;
	struct xfrm_dev_offload xso;
	u16 handle;
	unsigned refs;
};

#define XFRM_POLICY_OUT 1
#define XFRM_POLICY_FWD 2
#define XFRM_POLICY_MAX 3
/* A policy's direction is the low three bits of its index, and a socket's
 * own policy is filed under XFRM_POLICY_MAX plus its direction. */
static inline int xfrm_policy_id2dir(u32 index) { return index & 7; }
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
	u32 index;
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
static void xfrm_state_hold(struct xfrm_state *x)
{
	x->refs++; xfrm_state_refs++;
}
static void xfrm_state_put(struct xfrm_state *x)
{
	assert(x->refs && xfrm_state_refs);
	x->refs--; xfrm_state_refs--;
}

/* What xfrm's own replay code reaches, for the copy of it compiled in below
 * as the oracle for bit orientation. Nothing here audits or notifies. */
enum { XFRM_REPLAY_MODE_LEGACY, XFRM_REPLAY_MODE_BMP, XFRM_REPLAY_MODE_ESN };
#define XFRM_REPLAY_UPDATE 1
struct sk_buff;
static void xfrm_audit_state_replay(struct xfrm_state *x, struct sk_buff *skb,
				    __be32 net_seq)
{ (void)x; (void)skb; (void)net_seq; }
static void *xs_net(struct xfrm_state *x) { (void)x; return NULL; }
static bool xfrm_aevent_is_on(void *net) { (void)net; return false; }
static void xfrm_replay_notify(struct xfrm_state *x, int event) { (void)x; (void)event; }
static void xfrm_dev_state_advance_esn(struct xfrm_state *x) { (void)x; }
#define min_t(type, a, b) ((type)(a) < (type)(b) ? (type)(a) : (type)(b))
#define min(a, b) ((a) < (b) ? (a) : (b))
#define likely(x) (x)
#define unlikely(x) (x)
static u32 ntohl(__be32 v)
{
	return __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ ? __builtin_bswap32(v) : v;
}
static __be32 htonl(u32 v) { return ntohl(v); }

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
/* An OUT block whose selector names one IPv4 source, refused on any device;
 * zero is none. And the IPv4 questions asked, in order. */
static __be32 policy_block_saddr;
#define POLICY_QUERIES 8u
static struct flowi policy_queries[POLICY_QUERIES];

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
	if (policy_lookups < POLICY_QUERIES)
		policy_queries[policy_lookups] = *fl;
	policy_lookups++;
	assert(flags & XFRM_LOOKUP_KEEP_DST_REF);
	if (policy_error)
		return ERR_PTR(policy_error);
	if (policy_block_saddr && fl->u.ip4.saddr == policy_block_saddr)
		return ERR_PTR(-EPERM);
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

/* Whether output policy asks for no transform at all. A lookup that resolved
 * nothing can still mean a template is there -- an optional one whose SA does
 * not exist yet -- and that direction must not go to hardware plain. */
static bool out_template_unresolved;
static unsigned out_plain_asks;
static bool xfrm_flowtable_out_plain(struct net *net, const struct flowi *fl, u16 family)
{
	(void)net; (void)fl; (void)family;
	out_plain_asks++;
	return !out_template_unresolved;
}

static struct net init_net;

/* --- the SA backend -------------------------------------------------- */

/* An installed SA, as far as the adapter can see one: a handle, the framing
 * the backend was last told to write, and what SEC has counted on it. */
struct cdx_ipsec_sa {
	u16 handle;
	u8 dst_mac[ETH_ALEN];
	bool outbound;
	bool live;
	u64 packets, bytes, oseq;
	/* An inbound SA's window, as SEC's scorecard has it. */
	u64 seq;
	u32 seen[4];
	/* The path MTU its entry fragments SEC's output to. */
	u16 path_mtu;
};
static struct cdx_ipsec_sa sa_pool[8];
static unsigned sa_installed, sa_deleted;
static unsigned retirement_flows, retirement_barriers;
static int sa_add_error;
static const char *sa_add_message;
static int sa_next_hop_error;
static unsigned sa_next_hop_calls;

/* The clock a retired SA's record ages by, which a case moves on. */
static unsigned long jiffies = 100000;
/* The queue an add waits on for a retirement in its way. */
#define DECLARE_WAIT_QUEUE_HEAD(name) int name
#define time_before(a, b) ((long)((a) - (b)) < 0)
#define max(a, b) ((a) > (b) ? (a) : (b))
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define memzero_explicit(p, n) memset((p), 0, (n))
/* The digest's key, which the adapter must draw before its first digest, and
 * a keyed hash standing in for SipHash: the cases need equal keys to digest
 * equal and different ones not to. */
typedef struct { u64 key[2]; } siphash_key_t;
static bool digest_keyed;
static void get_random_once(void *buf, size_t len)
{
	if (!digest_keyed)
		memset(buf, 0x5a, len);
	digest_keyed = true;
}
static u64 siphash(const void *data, size_t len, const siphash_key_t *key)
{
	const u8 *p = data;
	u64 h = 0xcbf29ce484222325ULL ^ key->key[0] ^ (key->key[1] << 1);

	assert(digest_keyed);
	for (size_t i = 0; i < len; i++)
		h = (h ^ p[i]) * 0x100000001b3ULL;
	return h;
}

#include "ipsec_types.inc"

static bool cdx_ipsec_port_supported(struct net_device *dev);
static struct net_device *egress_change_during_add;
static void ft_ipsec_egress_changed(const struct net_device *dev);

static u16 cdx_ipsec_sa_handle(const struct cdx_ipsec_sa *sa)
{
	return sa ? sa->handle : 0;
}
struct netlink_ext_ack;
static void backend_says(struct netlink_ext_ack *extack, const char *msg);
/* The control-plane transaction, defined with its operations below. */
static int ft_transaction;
/* The last spec the backend was handed, and how many SAs were out of the
 * hardware when it was. */
static struct cdx_ipsec_sa_spec installed_spec;
static unsigned deleted_before_install;
static int cdx_ipsec_validate(const struct cdx_ipsec_sa_spec *spec);
static int cdx_ipsec_sa_add(const struct cdx_ipsec_sa_spec *spec,
			    struct xfrm_state *x, struct cdx_ipsec_sa **result,
			    struct netlink_ext_ack *extack)
{
	struct cdx_ipsec_sa *sa;

	(void)x;
	*result = NULL;
	/* The backend's own first check, compiled: what it refuses -- a port
	 * the engine cannot serve, a window or a sequence number it cannot
	 * carry -- is refused before anything is built. */
	int rc = cdx_ipsec_validate(spec);

	if (rc)
		return rc;
	if (sa_add_error) {
		/* What the backend says when it knows why, as it does when
		 * SEC fails the split-key job. */
		if (sa_add_message)
			backend_says(extack, sa_add_message);
		return sa_add_error;
	}
	/* The port's egress changing after the build read it and before the
	 * install publishes its watch: counted, then walked, as
	 * ft_egress_changed() does. */
	if (egress_change_during_add) {
		atomic64_inc_return(&ft_egress_changes);
		ft_ipsec_egress_changed(egress_change_during_add);
	}
	assert(sa_installed < sizeof(sa_pool) / sizeof(sa_pool[0]));
	sa = &sa_pool[sa_installed];
	sa->handle = (u16)(sa_installed + 1);
	sa->outbound = spec->dir == CDX_IPSEC_DIR_OUT;
	sa->live = true;
	ether_addr_copy(sa->dst_mac, spec->dst_mac);
	sa->path_mtu = spec->path_mtu;
	sa_installed++;
	installed_spec = *spec;
	deleted_before_install = sa_deleted;
	*result = sa;
	return 0;
}
/* A deletion reads where SEC left the SA as it goes: the figures the case
 * gave the SA are SEC's last. */
static void cdx_ipsec_sa_del(struct cdx_ipsec_sa **sa, struct cdx_ipsec_counters *last)
{
	memset(last, 0, sizeof(*last));
	if (!*sa)
		return;
	assert(!retirement_flows && !retirement_barriers && ft_transaction);
	if ((*sa)->outbound) {
		last->oseq = (*sa)->oseq;
	} else {
		last->seq = (*sa)->seq;
		memcpy(last->seen, (*sa)->seen, sizeof(last->seen));
	}
	(*sa)->live = false;
	*sa = NULL;
	sa_deleted++;
}
/* What a rebuild in progress lets a drain see, and an egress change landing
 * while it runs. */
static bool ft_ipsec_rebuild_pending(const struct net_device *dev);
static struct net_device *pending_during_rebuild, *egress_change_during_rebuild;
static int cdx_ipsec_sa_set_next_hop(struct cdx_ipsec_sa *sa, const u8 *dst_mac,
				     u16 path_mtu)
{
	sa_next_hop_calls++;
	/* The invariant the watch design rests on: a rebuild is only ever
	 * handed an SA that is still installed. */
	assert(sa && sa->live && sa->outbound);
	if (pending_during_rebuild)
		assert(ft_ipsec_rebuild_pending(pending_during_rebuild));
	if (egress_change_during_rebuild)
		ft_ipsec_egress_changed(egress_change_during_rebuild);
	if (sa_next_hop_error)
		return sa_next_hop_error;
	ether_addr_copy(sa->dst_mac, dst_mac);
	if (path_mtu)
		sa->path_mtu = path_mtu;
	return 0;
}
static bool port_supported = true;
static bool cdx_ipsec_port_supported(struct net_device *dev)
{
	return dev && dev->physical && port_supported;
}
/* Which authenticators SEC produces: the backend's predicate and the table
 * behind it, compiled, with SEC's operation codes from cdx's own header. */
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#include "ipsec_auth.inc"

/* The control-plane transaction. The rebuild must hold it; the resolution
 * that precedes the rebuild must not. */
static int ft_transaction;
static void cdx_ft_begin(void) { assert(!ft_transaction); ft_transaction = 1; }
static void cdx_ft_end(void) { assert(ft_transaction); ft_transaction = 0; }

/* What SEC counted, read the way the backend requires: inside the
 * transaction, and only for an SA that is still installed -- which is the
 * promise the accounting pass makes by holding the transaction across its
 * walk. A case can hook the read to model what a concurrent deletion does
 * while the pass is inside it. */
static unsigned sa_stats_reads;
static void (*sa_stats_hook)(struct cdx_ipsec_sa *sa);
static void cdx_ipsec_sa_stats(struct cdx_ipsec_sa *sa,
			       struct cdx_ipsec_counters *counters)
{
	assert(ft_transaction && sa && sa->live);
	sa_stats_reads++;
	if (sa_stats_hook)
		sa_stats_hook(sa);
	counters->packets = sa->packets;
	counters->bytes = sa->bytes;
	counters->oseq = sa->outbound ? sa->oseq : 0;
	counters->seq = sa->outbound ? 0 : sa->seq;
	memcpy(counters->seen, sa->outbound ? (u32[4]){ 0 } : sa->seen,
	       sizeof(counters->seen));
}

/* SEC's sequence space alone, read the way the backend allows it: with no
 * transaction, from an SA kept installed by the owned list's lock -- the
 * promise the op makes by reading the handle under it. Only the three
 * sequence fields are the reader's. */
static unsigned replay_state_reads;
static bool cdx_ipsec_sa_replay_state(const struct cdx_ipsec_sa *sa,
				      struct cdx_ipsec_counters *state)
{
	assert(ft_ipsec_retired_lock && sa && sa->live);
	replay_state_reads++;
	state->oseq = sa->outbound ? sa->oseq : 0;
	state->seq = sa->outbound ? 0 : sa->seq;
	memcpy(state->seen, sa->outbound ? (u32[4]){ 0 } : sa->seen,
	       sizeof(state->seen));
	return sa->outbound || sa->seq;
}

/* What the FMan microcode counted of the frames SEC refused, read the whole
 * way the kernel reads it: the SDK's reader over the microcode's own table,
 * through the SDK's own big-endian load, and the backend's sorting of it into
 * classes -- all compiled, over a block of "MURAM" a case fills in the
 * microcode's byte order. The load's two primitives are the kernel's, for a
 * little-endian host; each 32-bit load is counted. */
#define ENODEV 19
static unsigned muram_reads;
static u32 __raw_readl(const volatile void *addr)
{
	muram_reads++;
	return *(const volatile u32 *)addr;
}
#define __be32_to_cpu(x) ntohl(x)
/* The IPsec offline port's count of frames QMan would not let it enqueue, as
 * dpa_cfg reads it off the port: there only once a case gives it a port. */
static bool offline_port_present;
static u32 offline_port_rejections;
static int cdx_dpa_ipsec_offline_port_rejected(u32 *count)
{
	if (!offline_port_present)
		return -ENODEV;
	*count = offline_port_rejections;
	return 0;
}
/* And what SEC's input group refused of Linux's own enqueues to SEC, as
 * dpa_ipsec counts them. */
static u32 sec_input_refusals;
static u32 cdx_dpa_ipsec_input_refused(void) { return sec_input_refusals; }
#include "sec_refusals.inc"
/* The /proc/net/xfrm_stat counters the adapter adds to, numbered as the
 * kernel numbers them. Only init_net's are ever touched. */
static u64 xfrm_mib[__LINUX_MIB_XFRMMAX];
#define XFRM_ADD_STATS(net, field, val) \
	do { assert((net) == &init_net); xfrm_mib[field] += (val); } while (0)

/* xfrm's side of a lifetime. The judge itself is the kernel's, compiled; what
 * it reaches is recorded here. */
static time64_t wall_clock = 1700000000;
static time64_t ktime_get_real_seconds(void) { return wall_clock; }
#define HRTIMER_MODE_REL_SOFT 0
static unsigned timers_started;
static void hrtimer_start(int *timer, long expires, int mode)
{
	(void)timer; (void)mode;
	assert(expires == 0);
	timers_started++;
}
static unsigned soft_expires, hard_expires;
static void km_state_expired(struct xfrm_state *x, int hard, u32 portid)
{
	assert(x->lock && !portid);
	if (hard)
		hard_expires++;
	else
		soft_expires++;
}
static void xfrm_dev_state_update_stats(struct xfrm_state *x);
static int kernel_xfrm_state_check_expire(struct xfrm_state *x);
/* Counted, and asked the questions the pass's locking has to answer: x->lock
 * held, the owned list's lock not -- deletion takes that one under x->lock --
 * and the transaction held, which is what kept the SA to read. */
static unsigned expire_checks;
static int xfrm_state_check_expire(struct xfrm_state *x)
{
	assert(x->lock && !ft_ipsec_retired_lock && ft_transaction);
	expire_checks++;
	return kernel_xfrm_state_check_expire(x);
}

/* The accounting pass's work item. It must only ever be asked to run a
 * period out, never at once: installs come in bursts. */
static int ft_ipsec_stats;
static unsigned stats_scheduled;
static void schedule_delayed_work(int *work, unsigned long delay)
{
	assert(work == &ft_ipsec_stats && delay == FT_IPSEC_STATS_PERIOD);
	stats_scheduled++;
}

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
/* Waiting for a retirement is running the retirement work to the end, here:
 * it drains the whole queue, waking the waiter -- unless a case has it stuck,
 * as a wedged classifier keeps it, when the wait times out. Nothing may be
 * held that the work takes, and the condition is asked first, as the kernel
 * asks it. */
static void ft_ipsec_retire_work(struct work_struct *work);
static bool retirement_stuck;
static unsigned retire_waits, retire_wakes;
#define wait_event_timeout(wq, condition, timeout) ({				\
	assert(&(wq) == &ft_ipsec_retired_wait && (timeout) == FT_IPSEC_RETIRE_WAIT); \
	assert(!ft_transaction && !ft_ipsec_retired_lock);			\
	bool met_ = (condition);						\
	if (!met_) {								\
		retire_waits++;							\
		if (!retirement_stuck)						\
			ft_ipsec_retire_work(NULL);				\
		met_ = (condition);						\
	}									\
	met_ ? 1L : 0L;								\
})
#define wake_up_all(wq) do { assert((wq) == &ft_ipsec_retired_wait); retire_wakes++; } while (0)

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
	void (*xdo_dev_state_update_stats)(struct xfrm_state *x);
	int (*xdo_dev_policy_add)(struct xfrm_policy *x,
				  struct netlink_ext_ack *extack);
	void (*xdo_dev_policy_delete)(struct xfrm_policy *x);
	void (*xdo_dev_policy_free)(struct xfrm_policy *x);
};
/* xfrm's own call of that op, as include/net/xfrm.h makes it, from the one
 * caller of it compiled here: xfrm_state_check_expire(), which holds x->lock
 * as all its callers do. */
static unsigned update_stats_calls;
static void xfrm_dev_state_update_stats(struct xfrm_state *x)
{
	const struct xfrmdev_ops *ops = x->xso.dev ? x->xso.dev->xfrmdev_ops : NULL;

	assert(x->lock);
	update_stats_calls++;
	if (ops && ops->xdo_dev_state_update_stats)
		ops->xdo_dev_state_update_stats(x);
}
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
static void backend_says(struct netlink_ext_ack *extack, const char *msg)
{
	if (extack)
		extack->_msg = msg;
}

/* What the classifier callback borrowed for each direction. */
struct flow_cls_offload {
	struct dst_entry *nf_dst;
	struct dst_entry *nf_dst_reverse;
	const struct nf_conn { u32 mark; } *nf_ct;
	struct nf_flow_offload_handle { bool valid; } *nf_handle;
};
static atomic64_t ft_admission_invalidations, ft_ipsec_invalidations;
static atomic64_t ft_mtu_invalidations;
struct cdx_ft_entry {
	struct list_head list;
	/* The dependency watch's list, which a moved path is looked up on. */
	struct list_head neigh_list;
	struct { u16 sa_handle, in_sa_handle; } rule;
	struct nf_flow_offload_handle *handle;
};
static LIST_HEAD(ft_entries);
static LIST_HEAD(ft_neigh_entries);
/* The flowtable's own retirement: an unlink owes a barrier, and a settle
 * issues one for every unlink owed since the last. Compiled and tested in
 * flowtable.c; here they count, so a case can say how many of each a
 * retirement took. */
static unsigned unlinks_owed, settles;
static void cdx_ft_assert_held(void) { assert(ft_transaction); }
static int ft_unlink(struct cdx_ft_entry *e)
{
	assert(ft_transaction && retirement_flows);
	retirement_flows--;
	unlinks_owed++;
	list_del(&e->list);
	free(e);
	return 0;
}
static int ft_settle(void)
{
	assert(ft_transaction);
	if (unlinks_owed)
		settles++;
	unlinks_owed = 0;
	return 0;
}
/* Where a retirement walk lets the transaction go between batches. */
static unsigned reschedules;
static void cond_resched(void) { assert(!ft_transaction); reschedules++; }
static unsigned cdx_ft_pending(void) { assert(ft_transaction); return retirement_barriers; }
static int cdx_ft_recover(void)
{
	assert(ft_transaction && !retirement_flows);
	if (retirement_barriers) retirement_barriers--;
	return retirement_barriers ? -EIO : 0;
}
/* Every marking an SA's retirement asks for, already marked or not: one walk
 * of the flows marks each once. */
static unsigned ipsec_markings;
static void ft_handle_invalidate(struct nf_flow_offload_handle *h, atomic64_t *count)
{
	/* A moved path's flows are walked on the watch's list, which the
	 * watch lock guards. */
	if (count == &ft_mtu_invalidations)
		assert(ft_watch_lock);
	if (count == &ft_ipsec_invalidations)
		ipsec_markings++;
	if (h->valid) { h->valid = false; (*count)++; }
}

/* The route the FIB should answer with, and the neighbour on it. Every answer
 * is held, as the kernel's is, so a lookup the adapter does not release
 * leaves the route's count above zero. */
static struct rtable *route_answer;
static int route_error;
static struct neighbour *route_neigh;
static unsigned route_lookups;
static int route_oif, route_l3mdev;
static u32 route_mark;
/* The last lookup's whole key, in its family. */
static struct flowi4 route_key;
static struct flowi6 route6_key;
static struct dst_ops v4_ops = { .family = AF_INET };
static struct dst_ops v6_ops = { .family = AF_INET6 };
/* What ip6_route_output() answers a failed lookup with: a held route whose
 * error says why, never a pointer error. */
static struct dst_entry v6_null = { .ops = &v6_ops };
/* The IPv6 route to the peer, over the WAN port unless told otherwise. */
static struct dst_entry *route6_answer;
/* The VRF the SA's port is enslaved to, or zero. */
static int port_l3_master;
static int l3mdev_master_ifindex(struct net_device *dev) { (void)dev; return port_l3_master; }
static u32 xfrm_smark_get(u32 mark, struct xfrm_state *x)
{
	return (mark & ~x->props.smark.m) | (x->props.smark.v & x->props.smark.m);
}

/* The FIB's answer, which is all the adapter may ask for the peer. */
static struct rtable *__ip_route_output_key(void *net, struct flowi4 *fl4)
{
	(void)net;
	/* Asked with every lock dropped, as the adapter promises. */
	assert(!ft_watch_lock);
	route_oif = fl4->flowi4_oif;
	route_mark = fl4->flowi4_mark;
	route_l3mdev = fl4->flowi4_l3mdev;
	route_key = *fl4;
	route_lookups++;
	if (route_error)
		return ERR_PTR(route_error);
	dst_hold(&route_answer->dst);
	return route_answer;
}
static struct dst_entry *ip6_route_output(void *net, void *sk, struct flowi6 *fl6)
{
	struct dst_entry *dst = route6_answer;

	(void)net; (void)sk;
	assert(!ft_watch_lock);
	route_mark = fl6->flowi6_mark;
	route_l3mdev = fl6->flowi6_l3mdev;
	route6_key = *fl6;
	route_lookups++;
	if (route_error) {
		v6_null.error = route_error;
		dst = &v6_null;
	}
	dst_hold(dst);
	return dst;
}
/* What ip_route_output_key() adds when the flow names a protocol:
 * xfrm_lookup_route(), which answers with a policy's bundle when its selector
 * covers the flow -- here `route_bundle`, the SA's own over its port. Nothing
 * in the adapter may call it; it is here so that a peer lookup going back to
 * it compiles and is caught by the bundle case. */
static struct rtable *route_bundle;
static inline struct rtable *ip_route_output_key(void *net, struct flowi4 *fl4)
{
	struct rtable *rt = __ip_route_output_key(net, fl4);

	if (!IS_ERR(rt) && fl4->flowi4_proto && route_bundle)
		return route_bundle;
	return rt;
}

/* xfrm's own route lookup, which an inbound SA's peer is looked up with, in
 * either family: the route it answers with (the WAN route unless told
 * otherwise), or an error, and the whole key it was asked with. */
union flowi_uli { struct { __be16 dport, sport; } ports; };
struct xfrm_dst_lookup_params {
	struct net *net;
	int tos, oif;
	xfrm_address_t *saddr, *daddr;
	u32 mark;
	u8 ipproto;
	union flowi_uli uli;
};
static struct rtable wan_route;
static struct dst_entry *peer_answer;
static int peer_error, peer_family;
static unsigned peer_lookups;
static struct xfrm_dst_lookup_params peer_key;
static struct dst_entry *__xfrm_dst_lookup(int family,
					   const struct xfrm_dst_lookup_params *params)
{
	struct dst_entry *dst = peer_answer ? peer_answer : &wan_route.dst;

	peer_lookups++;
	peer_key = *params;
	peer_family = family;
	if (peer_error)
		return ERR_PTR(peer_error);
	dst_hold(dst);
	return dst;
}
static bool xfrm_addr_any(const xfrm_address_t *a, unsigned short family)
{
	return family == AF_INET ? !a->a4 : !(a->a6[0] | a->a6[1] | a->a6[2] | a->a6[3]);
}
static bool xfrm_addr_equal(const xfrm_address_t *a, const xfrm_address_t *b,
			    unsigned short family)
{
	return !memcmp(a, b, family == AF_INET ? 4 : 16);
}
static unsigned neigh_lookups;
static struct neighbour *dst_neigh_lookup(struct dst_entry *dst, const void *key)
{
	(void)dst; (void)key;
	neigh_lookups++;
	if (!route_neigh)
		return NULL;
	route_neigh->refs++;
	neigh_refs++;
	return route_neigh;
}
/* What the physical port carries for a direction, the core's to answer
 * (ft_port_mtu()): set below the outer route's MTU, it stands for a bridge
 * raised above its port. */
static u32 port_mtu = 65535;
u32 ft_port_mtu(const struct cdx_ft_rule *rule)
{
	(void)rule;
	return port_mtu;
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
/* 2001:db8:1::1 and 2001:db8:1::7a, the same pair over IPv6. */
static const struct in6_addr LOCAL6 = { { 0x20, 0x01, 0x0d, 0xb8, 0, 1, [15] = 0x01 } };
static const struct in6_addr PEER6 = { { 0x20, 0x01, 0x0d, 0xb8, 0, 1, [15] = 0x7a } };
#define CBC_TUNNEL6_HEADER (8 + 16 + 40)

static struct neighbour peer_neigh = {
	.tbl = &arp_tbl, .dev = &WAN, .nud_state = NUD_REACHABLE,
	.primary_key = { 0xc0, 0xa8, 1, 122 },
	.ha = { 0x02, 0xaa, 0, 0, 0, 1 },
};
static struct rtable wan_route;
static struct dst_entry wan_route6;

static struct xfrm_algo_auth auth_key = { .alg_key_len = 160, .alg_trunc_len = 96 };
static struct xfrm_algo cipher_key = { .alg_key_len = 128 };
/* What esp4 builds for AES-CBC with HMAC-MD5-96: a 16-byte block and IV and
 * a 12-byte ICV, behind an ESP header, an IV and, in tunnel mode, an outer
 * IPv4 header. */
static const struct xfrm_type esp_type = { .proto = IPPROTO_ESP };
static struct crypto_aead cbc_md5 = { .blocksize = 16, .authsize = 12 };
#define CBC_TUNNEL_HEADER (8 + 16 + 20)

static struct xfrm_state *outbound_state(void)
{
	static struct xfrm_state x;

	memset(&x, 0, sizeof(x));
	x.type = &esp_type;
	x.data = &cbc_md5;
	x.props.header_len = CBC_TUNNEL_HEADER;
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

/* The same SA between IPv6 endpoints: a 40-byte outer header. */
static void outbound6(struct xfrm_state *x)
{
	x->props.family = AF_INET6;
	x->props.header_len = CBC_TUNNEL6_HEADER;
	memcpy(&x->id.daddr, &PEER6, sizeof(PEER6));
	memcpy(&x->props.saddr, &LOCAL6, sizeof(LOCAL6));
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
	wan_route.dst.mtu = 0;
	WAN.mtu = 1500;
	neigh_lookups = 0;
	route_answer = &wan_route;
	route_bundle = NULL;
	route_error = 0;
	peer_answer = NULL;
	peer_error = 0;
	peer_lookups = 0;
	route_neigh = &peer_neigh;
	route_lookups = 0;
	route6_answer = &wan_route6;
	wan_route6.ops = &v6_ops;
	wan_route6.dev = &WAN;
	wan_route6.mtu = 0;
	peer_neigh.tbl = &arp_tbl;
	peer_neigh.nud_state = NUD_REACHABLE;
	peer_neigh.dead = false;
	peer_neigh.dev = &WAN;
	memcpy(peer_neigh.primary_key, (u8[16]){ 0xc0, 0xa8, 1, 122 }, 16);
	ether_addr_copy(peer_neigh.ha, PEER_MAC);
	memset(policy_answers, 0, sizeof(policy_answers));
	policy_error = 0;
	policy_lookups = 0;
	paired_state = NULL;
	sa_add_error = 0;
	sa_add_message = NULL;
	sa_next_hop_error = 0;
	sa_next_hop_calls = 0;
	works_scheduled = retires_scheduled = 0;
	retired_handles = 0;
	sa_stats_reads = expire_checks = 0;
	sa_stats_hook = NULL;
	soft_expires = hard_expires = timers_started = 0;
	stats_scheduled = 0;
	port_supported = true;
	WAN.xfrmdev_ops = NULL;
	WAN.features = WAN.hw_features = WAN.wanted_features = 0;
	features_changes = 0;
	slept = 0;
	neigh_probes = 0;
	probe_answers = false;
	auth_key.alg_key_len = 160;
	auth_key.alg_trunc_len = 96;
	retirement_stuck = false;
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
	/* Every deletion counted has reached the hardware. */
	assert(!ft_ipsec_retire_pending());
	while (ft_ipsec_owned.next != &ft_ipsec_owned) {
		struct ft_ipsec_retirement *r = list_entry(ft_ipsec_owned.next, struct ft_ipsec_retirement, list);
		list_del(&r->list);
		kfree(r);
	}
	ft_ipsec_forget_all();
	assert(!ft_ipsec_remembered_count && ft_ipsec_remembered.next == &ft_ipsec_remembered);
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
	/* ((1500 - 44 - 12) & ~15) - 2: what Linux answers Fragmentation
	 * Needed with, on a state not yet valid. */
	assert(spec.dev_mtu == 1500 && spec.mtu == 1438);
	/* And the path to the peer, which the SA's own entry fragments SEC's
	 * output to: the route's MTU where it has one -- a narrower hop, a
	 * learned PMTU -- never more than the port's. */
	assert(spec.path_mtu == 1500);
	wan_route.dst.mtu = 1492;
	assert(ft_ipsec_spec(x, &spec, &ack) == 0 && spec.path_mtu == 1492);
	wan_route.dst.mtu = 9000;
	assert(ft_ipsec_spec(x, &spec, &ack) == 0 && spec.path_mtu == 1500);
	wan_route.dst.mtu = 0;
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
	 * next hop. It is asked the question its outbound half will be --
	 * whether the route to the peer leaves by the SA's device -- through
	 * xfrm's own lookup: from the local endpoint to the peer, in the SA's
	 * family and its port's VRF, with no output mark. */
	x->xso.dir = XFRM_DEV_OFFLOAD_IN;
	x->props.smark.v = 0x40;
	x->props.smark.m = 0xff;
	route_lookups = 0;
	assert(ft_ipsec_spec(x, &spec, &ack) == 0);
	assert(spec.dir == CDX_IPSEC_DIR_IN && route_lookups == 0 && peer_lookups == 1);
	assert(is_zero_ether_addr(spec.dst_mac));
	assert(peer_family == AF_INET && peer_key.oif == WAN.ifindex);
	assert(peer_key.saddr == &x->id.daddr && peer_key.daddr == &x->props.saddr);
	assert(peer_key.mark == 0 && peer_key.ipproto == IPPROTO_ESP);
	x->props.smark.v = x->props.smark.m = 0;

	/* A peer routed by any other device is refused, and so is one with no
	 * route at all: its outbound half would be, and under `auto` this one
	 * then goes to software with it. */
	static struct rtable lan_route;
	lan_route.dst.ops = &v4_ops;
	lan_route.dst.dev = &LAN;
	peer_answer = &lan_route.dst;
	ack._msg = NULL;
	assert(ft_ipsec_spec(x, &spec, &ack) == -EOPNOTSUPP);
	assert(ack._msg && strstr(ack._msg, "does not leave by the offload device"));
	assert(lan_route.dst.refs == 0);
	peer_answer = NULL;
	peer_error = -ENETUNREACH;
	ack._msg = NULL;
	assert(ft_ipsec_spec(x, &spec, &ack) == -ENETUNREACH);
	assert(ack._msg && strstr(ack._msg, "no route"));
	peer_error = 0;

	/* NAT-T asks with the ports a reply to the peer carries: the state's
	 * own the other way round, since an inbound state's source is the
	 * peer's. */
	x->encap = &natt;
	natt.encap_type = UDP_ENCAP_ESPINUDP;
	assert(ft_ipsec_spec(x, &spec, &ack) == 0);
	assert(peer_key.ipproto == IPPROTO_UDP);
	assert(peer_key.uli.ports.sport == htons(61000) &&
	       peer_key.uli.ports.dport == htons(4500));
	x->encap = NULL;

	/* An IPv6 inbound SA is asked in its own family, and taken. */
	x->props.family = AF_INET6;
	assert(ft_ipsec_spec(x, &spec, &ack) == 0 && peer_family == AF_INET6);
	x->props.family = AF_INET;
	assert(wan_route.dst.refs == 0);
	/* SEC moves the traffic-class byte whole, so a tunnel asking for a
	 * marking that splits it stays in software: the outer DSCP without
	 * the outer ECN at decapsulation, and an outer header that does not
	 * carry the inner DSCP or ECN at encapsulation. Asking for no ECN at
	 * decapsulation is honoured instead, and the backend told. */
	assert(ft_ipsec_spec(x, &spec, &ack) == 0 && spec.ecn);
	x->props.flags = XFRM_STATE_DECAP_DSCP;
	assert(ft_ipsec_spec(x, &spec, &ack) == -EOPNOTSUPP);
	x->props.flags = XFRM_STATE_NOECN;
	assert(ft_ipsec_spec(x, &spec, &ack) == 0 && !spec.ecn);
	x->props.flags = 0;
	x->props.extra_flags = XFRM_SA_XFLAG_DONT_ENCAP_DSCP;
	assert(ft_ipsec_spec(x, &spec, &ack) == 0);
	x->props.extra_flags = 0;
	x->xso.dir = XFRM_DEV_OFFLOAD_OUT;
	assert(ft_ipsec_spec(x, &spec, &ack) == 0 && spec.ecn);
	x->props.extra_flags = XFRM_SA_XFLAG_DONT_ENCAP_DSCP;
	assert(ft_ipsec_spec(x, &spec, &ack) == -EOPNOTSUPP);
	x->props.extra_flags = 0;
	x->props.flags = XFRM_STATE_NOECN;
	assert(ft_ipsec_spec(x, &spec, &ack) == -EOPNOTSUPP);
	x->props.flags = XFRM_STATE_DECAP_DSCP;
	assert(ft_ipsec_spec(x, &spec, &ack) == 0);
	x->props.flags = 0;
	assert(wan_route.dst.refs == 0 && neigh_refs == 0);

	/* Transport mode keeps the SA's own reduced MTU and builds no outer
	 * header: ((1500 - 24 - 12 - 20) & ~15) + 20 - 2. */
	x->props.mode = XFRM_MODE_TRANSPORT;
	x->props.header_len = 8 + 16;
	assert(ft_ipsec_spec(x, &spec, &ack) == 0);
	assert(!spec.tunnel && spec.mtu == 1458);
	x->props.mode = XFRM_MODE_TUNNEL;
	x->props.header_len = CBC_TUNNEL_HEADER;

	/* An outbound IPv6 SA is addressed through its own family's route
	 * and neighbour (test_next_hop()), and taken. */
	outbound6(x);
	assert(ft_ipsec_spec(x, &spec, &ack) == 0 && spec.family == AF_INET6);
	assert(wan_route6.refs == 0 && neigh_refs == 0);
}

/* An AEAD transform is one key under an identity that names the mode and the
 * ICV length together. GCM is admitted at each of its three lengths. GMAC is
 * refused in both directions, and says why: SEC authenticates it without the
 * IV that RFC 4543 and every software peer authenticate, so not one frame
 * would pass the other side's check. */
static void test_spec_aead(void)
{
	static const u8 gcm[] = { SADB_X_EALG_AES_GCM_ICV8, SADB_X_EALG_AES_GCM_ICV12,
				  SADB_X_EALG_AES_GCM_ICV16 };
	/* An AES-128 key and the four-byte salt both RFCs append to it. */
	struct xfrm_algo_aead aead = { .alg_key_len = 160 };
	struct cdx_ipsec_sa_spec spec;
	struct netlink_ext_ack ack;
	struct xfrm_state *x;
	unsigned dir, i, lookups;

	bench_reset();
	memset(aead.alg_key, 0xc3, aead.alg_key_len / 8);
	for (dir = XFRM_DEV_OFFLOAD_OUT; dir <= XFRM_DEV_OFFLOAD_IN; dir++) {
		x = outbound_state();
		x->xso.dir = dir;
		x->aalg = NULL;
		x->ealg = NULL;
		x->props.aalgo = 0;
		x->aead = &aead;
		for (i = 0; i < sizeof(gcm) / sizeof(gcm[0]); i++) {
			x->props.ealgo = gcm[i];
			ack._msg = NULL;
			assert(ft_ipsec_spec(x, &spec, &ack) == 0 && !ack._msg);
			assert(spec.crypt.alg == gcm[i] && spec.crypt.bits == 160);
			assert(!memcmp(spec.crypt.key, aead.alg_key, aead.alg_key_len / 8));
			assert(!spec.auth.alg && !spec.auth.bits);
		}
		x->props.ealgo = SADB_X_EALG_NULL_AES_GMAC;
		ack._msg = NULL;
		lookups = route_lookups;
		assert(ft_ipsec_spec(x, &spec, &ack) == -EOPNOTSUPP);
		assert(ack._msg && strstr(ack._msg, "GMAC"));
		/* Refused before anything is resolved for it. */
		assert(route_lookups == lookups);
	}
}

/* An authenticator is its algorithm and the ICV it is truncated to, and SEC
 * fixes the ICV in its protocol operation. Every pair SEC has is admitted,
 * carries its length to the backend and selects that operation; every other
 * truncation of the same algorithms, and an algorithm SEC has no operation
 * for at all, is refused in both directions before anything is resolved, and
 * says why. */
static void test_spec_auth(void)
{
	/* The oracle is SEC RM table 7-54 rather than the code: each pair's
	 * PROTINFO[7:0], whose name states the ICV it produces. */
	static const struct { u8 alg; unsigned icv_bits; int op; } admitted[] = {
		{ SADB_AALG_MD5HMAC, 96, 0x01 },		/* HMAC_MD5_96 */
		{ SADB_AALG_MD5HMAC, 128, 0x06 },		/* HMAC_MD5_128 */
		{ SADB_AALG_SHA1HMAC, 96, 0x02 },		/* HMAC_SHA1_96 */
		{ SADB_AALG_SHA1HMAC, 160, 0x07 },		/* HMAC_SHA1_160 */
		{ SADB_X_AALG_SHA2_256HMAC, 128, 0x0c },	/* HMAC_SHA2_256_128 */
		{ SADB_X_AALG_SHA2_384HMAC, 192, 0x0d },	/* HMAC_SHA2_384_192 */
		{ SADB_X_AALG_SHA2_512HMAC, 256, 0x0e },	/* HMAC_SHA2_512_256 */
		{ SADB_X_AALG_AES_XCBC_MAC, 96, 0x05 },		/* AES_XCBC_MAC_96 */
		{ SADB_X_AALG_NULL, 0, 0x00 },			/* NULL */
	};
	/* Every authenticator xfrm can hand over, and the widest truncation it
	 * accepts for each: its full digest. xfrm's cmac(aes) has no PF_KEY
	 * number and arrives as algorithm 0 with a key; zero reads as "no
	 * authenticator" further down, so it has to be refused here rather
	 * than passed on, or the SA would leave unauthenticated. */
	static const struct { u8 alg; unsigned full_bits; } algorithms[] = {
		{ SADB_AALG_MD5HMAC, 128 }, { SADB_AALG_SHA1HMAC, 160 },
		{ SADB_X_AALG_SHA2_256HMAC, 256 }, { SADB_X_AALG_SHA2_384HMAC, 384 },
		{ SADB_X_AALG_SHA2_512HMAC, 512 }, { SADB_X_AALG_RIPEMD160HMAC, 160 },
		{ SADB_X_AALG_AES_XCBC_MAC, 128 }, { SADB_X_AALG_SM3_256HMAC, 256 },
		{ SADB_X_AALG_NULL, 0 }, { 0 /* cmac(aes) */, 128 },
	};
	struct cdx_ipsec_sa_spec spec;
	struct netlink_ext_ack ack;
	struct xfrm_state *x;
	unsigned dir, a, bits, i, lookups, admissions = 0;

	bench_reset();
	for (dir = XFRM_DEV_OFFLOAD_OUT; dir <= XFRM_DEV_OFFLOAD_IN; dir++) {
		for (a = 0; a < sizeof(algorithms) / sizeof(algorithms[0]); a++) {
			for (bits = 0; bits <= algorithms[a].full_bits; bits++) {
				int op = -1;

				for (i = 0; i < sizeof(admitted) / sizeof(admitted[0]); i++)
					if (admitted[i].alg == algorithms[a].alg &&
					    admitted[i].icv_bits == bits)
						op = admitted[i].op;
				x = outbound_state();
				x->xso.dir = dir;
				x->props.aalgo = algorithms[a].alg;
				auth_key.alg_trunc_len = bits;
				assert(cdx_ipsec_auth_op(algorithms[a].alg, bits) == op);
				assert(cdx_ipsec_auth_supported(algorithms[a].alg, bits) == (op >= 0));
				ack._msg = NULL;
				lookups = route_lookups;
				if (op >= 0) {
					assert(ft_ipsec_spec(x, &spec, &ack) == 0 && !ack._msg);
					assert(spec.auth.alg == algorithms[a].alg);
					assert(spec.auth.icv_bits == bits && spec.auth.bits == 160);
					admissions++;
					continue;
				}
				assert(ft_ipsec_spec(x, &spec, &ack) == -EOPNOTSUPP);
				assert(ack._msg && strstr(ack._msg, "ICV length"));
				assert(route_lookups == lookups);
			}
		}
	}
	/* Each pair once per direction, so none of the oracle went untried. */
	assert(admissions == 2 * sizeof(admitted) / sizeof(admitted[0]));
	auth_key.alg_trunc_len = 96;
}

/* The SA's MTU, whose difference from the port's is the expansion the
 * microcode adds to a packet bound for SEC before the size check that hands
 * an oversized IPv4 packet with DF to Linux. It has to be the MTU xfrm
 * computes for the state once it is valid -- the one Linux answers
 * Fragmentation Needed with -- for every transform geometry, mode, family
 * and encapsulation, whether the state is still being added (VOID, as
 * xfrm_user hands it over) or arrives valid (as a migrate does). xfrm's own
 * function is the oracle, compiled from the kernel. */
static void test_spec_mtu(void)
{
	/* Block size and ICV, and the IV esp puts in front: AES-CBC with a
	 * 96-, 128- and 256-bit HMAC, 3DES, and GCM, a stream whose block
	 * esp aligns to 4. */
	static struct crypto_aead geometries[] = {
		{ 16, 12 }, { 16, 16 }, { 16, 32 }, { 8, 12 }, { 1, 16 }, { 1, 8 },
	};
	static const int ivs[] = { 16, 16, 16, 8, 8, 8 };
	/* Some not a multiple of 4, where GCM's aligned block shows. */
	static const u32 mtus[] = { 1500, 1499, 1492, 1477, 1452, 1400, 1280, 9000, 1001, 100, 68 };
	struct cdx_ipsec_sa_spec spec;
	struct netlink_ext_ack ack = { NULL };
	struct xfrm_state *x;
	unsigned g, m, mode, family, natt;
	u32 expected;

	bench_reset();
	for (g = 0; g < sizeof(geometries) / sizeof(geometries[0]); g++)
	for (mode = XFRM_MODE_TRANSPORT; mode <= XFRM_MODE_TUNNEL; mode++)
	for (family = 0; family < 2; family++)
	for (natt = 0; natt < 2; natt++)
	for (m = 0; m < sizeof(mtus) / sizeof(mtus[0]); m++) {
		x = outbound_state();
		x->data = &geometries[g];
		x->props.mode = (u8)mode;
		x->props.family = family ? AF_INET6 : AF_INET;
		x->props.header_len = 8 + ivs[g] +
			(mode == XFRM_MODE_TUNNEL ? (family ? 40 : 20) : 0) + (natt ? 8 : 0);
		x->km.state = XFRM_STATE_VALID;
		expected = kernel_xfrm_state_mtu(x, (int)mtus[m]);
		assert(ft_ipsec_esp_mtu(x, mtus[m]) == expected);
		x->km.state = XFRM_STATE_VOID;
		assert(ft_ipsec_esp_mtu(x, mtus[m]) == expected);
	}

	/* Through the translation, on a state being added: the SA's MTU is
	 * the bundle's, not the port's less the headers alone, and the
	 * expansion the classifier gets carries the ICV, the trailer and the
	 * padding. For AES-CBC with HMAC-SHA256-128 over IPv4 that is
	 * 1500 - 1438 = 62 (tools/tests/flowtable_ipv6_sa.py), where xfrm
	 * answers a state not yet valid with 1456. */
	x = outbound_state();
	x->data = &geometries[1];
	x->km.state = XFRM_STATE_VOID;
	assert(kernel_xfrm_state_mtu(x, 1500) == 1500 - CBC_TUNNEL_HEADER);
	assert(ft_ipsec_spec(x, &spec, &ack) == 0);
	assert(spec.dev_mtu == 1500 && spec.mtu == 1438);
	x->km.state = XFRM_STATE_VALID;
	assert(ft_ipsec_spec(x, &spec, &ack) == 0 && spec.mtu == 1438);
	/* A state that is not ESP's has no transform to measure, and keeps
	 * xfrm's header-only answer. */
	x->data = NULL;
	assert(ft_ipsec_esp_mtu(x, 1500) == 1500 - CBC_TUNNEL_HEADER);
	assert(ft_ipsec_esp_mtu(x, 40) == 1);
}

static void test_next_hop(void)
{
	struct cdx_ipsec_sa_spec spec;
	struct xfrm_state *x = outbound_state();
	struct xfrm_encap_tmpl natt = { .encap_type = UDP_ENCAP_ESPINUDP,
					.encap_sport = htons(4500), .encap_dport = htons(61000) };
	struct netlink_ext_ack ack = { NULL };

	/* No route to the peer is a refusal: an outbound SA leaves SEC
	 * already addressed, so there is nothing to install without one. */
	bench_reset();
	route_error = -ENETUNREACH;
	assert(ft_ipsec_spec(x, &spec, &ack) == -ENETUNREACH);
	assert(route_lookups == 1 && wan_route.dst.refs == 0);

	/* A route leaving by another port is refused too. Packet offload
	 * binds a state to one device and the framing belongs to that device;
	 * accepting here would address a frame on a port it never leaves by. */
	bench_reset();
	x->xso.dev = &LAN;
	assert(ft_ipsec_spec(x, &spec, &ack) == -EOPNOTSUPP);
	assert(route_lookups == 1 && wan_route.dst.refs == 0);
	/* And the FIB is left free to say so: a lookup bound to the SA's port
	 * answers through that port whatever the table holds, and this refusal
	 * could never happen. */
	assert(route_oif == 0);
	x->xso.dev = &WAN;

	/* Unbound, but not without context: the peer is routed in the table
	 * of the port's VRF and with the SA's output mark, as the kernel's
	 * own lookup of it is. */
	bench_reset();
	port_l3_master = 9;
	x->props.smark.v = 0x70;
	x->props.smark.m = 0xf0;
	assert(ft_ipsec_spec(x, &spec, &ack) == 0);
	assert(route_l3mdev == 9 && route_mark == 0x70);
	port_l3_master = 0;
	x->props.smark.v = x->props.smark.m = 0;

	/* And with the protocol and ports the SA's frames leave with, which
	 * the kernel's lookup carries too, so a rule or a multipath hash on
	 * them answers both alike: ESP, or NAT-T's UDP and its own ports. */
	bench_reset();
	assert(ft_ipsec_spec(x, &spec, &ack) == 0 && route_lookups == 1);
	assert(route_key.flowi4_proto == IPPROTO_ESP);
	assert(route_key.fl4_sport == 0 && route_key.fl4_dport == 0);
	bench_reset();
	x->encap = &natt;
	assert(ft_ipsec_spec(x, &spec, &ack) == 0 && route_lookups == 1);
	assert(route_key.flowi4_proto == IPPROTO_UDP);
	assert(route_key.fl4_sport == htons(4500) && route_key.fl4_dport == htons(61000));
	x->encap = NULL;

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
	assert(neigh_refs == 0 && wan_route.dst.refs == 0);

	/* An IPv6 peer is asked in its own family with the same key, its
	 * neighbour taken from the route, and the route released. */
	bench_reset();
	outbound6(x);
	assert(ft_ipsec_spec(x, &spec, &ack) == 0 && route_lookups == 1);
	assert(ipv6_addr_equal(&route6_key.daddr, &PEER6));
	assert(ipv6_addr_equal(&route6_key.saddr, &LOCAL6));
	assert(route6_key.flowi6_proto == IPPROTO_ESP);
	assert(spec.family == AF_INET6 && ether_addr_equal(spec.dst_mac, PEER_MAC));
	assert(wan_route6.refs == 0 && neigh_refs == 0);
	/* ESP-in-UDP over IPv6 needs a UDP checksum SEC was never shown to
	 * write; it stays in software. */
	x->encap = &natt;
	assert(ft_ipsec_spec(x, &spec, &ack) == -EOPNOTSUPP && route_lookups == 1);
	x->encap = NULL;
	/* ip6_route_output() fails into the route it returns, not a pointer,
	 * and that route is still the caller's to release. */
	bench_reset();
	route_error = -ENETUNREACH;
	assert(ft_ipsec_spec(x, &spec, &ack) == -ENETUNREACH);
	assert(route_lookups == 1 && v6_null.refs == 0);
	bench_reset();
	wan_route6.dev = &LAN;
	assert(ft_ipsec_spec(x, &spec, &ack) == -EOPNOTSUPP);
	assert(wan_route6.refs == 0 && wan_route.dst.refs == 0);
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
	 * still names this SA -- and queues the hardware teardown. Until that
	 * has run, the deletion is counted where the egress drain looks: the
	 * SA's watch, which is how the drain saw it before, is already gone. */
	assert(!ft_ipsec_retire_pending());
	fail_alloc_after = 0;
	unsigned old_allocations = allocation_calls;
	ft_xdo_state_delete(x);
	assert(allocation_calls == old_allocations);
	fail_alloc_after = -1;
	assert(ft_ipsec_owned.next == &ft_ipsec_owned);
	assert(retired_handles == 1 && retires_scheduled == 1);
	assert(x->xso.offload_handle == 0);
	assert(ft_ipsec_retire_pending() && !ft_ipsec_rebuild_pending(&WAN));

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
	assert(!ft_ipsec_retire_pending());

	/* An SA more flows name than one transaction retires: they go a batch
	 * at a time, either end naming it, each batch settled behind one
	 * barrier and the transaction let go between batches -- not slept on,
	 * which is for a barrier still unproven. A flow naming another SA
	 * stays. */
	{
		enum { NAMING = 2 * FT_RETIRE_BATCH + 5, OTHERS = 3 };
		struct nf_flow_offload_handle handles[NAMING + OTHERS];
		unsigned batches = (NAMING + FT_RETIRE_BATCH - 1) / FT_RETIRE_BATCH;
		unsigned before = settles, drops = reschedules, deleted = sa_deleted;
		u16 sa;

		assert(ft_xdo_state_add(x, &ack) == 0);
		sa = x->handle;
		ft_xdo_state_delete(x);
		assert(ft_ipsec_retire_pending());
		for (unsigned i = 0; i < NAMING + OTHERS; i++) {
			struct cdx_ft_entry *e = calloc(1, sizeof(*e));

			assert(e);
			handles[i].valid = true;
			e->handle = &handles[i];
			if (i % 40 == 3 && i / 40 < OTHERS)
				e->rule.sa_handle = sa + 1;
			else if (i & 1)
				e->rule.sa_handle = sa;
			else
				e->rule.in_sa_handle = sa;
			list_add_tail(&e->list, &ft_entries);
		}
		retirement_flows = NAMING;
		slept_before = slept;
		unsigned markings = ipsec_markings;
		bench_drain_retirements();
		/* Marked in one walk before the first batch, not again for each. */
		assert(ipsec_markings == markings + NAMING);
		assert(!retirement_flows && !unlinks_owed && settles == before + batches);
		assert(reschedules == drops + batches - 1 && slept == slept_before);
		assert(sa_deleted == deleted + 1 && !ft_ipsec_retire_pending());
		for (unsigned i = 0; i < NAMING + OTHERS; i++)
			assert(handles[i].valid == (i % 40 == 3 && i / 40 < OTHERS));
		for (unsigned i = 0; i < OTHERS; i++) {
			struct cdx_ft_entry *e = list_entry(ft_entries.next, struct cdx_ft_entry, list);

			assert(e->rule.sa_handle == sa + 1 && !e->rule.in_sa_handle);
			list_del(&e->list);
			free(e);
		}
		assert(ft_entries.next == &ft_entries);
	}

	/* A refused install leaves nothing behind: no SA, and no watch whose
	 * SA never existed. */
	bench_reset();
	bench_clear_sas();
	sa_add_error = -EIO;
	ack._msg = NULL;
	assert(ft_xdo_state_add(x, &ack) == -EIO);
	assert(sa_installed == 0);
	assert(ack._msg && !strcmp(ack._msg, "cdx: the hardware refused this SA"));
	ft_ipsec_all_moved();
	assert(works_scheduled == 0);
	/* An inbound SA whose local address is not on the device it names is
	 * told so, not given the generic refusal. */
	sa_add_error = -EADDRNOTAVAIL;
	ack._msg = NULL;
	assert(ft_xdo_state_add(x, &ack) == -EADDRNOTAVAIL && sa_installed == 0);
	assert(ack._msg && strstr(ack._msg, "local address must be on the device"));
	/* A backend that says why keeps its reason, and its errno: a split
	 * key SEC failed to derive is a busy ring or a failed job, not a
	 * transform the port cannot carry. */
	sa_add_error = -EBUSY;
	sa_add_message = "cdx: SEC could not derive the HMAC split key";
	ack._msg = NULL;
	assert(ft_xdo_state_add(x, &ack) == -EBUSY);
	assert(ack._msg == sa_add_message && sa_installed == 0);
	sa_add_error = 0;
	sa_add_message = NULL;

	/* An inbound SA whose peer is routed by another device is refused
	 * before anything is built, with no watch and no handle. */
	bench_reset();
	bench_clear_sas();
	x->xso.dir = XFRM_DEV_OFFLOAD_IN;
	static struct rtable elsewhere;
	elsewhere.dst.ops = &v4_ops;
	elsewhere.dst.dev = &LAN;
	peer_answer = &elsewhere.dst;
	x->handle = 0;
	assert(ft_xdo_state_add(x, &ack) == -EOPNOTSUPP);
	assert(sa_installed == 0 && !x->handle && !x->xso.offload_handle);
	assert(ft_ipsec_owned.next == &ft_ipsec_owned);
	peer_answer = NULL;

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
	policy.xdo.type = XFRM_DEV_OFFLOAD_PACKET;

	/* An outbound policy naming an SA by SPI -- as strongSwan's do -- is
	 * taken only when that SA is one this adapter holds on the policy's
	 * device: xfrm_state_find() pairs a packet-offloaded policy with
	 * nothing else. Under `auto`, an outbound SA the adapter refused is
	 * installed in software, and the policy asked for next must go to
	 * software with it, or every packet it matches waits on an acquire. */
	struct xfrm_state *x = outbound_state();
	x->props.reqid = 7;
	bench_clear_sas();
	assert(ft_xdo_state_add(x, &ack) == 0);
	policy.xdo.dir = XFRM_DEV_OFFLOAD_OUT;
	policy.xfrm_nr = 1;
	policy.xfrm_vec[0] = (struct xfrm_tmpl){
		.id = { .daddr.a4 = PEER_IP, .spi = x->id.spi, .proto = IPPROTO_ESP },
		.saddr.a4 = LOCAL_IP, .reqid = 7, .mode = XFRM_MODE_TUNNEL,
		.encap_family = AF_INET };
	assert(ft_xdo_policy_add(&policy, &ack) == 0);
	/* The same SA by SPI alone, as a transport template leaves the
	 * address to the flow. */
	policy.xfrm_vec[0].id.daddr.a4 = 0;
	assert(ft_xdo_policy_add(&policy, &ack) == 0);
	policy.xfrm_vec[0].id.daddr.a4 = PEER_IP;

	/* Anything that would not pair is refused, and says why: an SPI the
	 * adapter never took, another peer, another reqid, mode, family, a
	 * transform that is not ESP (AH carrying the held ESP SA's SPI), or
	 * the SA held on another device than the policy's. */
	struct xfrm_tmpl good = policy.xfrm_vec[0];
	for (int miss = 0; miss < 7; miss++) {
		policy.xfrm_vec[0] = good;
		switch (miss) {
		case 0: policy.xfrm_vec[0].id.spi ^= 1; break;
		case 1: policy.xfrm_vec[0].id.daddr.a4 ^= 1; break;
		case 2: policy.xfrm_vec[0].reqid = 8; break;
		case 3: policy.xfrm_vec[0].mode = XFRM_MODE_TRANSPORT; break;
		case 4: policy.xfrm_vec[0].encap_family = AF_INET6; break;
		case 5: policy.xdo.dev = &LAN; break;
		case 6: policy.xfrm_vec[0].id.proto = IPPROTO_AH; break;
		}
		ack._msg = NULL;
		assert(ft_xdo_policy_add(&policy, &ack) == -EOPNOTSUPP);
		assert(ack._msg && strstr(ack._msg, "not offloaded to its device"));
		policy.xdo.dev = &WAN;
	}
	/* Every template that names an SPI has to be served, not just one. */
	policy.xfrm_vec[0] = good;
	policy.xfrm_vec[1] = good;
	policy.xfrm_vec[1].id.spi ^= 1;
	policy.xfrm_nr = 2;
	assert(ft_xdo_policy_add(&policy, &ack) == -EOPNOTSUPP);
	policy.xfrm_nr = 1;

	/* A template naming no SPI -- a trap policy, installed before any SA
	 * exists -- is taken as before, and so is an inbound policy, which
	 * xfrm checks against the states that decrypted a packet whatever
	 * their offload. */
	policy.xfrm_vec[0].id.spi = 0;
	assert(ft_xdo_policy_add(&policy, &ack) == 0);
	policy.xfrm_vec[0] = good;
	policy.xfrm_vec[0].id.spi ^= 1;
	policy.xdo.dir = XFRM_DEV_OFFLOAD_IN;
	assert(ft_xdo_policy_add(&policy, &ack) == 0);

	/* Once the SA is deleted the policy naming it goes to software too. */
	policy.xdo.dir = XFRM_DEV_OFFLOAD_OUT;
	policy.xfrm_vec[0] = good;
	ft_xdo_state_delete(x);
	assert(ft_xdo_policy_add(&policy, &ack) == -EOPNOTSUPP);
	bench_clear_sas();

	/* An inbound SA is not what an outbound policy selects, even one the
	 * adapter holds under the SPI, reqid and mode the template names, with
	 * no address in the template to tell them apart. */
	bench_reset();
	x->xso.dir = XFRM_DEV_OFFLOAD_IN;
	x->props.mode = XFRM_MODE_TRANSPORT;
	assert(ft_xdo_state_add(x, &ack) == 0);
	policy.xfrm_vec[0] = good;
	policy.xfrm_vec[0].mode = XFRM_MODE_TRANSPORT;
	policy.xfrm_vec[0].id.daddr.a4 = 0;
	ack._msg = NULL;
	assert(ft_xdo_policy_add(&policy, &ack) == -EOPNOTSUPP);
	assert(ack._msg && strstr(ack._msg, "not offloaded to its device"));
	ft_xdo_state_delete(x);
	bench_clear_sas();
	x->xso.dir = XFRM_DEV_OFFLOAD_OUT;
	x->props.mode = XFRM_MODE_TUNNEL;
	x->props.reqid = 0;
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

/* The adapter's own list of the SAs it holds, as ft_xdo_state_add() keeps it:
 * each added at the tail, so the tail is the most recently installed. */
static struct ft_ipsec_retirement owned_slots[FT_IPSEC_PAIRED_MAX + 2];
static void own(unsigned slot, struct xfrm_state *x)
{
	owned_slots[slot].x = x;
	owned_slots[slot].sa = (struct cdx_ipsec_sa *)x->xso.offload_handle;
	list_add_tail(&owned_slots[slot].list, &ft_ipsec_owned);
}
static void disown_all(void)
{
	while (!list_empty(&ft_ipsec_owned))
		list_del(ft_ipsec_owned.next);
}

/* An offloaded inbound half of `out` on `dev`, for child SA `reqid`. */
static void inbound_half(struct xfrm_state *in, const struct xfrm_state *out,
			 struct net_device *dev, struct cdx_ipsec_sa *sa, u16 handle,
			 u32 reqid)
{
	memset(in, 0, sizeof(*in));
	in->props.saddr = out->id.daddr;
	in->id.daddr = out->props.saddr;
	in->props.family = out->props.family;
	in->props.mode = XFRM_MODE_TUNNEL;
	in->props.reqid = reqid;
	in->id.proto = IPPROTO_ESP;
	in->id.spi = 0x0b000000 | reqid;
	in->xso.type = XFRM_DEV_OFFLOAD_PACKET;
	in->xso.dir = XFRM_DEV_OFFLOAD_IN;
	in->xso.dev = dev;
	in->xso.offload_handle = (unsigned long)sa;
	sa->handle = handle;
	in->km.state = XFRM_STATE_VALID;
}

/* The forwarding policy for the receiving end's tuple, whose one template
 * takes child SA `reqid` between the two ends of `in`. */
static void forwarding_policy(struct xfrm_policy *pol, const struct xfrm_state *in, u32 reqid)
{
	memset(pol, 0, sizeof(*pol));
	pol->xfrm_nr = 1;
	pol->xfrm_vec[0] = (struct xfrm_tmpl){ .mode = XFRM_MODE_TUNNEL, .reqid = reqid,
		.id.proto = IPPROTO_ESP, .allalgs = true };
	pol->xfrm_vec[0].id.daddr = in->id.daddr;
	pol->xfrm_vec[0].saddr = in->props.saddr;
	receiving_policy = pol;
	receiving_family = AF_INET;
	receiving_oif = WAN.ifindex;
}

static u16 paired(const struct xfrm_state *out, const struct ft_ipsec_receiver *recv,
		  bool *ok)
{
	struct xfrm_state *received = NULL;
	u16 handle = 0xffff;

	*ok = ft_ipsec_paired_inbound(out, recv, &handle, &received);
	/* The state named comes back held, and only when one is named. */
	assert(!!received == (*ok && handle));
	if (received)
		xfrm_state_put(received);
	assert(xfrm_state_refs == 0);
	return handle;
}

static void test_paired_inbound(void)
{
	struct xfrm_state *out = outbound_state();
	struct ft_ipsec_receiver recv = { .in = &LAN, .family = AF_INET };
	struct xfrm_state older, newer, many[FT_IPSEC_PAIRED_MAX + 1];
	struct cdx_ipsec_sa many_sa[FT_IPSEC_PAIRED_MAX + 1];
	struct xfrm_policy pol;
	bool ok;

	bench_reset();
	disown_all();
	recv.fl.flowi_oif = WAN.ifindex;

	/* No inbound half at all: the far end sends in the clear, which is
	 * unusual but legal, and the direction installs with no handle. */
	paired_state = NULL;
	assert(paired(out, &recv, &ok) == 0 && ok);

	/* The mirrored half, offloaded on the ingress port and taking the
	 * tuple: the forwarding policy's template is its child SA. */
	inbound_half(&older, out, &LAN, &sa_pool[0], 7, 42);
	own(0, &older);
	forwarding_policy(&pol, &older, 42);
	assert(paired(out, &recv, &ok) == 7 && ok);
	assert(!pol.refs);

	/* One whose selector does not cover the tuple is not the SA the kernel
	 * would accept it from. With no other, xfrm's own index still names an
	 * offloaded half, so the direction is a plain one to the caller, whose
	 * policy check then decides; the entry is never keyed on an SA that
	 * does not take the tuple. */
	older.sel.mismatch = true;
	paired_state = &older;
	assert(paired(out, &recv, &ok) == 0 && ok);
	older.sel.mismatch = false;

	/* Two child SAs between the same endpoints, the newer for other
	 * traffic selectors: the one named is the one the policy takes, not
	 * the most recent. xfrm's own index would have answered the newer. */
	inbound_half(&newer, out, &LAN, &sa_pool[1], 8, 43);
	own(1, &newer);
	paired_state = &newer;
	assert(paired(out, &recv, &ok) == 7 && ok);

	/* A rekey: both halves of one child SA take the tuple, and the newer
	 * is the one the peer moves to. */
	newer.props.reqid = 42;
	assert(paired(out, &recv, &ok) == 8 && ok);

	/* The newer one already being deleted has no handle to name any more;
	 * the older one still does. */
	newer.xso.offload_handle = 0;
	assert(paired(out, &recv, &ok) == 7 && ok);
	newer.xso.offload_handle = (unsigned long)&sa_pool[1];

	/* Dead, or behind a mark the outbound SA's own would not select, is
	 * not a candidate either. */
	newer.km.state = XFRM_STATE_DEAD;
	assert(paired(out, &recv, &ok) == 7 && ok);
	newer.km.state = XFRM_STATE_VALID;
	newer.mark.m = 0xff;
	newer.mark.v = 2;
	assert(paired(out, &recv, &ok) == 7 && ok);
	newer.mark.m = newer.mark.v = 0;

	/* The receiving policy refusing every half leaves nothing named. */
	pol.action = 1;
	assert(paired(out, &recv, &ok) == 0 && ok);
	pol.action = 0;
	disown_all();

	/* No more than FT_IPSEC_PAIRED_MAX, newest first: past that the
	 * oldest's flows stay in software rather than grow the admission. */
	for (unsigned i = 0; i <= FT_IPSEC_PAIRED_MAX; i++) {
		memset(&many_sa[i], 0, sizeof(many_sa[i]));
		inbound_half(&many[i], out, &LAN, &many_sa[i], 100 + i, i ? 50 : 42);
		own(i, &many[i]);
	}
	paired_state = &many[FT_IPSEC_PAIRED_MAX];
	assert(paired(out, &recv, &ok) == 0 && ok);
	many[1].props.reqid = 42;
	assert(paired(out, &recv, &ok) == 101 && ok);
	disown_all();
	receiving_policy = NULL;

	/* One that exists and cannot be named is a refusal, not an absence:
	 * its frames are decrypted before they could match this tuple, so an
	 * entry keyed on the physical port would be installed, counted, and
	 * never match a frame. A software state is never one of the adapter's
	 * own; xfrm's index is what finds it. */
	older.xso.type = XFRM_DEV_OFFLOAD_UNSPECIFIED;
	paired_state = &older;
	assert(paired(out, &recv, &ok) == 0 && !ok);
	older.xso.type = XFRM_DEV_OFFLOAD_PACKET;

	/* On another port, dead, or facing the wrong way is the same refusal,
	 * whether or not the adapter holds it. */
	own(0, &older);
	older.xso.dev = &WAN;
	assert(paired(out, &recv, &ok) == 0 && !ok);
	older.xso.dev = &LAN;
	older.km.state = XFRM_STATE_DEAD;
	assert(paired(out, &recv, &ok) == 0 && !ok);
	older.km.state = XFRM_STATE_VALID;
	older.xso.dir = XFRM_DEV_OFFLOAD_OUT;
	assert(paired(out, &recv, &ok) == 0 && !ok);
	disown_all();

	assert(xfrm_state_refs == 0);
	paired_state = NULL;
	sa_pool[0].handle = sa_pool[1].handle = 0;
}

static void test_resolve(void)
{
	struct xfrm_state *x = outbound_state();
	struct dst_entry plain = { .ops = &v4_ops, .refs = 1 };
	struct dst_entry bundle = { .ops = &v4_ops, .xfrm = x };
	struct ft_ipsec_receiver recv = { .in = &LAN, .family = AF_INET };
	struct flowi fl;
	u16 handle;

	bench_reset();
	memset(&fl, 0, sizeof(fl));
	fl.flowi_oif = WAN.ifindex;
	x->xso.offload_handle = (unsigned long)&sa_pool[0];
	sa_pool[0].handle = 5;

	/* No destination at all is not a refusal: a direction with nothing to
	 * ask about is a plain one. */
	assert(ft_ipsec_resolve(NULL, &fl, &WAN, NULL, &handle, NULL, 0, NULL, NULL));
	assert(handle == 0);

	/* A carried transform must not preserve a policy that has since been
	 * removed. Resolve the current policy from its underlying route. */
	{
		struct dst_entry under = { .ops = &v4_ops, .refs = 1 };
		struct dst_entry carried = { .ops = &v4_ops, .xfrm = x,
					     .child = &under, .refs = 1 };

		assert(ft_ipsec_resolve(&carried, &fl, &WAN, NULL, &handle, NULL, 0, NULL, NULL));
		assert(handle == 0 && policy_lookups == 1 && under.refs == 1);
		assert(carried.refs == 1);	/* borrowed, and given back */
	}

	/* No policy covers the tuple: an ordinary plain end, with the
	 * reference taken to ask handed back. */
	assert(ft_ipsec_resolve(&plain, &fl, &WAN, NULL, &handle, NULL, 0, NULL, NULL));
	assert(handle == 0 && plain.refs == 1 && policy_lookups == 2);

	/* Nothing resolved, but under a template -- an optional one whose SA
	 * does not exist yet (A306). Sent in hardware it would stay plain once
	 * the SA appears, where Linux encrypts; so it is refused. The far end's
	 * frames arrive plain either way, and policy accepts them. */
	out_template_unresolved = true;
	assert(!ft_ipsec_resolve(&plain, &fl, &WAN, NULL, &handle, NULL, 0, NULL, NULL));
	assert(handle == 0 && plain.refs == 1);
	assert(ft_ipsec_resolve(&plain, &fl, &LAN, &recv, &handle, NULL, 0, NULL, NULL));
	assert(plain.refs == 1);
	/* Unless the route's device has disable_xfrm: Linux then sends by it
	 * without asking policy, and so does hardware. */
	out_plain_asks = 0;
	plain.flags = DST_NOXFRM;
	assert(ft_ipsec_resolve(&plain, &fl, &WAN, NULL, &handle, NULL, 0, NULL, NULL));
	assert(plain.refs == 1 && out_plain_asks == 0);
	plain.flags = 0;
	out_template_unresolved = false;
	policy_lookups = 2;

	/* A policy resolving to an offloaded SA. The bundle takes over the
	 * caller's reference to the destination, and releasing the bundle has
	 * to leave the borrowed destination exactly as it was found. */
	policy_answer(WAN.ifindex, &bundle);
	bundle.refs = 0;
	assert(ft_ipsec_resolve(&plain, &fl, &WAN, NULL, &handle, NULL, 0, NULL, NULL));
	assert(handle == 5);
	assert(plain.refs == 1 && bundle.refs == 0);

	/* A policy that matched and resolved to nothing usable is a refusal
	 * at the sending end. Installing past it would forward in hardware
	 * what the policy says to encrypt, and the policy would never get a
	 * say -- which is how fifty-nine packets went out in the clear. */
	memset(policy_answers, 0, sizeof(policy_answers));
	policy_error = -EINVAL;
	assert(!ft_ipsec_resolve(&plain, &fl, &WAN, NULL, &handle, NULL, 0, NULL, NULL));
	assert(plain.refs == 1);

	/* The same answer at the receiving end is not a refusal: nothing has
	 * been decrypted, so nothing is arriving that this tuple could miss. */
	assert(ft_ipsec_resolve(&plain, &fl, &LAN, &recv, &handle, NULL, 0, NULL, NULL));
	policy_error = 0;

	/* A policy resolving to a transform the hardware cannot carry refuses
	 * the sending end for the same reason, and leaves the receiving end
	 * to install plain. */
	policy_answer(WAN.ifindex, &bundle);
	bundle.refs = 0;
	x->xso.type = XFRM_DEV_OFFLOAD_CRYPTO;
	assert(!ft_ipsec_resolve(&plain, &fl, &WAN, NULL, &handle, NULL, 0, NULL, NULL));
	assert(plain.refs == 1 && bundle.refs == 0);
	bundle.refs = 0;
	assert(ft_ipsec_resolve(&plain, &fl, &LAN, &recv, &handle, NULL, 0, NULL, NULL));
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
#ifdef FT_SOCKET_POLICY_EXEMPT
		/* A socket's own policy governs that socket's packets and never a
		 * forwarded one, however it is marked. */
		pol.index = 8 + XFRM_POLICY_MAX + XFRM_POLICY_OUT;
		assert(xfrm_flowtable_policy_check(&init_net, &fl, families[f], NULL));
		pol.index = 8 + XFRM_POLICY_FWD;
		assert(!xfrm_flowtable_policy_check(&init_net, &fl, families[f], NULL));
#endif
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
	struct dst_entry forward = { .ops = &v4_ops, .dev = &WAN, .refs = 1 };
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
	ft_ipsec_flowi(&rule, false, &WAN, 0x20, &fl);
	assert(fl.u.ip4.saddr == rule.new_src.ip && fl.u.ip4.daddr == rule.new_dst.ip);
	assert(fl.u.ip4.fl4_sport == 3000 && fl.u.ip4.fl4_dport == 4000);
	assert(fl.flowi_oif == WAN.ifindex && fl.flowi_proto == IPPROTO_TCP);
	/* And the mark the packets carry, which a selector can name too. */
	assert(fl.flowi_mark == 0x20);

	/* Receiving asks about the untranslated pair, inverted, because that
	 * is what the peer addressed. */
	ft_ipsec_flowi(&rule, true, &LAN, 0, &fl);
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
	/* The sending end carries the bound the SA puts on it over the path
	 * its frames take now -- the bundle's outer route -- and what SEC adds
	 * there: AES-CBC with HMAC-MD5-96 on a 1500-byte path is 1438 and 62.
	 * A narrower path, a 1492-byte hop or a PMTU learned for the peer,
	 * narrows it; the SA's own figures, from its install, would not. */
	assert(rule.sa_mtu == 1438 && rule.sa_expansion == 62);
	forward.mtu = 1492;
	bundle.refs = 0;
	assert(ft_ipsec_handle(&cls, &rule, &WAN, &LAN));
	assert(rule.sa_mtu == 1422 && rule.sa_expansion == 70);
	/* So does a port narrower than its route, which a bridge whose MTU was
	 * raised above its port's leaves the route unaware of (A340). */
	forward.mtu = 9000;
	port_mtu = 1492;
	bundle.refs = 0;
	assert(ft_ipsec_handle(&cls, &rule, &WAN, &LAN));
	assert(rule.sa_mtu == 1422 && rule.sa_expansion == 70);
	port_mtu = 65535;
	forward.mtu = 1492;
	/* An expansion past the byte the classifier carries it in is refused
	 * rather than wrapped, the generation with it. */
	x->props.header_len = 300;
	bundle.refs = 0;
	assert(!ft_ipsec_handle(&cls, &rule, &WAN, &LAN));
	assert(!handle.valid);
	x->props.header_len = CBC_TUNNEL_HEADER;
	forward.mtu = 0;
	handle.valid = true;
	ft_admission_invalidations = 0;

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
	in.props.family = AF_INET;
	in.id.proto = IPPROTO_ESP;
	in.xso.type = XFRM_DEV_OFFLOAD_PACKET;
	in.xso.dir = XFRM_DEV_OFFLOAD_IN;
	in.xso.dev = &LAN;
	in.xso.offload_handle = (unsigned long)&sa_pool[1];
	sa_pool[1].handle = 9;
	in.km.state = XFRM_STATE_VALID;
	own(0, &in);
	paired_state = &in;
	bundle.refs = back_bundle.refs = 0;
	assert(ft_ipsec_handle(&cls, &rule, &WAN, &LAN));
	assert(rule.sa_handle == 5 && rule.in_sa_handle == 9);
	assert(forward.refs == 1 && reverse.refs == 1);
	/* Asked about the tuple as it arrives: what the peer addressed, on its
	 * way in by the ingress port and out by the egress one. */
	assert(receiving_query.u.ip4.saddr == rule.src.ip &&
	       receiving_query.u.ip4.daddr == rule.dst.ip);
	assert(receiving_query.flowi_iif == LAN.ifindex &&
	       receiving_query.flowi_oif == WAN.ifindex);

	/* An inbound SA that exists and cannot be named refuses the whole
	 * direction rather than installing an entry nothing will match: its
	 * frames are decrypted on the offline port before they could reach a
	 * rule keyed on the physical one. */
	in.xso.dev = &WAN;
	bundle.refs = back_bundle.refs = 0;
	assert(!ft_ipsec_handle(&cls, &rule, &WAN, &LAN));
	assert(forward.refs == 1 && reverse.refs == 1);

	disown_all();
	paired_state = NULL;
	sa_pool[0].handle = sa_pool[1].handle = sa_pool[2].handle = 0;
}

/* Whether one of the questions asked so far was about this IPv4 tuple leaving
 * by this device. */
static bool policy_asked(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport,
			 int oif)
{
	for (unsigned i = 0; i < policy_lookups && i < POLICY_QUERIES; i++) {
		const struct flowi *fl = &policy_queries[i];

		if (fl->u.ip4.saddr == saddr && fl->u.ip4.daddr == daddr &&
		    fl->u.ip4.fl4_sport == sport && fl->u.ip4.fl4_dport == dport &&
		    fl->flowi_oif == oif)
			return true;
	}
	return false;
}

/* ip_forward() asks OUT policy once before NF_INET_FORWARD, about the tuple
 * between the translations -- DNAT done, this direction's SNAT not yet -- and
 * drops what policy refuses there. A direction its own SNAT translates asks
 * nothing else about that tuple, so a block naming the LAN source must refuse
 * it here too, or the hardware forwards what the slow path drops. */
static void test_handle_between_translations(void)
{
	struct dst_entry forward = { .ops = &v4_ops, .dev = &WAN, .refs = 1 };
	struct dst_entry reverse = { .ops = &v4_ops, .refs = 1 };
	struct nf_flow_offload_handle handle = { .valid = true };
	struct flow_cls_offload cls;
	struct cdx_ft_rule rule;
	struct nf_conn ct = {};

	bench_reset();
	memset(policy_answers, 0, sizeof(policy_answers));
	memset(&rule, 0, sizeof(rule));
	memset(&cls, 0, sizeof(cls));
	rule.family = AF_INET;
	rule.proto = IPPROTO_UDP;
	rule.in = rule.in_logical = &LAN;
	rule.out = rule.out_logical = &WAN;
	rule.src.ip = 0x0201a8c0;
	rule.dst.ip = 0x0301a8c0;
	rule.new_src.ip = 0x0401a8c0;
	rule.new_dst.ip = 0x0501a8c0;
	rule.sport = 1000;
	rule.dport = 2000;
	rule.new_sport = 3000;
	rule.new_dport = 4000;
	cls.nf_dst = &forward;
	cls.nf_dst_reverse = &reverse;
	cls.nf_ct = &ct;
	cls.nf_handle = &handle;

	/* No policy: admitted, having asked about the LAN source going to the
	 * translated destination by the egress port. Every question carries
	 * the connection's mark, as the packets do. */
	ct.mark = 0x20;
	policy_lookups = 0;
	assert(ft_ipsec_handle(&cls, &rule, &WAN, &LAN));
	assert(policy_asked(rule.src.ip, rule.new_dst.ip, rule.sport, rule.new_dport,
			    WAN.ifindex));
	for (unsigned i = 0; i < policy_lookups && i < POLICY_QUERIES; i++)
		assert(policy_queries[i].flowi_mark == 0x20);
	ct.mark = 0;
	assert(forward.refs == 1 && reverse.refs == 1);

	/* A block on that source refuses the direction and its generation. */
	policy_block_saddr = rule.src.ip;
	ft_admission_invalidations = 0;
	assert(!ft_ipsec_handle(&cls, &rule, &WAN, &LAN));
	assert(!handle.valid && ft_admission_invalidations == 1);
	assert(forward.refs == 1 && reverse.refs == 1);
	handle.valid = true;
	policy_block_saddr = 0;

	/* Whatever transform that tuple finds is the slow path's to discard: its
	 * POSTROUTING asks again about the translated tuple, which is the sending
	 * question. A bundle there is no refusal. */
	{
		struct xfrm_state *x = outbound_state();
		struct dst_entry bundle = { .ops = &v4_ops, .xfrm = x };

		x->xso.offload_handle = (unsigned long)&sa_pool[0];
		sa_pool[0].handle = 5;
		policy_answer(WAN.ifindex, &bundle);
		assert(ft_ipsec_handle(&cls, &rule, &WAN, &LAN) && rule.sa_handle == 5);
		assert(!bundle.refs && forward.refs == 1 && reverse.refs == 1);
		memset(policy_answers, 0, sizeof(policy_answers));
		sa_pool[0].handle = 0;
	}

	/* Without SNAT the tuple between the translations is the one that
	 * leaves, already asked: no further question. */
	rule.new_src = rule.src;
	rule.new_sport = rule.sport;
	policy_lookups = 0;
	assert(ft_ipsec_handle(&cls, &rule, &WAN, &LAN));
	assert(policy_lookups == 3);
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

	/* An IPv6 peer is followed through neighbour discovery's table, by
	 * its whole address; an ARP entry whose first four bytes happen to
	 * match it is not its neighbour. */
	bench_reset();
	peer_neigh.tbl = &nd_tbl;
	memcpy(peer_neigh.primary_key, &PEER6, sizeof(PEER6));
	*x = *outbound_state();
	outbound6(x);
	assert(ft_xdo_state_add(x, &(struct netlink_ext_ack){ NULL }) == 0);
	ft_ipsec_follow_work(NULL);
	works_scheduled = sa_next_hop_calls = 0;
	other = peer_neigh;
	other.tbl = &arp_tbl;
	memcpy(other.primary_key, &PEER6, sizeof(PEER6));
	ether_addr_copy(other.ha, MOVED_MAC);
	ft_ipsec_neigh_moved(&other);
	assert(works_scheduled == 0);
	other.tbl = &nd_tbl;
	other.primary_key[15] = 0x7b;
	ft_ipsec_neigh_moved(&other);
	assert(works_scheduled == 0);
	other.primary_key[15] = 0x7a;
	ft_ipsec_neigh_moved(&other);
	assert(works_scheduled == 1);
	ft_xdo_state_delete(x);
	bench_clear_sas();
}

/* A peer beyond a router is addressed to the router, and it is the router's
 * neighbour entry whose move has to be followed: an event for the peer's own
 * address never comes, since nothing on this link resolves it. */
static void test_watch_follows_gateway(void)
{
	struct neighbour gateway, peer;
	struct xfrm_state state;
	struct xfrm_state *x;

	bench_reset();
	bench_clear_sas();
	gateway = peer = peer_neigh;
	gateway.primary_key[3] = 254;		/* 192.168.1.254 */
	gateway.refs = 0;
	route_neigh = &gateway;
	x = install_outbound(&state);
	assert(ether_addr_equal(sa_pool[0].dst_mac, PEER_MAC));

	/* The peer's own address moving says nothing about this link. */
	ether_addr_copy(peer.ha, MOVED_MAC);
	ft_ipsec_neigh_moved(&peer);
	assert(works_scheduled == 0);

	/* The router moving is followed, and the SA rebuilt onto it. */
	ether_addr_copy(gateway.ha, MOVED_MAC);
	ft_ipsec_neigh_moved(&gateway);
	assert(works_scheduled == 1);
	ft_ipsec_follow_work(NULL);
	assert(sa_next_hop_calls == 1 && ether_addr_equal(sa_pool[0].dst_mac, MOVED_MAC));

	/* A pass that finds the route but can have no neighbour entry -- the
	 * table full -- says nothing about the router, which the watch keeps:
	 * the router's own answer is still what retries it. */
	route_neigh = NULL;
	ft_ipsec_route_moved(AF_INET, &(__be32){ PEER_IP }, 0xffffffff, 32);
	ft_ipsec_follow_work(NULL);
	route_neigh = &gateway;
	works_scheduled = 0;
	ether_addr_copy(gateway.ha, PEER_MAC);
	ft_ipsec_neigh_moved(&gateway);
	assert(works_scheduled == 1);
	ft_ipsec_follow_work(NULL);
	assert(ether_addr_equal(sa_pool[0].dst_mac, PEER_MAC));
	ether_addr_copy(gateway.ha, MOVED_MAC);
	ft_ipsec_neigh_moved(&gateway);
	ft_ipsec_follow_work(NULL);
	assert(ether_addr_equal(sa_pool[0].dst_mac, MOVED_MAC));

	/* The route then moves to another router: the watch follows the new
	 * one's events from the pass that found it. */
	route_neigh = &peer_neigh;
	ft_ipsec_route_moved(AF_INET, &(__be32){ PEER_IP }, 0xffffffff, 32);
	ft_ipsec_follow_work(NULL);
	assert(ether_addr_equal(sa_pool[0].dst_mac, PEER_MAC));
	works_scheduled = 0;
	ether_addr_copy(gateway.ha, PEER_MAC);
	ft_ipsec_neigh_moved(&gateway);
	assert(works_scheduled == 0);
	ether_addr_copy(peer_neigh.ha, MOVED_MAC);
	ft_ipsec_neigh_moved(&peer_neigh);
	assert(works_scheduled == 1);
	ft_ipsec_follow_work(NULL);
	assert(dev_holds == 0 && neigh_refs == 0 && gateway.refs == 0);
	ft_xdo_state_delete(x);
	bench_clear_sas();
}

/* The watch re-resolves with what the install resolved with: the SA's mark,
 * protocol and ports, not only its addresses. */
static void test_watch_routes_like_install(void)
{
	struct xfrm_encap_tmpl natt = { .encap_type = UDP_ENCAP_ESPINUDP,
					.encap_sport = htons(4500), .encap_dport = htons(61000) };
	struct netlink_ext_ack ack = { NULL };
	struct xfrm_state state;

	bench_reset();
	bench_clear_sas();
	state = *outbound_state();
	state.encap = &natt;
	state.props.smark.v = 0x70;
	state.props.smark.m = 0xf0;
	assert(ft_xdo_state_add(&state, &ack) == 0);
	/* The watch starts stale, so this pass is the re-resolution. */
	memset(&route_key, 0, sizeof(route_key));
	route_lookups = 0;
	ft_ipsec_follow_work(NULL);
	assert(route_lookups == 1);
	assert(route_key.flowi4_mark == 0x70 && route_key.flowi4_proto == IPPROTO_UDP);
	assert(route_key.fl4_sport == htons(4500) && route_key.fl4_dport == htons(61000));
	works_scheduled = 0;
	ft_xdo_state_delete(&state);
	bench_clear_sas();
}

/* An egress change landing while an SA is being installed. The build may have
 * read the port's queues from before it, and the watch the change would mark
 * is not listed yet, so nothing but the install can notice: it compares the
 * change count across the build and publishes its watch asking for the rebuild
 * itself. A caller draining the change finds it outstanding. */
static void test_watch_egress_change_during_install(void)
{
	struct netlink_ext_ack ack = { NULL };
	struct xfrm_state state;

	bench_reset();
	bench_clear_sas();
	state = *outbound_state();
	egress_change_during_add = &WAN;
	assert(ft_xdo_state_add(&state, &ack) == 0);
	egress_change_during_add = NULL;
	assert(ft_ipsec_rebuild_pending(&WAN) && !ft_ipsec_rebuild_pending(&LAN));
	assert(works_scheduled == 1 && sa_next_hop_calls == 0);
	/* Neither address moved, and the rebuild happens anyway. */
	ft_ipsec_follow_work(NULL);
	assert(sa_next_hop_calls == 1 && !ft_ipsec_rebuild_pending(&WAN));
	assert(dev_holds == 0 && !ft_transaction);
	ft_xdo_state_delete(&state);
	bench_clear_sas();

	/* A change on another port is not this SA's, but the count is global:
	 * the install asks for a rebuild it did not need, which costs one
	 * rewrite of an unchanged entry and nothing else. */
	bench_reset();
	state = *outbound_state();
	egress_change_during_add = &LAN;
	assert(ft_xdo_state_add(&state, &ack) == 0);
	egress_change_during_add = NULL;
	assert(ft_ipsec_rebuild_pending(&WAN));
	ft_ipsec_follow_work(NULL);
	assert(sa_next_hop_calls == 1 && !ft_ipsec_rebuild_pending(&WAN));
	ft_xdo_state_delete(&state);
	bench_clear_sas();

	/* An install no change crossed publishes a watch asking for nothing:
	 * one check, no rebuild. */
	bench_reset();
	state = *outbound_state();
	assert(ft_xdo_state_add(&state, &ack) == 0);
	assert(!ft_ipsec_rebuild_pending(&WAN));
	ft_ipsec_follow_work(NULL);
	assert(sa_next_hop_calls == 0);
	ft_xdo_state_delete(&state);
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
	assert(!ft_ipsec_rebuild_pending(&LAN) && !ft_ipsec_rebuild_pending(&WAN));
	ft_ipsec_egress_changed(&WAN);
	assert(works_scheduled == 1);
	/* Outstanding until the rebuild happens, and only on its own port: a
	 * caller waiting on the change -- the DSCP map leaving the port --
	 * asks exactly this. */
	assert(ft_ipsec_rebuild_pending(&WAN) && !ft_ipsec_rebuild_pending(&LAN));
	ft_ipsec_follow_work(NULL);
	assert(sa_next_hop_calls == 3);
	assert(!ft_ipsec_rebuild_pending(&WAN));
	ft_ipsec_follow_work(NULL);
	assert(sa_next_hop_calls == 3);
	/* A rebuild that fails stays outstanding. */
	route_neigh = NULL;
	ft_ipsec_egress_changed(&WAN);
	ft_ipsec_follow_work(NULL);
	assert(sa_next_hop_calls == 3 && ft_ipsec_rebuild_pending(&WAN));
	route_neigh = &peer_neigh;
	ft_ipsec_follow_work(NULL);
	assert(sa_next_hop_calls == 4 && !ft_ipsec_rebuild_pending(&WAN));
	/* Outstanding while the rebuild runs, too: a pass that has taken the
	 * watch on has not rebuilt anything yet, and a drain reading the flag
	 * then must not be told the change reached the hardware. */
	ft_ipsec_egress_changed(&WAN);
	pending_during_rebuild = &WAN;
	ft_ipsec_follow_work(NULL);
	pending_during_rebuild = NULL;
	assert(sa_next_hop_calls == 5 && !ft_ipsec_rebuild_pending(&WAN));
	/* A change landing while a rebuild runs asks for another: the one
	 * running may have read the port before it. */
	ft_ipsec_egress_changed(&WAN);
	egress_change_during_rebuild = &WAN;
	ft_ipsec_follow_work(NULL);
	egress_change_during_rebuild = NULL;
	assert(sa_next_hop_calls == 6 && ft_ipsec_rebuild_pending(&WAN));
	ft_ipsec_follow_work(NULL);
	assert(sa_next_hop_calls == 7 && !ft_ipsec_rebuild_pending(&WAN));
	WAN.dev_addr[5] = 4;

	/* Another port's address change is not this SA's business. */
	works_scheduled = 0;
	ft_ipsec_device_moved(&LAN);
	assert(works_scheduled == 0);

	ft_xdo_state_delete(x);
	bench_clear_sas();
}

/* Flows riding the bench SA, on the list a moved path is looked up on: one
 * direction it encrypts, one it decrypts, and one another SA encrypts. */
static struct nf_flow_offload_handle sending_handle, receiving_handle, other_handle;
static struct cdx_ft_entry sending_flow = { .handle = &sending_handle };
static struct cdx_ft_entry receiving_flow = { .handle = &receiving_handle };
static struct cdx_ft_entry other_flow = { .handle = &other_handle };

static void flows_ride(u16 handle)
{
	ft_neigh_entries.next = ft_neigh_entries.prev = &ft_neigh_entries;
	sending_flow.rule.sa_handle = handle;
	receiving_flow.rule.in_sa_handle = handle;
	other_flow.rule.sa_handle = handle + 1;
	sending_handle.valid = receiving_handle.valid = other_handle.valid = true;
	list_add_tail(&sending_flow.neigh_list, &ft_neigh_entries);
	list_add_tail(&receiving_flow.neigh_list, &ft_neigh_entries);
	list_add_tail(&other_flow.neigh_list, &ft_neigh_entries);
	ft_mtu_invalidations = 0;
}

/* Whether the directions the SA encrypts were retired since the last ask,
 * counted as an MTU invalidation, with the one it decrypts and another SA's
 * left alone. Rearms them for the next ask. */
static bool flows_retired(void)
{
	bool retired = !sending_handle.valid;

	assert(receiving_handle.valid && other_handle.valid);
	assert(ft_mtu_invalidations == retired);
	sending_handle.valid = true;
	ft_mtu_invalidations = 0;
	return retired;
}

static void flows_leave(void)
{
	ft_neigh_entries.next = ft_neigh_entries.prev = &ft_neigh_entries;
}

/* The path an SA's frames take is framing too. Its MTU changing -- a route to
 * the peer with an MTU of its own, a port whose MTU changed, a PMTU learned
 * for the peer that nothing announces -- rebuilds the SA's entry to fragment
 * SEC's output to the new MTU, and retires the directions the SA encrypts,
 * whose bound came from the old path. */
static void test_watch_path_mtu(void)
{
	struct xfrm_state state;
	struct xfrm_state *x;

	bench_reset();
	bench_clear_sas();
	x = install_outbound(&state);
	assert(sa_pool[0].path_mtu == 1500);
	flows_ride(sa_pool[0].handle);

	/* A route to the peer through a narrower hop. The route event marks
	 * the watch; the work rebuilds and retires. */
	wan_route.dst.mtu = 1492;
	ft_ipsec_route_moved(AF_INET, &(__be32){ PEER_IP }, 0xffffffff, 32);
	assert(works_scheduled == 1);
	ft_ipsec_follow_work(NULL);
	assert(sa_next_hop_calls == 1 && sa_pool[0].path_mtu == 1492);
	assert(flows_retired());
	assert(ft_ipsec_next_hop_updates == 1);
	assert(dev_holds == 0 && neigh_refs == 0 && !ft_transaction && !ft_watch_lock);
	/* Settled: the same path again moves nothing. */
	ft_ipsec_all_moved();
	ft_ipsec_follow_work(NULL);
	assert(sa_next_hop_calls == 1 && !flows_retired());

	/* A rebuild that fails is retried, but the directions are retired
	 * once: their bound followed the path already. */
	wan_route.dst.mtu = 1400;
	sa_next_hop_error = -EIO;
	ft_ipsec_all_moved();
	ft_ipsec_follow_work(NULL);
	assert(sa_next_hop_calls == 2 && flows_retired() && sa_pool[0].path_mtu == 1492);
	sa_next_hop_error = 0;
	ft_ipsec_follow_work(NULL);
	assert(sa_next_hop_calls == 3 && !flows_retired() && sa_pool[0].path_mtu == 1400);

	/* A PMTU learned for the peer changes nothing any notifier reports;
	 * the accounting pass asks every SA's path again. */
	wan_route.dst.mtu = 1300;
	works_scheduled = 0;
	ft_ipsec_stats_work(NULL);
	assert(works_scheduled == 1);
	ft_ipsec_follow_work(NULL);
	assert(sa_next_hop_calls == 4 && flows_retired() && sa_pool[0].path_mtu == 1300);

	/* The port's MTU is the path's when the route carries none: lowered,
	 * it is followed from the device event, and never exceeded. */
	wan_route.dst.mtu = 0;
	WAN.mtu = 1480;
	works_scheduled = 0;
	ft_ipsec_device_moved(&WAN);
	assert(works_scheduled == 1);
	ft_ipsec_follow_work(NULL);
	assert(sa_next_hop_calls == 5 && flows_retired() && sa_pool[0].path_mtu == 1480);
	wan_route.dst.mtu = 9000;
	ft_ipsec_all_moved();
	ft_ipsec_follow_work(NULL);
	assert(sa_pool[0].path_mtu == 1480 && !flows_retired());

	flows_leave();
	WAN.mtu = 1500;
	wan_route.dst.mtu = 0;
	ft_xdo_state_delete(x);
	bench_clear_sas();
}

/* Accounting passes, each followed by whatever it queued, run as the
 * workqueue would; how many queued anything. */
static unsigned accounting_passes(unsigned n)
{
	unsigned queued = 0;

	while (n--) {
		unsigned before = works_scheduled;

		ft_ipsec_stats_work(NULL);
		if (works_scheduled != before) {
			queued++;
			ft_ipsec_follow_work(NULL);
		}
	}
	return queued;
}

/* The accounting pass asks the FIB, never the neighbour table.
 *
 * It samples every SA's path each period for the PMTU nothing announces, and
 * the whole re-resolution is the real triggers' -- a neighbour or route
 * event, a port's address or MTU. Asked every period instead, it would probe
 * a peer that is down once a second and retry a refused rebuild on the same
 * clock. A path that did move is followed once, even with the peer down: the
 * directions retire, the path is recorded, and the passes after it are
 * quiet until the peer answers. */
static void test_watch_sample_route_only(void)
{
	struct xfrm_state state;
	struct xfrm_state *x;
	unsigned queued;

	bench_reset();
	bench_clear_sas();
	x = install_outbound(&state);
	flows_ride(sa_pool[0].handle);

	/* A peer that has gone away, on a path that has not moved. */
	peer_neigh.nud_state = NUD_FAILED;
	neigh_lookups = neigh_probes = route_lookups = 0;
	queued = accounting_passes(5);
	assert(neigh_lookups == 0 && neigh_probes == 0 && neigh_refs == 0);
	assert(queued == 0 && route_lookups == 5 && wan_route.dst.refs == 0);
	assert(sa_next_hop_calls == 0 && dev_holds == 0 && !ft_watch_lock);

	/* A rebuild the backend refuses is not retried on the clock either. */
	sa_next_hop_error = -EBUSY;
	peer_neigh.nud_state = NUD_REACHABLE;
	ether_addr_copy(peer_neigh.ha, MOVED_MAC);
	ft_ipsec_neigh_moved(&peer_neigh);
	ft_ipsec_follow_work(NULL);
	assert(sa_next_hop_calls == 1 && works_scheduled == 1);
	neigh_lookups = 0;
	assert(accounting_passes(5) == 0);
	assert(sa_next_hop_calls == 1 && neigh_lookups == 0);
	sa_next_hop_error = 0;
	ether_addr_copy(peer_neigh.ha, PEER_MAC);

	/* The path narrows while the peer is down. The pass marks the watch
	 * once; the work retires the directions and records the path although
	 * nothing can be rebuilt, probing the peer that once and looking at it
	 * once more after. */
	peer_neigh.nud_state = NUD_FAILED;
	wan_route.dst.mtu = 1400;
	neigh_probes = 0;
	assert(accounting_passes(1) == 1);
	assert(flows_retired() && neigh_probes == 1 && neigh_lookups == 2);
	assert(sa_next_hop_calls == 1 && sa_pool[0].path_mtu == 1500);
	/* And the passes after it are quiet. */
	assert(accounting_passes(5) == 0);
	assert(neigh_probes == 1 && neigh_lookups == 2);
	assert(sa_next_hop_calls == 1 && !flows_retired());

	/* The peer answering is what brings the rebuild, at the new MTU, and
	 * retires nothing further. */
	peer_neigh.nud_state = NUD_REACHABLE;
	works_scheduled = 0;
	ft_ipsec_neigh_moved(&peer_neigh);
	assert(works_scheduled == 1);
	ft_ipsec_follow_work(NULL);
	assert(sa_next_hop_calls == 2 && sa_pool[0].path_mtu == 1400);
	assert(!flows_retired());

	/* No route to the peer says nothing about its path. */
	route_error = -ENETUNREACH;
	assert(accounting_passes(1) == 0 && dev_holds == 0);
	route_error = 0;

	flows_leave();
	wan_route.dst.mtu = 0;
	ft_xdo_state_delete(x);
	bench_clear_sas();
}

/* The route to the peer is the FIB's, never a policy's bundle.
 *
 * A policy whose selector covers the SA's own endpoints for its protocol --
 * transport mode between two hosts, any protocol, or a host-to-host tunnel --
 * answers ip_route_output_key() with the SA's own bundle. That leaves by the
 * port, and its MTU is the SA's inner bound, so an SA that took it for its
 * path would have its entry fragment or except every full-size frame leaving
 * SEC, from its install or from the next accounting pass. */
static void test_peer_route_is_the_fibs(void)
{
	struct xfrm_state state;
	struct xfrm_state *x;
	static struct rtable bundle;

	bench_reset();
	bench_clear_sas();
	/* As xfrm_lookup_route() would answer: over the port's route, with
	 * xfrm_mtu() for its MTU -- 1458 for an AES-CBC SA with a 12-byte ICV
	 * in transport mode on 1500 bytes. */
	bundle.dst = (struct dst_entry){ .ops = &v4_ops, .dev = &WAN, .xfrm = &state,
					 .child = &wan_route.dst, .mtu = 1458 };

	/* The policy arrives after the SA: neither the accounting pass nor a
	 * route event takes its bundle for the path. */
	x = install_outbound(&state);
	assert(sa_pool[0].path_mtu == 1500);
	route_bundle = &bundle;
	assert(accounting_passes(3) == 0);
	ft_ipsec_route_moved(AF_INET, &(__be32){ PEER_IP }, 0xffffffff, 32);
	ft_ipsec_follow_work(NULL);
	assert(sa_next_hop_calls == 0 && sa_pool[0].path_mtu == 1500);
	assert(dev_holds == 0 && wan_route.dst.refs == 0);
	ft_xdo_state_delete(x);
	bench_clear_sas();

	/* The policy is there first, as a trap policy is: the install does
	 * not take it either. */
	works_scheduled = 0;
	x = install_outbound(&state);
	assert(sa_pool[0].path_mtu == 1500);
	assert(accounting_passes(3) == 0 && sa_next_hop_calls == 0);

	route_bundle = NULL;
	ft_xdo_state_delete(x);
	bench_clear_sas();
}

/* A peer that answers between the work's probe and its mark.
 *
 * The work probes a peer that does not resolve and leaves the watch stale for
 * the neighbour event the answer raises; that event marks an unchanged
 * address only on a stale watch, and the work marks it after the probe. An
 * answer landing in between found it neither, and the SA kept the framing it
 * had -- here the old path's MTU -- until something else moved. */
static void test_watch_answer_during_probe(void)
{
	struct xfrm_state state;
	struct xfrm_state *x;

	bench_reset();
	bench_clear_sas();
	x = install_outbound(&state);
	flows_ride(sa_pool[0].handle);

	/* The path narrows while the peer is unresolved, and the peer answers
	 * the very probe the work sends for it. */
	peer_neigh.nud_state = NUD_FAILED;
	wan_route.dst.mtu = 1400;
	probe_answers = true;
	ft_ipsec_route_moved(AF_INET, &(__be32){ PEER_IP }, 0xffffffff, 32);
	assert(works_scheduled == 1);
	ft_ipsec_follow_work(NULL);
	assert(neigh_probes == 1 && sa_next_hop_calls == 0 && flows_retired());
	/* The work looked again and went round once more. */
	assert(works_scheduled == 2);
	probe_answers = false;
	ft_ipsec_follow_work(NULL);
	assert(sa_next_hop_calls == 1 && sa_pool[0].path_mtu == 1400 && !flows_retired());
	assert(neigh_probes == 1 && dev_holds == 0 && neigh_refs == 0 && !ft_watch_lock);

	/* A rebuild that fails with the peer resolved is not gone round
	 * again: it waits for an event, as a peer that stays down does. */
	wan_route.dst.mtu = 1300;
	sa_next_hop_error = -EBUSY;
	works_scheduled = 0;
	ft_ipsec_all_moved();
	ft_ipsec_follow_work(NULL);
	assert(sa_next_hop_calls == 2 && works_scheduled == 1 && flows_retired());
	peer_neigh.nud_state = NUD_FAILED;
	ft_ipsec_device_moved(&WAN);
	ft_ipsec_follow_work(NULL);
	assert(works_scheduled == 2 && sa_next_hop_calls == 2 && neigh_probes == 2);
	sa_next_hop_error = 0;

	/* A usable neighbour with no address resolves nothing, so the second
	 * look must not take it for an answer: the work would find the same
	 * entry and queue itself for ever. */
	peer_neigh.nud_state = NUD_REACHABLE;
	memset(peer_neigh.ha, 0, ETH_ALEN);
	works_scheduled = 0;
	ft_ipsec_device_moved(&WAN);
	assert(works_scheduled == 1);
	ft_ipsec_follow_work(NULL);
	assert(works_scheduled == 1 && sa_next_hop_calls == 2 && neigh_probes == 2);
	assert(neigh_refs == 0 && dev_holds == 0);

	flows_leave();
	wan_route.dst.mtu = 0;
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

/* Install an SA for the accounting cases, with its state as xfrm has it once
 * inserted: VALID, every limit unlimited, nothing counted yet. */
static struct xfrm_state *install_accounted(struct xfrm_state *x, bool outbound,
					    u8 flags)
{
	struct netlink_ext_ack ack = { NULL };

	*x = *outbound_state();
	x->props.flags |= flags;
	if (!outbound)
		x->xso.dir = XFRM_DEV_OFFLOAD_IN;
	assert(ft_xdo_state_add(x, &ack) == 0);
	return x;
}

static struct cdx_ipsec_sa *sa_of(const struct xfrm_state *x)
{
	return (struct cdx_ipsec_sa *)x->xso.offload_handle;
}

/* What __xfrm_state_delete() does around the device callback: the state is
 * DEAD, under x->lock, before the device hears of it. */
static void delete_state(struct xfrm_state *x)
{
	test_lock(&x->lock);
	x->km.state = XFRM_STATE_DEAD;
	ft_xdo_state_delete(x);
	test_unlock(&x->lock);
}

/* A deletion landing while the pass is inside its walk, between gathering an
 * SA and publishing its counters -- which on hardware is any other CPU, at
 * any moment the pass does not hold x->lock. */
static struct xfrm_state *deleted_mid_pass;
static void delete_during_read(struct cdx_ipsec_sa *sa)
{
	if (deleted_mid_pass && sa_of(deleted_mid_pass) == sa)
		delete_state(deleted_mid_pass);
}

static void test_accounting(void)
{
	struct xfrm_state out_state, in_state, void_state;
	struct xfrm_state *out, *in, *fresh;
	struct cdx_ipsec_sa *out_sa, *in_sa;
	unsigned checks, reads;

	bench_reset();
	bench_clear_sas();

	/* The first SA starts the pass, a period out rather than at once. */
	out = install_accounted(&out_state, true, 0);
	assert(stats_scheduled == 1);
	in = install_accounted(&in_state, false, 0);
	out_sa = sa_of(out);
	in_sa = sa_of(in);

	/* Nothing carried: nothing published and nothing judged -- asking
	 * would stamp use_time on an SA that was never used, and its use-based
	 * lifetimes would start counting from the install. The pass keeps
	 * itself going while SAs are owned, and gives back every reference and
	 * lock it took. */
	stats_scheduled = 0;
	ft_ipsec_stats_work(NULL);
	assert(sa_stats_reads == 2 && expire_checks == 0);
	assert(!out->curlft.packets && !out->curlft.use_time);
	assert(stats_scheduled == 1);
	assert(xfrm_state_refs == 0 && !ft_transaction && !ft_ipsec_retired_lock);

	/* SEC's counts reach curlft in both directions, and xfrm judges them
	 * with its own function -- which is what stamps use_time. */
	out_sa->packets = 10;
	out_sa->bytes = 15000;
	in_sa->packets = 7;
	in_sa->bytes = 9000;
	ft_ipsec_stats_work(NULL);
	assert(out->curlft.packets == 10 && out->curlft.bytes == 15000);
	assert(in->curlft.packets == 7 && in->curlft.bytes == 9000);
	assert(expire_checks == 2 && out->curlft.use_time == wall_clock);
	assert(!soft_expires && !hard_expires);

	/* Only the difference is added, so what xfrm counted by another hand --
	 * a lifetime carried in with the state, a NEWAE -- is kept. */
	out->curlft.packets += 100;
	out->curlft.bytes += 1000;
	out_sa->packets = 12;
	out_sa->bytes = 18000;
	ft_ipsec_stats_work(NULL);
	assert(out->curlft.packets == 112 && out->curlft.bytes == 19000);

	/* Only ever forward: totals below what was published add nothing --
	 * rather than wrapping curlft to a limit's worth of traffic -- and
	 * counting resumes from the published figure once they pass it. */
	out_sa->packets = 5;
	out_sa->bytes = 100;
	ft_ipsec_stats_work(NULL);
	assert(out->curlft.packets == 112 && out->curlft.bytes == 19000);
	out_sa->packets = 13;
	out_sa->bytes = 18500;
	ft_ipsec_stats_work(NULL);
	assert(out->curlft.packets == 113 && out->curlft.bytes == 19500);
	out_sa->packets = 12;
	out_sa->bytes = 18000;

	/* A soft limit fires once, through xfrm's own judge, however many
	 * passes see it crossed. */
	out->lft.soft_packet_limit = 150;
	out_sa->packets = 50;
	ft_ipsec_stats_work(NULL);
	assert(soft_expires == 1 && out->km.dying && !hard_expires);
	out_sa->packets = 60;
	ft_ipsec_stats_work(NULL);
	assert(soft_expires == 1);

	/* A hard limit expires the state and leaves its deletion to xfrm's
	 * timer, exactly as the software path does. */
	in->lft.hard_byte_limit = 10000;
	in_sa->packets = 8;
	in_sa->bytes = 10000;
	ft_ipsec_stats_work(NULL);
	assert(in->km.state == XFRM_STATE_EXPIRED && timers_started == 1);

	/* No longer VALID: nothing published into it, nothing judged. */
	checks = expire_checks;
	in_sa->packets = 9;
	in_sa->bytes = 11000;
	ft_ipsec_stats_work(NULL);
	assert(expire_checks == checks + 1);	/* the outbound one alone */
	assert(in->curlft.bytes == 10000 && in->curlft.packets == 8);
	assert(timers_started == 1);

	/* Deleted: the entry is off the owned list, so the pass does not even
	 * read the SA, which is waiting for its retirement. */
	delete_state(in);
	reads = sa_stats_reads;
	ft_ipsec_stats_work(NULL);
	assert(sa_stats_reads == reads + 1 && in_sa->live);

	/* A state not yet inserted -- xfrm_add_sa() installs the offload before
	 * it inserts -- is read but neither published into nor judged. */
	fresh = install_accounted(&void_state, false, 0);
	fresh->km.state = XFRM_STATE_VOID;
	sa_of(fresh)->packets = 3;
	checks = expire_checks;
	ft_ipsec_stats_work(NULL);
	assert(!fresh->curlft.packets && expire_checks == checks + 1);
	delete_state(fresh);

	/* Deleted while the pass is inside its walk. The SA it gathered is still
	 * installed -- its retirement needs the transaction the pass holds --
	 * and the state, held by the pass, is DEAD by the time x->lock is
	 * taken: nothing is published and nothing judged. */
	deleted_mid_pass = out;
	sa_stats_hook = delete_during_read;
	checks = expire_checks;
	out_sa->packets = 70;
	stats_scheduled = 0;
	ft_ipsec_stats_work(NULL);
	assert(out_sa->live && out->curlft.packets == 112 + 60 - 12);
	assert(expire_checks == checks && xfrm_state_refs == 0);
	sa_stats_hook = NULL;
	deleted_mid_pass = NULL;

	/* Nothing is owned any more, so the pass does not come back until an
	 * install starts it again; the retirements then free every SA. */
	assert(stats_scheduled == 0);
	bench_drain_retirements();
	assert(!out_sa->live && !in_sa->live && sa_deleted == 3);
	bench_clear_sas();
}

/* A non-ESN outbound SA asks for a rekey before its sequence space runs out,
 * because SEC will not wrap it and the offload can get there inside an
 * ordinary rekey interval. */
static void test_sequence_exhaustion(void)
{
	struct xfrm_state out_state, esn_state, in_state, idle_state, hard_state;
	struct xfrm_state *out, *esn, *in, *idle, *hard;
	struct cdx_ipsec_sa *out_sa;

	bench_reset();
	bench_clear_sas();
	out = install_accounted(&out_state, true, 0);
	out_sa = sa_of(out);
	out_sa->packets = 1;

	/* One short of the headroom: nothing yet. */
	out_sa->oseq = (1ULL << 32) - FT_IPSEC_SEQ_HEADROOM - 1;
	ft_ipsec_stats_work(NULL);
	assert(!soft_expires && !out->km.dying);

	/* Inside it: the soft expiry xfrm raises for a byte or packet limit,
	 * which is what makes the keying daemon rekey. Once. */
	out_sa->oseq++;
	ft_ipsec_stats_work(NULL);
	assert(soft_expires == 1 && out->km.dying && !hard_expires);
	out_sa->oseq = 0xffffffff;
	ft_ipsec_stats_work(NULL);
	assert(soft_expires == 1 && out->km.state == XFRM_STATE_VALID);

	/* ESN has 2^64 and never gets close; the same count means nothing. */
	esn = install_accounted(&esn_state, true, XFRM_STATE_ESN);
	sa_of(esn)->packets = 1;
	sa_of(esn)->oseq = (5ULL << 32) | 0xfffffff0;
	ft_ipsec_stats_work(NULL);
	assert(soft_expires == 1 && !esn->km.dying);

	/* An inbound SA sends nothing and has no sequence of its own. */
	in = install_accounted(&in_state, false, 0);
	assert(!ft_ipsec_seq_exhausting(in, 0xffffffff));
	assert(ft_ipsec_seq_exhausting(out, 0xffffffff));
	assert(!ft_ipsec_seq_exhausting(esn, 0xffffffff));

	/* An SA installed already inside the headroom asks before it has
	 * carried anything: the question is about the space, not the traffic. */
	idle = install_accounted(&idle_state, true, 0);
	sa_of(idle)->oseq = 0xfffffffe;
	ft_ipsec_stats_work(NULL);
	assert(soft_expires == 2 && idle->km.dying && !idle->curlft.use_time);

	/* A state its hard limit has just expired is past rekeying: it is told
	 * of that, by xfrm, and of nothing else. */
	hard = install_accounted(&hard_state, true, 0);
	hard->lft.hard_packet_limit = 5;
	sa_of(hard)->packets = 5;
	sa_of(hard)->oseq = 0xfffffffe;
	ft_ipsec_stats_work(NULL);
	assert(hard->km.state == XFRM_STATE_EXPIRED && !hard->km.dying);
	assert(soft_expires == 2);

	delete_state(out);
	delete_state(esn);
	delete_state(in);
	delete_state(idle);
	delete_state(hard);
	bench_clear_sas();
}

/* Where an SA's sequence space stands, and how wide a window guards it, as
 * xfrm hands them over -- in both of the shapes xfrm keeps them. */
static void test_spec_sequence(void)
{
	/* With room for the ring, as xfrm_user allocates it. */
	struct xfrm_replay_state_esn *esn = calloc(1, sizeof(*esn) + 4 * sizeof(u32));
	struct cdx_ipsec_sa_spec spec;
	struct xfrm_state *x = outbound_state();
	struct netlink_ext_ack ack = { NULL };

	bench_reset();

	/* A fresh SA starts at zero with anti-replay off, which is what a zero
	 * window means -- not the fixed window it used to get regardless. */
	assert(ft_ipsec_spec(x, &spec, &ack) == 0);
	assert(spec.seq == 0 && spec.replay_window == 0);

	/* The legacy shape: an outbound SA carries on from the last number it
	 * sent, an inbound one from the highest it received, each from its own
	 * field. */
	x->replay.oseq = 1000;
	x->replay.seq = 7;
	assert(ft_ipsec_spec(x, &spec, &ack) == 0);
	assert(spec.seq == 1000);
	x->xso.dir = XFRM_DEV_OFFLOAD_IN;
	x->props.replay_window = 32;
	assert(ft_ipsec_spec(x, &spec, &ack) == 0);
	assert(spec.seq == 7 && spec.replay_window == 32);

	/* ESN: the high word is part of the number, in each direction. */
	x->props.replay_window = 0;
	x->props.flags |= XFRM_STATE_ESN;
	assert(esn);
	esn->bmp_len = 4;
	x->replay_esn = esn;
	esn->seq = 9;
	esn->seq_hi = 1;
	esn->oseq = 5;
	esn->oseq_hi = 2;
	esn->replay_window = 64;
	assert(ft_ipsec_spec(x, &spec, &ack) == 0);
	assert(spec.esn && spec.seq == ((1ULL << 32) | 9));
	assert(spec.replay_window == 64);
	x->xso.dir = XFRM_DEV_OFFLOAD_OUT;
	assert(ft_ipsec_spec(x, &spec, &ack) == 0);
	assert(spec.seq == ((2ULL << 32) | 5));

	/* The same shape without ESN, which xfrm uses for a window wider than
	 * its legacy 32-bit bitmap: the high word is not part of the number,
	 * whatever it holds. */
	x->props.flags &= ~XFRM_STATE_ESN;
	assert(ft_ipsec_spec(x, &spec, &ack) == 0);
	assert(!spec.esn && spec.seq == 5);
	x->xso.dir = XFRM_DEV_OFFLOAD_IN;
	esn->replay_window = 128;
	assert(ft_ipsec_spec(x, &spec, &ack) == 0);
	assert(spec.seq == 9 && spec.replay_window == 128);

	/* A window SEC cannot keep at exactly its width is refused, and said
	 * so, rather than carried on another width, where SEC would take late
	 * frames xfrm's own check of the state refuses -- or drop ones it
	 * takes. */
	static const u32 foreign[] = { 1, 16, 31, 33, 48, 63, 65, 100, 127,
				       CDX_IPSEC_REPLAY_WINDOW_MAX + 1, 256 };
	for (unsigned i = 0; i < ARRAY_SIZE(foreign); i++) {
		esn->replay_window = foreign[i];
		ack._msg = NULL;
		assert(ft_ipsec_spec(x, &spec, &ack) == -EOPNOTSUPP);
		assert(ack._msg && !strcmp(ack._msg, "cdx: SEC keeps 32/64/128-packet replay windows"));
	}
	/* 128 is the tunnel-mode protocol's alone: a transport SA runs SEC's
	 * legacy protocol, which keeps 32 and 64. */
	x->props.mode = XFRM_MODE_TRANSPORT;
	esn->replay_window = 128;
	ack._msg = NULL;
	assert(ft_ipsec_spec(x, &spec, &ack) == -EOPNOTSUPP);
	assert(ack._msg && !strcmp(ack._msg, "cdx: SEC keeps a 128-packet replay window only in tunnel mode"));
	esn->replay_window = 64;
	assert(ft_ipsec_spec(x, &spec, &ack) == 0 && spec.replay_window == 64);
	x->props.mode = XFRM_MODE_TUNNEL;
	/* An outbound SA checks nothing, so any window it names is no reason
	 * to refuse it, in either mode: strongSwan gives one 0 or 1. */
	x->xso.dir = XFRM_DEV_OFFLOAD_OUT;
	esn->replay_window = 1024;
	assert(ft_ipsec_spec(x, &spec, &ack) == 0);
	for (unsigned i = 0; i < ARRAY_SIZE(foreign); i++) {
		esn->replay_window = foreign[i];
		assert(ft_ipsec_spec(x, &spec, &ack) == 0);
	}
	x->props.mode = XFRM_MODE_TRANSPORT;
	esn->replay_window = 128;
	assert(ft_ipsec_spec(x, &spec, &ack) == 0);
	x->props.mode = XFRM_MODE_TUNNEL;
	x->replay_esn = NULL;
	x->props.replay_window = 1;
	assert(ft_ipsec_spec(x, &spec, &ack) == 0);
	x->props.replay_window = 0;

	x->replay_esn = NULL;
	free(esn);
	memset(&x->replay, 0, sizeof(x->replay));
}

/* The sequence number SEC has reached goes back into the state, so that
 * whatever re-adds or migrates the SA carries on from there. */
static void test_publish_oseq(void)
{
	struct xfrm_replay_state_esn esn = { .bmp_len = 4 };
	struct xfrm_state out_state, esn_state, bmp_state, in_state;
	struct xfrm_state *out, *esn_out, *bmp_out, *in;

	bench_reset();
	bench_clear_sas();
	out = install_accounted(&out_state, true, 0);
	esn_out = install_accounted(&esn_state, true, XFRM_STATE_ESN);
	esn_out->replay_esn = &esn;
	bmp_out = install_accounted(&bmp_state, true, 0);
	in = install_accounted(&in_state, false, 0);

	/* SEC's own number, as it is: an SA that has sent nothing reads back
	 * as installed, and what `ip xfrm state` and the exhaustion check see
	 * is a number SEC has sent. However busy the SA, nothing is projected
	 * ahead of SEC here; a re-add is carried past the old SA instead. */
	sa_of(out)->oseq = 0;
	ft_ipsec_stats_work(NULL);
	assert(out->replay.oseq == 0);
	sa_of(out)->oseq = 4096;
	ft_ipsec_stats_work(NULL);
	assert(out->replay.oseq == 4096);
	sa_of(out)->packets = 100000;
	sa_of(out)->oseq = 105000;
	ft_ipsec_stats_work(NULL);
	assert(out->replay.oseq == 105000);
	/* The rate is kept for that re-add, though. */
	assert(list_entry(ft_ipsec_owned.next, struct ft_ipsec_retirement, list)->sent == 100000);
	/* A reading behind the published one takes nothing back, and the same
	 * reading again, however often, moves nothing. */
	sa_of(out)->oseq = 104000;
	ft_ipsec_stats_work(NULL);
	assert(out->replay.oseq == 105000);
	sa_of(out)->oseq = 106000;
	ft_ipsec_stats_work(NULL);
	ft_ipsec_stats_work(NULL);
	assert(out->replay.oseq == 106000);

	/* ESN splits it across both words. */
	sa_of(esn_out)->packets = 16;
	sa_of(esn_out)->oseq = (3ULL << 32) | 0xfffffff0;
	ft_ipsec_stats_work(NULL);
	assert(esn.oseq_hi == 3 && esn.oseq == 0xfffffff0);
	sa_of(esn_out)->oseq = (4ULL << 32) | 0x10;
	ft_ipsec_stats_work(NULL);
	assert(esn.oseq_hi == 4 && esn.oseq == 0x10);

	/* Only forward: a value set by other means is not undone by a reading
	 * behind it. */
	out->replay.oseq = 1000000;
	ft_ipsec_stats_work(NULL);
	assert(out->replay.oseq == 1000000);

	/* Not ESN but in the wide shape: the low word alone, up to the last
	 * number SEC sends. */
	{
		struct xfrm_replay_state_esn wide = { .bmp_len = 4, .oseq_hi = 9 };

		bmp_out->replay_esn = &wide;
		sa_of(bmp_out)->oseq = 77;
		ft_ipsec_stats_work(NULL);
		assert(wide.oseq == 77 && wide.oseq_hi == 9);
		sa_of(bmp_out)->packets = 200;
		sa_of(bmp_out)->oseq = 0xfffffffe;
		ft_ipsec_stats_work(NULL);
		assert(wide.oseq == 0xfffffffe && wide.oseq_hi == 9);
		bmp_out->replay_esn = NULL;
	}

	/* An inbound SA has no sequence of its own to publish, whatever it is
	 * handed. */
	test_lock(&in->lock);
	ft_ipsec_publish_oseq(in, 555);
	test_unlock(&in->lock);
	assert(in->replay.oseq == 0);

	/* Not VALID: nothing goes back from the pass. */
	out->km.state = XFRM_STATE_EXPIRED;
	sa_of(out)->oseq = 2000000;
	ft_ipsec_stats_work(NULL);
	assert(out->replay.oseq == 1000000);

	delete_state(out);
	delete_state(esn_out);
	delete_state(bmp_out);
	delete_state(in);
	bench_clear_sas();
}

/* A replay_esn with room for a 128-entry ring, as xfrm_user allocates one. */
static struct xfrm_replay_state_esn *ring_alloc(u32 window)
{
	struct xfrm_replay_state_esn *r = calloc(1, sizeof(*r) + 4 * sizeof(u32));

	assert(r);
	r->bmp_len = 4;
	r->replay_window = window;
	return r;
}

/* An inbound state that has received the numbers from..to except `missing`,
 * put through xfrm's own receive bookkeeping one number at a time. */
static void receive(struct xfrm_state *x, u64 from, u64 to, const u64 *missing,
		    unsigned int nmissing)
{
	for (u64 s = from; s <= to; s++) {
		bool skip = false;

		for (unsigned int i = 0; i < nmissing; i++)
			skip |= missing[i] == s;
		if (!skip)
			xfrm_replay_advance(x, htonl((u32)s));
	}
}

static bool was_missing(u64 s, const u64 *missing, unsigned int nmissing)
{
	for (unsigned int i = 0; i < nmissing; i++)
		if (missing[i] == s)
			return true;
	return false;
}

static bool seen_bit(const u32 *seen, u32 k)
{
	return seen[k / 32] & (1U << (k % 32));
}

/* A state re-added with history carries it to SEC in SEC's orientation --
 * bit k for seq - k -- whichever of xfrm's three shapes it came in, and marks
 * everything past its own window as seen. xfrm's own receive code builds the
 * history, so the orientation is checked against xfrm rather than against a
 * restatement of it. */
static void test_replay_seeding(void)
{
	static const u64 legacy_missing[] = { 35, 38, 20 };
	static const u64 bmp_missing[] = { 99, 70, 50 };
	const u64 esn_missing[] = { (2ULL << 32) | 0xfffffff8, (3ULL << 32) | 0x5,
				    (3ULL << 32) | 0x1f };
	struct cdx_ipsec_sa_spec spec;
	struct xfrm_state *x = outbound_state();
	struct netlink_ext_ack ack = { NULL };
	u64 top;

	bench_reset();
	x->xso.dir = XFRM_DEV_OFFLOAD_IN;

	/* A fresh state has no history to carry. */
	x->props.replay_window = 32;
	assert(ft_ipsec_spec(x, &spec, &ack) == 0);
	for (u32 k = 0; k < 128; k++)
		assert(!seen_bit(spec.replay_seen, k));

	/* The legacy shape: a linear 32-bit bitmap. */
	x->repl_mode = XFRM_REPLAY_MODE_LEGACY;
	receive(x, 1, 40, legacy_missing, 3);
	assert(x->replay.seq == 40);
	assert(ft_ipsec_spec(x, &spec, &ack) == 0);
	assert(spec.seq == 40 && spec.replay_window == 32);
	for (u32 k = 0; k < 128; k++)
		assert(seen_bit(spec.replay_seen, k) ==
		       (k >= 32 || !was_missing(40 - k, legacy_missing, 3)));

	/* The ring xfrm keeps for a window wider than 32, without ESN. */
	memset(&x->replay, 0, sizeof(x->replay));
	x->props.replay_window = 0;
	x->replay_esn = ring_alloc(64);
	x->repl_mode = XFRM_REPLAY_MODE_BMP;
	receive(x, 1, 100, bmp_missing, 3);
	assert(ft_ipsec_spec(x, &spec, &ack) == 0);
	assert(spec.seq == 100 && spec.replay_window == 64);
	for (u32 k = 0; k < 128; k++)
		assert(seen_bit(spec.replay_seen, k) ==
		       (k >= 64 || !was_missing(100 - k, bmp_missing, 3)));
	free(x->replay_esn);

	/* ESN, across a carry into the high word: the ring is indexed by the
	 * low 32 bits, and the history straddles the wrap. */
	x->props.flags |= XFRM_STATE_ESN;
	x->replay_esn = ring_alloc(64);
	x->replay_esn->seq_hi = 2;
	x->replay_esn->seq = 0xffffffe0;
	x->repl_mode = XFRM_REPLAY_MODE_ESN;
	receive(x, (2ULL << 32) | 0xffffffe1, (3ULL << 32) | 0x20, esn_missing, 3);
	top = (3ULL << 32) | 0x20;
	assert(x->replay_esn->seq_hi == 3 && x->replay_esn->seq == 0x20);
	assert(ft_ipsec_spec(x, &spec, &ack) == 0);
	assert(spec.esn && spec.seq == top);
	for (u32 k = 0; k < 128; k++)
		assert(seen_bit(spec.replay_seen, k) ==
		       (k >= 64 || !was_missing(top - k, esn_missing, 3)));
	free(x->replay_esn);

	x->replay_esn = NULL;
	x->props.flags &= ~XFRM_STATE_ESN;
	x->props.replay_window = 0;
	x->repl_mode = XFRM_REPLAY_MODE_LEGACY;
	memset(&x->replay, 0, sizeof(x->replay));
}

/* Ask xfrm's own check whether it would take sequence number s. */
static bool accepts(struct xfrm_state *x, u64 s)
{
	return xfrm_replay_check(x, NULL, htonl((u32)s)) == 0;
}

/* SEC's scorecard goes back into the state in xfrm's orientation, so the
 * state refuses exactly what SEC has seen -- which is what a re-add built
 * from it inherits. xfrm's own check is the oracle. */
static void test_publish_window(void)
{
	struct xfrm_state in_state, bmp_state, esn_state;
	struct xfrm_state *in, *bmp, *esn;
	u32 pattern[4] = { 0xa5a5f00f, 0x0ff05a5a, 0x12345678, 0x9abcdef1 };
	u64 top;

	bench_reset();
	bench_clear_sas();

	/* The legacy shape, 32 wide. */
	in = install_accounted(&in_state, false, 0);
	in->props.replay_window = 32;
	in->repl_mode = XFRM_REPLAY_MODE_LEGACY;
	sa_of(in)->seq = 1000;
	memcpy(sa_of(in)->seen, pattern, sizeof(pattern));
	ft_ipsec_stats_work(NULL);
	assert(in->replay.seq == 1000);
	for (u32 k = 0; k < 32; k++)
		assert(accepts(in, 1000 - k) == !seen_bit(pattern, k));
	assert(!accepts(in, 1000 - 32) && accepts(in, 1001));

	/* A window behind the state's is not applied; one level with it only
	 * adds what SEC has seen since. */
	sa_of(in)->seq = 900;
	sa_of(in)->seen[0] = ~0U;
	ft_ipsec_stats_work(NULL);
	assert(in->replay.seq == 1000);
	for (u32 k = 0; k < 32; k++)
		assert(accepts(in, 1000 - k) == !seen_bit(pattern, k));
	sa_of(in)->seq = 1000;
	sa_of(in)->seen[0] = pattern[0] | 1U << 2;
	ft_ipsec_stats_work(NULL);
	assert(!accepts(in, 998));
	for (u32 k = 0; k < 32; k++)
		if (k != 2)
			assert(accepts(in, 1000 - k) == !seen_bit(pattern, k));

	/* One ahead replaces it outright: nothing seen at the old anchor
	 * carries over to the new one. */
	sa_of(in)->seq = 1100;
	sa_of(in)->seen[0] = 1;
	ft_ipsec_stats_work(NULL);
	assert(in->replay.seq == 1100 && !accepts(in, 1100));
	for (u32 k = 1; k < 32; k++)
		assert(accepts(in, 1100 - k));

	/* The ring, 64 wide, without ESN; a window ahead replaces what was
	 * there. */
	bmp = install_accounted(&bmp_state, false, 0);
	bmp->replay_esn = ring_alloc(64);
	bmp->repl_mode = XFRM_REPLAY_MODE_BMP;
	bmp->replay_esn->seq = 50;
	bmp->replay_esn->bmp[0] = bmp->replay_esn->bmp[1] = ~0U;
	sa_of(bmp)->seq = 5000;
	memcpy(sa_of(bmp)->seen, pattern, sizeof(pattern));
	ft_ipsec_stats_work(NULL);
	assert(bmp->replay_esn->seq == 5000);
	for (u32 k = 0; k < 64; k++)
		assert(accepts(bmp, 5000 - k) == !seen_bit(pattern, k));
	assert(!accepts(bmp, 5000 - 64) && accepts(bmp, 5001));

	/* ESN, the window straddling a carry into the high word. */
	esn = install_accounted(&esn_state, false, XFRM_STATE_ESN);
	esn->replay_esn = ring_alloc(128);
	esn->repl_mode = XFRM_REPLAY_MODE_ESN;
	esn->replay_esn->seq_hi = 6;
	esn->replay_esn->seq = 0xfffffff0;
	top = (7ULL << 32) | 0x30;
	sa_of(esn)->seq = top;
	memcpy(sa_of(esn)->seen, pattern, sizeof(pattern));
	ft_ipsec_stats_work(NULL);
	assert(esn->replay_esn->seq_hi == 7 && esn->replay_esn->seq == 0x30);
	for (u32 k = 0; k < 128; k++)
		assert(accepts(esn, top - k) == !seen_bit(pattern, k));
	assert(accepts(esn, top + 1));

	/* An SA with anti-replay off keeps no window to publish. */
	sa_of(in)->seq = 2000;
	in->props.replay_window = 0;
	ft_ipsec_stats_work(NULL);
	assert(in->replay.seq == 1100);

	free(bmp->replay_esn);
	free(esn->replay_esn);
	bmp->replay_esn = esn->replay_esn = NULL;
	delete_state(in);
	delete_state(bmp);
	delete_state(esn);
	bench_clear_sas();
}

/* The whole round trip: a state's history goes to SEC on install, SEC's
 * scorecard comes back into a state, and a re-add built from that state
 * refuses exactly what the first one had seen. */
static void test_replay_round_trip(void)
{
	static const u64 missing[] = { 190, 175, 131 };
	struct xfrm_state first_state, second_state;
	struct xfrm_state *first, *second;
	struct cdx_ipsec_sa_spec spec;
	struct netlink_ext_ack ack = { NULL };

	bench_reset();
	bench_clear_sas();
	first_state = *outbound_state();
	first = &first_state;
	first->xso.dir = XFRM_DEV_OFFLOAD_IN;
	first->replay_esn = ring_alloc(128);
	first->repl_mode = XFRM_REPLAY_MODE_BMP;
	receive(first, 1, 200, missing, 3);

	/* To SEC: the spec's scorecard is what SEC starts from. */
	assert(ft_ipsec_spec(first, &spec, &ack) == 0);

	/* From SEC, into a state installed fresh and anchored nowhere yet. */
	second = install_accounted(&second_state, false, 0);
	second->replay_esn = ring_alloc(128);
	second->repl_mode = XFRM_REPLAY_MODE_BMP;
	sa_of(second)->seq = spec.seq;
	memcpy(sa_of(second)->seen, spec.replay_seen, sizeof(spec.replay_seen));
	ft_ipsec_stats_work(NULL);
	for (u64 s = 200 - 127; s <= 201; s++)
		assert(accepts(second, s) == accepts(first, s));

	free(first->replay_esn);
	free(second->replay_esn);
	second->replay_esn = NULL;
	delete_state(second);
	bench_clear_sas();
}

/* xfrm asks the driver to publish right before it reads a state -- GETSA,
 * GETAE, dumps, the state timer, its own expiry check -- from wherever it
 * is, x->lock held or not. What goes back is SEC's reading of that moment,
 * never behind what was published, and nothing once deletion has begun. */
static void test_update_stats(void)
{
	struct xfrm_state out_state, in_state;
	struct xfrm_state *out, *in;
	struct cdx_ipsec_sa *gone;
	unsigned calls, reads;

	bench_reset();
	bench_clear_sas();
	/* Attached, so xfrm's own expiry check reaches the op too. */
	WAN.xfrmdev_ops = &ft_xfrmdev_ops;
	out = install_accounted(&out_state, true, 0);
	in = install_accounted(&in_state, false, 0);
	in->props.replay_window = 32;
	in->repl_mode = XFRM_REPLAY_MODE_LEGACY;

	/* As GETSA calls it, without x->lock: SEC's number of that moment,
	 * nothing added. */
	sa_of(out)->oseq = 1000;
	ft_xfrmdev_ops.xdo_dev_state_update_stats(out);
	assert(out->replay.oseq == 1000);
	assert(!ft_ipsec_retired_lock && !out->lock && !ft_transaction);
	/* The same reading again, as a dump of every state gives it, moves
	 * nothing; a reading behind it takes nothing back. */
	ft_xfrmdev_ops.xdo_dev_state_update_stats(out);
	assert(out->replay.oseq == 1000);
	sa_of(out)->oseq = 900;
	ft_xfrmdev_ops.xdo_dev_state_update_stats(out);
	assert(out->replay.oseq == 1000);
	/* As the state timer and GETAE call it, under x->lock: it takes no
	 * lock of the state's, which would deadlock there. */
	sa_of(out)->oseq = 2000;
	test_lock(&out->lock);
	ft_xfrmdev_ops.xdo_dev_state_update_stats(out);
	test_unlock(&out->lock);
	assert(out->replay.oseq == 2000);

	/* Between passes, the live number, however busy the SA. */
	sa_of(out)->packets = 100000;
	ft_ipsec_stats_work(NULL);
	assert(out->replay.oseq == 2000);
	sa_of(out)->oseq = 50000;
	ft_xfrmdev_ops.xdo_dev_state_update_stats(out);
	assert(out->replay.oseq == 50000);

	/* Inbound: the window as SEC has it now, in xfrm's orientation. */
	sa_of(in)->seq = 500;
	sa_of(in)->seen[0] = 0x5;
	ft_xfrmdev_ops.xdo_dev_state_update_stats(in);
	assert(in->replay.seq == 500 && in->replay.bitmap == 0x5);
	assert(!accepts(in, 500) && accepts(in, 499) && !accepts(in, 498));

	/* The pass's own judge asks again, under x->lock, with the owned
	 * list's lock already dropped -- the stubs assert both. */
	calls = update_stats_calls;
	reads = replay_state_reads;
	sa_of(in)->packets = 3;
	sa_of(in)->seq = 510;
	ft_ipsec_stats_work(NULL);
	assert(update_stats_calls > calls && replay_state_reads > reads);
	assert(in->replay.seq == 510);

	/* Deleted: the handle is gone, and with it every publication. */
	gone = sa_of(out);
	delete_state(out);
	gone->oseq = 900000;
	reads = replay_state_reads;
	ft_xfrmdev_ops.xdo_dev_state_update_stats(out);
	assert(replay_state_reads == reads && out->replay.oseq == 50000);

	delete_state(in);
	bench_clear_sas();
	WAN.xfrmdev_ops = NULL;
}

/* Whether SEC's scorecard, top and window refuse n: seen, or too old. */
static bool sec_refuses(const u32 *seen, u64 top, u32 window, u64 n)
{
	if (n > top)
		return false;
	return top - n >= window || seen_bit(seen, (u32)(top - n));
}

/* An inbound state in the ring shape, the fixture's SPI and keys. */
static struct xfrm_state *inbound_ring(struct xfrm_state *x, u32 window)
{
	*x = *outbound_state();
	x->xso.dir = XFRM_DEV_OFFLOAD_IN;
	x->replay_esn = ring_alloc(window);
	x->repl_mode = XFRM_REPLAY_MODE_BMP;
	return x;
}

/* A keying daemon moving an SA to a new address reads the state, deletes it
 * and adds it again with the same SPI and keys and the replay state it read.
 * The re-add starts past where SEC left the old SA, whatever the reading
 * missed; a re-add that is not the same SA starts where it asked to. */
static void test_readd_fold(void)
{
	static const u64 missing[] = { 990, 971, 950 };
	const u32 pattern[4] = { 0xfffff0ff, 0x0f0f0f0f, 0, 0 };
	struct xfrm_state s1, s2, s3, s4, s5;
	struct xfrm_state *first, *second, *third, *fourth, *fifth;
	struct netlink_ext_ack ack = { NULL };
	unsigned waits, deleted, installed;

	/* Still on its way out when the re-add comes: its retirement is waited
	 * for, then folded in -- the higher top, and everything the read state
	 * or SEC refuses. */
	bench_reset();
	bench_clear_sas();
	first = inbound_ring(&s1, 64);
	assert(ft_xdo_state_add(first, &ack) == 0);
	sa_of(first)->seq = 1040;
	memcpy(sa_of(first)->seen, pattern, sizeof(pattern));
	second = inbound_ring(&s2, 64);
	receive(second, 937, 1000, missing, 3);
	delete_state(first);
	waits = retire_waits;
	deleted = sa_deleted;
	assert(ft_xdo_state_add(second, &ack) == 0);
	assert(retire_waits == waits + 1 && deleted_before_install == deleted + 1);
	assert(retire_wakes > 0);
	assert(installed_spec.seq == 1040 && installed_spec.replay_window == 64);
	for (u32 k = 0; k < 128; k++) {
		u64 n = 1040 - k;

		assert(seen_bit(installed_spec.replay_seen, k) ==
		       (k >= 64 || !accepts(second, n) || sec_refuses(pattern, 1040, 64, n)));
	}
	/* 990 had not reached the state that was read, but SEC took it after
	 * the reading: the re-add refuses it. 1032 neither had seen, and it
	 * is still to be taken. */
	assert(accepts(second, 990) && seen_bit(installed_spec.replay_seen, 1040 - 990));
	assert(seen_bit(installed_spec.replay_seen, 0) && !seen_bit(installed_spec.replay_seen, 8));
	delete_state(second);

	/* A MOBIKE move of this end changes the inbound SA's destination: the
	 * same SA all the same, waited for and carried on from. */
	third = inbound_ring(&s3, 64);
	assert(ft_xdo_state_add(third, &ack) == 0);
	sa_of(third)->seq = 2000;
	memcpy(sa_of(third)->seen, pattern, sizeof(pattern));
	delete_state(third);
	fourth = inbound_ring(&s4, 64);
	fourth->id.daddr.a4 = 0x7b01a8c0;	/* 192.168.1.123 */
	receive(fourth, 1937, 1990, missing, 0);
	waits = retire_waits;
	assert(ft_xdo_state_add(fourth, &ack) == 0);
	assert(retire_waits == waits + 1 && installed_spec.seq == 2000);
	assert(installed_spec.dst.ip == 0x7b01a8c0);
	delete_state(fourth);
	free(first->replay_esn);
	free(second->replay_esn);
	free(third->replay_esn);
	free(fourth->replay_esn);
	bench_clear_sas();

	/* Already out of the hardware: its record is what is folded. */
	bench_reset();
	first = inbound_ring(&s1, 64);
	assert(ft_xdo_state_add(first, &ack) == 0);
	sa_of(first)->seq = 1040;
	memcpy(sa_of(first)->seen, pattern, sizeof(pattern));
	delete_state(first);
	bench_drain_retirements();
	assert(ft_ipsec_remembered_count == 1);
	waits = retire_waits;
	second = inbound_ring(&s2, 64);
	receive(second, 937, 1000, missing, 3);
	assert(ft_xdo_state_add(second, &ack) == 0);
	assert(retire_waits == waits && installed_spec.seq == 1040);
	delete_state(second);
	bench_drain_retirements();

	/* The same SPI under other keys is another SA: nothing carried. */
	third = inbound_ring(&s3, 64);
	receive(third, 937, 1000, missing, 3);
	cipher_key.alg_key[0] ^= 0xff;
	assert(ft_xdo_state_add(third, &ack) == 0);
	cipher_key.alg_key[0] ^= 0xff;
	assert(installed_spec.seq == 1000);
	delete_state(third);
	bench_drain_retirements();
	/* The same SA added again with nothing carried is carried on from all
	 * the same: under the same keys, a number taken once is a replay. */
	fourth = inbound_ring(&s4, 64);
	assert(ft_xdo_state_add(fourth, &ack) == 0);
	assert(installed_spec.seq == 1040);
	for (u32 k = 0; k < 128; k++)
		assert(seen_bit(installed_spec.replay_seen, k) ==
		       (k >= 64 || sec_refuses(pattern, 1040, 64, 1040 - k)));
	delete_state(fourth);
	bench_drain_retirements();
	/* Nothing from a record gone stale. */
	jiffies += FT_IPSEC_REMEMBER_FOR;
	fifth = inbound_ring(&s5, 64);
	receive(fifth, 937, 1000, missing, 3);
	assert(ft_xdo_state_add(fifth, &ack) == 0);
	assert(installed_spec.seq == 1000);
	delete_state(fifth);
	free(first->replay_esn);
	free(second->replay_esn);
	free(third->replay_esn);
	free(fourth->replay_esn);
	free(fifth->replay_esn);
	bench_clear_sas();

	/* Another SA whose entry would take the retiring one's key -- the same
	 * SPI and destination, other keys -- waits for it too, and carries
	 * nothing from it. */
	bench_reset();
	first = inbound_ring(&s1, 64);
	assert(ft_xdo_state_add(first, &ack) == 0);
	sa_of(first)->seq = 1040;
	delete_state(first);
	second = inbound_ring(&s2, 64);
	receive(second, 937, 1000, missing, 3);
	cipher_key.alg_key[0] ^= 0xff;
	waits = retire_waits;
	assert(ft_xdo_state_add(second, &ack) == 0);
	cipher_key.alg_key[0] ^= 0xff;
	assert(retire_waits == waits + 1 && installed_spec.seq == 1000);
	delete_state(second);
	bench_drain_retirements();
	/* A retirement that cannot finish is not waited for forever: the add
	 * holds xfrm_cfg_mutex. It is refused, with nothing installed. */
	third = inbound_ring(&s3, 64);
	assert(ft_xdo_state_add(third, &ack) == 0);
	sa_of(third)->seq = 3000;
	delete_state(third);
	retirement_stuck = true;
	fourth = inbound_ring(&s4, 64);
	installed = sa_installed;
	ack._msg = NULL;
	assert(ft_xdo_state_add(fourth, &ack) == -EBUSY);
	assert(ack._msg && strstr(ack._msg, "still leaving the hardware"));
	assert(sa_installed == installed && !fourth->xso.offload_handle && !fourth->handle);
	retirement_stuck = false;
	bench_drain_retirements();
	free(first->replay_esn);
	free(second->replay_esn);
	free(third->replay_esn);
	free(fourth->replay_esn);
	bench_clear_sas();

	/* Outbound, and no SA of its before: an add starts exactly where it
	 * asked to, however far along that is. */
	bench_reset();
	s1 = *outbound_state();
	s1.replay.oseq = 0x1000;
	assert(ft_xdo_state_add(&s1, &ack) == 0);
	assert(installed_spec.seq == 0x1000);
	delete_state(&s1);
	bench_drain_retirements();
	bench_clear_sas();

	/* A re-add: past the higher of the number it carried and the old SA's
	 * last, by the floor, which covers what SEC may still have held of
	 * the old SA when it was read. */
	bench_reset();
	s1 = *outbound_state();
	assert(ft_xdo_state_add(&s1, &ack) == 0);
	sa_of(&s1)->oseq = 7000;
	delete_state(&s1);
	bench_drain_retirements();
	s2 = *outbound_state();
	s2.replay.oseq = 5000;
	assert(ft_xdo_state_add(&s2, &ack) == 0);
	assert(installed_spec.seq == 7000 + FT_IPSEC_OSEQ_FLOOR);
	/* That SA sent nothing, so its own deletion leaves the record be. */
	delete_state(&s2);
	bench_drain_retirements();
	assert(ft_ipsec_remembered_count == 1);
	/* A number carried ahead of the old SA's goes on from there. */
	s3 = *outbound_state();
	s3.replay.oseq = 1000000;
	assert(ft_xdo_state_add(&s3, &ack) == 0);
	assert(installed_spec.seq == 1000000 + FT_IPSEC_OSEQ_FLOOR);
	delete_state(&s3);
	/* One the peer's move sent elsewhere, or added with nothing carried,
	 * is the same SA, and starts past it too. */
	s4 = *outbound_state();
	s4.id.daddr.a4 = 0x7c01a8c0;		/* 192.168.1.124 */
	assert(ft_xdo_state_add(&s4, &ack) == 0);
	assert(installed_spec.seq == 7000 + FT_IPSEC_OSEQ_FLOOR);
	delete_state(&s4);
	s5 = *outbound_state();
	assert(ft_xdo_state_add(&s5, &ack) == 0);
	assert(installed_spec.seq == 7000 + FT_IPSEC_OSEQ_FLOOR);
	delete_state(&s5);
	bench_clear_sas();

	/* A busy old SA is skipped past by twice what it sent in its last
	 * period; and never past the last number SEC sends. */
	bench_reset();
	s1 = *outbound_state();
	s1.km.state = XFRM_STATE_VALID;
	assert(ft_xdo_state_add(&s1, &ack) == 0);
	sa_of(&s1)->packets = 300000;
	sa_of(&s1)->oseq = 400000;
	ft_ipsec_stats_work(NULL);
	delete_state(&s1);
	bench_drain_retirements();
	s2 = *outbound_state();
	s2.replay.oseq = 350000;
	assert(ft_xdo_state_add(&s2, &ack) == 0);
	assert(installed_spec.seq == 400000 + 600000);
	delete_state(&s2);
	bench_drain_retirements();
	bench_clear_sas();
	bench_reset();
	s1 = *outbound_state();
	assert(ft_xdo_state_add(&s1, &ack) == 0);
	sa_of(&s1)->oseq = 0xfffff000;
	delete_state(&s1);
	bench_drain_retirements();
	/* An old SA that close to the end of its space leaves a re-add no
	 * number it could send without reusing one: the margin stops at the
	 * last one, and the backend refuses to start there. */
	s2 = *outbound_state();
	s2.replay.oseq = 0xffff0000;
	installed = sa_installed;
	ack._msg = NULL;
	assert(ft_xdo_state_add(&s2, &ack) == -EINVAL);
	assert(sa_installed == installed && !s2.xso.offload_handle);
	assert(ack._msg && !strcmp(ack._msg, "cdx: the hardware refused this SA"));
	{
		struct cdx_ipsec_sa_spec spec;

		memset(&spec, 0, sizeof(spec));
		spec.esn = false;
		spec.seq = 0xfffff000;
		ft_ipsec_fold_oseq(&spec, 0xfffff000, 0);
		assert(spec.seq == U32_MAX - 1);
	}
	bench_clear_sas();
}

/* Retired SAs are remembered one record each, for a while, and never more
 * than FT_IPSEC_REMEMBERED of them. */
static void test_remembered_bound(void)
{
	struct ft_ipsec_retirement *r;

	bench_reset();
	bench_clear_sas();
	for (u32 i = 0; i < FT_IPSEC_REMEMBERED + 10; i++) {
		r = calloc(1, sizeof(*r));
		r->id.family = AF_INET;
		r->id.spi = i + 1;
		r->last.seq = 1;
		test_lock(&ft_ipsec_retired_lock);
		assert(ft_ipsec_remember(r));
		test_unlock(&ft_ipsec_retired_lock);
	}
	assert(ft_ipsec_remembered_count == FT_IPSEC_REMEMBERED);
	r = list_entry(ft_ipsec_remembered.next, struct ft_ipsec_retirement, list);
	assert(r->id.spi == 11);
	/* The same SA again replaces its record rather than adding one. */
	r = calloc(1, sizeof(*r));
	r->id.family = AF_INET;
	r->id.spi = 100;
	r->last.oseq = 5;
	test_lock(&ft_ipsec_retired_lock);
	assert(ft_ipsec_remember(r));
	test_unlock(&ft_ipsec_retired_lock);
	assert(ft_ipsec_remembered_count == FT_IPSEC_REMEMBERED);
	unsigned same = 0;
	list_for_each_entry(r, &ft_ipsec_remembered, list)
		same += r->id.spi == 100;
	assert(same == 1);
	/* An SA SEC left nothing of is not kept. */
	r = calloc(1, sizeof(*r));
	test_lock(&ft_ipsec_retired_lock);
	assert(!ft_ipsec_remember(r));
	test_unlock(&ft_ipsec_retired_lock);
	free(r);
	/* And the rest age out as the next one comes. */
	jiffies += FT_IPSEC_REMEMBER_FOR;
	r = calloc(1, sizeof(*r));
	r->id.spi = 7;
	r->last.seq = 9;
	test_lock(&ft_ipsec_retired_lock);
	assert(ft_ipsec_remember(r));
	test_unlock(&ft_ipsec_retired_lock);
	assert(ft_ipsec_remembered_count == 1);
	bench_clear_sas();
}

/* The global block the microcode keeps in MURAM, and its refusal table. */
static en_exthash_global_mem muram;
static en_SEC_failure_stats *const table = &muram.SEC_failure_stats;

static u64 sec_total(void)
{
	u64 total = 0;

	for (unsigned i = 0; i < CDX_SEC_REFUSAL_CLASSES; i++)
		total += ft_sec_counted[i];
	return total;
}

static u64 mib_total(void)
{
	u64 total = 0;

	for (unsigned i = 0; i < __LINUX_MIB_XFRMMAX; i++)
		total += xfrm_mib[i];
	return total;
}

/* Frames SEC refused reach the counters xfrm keeps for its own equivalent
 * drops, from the only record of them there is: the microcode's global table,
 * read differences at a time. */
static void test_sec_refusals(void)
{
	struct xfrm_state in_state, out_state;
	struct xfrm_state *in, *out;
	struct cdx_sec_refusals now;
	struct seq_file seq = { .len = 0 };
	unsigned reads;
	char row[64];

	bench_reset();
	bench_clear_sas();
	memset(xfrm_mib, 0, sizeof(xfrm_mib));
	sec_fault_lines = 0;

	/* Before FMan has placed the table there is nothing to read, and so no
	 * reading to count from either. */
	en_global_muram_mem = NULL;
	assert(cdx_ipsec_sec_refusals(&now) == -ENODEV);
	ft_sec_refusals_fold();
	assert(!ft_sec_known && !sec_total() && !mib_total());

	/* Placed, and already counting what was refused before this module
	 * existed -- the rig's boot totals. The first reading is only where
	 * counting starts: none of it is put down to the adapter. */
	memset(&muram, 0, sizeof(muram));
	table->icv_failures = htonl(9);
	table->other_errs = htonl(55);
	table->buff_pool_depletion_errs = htonl(256);
	en_global_muram_mem = &muram;
	ft_sec_refusals_fold();
	assert(ft_sec_known && !sec_total() && !mib_total() && !sec_fault_lines);
	/* The table is big-endian, and read in host order exactly once. */
	assert(cdx_ipsec_sec_refusals(&now) == 0);
	assert(now.count[CDX_SEC_REFUSED_ICV] == 9 && now.count[CDX_SEC_REFUSED_OTHER] == 55 &&
	       now.count[CDX_SEC_REFUSED_BUFFER_DEPLETION] == 256);

	/* Ten frames under a wrong GCM key, split the way the microcode split
	 * one measured burst: one ICV failure, nine "other". Counted once a
	 * pass, not once an SA -- one reading of the whole table. */
	in = install_accounted(&in_state, false, 0);
	out = install_accounted(&out_state, true, 0);
	table->icv_failures = htonl(10);
	table->other_errs = htonl(64);
	reads = muram_reads;
	ft_ipsec_stats_work(NULL);
	assert(muram_reads - reads == CDX_SEC_REFUSAL_CLASSES);
	assert(xfrm_mib[LINUX_MIB_XFRMINSTATEPROTOERROR] == 1 && xfrm_mib[LINUX_MIB_XFRMINERROR] == 9);
	assert(sec_total() == 10 && mib_total() == 10 && !sec_fault_lines);
	/* Nothing moved: nothing more. */
	ft_ipsec_stats_work(NULL);
	assert(sec_total() == 10 && mib_total() == 10);

	/* Each class xfrm has a counter for goes to it. A TTL taken to zero
	 * has none, and is counted here only. */
	table->anti_replay_replay_errs = htonl(3);
	table->anti_replay_late_errs = htonl(2);
	table->seq_num_overflows = htonl(1);
	table->CCM_AAD_size_errs = htonl(1);
	table->ipsec_pad_chk_failures = htonl(1);
	table->protocol_format_errs = htonl(1);
	table->ipsec_ttl_zero_errs = htonl(4);
	ft_ipsec_stats_work(NULL);
	assert(xfrm_mib[LINUX_MIB_XFRMINSTATESEQERROR] == 5);
	assert(xfrm_mib[LINUX_MIB_XFRMOUTSTATESEQERROR] == 1);
	assert(xfrm_mib[LINUX_MIB_XFRMINSTATEPROTOERROR] == 4);
	assert(xfrm_mib[LINUX_MIB_XFRMINERROR] == 9);
	assert(ft_sec_counted[CDX_SEC_REFUSED_TTL_ZERO] == 4);
	assert(sec_total() == 23 && mib_total() == 19 && !sec_fault_lines);

	/* SEC's own faults and the resources it ran out of reach no xfrm
	 * counter, and are said out loud: one line, naming each class. */
	table->buff_pool_depletion_errs = htonl(256 + 7);
	table->DMA_errs = htonl(1);
	ft_ipsec_stats_work(NULL);
	assert(mib_total() == 19 && sec_total() == 31);
	assert(sec_fault_lines == 1);
	assert(strstr(sec_fault_line, "8 IPsec frames dropped"));
	assert(strstr(sec_fault_line, " dma=1") && strstr(sec_fault_line, " buffer_depletion=7"));
	assert(!strstr(sec_fault_line, "other") && !strstr(sec_fault_line, "ttl_zero"));
	/* And not again while they stand still. */
	ft_ipsec_stats_work(NULL);
	assert(sec_fault_lines == 1);

	/* A count that wrapped since the last reading adds what it counted. */
	table->other_errs = htonl(0xfffffff0);
	ft_ipsec_stats_work(NULL);
	assert(xfrm_mib[LINUX_MIB_XFRMINERROR] == 9 + (0xfffffff0 - 64));
	table->other_errs = htonl(5);
	ft_ipsec_stats_work(NULL);
	assert(xfrm_mib[LINUX_MIB_XFRMINERROR] == 9 + (0xfffffff0 - 64) + 21);
	assert(ft_sec_counted[CDX_SEC_REFUSED_OTHER] == 9 + (0xfffffff0 - 64) + 21);

	/* The pass stops once no SA is owned. The last SA out counts what was
	 * refused up to its going; one leaving beside another does not. */
	table->anti_replay_replay_errs = htonl(3 + 4);
	delete_state(in);
	reads = muram_reads;
	bench_drain_retirements();
	assert(muram_reads == reads && xfrm_mib[LINUX_MIB_XFRMINSTATESEQERROR] == 5);
	delete_state(out);
	bench_drain_retirements();
	assert(muram_reads - reads == CDX_SEC_REFUSAL_CLASSES);
	assert(xfrm_mib[LINUX_MIB_XFRMINSTATESEQERROR] == 9);

	/* /proc/cdx_flowtable: the total since load, then every class. */
	ft_sec_refusal_rows(&seq);
	snprintf(row, sizeof(row), "ipsec_sec_refused %llu\n", (unsigned long long)sec_total());
	assert(!strncmp(seq.buf, row, strlen(row)));
	assert(strstr(seq.buf, "\nipsec_sec_refused_buffer_depletion 7\n"));
	assert(strstr(seq.buf, "\nipsec_sec_refused_ttl_zero 4\n"));
	assert(strstr(seq.buf, "\nipsec_sec_refused_replay 7\n"));
	/* The fault line has room for every fault class moving at once, each
	 * at the widest count a u32 prints. */
	size_t widest = 1;
	for (unsigned i = 0; i < CDX_SEC_REFUSAL_CLASSES; i++)
		if (ft_sec_refusal[i].fault)
			widest += strlen(ft_sec_refusal[i].name) + strlen(" =4294967295");
	assert(widest <= FT_SEC_FAULT_TEXT);
	for (unsigned i = 0; i < CDX_SEC_REFUSAL_CLASSES; i++) {
		/* Every class has a row, under a name no other has. */
		assert(ft_sec_refusal[i].name);
		snprintf(row, sizeof(row), "\nipsec_sec_refused_%s ", ft_sec_refusal[i].name);
		assert(strstr(seq.buf, row));
		for (unsigned j = 0; j < i; j++)
			assert(strcmp(ft_sec_refusal[i].name, ft_sec_refusal[j].name));
		/* A class is folded into a counter of xfrm's, or is a fault
		 * said out loud, or neither; never both. */
		assert(!(ft_sec_refusal[i].mib && ft_sec_refusal[i].fault));
	}

	/* Every counter of the microcode's at once, each moving by an amount
	 * no other does: each lands in its own class and no other, and each
	 * class in the xfrm counter it is folded into, or in none. Named by
	 * field, so a class read from the wrong one fails here. */
#define SEC_FIELD(f) offsetof(en_SEC_failure_stats, f)
	static const struct {
		size_t field;
		enum cdx_sec_refusal cls;
		int mib;	/* zero for none */
	} every[] = {
		{ SEC_FIELD(icv_failures), CDX_SEC_REFUSED_ICV, LINUX_MIB_XFRMINSTATEPROTOERROR },
		{ SEC_FIELD(hw_errs), CDX_SEC_REFUSED_HW, 0 },
		{ SEC_FIELD(CCM_AAD_size_errs), CDX_SEC_REFUSED_CCM_AAD_SIZE, LINUX_MIB_XFRMINSTATEPROTOERROR },
		{ SEC_FIELD(anti_replay_late_errs), CDX_SEC_REFUSED_LATE, LINUX_MIB_XFRMINSTATESEQERROR },
		{ SEC_FIELD(anti_replay_replay_errs), CDX_SEC_REFUSED_REPLAY, LINUX_MIB_XFRMINSTATESEQERROR },
		{ SEC_FIELD(seq_num_overflows), CDX_SEC_REFUSED_SEQ_OVERFLOW, LINUX_MIB_XFRMOUTSTATESEQERROR },
		{ SEC_FIELD(DMA_errs), CDX_SEC_REFUSED_DMA, 0 },
		{ SEC_FIELD(DECO_watchdog_timer_timedout_errs), CDX_SEC_REFUSED_DECO_WATCHDOG, 0 },
		{ SEC_FIELD(input_frame_read_errs), CDX_SEC_REFUSED_INPUT_READ, 0 },
		{ SEC_FIELD(protocol_format_errs), CDX_SEC_REFUSED_PROTOCOL_FORMAT, LINUX_MIB_XFRMINSTATEPROTOERROR },
		{ SEC_FIELD(ipsec_ttl_zero_errs), CDX_SEC_REFUSED_TTL_ZERO, 0 },
		{ SEC_FIELD(ipsec_pad_chk_failures), CDX_SEC_REFUSED_PAD_CHECK, LINUX_MIB_XFRMINSTATEPROTOERROR },
		{ SEC_FIELD(output_frame_length_rollover_errs), CDX_SEC_REFUSED_LENGTH_ROLLOVER, 0 },
		{ SEC_FIELD(tbl_buff_too_small_errs), CDX_SEC_REFUSED_TABLE_TOO_SMALL, 0 },
		{ SEC_FIELD(tbl_buff_pool_depletion_errs), CDX_SEC_REFUSED_TABLE_DEPLETION, 0 },
		{ SEC_FIELD(output_frame_too_large_errs), CDX_SEC_REFUSED_OUTPUT_TOO_LARGE, 0 },
		{ SEC_FIELD(cmpnd_frame_write_errs), CDX_SEC_REFUSED_COMPOUND_WRITE, 0 },
		{ SEC_FIELD(buff_too_small_errs), CDX_SEC_REFUSED_BUFFER_TOO_SMALL, 0 },
		{ SEC_FIELD(buff_pool_depletion_errs), CDX_SEC_REFUSED_BUFFER_DEPLETION, 0 },
		{ SEC_FIELD(output_frame_write_errs), CDX_SEC_REFUSED_OUTPUT_WRITE, 0 },
		{ SEC_FIELD(cmpnd_frame_read_errs), CDX_SEC_REFUSED_COMPOUND_READ, 0 },
		{ SEC_FIELD(prehdr_read_errs), CDX_SEC_REFUSED_PREHEADER_READ, 0 },
		{ SEC_FIELD(other_errs), CDX_SEC_REFUSED_OTHER, LINUX_MIB_XFRMINERROR },
	};
#undef SEC_FIELD
	_Static_assert(sizeof(every) / sizeof(every[0]) == CDX_SEC_REFUSAL_CLASSES,
		       "every class of the microcode's is exercised");
	u64 counted_before[CDX_SEC_REFUSAL_CLASSES], mib_before[__LINUX_MIB_XFRMMAX];
	u64 mib_expected[__LINUX_MIB_XFRMMAX] = { 0 };
	bool covered[CDX_SEC_REFUSAL_CLASSES] = { false };
	unsigned lines = sec_fault_lines;

	memcpy(counted_before, ft_sec_counted, sizeof(counted_before));
	memcpy(mib_before, xfrm_mib, sizeof(mib_before));
	for (unsigned i = 0; i < CDX_SEC_REFUSAL_CLASSES; i++) {
		u32 value;

		/* Byte-wise: the table is packed, and big-endian. */
		memcpy(&value, (u8 *)table + every[i].field, sizeof(value));
		value = htonl(ntohl(value) + 1000 * (i + 1));
		memcpy((u8 *)table + every[i].field, &value, sizeof(value));
	}
	ft_ipsec_stats_work(NULL);
	for (unsigned i = 0; i < CDX_SEC_REFUSAL_CLASSES; i++) {
		enum cdx_sec_refusal cls = every[i].cls;

		assert(!covered[cls]);
		covered[cls] = true;
		assert(ft_sec_counted[cls] - counted_before[cls] == 1000 * (i + 1));
		assert(ft_sec_refusal[cls].mib == every[i].mib);
		mib_expected[every[i].mib] += 1000 * (i + 1);
		/* Each fault class moved, so the one line names each. */
		snprintf(row, sizeof(row), " %s=%u", ft_sec_refusal[cls].name, 1000 * (i + 1));
		assert(!ft_sec_refusal[cls].fault == !strstr(sec_fault_line, row));
	}
	for (unsigned m = 1; m < __LINUX_MIB_XFRMMAX; m++)
		assert(xfrm_mib[m] - mib_before[m] == mib_expected[m]);
	assert(sec_fault_lines == lines + 1);

	/* What SEC produced and the offline port then could not enqueue is
	 * counted beside the refusals, from the port's own counter: from its
	 * first reading on, through a wrap, and not while there is no port to
	 * read, which costs nothing it counted before or after. It reaches no
	 * xfrm counter and no fault line. */
	struct seq_file rows = { .len = 0 };
	unsigned long long mibs = mib_total();

	assert(strstr(seq.buf, "\nipsec_offline_port_rejected 0\n") && !ft_sec_rejected_known);
	lines = sec_fault_lines;
	offline_port_present = true;
	offline_port_rejections = 0xfffffff0;
	ft_ipsec_stats_work(NULL);
	assert(ft_sec_rejected_known && !ft_sec_rejected);
	offline_port_rejections = 0x10;
	ft_ipsec_stats_work(NULL);
	assert(ft_sec_rejected == 0x20);
	offline_port_present = false;
	offline_port_rejections = 0x99;
	ft_ipsec_stats_work(NULL);
	assert(ft_sec_rejected == 0x20);
	offline_port_present = true;
	offline_port_rejections = 0x30;
	ft_ipsec_stats_work(NULL);
	assert(ft_sec_rejected == 0x40);
	assert(mib_total() == mibs && sec_fault_lines == lines);
	ft_sec_refusal_rows(&rows);
	assert(strstr(rows.buf, "\nipsec_offline_port_rejected 64\n"));
	/* Linux's own enqueues SEC's input group refused are counted the same
	 * way, beside it, through a wrap, and reach no xfrm counter either. */
	assert(strstr(rows.buf, "\nipsec_sec_input_refused 0\n") && ft_sec_input_refused_known);
	sec_input_refusals = 0xfffffffc;
	ft_ipsec_stats_work(NULL);
	sec_input_refusals = 3;
	ft_ipsec_stats_work(NULL);
	assert(ft_sec_input_refused == 0xfffffffcull + 7);
	assert(mib_total() == mibs && sec_fault_lines == lines);
	struct seq_file refused = { .len = 0 };
	ft_sec_refusal_rows(&refused);
	snprintf(row, sizeof(row), "\nipsec_sec_input_refused %llu\n", 0xfffffffcull + 7);
	assert(strstr(refused.buf, row));

	bench_clear_sas();
	en_global_muram_mem = NULL;
	ft_sec_known = false;
	memset(ft_sec_counted, 0, sizeof(ft_sec_counted));
	offline_port_present = false;
	ft_sec_rejected_known = false;
	ft_sec_rejected = 0;
	sec_input_refusals = 0;
	ft_sec_input_refused_known = false;
	ft_sec_input_refused = 0;
}

int main(void)
{
	test_spec();
	test_spec_aead();
	test_spec_auth();
	test_spec_mtu();
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
	test_handle_between_translations();
	test_watch_follows_peer();
	test_watch_follows_gateway();
	test_watch_routes_like_install();
	test_watch_egress_change_during_install();
	test_watch_route_and_device();
	test_watch_unreachable_peer();
	test_watch_failures();
	test_watch_delete_ordering();
	test_watch_path_mtu();
	test_watch_sample_route_only();
	test_peer_route_is_the_fibs();
	test_watch_answer_during_probe();
	test_accounting();
	test_sequence_exhaustion();
	test_spec_sequence();
	test_publish_oseq();
	test_replay_seeding();
	test_publish_window();
	test_replay_round_trip();
	test_update_stats();
	test_readd_fold();
	test_remembered_bound();
	test_sec_refusals();
	assert(dev_holds == 0 && neigh_refs == 0 && xfrm_state_refs == 0);
	printf("ipsec adapter: ok\n");
	return 0;
}
