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
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
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
struct flowi4 {
	__be32 daddr, saddr;
	__be16 fl4_dport, fl4_sport;
	int flowi4_oif;
	u32 flowi4_mark;
	int flowi4_l3mdev;
	u8 flowi4_proto;
};
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
#define U32_MAX ((u32)~0U)
#define U64_MAX ((u64)~0ULL)
#define lower_32_bits(n) ((u32)(n))
#define upper_32_bits(n) ((u32)((u64)(n) >> 32))

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
		struct { u32 v, m; } smark;
	} props;
	struct { u32 v; } mark;
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
};
static struct cdx_ipsec_sa sa_pool[8];
static unsigned sa_installed, sa_deleted;
static unsigned retirement_flows, retirement_barriers;
static int sa_add_error;
static int sa_next_hop_error;
static unsigned sa_next_hop_calls;

#include "ipsec_types.inc"

static bool cdx_ipsec_port_supported(struct net_device *dev);
static struct net_device *egress_change_during_add;
static void ft_ipsec_egress_changed(const struct net_device *dev);

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
/* What a rebuild in progress lets a drain see, and an egress change landing
 * while it runs. */
static bool ft_ipsec_rebuild_pending(const struct net_device *dev);
static struct net_device *pending_during_rebuild, *egress_change_during_rebuild;
static int cdx_ipsec_sa_set_next_hop(struct cdx_ipsec_sa *sa, const u8 *dst_mac)
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
static void xfrm_dev_state_update_stats(struct xfrm_state *x) { assert(x->lock); }
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
static int route_oif, route_l3mdev;
static u32 route_mark;
/* The last lookup's whole key. */
static struct flowi4 route_key;
static struct dst_ops v4_ops = { .family = AF_INET };
/* The VRF the SA's port is enslaved to, or zero. */
static int port_l3_master;
static int l3mdev_master_ifindex(struct net_device *dev) { (void)dev; return port_l3_master; }
static u32 xfrm_smark_get(u32 mark, struct xfrm_state *x)
{
	return (mark & ~x->props.smark.m) | (x->props.smark.v & x->props.smark.m);
}

static struct rtable *ip_route_output_key(void *net, struct flowi4 *fl4)
{
	(void)net;
	route_oif = fl4->flowi4_oif;
	route_mark = fl4->flowi4_mark;
	route_l3mdev = fl4->flowi4_l3mdev;
	route_key = *fl4;
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
	/* Every deletion counted has reached the hardware. */
	assert(!ft_ipsec_retire_pending());
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
	struct xfrm_encap_tmpl natt = { .encap_type = UDP_ENCAP_ESPINUDP,
					.encap_sport = htons(4500), .encap_dport = htons(61000) };
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

	/* A window SEC cannot keep is refused, and said so, rather than
	 * narrowed into dropping late frames the configuration accepts. */
	esn->replay_window = CDX_IPSEC_REPLAY_WINDOW_MAX + 1;
	ack._msg = NULL;
	assert(ft_ipsec_spec(x, &spec, &ack) == -EOPNOTSUPP && ack._msg);
	/* An outbound SA checks nothing, so any window it names is no reason
	 * to refuse it. */
	x->xso.dir = XFRM_DEV_OFFLOAD_OUT;
	esn->replay_window = 1024;
	assert(ft_ipsec_spec(x, &spec, &ack) == 0);

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

	/* An SA that has sent nothing reads back as installed, which moves
	 * nothing. */
	sa_of(out)->oseq = 0;
	ft_ipsec_stats_work(NULL);
	assert(out->replay.oseq == 0);

	/* The legacy shape takes the number as it is, when nothing was sent in
	 * the period behind it. */
	sa_of(out)->oseq = 4096;
	ft_ipsec_stats_work(NULL);
	assert(out->replay.oseq == 4096);

	/* Ahead by twice what the SA sent in the last period: SEC goes on
	 * numbering until the SA is deleted, and a re-add must start past
	 * wherever it got to. */
	sa_of(out)->packets = 1000;
	sa_of(out)->oseq = 5000;
	ft_ipsec_stats_work(NULL);
	assert(out->replay.oseq == 7000);
	/* A quiet period after it holds the number published, rather than
	 * taking it back to SEC's. */
	sa_of(out)->oseq = 6000;
	ft_ipsec_stats_work(NULL);
	assert(out->replay.oseq == 7000);
	sa_of(out)->packets = 1500;
	sa_of(out)->oseq = 8000;
	ft_ipsec_stats_work(NULL);
	assert(out->replay.oseq == 9000);

	/* ESN splits it across both words, the margin carrying into the high
	 * one. */
	sa_of(esn_out)->packets = 16;
	sa_of(esn_out)->oseq = (3ULL << 32) | 0xfffffff0;
	ft_ipsec_stats_work(NULL);
	assert(esn.oseq == 0x10 && esn.oseq_hi == 4);

	/* Only forward: a value set by other means is not undone by a reading
	 * behind it. */
	out->replay.oseq = 10000;
	ft_ipsec_stats_work(NULL);
	assert(out->replay.oseq == 10000);

	/* Not ESN but in the wide shape: the low word alone. */
	{
		struct xfrm_replay_state_esn wide = { .bmp_len = 4, .oseq_hi = 9 };

		bmp_out->replay_esn = &wide;
		sa_of(bmp_out)->oseq = 77;
		ft_ipsec_stats_work(NULL);
		assert(wide.oseq == 77 && wide.oseq_hi == 9);
		/* And a margin past the end of a 32-bit space stops at the
		 * last number SEC will send, FFFFFFFE -- the truth about an SA
		 * that close. */
		sa_of(bmp_out)->packets = 200;
		sa_of(bmp_out)->oseq = 0xffffff00;
		ft_ipsec_stats_work(NULL);
		assert(wide.oseq == 0xfffffffe && wide.oseq_hi == 9);
		bmp_out->replay_esn = NULL;
	}

	/* An inbound SA has no sequence of its own to publish, whatever it is
	 * handed. */
	test_lock(&in->lock);
	ft_ipsec_publish_oseq(in, 555, 10);
	test_unlock(&in->lock);
	assert(in->replay.oseq == 0);

	/* Not VALID: nothing goes back. */
	out->km.state = XFRM_STATE_EXPIRED;
	sa_of(out)->oseq = 20000;
	ft_ipsec_stats_work(NULL);
	assert(out->replay.oseq == 10000);

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
	first->replay_esn = ring_alloc(96);
	first->repl_mode = XFRM_REPLAY_MODE_BMP;
	receive(first, 1, 200, missing, 3);

	/* To SEC: the spec's scorecard is what SEC starts from. */
	assert(ft_ipsec_spec(first, &spec, &ack) == 0);

	/* From SEC, into a state installed fresh and anchored nowhere yet. */
	second = install_accounted(&second_state, false, 0);
	second->replay_esn = ring_alloc(96);
	second->repl_mode = XFRM_REPLAY_MODE_BMP;
	sa_of(second)->seq = spec.seq;
	memcpy(sa_of(second)->seen, spec.replay_seen, sizeof(spec.replay_seen));
	ft_ipsec_stats_work(NULL);
	for (u64 s = 200 - 95; s <= 201; s++)
		assert(accepts(second, s) == accepts(first, s));

	free(first->replay_esn);
	free(second->replay_esn);
	second->replay_esn = NULL;
	delete_state(second);
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

	bench_clear_sas();
	en_global_muram_mem = NULL;
	ft_sec_known = false;
	memset(ft_sec_counted, 0, sizeof(ft_sec_counted));
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
	test_watch_routes_like_install();
	test_watch_egress_change_during_install();
	test_watch_route_and_device();
	test_watch_unreachable_peer();
	test_watch_failures();
	test_watch_delete_ordering();
	test_accounting();
	test_sequence_exhaustion();
	test_spec_sequence();
	test_publish_oseq();
	test_replay_seeding();
	test_publish_window();
	test_replay_round_trip();
	test_sec_refusals();
	assert(dev_holds == 0 && neigh_refs == 0 && xfrm_state_refs == 0);
	printf("ipsec adapter: ok\n");
	return 0;
}
