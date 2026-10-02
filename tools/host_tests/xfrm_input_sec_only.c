/* xfrm_input() itself, compiled from the patched tree, around a state the DPAA
 * offload module holds (a packet-offloaded state with a handle) and states it
 * does not. Everything xfrm_input() calls is a stub that records what was done
 * with the frame: whether the driver was asked to hand it to SEC, whether
 * software ESP ran, what was counted, and whether the skb was freed or
 * delivered. */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint32_t __be32;

#define CONFIG_INET_IPSEC_OFFLOAD 1
#define likely(x) (x)
#define unlikely(x) (x)
#define be32_to_cpu(x) (x)
#define htonl(x) (x)

#define AF_UNSPEC 0
#define AF_INET 2
#define AF_INET6 10
#define EBADMSG 74
#define EAFNOSUPPORT 97
#define EINPROGRESS 115
#define IPPROTO_IPIP 4
#define IPPROTO_ESP 50
#define UDP_ENCAP_ESPINUDP 2
#define XFRM_MAX_DEPTH 6
#define XFRM_MODE_FLAG_TUNNEL 1
#define XFRM_GRO 32
#define CRYPTO_SUCCESS 1
#define CRYPTO_DONE 2
#define CRYPTO_TRANSPORT_AH_AUTH_FAILED 8
#define CRYPTO_TRANSPORT_ESP_AUTH_FAILED 16
#define CRYPTO_TUNNEL_AH_AUTH_FAILED 32
#define CRYPTO_TUNNEL_ESP_AUTH_FAILED 64
#define CRYPTO_INVALID_PROTOCOL 128

/* xfrm's own MIB numbering, from the tree. */
#include "xfrm_input_mib.inc"

enum { XFRM_STATE_VOID, XFRM_STATE_ACQ, XFRM_STATE_VALID, XFRM_STATE_ERROR,
       XFRM_STATE_EXPIRED, XFRM_STATE_DEAD };
enum { XFRM_SA_DIR_IN = 1, XFRM_SA_DIR_OUT };
enum xfrm_dev_offload_type { XFRM_DEV_OFFLOAD_UNSPECIFIED, XFRM_DEV_OFFLOAD_CRYPTO,
			     XFRM_DEV_OFFLOAD_PACKET };

struct net { unsigned long mib[__LINUX_MIB_XFRMMAX]; };
#define XFRM_INC_STATS(net, field) ((net)->mib[field]++)
struct net_device { struct net *net; int held; };
struct dst_entry { int unused; };
struct ip_tunnel { struct { u32 i_key; } parms; };
struct ip6_tnl { struct { u32 i_key; } parms; };
typedef union { u32 a4; u32 a6[4]; } xfrm_address_t;

struct xfrm_state;
struct sk_buff;
struct xfrm_type {
	u8 proto;
	int (*input)(struct xfrm_state *x, struct sk_buff *skb);
};
struct xfrm_type_offload { int (*input_tail)(struct xfrm_state *x, struct sk_buff *skb); };
struct xfrm_encap_tmpl { u16 encap_type; };
struct xfrm_state {
	struct { int state; } km;
	u8 dir;
	struct { struct net_device *dev; enum xfrm_dev_offload_type type; } xso;
	u16 handle;
	int lock;
	struct xfrm_encap_tmpl *encap;
	struct { unsigned short family; } props;
	const struct xfrm_type *type;
	const struct xfrm_type_offload *type_offload;
	struct { unsigned int flags; } outer_mode;
	struct { xfrm_address_t daddr; } id;
	struct { u64 bytes, packets; } curlft;
	long long lastused;
	struct { u32 integrity_failed; } stats;
	int refs;
};
struct sec_path { int len, olen; struct xfrm_state *xvec[XFRM_MAX_DEPTH]; };
struct xfrm_offload { u32 flags, status; };
struct sk_buff {
	struct net_device *dev;
	u32 mark;
	unsigned int len;
	_Alignas(8) char cb[48];
	struct sec_path *sp, sp_storage;
	struct xfrm_offload *xo;
	struct dst_entry *dst;
	unsigned char *nh;
};

struct xfrm_tunnel_skb_cb {
	char header[8];
	union { struct ip_tunnel *ip4; struct ip6_tnl *ip6; } tunnel;
};
struct xfrm_skb_cb {
	struct xfrm_tunnel_skb_cb header;
	union { struct { u32 low, hi; } output; struct { __be32 low, hi; } input; } seq;
};
struct xfrm_mode_skb_cb { struct xfrm_tunnel_skb_cb header; u8 protocol; };
struct xfrm_spi_skb_cb {
	struct xfrm_tunnel_skb_cb header;
	unsigned int daddroff;
	unsigned int family;
	__be32 seq;
};
#define XFRM_TUNNEL_SKB_CB(s) ((struct xfrm_tunnel_skb_cb *)&(s)->cb[0])
#define XFRM_SKB_CB(s) ((struct xfrm_skb_cb *)&(s)->cb[0])
#define XFRM_MODE_SKB_CB(s) ((struct xfrm_mode_skb_cb *)&(s)->cb[0])
#define XFRM_SPI_SKB_CB(s) ((struct xfrm_spi_skb_cb *)&(s)->cb[0])
_Static_assert(sizeof(struct xfrm_skb_cb) <= 48 && sizeof(struct xfrm_spi_skb_cb) <= 48,
	       "control block");

/* What happened to the frame. */
static struct {
	unsigned submits, software, advances, frees, delivered, lookups;
	int submit_result;
	struct xfrm_state *submitted;
} bench;
static int lock_depth, rcu_depth;
static struct xfrm_state *table;

static struct net *dev_net(const struct net_device *dev) { return dev->net; }
static struct xfrm_offload *xfrm_offload(struct sk_buff *skb) { return skb->xo; }
static struct xfrm_state *xfrm_input_state(struct sk_buff *skb)
{
	return skb->sp->xvec[skb->sp->len - 1];
}
static struct sec_path *secpath_set(struct sk_buff *skb)
{
	if (!skb->sp)
		skb->sp = &skb->sp_storage;
	return skb->sp;
}
static struct sec_path *skb_sec_path(struct sk_buff *skb) { return skb->sp; }
static void secpath_reset(struct sk_buff *skb)
{
	if (!skb->sp)
		return;
	for (int i = 0; i < skb->sp->len; i++)
		skb->sp->xvec[i]->refs--;
	skb->sp = NULL;
}
static int xfrm_parse_spi(struct sk_buff *skb, u8 nexthdr, __be32 *spi, __be32 *seq)
{
	(void)skb; (void)nexthdr;
	*spi = 0x1000;
	*seq = 1;
	return 0;
}
static unsigned char *skb_network_header(const struct sk_buff *skb) { return skb->nh; }
static struct xfrm_state *xfrm_input_state_lookup(struct net *net, u32 mark,
						  const xfrm_address_t *daddr, __be32 spi,
						  u8 proto, unsigned short family)
{
	(void)net; (void)mark; (void)daddr; (void)spi; (void)proto; (void)family;
	bench.lookups++;
	if (table)
		table->refs++;
	return table;
}
static void xfrm_audit_state_notfound(struct sk_buff *skb, u16 family, __be32 spi, __be32 seq)
{ (void)skb; (void)family; (void)spi; (void)seq; }
static void xfrm_audit_state_icvfail(struct xfrm_state *x, struct sk_buff *skb, u8 proto)
{ (void)x; (void)skb; (void)proto; }
static void xfrm_state_put(struct xfrm_state *x) { assert(x->refs > 0); x->refs--; }
static u32 xfrm_smark_get(u32 mark, struct xfrm_state *x) { (void)x; return mark; }
static void skb_dst_force(struct sk_buff *skb) { (void)skb; }
static struct dst_entry *skb_dst(const struct sk_buff *skb) { return skb->dst; }
static bool skb_valid_dst(const struct sk_buff *skb) { (void)skb; return false; }
static void skb_dst_drop(struct sk_buff *skb) { (void)skb; }
static void spin_lock(int *lock) { assert(!*lock); *lock = 1; lock_depth++; }
static void spin_unlock(int *lock) { assert(*lock); *lock = 0; lock_depth--; }
static void rcu_read_lock(void) { rcu_depth++; }
static void rcu_read_unlock(void) { rcu_depth--; }
static int xfrm_replay_check(struct xfrm_state *x, struct sk_buff *skb, __be32 seq)
{ (void)x; (void)skb; (void)seq; return 0; }
static int xfrm_replay_recheck(struct xfrm_state *x, struct sk_buff *skb, __be32 seq)
{ (void)x; (void)skb; (void)seq; return 0; }
static void xfrm_replay_advance(struct xfrm_state *x, __be32 seq)
{ (void)x; (void)seq; bench.advances++; }
static u32 xfrm_replay_seqhi(struct xfrm_state *x, __be32 seq) { (void)x; (void)seq; return 0; }
static int xfrm_state_check_expire(struct xfrm_state *x) { (void)x; return 0; }
static int xfrm_tunnel_check(struct sk_buff *skb, struct xfrm_state *x, unsigned int family)
{ (void)skb; (void)x; (void)family; return 0; }
static int xfrm_inner_mode_input(struct xfrm_state *x, struct sk_buff *skb)
{ (void)x; (void)skb; return 0; }
static void dev_hold(struct net_device *dev) { dev->held++; }
static void dev_put(struct net_device *dev) { dev->held--; }
static long long ktime_get_real_seconds(void) { return 1; }
static int xfrm_rcv_cb(struct sk_buff *skb, unsigned int family, u8 protocol, int err)
{ (void)skb; (void)family; (void)protocol; (void)err; return 0; }
static void nf_reset_ct(struct sk_buff *skb) { (void)skb; }
static struct gro_cells { int unused; } gro_cells;
static void gro_cells_receive(struct gro_cells *cells, struct sk_buff *skb)
{
	(void)cells;
	bench.delivered++;
	secpath_reset(skb);
}
struct xfrm_state_afinfo { int (*transport_finish)(struct sk_buff *skb, int async); };
static const struct xfrm_state_afinfo *xfrm_state_afinfo_get_rcu(unsigned int family)
{ (void)family; return NULL; }
static void kfree_skb(struct sk_buff *skb)
{
	bench.frees++;
	secpath_reset(skb);
}

/* The DPAA driver's side: SEC takes the frame, or it is given back as it
 * came. Asked about only the states the offload module holds. */
static int dpaa_submit_inb_pkt_to_SEC(struct sk_buff *skb, const struct xfrm_state *x)
{
	(void)skb;
	assert(x->xso.type == XFRM_DEV_OFFLOAD_PACKET && x->handle);
	bench.submits++;
	bench.submitted = (struct xfrm_state *)x;
	return bench.submit_result;
}

#include "xfrm_input_sec_only.inc"

/* Software ESP: decrypts, and says the inner packet is IPv4 in a tunnel. */
static int esp_input(struct xfrm_state *x, struct sk_buff *skb)
{
	(void)x; (void)skb;
	bench.software++;
	return IPPROTO_IPIP;
}
static const struct xfrm_type esp_type = { .proto = IPPROTO_ESP, .input = esp_input };

static struct net net;
static struct net_device port = { .net = &net }, other_nic = { .net = &net };
static struct dst_entry route;
static unsigned char packet[64];

static struct xfrm_state state(enum xfrm_dev_offload_type type, u16 handle)
{
	return (struct xfrm_state){
		.km.state = XFRM_STATE_VALID, .dir = XFRM_SA_DIR_IN,
		.xso = { .dev = type ? &port : NULL, .type = type }, .handle = handle,
		.props.family = AF_INET, .type = &esp_type,
		.outer_mode.flags = XFRM_MODE_FLAG_TUNNEL,
	};
}

static struct sk_buff skb;
static unsigned long before[__LINUX_MIB_XFRMMAX];

/* An ESP datagram on its way in by `dev`, as xfrm4_rcv() hands it over. */
static void frame(struct net_device *dev)
{
	memset(&bench, 0, sizeof(bench));
	memcpy(before, net.mib, sizeof(before));
	skb = (struct sk_buff){ .dev = dev, .len = 64, .dst = &route, .nh = packet };
	XFRM_SPI_SKB_CB(&skb)->family = AF_INET;
	XFRM_SPI_SKB_CB(&skb)->daddroff = 16;
}

/* The counters that moved since the frame came in, one each. */
static bool counted(int field)
{
	for (int i = 0; i < __LINUX_MIB_XFRMMAX; i++)
		if (net.mib[i] - before[i] != (unsigned long)(i == field))
			return false;
	return true;
}

static bool nothing_counted(void) { return counted(-1); }

/* Decrypted in software and delivered, as upstream does. */
static bool software(void)
{
	return bench.software == 1 && bench.advances == 1 && bench.delivered == 1 &&
	       !bench.frees && nothing_counted();
}

/* Dropped without being decrypted, counted as a state mismatch. */
static bool dropped(void)
{
	return !bench.software && !bench.advances && !bench.delivered && bench.frees == 1 &&
	       counted(LINUX_MIB_XFRMINSTATEMISMATCH);
}

static int input(void) { return xfrm_input(&skb, IPPROTO_ESP, 0, 0); }

/* The GRO entry: esp4_gro_receive() found the state, put it on the secpath
 * with an offload record flagged XFRM_GRO, and calls in with that record,
 * which takes xfrm_input() past the per-state loop and its driver hand-off. */
static struct xfrm_offload gro = { .flags = XFRM_GRO };
static int input_gro(struct xfrm_state *x)
{
	struct sec_path *sp = secpath_set(&skb);

	x->refs++;
	sp->xvec[sp->len++] = x;
	sp->olen++;
	skb.xo = &gro;
	XFRM_SPI_SKB_CB(&skb)->seq = 1;
	return xfrm_input(&skb, IPPROTO_ESP, 0x1000, 0);
}

int main(void)
{
	struct xfrm_state held = state(XFRM_DEV_OFFLOAD_PACKET, 7);
	struct xfrm_state foreign = state(XFRM_DEV_OFFLOAD_PACKET, 0);
	struct xfrm_state crypto = state(XFRM_DEV_OFFLOAD_CRYPTO, 0);
	struct xfrm_state plain = state(XFRM_DEV_OFFLOAD_UNSPECIFIED, 0);

	/* SEC takes it: consumed, nothing else done and nothing counted. The
	 * secpath entry now travels with SEC's job. */
	table = &held;
	frame(&port);
	bench.submit_result = 0;
	assert(input() == 0 && bench.submits == 1 && bench.submitted == &held);
	assert(!bench.software && !bench.frees && !bench.delivered && nothing_counted());
	assert(skb.sp->len == 1 && held.refs == 1 && !lock_depth);
	secpath_reset(&skb);

	/* SEC does not take it -- another device, another port, a queue that
	 * refused it, no queue at all: dropped, counted, never decrypted, and
	 * the state's reference given back with the skb. */
	frame(&other_nic);
	bench.submit_result = -1;
	assert(input() == 0 && bench.submits == 1 && dropped());
	assert(held.refs == 0 && !lock_depth);

	/* The same state reached through GRO never meets the driver at all,
	 * and is dropped the same way. */
	frame(&other_nic);
	assert(input_gro(&held) == 0 && !bench.submits && !bench.lookups && dropped());
	assert(held.refs == 0 && !lock_depth);

	/* A state of the offload module that is no longer live is refused as
	 * dead before anything else, and never offered to the driver. */
	held.km.state = XFRM_STATE_DEAD;
	frame(&port);
	assert(input() == 0 && !bench.submits && !bench.software && bench.frees == 1);
	assert(counted(LINUX_MIB_XFRMINSTATEINVALID) && held.refs == 0);
	frame(&other_nic);
	assert(input_gro(&held) == 0 && !bench.software && bench.frees == 1);
	assert(counted(LINUX_MIB_XFRMINSTATEINVALID) && held.refs == 0);
	held.km.state = XFRM_STATE_VALID;

	/* NAT-T: the UDP socket's receive hands the frame in with its encap
	 * type, through the same loop. SEC takes it or it is dropped; the GRO
	 * form of it is dropped too. */
	struct xfrm_encap_tmpl natt = { .encap_type = UDP_ENCAP_ESPINUDP };
	held.encap = &natt;
	frame(&port);
	bench.submit_result = 0;
	assert(xfrm_input(&skb, IPPROTO_ESP, 0, UDP_ENCAP_ESPINUDP) == 0 && bench.submits == 1);
	assert(!bench.software && !bench.frees && nothing_counted());
	secpath_reset(&skb);
	frame(&port);
	bench.submit_result = -1;
	assert(xfrm_input(&skb, IPPROTO_ESP, 0, UDP_ENCAP_ESPINUDP) == 0 && dropped());
	frame(&other_nic);
	held.refs++;
	secpath_set(&skb)->xvec[skb.sp->len++] = &held;
	skb.sp->olen++;
	skb.xo = &gro;
	assert(xfrm_input(&skb, IPPROTO_ESP, 0x1000, UDP_ENCAP_ESPINUDP) == 0 && dropped());
	assert(held.refs == 0 && !lock_depth);
	held.encap = NULL;

	/* A packet-offloaded state of any other driver has no handle: it is
	 * never offered to this driver and is decrypted as upstream does, by
	 * either entry. So are crypto-offloaded and plain states. */
	struct xfrm_state *others[] = { &foreign, &crypto, &plain };
	for (unsigned i = 0; i < sizeof(others) / sizeof(others[0]); i++) {
		table = others[i];
		frame(&port);
		assert(input() == 0 && !bench.submits && software());
		assert(others[i]->refs == 0 && !lock_depth);
		frame(&other_nic);
		assert(input_gro(others[i]) == 0 && !bench.submits && software());
		assert(others[i]->refs == 0 && !lock_depth);
	}
	return 0;
}
