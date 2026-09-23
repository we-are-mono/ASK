/* The driver's hand-off to SEC is production code: the L3 finder, the DPOVRD
 * choice and the submit itself. Frames are built here byte by byte, as SEC
 * would read them; the queue manager, the S/G builder and the skb are stubs
 * that count what was done with the frame. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define htons(x) ((u16)__builtin_bswap16((u16)(x)))
#else
#define htons(x) ((u16)(x))
#endif
#define ntohs(x) htons(x)

#define __hot
#define unlikely(x) (x)
#define READ_ONCE(x) (x)
#define pr_err_ratelimited(...) ((void)0)
#define net_err_ratelimited(...) ((void)0)

#define XFRM_MODE_TRANSPORT 0
#define XFRM_MODE_TUNNEL 1
#define IPVERSION 4
#define IPPROTO_IPIP 4
#define IPPROTO_UDP 17
#define IPPROTO_IPV6 41
#define IPPROTO_ESP 50
#define NEXTHDR_HOP 0
#define NEXTHDR_ROUTING 43
#define NEXTHDR_DEST 60
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_8021Q 0x8100
#define ETH_P_PPP_SES 0x8864
#define PPP_IP 0x21
#define PPP_IPV6 0x57

struct xfrm_state { struct { u8 mode; } props; u32 handle; };
struct iphdr { u8 bytes[20]; };
struct ipv6hdr { u8 version_class[4]; u8 payload_len[2]; u8 nexthdr; u8 hop_limit; u8 addrs[32]; };
struct sec_path { int len; struct xfrm_state *xvec[6]; };
struct sk_buff {
	unsigned char *data;
	unsigned int len, data_len;
	struct sec_path *sp;
};
struct net_device { unsigned long tx_dropped; unsigned trans; };
struct device { int unused; };
struct dpa_bp { struct device *dev; };
struct qman_fq { int unused; };
struct qm_fd { u32 cmd; };

static struct sec_path *skb_sec_path(const struct sk_buff *skb) { return skb->sp; }
static unsigned int skb_headlen(const struct sk_buff *skb) { return skb->len - skb->data_len; }

typedef struct qman_fq *(*cdx_get_ipsec_fq_hook_t)(u32 handle);
static cdx_get_ipsec_fq_hook_t cdx_get_ipsec_fq_hookfn;

/* What happened to the frame. */
static struct {
	int cow_result, sg_result, enqueue_result;
	unsigned enqueue_busy;
	unsigned cows, sg_calls, enqueues, releases, frees;
	u32 sg_cmd;
} bench;

static int skb_cow_head(struct sk_buff *skb, unsigned int headroom)
{
	(void)skb; (void)headroom;
	bench.cows++;
	return bench.cow_result;
}

static int skb_fraglist_to_sg_fd(struct device *dev, struct net_device *net_dev,
				 struct sk_buff *skb, struct qm_fd *fd, u32 fd_cmd)
{
	(void)dev; (void)net_dev; (void)skb;
	bench.sg_calls++;
	bench.sg_cmd = fd_cmd;
	fd->cmd = fd_cmd;
	return bench.sg_result;
}

static int qman_enqueue(struct qman_fq *fq, const struct qm_fd *fd, u32 flags)
{
	(void)fq; (void)fd; (void)flags;
	bench.enqueues++;
	if (bench.enqueue_busy) {
		bench.enqueue_busy--;
		return -EBUSY;
	}
	return bench.enqueue_result;
}

static void dpaa_sec_sg_release(const struct qm_fd *fd, bool free_skb)
{
	(void)fd;
	/* The submit frees the skb itself; the release must not as well. */
	assert(!free_skb);
	bench.releases++;
}

static void kfree_skb(struct sk_buff *skb) { (void)skb; bench.frees++; }
static void dev_core_stats_tx_dropped_inc(struct net_device *dev) { dev->tx_dropped++; }
static void netif_trans_update(struct net_device *dev) { dev->trans++; }

#include "ipsec_sec_submit.inc"

static const struct xfrm_state tunnel = { .props.mode = XFRM_MODE_TUNNEL };
static const struct xfrm_state transport = { .props.mode = XFRM_MODE_TRANSPORT };

static u32 expect(unsigned hdr_len, unsigned nh_offset)
{
	return DPOVRD_ENABLE | hdr_len << 16 | nh_offset << 8 | IPPROTO_ESP;
}

/* An IPv6 header followed by `n` extension headers of the given types and
 * eight-byte lengths, then UDP. */
static unsigned build6(u8 *frame, const u8 *types, const u8 *units, int n)
{
	unsigned off = sizeof(struct ipv6hdr);

	memset(frame, 0, 512);
	frame[0] = 0x60;
	frame[6] = n ? types[0] : IPPROTO_UDP;
	for (int i = 0; i < n; i++) {
		frame[off] = i + 1 < n ? types[i + 1] : IPPROTO_UDP;
		frame[off + 1] = units[i] - 1;
		off += units[i] * 8;
	}
	return off;
}

static void test_dpovrd(void)
{
	u8 frame[512] = {0};
	u32 dpovrd;

	/* A tunnel's trailer names the inner packet's own protocol. */
	frame[0] = 0x45;
	assert(dpa_ipsec_dpovrd(&tunnel, frame, 64, &dpovrd));
	assert(dpovrd == (DPOVRD_ENABLE | IPPROTO_IPIP));
	frame[0] = 0x60;
	assert(dpa_ipsec_dpovrd(&tunnel, frame, 64, &dpovrd));
	assert(dpovrd == (DPOVRD_ENABLE | IPPROTO_IPV6));

	/* Transport IPv4: the header's own length, options included, and the
	 * protocol byte swapped for ESP. */
	frame[0] = 0x45;
	assert(dpa_ipsec_dpovrd(&transport, frame, 64, &dpovrd) && dpovrd == expect(20, 1));
	frame[0] = 0x46;
	assert(dpa_ipsec_dpovrd(&transport, frame, 64, &dpovrd) && dpovrd == expect(24, 1));
	frame[0] = 0x4f;
	assert(dpa_ipsec_dpovrd(&transport, frame, 64, &dpovrd) && dpovrd == expect(60, 1));
	/* Shorter than a header, or longer than what is there. */
	frame[0] = 0x44;
	assert(!dpa_ipsec_dpovrd(&transport, frame, 64, &dpovrd));
	frame[0] = 0x4f;
	assert(!dpa_ipsec_dpovrd(&transport, frame, 40, &dpovrd));

	/* Transport IPv6 with no extension headers: byte 6, offset one. */
	unsigned len = build6(frame, NULL, NULL, 0);
	assert(dpa_ipsec_dpovrd(&transport, frame, len + 8, &dpovrd) && dpovrd == expect(40, 1));

	/* Hop-by-hop options stay ahead of ESP; its own next-header byte, at
	 * 40, is the one swapped. */
	len = build6(frame, (u8[]){NEXTHDR_HOP}, (u8[]){1}, 1);
	assert(len == 48);
	assert(dpa_ipsec_dpovrd(&transport, frame, len + 8, &dpovrd) && dpovrd == expect(48, 5));

	/* Destination options ahead of a routing header stay ahead of ESP with
	 * it; ones after the routing header are encrypted. */
	len = build6(frame, (u8[]){NEXTHDR_DEST, NEXTHDR_ROUTING, NEXTHDR_DEST},
		     (u8[]){1, 3, 1}, 3);
	assert(dpa_ipsec_dpovrd(&transport, frame, len + 8, &dpovrd) && dpovrd == expect(72, 6));

	/* Destination options with no routing header are not the transport
	 * payload's either, as ip6_find_1stfragopt() has it. */
	len = build6(frame, (u8[]){NEXTHDR_DEST}, (u8[]){2}, 1);
	assert(dpa_ipsec_dpovrd(&transport, frame, len + 8, &dpovrd) && dpovrd == expect(56, 5));

	/* An extension header running past the frame, and headers longer than
	 * the eight-bit length field SEC is given. */
	len = build6(frame, (u8[]){NEXTHDR_HOP}, (u8[]){4}, 1);
	assert(!dpa_ipsec_dpovrd(&transport, frame, 60, &dpovrd));
	len = build6(frame, (u8[]){NEXTHDR_HOP, NEXTHDR_ROUTING}, (u8[]){16, 16}, 2);
	assert(len > 0xff && !dpa_ipsec_dpovrd(&transport, frame, len + 8, &dpovrd));
}

static struct qman_fq sec_fq;
static struct qman_fq *fq_answer;
static u32 fq_asked;

static struct qman_fq *get_fq(u32 handle)
{
	fq_asked = handle;
	return fq_answer;
}

static _Alignas(8) u8 buffer[128];
static struct xfrm_state sa = { .props.mode = XFRM_MODE_TRANSPORT, .handle = 77 };
static struct sec_path sp = { .len = 1, .xvec = { &sa } };
static struct net_device port;
static struct device sec_dev;
static struct dpa_bp bp = { .dev = &sec_dev };
static struct sk_buff skb;

/* A 64-byte IPv4 packet whose first byte is `ip0`, behind an Ethernet
 * header, VLAN-tagged if asked, ready to submit. */
static void frame(u8 ip0, bool vlan)
{
	unsigned l3 = vlan ? 18 : 14;

	memset(buffer, 0, sizeof(buffer));
	memset(buffer, 0xaa, 6);
	memset(buffer + 6, 0xbb, 6);
	if (vlan) {
		*(u16 *)(buffer + 12) = htons(ETH_P_8021Q);
		*(u16 *)(buffer + 14) = htons(5);
	}
	*(u16 *)(buffer + l3 - 2) = htons(ETH_P_IP);
	buffer[l3] = ip0;
	skb = (struct sk_buff){ .data = buffer, .len = l3 + 64, .sp = &sp };
	memset(&bench, 0, sizeof(bench));
	port = (struct net_device){ 0 };
	cdx_get_ipsec_fq_hookfn = get_fq;
	fq_answer = &sec_fq;
	fq_asked = 0;
}

static int submit(void)
{
	return dpaa_submit_outb_pkt_to_SEC(&skb, &port, &bp);
}

/* Freed once, counted once as the port's transmit drop, and never reported
 * as transmitted. */
static bool dropped(void)
{
	return bench.frees == 1 && port.tx_dropped == 1 && port.trans == 0;
}

static void test_submit(void)
{
	/* SEC has it: 0, nothing freed, nothing dropped, and the transport
	 * frame's own header described. */
	frame(0x46, false);
	assert(submit() == 0);
	assert(fq_asked == 77 && bench.enqueues == 1 && port.trans == 1);
	assert(bench.frees == 0 && port.tx_dropped == 0);
	assert(bench.sg_cmd == expect(24, 1));

	/* A busy queue is retried, not refused. */
	frame(0x45, false);
	bench.enqueue_busy = 2;
	assert(submit() == 0 && bench.enqueues == 3 && port.tx_dropped == 0);

	/* A VLAN tag is folded into the Ethernet header SEC copies, and the
	 * header is still measured from the IP header. */
	frame(0x45, true);
	assert(submit() == 0 && bench.cows == 1);
	assert(skb.data == buffer + 4 && skb.len == 14 + 64);
	assert(skb.data[0] == 0xaa && skb.data[6] == 0xbb);
	assert(*(u16 *)(skb.data + 12) == htons(ETH_P_IP));
	assert(bench.sg_cmd == expect(20, 1));

	/* Every way it can fail answers non-zero and counts a drop. */
	frame(0x45, false);
	cdx_get_ipsec_fq_hookfn = NULL;
	assert(submit() != 0 && dropped() && bench.sg_calls == 0);

	frame(0x45, false);
	skb.sp = NULL;
	assert(submit() != 0 && dropped() && bench.sg_calls == 0);

	frame(0x45, false);
	fq_answer = NULL;
	assert(submit() != 0 && dropped() && bench.sg_calls == 0);

	frame(0x45, true);
	bench.cow_result = -ENOMEM;
	assert(submit() == -ENOMEM && dropped() && bench.sg_calls == 0);

	/* A header DPOVRD cannot describe. */
	frame(0x44, false);
	assert(submit() == -EINVAL && dropped() && bench.sg_calls == 0);

	frame(0x45, false);
	bench.sg_result = -ENOMEM;
	assert(submit() == -ENOMEM && dropped() && bench.enqueues == 0);

	/* A queue busy through every retry gives up with -EBUSY, and the S/G
	 * table goes back with the frame. */
	frame(0x45, false);
	bench.enqueue_busy = 100000;
	assert(submit() == -EBUSY && dropped());
	assert(bench.enqueues == 100000 && bench.releases == 1);

	/* So does a queue that refuses it outright, without a retry. */
	frame(0x45, false);
	bench.enqueue_result = -EIO;
	assert(submit() == -EIO && dropped());
	assert(bench.enqueues == 1 && bench.releases == 1);
}

int main(void)
{
	test_dpovrd();
	test_submit();
	return 0;
}
