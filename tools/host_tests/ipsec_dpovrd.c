/* The driver's DPOVRD choice is production code; the frames are built here
 * byte by byte, as SEC would read them. */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef uint8_t u8;
typedef uint32_t u32;

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

struct xfrm_state { struct { u8 mode; } props; };
struct iphdr { u8 bytes[20]; };
struct ipv6hdr { u8 version_class[4]; u8 payload_len[2]; u8 nexthdr; u8 hop_limit; u8 addrs[32]; };

#include "ipsec_dpovrd.inc"

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

int main(void)
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
	return 0;
}
