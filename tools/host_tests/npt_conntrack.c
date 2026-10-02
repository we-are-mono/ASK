/* ip6t_NPT's fix-up of the connection it translates, compiled from the kernel.
 *
 * The targets point a connection's reply tuple at the address the peer will
 * answer. That is only safe before the conntrack is confirmed: once it is, it
 * sits in the table hashed on the tuple it has, and a rewrite in place leaves
 * it under one address while holding another. Later packets of a connection
 * are IP_CT_NEW until a reply is seen -- including those the software
 * flowtable forwards to an XFRM output, which carry the confirmed conntrack --
 * and an ICMP error is IP_CT_RELATED to the connection it is about, from
 * whatever address sent it. Neither may touch a confirmed entry.
 */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef uint8_t u8;
typedef uint8_t __u8;
typedef uint16_t __sum16;
typedef uint32_t u32;

#define CONFIG_CPE_FAST_PATH	1
#define __KERNEL__
#define NF_DROP			0
#define XT_CONTINUE		0xFFFFFFFFU
#define ICMPV6_PARAMPROB	4
#define ICMPV6_HDR_FIELD	0
#define IP_CT_DIR_REPLY		1
#define NFCT_INFOMASK		7UL

struct in6_addr { u8 s6_addr[16]; };
union nf_inet_addr { u32 all[4]; struct in6_addr in6; };
#include "npt_types.inc"

struct ipv6hdr { u8 head[8]; struct in6_addr saddr, daddr; };
struct sk_buff { struct ipv6hdr hdr; unsigned long _nfct; };
static struct ipv6hdr *ipv6_hdr(struct sk_buff *skb) { return &skb->hdr; }
struct xt_action_param { const void *targinfo; };
struct nf_conntrack_tuple { struct { union nf_inet_addr u3; } src, dst; };
struct nf_conn {
	struct { struct nf_conntrack_tuple tuple; } tuplehash[2];
	bool confirmed;
};
static struct nf_conn *nf_ct_get(const struct sk_buff *skb, enum ip_conntrack_info *ctinfo)
{
	*ctinfo = skb->_nfct & NFCT_INFOMASK;
	return (struct nf_conn *)(skb->_nfct & ~NFCT_INFOMASK);
}
/* Unused by some forms of the targets, which the test is also run against to
 * see it fail. */
static __attribute__((unused)) bool nf_ct_is_confirmed(const struct nf_conn *ct)
{ return ct->confirmed; }
static __attribute__((unused)) void rcu_read_lock(void) {}
static __attribute__((unused)) void rcu_read_unlock(void) {}

/* The prefix mapping itself is not what is under test: it puts the prefix's
 * first byte in place, which is enough to tell a translated address from an
 * untranslated one. */
static bool ip6t_npt_map_pfx(const struct ip6t_npt_tginfo *npt, struct in6_addr *addr)
{
	addr->s6_addr[0] = npt->dst_pfx.in6.s6_addr[0];
	return true;
}
static struct ipv6hdr *icmpv6_bounced_ipv6hdr(struct sk_buff *skb, struct ipv6hdr *hdr)
{ return NULL; }
static void icmpv6_send(struct sk_buff *skb, int type, int code, size_t info) { assert(0); }
static void ipv6_addr_prefix(struct in6_addr *pfx, const struct in6_addr *addr, int len)
{ assert(0); }
static int ipv6_addr_cmp(const struct in6_addr *a, const struct in6_addr *b) { assert(0); return 0; }

#include "npt_production.inc"

static const struct in6_addr lan = { { 0xfd, 1 } }, remote = { { 0x20, 2 } }, other = { { 0xfd, 9 } };

static void packet(struct sk_buff *skb, struct nf_conn *ct, enum ip_conntrack_info info,
		   struct in6_addr saddr, struct in6_addr daddr)
{
	memset(skb, 0, sizeof(*skb));
	skb->hdr.saddr = saddr;
	skb->hdr.daddr = daddr;
	skb->_nfct = ct ? (unsigned long)ct | info : 0;
}

int main(void)
{
	struct ip6t_npt_tginfo snpt = { .dst_pfx.in6 = { { 0x2a } } };
	struct ip6t_npt_tginfo dnpt = { .dst_pfx.in6 = { { 0xfd } } };
	struct xt_action_param spar = { &snpt }, dpar = { &dnpt };
	struct nf_conn ct;
	struct sk_buff skb;

	/* The first packet of a connection from the LAN: its conntrack is
	 * unconfirmed, and its reply tuple is pointed at the translated source,
	 * which is the address the peer answers. */
	memset(&ct, 0, sizeof(ct));
	ct.tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.in6 = lan;
	packet(&skb, &ct, IP_CT_NEW, lan, remote);
	assert(ip6t_snpt_tg(&skb, &spar) == XT_CONTINUE);
	assert(skb.hdr.saddr.s6_addr[0] == 0x2a);
	assert(!memcmp(&ct.tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.in6, &skb.hdr.saddr,
		       sizeof(skb.hdr.saddr)));

	/* Confirmed: a later packet still IP_CT_NEW, and an ICMP error from
	 * another LAN address related to the connection. Neither rewrites the
	 * tuple the entry is hashed on. */
	ct.confirmed = true;
	struct nf_conntrack_tuple kept = ct.tuplehash[IP_CT_DIR_REPLY].tuple;
	packet(&skb, &ct, IP_CT_NEW, lan, remote);
	assert(ip6t_snpt_tg(&skb, &spar) == XT_CONTINUE);
	packet(&skb, &ct, IP_CT_RELATED, other, remote);
	assert(ip6t_snpt_tg(&skb, &spar) == XT_CONTINUE && skb.hdr.saddr.s6_addr[0] == 0x2a);
	assert(!memcmp(&ct.tuplehash[IP_CT_DIR_REPLY].tuple, &kept, sizeof(kept)));

	/* The mirror: a connection opened from outside, answered from the
	 * address the destination was rewritten to. */
	memset(&ct, 0, sizeof(ct));
	ct.tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.in6 = remote;
	packet(&skb, &ct, IP_CT_NEW, remote, (struct in6_addr){ { 0x2a, 1 } });
	assert(ip6t_dnpt_tg(&skb, &dpar) == XT_CONTINUE);
	assert(ct.tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.in6.s6_addr[0] == 0xfd);
	ct.confirmed = true;
	kept = ct.tuplehash[IP_CT_DIR_REPLY].tuple;
	packet(&skb, &ct, IP_CT_RELATED, remote, (struct in6_addr){ { 0x2a, 9 } });
	assert(ip6t_dnpt_tg(&skb, &dpar) == XT_CONTINUE);
	assert(!memcmp(&ct.tuplehash[IP_CT_DIR_REPLY].tuple, &kept, sizeof(kept)));

	/* And a packet with no conntrack at all is only translated. */
	packet(&skb, NULL, IP_CT_NEW, lan, remote);
	assert(ip6t_snpt_tg(&skb, &spar) == XT_CONTINUE);
	return 0;
}
