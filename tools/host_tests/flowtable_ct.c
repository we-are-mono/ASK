/* Compile the kernel's software flowtable forward step and prove it hands the
 * frame its flow's conntrack.
 *
 * A frame the software flowtable forwards bypasses the stack, and without its
 * conntrack everything after it -- an egress qdisc classifying by the
 * connection's mark, CDX's queue selection among them -- takes it for an
 * untracked frame. The forward step is compiled from the kernel source; what it
 * calls is simulated, down to the conntrack's reference count, so a leaked or
 * missing reference, a frame given a conntrack on a path that returns it to
 * the stack, or a second accounting update fails here.
 */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef uint8_t u8;
typedef uint32_t u32;

#define unlikely(x) (x)
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define ENOMEM 12

/* The real conntrack enums, taken from the uapi header. */
#include "flowtable_ct_types.inc"

struct nf_conntrack { unsigned use; };
struct nf_conn {
    struct nf_conntrack ct_general;
    unsigned long status;
    unsigned long long acct_packets[2], acct_bytes[2];
};
static bool test_bit(unsigned nr, const unsigned long *addr) { return (*addr >> nr) & 1; }

enum flow_offload_tuple_dir { FLOW_OFFLOAD_DIR_ORIGINAL, FLOW_OFFLOAD_DIR_REPLY,
                              FLOW_OFFLOAD_DIR_MAX };
struct flow_offload_tuple { enum flow_offload_tuple_dir dir; unsigned mtu; };
struct flow_offload_tuple_rhash { struct flow_offload_tuple tuple; };
struct flow_offload {
    struct flow_offload_tuple_rhash tuplehash[FLOW_OFFLOAD_DIR_MAX];
    struct nf_conn *ct;
    bool torn_down;
    unsigned refreshed;
};
#define NF_FLOWTABLE_COUNTER 0x8
struct nf_flowtable { unsigned flags; };
struct net_device { int ifindex; };
/* The kernel file's own context, restated: it is a file-local struct. */
struct nf_flowtable_ctx { const struct net_device *in; u32 offset; u32 hdrsize; };

struct iphdr { u8 ihl, protocol, ttl; };
struct ipv6hdr { u8 nexthdr, hop_limit; };
struct sk_buff {
    unsigned len;
    unsigned long _nfct;
    union { struct iphdr ip; struct ipv6hdr ip6; } header;
};
static unsigned char *skb_network_header(struct sk_buff *skb) { return (unsigned char *)&skb->header; }
static struct iphdr *ip_hdr(struct sk_buff *skb) { return &skb->header.ip; }
static struct ipv6hdr *ipv6_hdr(struct sk_buff *skb) { return &skb->header.ip6; }

/* --- the conntrack's reference and the skb's slot ----------------------- */
static struct nf_conntrack *skb_nfct(const struct sk_buff *skb)
{ return (struct nf_conntrack *)(skb->_nfct & ~7UL); }
static void nf_conntrack_get(struct nf_conntrack *nfct) { assert(nfct->use); nfct->use++; }
static void nf_conntrack_put(struct nf_conntrack *nfct) { if (nfct) { assert(nfct->use); nfct->use--; } }
static void nf_reset_ct(struct sk_buff *skb) { nf_conntrack_put(skb_nfct(skb)); skb->_nfct = 0; }
static void nf_ct_set(struct sk_buff *skb, struct nf_conn *ct, enum ip_conntrack_info info)
{ assert(!skb->_nfct); skb->_nfct = (unsigned long)ct | info; }

/* --- the rest of the forward step, each a way back to the stack --------- */
static bool too_big, closing, stale_route, unwritable;
static unsigned accounted, rewritten;
static bool nf_flow_exceeds_mtu(const struct sk_buff *skb, unsigned int mtu) { return too_big; }
static int nf_flow_state_check(struct flow_offload *flow, int proto, struct sk_buff *skb,
                               unsigned int thoff) { return closing ? -1 : 0; }
static bool nf_flow_dst_check(const struct nf_flowtable *t, struct flow_offload_tuple *tuple)
{ return !stale_route; }
static void flow_offload_teardown(struct flow_offload *flow) { flow->torn_down = true; }
static int skb_try_make_writable(struct sk_buff *skb, unsigned int len) { return unwritable ? -ENOMEM : 0; }
static void flow_offload_refresh(struct nf_flowtable *t, struct flow_offload *flow, bool force)
{ flow->refreshed++; }
static void nf_flow_encap_pop(struct sk_buff *skb, struct flow_offload_tuple_rhash *t) { }
static void nf_flow_nat_ip(const struct flow_offload *flow, struct sk_buff *skb,
                           unsigned int thoff, enum flow_offload_tuple_dir dir,
                           struct iphdr *iph)
{ assert(!skb->_nfct || skb_nfct(skb) != &flow->ct->ct_general); rewritten++; }
static void nf_flow_nat_ipv6(const struct flow_offload *flow, struct sk_buff *skb,
                             enum flow_offload_tuple_dir dir, struct ipv6hdr *ip6h)
{ assert(!skb->_nfct || skb_nfct(skb) != &flow->ct->ct_general); rewritten++; }
static void ip_decrease_ttl(struct iphdr *iph) { iph->ttl--; }
static void skb_clear_tstamp(struct sk_buff *skb) { }
static void nf_ct_acct_update(struct nf_conn *ct, u32 dir, unsigned int bytes)
{ accounted++; ct->acct_packets[dir]++; ct->acct_bytes[dir] += bytes; }

#include "flowtable_ct_production.inc"

typedef int (*forward_fn)(struct nf_flowtable_ctx *, struct nf_flowtable *,
                          struct flow_offload_tuple_rhash *, struct sk_buff *);

static struct net_device in = { 3 };

static int forward(forward_fn fn, struct nf_flowtable *table, struct flow_offload *flow,
                   enum flow_offload_tuple_dir dir, struct sk_buff *skb)
{
    struct nf_flowtable_ctx ctx = { .in = &in };

    skb->len = 300;
    skb->header.ip.ihl = 5;
    skb->header.ip.protocol = 17;
    skb->header.ip.ttl = 64;
    return fn(&ctx, table, &flow->tuplehash[dir], skb);
}

static void family(forward_fn fn)
{
    struct nf_conn ct = { .ct_general = { 1 }, .status = 1UL << IPS_SEEN_REPLY_BIT };
    struct nf_conn other = { .ct_general = { 1 } };
    struct nf_flowtable table = { .flags = NF_FLOWTABLE_COUNTER };
    struct flow_offload flow = { .ct = &ct };
    struct sk_buff skb = { 0 };

    accounted = rewritten = 0;
    flow.tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.dir = FLOW_OFFLOAD_DIR_ORIGINAL;
    flow.tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.dir = FLOW_OFFLOAD_DIR_REPLY;
    flow.tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.mtu = 1500;
    flow.tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.mtu = 1500;

    /* Forwarded: the frame leaves carrying the flow's conntrack, holding a
     * reference of its own, established in the direction it travels -- and
     * accounted once, by the flowtable, as before. */
    assert(forward(fn, &table, &flow, FLOW_OFFLOAD_DIR_ORIGINAL, &skb) == 1);
    assert(skb_nfct(&skb) == &ct.ct_general && ct.ct_general.use == 2);
    assert((skb._nfct & 7) == IP_CT_ESTABLISHED);
    assert(accounted == 1 && ct.acct_packets[FLOW_OFFLOAD_DIR_ORIGINAL] == 1);
    nf_reset_ct(&skb);            /* the skb is freed */
    assert(ct.ct_general.use == 1);

    assert(forward(fn, &table, &flow, FLOW_OFFLOAD_DIR_REPLY, &skb) == 1);
    assert(skb_nfct(&skb) == &ct.ct_general && ct.ct_general.use == 2);
    assert((skb._nfct & 7) == IP_CT_ESTABLISHED_REPLY);
    assert(accounted == 2 && ct.acct_packets[FLOW_OFFLOAD_DIR_REPLY] == 1);
    nf_reset_ct(&skb);

    /* An original-direction frame before any reply is a new connection's,
     * as act_ct has it. */
    ct.status = 0;
    assert(forward(fn, &table, &flow, FLOW_OFFLOAD_DIR_ORIGINAL, &skb) == 1);
    assert((skb._nfct & 7) == IP_CT_NEW);
    nf_reset_ct(&skb);
    ct.status = 1UL << IPS_SEEN_REPLY_BIT;

    /* A frame that arrived with a conntrack of its own gives it back: it
     * describes some other connection. */
    nf_conntrack_get(&other.ct_general);
    nf_ct_set(&skb, &other, IP_CT_ESTABLISHED);
    assert(forward(fn, &table, &flow, FLOW_OFFLOAD_DIR_ORIGINAL, &skb) == 1);
    assert(other.ct_general.use == 1);
    assert(skb_nfct(&skb) == &ct.ct_general && ct.ct_general.use == 2);
    nf_reset_ct(&skb);

    /* Without a counter the flowtable accounts nothing, and neither does
     * attaching the conntrack. */
    table.flags = 0;
    assert(forward(fn, &table, &flow, FLOW_OFFLOAD_DIR_ORIGINAL, &skb) == 1);
    assert(accounted == 4 && skb_nfct(&skb) == &ct.ct_general);
    nf_reset_ct(&skb);
    table.flags = NF_FLOWTABLE_COUNTER;

    /* Every way back to the stack leaves the frame as it came: the stack
     * gives it a conntrack of its own, and a reference taken here would be
     * one nothing puts. */
    unsigned before = accounted;
    bool *exits[] = { &too_big, &closing, &stale_route, &unwritable };
    for (unsigned i = 0; i < sizeof(exits) / sizeof(exits[0]); i++) {
        *exits[i] = true;
        assert(forward(fn, &table, &flow, FLOW_OFFLOAD_DIR_ORIGINAL, &skb) ==
               (exits[i] == &unwritable ? -1 : 0));
        *exits[i] = false;
        assert(!skb._nfct && ct.ct_general.use == 1 && accounted == before);
    }
    assert(flow.torn_down && rewritten == 5);
    assert(ct.ct_general.use == 1 && other.ct_general.use == 1);
}

int main(void)
{
    family(nf_flow_offload_forward);
    family(nf_flow_offload_ipv6_forward);
    return 0;
}
