/* Compile the flowtable's hand-back of a flow's conntrack from the kernel and
 * prove the timeout it gives the conntrack back with.
 *
 * A flow torn down while it still carries traffic -- its table deleted, a port
 * going down -- hands its conntrack to the stack, which goes on with it from
 * the next packet. That conntrack gets its protocol's timeout for the state it
 * is in; only a flow that expired, idle for the flowtable's own timeout, gives
 * back what is left after that. An unanswered UDP conntrack handed back live
 * with the idle allowance taken off as well expires on the spot, and the
 * stream's next datagram opens another connection, its counts and translation
 * lost. The hand-back is compiled from the kernel; the conntrack and its
 * namespace's timeouts are simulated. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <netinet/in.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef int32_t s32;
typedef int32_t __s32;
#define HZ 100
#define IS_ENABLED(option) 1
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
#define EXPORT_SYMBOL_GPL(sym)
static bool test_bit(unsigned nr, const unsigned long *addr) { return (*addr >> nr) & 1; }
static void clear_bit(unsigned nr, unsigned long *addr) { *addr &= ~(1UL << nr); }
static bool test_and_set_bit(unsigned nr, unsigned long *addr)
{ bool old = test_bit(nr, addr); *addr |= 1UL << nr; return old; }

/* The real enums and per-namespace timeouts, taken from the kernel headers. */
#include "teardown_ct_types.inc"

/* Any point on the clock, the flowtable's and conntrack's alike. */
static u32 jiffies = 7 * 86400 * HZ;
#define nfct_time_stamp jiffies
#define nf_flowtable_time_stamp jiffies

struct ip_ct_tcp_state { u32 td_maxwin; };
struct ip_ct_tcp { struct ip_ct_tcp_state seen[2]; u8 state; };
struct nf_conn { unsigned long status; u32 timeout; u8 protonum; union { struct ip_ct_tcp tcp; } proto; };
struct net { struct nf_generic_net generic; struct nf_tcp_net tcp; struct nf_udp_net udp; };
static struct net net;
static struct net *nf_ct_net(const struct nf_conn *ct) { return &net; }
static u8 nf_ct_protonum(const struct nf_conn *ct) { return ct->protonum; }
static struct nf_tcp_net *nf_tcp_pernet(struct net *n) { return &n->tcp; }
static struct nf_udp_net *nf_udp_pernet(struct net *n) { return &n->udp; }
static struct nf_generic_net *nf_generic_pernet(struct net *n) { return &n->generic; }
struct flow_offload { struct nf_conn *ct; unsigned long flags; u32 timeout; };

#include "teardown_ct_production.inc"

/* What a conntrack holding `ct_left`, offloaded by a flow with `flow_left`
 * to go, is handed back with. The collector's next pass over the flow, still
 * waiting for its hardware to let go, hands back nothing more. */
static s32 handed_back(u8 proto, unsigned long status, u8 tcp_state, s32 flow_left, u32 ct_left)
{
    struct nf_conn ct = { .status = status | 1UL << IPS_OFFLOAD_BIT, .timeout = jiffies + ct_left,
                          .protonum = proto };
    struct flow_offload flow = { .ct = &ct, .timeout = jiffies + flow_left };
    s32 given;

    ct.proto.tcp.state = tcp_state;
    flow_offload_teardown(&flow);
    assert(test_bit(NF_FLOW_TEARDOWN, &flow.flags) && !test_bit(IPS_OFFLOAD_BIT, &ct.status));
    given = (s32)(ct.timeout - jiffies);
    ct.timeout = jiffies + 12345 * HZ;
    flow_offload_teardown(&flow);
    assert(ct.timeout == jiffies + 12345 * HZ);
    return given;
}

int main(void)
{
    const unsigned long replied = 1UL << IPS_SEEN_REPLY_BIT;
    const u32 day = 86400 * HZ;

    net.udp.timeouts[UDP_CT_UNREPLIED] = 30 * HZ;
    net.udp.timeouts[UDP_CT_REPLIED] = 120 * HZ;
    net.udp.offload_timeout = 30 * HZ;
    net.tcp.timeouts[TCP_CONNTRACK_ESTABLISHED] = 432000 * HZ;
    net.tcp.offload_timeout = 30 * HZ;
    net.generic.timeout = 600 * HZ;

    /* Torn down while it carries traffic: the state's timeout, whole. An
     * unanswered UDP conntrack keeps the time conntrack gives one. */
    assert(handed_back(IPPROTO_UDP, 0, 0, 10 * HZ, day) == 30 * HZ);
    assert(handed_back(IPPROTO_UDP, replied, 0, 10 * HZ, day) == 120 * HZ);
    assert(handed_back(IPPROTO_TCP, replied, TCP_CONNTRACK_ESTABLISHED, 10 * HZ, 10 * day) ==
           432000 * HZ);

    /* Expired, idle for the flowtable's timeout: what is left after it. */
    assert(handed_back(IPPROTO_UDP, 0, 0, 0, day) == 0);
    assert(handed_back(IPPROTO_UDP, replied, 0, -HZ, day) == 90 * HZ);
    assert(handed_back(IPPROTO_TCP, replied, TCP_CONNTRACK_ESTABLISHED, 0, 10 * day) ==
           (432000 - 30) * HZ);

    /* A conntrack the stack had already given less keeps what it has. */
    assert(handed_back(IPPROTO_UDP, replied, 0, 10 * HZ, 5 * HZ) == 5 * HZ);

    /* Transit ESP gets conntrack's own timeout for it either way. */
    assert(handed_back(IPPROTO_ESP, 0, 0, 10 * HZ, day) == 600 * HZ);
    assert(handed_back(IPPROTO_ESP, 0, 0, 0, day) == 600 * HZ);

    puts("Flowtable teardown: a live flow hands its conntrack back with the state's whole timeout, an expired one with what is left");
    return 0;
}
