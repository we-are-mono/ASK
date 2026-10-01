/* What a DSCP filter has to say before the map is touched, and what it means
 * afterwards.
 *
 * The table has one entry per codepoint and no way to say "these frames and
 * not those", so a filter that matched anything narrower than a whole DSCP
 * would claim more traffic than the operator described. That is the whole of
 * the parse. The rest is the correspondence between a tc classid and a CEETM
 * (channel, class queue), which the qdisc owns and this file only asks about --
 * and which has to be asked again every time the tree moves, or a codepoint
 * ends up naming a queue nobody meant.
 */
#include <arpa/inet.h>
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef uint16_t __be16;
#define EOPNOTSUPP 95
#define EINVAL 22
#define ENOENT 2
#define ENOMEM 12
#define EEXIST 17
#define EBUSY 16
#define EAGAIN 11
#define BIT_ULL(n) (1ULL << (n))
#define GFP_KERNEL 0
#define CEETM_SUCCESS 0
#define CEETM_FAILURE 1
#define MAX_PHY_PORTS 16
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define TC_H_MAJ(h) ((h) & 0xFFFF0000U)
#define TC_H_MIN(h) ((h) & 0x0000FFFFU)

/* --- lists, as the kernel shapes them ------------------------------------ */
struct list_head { struct list_head *next, *prev; };
#define LIST_HEAD_INIT(n) { &(n), &(n) }
#define LIST_HEAD(n) struct list_head n = LIST_HEAD_INIT(n)
static void INIT_LIST_HEAD(struct list_head *h) { h->next = h->prev = h; }
static void list_add_tail(struct list_head *e, struct list_head *h)
{ e->next = h; e->prev = h->prev; h->prev->next = e; h->prev = e; }
static void list_del(struct list_head *e)
{ e->prev->next = e->next; e->next->prev = e->prev; }
static bool list_empty(const struct list_head *h) { return h->next == h; }
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define list_entry(p, t, m) container_of(p, t, m)
#define list_for_each_entry(pos, head, m) \
    for (pos = list_entry((head)->next, typeof(*pos), m); &pos->m != (head); \
         pos = list_entry(pos->m.next, typeof(*pos), m))
#define list_for_each_entry_safe(pos, n, head, m) \
    for (pos = list_entry((head)->next, typeof(*pos), m), \
         n = list_entry(pos->m.next, typeof(*pos), m); &pos->m != (head); \
         pos = n, n = list_entry(n->m.next, typeof(*n), m))

#define READ_ONCE(x)  (*(volatile typeof(x) *)&(x))
#define WRITE_ONCE(x, v) (*(volatile typeof(x) *)&(x) = (v))
#define smp_store_release(p, v) WRITE_ONCE(*(p), v)
#define smp_load_acquire(p) READ_ONCE(*(p))

/* RCU as one thread sees it: a reader's section only counts, and a record
 * is freed at once, since no reader runs beside the writer here. */
struct rcu_head { int unused; };
static int rcu_depth;
static void rcu_read_lock(void) { rcu_depth++; }
static void rcu_read_unlock(void) { assert(rcu_depth > 0); rcu_depth--; }
#define list_add_tail_rcu list_add_tail
#define list_del_rcu list_del
#define list_for_each_entry_rcu list_for_each_entry

typedef int mutex_t;
#define DEFINE_MUTEX(x) mutex_t x
static void mutex_lock(mutex_t *m) { assert(!*m); *m = 1; }
static void mutex_unlock(mutex_t *m) { assert(*m); *m = 0; }
#define lockdep_assert_held(m) assert(*(m))

static unsigned allocations;
static void *kzalloc(size_t n, int f) { (void)f; allocations++; return calloc(1, n); }
static void kfree(void *p) { if (p) { assert(allocations); allocations--; } free(p); }
#define kfree_rcu(p, f) kfree(p)

/* --- the offload vocabulary ---------------------------------------------- */
enum flow_action_id { FLOW_ACTION_DROP, FLOW_ACTION_PRIORITY, FLOW_ACTION_MANGLE };
struct flow_action_entry { enum flow_action_id id; u32 priority; };
struct flow_action { unsigned num_entries; struct flow_action_entry entries[4]; };
struct netlink_ext_ack { const char *msg; };
#define NL_SET_ERR_MSG_MOD(e, m) do { if (e) (e)->msg = (m); } while (0)
static bool flow_offload_has_one_action(const struct flow_action *a)
{ return a->num_entries == 1; }

enum {
    FLOW_DISSECTOR_KEY_CONTROL, FLOW_DISSECTOR_KEY_BASIC,
    FLOW_DISSECTOR_KEY_IP, FLOW_DISSECTOR_KEY_PORTS,
};
struct flow_dissector_key_control { u16 thoff, addr_type; u32 flags; };
struct flow_dissector_key_basic { __be16 n_proto; u8 ip_proto; };
struct flow_dissector_key_ip { u8 tos, ttl; };
struct flow_dissector { unsigned long long used_keys; };
struct flow_match_control { struct flow_dissector_key_control *key, *mask; };
struct flow_match_basic { struct flow_dissector_key_basic *key, *mask; };
struct flow_match_ip { struct flow_dissector_key_ip *key, *mask; };

struct flow_rule {
    struct { struct flow_dissector *dissector; } match;
    struct flow_action action;
    struct flow_dissector dis;
    struct flow_dissector_key_control control, control_mask;
    struct flow_dissector_key_basic basic, basic_mask;
    struct flow_dissector_key_ip ip, ip_mask;
};
static bool flow_rule_match_key(const struct flow_rule *r, unsigned key)
{ return r->match.dissector->used_keys & BIT_ULL(key); }
#define flow_rule_match_control(r, m) do { (m)->key = &(r)->control; (m)->mask = &(r)->control_mask; } while (0)
#define flow_rule_match_basic(r, m) do { (m)->key = &(r)->basic; (m)->mask = &(r)->basic_mask; } while (0)
#define flow_rule_match_ip(r, m) do { (m)->key = &(r)->ip; (m)->mask = &(r)->ip_mask; } while (0)

enum { FLOW_CLS_REPLACE, FLOW_CLS_DESTROY, FLOW_CLS_STATS };
struct flow_cls_offload {
    struct { struct netlink_ext_ack *extack; u32 chain_index, prio; } common;
    int command;
    unsigned long cookie;
    struct flow_rule *rule;
};
static struct flow_rule *flow_cls_offload_flow_rule(struct flow_cls_offload *f)
{ return f->rule; }

/* --- the port, and the qdisc this file asks questions of ------------------ */
struct tQM_context_ctl { int portid; };
struct dpa_priv_s { struct tQM_context_ctl *qm_ctx; };
struct net_device { struct dpa_priv_s priv; int refs; };
static void dev_hold(struct net_device *dev) { assert(dev); dev->refs++; }
static void dev_put(struct net_device *dev) { assert(dev && dev->refs > 0); dev->refs--; }
static struct dpa_priv_s *netdev_priv(struct net_device *dev) { return &dev->priv; }

static struct tQM_context_ctl gQMCtx[MAX_PHY_PORTS];

/* The tree, as the qdisc would answer for it: a classid resolves to a leaf's
 * (channel, class queue), or to an error. */
static struct { u32 classid; u8 channel, cq; bool inner, live; } tree[8];
static int htb_rc;
static int cdx_htb_class_queue(struct net_device *dev, u32 classid, u8 *channel,
                               u8 *cq, struct netlink_ext_ack *extack)
{
    (void)dev;
    if (htb_rc) return htb_rc;
    for (unsigned i = 0; i < ARRAY_SIZE(tree); i++)
        if (tree[i].live && tree[i].classid == classid) {
            if (tree[i].inner) {
                NL_SET_ERR_MSG_MOD(extack, "inner");
                return -EINVAL;
            }
            *channel = tree[i].channel;
            *cq = tree[i].cq;
            return 0;
        }
    NL_SET_ERR_MSG_MOD(extack, "no such class");
    return -ENOENT;
}

/* The hardware map, recorded rather than performed. It is one table for the
 * whole SoC with one owner, and a port's view of it goes through four steps:
 * claimed (the owner, programmable), published (new entries on the port read
 * it), unpublished, released. `enabled' and `disabled' count the claims and
 * releases; `on' is whether it is published. */
static struct {
    int fq[64];
    unsigned enabled, disabled;
    bool on;
    struct tQM_context_ctl *owner;
} hw;
static bool enable_fail, map_fail;

/* Everything that orders a transition, in the order it happened, so a case can
 * say not only that the map ended up right but that nothing could read it at
 * a moment it was wrong. */
enum { EV_CLAIM, EV_PROGRAM, EV_PUBLISH, EV_UNPUBLISH, EV_CHANGED, EV_DRAIN, EV_RELEASE };
static struct { int what; struct tQM_context_ctl *ctx; } events[1024];
static unsigned nevents;
static void event(int what, struct tQM_context_ctl *ctx)
{
    assert(nevents < ARRAY_SIZE(events));
    events[nevents].what = what;
    events[nevents++].ctx = ctx;
}
/* The events since `from', compared against an expected sequence. */
static bool happened(unsigned from, const int *seq, unsigned n)
{
    if (nevents - from != n) return false;
    for (unsigned i = 0; i < n; i++)
        if (events[from + i].what != seq[i]) return false;
    return true;
}

static int ceetm_dscp_map_claim(struct tQM_context_ctl *qm_ctx)
{
    if (hw.owner == qm_ctx) return CEETM_SUCCESS;
    if (enable_fail || hw.owner) return CEETM_FAILURE;
    hw.owner = qm_ctx; hw.enabled++;
    event(EV_CLAIM, qm_ctx);
    return CEETM_SUCCESS;
}
static void ceetm_dscp_map_publish(struct tQM_context_ctl *qm_ctx)
{
    assert(hw.owner == qm_ctx && !hw.on);
    hw.on = true;
    event(EV_PUBLISH, qm_ctx);
}
static void ceetm_dscp_map_unpublish(struct tQM_context_ctl *qm_ctx)
{
    assert(hw.owner == qm_ctx && hw.on);
    hw.on = false;
    event(EV_UNPUBLISH, qm_ctx);
}
static int ceetm_dscp_map_release(struct tQM_context_ctl *qm_ctx)
{
    assert(hw.owner == qm_ctx);
    hw.owner = NULL; hw.on = false; hw.disabled++;
    for (unsigned i = 0; i < 64; i++) hw.fq[i] = -1;
    event(EV_RELEASE, qm_ctx);
    return CEETM_SUCCESS;
}
static int ceetm_dscp_fq_map(struct tQM_context_ctl *qm_ctx, u8 dscp, u8 channel, u8 cq)
{
    /* Only the owner's table can be written. */
    assert(hw.owner == qm_ctx);
    if (map_fail) return CEETM_FAILURE;
    assert(dscp < 64);
    hw.fq[dscp] = (channel << 8) | cq;
    event(EV_PROGRAM, qm_ctx);
    return CEETM_SUCCESS;
}
static int ceetm_dscp_fq_unmap(struct tQM_context_ctl *qm_ctx, u8 dscp)
{
    assert(hw.owner == qm_ctx);
    assert(dscp < 64);
    hw.fq[dscp] = -1;
    return CEETM_SUCCESS;
}

/* The flowtable's egress hook. changed() is recorded; drain() is recorded and
 * answers `drain_rc', and a case can have it run something first, which is
 * what happens concurrently in production while the mutex is dropped. */
struct net_device;
static int drain_rc;
static void (*during_drain)(void);
static unsigned drains_running;
static void cdx_ft_egress_changed(struct net_device *dev)
{
    struct tQM_context_ctl *ctx = netdev_priv(dev)->qm_ctx;

    event(EV_CHANGED, ctx);
}
static int cdx_ft_egress_drain(struct net_device *dev)
{
    void (*hook)(void) = during_drain;

    assert(dev && dev->refs > 0);
    event(EV_DRAIN, netdev_priv(dev)->qm_ctx);
    drains_running++;
    during_drain = NULL;
    if (hook) hook();
    drains_running--;
    return drain_rc;
}
static unsigned warnings;
#define pr_warn(...) ((void)snprintf(NULL, 0, __VA_ARGS__), warnings++)
#define __must_hold(x)
static const char *netdev_name(const struct net_device *dev) { (void)dev; return "eth"; }

#include "dscp_production.inc"

static struct netlink_ext_ack ack;
static struct net_device dev;

/* A filter matching one whole DSCP and naming a class, the way
 * `tc filter add ... protocol ip flower ip_tos ...' arrives: tc sends the
 * protocol as the flower key's ethertype. */
static struct flow_rule dscp_rule(u8 dscp, u32 classid)
{
    struct flow_rule r = { .action = { .num_entries = 1 } };
    r.action.entries[0].id = FLOW_ACTION_PRIORITY;
    r.action.entries[0].priority = classid;
    r.dis.used_keys = BIT_ULL(FLOW_DISSECTOR_KEY_CONTROL) |
                      BIT_ULL(FLOW_DISSECTOR_KEY_BASIC) | BIT_ULL(FLOW_DISSECTOR_KEY_IP);
    r.basic.n_proto = htons(0x0800);
    r.basic_mask.n_proto = 0xffff;
    r.ip.tos = dscp << 2;
    r.ip_mask.tos = 0xfc;
    return r;
}

/* The tc instance -- chain and preference -- the next filter is added in. */
static u32 filter_prio = 1, filter_chain;

static int add(unsigned long cookie, struct flow_rule *r)
{
    struct flow_cls_offload f = { .common = { .extack = &ack,
        .chain_index = filter_chain, .prio = filter_prio },
        .command = FLOW_CLS_REPLACE, .cookie = cookie, .rule = r };
    r->match.dissector = &r->dis;
    ack.msg = NULL;
    return cdx_dscp_flower(&dev, &f);
}

static int del(unsigned long cookie)
{
    struct flow_cls_offload f = { .common = { .extack = &ack },
        .command = FLOW_CLS_DESTROY, .cookie = cookie };
    ack.msg = NULL;
    return cdx_dscp_flower(&dev, &f);
}

/* ---- turning the map on and off retires what the hardware installed ---- */

/* Two ports, as the map is moved between the LAN and the WAN. */
static struct net_device lan = { .priv.qm_ctx = &gQMCtx[3] };
static struct net_device wan = { .priv.qm_ctx = &gQMCtx[4] };

static int add_on(struct net_device *d, unsigned long cookie, u8 dscp)
{
    struct flow_rule r = dscp_rule(dscp, 0x00010010);
    struct flow_cls_offload f = { .common = { .extack = &ack, .prio = filter_prio },
        .command = FLOW_CLS_REPLACE, .cookie = cookie, .rule = &r };
    r.match.dissector = &r.dis;
    ack.msg = NULL;
    return cdx_dscp_flower(d, &f);
}

static int del_on(struct net_device *d, unsigned long cookie)
{
    struct flow_cls_offload f = { .common = { .extack = &ack },
        .command = FLOW_CLS_DESTROY, .cookie = cookie };
    ack.msg = NULL;
    return cdx_dscp_flower(d, &f);
}

#define HAPPENED(from, ...) ({ static const int __seq[] = { __VA_ARGS__ }; \
    happened((from), __seq, ARRAY_SIZE(__seq)); })

/* What runs while a drain has the mutex dropped. */
static int concurrent_rc;
static void wan_asks(void) { concurrent_rc = add_on(&wan, 90, 46); }
static void lan_takes_it_back_and_lets_go(void)
{
    /* Retiring is still this port's claim, so taking it back needs no
     * drain -- and letting go again cannot start a second drain while the
     * first is running, so it asks the first to go round again. */
    assert(!add_on(&lan, 91, 46) && hw.on && hw.owner == &gQMCtx[3]);
    assert(!del_on(&lan, 91));
    assert(!hw.on && hw.owner == &gQMCtx[3]);
}
static void lan_goes(void)
{
    /* The interface is removed: its filters go, and the context release
     * that follows gives the claim back itself. */
    cdx_dscp_port_gone(&gQMCtx[3]);
    ceetm_dscp_map_release(&gQMCtx[3]);
    /* The map is free, but the drain still running is what proves the
     * port's entries are out of the hardware; until it returns, another
     * port is told to wait. */
    concurrent_rc = add_on(&wan, 92, 46);
}

static void test_transitions(void)
{
    unsigned from;

    memset(&hw, 0, sizeof(hw));
    for (unsigned i = 0; i < 64; i++) hw.fq[i] = -1;
    nevents = 0;

    /* On: claimed, programmed, published, and only then is the port told,
     * so the flows it retires come back reading a table already filled. */
    from = nevents;
    assert(!add_on(&lan, 20, 46));
    assert(HAPPENED(from, EV_CLAIM, EV_PROGRAM, EV_PUBLISH, EV_CHANGED));
    assert(events[from + 3].ctx == &gQMCtx[3]);
    assert(cdx_dscp_mirrored(&lan, 20) && !cdx_dscp_mirrored(&wan, 20));

    /* Editing one codepoint while the map stays on retires nothing: an
     * entry reads the table per frame. */
    from = nevents;
    assert(!add_on(&lan, 21, 10));
    assert(HAPPENED(from, EV_PROGRAM));
    from = nevents;
    assert(!del_on(&lan, 21));
    assert(nevents == from && hw.on);

    /* Off: unpublished, the port told, the retirement waited out, and only
     * then is the table handed back for another port to take. */
    from = nevents;
    assert(!del_on(&lan, 20));
    assert(HAPPENED(from, EV_UNPUBLISH, EV_CHANGED, EV_DRAIN, EV_RELEASE));
    assert(!hw.owner && !hw.on && !lan.refs);

    /* Another port asking while the drain runs is told to wait, and gets
     * the map once it has been handed back. */
    assert(!add_on(&lan, 22, 46));
    during_drain = wan_asks;
    concurrent_rc = 0;
    assert(!del_on(&lan, 22));
    assert(concurrent_rc == -EBUSY && ack.msg);
    assert(!hw.owner);
    from = nevents;
    assert(!add_on(&wan, 30, 46));
    assert(HAPPENED(from, EV_CLAIM, EV_PROGRAM, EV_PUBLISH, EV_CHANGED));
    assert(events[from].ctx == &gQMCtx[4] && hw.owner == &gQMCtx[4]);
    assert(!del_on(&wan, 30) && !hw.owner);

    /* A drain that cannot prove the entries gone keeps the claim, and says
     * so. The next port to ask tries the drain again, and is refused while
     * it still cannot finish -- the map stays where its readers are. */
    assert(!add_on(&lan, 23, 46));
    drain_rc = -EAGAIN;
    warnings = 0;
    assert(!del_on(&lan, 23));
    assert(hw.owner == &gQMCtx[3] && !hw.on && warnings == 1);
    from = nevents;
    assert(add_on(&wan, 31, 46) == -EBUSY);
    assert(HAPPENED(from, EV_DRAIN) && hw.owner == &gQMCtx[3]);
    drain_rc = 0;
    from = nevents;
    assert(!add_on(&wan, 31, 46));
    assert(HAPPENED(from, EV_DRAIN, EV_RELEASE, EV_CLAIM, EV_PROGRAM, EV_PUBLISH,
                    EV_CHANGED));
    assert(hw.owner == &gQMCtx[4]);
    assert(!del_on(&wan, 31) && !hw.owner);

    /* The port whose claim is retiring can take it back without a drain:
     * whatever still reads it reads that port's own queues. */
    assert(!add_on(&lan, 24, 46));
    drain_rc = -EAGAIN;
    assert(!del_on(&lan, 24));
    drain_rc = 0;
    /* Retiring, nothing on the port is the hardware's to apply. */
    assert(!cdx_dscp_mirrored(&lan, 24));
    from = nevents;
    assert(!add_on(&lan, 25, 46));
    assert(HAPPENED(from, EV_PROGRAM, EV_PUBLISH, EV_CHANGED) && hw.on);
    assert(cdx_dscp_mirrored(&lan, 25));
    from = nevents;
    assert(!del_on(&lan, 25));
    assert(HAPPENED(from, EV_UNPUBLISH, EV_CHANGED, EV_DRAIN, EV_RELEASE));

    /* Taken back and let go again while the first drain runs: that drain
     * releases nothing on the strength of a wait that began before the
     * second retirement, and goes round again first. */
    assert(!add_on(&lan, 26, 46));
    during_drain = lan_takes_it_back_and_lets_go;
    from = nevents;
    assert(!del_on(&lan, 26));
    assert(HAPPENED(from, EV_UNPUBLISH, EV_CHANGED, EV_DRAIN,
                    EV_PROGRAM, EV_PUBLISH, EV_CHANGED, EV_UNPUBLISH, EV_CHANGED,
                    EV_DRAIN, EV_RELEASE));
    assert(!hw.owner && !lan.refs);

    /* The port goes while its drain runs: the drain releases nothing, the
     * context did, and another port waits for the drain all the same. */
    assert(!add_on(&lan, 28, 46));
    during_drain = lan_goes;
    concurrent_rc = 0;
    from = nevents;
    assert(!del_on(&lan, 28));
    assert(concurrent_rc == -EBUSY);
    assert(HAPPENED(from, EV_UNPUBLISH, EV_CHANGED, EV_DRAIN, EV_RELEASE));
    assert(!hw.owner && !lan.refs);
    /* Gone, its slot names no device for a filter to be found under. */
    assert(!cdx_dscp_mirrored(&lan, 28) && !rcu_depth);
    assert(!add_on(&wan, 32, 46) && hw.owner == &gQMCtx[4]);
    assert(!del_on(&wan, 32) && !hw.owner);

    /* A first filter that cannot be programmed gives back a claim nothing
     * ever read: no port is told anything and nothing is drained. */
    map_fail = true;
    from = nevents;
    assert(add_on(&wan, 33, 46) == -EINVAL);
    map_fail = false;
    assert(HAPPENED(from, EV_CLAIM, EV_RELEASE) && !hw.owner);

    for (unsigned pass = 0; pass < 2; pass++)
        for (unsigned i = 0; i < ARRAY_SIZE(gQMCtx); i++)
            cdx_dscp_port_gone(&gQMCtx[i]);
    assert(!allocations && !drains_running);
}

int main(void)
{
    /* Provider shutdown visits every slot, including ports which have never
     * had a DSCP filter or an HTB tree. Cleanup must also be repeatable. */
    for (unsigned pass = 0; pass < 2; pass++)
        for (unsigned i = 0; i < ARRAY_SIZE(gQMCtx); i++) {
            cdx_dscp_port_gone(&gQMCtx[i]);
            for (unsigned dscp = 0; dscp < 64; dscp++)
                assert(cdx_dscp_class(&gQMCtx[i], dscp) == 0);
        }
    cdx_dscp_port_gone(NULL);

    dev.priv.qm_ctx = &gQMCtx[3];
    memset(&hw, 0, sizeof(hw));
    for (unsigned i = 0; i < 64; i++) hw.fq[i] = -1;
    /* 1:10 is a leaf on channel 2, class queue 7; 1:20 a leaf on channel 0,
     * queue 3; 1:1 is a channel rather than a queue. */
    tree[0] = (typeof(tree[0])){ .classid = 0x00010010, .channel = 2, .cq = 7, .live = true };
    tree[1] = (typeof(tree[1])){ .classid = 0x00010020, .channel = 0, .cq = 3, .live = true };
    tree[2] = (typeof(tree[2])){ .classid = 0x00010001, .inner = true, .live = true };

    /* ---- what the map records ---- */

    struct flow_rule r = dscp_rule(46, 0x00010010);     /* EF */
    assert(add(1, &r) == 0);
    assert(hw.on && hw.enabled == 1);
    /* The map is told the channel one higher than the tree numbers it,
     * because zero there means "whichever channel this port owns". */
    assert(hw.fq[46] == ((3 << 8) | 7));
    /* And only that codepoint. */
    assert(hw.fq[45] == -1 && hw.fq[47] == -1);

    /* The software Tx path reads the same answer, in the encoding the qdisc's
     * own class map is indexed by, so one filter serves both paths rather than
     * two lookups agreeing. */
    assert(cdx_dscp_class(&gQMCtx[3], 46) == ((3 << 4) | 7));
    assert(cdx_dscp_class(&gQMCtx[3], 45) == 0);
    assert(cdx_dscp_class(&gQMCtx[3], 64) == 0);        /* not a codepoint */

    r = dscp_rule(10, 0x00010020);                      /* AF11 */
    assert(add(2, &r) == 0);
    assert(hw.fq[10] == ((1 << 8) | 3));
    assert(hw.enabled == 1);                            /* enabled once */
    assert(cdx_dscp_class(&gQMCtx[3], 10) == ((1 << 4) | 3));

    /* ---- what the hardware applies as it is ----
     *
     * A filter of the port's, while its map is published, is one every
     * listener entry on the port applies per frame, so the routed multicast
     * learner may carry a group past it. Any other cookie is not, and nor is
     * any other device -- even one whose private area points at the same
     * context, since the learner asks of VLANs and bridges as well and the
     * slot is found by its device rather than through netdev_priv(). */
    assert(cdx_dscp_mirrored(&dev, 1) && cdx_dscp_mirrored(&dev, 2));
    assert(!cdx_dscp_mirrored(&dev, 3));
    {
        struct net_device stranger = { .priv.qm_ctx = &gQMCtx[3] };

        assert(!cdx_dscp_mirrored(&stranger, 1));
    }
    assert(!rcu_depth);

    /* ---- what it refuses ---- */

    /* Two filters cannot both be the whole answer for one codepoint: not
     * from another preference, another chain, or the same instance with
     * another protocol, all of which tc keeps beside the first. */
    r = dscp_rule(46, 0x00010020);
    filter_prio = 2;
    assert(add(3, &r) == -EEXIST);
    filter_prio = 1; filter_chain = 1;
    assert(add(3, &r) == -EEXIST);
    filter_chain = 0;
    r.basic.n_proto = htons(0x86dd);
    assert(add(3, &r) == -EEXIST);
    assert(hw.fq[46] == ((3 << 8) | 7));
    assert(cdx_dscp_class(&gQMCtx[3], 46) == ((3 << 4) | 7));

    /* `ip_proto' shares the protocol's key and names one transport's
     * frames of the codepoint, which the table cannot. */
    r = dscp_rule(20, 0x00010010); r.basic.ip_proto = 17; r.basic_mask.ip_proto = 0xff;
    assert(add(4, &r) == -EOPNOTSUPP);
    assert(hw.fq[20] == -1);

    /* Half a DSCP would claim codepoints the filter did not name, and the
     * ECN bits share the byte and are not ours. */
    r = dscp_rule(46, 0x00010010); r.ip_mask.tos = 0xf0;
    assert(add(4, &r) == -EOPNOTSUPP);
    r = dscp_rule(46, 0x00010010); r.ip_mask.tos = 0xff;
    assert(add(4, &r) == -EOPNOTSUPP);

    /* A narrower match than a codepoint cannot be expressed by a table with
     * one entry per codepoint. */
    r = dscp_rule(46, 0x00010010); r.dis.used_keys |= BIT_ULL(FLOW_DISSECTOR_KEY_PORTS);
    assert(add(4, &r) == -EOPNOTSUPP);
    r = dscp_rule(46, 0x00010010); r.ip_mask.ttl = 0xff;
    assert(add(4, &r) == -EOPNOTSUPP);

    /* No ip_dscp at all is not a DSCP filter. */
    r = dscp_rule(46, 0x00010010); r.dis.used_keys &= ~BIT_ULL(FLOW_DISSECTOR_KEY_IP);
    assert(add(4, &r) == -EOPNOTSUPP);

    /* Only skbedit priority says "send this to that class". */
    r = dscp_rule(20, 0x00010010); r.action.entries[0].id = FLOW_ACTION_DROP;
    assert(add(4, &r) == -EOPNOTSUPP);
    r = dscp_rule(20, 0x00010010); r.action.num_entries = 2;
    assert(add(4, &r) == -EOPNOTSUPP);
    r = dscp_rule(20, 0); /* priority 0 names no class */
    assert(add(4, &r) == -EOPNOTSUPP);

    /* A class that is a channel holds sixteen queues; a frame goes to one. */
    r = dscp_rule(20, 0x00010001);
    assert(add(4, &r) == -EINVAL);
    /* And a class that does not exist is not a silent default. */
    r = dscp_rule(20, 0x00010099);
    assert(add(4, &r) == -ENOENT);
    assert(hw.fq[20] == -1);

    /* Nothing above left the map holding a codepoint it should not. */
    assert(hw.fq[46] == ((3 << 8) | 7) && hw.fq[10] == ((1 << 8) | 3));

    /* ---- `tc filter replace' ----
     *
     * Flower offloads the new filter under a new cookie and only then
     * destroys the old one, so the new one arrives while the old one still
     * holds the codepoint. Same instance, same key: it takes the codepoint
     * over, and the old one's destroy leaves it with the new class rather
     * than unmapping it -- or turning the map off, had it been the last. */
    r = dscp_rule(46, 0x00010020);
    assert(add(11, &r) == 0);
    assert(hw.fq[46] == ((1 << 8) | 3));
    assert(cdx_dscp_class(&gQMCtx[3], 46) == ((1 << 4) | 3));
    assert(del(1) == 0);
    assert(hw.on && hw.fq[46] == ((1 << 8) | 3));
    assert(cdx_dscp_class(&gQMCtx[3], 46) == ((1 << 4) | 3));
    /* Flower failing after it offloaded the replacement destroys the
     * replacement and keeps the old filter, whose class comes back. */
    r = dscp_rule(46, 0x00010010);
    assert(add(12, &r) == 0);
    assert(hw.fq[46] == ((3 << 8) | 7));
    assert(del(12) == 0);
    assert(hw.fq[46] == ((1 << 8) | 3));
    assert(cdx_dscp_class(&gQMCtx[3], 46) == ((1 << 4) | 3));
    /* While the replacement and the filter it replaces both hold the
     * codepoint, the software table answers as the hardware does: the last
     * one programmed, even when its class has just gone and the codepoint
     * selects nothing. */
    r = dscp_rule(46, 0x00010010);
    assert(add(12, &r) == 0);
    tree[0].live = false;
    cdx_dscp_tree_changed(&dev);
    assert(hw.fq[46] == -1 && cdx_dscp_class(&gQMCtx[3], 46) == 0);
    tree[0].live = true;
    assert(del(12) == 0);
    assert(hw.fq[46] == ((1 << 8) | 3));
    assert(cdx_dscp_class(&gQMCtx[3], 46) == ((1 << 4) | 3));
    /* An empty address prefix still asks for an address type, which is a
     * mask a plain codepoint filter does not have: flower keeps the two side
     * by side in one instance, so it cannot be taken for a replacement. */
    r = dscp_rule(46, 0x00010010); r.control_mask.addr_type = 0xffff;
    assert(add(14, &r) == -EOPNOTSUPP);
    assert(hw.fq[46] == ((1 << 8) | 3));
    /* A replacement that cannot be programmed leaves the codepoint with the
     * filter it would have replaced. */
    r = dscp_rule(46, 0x00010099);
    assert(add(13, &r) == -ENOENT);
    assert(hw.fq[46] == ((1 << 8) | 3));
    /* Back to where the cases below expect it: EF on 1:10, as cookie 1. */
    r = dscp_rule(46, 0x00010010);
    assert(add(1, &r) == 0);
    assert(del(11) == 0);
    assert(hw.fq[46] == ((3 << 8) | 7) && hw.fq[10] == ((1 << 8) | 3));
    assert(allocations == 2);

    /* ---- the tree moves underneath ---- */

    /* 1:10 is rebuilt on a different channel and queue. Every filter naming
     * it has to follow, or the codepoint keeps sending frames to whatever
     * now holds the old indices. */
    tree[0].channel = 5; tree[0].cq = 1;
    cdx_dscp_tree_changed(&dev);
    assert(hw.fq[46] == ((6 << 8) | 1));
    assert(hw.fq[10] == ((1 << 8) | 3));

    /* 1:10 is deleted. The codepoint stops selecting anything rather than
     * keeping a queue the operator no longer means. */
    tree[0].live = false;
    cdx_dscp_tree_changed(&dev);
    assert(hw.fq[46] == -1);
    assert(hw.fq[10] == ((1 << 8) | 3));
    /* The software path stops selecting it too, rather than sending frames to
     * whatever now holds those indices. */
    assert(cdx_dscp_class(&gQMCtx[3], 46) == 0);
    assert(cdx_dscp_class(&gQMCtx[3], 10) == ((1 << 4) | 3));
    tree[0].live = true; tree[0].channel = 2; tree[0].cq = 7;
    cdx_dscp_tree_changed(&dev);
    assert(hw.fq[46] == ((3 << 8) | 7));

    /* ---- teardown ---- */

    assert(del(1) == 0);
    assert(hw.fq[46] == -1);
    assert(hw.on);                      /* one filter left */
    assert(!cdx_dscp_mirrored(&dev, 1) && cdx_dscp_mirrored(&dev, 2));
    assert(del(1) == -ENOENT);
    assert(del(2) == 0);
    /* The last filter takes the map with it, so the port classifies as it
     * did before one existed -- and hands the microcode's single table back
     * to whichever port asks next. */
    assert(!hw.on && hw.disabled == 1);
    assert(!cdx_dscp_mirrored(&dev, 2) && !rcu_depth);

    /* A port that cannot have the map is told so rather than left thinking
     * it has one. */
    enable_fail = true;
    r = dscp_rule(46, 0x00010010);
    assert(add(5, &r) == -EBUSY);
    assert(!hw.on);
    enable_fail = false;

    /* A map that will not program is a failure to report, and must not leave
     * the map enabled with nothing in it. */
    map_fail = true;
    r = dscp_rule(46, 0x00010010);
    assert(add(6, &r) == -EINVAL);
    assert(!hw.on);
    map_fail = false;

    r = dscp_rule(46, 0x00010010);
    assert(add(7, &r) == 0);
    assert(del(7) == 0);
    assert(!hw.on);

    /* Context teardown owns the hardware map; DSCP cleanup must release
     * populated software state without programming a disappearing context. */
    assert(add(8, &r) == 0);
    r = dscp_rule(10, 0x00010020);
    assert(add(9, &r) == 0);
    assert(allocations == 2);
    unsigned disabled = hw.disabled;
    cdx_dscp_port_gone(&gQMCtx[3]);
    cdx_dscp_port_gone(&gQMCtx[3]);
    assert(!allocations && hw.disabled == disabled);
    for (unsigned dscp = 0; dscp < 64; dscp++)
        assert(cdx_dscp_class(&gQMCtx[3], dscp) == 0);
    /* What the context release does with the claim. */
    ceetm_dscp_map_release(&gQMCtx[3]);

    /* Reusing the slot must not dereference the previous device, whose
     * CEETM attachment no longer exists. */
    struct net_device replacement = { .priv.qm_ctx = &gQMCtx[3] };
    dev.priv.qm_ctx = NULL;
    struct flow_cls_offload f = { .common.extack = &ack,
        .command = FLOW_CLS_REPLACE, .cookie = 10, .rule = &r };
    r.match.dissector = &r.dis;
    assert(cdx_dscp_flower(&replacement, &f) == 0);
    assert(hw.on && cdx_dscp_class(&gQMCtx[3], 10) == ((1 << 4) | 3));
    cdx_dscp_tree_changed(&replacement);
    f.command = FLOW_CLS_DESTROY;
    assert(cdx_dscp_flower(&replacement, &f) == 0);
    assert(!hw.on);
    for (unsigned pass = 0; pass < 2; pass++)
        for (unsigned i = 0; i < ARRAY_SIZE(gQMCtx); i++)
            cdx_dscp_port_gone(&gQMCtx[i]);

    assert(!allocations);
    test_transitions();
    puts("DSCP map: codepoint parse, class resolution, tree tracking, transitions and "
         "teardown passed");
    return 0;
}
