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
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
#define EOPNOTSUPP 95
#define EINVAL 22
#define ENOENT 2
#define ENOMEM 12
#define EEXIST 17
#define EBUSY 16
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

typedef int mutex_t;
#define DEFINE_MUTEX(x) mutex_t x
static void mutex_lock(mutex_t *m) { assert(!*m); *m = 1; }
static void mutex_unlock(mutex_t *m) { assert(*m); *m = 0; }

static unsigned allocations;
static void *kzalloc(size_t n, int f) { (void)f; allocations++; return calloc(1, n); }
static void kfree(void *p) { if (p) { assert(allocations); allocations--; } free(p); }

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
struct flow_dissector_key_control { u16 addr_type; u32 flags; };
struct flow_dissector_key_ip { u8 tos, ttl; };
struct flow_dissector { unsigned long long used_keys; };
struct flow_match_control { struct flow_dissector_key_control *key, *mask; };
struct flow_match_ip { struct flow_dissector_key_ip *key, *mask; };

struct flow_rule {
    struct { struct flow_dissector *dissector; } match;
    struct flow_action action;
    struct flow_dissector dis;
    struct flow_dissector_key_control control, control_mask;
    struct flow_dissector_key_ip ip, ip_mask;
};
static bool flow_rule_match_key(const struct flow_rule *r, unsigned key)
{ return r->match.dissector->used_keys & BIT_ULL(key); }
#define flow_rule_match_control(r, m) do { (m)->key = &(r)->control; (m)->mask = &(r)->control_mask; } while (0)
#define flow_rule_match_ip(r, m) do { (m)->key = &(r)->ip; (m)->mask = &(r)->ip_mask; } while (0)

enum { FLOW_CLS_REPLACE, FLOW_CLS_DESTROY, FLOW_CLS_STATS };
struct flow_cls_offload {
    struct { struct netlink_ext_ack *extack; } common;
    int command;
    unsigned long cookie;
    struct flow_rule *rule;
};
static struct flow_rule *flow_cls_offload_flow_rule(struct flow_cls_offload *f)
{ return f->rule; }

/* --- the port, and the qdisc this file asks questions of ------------------ */
struct tQM_context_ctl { int portid; };
struct dpa_priv_s { struct tQM_context_ctl *qm_ctx; };
struct net_device { struct dpa_priv_s priv; };
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

/* The hardware map, recorded rather than performed. */
static struct { int fq[64]; unsigned enabled, disabled; bool on; } hw;
static bool enable_fail, map_fail;
static int ceetm_enable_disable_dscp_fq_map(struct tQM_context_ctl *qm_ctx, u8 status)
{
    (void)qm_ctx;
    if (status) {
        if (enable_fail) return CEETM_FAILURE;
        hw.enabled++; hw.on = true;
    } else {
        hw.disabled++; hw.on = false;
        for (unsigned i = 0; i < 64; i++) hw.fq[i] = -1;
    }
    return CEETM_SUCCESS;
}
static int ceetm_dscp_fq_map(struct tQM_context_ctl *qm_ctx, u8 dscp, u8 channel, u8 cq)
{
    (void)qm_ctx;
    if (map_fail) return CEETM_FAILURE;
    assert(dscp < 64);
    hw.fq[dscp] = (channel << 8) | cq;
    return CEETM_SUCCESS;
}
static int ceetm_dscp_fq_unmap(struct tQM_context_ctl *qm_ctx, u8 dscp)
{
    (void)qm_ctx;
    assert(dscp < 64);
    hw.fq[dscp] = -1;
    return CEETM_SUCCESS;
}

#include "dscp_production.inc"

static struct netlink_ext_ack ack;
static struct net_device dev;

/* A filter matching one whole DSCP and naming a class. */
static struct flow_rule dscp_rule(u8 dscp, u32 classid)
{
    struct flow_rule r = { .action = { .num_entries = 1 } };
    r.action.entries[0].id = FLOW_ACTION_PRIORITY;
    r.action.entries[0].priority = classid;
    r.dis.used_keys = BIT_ULL(FLOW_DISSECTOR_KEY_CONTROL) | BIT_ULL(FLOW_DISSECTOR_KEY_IP);
    r.ip.tos = dscp << 2;
    r.ip_mask.tos = 0xfc;
    return r;
}

static int add(unsigned long cookie, struct flow_rule *r)
{
    struct flow_cls_offload f = { .common = { .extack = &ack },
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

int main(void)
{
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

    /* ---- what it refuses ---- */

    /* Two filters cannot both be the whole answer for one codepoint. */
    r = dscp_rule(46, 0x00010020);
    assert(add(3, &r) == -EEXIST);
    assert(hw.fq[46] == ((3 << 8) | 7));

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
    assert(del(1) == -ENOENT);
    assert(del(2) == 0);
    /* The last filter takes the map with it, so the port classifies as it
     * did before one existed -- and hands the microcode's single table back
     * to whichever port asks next. */
    assert(!hw.on && hw.disabled == 1);

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

    assert(!allocations);
    puts("DSCP map: codepoint parse, class resolution, tree tracking and teardown passed");
    return 0;
}
