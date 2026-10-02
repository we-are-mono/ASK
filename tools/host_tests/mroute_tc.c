#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;
#define MAXVIFS 32
#define IS_ENABLED(x) (x)
#define CONFIG_NET_CLS 1
#define CONFIG_NET_CLS_ACT 1
#define CONFIG_NET_SCHED 1
#define CONFIG_NET_XGRESS 1
#define TCQ_F_INGRESS 2
#define TC_H_MIN(h) ((h) & 0x0000FFFFU)
#define TC_H_MIN_INGRESS 0xFFF2U
#define TC_H_MIN_EGRESS 0xFFF3U
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
typedef struct { int counter; } atomic_t;
#define atomic_read(v) ((v)->counter)

/* RTNL, which every helper runs under, and RCU, which must be let go of
 * before a block is walked: its iterators take mutexes. */
static bool rtnl;
static int rcu_depth;
#define ASSERT_RTNL() assert(rtnl)
static void rcu_read_lock(void) { rcu_depth++; }
static void rcu_read_unlock(void) { assert(rcu_depth > 0); rcu_depth--; }
#define rcu_dereference(p) ({ assert(rcu_depth > 0); (p); })
#define rtnl_dereference(p) ({ assert(rtnl); (p); })

/* ---- classifiers ----------------------------------------------------------
 *
 * A block's chains and a chain's classifiers, each handed out with a
 * reference that the next call for its successor puts. `held' is every
 * reference outstanding; a walk that stopped iterating would leave some. */
struct netlink_ext_ack;
struct tcf_proto;
struct tcf_walker {
    int stop;
    int skip;
    int count;
    bool nonempty;
    unsigned long cookie;
    int (*fn)(struct tcf_proto *, void *node, struct tcf_walker *);
};
struct tcf_proto_ops {
    void (*walk)(struct tcf_proto *tp, struct tcf_walker *arg, bool rtnl_held);
};
struct filter { int unused; };
struct tcf_chain;
struct tcf_proto {
    int refs;
    bool usesw;
    const struct tcf_proto_ops *ops;
    struct tcf_chain *chain;
    struct filter *filter[4];
    unsigned nfilters;
    /* How many times its filters were walked, and how many filters the
     * walks handed over. */
    unsigned walks, visited;
};
struct tcf_block;
struct tcf_chain {
    int refs;
    struct tcf_block *block;
    struct tcf_proto *proto[4];
    unsigned nprotos;
};
struct tcf_block {
    atomic_t useswcnt;
    struct tcf_chain *chain[3];
    unsigned nchains;
};
static int held;
/* Chain lookups, each of which takes the block's mutex. */
static unsigned chain_lookups;
static struct tcf_chain *tcf_get_next_chain(struct tcf_block *block, struct tcf_chain *chain)
{
    struct tcf_chain *next = NULL;
    unsigned i;

    assert(rtnl && !rcu_depth);
    chain_lookups++;
    if (!chain && block->nchains)
        next = block->chain[0];
    for (i = 0; chain && i + 1 < block->nchains; i++)
        if (block->chain[i] == chain)
            next = block->chain[i + 1];
    if (next) {
        next->refs++;
        held++;
    }
    if (chain) {
        assert(chain->refs > 0);
        chain->refs--;
        held--;
    }
    return next;
}
static struct tcf_proto *tcf_get_next_proto(struct tcf_chain *chain, struct tcf_proto *tp)
{
    struct tcf_proto *next = NULL;
    unsigned i;

    ASSERT_RTNL();
    assert(!rcu_depth && chain->refs > 0);
    if (!tp && chain->nprotos)
        next = chain->proto[0];
    for (i = 0; tp && i + 1 < chain->nprotos; i++)
        if (chain->proto[i] == tp)
            next = chain->proto[i + 1];
    if (next) {
        next->refs++;
        held++;
    }
    if (tp) {
        assert(tp->refs > 0);
        tp->refs--;
        held--;
    }
    return next;
}
/* flower's walk: from the filter the cookie names, each handed over by its
 * own address, which is the cookie it is offloaded under. A walker is fresh
 * for every classifier, or the cookie a previous walk left would skip
 * filters. */
static void flower_walk(struct tcf_proto *tp, struct tcf_walker *arg, bool rtnl_held)
{
    unsigned long id = arg->cookie;

    assert(rtnl_held && !arg->stop && !arg->skip && !arg->count && !arg->cookie);
    tp->walks++;
    arg->count = arg->skip;
    for (; id < tp->nfilters; id++) {
        tp->visited++;
        if (arg->fn(tp, tp->filter[id], arg) < 0) {
            arg->stop = 1;
            break;
        }
        arg->count++;
    }
    arg->cookie = id;
}
/* matchall's: its one filter, by the address of its head. */
static void matchall_walk(struct tcf_proto *tp, struct tcf_walker *arg, bool rtnl_held)
{
    assert(rtnl_held && !arg->stop && !arg->count);
    tp->walks++;
    if (arg->count < arg->skip)
        goto skip;
    if (!tp->nfilters)
        return;
    tp->visited++;
    if (arg->fn(tp, tp->filter[0], arg) < 0)
        arg->stop = 1;
skip:
    arg->count++;
}
static const struct tcf_proto_ops flower = { .walk = flower_walk };
static const struct tcf_proto_ops matchall = { .walk = matchall_walk };
/* A classifier that cannot list its filters. */
static const struct tcf_proto_ops opaque = { .walk = NULL };

/* ---- qdiscs ----------------------------------------------------------------
 *
 * A qdisc's own block is class 0; its classes are numbered from 1. */
struct Qdisc;
struct qdisc_walker {
    int stop;
    int skip;
    int count;
    int (*fn)(struct Qdisc *, unsigned long cl, struct qdisc_walker *);
};
struct Qdisc_class_ops {
    struct tcf_block *(*tcf_block)(struct Qdisc *, unsigned long cl,
                                   struct netlink_ext_ack *extack);
    void (*walk)(struct Qdisc *, struct qdisc_walker *);
};
struct Qdisc_ops {
    const struct Qdisc_class_ops *cl_ops;
};
struct Qdisc {
    const struct Qdisc_ops *ops;
    unsigned flags;
    struct tcf_block *block;
    struct tcf_block *class_block[3];
    unsigned classes;
    int hash;
    /* clsact's two halves. */
    struct tcf_block *ingress_block, *egress_block;
};
static struct tcf_block *classful_block(struct Qdisc *q, unsigned long cl,
                                        struct netlink_ext_ack *extack)
{
    assert(!extack && cl <= q->classes);
    return cl ? q->class_block[cl - 1] : q->block;
}
static void classful_walk(struct Qdisc *q, struct qdisc_walker *arg)
{
    unsigned long cl;

    for (cl = 1; cl <= q->classes && !arg->stop; cl++) {
        if (arg->count >= arg->skip && arg->fn(q, cl, arg) < 0) {
            arg->stop = 1;
            break;
        }
        arg->count++;
    }
}
static const struct Qdisc_class_ops classful_ops = {
    .tcf_block = classful_block, .walk = classful_walk,
};
/* mq: classes, but no filters of its own. */
static const struct Qdisc_class_ops blockless_ops = { .walk = classful_walk };
static const struct Qdisc_ops classful = { .cl_ops = &classful_ops };
static const struct Qdisc_ops blockless = { .cl_ops = &blockless_ops };
/* pfifo_fast, noqueue: no classes at all. */
static const struct Qdisc_ops classless = { .cl_ops = NULL };
/* sch_ingress.c's two: clsact answers by direction, and ingress has its one
 * block whatever is asked. */
static struct tcf_block *clsact_tcf_block(struct Qdisc *q, unsigned long cl,
                                          struct netlink_ext_ack *extack)
{
    assert(!extack);
    switch (cl) {
    case TC_H_MIN(TC_H_MIN_INGRESS):
        return q->ingress_block;
    case TC_H_MIN(TC_H_MIN_EGRESS):
        return q->egress_block;
    default:
        return NULL;
    }
}
static struct tcf_block *ingress_tcf_block(struct Qdisc *q, unsigned long cl,
                                           struct netlink_ext_ack *extack)
{
    assert(!extack);
    return q->block;
}
static const struct Qdisc_class_ops clsact_cops = { .tcf_block = clsact_tcf_block };
static const struct Qdisc_class_ops ingress_cops = { .tcf_block = ingress_tcf_block };
static const struct Qdisc_ops clsact_qops = { .cl_ops = &clsact_cops };
static const struct Qdisc_ops ingress_qops = { .cl_ops = &ingress_cops };

/* ---- devices -------------------------------------------------------------- */
/* As in the kernel: clsact gives only the ingress miniq its block, which
 * tc_run() needs there to bypass a block nothing runs in software; the
 * egress one has none, and its filters are found through the qdisc. */
struct mini_Qdisc { struct tcf_block *block; };
/* The ingress queue, where the clsact or ingress qdisc lives. */
struct netdev_queue { struct Qdisc *qdisc_sleeping; };
/* The tcx entry: its BPF programs, and the clsact or ingress qdisc's
 * mini_Qdisc, which is NULL while chain 0 is empty. */
struct bpf_mprog_entry { int total; };
struct tcx_entry {
    struct mini_Qdisc *miniq;
    struct bpf_mprog_entry entry;
};
static struct tcx_entry *tcx_entry(struct bpf_mprog_entry *entry)
{
    return container_of(entry, struct tcx_entry, entry);
}
static int bpf_mprog_total(struct bpf_mprog_entry *entry) { return entry->total; }
struct net_device {
    int ifindex;
    bool registered;
    struct bpf_mprog_entry *tcx_ingress, *tcx_egress;
    struct netdev_queue *ingress_queue;
    struct Qdisc *qdisc;
    struct { unsigned n; struct Qdisc *q[4]; } qdisc_hash;
    u8 xdp;
    struct net_device *lower[2];
    unsigned lowers;
};
#define hash_for_each(name, bkt, obj, member) \
    for ((bkt) = 0; (bkt) < (name).n && ((obj) = (name).q[(bkt)], 1); (bkt)++)
static unsigned char dev_xdp_prog_count(struct net_device *dev) { return dev->xdp; }
struct netdev_nested_priv {
    unsigned char flags;
    void *data;
};
/* Every device below, at any depth, until the callback says stop. */
static int netdev_walk_all_lower_dev(struct net_device *dev,
                                     int (*fn)(struct net_device *, struct netdev_nested_priv *),
                                     struct netdev_nested_priv *priv)
{
    unsigned i;
    int ret;

    ASSERT_RTNL();
    for (i = 0; i < dev->lowers; i++) {
        ret = fn(dev->lower[i], priv);
        if (ret)
            return ret;
        ret = netdev_walk_all_lower_dev(dev->lower[i], fn, priv);
        if (ret)
            return ret;
    }
    return 0;
}
static struct net { int unused; } init_net;
/* The parent VIF's device over its port; the first oif a port of its own;
 * the second a VLAN over another port. */
enum { PARENT = 41, PARENT_PORT = 51, PARENT_BOND = 61, OIF_A = 31, OIF_B = 32, OIF_B_PORT = 52 };
static struct net_device parent, parent_port, parent_bond, oif_a, oif_b, oif_b_port;
static struct net_device *const devices[] = {
    &parent, &parent_port, &parent_bond, &oif_a, &oif_b, &oif_b_port,
};
static struct net_device *__dev_get_by_index(struct net *net, int ifindex)
{
    unsigned i;

    ASSERT_RTNL();
    for (i = 0; i < sizeof(devices) / sizeof(devices[0]); i++)
        if (devices[i]->registered && devices[i]->ifindex == ifindex)
            return devices[i];
    return NULL;
}

/* What the hardware applies as it is: the DSCP map's filters, by port and
 * cookie, and only on egress. Every question is counted. */
struct mirrored { struct net_device *dev; unsigned long cookie; };
static struct mirrored mirrors[4];
static unsigned nmirrors, mirror_asks, mirror_asks_ingress;
static bool cdx_tc_filter_mirrored(struct net_device *dev, bool ingress, unsigned long cookie)
{
    unsigned i;

    mirror_asks++;
    if (ingress)
        mirror_asks_ingress++;
    for (i = 0; i < nmirrors; i++)
        if (mirrors[i].dev == dev && mirrors[i].cookie == cookie)
            return !ingress;
    return false;
}
static void mirror(struct net_device *dev, struct filter *f)
{
    assert(nmirrors < 4);
    mirrors[nmirrors++] = (struct mirrored){ dev, (unsigned long)f };
}

struct ft_mr_plan {
    int oif[MAXVIFS];
    int parent;
    u8 oif_count;
};
#include "mroute_tc.inc"

/* ---- building a case ------------------------------------------------------ */
static struct tcf_block blocks[8];
static struct tcf_chain chains[12];
static struct tcf_proto protos[16];
static struct filter filters[24];
static struct Qdisc qdiscs[12];
static struct tcx_entry tcxs[6];
static struct mini_Qdisc miniqs[6];
static struct netdev_queue queues[6];
static unsigned nblocks, nchains, nprotos, nfilters, nqdiscs, ntcxs, nqueues;

static void reset(void)
{
    unsigned i;

    memset(blocks, 0, sizeof(blocks));
    memset(chains, 0, sizeof(chains));
    memset(protos, 0, sizeof(protos));
    memset(qdiscs, 0, sizeof(qdiscs));
    memset(tcxs, 0, sizeof(tcxs));
    memset(miniqs, 0, sizeof(miniqs));
    memset(queues, 0, sizeof(queues));
    nblocks = nchains = nprotos = nfilters = nqdiscs = ntcxs = nqueues = 0;
    nmirrors = mirror_asks = mirror_asks_ingress = chain_lookups = 0;
    for (i = 0; i < sizeof(devices) / sizeof(devices[0]); i++) {
        struct net_device *d = devices[i];
        int ifindex = d->ifindex;
        struct net_device *lower[2] = { d->lower[0], d->lower[1] };
        unsigned lowers = d->lowers;

        memset(d, 0, sizeof(*d));
        d->ifindex = ifindex;
        d->registered = true;
        d->lower[0] = lower[0];
        d->lower[1] = lower[1];
        d->lowers = lowers;
    }
}
static struct tcf_block *block(void)
{
    assert(nblocks < 8);
    return &blocks[nblocks++];
}
static struct tcf_chain *chain(struct tcf_block *b)
{
    struct tcf_chain *c = &chains[nchains++];

    assert(nchains <= 12 && b->nchains < 3);
    c->block = b;
    b->chain[b->nchains++] = c;
    return c;
}
/* A classifier, counted in its block's useswcnt as cls_api counts it: once,
 * if any of its filters ever ran in software. */
static struct tcf_proto *proto(struct tcf_chain *c, const struct tcf_proto_ops *ops, bool usesw)
{
    struct tcf_proto *tp = &protos[nprotos++];

    assert(nprotos <= 16 && c->nprotos < 4);
    tp->ops = ops;
    tp->usesw = usesw;
    tp->chain = c;
    c->proto[c->nprotos++] = tp;
    if (usesw)
        c->block->useswcnt.counter++;
    return tp;
}
static struct filter *filter(struct tcf_proto *tp)
{
    assert(nfilters < 24 && tp->nfilters < 4);
    tp->filter[tp->nfilters] = &filters[nfilters++];
    return tp->filter[tp->nfilters++];
}
/* A one-filter block: a classifier of `ops' in chain 0. */
static struct tcf_block *one(const struct tcf_proto_ops *ops, bool usesw, struct filter **f)
{
    struct tcf_block *b = block();
    struct filter *made = filter(proto(chain(b), ops, usesw));

    if (f)
        *f = made;
    return b;
}
static struct Qdisc *qdisc(const struct Qdisc_ops *ops, struct tcf_block *own, unsigned flags);

/* The qdisc on `dev''s ingress queue: clsact, made on first use. */
static struct Qdisc *xgress_qdisc(struct net_device *dev, const struct Qdisc_ops *ops)
{
    if (!dev->ingress_queue) {
        assert(nqueues < 6);
        dev->ingress_queue = &queues[nqueues++];
        dev->ingress_queue->qdisc_sleeping = qdisc(ops, NULL, TCQ_F_INGRESS);
    }
    assert(dev->ingress_queue->qdisc_sleeping->ops == ops);
    return dev->ingress_queue->qdisc_sleeping;
}

/* A clsact half on `dev': its block the qdisc's, with the tcx entry's miniq
 * there only while chain 0 has a classifier, naming the block on the way in
 * alone. */
static struct bpf_mprog_entry *clsact(struct net_device *dev, bool ingress,
                                      struct tcf_block *b, bool chain0)
{
    struct tcx_entry *t = &tcxs[ntcxs];
    struct Qdisc *q = xgress_qdisc(dev, &clsact_qops);

    assert(ntcxs < 6);
    if (ingress)
        q->ingress_block = b;
    else
        q->egress_block = b;
    if (b && chain0) {
        miniqs[ntcxs].block = ingress ? b : NULL;
        t->miniq = &miniqs[ntcxs];
    }
    ntcxs++;
    if (ingress)
        dev->tcx_ingress = &t->entry;
    else
        dev->tcx_egress = &t->entry;
    return &t->entry;
}
/* The ingress qdisc on `dev', which has one block and no egress half. */
static void ingress_qdisc(struct net_device *dev, struct tcf_block *b)
{
    struct tcx_entry *t = &tcxs[ntcxs];

    assert(ntcxs < 6);
    xgress_qdisc(dev, &ingress_qops)->block = b;
    miniqs[ntcxs].block = b;
    t->miniq = &miniqs[ntcxs];
    ntcxs++;
    dev->tcx_ingress = &t->entry;
}
static struct Qdisc *qdisc(const struct Qdisc_ops *ops, struct tcf_block *own, unsigned flags)
{
    struct Qdisc *q = &qdiscs[nqdiscs++];

    assert(nqdiscs <= 12);
    q->ops = ops;
    q->block = own;
    q->flags = flags;
    return q;
}
static void hashed(struct net_device *dev, struct Qdisc *q)
{
    assert(dev->qdisc_hash.n < 4);
    dev->qdisc_hash.q[dev->qdisc_hash.n++] = q;
}

/* The plan every case asks about: the stream arrives by the parent VIF and
 * leaves by both oifs. Every reference the iterators handed out is back, RCU
 * is let go of, and RTNL is held throughout. */
static bool filtered(void)
{
    struct ft_mr_plan plan = { .parent = PARENT, .oif = { OIF_A, OIF_B }, .oif_count = 2 };
    bool soft;
    unsigned i;

    rtnl = true;
    soft = ft_mr_tc_filtered(&plan);
    rtnl = false;
    assert(!held && !rcu_depth);
    for (i = 0; i < nchains; i++)
        assert(!chains[i].refs);
    for (i = 0; i < nprotos; i++)
        assert(!protos[i].refs);
    return soft;
}

int main(void)
{
    struct tcf_block *b;
    struct tcf_proto *tp, *other;
    struct filter *f;
    struct Qdisc *q;

    parent.ifindex = PARENT;
    parent_port.ifindex = PARENT_PORT;
    parent_bond.ifindex = PARENT_BOND;
    oif_a.ifindex = OIF_A;
    oif_b.ifindex = OIF_B;
    oif_b_port.ifindex = OIF_B_PORT;
    /* The parent is a VLAN over a bond over a port; the second oif a VLAN
     * over a port. */
    parent.lower[0] = &parent_bond;
    parent.lowers = 1;
    parent_bond.lower[0] = &parent_port;
    parent_bond.lowers = 1;
    oif_b.lower[0] = &oif_b_port;
    oif_b.lowers = 1;

    /* Nothing of tc anywhere. */
    reset();
    assert(!filtered() && !mirror_asks);

    /* A clsact qdisc with nothing in it: no filter, no mini_Qdisc. And one
     * whose block is reachable but counts nothing that runs in software. */
    reset();
    clsact(&parent, true, block(), false);
    clsact(&oif_a, false, block(), true);
    assert(!filtered());

    /* skip_sw filters alone: tc_run() bypasses the block, and so does the
     * walk, which does not so much as look its chains up. */
    reset();
    b = one(&flower, false, NULL);
    tp = &protos[0];
    clsact(&parent, true, b, true);
    assert(!atomic_read(&b->useswcnt) && !filtered() && !tp->walks && !chain_lookups);

    /* A filter that runs in software where the stream arrives. */
    reset();
    clsact(&parent, true, one(&flower, true, &f), true);
    assert(filtered() && mirror_asks == 1 && mirror_asks_ingress == 1);

    /* One where a copy leaves: clsact's egress miniq names no block, so the
     * block is the qdisc's to give -- a VLAN oif's egress drop is one. */
    reset();
    clsact(&oif_b, false, one(&flower, true, &f), true);
    assert(!oif_b.ingress_queue->qdisc_sleeping->ingress_block);
    assert(!tcx_entry(oif_b.tcx_egress)->miniq->block && filtered());

    /* The ingress qdisc rather than clsact, whose one block answers. */
    reset();
    ingress_qdisc(&parent, one(&flower, true, &f));
    assert(filtered() && mirror_asks_ingress == 1);

    /* A tcx BPF program there, which nothing can read, with no clsact. */
    reset();
    clsact(&parent, true, NULL, false)->total = 1;
    assert(filtered());

    /* The DSCP map's filter on an oif's egress: the listener entries read
     * the map per frame, so it counts for nothing. */
    reset();
    clsact(&oif_a, false, one(&flower, true, &f), true);
    mirror(&oif_a, f);
    assert(!filtered() && mirror_asks == 1 && !mirror_asks_ingress);
    /* The same filter on the other oif is no filter of the map's. */
    reset();
    clsact(&oif_b, false, one(&flower, true, &f), true);
    mirror(&oif_a, f);
    assert(filtered());

    /* A foreign filter beside it in the same egress block. */
    reset();
    b = one(&flower, true, &f);
    filter(&protos[0]);
    clsact(&oif_a, false, b, true);
    mirror(&oif_a, f);
    assert(filtered() && mirror_asks == 2);
    /* And in a classifier of its own, after it. */
    reset();
    b = one(&flower, true, &f);
    filter(proto(b->chain[0], &flower, true));
    clsact(&oif_a, false, b, true);
    mirror(&oif_a, f);
    assert(filtered());

    /* A police filter on the parent's ingress, matchall or flower: the
     * hardware meters no multicast frame, so neither is mirrored, even
     * under a cookie the map holds on the port's egress. */
    reset();
    clsact(&parent, true, one(&matchall, true, &f), true);
    mirror(&parent, f);
    assert(filtered() && mirror_asks_ingress == 1);
    reset();
    clsact(&parent, true, one(&flower, true, &f), true);
    assert(filtered());

    /* Each half of clsact in the direction it does not see: an ingress
     * filter on an oif, an egress one on the parent. */
    reset();
    clsact(&oif_a, true, one(&flower, true, NULL), true);
    clsact(&oif_b, true, one(&matchall, true, NULL), true);
    clsact(&parent, false, one(&flower, true, NULL), true);
    assert(!filtered() && !mirror_asks);

    /* Below the devices: the port under a VLAN oif, and the port two levels
     * under the parent. */
    reset();
    clsact(&oif_b_port, false, one(&flower, true, NULL), true);
    assert(filtered());
    reset();
    clsact(&parent_port, true, one(&flower, true, NULL), true);
    assert(filtered());
    /* The wrong direction there counts for nothing either. */
    reset();
    clsact(&oif_b_port, true, one(&flower, true, NULL), true);
    clsact(&parent_port, false, one(&flower, true, NULL), true);
    assert(!filtered());

    /* The root qdisc of an oif: a filter on one of its classes, or on the
     * qdisc itself. */
    reset();
    q = qdisc(&classful, NULL, 0);
    q->classes = 2;
    q->class_block[1] = one(&flower, true, NULL);
    oif_a.qdisc = q;
    assert(filtered());
    reset();
    oif_b_port.qdisc = qdisc(&classful, one(&flower, true, NULL), 0);
    assert(filtered());
    /* A class filter that only skips software, a qdisc with classes but no
     * filters, and one with no classes. */
    reset();
    q = qdisc(&classful, NULL, 0);
    q->classes = 1;
    q->class_block[0] = one(&flower, false, NULL);
    oif_a.qdisc = q;
    oif_b.qdisc = qdisc(&blockless, NULL, 0);
    oif_b.qdisc->classes = 2;
    oif_b_port.qdisc = qdisc(&classless, NULL, 0);
    assert(!filtered());
    /* The parent's qdisc tree is on its way out, not the stream's way in. */
    reset();
    parent.qdisc = qdisc(&classful, one(&flower, true, NULL), 0);
    assert(!filtered());

    /* The qdiscs below the root. An ingress-flagged one is reached through
     * the tcx entry, not the tree; any other is part of the tree. */
    reset();
    hashed(&oif_a, qdisc(&classful, one(&flower, true, NULL), TCQ_F_INGRESS));
    assert(!filtered());
    reset();
    q = qdisc(&classful, NULL, 0);
    q->classes = 1;
    q->class_block[0] = one(&flower, true, NULL);
    hashed(&oif_a, qdisc(&classless, NULL, 0));
    hashed(&oif_a, q);
    assert(filtered());

    /* XDP on the way in, and only there. */
    reset();
    parent.xdp = 1;
    assert(filtered());
    reset();
    oif_a.xdp = 1;
    oif_b_port.xdp = 2;
    assert(!filtered());
    reset();
    parent_port.xdp = 1;
    assert(filtered());

    /* A VIF device gone: nothing can be said of it. */
    reset();
    parent.registered = false;
    assert(filtered());
    reset();
    oif_b.registered = false;
    assert(filtered());

    /* A classifier that never ran in software sits beside one that did:
     * only the second is listed, and its filter is the map's. */
    reset();
    b = one(&flower, false, NULL);
    other = proto(b->chain[0], &flower, true);
    f = filter(other);
    tp = &protos[0];
    clsact(&oif_a, false, b, true);
    mirror(&oif_a, f);
    assert(!filtered() && !tp->walks && other->walks == 1 && mirror_asks == 1);

    /* A classifier that cannot list its filters, running in software. */
    reset();
    clsact(&parent, true, one(&opaque, true, NULL), true);
    assert(filtered() && !mirror_asks);

    /* The first filter that runs in software ends the listing: the rest of
     * its classifier, the next classifier and every later chain go unwalked
     * -- yet every chain and classifier is still iterated to the end, which
     * is the only way their references are put. */
    reset();
    b = one(&flower, true, NULL);
    tp = &protos[0];
    filter(tp);
    filter(tp);
    other = proto(b->chain[0], &flower, true);
    filter(other);
    filter(proto(chain(b), &matchall, true));
    clsact(&parent, true, b, true);
    assert(filtered() && tp->walks == 1 && tp->visited == 1 && mirror_asks == 1);
    assert(!other->walks && !protos[2].walks);

    /* Filters in another chain only, chain 0 empty: tc_run() has no
     * mini_Qdisc to classify with, so nothing runs. */
    reset();
    b = block();
    chain(b);
    filter(proto(chain(b), &flower, true));
    clsact(&parent, true, b, false);
    clsact(&oif_a, false, b, false);
    assert(atomic_read(&b->useswcnt) && !filtered() && !protos[0].walks);
    /* The same with chain 0 in use: every chain is walked. */
    reset();
    b = block();
    filter(proto(chain(b), &flower, true));
    filter(proto(chain(b), &flower, true));
    f = &filters[0];
    mirror(&oif_a, f);
    clsact(&oif_a, false, b, true);
    assert(filtered() && protos[0].walks == 1 && protos[1].walks == 1);

    puts("routed multicast tc admission scenarios passed");
    return 0;
}
