#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t s64;
#define AF_INET 2
#define AF_INET6 10
#define MAXVIFS 32
#define FT_MR_OIF_TEXT 136
#define CDX_MC_MAX_LISTENERS 8
#define FT_MR_MAX_RETRIES 4
#define FT_MR_MAX_RESTARTS 4
#define FT_MR_STATS_INTERVAL 5
/* Upstream's values, for the events a case queues. */
#define FIB_EVENT_ENTRY_REPLACE 0
#define FIB_EVENT_ENTRY_DEL 3
#define FIB_EVENT_VIF_DEL 9
#define MFC_OFFLOAD 1
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
#define smp_load_acquire(p) (*(p))
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define min(a, b) ((a) < (b) ? (a) : (b))
/* An allocation a case can refuse. */
static bool fail_alloc;
#define kzalloc(n, f) (fail_alloc ? NULL : calloc(1, (n)))
#define GFP_KERNEL 0
#define kfree free
#define strscpy(d, s, n) snprintf(d, n, "%s", s)
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
struct list_head { struct list_head *next, *prev; };
#define LIST_HEAD(n) struct list_head n = { &n, &n }
static void INIT_LIST_HEAD(struct list_head *h) { h->next = h->prev = h; }
static void list_add(struct list_head *n, struct list_head *h)
{ n->next = h->next; n->prev = h; h->next->prev = n; h->next = n; }
static void list_del(struct list_head *n)
{ n->prev->next = n->next; n->next->prev = n->prev; }
static void list_move(struct list_head *n, struct list_head *h)
{ list_del(n); list_add(n, h); }
static void list_add_tail(struct list_head *n, struct list_head *h)
{ n->next = h; n->prev = h->prev; h->prev->next = n; h->prev = n; }
static bool list_empty(const struct list_head *h) { return h->next == h; }
#define list_for_each_entry(p, h, m) \
    for (p = container_of((h)->next, __typeof__(*p), m); &p->m != h; \
         p = container_of(p->m.next, __typeof__(*p), m))
#define list_for_each_entry_safe(p, t, h, m) \
    for (p = container_of((h)->next, __typeof__(*p), m), \
         t = container_of(p->m.next, __typeof__(*p), m); &p->m != h; \
         p = t, t = container_of(t->m.next, __typeof__(*t), m))
#define list_first_entry_or_null(h, t, m) \
    ((h)->next == h ? NULL : container_of((h)->next, t, m))
struct net_device { unsigned refs; bool bridge; };
static bool netif_is_bridge_master(const struct net_device *d) { return d->bridge; }
struct mr_mfc { int mfc_flags; unsigned refs; };
union nf_inet_addr { u32 all[4]; };
struct cdx_ft_vlan { u16 proto, id; };
#define CDX_FT_VLAN_MAX 2
#define ETH_ALEN 6
static bool ether_addr_equal(const u8 *a, const u8 *b) { return !memcmp(a, b, ETH_ALEN); }
/* The address each oif's copy leaves with, which a case changes the way an
 * address change on the oif would. */
static u8 oif_addr[2][ETH_ALEN] = { { 0x02, 0, 0, 0, 0, 0x31 },
                                    { 0x02, 0, 0, 0, 0, 0x32 } };
/* The listener and group descriptions are the header's own, extracted into
 * the generated include, so a field added there is one the worker here has. */
#include "mroute_backend.inc"
/* `in` is the ingress the backend borrows and deletes through. */
/* `built_at' is the egress count the last chain was built against: a chain
 * built before the latest change still names the queues from before it. */
struct cdx_mc_group { bool live; unsigned copies; struct net_device *in; s64 built_at; };
#define WARN_ON_ONCE(x) assert(!(x))
struct cdx_ft_counters { u64 packets, bytes; };
struct work_struct { bool queued; };
#include "mroute_types.inc"
/* The confirmation table's building blocks: hlist and RCU as a single thread
 * sees them, a grace period that only counts, and nftables' generation as a
 * field a case can move. */
struct hlist_node { struct hlist_node *next, **pprev; };
struct hlist_head { struct hlist_node *first; };
struct rcu_head { int unused; };
static void hlist_add_head_rcu(struct hlist_node *n, struct hlist_head *h)
{
    n->next = h->first;
    if (h->first)
        h->first->pprev = &n->next;
    h->first = n;
    n->pprev = &h->first;
}
static void hlist_del_rcu(struct hlist_node *n)
{
    *n->pprev = n->next;
    if (n->next)
        n->next->pprev = n->pprev;
}
static void hlist_replace_rcu(struct hlist_node *old, struct hlist_node *new)
{
    new->next = old->next;
    new->pprev = old->pprev;
    *new->pprev = new;
    if (new->next)
        new->next->pprev = &new->next;
}
#define hlist_entry_safe(ptr, type, member) \
    ((ptr) ? container_of(ptr, type, member) : NULL)
#define hlist_for_each_entry(pos, head, member) \
    for (pos = hlist_entry_safe((head)->first, __typeof__(*(pos)), member); pos; \
         pos = hlist_entry_safe((pos)->member.next, __typeof__(*(pos)), member))
#define hlist_for_each_entry_rcu hlist_for_each_entry
#define DEFINE_SPINLOCK(x) int x
#define DECLARE_DELAYED_WORK(n, f) struct work_struct n
#define BIT(n) (1UL << (n))
#define BITS_PER_LONG 64
#define kfree_rcu(p, f) free(p)
#define xchg(p, v) ({ __typeof__(*(p)) old__ = *(p); *(p) = (v); old__; })
#define IS_ENABLED(x) (x)
#define CONFIG_NF_TABLES 1
#define HZ 100
/* Time as the worker reads it, which a case moves by hand. */
static unsigned long jiffies = 1000;
#define time_before(a, b) ((long)((a) - (b)) < 0)
#define time_after(a, b) time_before(b, a)
static struct {
    struct { unsigned int base_seq; u8 gencursor; u8 commit_applying; } nft;
} init_net;
/* The kernel's reader of the mark a commit holds while it applies itself. */
static bool nft_commit_in_progress(const __typeof__(init_net) *net)
{
    return net->nft.commit_applying;
}
/* A grace period only counts, unless a case has a commit land inside the
 * next one. */
static unsigned grace_periods;
static bool commit_in_grace;
static void synchronize_rcu(void)
{
    grace_periods++;
    if (commit_in_grace) {
        commit_in_grace = false;
        init_net.nft.base_seq++;
    }
}
static bool test_and_set_bit(unsigned n, unsigned long *p)
{
    bool old = (*p >> n) & 1;

    *p |= 1UL << n;
    return old;
}
static void __set_bit(unsigned n, unsigned long *p) { *p |= 1UL << n; }
static u32 jhash2(const u32 *k, unsigned n, u32 seed)
{
    u32 h = seed;

    for (unsigned i = 0; i < n; i++)
        h = h * 31 + k[i];
    return h;
}
enum { NF_BR_PRE_ROUTING, NF_BR_LOCAL_IN, NF_BR_FORWARD, NF_BR_LOCAL_OUT,
       NF_BR_POST_ROUTING };
/* A hook on a bridge's output, which a copy routed into the bridge passes
 * after it was confirmed. */
static bool bridge_out_hooked;
static bool ft_bridge_hooked(unsigned int hooks)
{
    return bridge_out_hooked &&
           (hooks & (BIT(NF_BR_LOCAL_OUT) | BIT(NF_BR_POST_ROUTING)));
}
/* An nftables chain or BPF program running after the observer at
 * POST_ROUTING, which mroute_confirm_order.c finds in the real hook lists. */
static bool observer_followed;
static bool ft_mr_observer_followed(u8 family)
{
    return observer_followed;
}
#include "mroute_confirm_types.inc"
static LIST_HEAD(ft_mr_groups);
static LIST_HEAD(ft_mr_queue);
static int ft_mr_lock, ft_mr_queue_lock, rtnl, ctrl;
static struct ft_mr_vif ft_mr_vif[2][MAXVIFS];
static unsigned ft_mr_count, ft_mr_installed, ft_mr_policy[2];
static u64 ft_mr_refused, ft_mr_install_errors;
static bool ft_mr_stopping, ft_mr_recheck, ft_mr_key_freed, ft_mr_taps_stale;
static bool ft_mr_ready;
/* The `multicast` parameter both learners answer to, on at load. */
static bool ft_mc_enabled = true;
static unsigned long ft_mr_resync_pending;
static unsigned ft_mr_idx(u8 family) { return family == AF_INET6; }
static bool test_bit(unsigned n, const unsigned long *p) { return (*p >> n) & 1; }
static struct work_struct ft_mr_work, ft_mr_stats;
static struct cdx_mc_group hardware;
static struct net_device input, output[2];
static unsigned wanted = 1, adds, replaces, deletes, derives, folds;
static bool fail_add, fail_replace, refuse;
/* What teardown cancelled, in order: s the refresh, r the ruleset watch, w
 * the worker. */
static char cancels[16];
static unsigned cancel_count;
static bool simulate_rearm;
/* The MFC oifs the derivation names, by ifindex, the parent VIF's, and
 * whether a copy leaves through a bridge. A derivation that bumps the
 * ruleset is a commit landing between the worker's sync and its admission. */
enum { OIF_A = 31, OIF_B = 32, PARENT_A = 41, PARENT_B = 42 };
static int planned[2] = { OIF_A, OIF_B };
static unsigned planned_oifs = 1;
static int planned_parent = PARENT_A;
static bool out_bridged, commit_in_derive;
/* The multicast switch turned off once the derivation has answered, as its
 * setter can between the contract and the worker's transaction. */
static bool switch_in_derive;
static void mutex_lock(int *m) { assert(!*m); *m = 1; }
#define lockdep_assert_held(m) assert(*(m))
static void mutex_unlock(int *m) { assert(*m); *m = 0; }
#define spin_lock_bh mutex_lock
#define spin_unlock_bh mutex_unlock
/* The learner never takes the transaction under RTNL. A DSCP filter's drain
 * does, holding the RTNL tc took for it, which is the order the flowtable's
 * bind path already uses; `caller_rtnl' marks that one. */
static bool caller_rtnl;
static void egress_change(struct net_device *dev);
static int ft_mr_egress_drain(const struct net_device *dev);
/* A tc command holding RTNL while the worker waits for it: its egress change
 * and its drain run before the worker gets the lock, with the group the
 * worker has picked in whatever state picking left it. */
static struct net_device *drain_while_waiting;
static int drain_rc;
#define ASSERT_RTNL() assert(rtnl)
/* The chain speaking while the worker waits for RTNL: whoever holds it queues
 * an event, as ipmr does under RTNL, about the group the worker has picked, at
 * each of the next `speak_while_waiting` waits. What it says is `speech`: a
 * VIF of the group's family going; the group's own entry deleted; a VIF of
 * that family going in another table, which the learner does not mirror;
 * another entry of the family replaced; a VIF of the other family going; or
 * an event lost for want of memory, which asks for a resync and queues
 * nothing. A derivation made with anything queued is counted. */
enum speech {
    SPEAK_VIF, SPEAK_DELETE, SPEAK_OTHER_TABLE, SPEAK_OTHER_ENTRY,
    SPEAK_OTHER_FAMILY, SPEAK_LOST,
};
static enum speech speech;
static unsigned speak_while_waiting, derived_behind;
static struct mr_mfc other_entry = { .refs = 1 };
static void chain_speaks(void)
{
    struct ft_mr_group *h, *picked = NULL;
    struct ft_mr_event *e;

    list_for_each_entry(h, &ft_mr_groups, list)
        if (h->busy)
            picked = h;
    if (!speak_while_waiting || !picked)
        return;
    speak_while_waiting--;
    if (speech == SPEAK_LOST) {
        ft_mr_resync_pending |= 1UL << ft_mr_idx(picked->family);
        return;
    }
    e = calloc(1, sizeof(*e));
    assert(e);
    e->family = picked->family;
    e->event = FIB_EVENT_VIF_DEL;
    switch (speech) {
    case SPEAK_DELETE:
        e->event = FIB_EVENT_ENTRY_DEL;
        e->mfc = picked->mfc;
        break;
    case SPEAK_OTHER_TABLE:
        e->table = 100;
        break;
    case SPEAK_OTHER_ENTRY:
        e->event = FIB_EVENT_ENTRY_REPLACE;
        e->mfc = &other_entry;
        break;
    case SPEAK_OTHER_FAMILY:
        e->family = picked->family == AF_INET ? AF_INET6 : AF_INET;
        break;
    default:
        break;
    }
    list_add_tail(&e->list, &ft_mr_queue);
}
static void rtnl_lock(void)
{
    assert(!rtnl && !ctrl && !ft_mr_lock);
    chain_speaks();
    if (drain_while_waiting) {
        struct net_device *dev = drain_while_waiting;

        drain_while_waiting = NULL;
        rtnl = 1;
        caller_rtnl = true;
        egress_change(dev);
        drain_rc = ft_mr_egress_drain(dev);
        caller_rtnl = false;
        rtnl = 0;
    }
    rtnl = 1;
}
/* A tc command that gets RTNL the moment the worker lets go of it, having
 * decided: its egress change lands after the decision and before the outcome
 * is recorded. */
static struct net_device *change_after_decision;
static void rtnl_unlock(void)
{
    assert(rtnl);
    rtnl = 0;
    if (change_after_decision && !caller_rtnl) {
        struct net_device *dev = change_after_decision;

        change_after_decision = NULL;
        rtnl = 1;
        caller_rtnl = true;
        egress_change(dev);
        caller_rtnl = false;
        rtnl = 0;
    }
}
/* Egress changes, counted by ft_egress_changed() before any learner walks
 * its groups, and this learner's half of the walk. */
static s64 ft_egress_changes;
static s64 atomic64_read(const s64 *v) { return *v; }
static s64 atomic64_read_acquire(const s64 *v) { return *v; }
static unsigned int ft_mr_egress_mark(const struct net_device *dev);
static void egress_change(struct net_device *dev)
{
    ft_egress_changes++;
    ft_mr_egress_mark(dev);
}
/* A change landing while the worker is deciding or programming a group. */
static struct net_device *change_during_derive, *change_during_program;
/* A tc command that gets the transaction just before its next taker, holding
 * RTNL of its own, and drains a port whose change was marked earlier. What
 * the drain said, and whether it left installed an entry built before the
 * last change, are kept for a case to read. */
static struct net_device *drain_first;
static int drain_first_rc;
static bool drain_first_left_stale;
static void cdx_ft_begin(void)
{
    assert((!rtnl || caller_rtnl) && !ctrl && !ft_mr_lock);
    if (drain_first) {
        struct net_device *dev = drain_first;

        drain_first = NULL;
        rtnl = 1;
        caller_rtnl = true;
        drain_first_rc = ft_mr_egress_drain(dev);
        drain_first_left_stale = hardware.live &&
                                 hardware.built_at < ft_egress_changes;
        caller_rtnl = false;
        rtnl = 0;
    }
    ctrl = 1;
}
static void cdx_ft_end(void) { assert(ctrl); ctrl = 0; }
static void dev_hold(struct net_device *d) { d->refs++; }
static void dev_put(struct net_device *d) { assert(d->refs); d->refs--; }
static void mr_cache_put(struct mr_mfc *c) { assert(c->refs); c->refs--; }
static void schedule_work(struct work_struct *w) { w->queued = true; }
static void schedule_delayed_work(struct work_struct *w, unsigned delay)
{ w->queued = true; }
/* The ruleset poll moved to when a settling ruleset will have settled. */
static unsigned long ruleset_delay;
#define system_wq NULL
static void mod_delayed_work(void *wq, struct work_struct *w, unsigned long delay)
{
    assert(w == &ft_mr_ruleset);
    w->queued = true;
    ruleset_delay = delay;
}
static void cancel_delayed_work_sync(struct work_struct *w)
{
    assert(ft_mr_stopping && cancel_count < sizeof(cancels) - 1);
    assert(w == &ft_mr_stats || w == &ft_mr_ruleset);
    cancels[cancel_count++] = w == &ft_mr_stats ? 's' : 'r';
    w->queued = false;
}
static void cancel_work_sync(struct work_struct *w)
{
    assert(w == &ft_mr_work && cancel_count < sizeof(cancels) - 1);
    cancels[cancel_count++] = 'w';
    w->queued = false;
    /* A worker already past its stopping check can rearm during the drain. */
    if (simulate_rearm) {
        schedule_delayed_work(&ft_mr_stats, FT_MR_STATS_INTERVAL);
        schedule_delayed_work(&ft_mr_ruleset, FT_MR_RULESET_INTERVAL);
    }
}
/* The bridged learner, as the routed worker reaches it: every call takes
 * ft_mc_lock, which may never nest inside ft_mr_lock, RTNL or the
 * transaction. The route is the one a group routed through a bridge
 * publishes; `carried` is what the bridged learner would report back. */
static int ft_mc_lock;
static struct net_device bridge;
static bool through_bridge, carried;
static unsigned publishes, withdrawals, taps_published;
static struct cdx_ft_counters bridged_count = { .packets = 7, .bytes = 7 * 578 };
static void bridged_side(void)
{
    assert(!ft_mr_lock && !rtnl && !ctrl && !ft_mc_lock);
}
static bool ft_mc_route_publish(struct ft_mc_route *r, const struct ft_mc_route *want)
{
    bridged_side();
    publishes++;
    assert(want->bridge == &bridge && want->listeners == wanted);
    for (unsigned i = 0; i < want->listeners; i++)
        assert(want->listener[i].dev == &output[i]);
    /* Linking starts the count again, and a new series says so; restating
     * a linked route does neither. */
    if (!r->linked)
        r->series++;
    r->linked = true;
    r->carried = carried;
    return carried;
}
/* A published route holds what its carrying flow counted, `bridged_count`
 * here, and hands it back as it goes. */
static bool ft_mc_route_withdraw(struct ft_mc_route *r, struct cdx_ft_counters *last,
                                 u8 *in_tags, u32 *series)
{
    bool counted = r->linked;

    bridged_side();
    withdrawals++;
    *last = counted ? bridged_count : (struct cdx_ft_counters){ 0, 0 };
    *in_tags = 1;
    *series = r->series;
    r->linked = false;
    r->carried = false;
    r->series++;
    return counted;
}
static bool ft_mc_route_state(struct ft_mc_route *r, struct cdx_ft_counters *stats,
                              u8 *in_tags, u32 *series)
{
    assert(ft_mr_lock);   /* a leaf lock, readable under this learner's */
    *stats = bridged_count;
    *in_tags = 1;
    *series = r->series;
    return r->carried;
}
static void ft_mr_publish_taps(void) { bridged_side(); taps_published++; }
/* The add below can move the egress count mid-build, which is the race the
 * count exists for. */
static bool queues_move_during_add;
/* Only chain_speaks() queues anything, and what it queues is applied the way
 * ft_mr_apply() applies it (mroute_learner.c runs the real one): a VIF in
 * another table is none of this learner's, a VIF going asks its family
 * again, an entry's change asks its own group again and its delete retires
 * it. */
static unsigned applied;
static bool ft_mr_apply(struct ft_mr_event *e)
{
    struct ft_mr_group *h;

    assert(ft_mr_lock && !rtnl);
    applied++;
    if (e->table)
        return true;
    list_for_each_entry(h, &ft_mr_groups, list) {
        if (e->mfc ? h->mfc != e->mfc : h->family != e->family)
            continue;
        h->dirty = true;
        if (e->event == FIB_EVENT_ENTRY_DEL)
            h->gone = true;
    }
    return true;
}
static void ft_mr_lost_event(u8 family) { abort(); }
static void ft_mr_event_free(struct ft_mr_event *e) { free(e); }
/* The resync a lost event asks for, as the worker's first step runs it: it
 * takes RTNL of its own, and whether it finishes or not, every group of a
 * family it was asked for is derived again. One that does not finish leaves
 * the family asked for, and is what it returns. `lost_after_resync` is an
 * event lost behind it, once it has let go of RTNL: the family is asked for
 * again, though this resync finished it. */
static unsigned resyncs, lost_after_resync;
static bool resync_fails;
static void ft_mr_dirty_family(u8 family);
static unsigned long ft_mr_resync(void)
{
    unsigned long failed = 0;

    assert(!rtnl && !ft_mr_lock && !ctrl);
    resyncs++;
    for (unsigned idx = 0; idx < 2; idx++) {
        if (!test_bit(idx, &ft_mr_resync_pending))
            continue;
        if (resync_fails)
            failed |= 1UL << idx;
        else
            ft_mr_resync_pending &= ~(1UL << idx);
        mutex_lock(&ft_mr_lock);
        ft_mr_dirty_family(idx ? AF_INET6 : AF_INET);
        mutex_unlock(&ft_mr_lock);
        if (lost_after_resync) {
            lost_after_resync--;
            ft_mr_resync_pending |= 1UL << idx;
        }
    }
    return failed;
}
/* The stream arrives tagged on its port: a spec the root validates the tag
 * of, which a rebuild has to carry as well. */
static bool tagged_ingress;
static enum ft_mr_state ft_mr_derive(struct ft_mr_group *g, struct ft_mr_plan *p)
{
    assert(rtnl);
    if (!list_empty(&ft_mr_queue))
        derived_behind++;
    derives++;
    if (change_during_derive) {
        /* Under RTNL, as the tc caller is: the group is the worker's, and
         * still holds what it installed. */
        assert(g->busy);
        egress_change(change_during_derive);
        change_during_derive = NULL;
    }
    if (refuse) return FT_MR_REFUSED_LISTENER;
    /* The oif walk, which a refusal above never reached. */
    for (unsigned i = 0; i < planned_oifs; i++)
        p->oif[p->oif_count++] = planned[i];
    p->parent = planned_parent;
    p->oifs_known = true;
    /* Switched off: refused once its oifs are named, as the contract does,
     * so it goes on gathering confirmations in software. */
    if (!ft_mc_enabled) return FT_MR_REFUSED_PAUSED;
    p->out_bridged = out_bridged;
    if (commit_in_derive) {
        commit_in_derive = false;
        init_net.nft.base_seq++;
    }
    if (through_bridge) {
        p->via = &bridge;
        p->via_vid = 289;
        p->via_tagged = true;
        p->mtu = 1500;
        dev_hold(&bridge);
    } else {
        p->spec.in = &input;
        dev_hold(&input);
        if (tagged_ingress) {
            p->spec.in_vlan[0].proto = 0x0081;
            p->spec.in_vlan[0].id = 100;
            p->spec.in_vlans = 1;
            p->in_tags = 1;
        }
    }
    p->spec.listeners = wanted;
    for (unsigned i = 0; i < wanted; i++) {
        p->spec.listener[i].dev = &output[i];
        p->spec.listener[i].routed = true;
        memcpy(p->spec.listener[i].src_mac, oif_addr[i], ETH_ALEN);
        dev_hold(&output[i]);
    }
    if (switch_in_derive) {
        switch_in_derive = false;
        ft_mc_enabled = false;
    }
    return FT_MR_PENDING;
}
/* The worker programs the hardware with the transaction alone: the netdev
 * events and the egress mark, which take ft_mr_lock under RTNL, must never
 * wait behind a hardware call. Only the drain, under its tc command's RTNL,
 * replaces holding it. */
static int cdx_mc_group_add(const struct cdx_mc_group_spec *s, struct cdx_mc_group **hw)
{
    assert(ctrl && !ft_mr_lock && !hardware.live && s->in);
    adds++;
    if (fail_add) return -ENOMEM;
    if (queues_move_during_add) {
        queues_move_during_add = false;
        ft_egress_changes++;
    }
    hardware.live = true;
    hardware.copies = s->listeners;
    hardware.in = s->in;
    hardware.built_at = ft_egress_changes;
    *hw = &hardware;
    return 0;
}
/* What the last replace was asked to build, for a case to read. */
static struct cdx_mc_group_spec replaced_with;
static int cdx_mc_group_replace(struct cdx_mc_group *hw, const struct cdx_mc_group_spec *s)
{
    assert(ctrl && hw->live && s->in == hw->in);
    assert(!ft_mr_lock == !caller_rtnl);
    replaces++;
    replaced_with = *s;
    if (fail_replace) return -ENOMEM;  /* backend keeps the previous chain */
    hw->copies = s->listeners;
    hw->built_at = ft_egress_changes;
    if (change_during_program) {
        /* After the chain read the port, so this chain is from before the
         * change. The change is counted and marks the group now, not once
         * the worker has recorded: the worker holds no learner lock while
         * it programs. */
        struct net_device *dev = change_during_program;

        change_during_program = NULL;
        egress_change(dev);
        assert(hw->built_at < ft_egress_changes);
    }
    return 0;
}
static void cdx_mc_group_del(struct cdx_mc_group **hw)
{
    assert(ctrl && !ft_mr_lock && *hw && (*hw)->live);
    /* The delete unsubscribes the port's address through the ingress, so
     * somebody must still hold it. */
    assert((*hw)->in && (*hw)->in->refs);
    deletes++;
    (*hw)->live = false;
    *hw = NULL;
}
static struct cdx_ft_counters hw_count;
/* A read the backend could not make: zero, and said so. */
static bool fail_stats;
static bool cdx_mc_group_stats(struct cdx_mc_group *hw, struct cdx_ft_counters *c)
{
    assert(ctrl && hw->live);
    if (fail_stats) {
        memset(c, 0, sizeof(*c));
        return false;
    }
    *c = hw_count;
    return true;
}
/* What the last fold was given, whether the group had an entry of its own
 * and that entry was in hardware when it was made, and the baseline and run
 * it was folded against. */
static unsigned folded_tags;
static struct cdx_ft_counters folded;
static bool folded_own, folded_live;
static u64 folded_base;
static u32 folded_run;
static void ft_mr_fold(struct ft_mr_group *g, const struct cdx_ft_counters *c, u8 tags)
{
    folds++;
    folded = *c;
    folded_tags = tags;
    folded_own = g->hw != NULL;
    folded_live = hardware.live;
    folded_base = g->folded_packets;
    folded_run = g->folded_series;
}
/* The forwarding check's registration, as the worker asks for it. A failed
 * one is counted in /proc, which is not compiled here. */
static bool confirm_hooked[2];
static void ft_mr_confirm_sync(void)
{
    (void)ft_mr_confirm_errors;
    for (unsigned idx = 0; idx < 2; idx++)
        confirm_hooked[idx] = !ft_mr_stopping && ft_mr_watch_count[idx];
}
#include "mroute_refresh.inc"
static void run(void)
{ ft_mr_work.queued = false; ft_mr_work_fn(&ft_mr_work); }
static void refresh(void)
{
    ft_mr_stats.queued = false;
    ft_mr_stats_fn(&ft_mr_stats);
    assert(ft_mr_work.queued && ft_mr_stats.queued);
    run();
}
/* A copy of the group's stream seen leaving by `ifindex` at POST_ROUTING, as
 * the hook reports it, having arrived by `iif` -- by default the parent the
 * derivation names. */
static void seen_from(const struct ft_mr_group *g, int ifindex, int iif)
{
    ft_mr_confirm_seen(g->family, &g->src, &g->dst, ifindex, iif);
}
static void seen(const struct ft_mr_group *g, int ifindex)
{
    seen_from(g, ifindex, planned_parent);
}
/* The ruleset poll, as its timer runs it. */
static void poll_ruleset(void)
{
    ft_mr_ruleset.queued = false;
    ft_mr_ruleset_fn(&ft_mr_ruleset);
}
/* The ruleset stands still for as long as the worker asks it to: the poll
 * finds it settling and wakes the worker, which lets copies confirm. */
static void settle(void)
{
    assert(!ft_mr_gen_open && ft_mr_ruleset.queued);
    jiffies += ruleset_delay;
    poll_ruleset();
    assert(ft_mr_work.queued);
    run();
    assert(ft_mr_gen_open);
}
int main(void)
{
    struct mr_mfc cache = { .refs = 1 };
    struct ft_mr_group *g = calloc(1, sizeof(*g));
    assert(g);
    g->mfc = &cache;
    g->family = AF_INET;
    g->dirty = true;
    list_add(&g->list, &ft_mr_groups);
    ft_mr_count = 1;
    /* Initial provider enumeration may queue work before the learner is
     * published. No partial snapshot may reach the backend. */
    run();
    assert(!adds && !hardware.live && g->dirty);
    ft_mr_ready = true;
    run();
    /* Eligible, and not carried: Linux has not been seen forwarding the
     * stream to its oif. The ruleset in force has been read, after a grace
     * period, and is being timed; the group is watched for copies from its
     * parent, and the forwarding check is registered for its family. */
    assert(!adds && !hardware.live && g->state == FT_MR_UNCONFIRMED);
    assert(!strcmp(ft_mr_state_text(g->state), "pending-confirm"));
    assert(!ft_mr_refusal(g->state) && !g->offloaded);
    assert(!ft_mr_gen_open && grace_periods == 1 && !ft_mr_ruleset_changes);
    assert(g->watch && g->watch->oifs == 1 && g->watch->oif[0] == OIF_A);
    assert(g->watch->parent == PARENT_A);
    assert(confirm_hooked[0] && !confirm_hooked[1]);
    /* The poll comes back when the ruleset will have stood still long
     * enough, and until then a copy confirms nothing, and wakes nobody. */
    assert(ft_mr_ruleset.queued && ruleset_delay == FT_MR_RULESET_SETTLE);
    ft_mr_work.queued = false;
    seen(g, OIF_A);
    assert(!g->watch->seen && !ft_mr_work.queued);
    /* Early, the poll finds it still settling: the worker is woken, looks,
     * and leaves it closed. */
    jiffies += FT_MR_RULESET_SETTLE - 1;
    poll_ruleset();
    assert(ft_mr_work.queued);
    run();
    assert(!ft_mr_gen_open && grace_periods == 1 && ruleset_delay == 1);
    /* On time, it opens, after a grace period for the copies already past
     * FORWARD when the ruleset was read. */
    settle();
    assert(grace_periods == 2 && !ft_mr_ruleset_changes);
    assert(!adds && g->state == FT_MR_UNCONFIRMED);
    /* A copy to another interface, of another group, or from another
     * parent is not this one. */
    {
        union nf_inet_addr other = { .all = { 1 } };

        ft_mr_work.queued = false;
        seen(g, OIF_B);
        seen_from(g, OIF_A, PARENT_B);
        ft_mr_confirm_seen(AF_INET, &other, &g->dst, OIF_A, PARENT_A);
        ft_mr_confirm_seen(AF_INET6, &g->src, &g->dst, OIF_A, PARENT_A);
        assert(!g->watch->seen && !ft_mr_work.queued);
    }
    /* Its own oif: the worker is woken, asks again, and carries it. */
    seen(g, OIF_A);
    assert(g->watch->seen == 1 && g->watch->news && ft_mr_work.queued);
    run();
    assert(adds == 1 && hardware.live && ft_mr_installed == 1);
    assert(g->offloaded && cache.mfc_flags == MFC_OFFLOAD && !g->watch->news);
    /* The group's own count of entries added, which /proc reports per row. */
    assert(g->adds == 1);
    /* A copy seen again is no news. */
    ft_mr_work.queued = false;
    seen(g, OIF_A);
    assert(!ft_mr_work.queued);
    /* The ingress twice: the group's, and the entry's own. */
    assert(input.refs == 2 && output[0].refs == 1 && g->hw_in == &input);
    for (unsigned i = 0; i < 20; i++) refresh();
    assert(adds == 1 && replaces == 0 && deletes == 0);
    assert(derives == 22 && folds == 20 && input.refs == 2);
    /* A read that fails is no sample, however many come in a row: folded as
     * zero it would re-base the fold, and the first read after would count
     * the whole stream into the MFC entry again. */
    fail_stats = true;
    for (unsigned i = 0; i < 3; i++) refresh();
    assert(folds == 20 && hardware.live && g->offloaded);
    fail_stats = false;
    refresh();
    assert(folds == 21);

    /* A router appeared, then disappeared. Refreshed chains carry exact sets,
     * swapped under the entry already there: the group adds none. */
    wanted = 2;
    ft_mr_recheck = true;
    run();
    assert(replaces == 1 && hardware.copies == 2 && output[1].refs == 1);
    wanted = 1;
    refresh();
    assert(replaces == 2 && hardware.copies == 1 && output[1].refs == 0);
    assert(g->adds == 1);

    /* Exhaustion must not retain a subset and report offload forever. And a
     * failure is tried again once a refresh, not back to back in the same
     * pass, where nothing could have changed: four tries a refresh apart,
     * then refused until the answer changes. */
    wanted = 2;
    fail_replace = fail_add = true;
    refresh();
    assert(replaces == 3 && deletes == 1 && !hardware.live);
    assert(!g->hw && !g->offloaded);
    assert(!cache.mfc_flags && !ft_mr_installed);
    assert(!input.refs && !output[0].refs && !output[1].refs);
    assert(g->retries == 1 && g->state != FT_MR_REFUSED_FAILED && !g->dirty);
    unsigned before = adds;
    run();                  /* nothing asks for it between refreshes */
    assert(adds == before);
    for (unsigned i = 2; i <= FT_MR_MAX_RETRIES; i++) {
        refresh();
        assert(adds == before + i - 1 && g->retries == i && !g->dirty);
    }
    assert(g->state == FT_MR_REFUSED_FAILED);
    before = adds;
    refresh();
    assert(adds == before); /* timer cannot evade the bounded retry policy */
    fail_replace = fail_add = false;
    ft_mr_recheck = true;
    run();
    assert(hardware.live && hardware.copies == 2 && g->offloaded);
    /* Withdrawn and put back: an entry added again, which the group counts,
     * where only the failed tries did not. */
    assert(g->adds == 2);

    /* An uncarriable router withdraws the whole chain. A timer discovers
     * restored eligibility even while no group is installed. What the entry
     * counted after the refresh's fold is read before it goes, and folded:
     * the refresh folds once, the delete once more, with the entry's count. */
    refuse = true;
    hw_count = (struct cdx_ft_counters){ 9, 9 * 100 };
    {
        unsigned before = folds;

        refresh();
        assert(folds == before + 2 && folded.packets == 9);
    }
    hw_count = (struct cdx_ft_counters){ 0, 0 };
    assert(!hardware.live && !ft_mr_installed && !input.refs);
    refuse = false;
    refresh();
    assert(hardware.live && hardware.copies == 2 && g->offloaded);
    /* The same withdrawal with every read failing, the one taken just before
     * the delete included: nothing is folded for it. */
    refuse = true;
    fail_stats = true;
    {
        unsigned before = folds;

        refresh();
        assert(folds == before && !hardware.live);
    }
    fail_stats = false;
    refuse = false;
    refresh();
    assert(hardware.live && hardware.copies == 2 && g->offloaded);

    /* A router netdev unregisters: the copies' references are let go of
     * synchronously, and the ingress, which is still the entry's key, is
     * kept. So the rederivation without it swaps the chain under the same
     * root -- one replace, no delete and add -- and the stream never leaves
     * hardware for a listener it did not lose. */
    {
        unsigned a0 = adds, r0 = replaces, d0 = deletes;
        u32 own = g->adds;

        rtnl_lock();
        ft_mr_device_gone(&output[1]);
        rtnl_unlock();
        assert(input.refs == 2 && g->in == &input && g->hw_in == &input);
        assert(!output[0].refs && !output[1].refs && !g->listeners);
        assert(!g->hw_spec.listeners);   /* no drain may replay it */
        assert(!ft_mr_taps_stale);   /* a port: the VIFs on bridges stand */
        wanted = 1;
        run();
        assert(replaces == r0 + 1 && adds == a0 && deletes == d0);
        assert(hardware.live && hardware.copies == 1 && output[0].refs == 1);
        assert(input.refs == 2 && g->state == FT_MR_INSTALLED);
        /* And the row says so: its own count of entries added stood still,
         * which a withdrawal and re-add ending on the same set would not. */
        assert(g->adds == own);
    }

    /* The oif given another address. Nothing else about the plan moved, yet
     * the chain writes the old address, so the group asked again -- an
     * address change kicks the learner -- swaps it for one that writes the
     * new, under the same key. A pass that finds the address as it was
     * swaps nothing. */
    {
        unsigned a0 = adds, r0 = replaces, d0 = deletes;
        u32 own = g->adds;

        ft_mr_recheck = true;
        run();
        assert(replaces == r0);
        oif_addr[0][4] = 0x10;
        ft_mr_recheck = true;
        run();
        assert(replaces == r0 + 1 && adds == a0 && deletes == d0 && g->adds == own);
        assert(ether_addr_equal(replaced_with.listener[0].src_mac, oif_addr[0]));
        assert(ether_addr_equal(g->listener[0].src_mac, oif_addr[0]));
        assert(ether_addr_equal(g->hw_spec.listener[0].src_mac, oif_addr[0]));
        assert(hardware.live && g->state == FT_MR_INSTALLED);
    }

    /* The ingress itself unregisters. The group lets go of its reference at
     * once; the entry, which the delete goes through, keeps its own until
     * the worker takes it out of hardware -- and then lets go too. */
    {
        u32 own = g->adds;

        rtnl_lock();
        ft_mr_device_gone(&input);
        rtnl_unlock();
        assert(input.refs == 1 && hardware.live && g->hw_in == &input);
        refuse = true;           /* the plan has no ingress to name any more */
        run();
        assert(!hardware.live && !input.refs && !g->hw_in);
        refuse = false;
        ft_mr_recheck = true;
        run();
        assert(hardware.live && input.refs == 2);
        /* Out of hardware and back in: one more entry of its own. */
        assert(g->adds == own + 1);
    }

    /* A bridge going down: the bridged learner drops its taps, and ipmr
     * keeps the VIFs, so nothing but this would publish them again. */
    bridge.bridge = true;
    ft_mr_work.queued = false;
    rtnl_lock();
    ft_mr_device_gone(&bridge);
    rtnl_unlock();
    assert(ft_mr_taps_stale && ft_mr_work.queued);
    ft_mr_taps_stale = false;
    bridge.bridge = false;

    /* A second entry for the same (S,G) arriving on the same port -- another
     * VLAN of it, which the key does not name -- is one classifier entry
     * whose root validates one tag stack. It is refused, not installed over
     * the first, and takes the key in the same pass the first gives it up. */
    {
        struct mr_mfc other = { .refs = 1 };
        struct ft_mr_group *h = calloc(1, sizeof(*h));
        unsigned added = adds;

        assert(h);
        h->mfc = &other;
        h->family = AF_INET;
        h->dirty = true;
        list_add(&h->list, &ft_mr_groups);
        ft_mr_count = 2;
        run();
        assert(h->state == FT_MR_UNCONFIRMED && h->watch && !h->watch->seen);
        seen(h, OIF_A);
        run();
        assert(h->state == FT_MR_REFUSED_CONTESTED && !h->hw && !h->offloaded);
        assert(adds == added && g->hw && g->state == FT_MR_INSTALLED);
        assert(ft_mc_lock == 0 && !ft_mr_lock);
        g->gone = true;
        run();
        assert(adds == added + 1 && h->hw && h->state == FT_MR_INSTALLED);
        assert(h->offloaded && other.mfc_flags == MFC_OFFLOAD && !cache.refs);
        /* Each group counts its own: the refused one's first entry. */
        assert(h->adds == 1);
        g = h;
        cache = other;
        g->mfc = &cache;
    }

    /* A port the group copies out of changes its egress queues. The plan is
     * the same, which the worker would skip; the chain names the old queues,
     * so it is replaced all the same, and only for a group copying out of
     * that port. The mark stays until a rebuild after the change has
     * happened, for a drain to read. */
    {
        unsigned replaced = replaces;

        assert(ft_mr_egress_mark(&input) == 0 && !g->egress_stale);
        assert(ft_mr_egress_mark(&output[0]) == 1);
        assert(g->egress_stale && g->dirty && ft_mr_work.queued);
        assert(!ft_mr_lock);
        run();
        assert(replaces == replaced + 1 && hardware.live && !g->egress_stale);
        assert(hardware.built_at == ft_egress_changes);
        assert(g->state == FT_MR_INSTALLED && g->offloaded);
        /* And nothing more on the next pass: the plan is the same again. */
        ft_mr_recheck = true;
        run();
        assert(replaces == replaced + 1);
    }

    /* The queues move while a chain is being built from the old ones, and
     * the group, having no entry yet, was not there to be marked. The count
     * it was built under says so, and it is built again in the same pass. */
    {
        unsigned added = adds, replaced = replaces;

        ft_mr_recheck = true;
        refuse = true;
        run();
        assert(!hardware.live);
        refuse = false;
        queues_move_during_add = true;
        ft_mr_recheck = true;
        run();
        assert(adds == added + 1 && replaces == replaced + 1);
        assert(hardware.live && !g->egress_stale && !g->dirty);
        assert(hardware.built_at == ft_egress_changes);
    }

    /* A DSCP filter's drain cannot wait for the worker: the worker takes
     * RTNL, which the filter's caller holds. It rebuilds the installed chain
     * itself, from the spec recorded with it, without deriving anything, and
     * the worker then finds the group current. */
    {
        unsigned r0 = replaces, d0 = derives;

        rtnl_lock();
        caller_rtnl = true;
        egress_change(&output[0]);
        assert(!ft_mr_egress_drain(&output[0]));
        assert(replaces == r0 + 1 && !g->egress_stale && derives == d0);
        assert(hardware.built_at == ft_egress_changes && hardware.copies == 1);
        assert(replaced_with.in == &input && replaced_with.listeners == 1 &&
               replaced_with.listener[0].dev == &output[0]);
        caller_rtnl = false;
        rtnl_unlock();
        run();
        assert(replaces == r0 + 1 && derives == d0 + 1);

        /* A rebuild that fails in the drain hands the group to the worker
         * and holds the drain -- once: the worker's own failed replace
         * withdraws the group, so the next drain finds nothing reading the
         * old queues, whatever the refresh's retry pacing. Another port's
         * drain is not held by it. */
        rtnl_lock();
        caller_rtnl = true;
        egress_change(&output[0]);
        fail_replace = true;
        assert(ft_mr_egress_drain(&output[0]) == -EAGAIN);
        assert(g->egress_stale && g->dirty && ft_mr_work.queued);
        assert(!ft_mr_egress_drain(&output[1]));
        caller_rtnl = false;
        rtnl_unlock();
        run();
        assert(!hardware.live && !g->hw && !g->egress_stale);
        rtnl_lock();
        caller_rtnl = true;
        assert(!ft_mr_egress_drain(&output[0]));
        caller_rtnl = false;
        rtnl_unlock();
        fail_replace = false;
        g->retries = 0;
        ft_mr_recheck = true;
        run();
        assert(hardware.live && g->hw && g->state == FT_MR_INSTALLED);
    }

    /* The drain's common case: the refresh keeps the worker busy, and a
     * worker that has picked a group waits for the RTNL the tc caller holds.
     * The group is still what it installed until the worker's own pass, so
     * the drain rebuilds it in place rather than report it held -- and a
     * drain for a port the group does not list is not held by it at all.
     * The worker then finds the chain current and builds nothing. */
    {
        unsigned r2 = replaces, d2 = derives;

        g->dirty = true;
        drain_rc = 1;
        drain_while_waiting = &output[1];
        run();
        assert(!drain_rc && replaces == r2 && derives == d2 + 1);
        g->dirty = true;
        drain_rc = 1;
        drain_while_waiting = &output[0];
        run();
        assert(!drain_rc && replaces == r2 + 1 && derives == d2 + 2);
        assert(!g->egress_stale && !g->busy && hardware.built_at == ft_egress_changes);
        assert(hardware.live && input.refs == 2 && output[0].refs == 1);
    }

    /* A change landing while the worker decides marks a group the worker
     * holds, and the decision sees the mark: the unchanged plan is rebuilt
     * in the same pass. */
    {
        unsigned r1 = replaces;

        g->dirty = true;
        change_during_derive = &output[0];
        run();
        assert(replaces == r1 + 1 && !g->egress_stale);
        assert(hardware.built_at == ft_egress_changes);
        /* One landing after the worker has decided, the plan unchanged and
         * nothing to build, marks a group the worker still holds, which the
         * mark leaves to it: recording nothing built, the worker sees the
         * mark and goes round again rather than leave the old chain. */
        g->dirty = true;
        change_after_decision = &output[0];
        run();
        assert(!change_after_decision && replaces == r1 + 2);
        assert(!g->egress_stale && !g->dirty && !g->busy);
        assert(hardware.built_at == ft_egress_changes);
        /* And one landing after the chain read the port moves the count
         * under the build, so the worker builds again. */
        r1 = replaces;
        egress_change(&output[0]);
        change_during_program = &output[0];
        run();
        assert(replaces == r1 + 2 && !g->egress_stale);
        assert(hardware.built_at == ft_egress_changes);
    }

    /* IPTV on a VLAN: the stream arrives tagged, and the root validates the
     * tag. The drain replaces the chain with the spec it was built from,
     * tag included -- one made up from the group's addresses would carry
     * no tag, which the backend refuses as another key, so the drain
     * would hold the map for good. */
    {
        unsigned r3 = replaces;

        tagged_ingress = true;
        ft_mr_recheck = true;
        run();
        assert(hardware.live && g->in_tags == 1 && g->hw_spec.in_vlans == 1);
        r3 = replaces;
        rtnl_lock();
        caller_rtnl = true;
        egress_change(&output[0]);
        assert(!ft_mr_egress_drain(&output[0]) && replaces == r3 + 1);
        assert(replaced_with.in_vlans == 1 && replaced_with.in_vlan[0].id == 100);
        caller_rtnl = false;
        rtnl_unlock();
        tagged_ingress = false;
        ft_mr_recheck = true;
        run();
        assert(hardware.live && !g->in_tags && !g->hw_spec.in_vlans);
    }

    /* A device the installed set names going away releases the set, and
     * the recorded spec with it: nothing may replay a spec naming a device
     * that is going. Until the worker has rebuilt the group, a drain cannot
     * vouch for it. */
    {
        rtnl_lock();
        ft_mr_device_gone(&output[0]);
        rtnl_unlock();
        assert(!g->listeners && !g->hw_spec.listeners && g->hw && g->dirty);
        assert(ft_mr_egress_mark(&output[1]) == 1 && g->egress_stale);
        rtnl_lock();
        caller_rtnl = true;
        assert(ft_mr_egress_drain(&output[1]) == -EAGAIN);
        caller_rtnl = false;
        rtnl_unlock();
        run();
        assert(hardware.live && g->listeners == 1 && g->hw_spec.listeners == 1);
        assert(!g->egress_stale);
    }

    /* Routed through a bridge: nothing of its own goes into hardware. The
     * copies are published to the bridged learner, the state follows what it
     * reports, and the counters folded into the MFC are the bridged group's,
     * less the ingress framing it reports -- one tag here. */
    {
        unsigned added = adds, before = publishes, withdrawn = withdrawals;

        through_bridge = true;
        ft_mr_recheck = true;
        run();
        /* Its own entry, keyed on a port the stream no longer arrives on,
         * comes out; the route goes to the bridged learner instead. */
        assert(!hardware.live && !g->hw && adds == added);
        assert(publishes == before + 1 && g->route && g->route->linked);
        assert(g->state == FT_MR_BRIDGED && !g->offloaded && !cache.mfc_flags);
        assert(g->via == &bridge && bridge.refs == 1 && !input.refs);
        assert(!strcmp(ft_mr_state_text(g->state), "pending-bridged"));
        assert(!ft_mr_refusal(g->state));
        /* The bridged group installs and says so; the kick re-derives. */
        carried = true;
        ft_mr_recheck = true;
        run();
        assert(g->state == FT_MR_INSTALLED && g->offloaded &&
               cache.mfc_flags == MFC_OFFLOAD && !hardware.live);
        unsigned folding = folds;
        refresh();
        assert(folds == folding + 1 && folded.packets == 7 && folded_tags == 1);
        /* The bridge goes down while the route stays published: the group
         * lets go of it and derives it again, and the route's count goes on
         * from where it was. So does the baseline the MFC's count was folded
         * to -- here the route's 7, as a real fold would have left it. Taken
         * from zero instead, the next fold would add all 7 a second time. */
        {
            unsigned published = publishes;

            g->folded_packets = bridged_count.packets;
            g->folded_bytes = bridged_count.bytes;
            rtnl_lock();
            ft_mr_device_gone(&bridge);
            rtnl_unlock();
            assert(!g->via && !bridge.refs && g->route->linked);
            run();
            assert(g->via == &bridge && g->state == FT_MR_INSTALLED);
            assert(publishes == published + 1 && withdrawals == withdrawn);
            refresh();
            assert(g->folded_packets == bridged_count.packets);
            assert(g->folded_bytes == bridged_count.bytes);
            /* A route taken back and published again does start from
             * zero, and the baseline with it. */
            refuse = true;
            ft_mr_recheck = true;
            run();
            assert(withdrawals == withdrawn + 1 && !g->route->linked);
            refuse = false;
            ft_mr_recheck = true;
            run();
            assert(g->route->linked && g->state == FT_MR_INSTALLED);
            refresh();
            assert(!g->folded_packets && !g->folded_bytes);
            withdrawn = withdrawals;
        }
        /* And stops carrying it. */
        carried = false;
        ft_mr_recheck = true;
        run();
        assert(g->state == FT_MR_BRIDGED && !g->offloaded && !cache.mfc_flags);
        folding = folds;
        refresh();
        assert(folds == folding);
        /* Its copies are the bridged group's, rebuilt by the other half. */
        assert(ft_mr_egress_mark(&output[0]) == 0 && !g->egress_stale);
        /* The parent moving back to a port takes the route back, and what
         * it counted since the last fold is folded as it goes: against its
         * own baseline, before the entry of the group's own is added and
         * takes the baseline from zero. */
        folding = folds;
        through_bridge = false;
        ft_mr_recheck = true;
        run();
        assert(withdrawals == withdrawn + 1 && !g->route->linked);
        assert(folds == folding + 1 && folded.packets == bridged_count.packets);
        assert(folded_tags == 1 && !folded_own);
        assert(hardware.live && g->hw && g->state == FT_MR_INSTALLED);
        assert(!bridge.refs && g->via == NULL);
        assert(!g->folded_packets && !g->folded_series);
        /* Taken back already: a later pass folds nothing more of it. */
        folding = folds;
        ft_mr_recheck = true;
        run();
        assert(folds == folding);
    }
    /* A route taken back before anything of it was folded. The group's
     * baseline is still its own entry's -- here 1000, as a real fold of that
     * entry would have left it, well above the 7 the route counted -- and
     * belongs to no run of the route's. The route's count is folded from
     * zero, its own run's start: against the entry's baseline it would read
     * as a count gone backwards and be lost, or come short by 1000. */
    {
        unsigned folding;
        u32 run_linked;

        g->folded_packets = 1000;
        g->folded_bytes = 1000 * 100;
        g->folded_series = 0;
        through_bridge = true;
        carried = true;
        ft_mr_recheck = true;
        run();
        assert(!g->hw && g->route->linked && g->state == FT_MR_INSTALLED);
        assert(g->folded_packets == 1000 && !g->folded_series);
        run_linked = g->route->series;
        folding = folds;
        through_bridge = false;
        ft_mr_recheck = true;
        run();
        assert(folds == folding + 1 && folded.packets == bridged_count.packets);
        assert(folded_run == run_linked && !folded_base && !folded_own);
        assert(hardware.live && g->hw && !g->route->linked);
        carried = false;
    }
    /* A group freed while it rides a bridge -- its entry deleted, or the
     * adapter unloading -- folds what its route counted too, into the MFC
     * entry it still holds. */
    {
        struct mr_mfc gone = { .refs = 1 };
        struct ft_mr_group *h = calloc(1, sizeof(*h));
        unsigned folding = folds, withdrawn = withdrawals;

        assert(h);
        h->mfc = &gone;
        h->family = AF_INET;
        h->route = calloc(1, sizeof(*h->route));
        assert(h->route);
        h->route->linked = true;
        h->route->series = 1;
        ft_mr_group_free(h);
        assert(withdrawals == withdrawn + 1 && folds == folding + 1);
        assert(folded.packets == bridged_count.packets && !gone.refs);
    }

    /* ---- a ruleset commit ---------------------------------------------
     *
     * A rule added under a carried group has to stop it, and nothing but the
     * generation says one was. The commit takes every confirmation back and
     * the group returns to software, where the next copy Linux forwards
     * confirms it again under the new rules. */
    {
        unsigned added = adds, deleted = deletes, periods = grace_periods;

        assert(hardware.live && g->state == FT_MR_INSTALLED);
        ft_mr_work.queued = false;
        poll_ruleset();
        assert(!ft_mr_work.queued && ft_mr_ruleset.queued);  /* nothing moved */
        init_net.nft.base_seq++;
        poll_ruleset();
        assert(ft_mr_work.queued);                           /* this did */
        run();
        assert(deletes == deleted + 1 && !hardware.live && !g->offloaded);
        assert(g->state == FT_MR_UNCONFIRMED && !g->watch->seen);
        assert(ft_mr_ruleset_changes == 1 && grace_periods == periods + 1);
        /* Re-admission waits for the ruleset to stand still: a copy while
         * it settles confirms nothing. */
        seen(g, OIF_A);
        assert(!g->watch->seen && !ft_mr_gen_open);
        settle();
        assert(grace_periods == periods + 2 && adds == added);
        seen(g, OIF_A);
        run();
        assert(adds == added + 1 && hardware.live && g->state == FT_MR_INSTALLED);
        /* The cursor the rules are read through moving is a commit as well:
         * the commit moves the counter first, and a pass between the two
         * armed for the pair it read. */
        init_net.nft.gencursor ^= 1;
        run();
        assert(!hardware.live && g->state == FT_MR_UNCONFIRMED);
        assert(ft_mr_ruleset_changes == 2);
        settle();
        /* A copy seen after a commit the worker has not caught up with was
         * judged by rules nothing is armed for: no confirmation, and the
         * worker is woken to re-arm. */
        init_net.nft.base_seq++;
        ft_mr_work.queued = false;
        seen(g, OIF_A);
        assert(!g->watch->seen && ft_mr_work.queued);
        run();
        assert(ft_mr_ruleset_changes == 3 && g->state == FT_MR_UNCONFIRMED);
        /* Another commit while it settles starts the wait again, from the
         * newer ruleset. */
        jiffies += FT_MR_RULESET_SETTLE - 1;
        init_net.nft.base_seq++;
        poll_ruleset();
        run();
        assert(ft_mr_ruleset_changes == 4 && !ft_mr_gen_open);
        assert(ruleset_delay == FT_MR_RULESET_SETTLE);
        /* And one landing in the grace period before it would open leaves
         * it closed; the next pass sees it and starts again. */
        jiffies += ruleset_delay;
        commit_in_grace = true;
        poll_ruleset();
        run();
        assert(!ft_mr_gen_open && ft_mr_ruleset_changes == 4);
        run();
        assert(!ft_mr_gen_open && ft_mr_ruleset_changes == 5);
        /* A commit still applying itself when the second is up -- a
         * large set load -- is not settled however long it takes: looked
         * at again a short while later, and opened only once it is done,
         * after a grace period for the copies it judged half applied. */
        jiffies += ruleset_delay;
        init_net.nft.commit_applying = 1;
        {
            unsigned periods = grace_periods;

            for (unsigned i = 0; i < 3; i++) {
                poll_ruleset();
                run();
                assert(!ft_mr_gen_open && grace_periods == periods);
                assert(ruleset_delay == FT_MR_RULESET_APPLYING);
                jiffies += ruleset_delay;
            }
            init_net.nft.commit_applying = 0;
            poll_ruleset();
            run();
            assert(ft_mr_gen_open && grace_periods == periods + 1);
            assert(ft_mr_ruleset_changes == 5);
        }
        seen(g, OIF_A);
        run();
        assert(hardware.live && g->state == FT_MR_INSTALLED);
    }

    /* ---- a commit between the pass's sync and its admission ------------
     *
     * The derivation runs under RTNL after the worker followed the ruleset,
     * and a commit can land in between. The watch is complete and was made
     * under the ruleset before it, which is no longer the one in force: the
     * group is not carried, and the worker is asked to look again. */
    {
        unsigned deleted = deletes;

        commit_in_derive = true;
        ft_mr_recheck = true;
        run();
        assert(!hardware.live && deletes == deleted + 1);
        assert(g->state == FT_MR_UNCONFIRMED && ft_mr_work.queued);
        run();
        assert(ft_mr_ruleset_changes == 6 && !g->watch->seen);
        settle();
        seen(g, OIF_A);
        run();
        assert(hardware.live && g->state == FT_MR_INSTALLED);
    }

    /* ---- the parent moves ------------------------------------------------
     *
     * An MFC entry replaced with another parent and the same oifs -- a route
     * added again from another inbound interface, an RPF change -- is a
     * stream judged as coming from somewhere else: an iif-keyed forward
     * rule may drop it. Nothing seen from the old parent confirms anything
     * for the new one. */
    {
        unsigned added = adds;

        planned_parent = PARENT_B;
        ft_mr_recheck = true;
        run();
        assert(!hardware.live && g->state == FT_MR_UNCONFIRMED);
        assert(g->watch->parent == PARENT_B && !g->watch->seen);
        seen_from(g, OIF_A, PARENT_A);
        run();
        assert(adds == added && !hardware.live && !g->watch->seen);
        seen(g, OIF_A);
        run();
        assert(adds == added + 1 && hardware.live && g->state == FT_MR_INSTALLED);
        planned_parent = PARENT_A;
        ft_mr_recheck = true;
        run();
        assert(!hardware.live && g->watch->parent == PARENT_A && !g->watch->seen);
        seen(g, OIF_A);
        run();
        assert(hardware.live && g->state == FT_MR_INSTALLED);
    }

    /* ---- a hook after the observer ---------------------------------------
     *
     * An nftables chain or a BPF program that runs after the observer can
     * still drop what it confirmed: the group stays in software while one
     * does, and its confirmations stand for when it goes. */
    {
        observer_followed = true;
        ft_mr_recheck = true;
        run();
        assert(!hardware.live && g->state == FT_MR_REFUSED_FILTER);
        assert(g->watch->seen == 1);
        observer_followed = false;
        ft_mr_recheck = true;
        run();
        assert(hardware.live && g->state == FT_MR_INSTALLED);
    }

    /* ---- a watch that cannot be allocated --------------------------------
     *
     * A changed oif list needs a new watch. Without one nothing describes
     * the list, so nothing admits the group, and /proc counts why. */
    {
        u64 errors = ft_mr_confirm_errors;

        planned_oifs = 2;
        fail_alloc = true;
        ft_mr_recheck = true;
        run();
        fail_alloc = false;
        assert(!g->watch && ft_mr_confirm_errors == errors + 1);
        assert(!hardware.live && g->state == FT_MR_UNCONFIRMED);
        assert(!ft_mr_watch_count[0]);
        planned_oifs = 1;
        ft_mr_recheck = true;
        run();
        assert(g->watch && !g->watch->seen && g->state == FT_MR_UNCONFIRMED);
        seen(g, OIF_A);
        run();
        assert(hardware.live && g->state == FT_MR_INSTALLED);
    }

    /* ---- an oif the firewall drops toward --------------------------------
     *
     * A second oif joins. Linux forwards to the first and never to the
     * second, so no copy is ever seen leaving by it: the group goes back to
     * software, which is the one place the second oif's drop still happens,
     * and stays there however long the stream runs. Allowed, it is carried
     * whole. Its confirmation for the first oif is carried over, not asked
     * again. */
    {
        unsigned added = adds;

        planned_oifs = 2;
        ft_mr_recheck = true;
        run();
        assert(!hardware.live && g->state == FT_MR_UNCONFIRMED);
        assert(g->watch->oifs == 2 && g->watch->seen == 1);
        for (unsigned i = 0; i < 3; i++) {
            seen(g, OIF_A);
            refresh();
        }
        assert(adds == added && !hardware.live && g->state == FT_MR_UNCONFIRMED);
        seen(g, OIF_B);
        run();
        assert(adds == added + 1 && hardware.live && g->state == FT_MR_INSTALLED);
        /* The second oif going keeps the group carried: what is left was
         * all seen. */
        planned_oifs = 1;
        ft_mr_recheck = true;
        run();
        assert(hardware.live && g->state == FT_MR_INSTALLED && g->watch->oifs == 1);
        assert(g->watch->seen == 1);
    }

    /* ---- a copy routed into a bridge -------------------------------------
     *
     * The confirmation is made at the inet POST_ROUTING hook. The bridge's own
     * LOCAL_OUT and POST_ROUTING hooks see the copy after that, so any hook
     * there keeps the group in software, whatever was confirmed. */
    {
        out_bridged = true;
        ft_mr_recheck = true;
        run();
        assert(hardware.live && g->state == FT_MR_INSTALLED);   /* no hook */
        bridge_out_hooked = true;
        ft_mr_recheck = true;
        run();
        assert(!hardware.live && g->state == FT_MR_REFUSED_FILTER);
        assert(!strcmp(ft_mr_state_text(g->state), "refused-filter"));
        bridge_out_hooked = false;
        ft_mr_recheck = true;
        run();
        assert(hardware.live && g->state == FT_MR_INSTALLED);
        out_bridged = false;
    }

    /* Deleting the route while a port it copies out of changes its egress:
     * the change marks the group, and a tc command's drain gets the
     * transaction before the worker's retirement does. The group leaves the
     * list only in the transaction hold that takes its entry out of the
     * hardware, so the drain finds it still listed and rebuilds it; it never
     * answers for an entry it did not see. */
    {
        unsigned deleted = deletes;

        rtnl_lock();
        caller_rtnl = true;
        egress_change(&output[0]);
        caller_rtnl = false;
        rtnl_unlock();
        assert(g->egress_stale && hardware.live);
        g->gone = true;
        drain_first = &output[0];
        drain_first_rc = 1;
        run();
        assert(!drain_first && !drain_first_rc && !drain_first_left_stale);
        assert(deletes == deleted + 1);
    }

    /* Deleting the route leaves no hardware key, port or MFC reference, and
     * no watch: the forwarding check goes with the last group of its
     * family. */
    assert(!hardware.live && !cache.refs && !input.refs);
    assert(!cache.mfc_flags && !ft_mr_count && !ft_mr_installed);
    assert(!ft_mr_watch_count[0] && !confirm_hooked[0]);

    /* ---- IPv6 ------------------------------------------------------------
     *
     * The same admission for ip6mr's entries, in a table and a hook of the
     * family's own. */
    g = calloc(1, sizeof(*g));
    assert(g);
    cache.refs = 1;
    g->mfc = &cache;
    g->family = AF_INET6;
    g->src.all[0] = 0x20010db8;
    g->dst.all[0] = 0xff0e0000;
    g->dst.all[3] = 1;
    g->dirty = true;
    list_add(&g->list, &ft_mr_groups);
    ft_mr_count = 1;
    run();
    assert(!hardware.live && g->state == FT_MR_UNCONFIRMED);
    assert(confirm_hooked[1] && !confirm_hooked[0] && ft_mr_watch_count[1] == 1);
    ft_mr_confirm_seen(AF_INET, &g->src, &g->dst, OIF_A, PARENT_A); /* not this family */
    assert(!g->watch->seen);
    seen(g, OIF_A);
    run();
    assert(hardware.live && g->state == FT_MR_INSTALLED);
    init_net.nft.base_seq++;
    run();
    assert(!hardware.live && g->state == FT_MR_UNCONFIRMED);
    settle();
    seen(g, OIF_A);
    run();
    assert(hardware.live);

    /* ---- the chain speaks while the worker waits for RTNL --------------
     *
     * A VIF goes while the worker, having picked the group, waits for the
     * lock. Nothing is decided against the mirror that VIF is still in: the
     * worker applies what was queued, picks the group again, and decides
     * once, against the chain as it stands. */
    {
        unsigned d0 = derives, a0 = applied;
        unsigned x0 = adds, r0 = replaces, del0 = deletes;

        g->dirty = true;
        speech = SPEAK_VIF;
        speak_while_waiting = 1;
        run();
        assert(!speak_while_waiting && applied == a0 + 1);
        assert(derives == d0 + 1 && !derived_behind);
        assert(adds == x0 && replaces == r0 && deletes == del0);
        assert(hardware.live && g->state == FT_MR_INSTALLED && !g->busy);
        assert(list_empty(&ft_mr_queue));
    }
    /* What was queued need not ask the group again: a VIF in a table this
     * learner does not mirror is applied and touches nothing. The group was
     * handed back undecided, so it is decided in the same run all the same,
     * not left for the refresh five seconds on. */
    {
        unsigned d0 = derives, a0 = applied;

        g->dirty = true;
        speech = SPEAK_OTHER_TABLE;
        speak_while_waiting = 1;
        run();
        assert(!speak_while_waiting && applied == a0 + 1);
        assert(derives == d0 + 1 && !derived_behind);
        assert(!g->dirty && !g->busy && g->state == FT_MR_INSTALLED);
    }
    /* And what cannot change its answer is not waited for: the other
     * family's VIFs, another entry of its own. The group is decided at once,
     * with the event still queued, and the next run applies it. */
    {
        static const enum speech idle[] = { SPEAK_OTHER_FAMILY, SPEAK_OTHER_ENTRY };

        for (unsigned i = 0; i < ARRAY_SIZE(idle); i++) {
            unsigned d0 = derives, a0 = applied, b0 = derived_behind;

            g->dirty = true;
            speech = idle[i];
            speak_while_waiting = 1;
            run();
            assert(!speak_while_waiting && applied == a0);
            assert(derives == d0 + 1 && derived_behind == b0 + 1);
            assert(!list_empty(&ft_mr_queue) && g->state == FT_MR_INSTALLED);
            run();
            assert(applied == a0 + 1 && list_empty(&ft_mr_queue));
        }
        derived_behind = 0;
    }
    /* A chain that never falls quiet delays the decision rather than
     * preventing it: past FT_MR_MAX_RESTARTS the worker decides against a
     * mirror one event behind, and the next run applies that event. */
    {
        unsigned d0 = derives, a0 = applied;

        g->dirty = true;
        speech = SPEAK_VIF;
        speak_while_waiting = FT_MR_MAX_RESTARTS + 1;
        run();
        assert(!speak_while_waiting && applied == a0 + FT_MR_MAX_RESTARTS);
        assert(derives == d0 + 1 && derived_behind == 1);
        assert(!list_empty(&ft_mr_queue) && !g->busy);
        run();
        assert(applied == a0 + FT_MR_MAX_RESTARTS + 1);
        assert(list_empty(&ft_mr_queue) && derived_behind == 1);
        assert(hardware.live && g->state == FT_MR_INSTALLED);
        derived_behind = 0;
    }
    /* An event lost for want of memory while the worker waits asks for a
     * resync and queues nothing. The resync runs before the group is
     * decided, rather than the group going to software for a resync the
     * next pass would have finished. */
    {
        unsigned d0 = derives, s0 = resyncs, del0 = deletes;

        g->dirty = true;
        speech = SPEAK_LOST;
        speak_while_waiting = 1;
        run();
        assert(!speak_while_waiting && resyncs == s0 + 1);
        assert(!ft_mr_resync_pending && derives == d0 + 1);
        assert(deletes == del0 && hardware.live && g->state == FT_MR_INSTALLED);
    }
    /* A resync that cannot finish is tried once a run, not once a wait: the
     * group is refused until it does, as it always was. */
    {
        unsigned s0 = resyncs, del0 = deletes, x0 = adds;

        g->dirty = true;
        resync_fails = true;
        speech = SPEAK_LOST;
        speak_while_waiting = 1;
        run();
        assert(resyncs == s0 + 1 && ft_mr_resync_pending);
        assert(deletes == del0 + 1 && !hardware.live);
        assert(g->state == FT_MR_REFUSED_RESYNC);
        resync_fails = false;
        run();
        assert(resyncs == s0 + 2 && !ft_mr_resync_pending);
        assert(adds == x0 + 1 && hardware.live && g->state == FT_MR_INSTALLED);
    }
    /* An event lost just after a resync finished, once it has let go of
     * RTNL: the family is asked for again, but not by a resync that failed,
     * so it is run again before the group is decided rather than the group
     * refused for it. */
    {
        unsigned s0 = resyncs, del0 = deletes;

        g->dirty = true;
        ft_mr_resync_pending |= 1UL << ft_mr_idx(g->family);
        lost_after_resync = 1;
        run();
        assert(!lost_after_resync && resyncs == s0 + 2 && !ft_mr_resync_pending);
        assert(deletes == del0 && hardware.live && g->state == FT_MR_INSTALLED);
    }
    /* Multicast acceleration switched off: the group is refused as paused
     * and its entry comes out; back on, it is carried again at once, its
     * confirmations kept. The switch is checked again inside the transaction,
     * after the contract was answered: turned off between the two, neither a
     * replace nor an add lands, so a stop that has read nothing installed
     * under the transaction never finds an entry appear after. */
    {
        unsigned x0 = adds, r0 = replaces, del0 = deletes;

        ft_mc_enabled = false;
        ft_mr_recheck = true;
        run();
        assert(deletes == del0 + 1 && !hardware.live && !g->offloaded);
        assert(g->state == FT_MR_REFUSED_PAUSED && ft_mr_refusal(g->state));
        assert(!strcmp(ft_mr_state_text(g->state), "refused-paused"));
        ft_mc_enabled = true;
        ft_mr_recheck = true;
        run();
        assert(adds == x0 + 1 && hardware.live && g->state == FT_MR_INSTALLED);
        g->dirty = true;
        wanted = 2;
        switch_in_derive = true;
        run();
        wanted = 1;
        assert(!switch_in_derive && !ft_mc_enabled && replaces == r0);
        assert(deletes == del0 + 2 && !hardware.live && g->state == FT_MR_REFUSED_PAUSED);
        ft_mc_enabled = true;
        g->dirty = true;
        switch_in_derive = true;
        run();
        assert(adds == x0 + 1 && !hardware.live && g->state == FT_MR_REFUSED_PAUSED);
        ft_mc_enabled = true;
        ft_mr_recheck = true;
        run();
        assert(adds == x0 + 2 && hardware.live && g->state == FT_MR_INSTALLED);
    }
    /* The entry the worker picked is deleted while it waits: it is retired
     * from hardware, and nothing is built for an entry ipmr no longer has --
     * here a second listener it would otherwise have been replaced with. */
    {
        unsigned d0 = derives, x0 = adds, r0 = replaces, del0 = deletes;

        g->dirty = true;
        wanted = 2;
        speech = SPEAK_DELETE;
        speak_while_waiting = 1;
        run();
        speech = SPEAK_VIF;
        wanted = 1;
        assert(derives == d0 && adds == x0 && replaces == r0);
        assert(deletes == del0 + 1 && !hardware.live);
        assert(!ft_mr_count && !ft_mr_installed && !ft_mr_watch_count[1]);
        assert(!cache.refs && !cache.mfc_flags && !input.refs);
        assert(!output[0].refs && !output[1].refs);
    }
    /* And back, for teardown to find something to release. */
    g = calloc(1, sizeof(*g));
    assert(g);
    cache.refs = 1;
    g->mfc = &cache;
    g->family = AF_INET6;
    g->src.all[0] = 0x20010db8;
    g->dst.all[0] = 0xff0e0000;
    g->dst.all[3] = 1;
    g->dirty = true;
    list_add(&g->list, &ft_mr_groups);
    ft_mr_count = 1;
    run();
    assert(g->state == FT_MR_UNCONFIRMED);
    seen(g, OIF_A);
    run();
    assert(hardware.live && g->state == FT_MR_INSTALLED);

    /* Stop with a timer/worker rearm in flight, and release every owner --
     * folding what the entry counted since the last fold into the MFC entry
     * before it is deleted, as the worker's own deletes do: the entry
     * outlives the adapter. */
    simulate_rearm = true;
    unsigned exiting = folds;
    hw_count = (struct cdx_ft_counters){ 3, 3 * 100 };
    ft_mr_exit();
    assert(folds == exiting + 1 && folded.packets == 3 && folded_live && folded_own);
    hw_count = (struct cdx_ft_counters){ 0, 0 };
    /* The producers, the worker, then again whatever the worker rearmed. */
    assert(!strcmp(cancels, "srwsr") && !ft_mr_work.queued && !ft_mr_stats.queued);
    assert(!ft_mr_ruleset.queued && !confirm_hooked[0] && !confirm_hooked[1]);
    assert(!ft_mr_watch_count[0] && !ft_mr_watch_count[1]);
    assert(!hardware.live && !cache.refs && !cache.mfc_flags);
    assert(!input.refs && !output[0].refs && !output[1].refs);
    assert(!ft_mr_count && !ft_mr_installed);
    assert(ft_mr_groups.next == &ft_mr_groups);
    puts("routed refresh, failure fallback, retry and teardown scenarios passed");
    return 0;
}
