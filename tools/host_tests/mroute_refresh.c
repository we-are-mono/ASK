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
#define AF_INET 2
#define AF_INET6 10
#define MAXVIFS 32
#define FT_MR_OIF_TEXT 136
#define CDX_MC_MAX_LISTENERS 8
#define FT_MR_MAX_RETRIES 4
#define FT_MR_STATS_INTERVAL 5
#define MFC_OFFLOAD 1
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
#define smp_load_acquire(p) (*(p))
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define min(a, b) ((a) < (b) ? (a) : (b))
#define kzalloc(n, f) calloc(1, (n))
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
/* The listener and group descriptions are the header's own, extracted into
 * the generated include, so a field added there is one the worker here has. */
#include "mroute_backend.inc"
/* `in` is the ingress the backend borrows and deletes through. */
struct cdx_mc_group { bool live; unsigned copies; struct net_device *in; };
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
static unsigned grace_periods;
static void synchronize_rcu(void) { grace_periods++; }
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
static struct { struct { unsigned int base_seq; u8 gencursor; } nft; } init_net;
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
#include "mroute_confirm_types.inc"
static LIST_HEAD(ft_mr_groups);
static LIST_HEAD(ft_mr_queue);
static int ft_mr_lock, ft_mr_queue_lock, rtnl, ctrl;
static struct ft_mr_vif ft_mr_vif[2][MAXVIFS];
static unsigned ft_mr_count, ft_mr_installed, ft_mr_policy[2];
static u64 ft_mr_refused, ft_mr_install_errors;
static bool ft_mr_stopping, ft_mr_recheck, ft_mr_key_freed, ft_mr_taps_stale;
static bool ft_mr_ready;
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
/* The MFC oifs the derivation names, by ifindex, and whether a copy leaves
 * through a bridge. */
enum { OIF_A = 31, OIF_B = 32 };
static int planned[2] = { OIF_A, OIF_B };
static unsigned planned_oifs = 1;
static bool out_bridged;
static void mutex_lock(int *m) { assert(!*m); *m = 1; }
static void mutex_unlock(int *m) { assert(*m); *m = 0; }
#define spin_lock_bh mutex_lock
#define spin_unlock_bh mutex_unlock
static void rtnl_lock(void) { assert(!rtnl && !ctrl && !ft_mr_lock); rtnl = 1; }
static void rtnl_unlock(void) { assert(rtnl); rtnl = 0; }
static void cdx_ft_begin(void) { assert(!rtnl && !ctrl && !ft_mr_lock); ctrl = 1; }
static void cdx_ft_end(void) { assert(ctrl); ctrl = 0; }
static void dev_hold(struct net_device *d) { d->refs++; }
static void dev_put(struct net_device *d) { assert(d->refs); d->refs--; }
static void mr_cache_put(struct mr_mfc *c) { assert(c->refs); c->refs--; }
static void schedule_work(struct work_struct *w) { w->queued = true; }
static void schedule_delayed_work(struct work_struct *w, unsigned delay)
{ w->queued = true; }
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
    r->linked = true;
    r->carried = carried;
    return carried;
}
static void ft_mc_route_withdraw(struct ft_mc_route *r)
{
    bridged_side();
    withdrawals++;
    r->linked = false;
    r->carried = false;
}
static bool ft_mc_route_state(struct ft_mc_route *r, struct cdx_ft_counters *stats,
                              u8 *in_tags)
{
    assert(ft_mr_lock);   /* a leaf lock, readable under this learner's */
    *stats = bridged_count;
    *in_tags = 1;
    return r->carried;
}
static void ft_mr_publish_taps(void) { bridged_side(); taps_published++; }
/* The generation ft_mc_egress_changed() bumps before it marks anything; the
 * add below can bump it mid-build, which is the race it exists for. */
typedef struct { int counter; } atomic_t;
static atomic_t ft_mc_egress_gen;
static int atomic_read(const atomic_t *a) { return a->counter; }
static bool queues_move_during_add;
static bool ft_mr_apply(struct ft_mr_event *e) { abort(); }
static void ft_mr_lost_event(u8 family) { abort(); }
static void ft_mr_event_free(struct ft_mr_event *e) { abort(); }
static void ft_mr_resync(void) { abort(); }
static enum ft_mr_state ft_mr_derive(struct ft_mr_group *g, struct ft_mr_plan *p)
{
    assert(rtnl);
    derives++;
    if (refuse) return FT_MR_REFUSED_LISTENER;
    /* The oif walk, which a refusal above never reached. */
    for (unsigned i = 0; i < planned_oifs; i++)
        p->oif[p->oif_count++] = planned[i];
    p->oifs_known = true;
    p->out_bridged = out_bridged;
    if (through_bridge) {
        p->via = &bridge;
        p->via_vid = 289;
        p->via_tagged = true;
        p->mtu = 1500;
        dev_hold(&bridge);
    } else {
        p->spec.in = &input;
        dev_hold(&input);
    }
    p->spec.listeners = wanted;
    for (unsigned i = 0; i < wanted; i++) {
        p->spec.listener[i].dev = &output[i];
        p->spec.listener[i].routed = true;
        dev_hold(&output[i]);
    }
    return FT_MR_PENDING;
}
static int cdx_mc_group_add(const struct cdx_mc_group_spec *s, struct cdx_mc_group **hw)
{
    assert(ctrl && !hardware.live && s->in);
    adds++;
    if (fail_add) return -ENOMEM;
    if (queues_move_during_add) {
        queues_move_during_add = false;
        ft_mc_egress_gen.counter++;
    }
    hardware.live = true;
    hardware.copies = s->listeners;
    hardware.in = s->in;
    *hw = &hardware;
    return 0;
}
static int cdx_mc_group_replace(struct cdx_mc_group *hw, const struct cdx_mc_group_spec *s)
{
    assert(ctrl && hw->live);
    replaces++;
    if (fail_replace) return -ENOMEM;  /* backend keeps the previous chain */
    hw->copies = s->listeners;
    return 0;
}
static void cdx_mc_group_del(struct cdx_mc_group **hw)
{
    assert(ctrl && *hw && (*hw)->live);
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
static unsigned folded_tags;
static struct cdx_ft_counters folded;
static void ft_mr_fold(struct ft_mr_group *g, const struct cdx_ft_counters *c, u8 tags)
{ folds++; folded = *c; folded_tags = tags; }
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
 * the hook reports it. */
static void seen(const struct ft_mr_group *g, int ifindex)
{
    ft_mr_confirm_seen(g->family, &g->src, &g->dst, ifindex);
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
     * stream to its oif. The confirmations are armed for the ruleset in
     * force -- one grace period each side of reading it -- the group is
     * watched, and the forwarding check is registered for its family. */
    assert(!adds && !hardware.live && g->state == FT_MR_UNCONFIRMED);
    assert(!strcmp(ft_mr_state_text(g->state), "pending-confirm"));
    assert(!ft_mr_refusal(g->state) && !g->offloaded);
    assert(ft_mr_gen_open && grace_periods == 2 && !ft_mr_ruleset_changes);
    assert(g->watch && g->watch->oifs == 1 && g->watch->oif[0] == OIF_A);
    assert(confirm_hooked[0] && !confirm_hooked[1] && ft_mr_ruleset.queued);
    /* A copy to another interface, or of another group, is not this one. */
    {
        union nf_inet_addr other = { .all = { 1 } };

        ft_mr_work.queued = false;
        seen(g, OIF_B);
        ft_mr_confirm_seen(AF_INET, &other, &g->dst, OIF_A);
        ft_mr_confirm_seen(AF_INET6, &g->src, &g->dst, OIF_A);
        assert(!g->watch->seen && !ft_mr_work.queued);
    }
    /* Its own oif: the worker is woken, asks again, and carries it. */
    seen(g, OIF_A);
    assert(g->watch->seen == 1 && g->watch->news && ft_mr_work.queued);
    run();
    assert(adds == 1 && hardware.live && ft_mr_installed == 1);
    assert(g->offloaded && cache.mfc_flags == MFC_OFFLOAD && !g->watch->news);
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

    /* A router appeared, then disappeared. Refreshed chains carry exact sets. */
    wanted = 2;
    ft_mr_recheck = true;
    run();
    assert(replaces == 1 && hardware.copies == 2 && output[1].refs == 1);
    wanted = 1;
    refresh();
    assert(replaces == 2 && hardware.copies == 1 && output[1].refs == 0);

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

    /* A router netdev unregisters: release its borrowed plan references
     * synchronously, then rederive without it and retire the stale root. The
     * entry keeps its own hold on the ingress until it is deleted. */
    rtnl_lock();
    ft_mr_device_gone(&output[1]);
    rtnl_unlock();
    assert(input.refs == 1 && !output[0].refs && !output[1].refs);
    assert(!ft_mr_taps_stale);   /* a port: the VIFs on bridges stand */
    wanted = 1;
    run();
    assert(hardware.live && hardware.copies == 1 && output[0].refs == 1);
    assert(input.refs == 2);

    /* The ingress itself unregisters. The group lets go of its reference at
     * once; the entry, which the delete goes through, keeps its own until
     * the worker takes it out of hardware -- and then lets go too. */
    rtnl_lock();
    ft_mr_device_gone(&input);
    rtnl_unlock();
    assert(input.refs == 1 && hardware.live && g->hw_in == &input);
    refuse = true;               /* the plan has no ingress to name any more */
    run();
    assert(!hardware.live && !input.refs && !g->hw_in);
    refuse = false;
    ft_mr_recheck = true;
    run();
    assert(hardware.live && input.refs == 2);

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
        g = h;
        cache = other;
        g->mfc = &cache;
    }

    /* A port the group copies out of changes its egress queues. The plan is
     * the same, which the worker would skip; the chain names the old queues,
     * so it is replaced all the same, and only for a group copying out of
     * that port. */
    {
        unsigned replaced = replaces;

        assert(ft_mr_egress_mark(&input) == 0 && !g->rebuild);
        assert(ft_mr_egress_mark(&output[0]) == 1);
        assert(g->rebuild && g->dirty && ft_mr_work.queued);
        assert(!ft_mr_lock);
        run();
        assert(replaces == replaced + 1 && hardware.live && !g->rebuild);
        assert(g->state == FT_MR_INSTALLED && g->offloaded);
        /* And nothing more on the next pass: the plan is the same again. */
        ft_mr_recheck = true;
        run();
        assert(replaces == replaced + 1);
    }

    /* The queues move while a chain is being built from the old ones, and
     * the group, taken off its hardware for the build, was not there to be
     * marked. The generation it was built under says so, and it is built
     * again in the same pass. */
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
        assert(hardware.live && !g->rebuild && !g->dirty);
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
        /* And stops carrying it. */
        carried = false;
        ft_mr_recheck = true;
        run();
        assert(g->state == FT_MR_BRIDGED && !g->offloaded && !cache.mfc_flags);
        folding = folds;
        refresh();
        assert(folds == folding);
        /* Its copies are the bridged group's, rebuilt by the other half. */
        assert(ft_mr_egress_mark(&output[0]) == 0 && !g->rebuild);
        /* The parent moving back to a port takes the route back. */
        through_bridge = false;
        ft_mr_recheck = true;
        run();
        assert(withdrawals == withdrawn + 1 && !g->route->linked);
        assert(hardware.live && g->hw && g->state == FT_MR_INSTALLED);
        assert(!bridge.refs && g->via == NULL);
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
        ft_mr_ruleset.queued = false;
        ft_mr_ruleset_fn(&ft_mr_ruleset);
        assert(!ft_mr_work.queued && ft_mr_ruleset.queued);  /* nothing moved */
        init_net.nft.base_seq++;
        ft_mr_ruleset_fn(&ft_mr_ruleset);
        assert(ft_mr_work.queued);                           /* this did */
        run();
        assert(deletes == deleted + 1 && !hardware.live && !g->offloaded);
        assert(g->state == FT_MR_UNCONFIRMED && !g->watch->seen);
        assert(ft_mr_ruleset_changes == 1 && grace_periods == periods + 2);
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
        /* A copy seen after a commit the worker has not caught up with was
         * judged by rules nothing is armed for: no confirmation, and the
         * worker is woken to re-arm. */
        init_net.nft.base_seq++;
        ft_mr_work.queued = false;
        seen(g, OIF_A);
        assert(!g->watch->seen && ft_mr_work.queued);
        run();
        assert(ft_mr_ruleset_changes == 3 && g->state == FT_MR_UNCONFIRMED);
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

    /* Deleting the route leaves no hardware key, port or MFC reference, and
     * no watch: the forwarding check goes with the last group of its
     * family. */
    g->gone = true;
    run();
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
    ft_mr_confirm_seen(AF_INET, &g->src, &g->dst, OIF_A);     /* not this family */
    assert(!g->watch->seen);
    seen(g, OIF_A);
    run();
    assert(hardware.live && g->state == FT_MR_INSTALLED);
    init_net.nft.base_seq++;
    run();
    assert(!hardware.live && g->state == FT_MR_UNCONFIRMED);
    seen(g, OIF_A);
    run();
    assert(hardware.live);

    /* Stop with a timer/worker rearm in flight, and release every owner. */
    simulate_rearm = true;
    ft_mr_exit();
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
