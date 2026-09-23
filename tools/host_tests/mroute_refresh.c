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
struct cdx_mc_group { bool live; unsigned copies; };
struct cdx_ft_counters { u64 packets, bytes; };
struct work_struct { bool queued; };
#include "mroute_types.inc"
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
static unsigned cancel_step;
static bool simulate_rearm;
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
    assert(ft_mr_stopping);
    assert(cancel_step == 0 || cancel_step == 2);
    cancel_step++;
    w->queued = false;
}
static void cancel_work_sync(struct work_struct *w)
{
    assert(cancel_step++ == 1);
    w->queued = false;
    /* A worker already past its stopping check can rearm during the drain. */
    if (simulate_rearm)
        schedule_delayed_work(&ft_mr_stats, FT_MR_STATS_INTERVAL);
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
static bool ft_mr_apply(struct ft_mr_event *e) { abort(); }
static void ft_mr_lost_event(u8 family) { abort(); }
static void ft_mr_event_free(struct ft_mr_event *e) { abort(); }
static void ft_mr_resync(void) { abort(); }
static enum ft_mr_state ft_mr_derive(struct ft_mr_group *g, struct ft_mr_plan *p)
{
    assert(rtnl);
    derives++;
    if (refuse) return FT_MR_REFUSED_LISTENER;
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
    hardware.live = true;
    hardware.copies = s->listeners;
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
    deletes++;
    (*hw)->live = false;
    *hw = NULL;
}
static void cdx_mc_group_stats(struct cdx_mc_group *hw, struct cdx_ft_counters *c)
{ assert(ctrl && hw->live); memset(c, 0, sizeof(*c)); }
static unsigned folded_tags;
static struct cdx_ft_counters folded;
static void ft_mr_fold(struct ft_mr_group *g, const struct cdx_ft_counters *c, u8 tags)
{ folds++; folded = *c; folded_tags = tags; }
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
    assert(adds == 1 && hardware.live && ft_mr_installed == 1);
    assert(g->offloaded && cache.mfc_flags == MFC_OFFLOAD);
    assert(input.refs == 1 && output[0].refs == 1);
    for (unsigned i = 0; i < 20; i++) refresh();
    assert(adds == 1 && replaces == 0 && deletes == 0);
    assert(derives == 21 && folds == 20 && input.refs == 1);

    /* A router appeared, then disappeared. Refreshed chains carry exact sets. */
    wanted = 2;
    ft_mr_recheck = true;
    run();
    assert(replaces == 1 && hardware.copies == 2 && output[1].refs == 1);
    wanted = 1;
    refresh();
    assert(replaces == 2 && hardware.copies == 1 && output[1].refs == 0);

    /* Exhaustion must not retain a subset and report offload forever. */
    wanted = 2;
    fail_replace = fail_add = true;
    refresh();
    assert(replaces == 3 && deletes == 1 && !hardware.live);
    assert(!g->hw && !g->offloaded);
    assert(!cache.mfc_flags && !ft_mr_installed);
    assert(!input.refs && !output[0].refs && !output[1].refs);
    assert(g->state == FT_MR_REFUSED_FAILED && g->retries == FT_MR_MAX_RETRIES);
    unsigned before = adds;
    refresh();
    assert(adds == before); /* timer cannot evade the bounded retry policy */
    fail_replace = fail_add = false;
    ft_mr_recheck = true;
    run();
    assert(hardware.live && hardware.copies == 2 && g->offloaded);

    /* An uncarriable router withdraws the whole chain. A timer discovers
     * restored eligibility even while no group is installed. */
    refuse = true;
    refresh();
    assert(!hardware.live && !ft_mr_installed && !input.refs);
    refuse = false;
    refresh();
    assert(hardware.live && hardware.copies == 2 && g->offloaded);

    /* A router netdev unregisters: release its borrowed plan references
     * synchronously, then rederive without it and retire the stale root. */
    rtnl_lock();
    ft_mr_device_gone(&output[1]);
    rtnl_unlock();
    assert(!input.refs && !output[0].refs && !output[1].refs);
    assert(!ft_mr_taps_stale);   /* a port: the VIFs on bridges stand */
    wanted = 1;
    run();
    assert(hardware.live && hardware.copies == 1 && output[0].refs == 1);

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
        /* The parent moving back to a port takes the route back. */
        through_bridge = false;
        ft_mr_recheck = true;
        run();
        assert(withdrawals == withdrawn + 1 && !g->route->linked);
        assert(hardware.live && g->hw && g->state == FT_MR_INSTALLED);
        assert(!bridge.refs && g->via == NULL);
    }

    /* Deleting the route leaves no hardware key, port or MFC reference. */
    g->gone = true;
    run();
    assert(!hardware.live && !cache.refs && !input.refs);
    assert(!cache.mfc_flags && !ft_mr_count && !ft_mr_installed);
    g = calloc(1, sizeof(*g));
    assert(g);
    cache.refs = 1;
    g->mfc = &cache;
    g->family = AF_INET;
    g->dirty = true;
    list_add(&g->list, &ft_mr_groups);
    ft_mr_count = 1;
    run();
    assert(hardware.live);

    /* Stop with a timer/worker rearm in flight, and release every owner. */
    simulate_rearm = true;
    ft_mr_exit();
    assert(cancel_step == 3 && !ft_mr_work.queued && !ft_mr_stats.queued);
    assert(!hardware.live && !cache.refs && !cache.mfc_flags);
    assert(!input.refs && !output[0].refs && !output[1].refs);
    assert(!ft_mr_count && !ft_mr_installed);
    assert(ft_mr_groups.next == &ft_mr_groups);
    puts("routed refresh, failure fallback, retry and teardown scenarios passed");
    return 0;
}
