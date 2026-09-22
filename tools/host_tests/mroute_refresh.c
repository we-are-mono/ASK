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
#define kfree free
#define strscpy(d, s, n) snprintf(d, n, "%s", s)
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
struct list_head { struct list_head *next, *prev; };
#define LIST_HEAD(n) struct list_head n = { &n, &n }
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
struct net_device { unsigned refs; };
struct mr_mfc { int mfc_flags; unsigned refs; };
union nf_inet_addr { u32 all[4]; };
struct cdx_ft_vlan { u16 proto, id; };
struct cdx_mc_listener { struct net_device *dev; struct cdx_ft_vlan vlan[2]; u8 vlans; };
struct cdx_mc_group_spec {
    struct net_device *in;
    struct cdx_mc_listener listener[8];
    u8 listeners, family;
    union nf_inet_addr src, dst;
};
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
static bool ft_mr_stopping, ft_mr_recheck, claimed;
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
static int ft_mc_claim_take(u8 family, const union nf_inet_addr *s,
                            const union nf_inet_addr *d)
{
    if (claimed) return -EEXIST;
    claimed = true; return 0;
}
static void ft_mc_claim_give(u8 family, const union nf_inet_addr *s,
                            const union nf_inet_addr *d)
{ assert(claimed); claimed = false; }
static bool ft_mr_apply(struct ft_mr_event *e) { abort(); }
static void ft_mr_lost_event(u8 family) { abort(); }
static void ft_mr_event_free(struct ft_mr_event *e) { abort(); }
static void ft_mr_resync(void) { abort(); }
static enum ft_mr_state ft_mr_derive(struct ft_mr_group *g, struct ft_mr_plan *p)
{
    assert(rtnl);
    derives++;
    if (refuse) return FT_MR_REFUSED_LISTENER;
    p->spec.in = &input;
    dev_hold(&input);
    p->spec.listeners = wanted;
    for (unsigned i = 0; i < wanted; i++) {
        p->spec.listener[i].dev = &output[i];
        dev_hold(&output[i]);
    }
    return FT_MR_PENDING;
}
static int cdx_mc_group_add(const struct cdx_mc_group_spec *s, struct cdx_mc_group **hw)
{
    assert(ctrl && !hardware.live && claimed);
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
static void ft_mr_fold(struct ft_mr_group *g, const struct cdx_ft_counters *c)
{ folds++; }
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
    assert(!g->hw && !g->claimed && !claimed && !g->offloaded);
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
    assert(!hardware.live && !ft_mr_installed && !input.refs && !claimed);
    refuse = false;
    refresh();
    assert(hardware.live && hardware.copies == 2 && g->offloaded);

    /* A router netdev unregisters: release its borrowed plan references
     * synchronously, then rederive without it and retire the stale root. */
    rtnl_lock();
    ft_mr_device_gone(&output[1]);
    rtnl_unlock();
    assert(!input.refs && !output[0].refs && !output[1].refs);
    wanted = 1;
    run();
    assert(hardware.live && hardware.copies == 1 && output[0].refs == 1);

    /* Deleting the route leaves no hardware key, port or MFC reference. */
    g->gone = true;
    run();
    assert(!hardware.live && !claimed && !cache.refs && !input.refs);
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
    assert(!hardware.live && !claimed && !cache.refs && !cache.mfc_flags);
    assert(!input.refs && !output[0].refs && !output[1].refs);
    assert(!ft_mr_count && !ft_mr_installed);
    assert(ft_mr_groups.next == &ft_mr_groups);
    puts("routed refresh, failure fallback, retry and teardown scenarios passed");
    return 0;
}
