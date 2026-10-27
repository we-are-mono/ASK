/* The tc sample's worker (cdx/ask_flowtable_tc.c), compiled whole from the
 * production source over stub devices: what it publishes, which installed
 * directions it retires, and what it tells the bridged learner as a device's
 * answer tightens or loosens. tc itself is a per-device answer a case sets;
 * mroute_tc.c tests the walk that gives it. */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8;
typedef long long atomic64_t;
#define BIT(n) (1U << (n))
/* FT_TC_* and CDX_POLICE_*, as the adapter's headers define them. */
#include "tc_sample_bits.inc"
#define HZ 100
#define GFP_KERNEL 0
#define READ_ONCE(x) (x)
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define struct_size(p, member, n) (sizeof(*(p)) + (n) * sizeof((p)->member[0]))

/* ---- RCU and RTNL --------------------------------------------------------
 *
 * Readers here run on the one thread, so a published pointer is freed at
 * once; ASan catches a reader that kept one. */
#define __rcu
struct rcu_head { int unused; };
static int rcu_depth;
static void rcu_read_lock(void) { rcu_depth++; }
static void rcu_read_unlock(void) { assert(rcu_depth > 0); rcu_depth--; }
#define rcu_dereference(p) ({ assert(rcu_depth > 0); (p); })
#define rcu_dereference_protected(p, c) (p)
#define rcu_access_pointer(p) (p)
#define RCU_INIT_POINTER(p, v) ((p) = (v))
#define rcu_assign_pointer(p, v) ({ assert(rtnl); (p) = (v); })
#define kfree_rcu(p, f) free(p)
static bool rtnl;
static void rtnl_lock(void) { assert(!rtnl); rtnl = true; }
static void rtnl_unlock(void) { assert(rtnl); rtnl = false; }

static bool alloc_fails;
static void *kzalloc(size_t size, int gfp)
{
    (void)gfp;
    return alloc_fails ? NULL : calloc(1, size);
}

/* ---- devices --------------------------------------------------------------
 *
 * What tc runs on each, as FT_TC_* bits a case sets: the plain answer each
 * way, and the routed ones on the way in, each narrower than the plain one. */
struct net_device { char name[16]; int ifindex; unsigned answer; };
struct net { int unused; };
static struct net init_net;
static struct net_device wan = { .name = "eth4", .ifindex = 4 },
                         lan = { .name = "eth3", .ifindex = 3 },
                         ppp = { .name = "pppoe-wan", .ifindex = 9 };
static struct net_device *devices[] = { &wan, &lan, &ppp };
#define for_each_netdev(net, d) \
    for (unsigned _n = 0; (void)(net), _n < sizeof(devices) / sizeof(devices[0]) && \
         ((d) = devices[_n]); _n++)
static const char *netdev_name(const struct net_device *dev) { return dev->name; }

static unsigned reports;
static char report[256];
#define pr_info(...) (snprintf(report, sizeof(report), __VA_ARGS__), reports++)

/* ---- locks ----------------------------------------------------------------
 *
 * The ones a tc walk must never run under: the watch lock the retire scan
 * takes, and the learner's, which the stubs below take as the real ones do. */
static int ft_watch_lock, ft_l2_lock;
static void spin_lock_bh(int *lock) { assert(!*lock); *lock = 1; }
static void spin_unlock_bh(int *lock) { assert(*lock); *lock = 0; }

static unsigned walks;
static void walked(void)
{
    assert(rtnl && !ft_watch_lock && !ft_l2_lock && !rcu_depth);
    walks++;
}

/* ---- what the worker calls ----------------------------------------------- */

struct work_struct { int unused; };
struct delayed_work {
    struct work_struct work;
    void (*fn)(struct work_struct *);
    bool queued, disabled;
    unsigned long delay;
};
#define DECLARE_DELAYED_WORK(n, f) struct delayed_work n = { .fn = f }
static int unbound;
static int *const system_unbound_wq = &unbound;
static bool queue_delayed_work(int *wq, struct delayed_work *w, unsigned long delay)
{
    assert(wq == system_unbound_wq);
    if (w->disabled || w->queued)
        return false;
    w->queued = true;
    w->delay = delay;
    return true;
}
static bool mod_delayed_work(int *wq, struct delayed_work *w, unsigned long delay)
{
    assert(wq == system_unbound_wq);
    if (w->disabled)
        return false;
    w->queued = true;
    w->delay = delay;
    return true;
}
static bool disable_delayed_work_sync(struct delayed_work *w)
{
    bool was = w->queued;

    w->disabled = true;
    w->queued = false;
    return was;
}

bool ft_dev_tc_soft(struct net_device *dev, bool ingress);
bool ft_dev_tc_soft_routed(struct net_device *dev, unsigned int reach);
bool ft_dev_tc_soft(struct net_device *dev, bool ingress)
{
    walked();
    return dev->answer & (ingress ? FT_TC_RX : FT_TC_TX);
}
bool ft_dev_tc_soft_routed(struct net_device *dev, unsigned int reach)
{
    walked();
    assert(reach == CDX_POLICE_L4 || reach == CDX_POLICE_ESP);
    return dev->answer & (reach == CDX_POLICE_L4 ? FT_TC_RX_L4 : FT_TC_RX_ESP);
}

/* Installed directions, each leaving by one device, which the sample keeps
 * out while that device runs tc on what it sends. */
struct list_head { struct list_head *next, *prev; };
#define list_for_each_entry(pos, head, member) \
    for (pos = container_of((head)->next, __typeof__(*pos), member); \
         &pos->member != (head); \
         pos = container_of(pos->member.next, __typeof__(*pos), member))
struct cdx_ft_rule { const struct net_device *out; };
struct nf_flow_offload_handle { bool invalid; };
struct cdx_ft_entry {
    struct cdx_ft_rule rule;
    struct nf_flow_offload_handle *handle;
    struct list_head neigh_list;
};
static struct list_head ft_neigh_entries = { &ft_neigh_entries, &ft_neigh_entries };
static atomic64_t ft_tc_invalidations;
u8 ft_tc_dev_bits(const struct net_device *dev);
bool ft_rule_tc_soft(const struct cdx_ft_rule *rule);
bool ft_rule_tc_soft(const struct cdx_ft_rule *rule)
{
    return ft_tc_dev_bits(rule->out) & FT_TC_TX;
}
static void ft_handle_invalidate(struct nf_flow_offload_handle *handle, atomic64_t *counter)
{
    assert(ft_watch_lock);
    handle->invalid = true;
    (*counter)++;
}

/* The bridged learner, as the worker reaches it: both take its lock and let
 * it go, and walk no tc. */
static bool ft_bound, paired;
static const struct net_device *changed_dev[4];
static unsigned devs_changed, refusal_resets, mc_kicks, mr_kicks;
bool ft_l2_paired(void);
void ft_l2_dev_changed(const struct net_device *dev);
void ft_l2_refusals_reset(void);
void ft_mc_kick_all(void);
void ft_mr_kick(void);
bool ft_l2_paired(void) { return paired; }
void ft_l2_dev_changed(const struct net_device *dev)
{
    spin_lock_bh(&ft_l2_lock);
    assert(devs_changed < 4);
    changed_dev[devs_changed++] = dev;
    spin_unlock_bh(&ft_l2_lock);
}
void ft_l2_refusals_reset(void)
{
    spin_lock_bh(&ft_l2_lock);
    refusal_resets++;
    spin_unlock_bh(&ft_l2_lock);
}
void ft_mc_kick_all(void) { mc_kicks++; }
void ft_mr_kick(void) { mr_kicks++; }

#include "tc_sample.inc"

/* ---- cases ---------------------------------------------------------------- */

static struct nf_flow_offload_handle up_handle, down_handle;
static struct cdx_ft_entry upload = { .rule = { &wan }, .handle = &up_handle },
                           download = { .rule = { &lan }, .handle = &down_handle };

static void install(struct cdx_ft_entry *e)
{
    e->handle->invalid = false;
    e->neigh_list.next = &ft_neigh_entries;
    e->neigh_list.prev = ft_neigh_entries.prev;
    ft_neigh_entries.prev->next = &e->neigh_list;
    ft_neigh_entries.prev = &e->neigh_list;
}

/* One pass of the worker, as the workqueue runs it once queued, with the
 * counters a case reads cleared first. */
static void pass(void)
{
    assert(ft_tc_work.queued);
    ft_tc_work.queued = false;
    devs_changed = refusal_resets = mc_kicks = mr_kicks = reports = walks = 0;
    ft_tc_work.fn(&ft_tc_work.work);
    assert(!rtnl && !rcu_depth && !ft_watch_lock && !ft_l2_lock);
}

static bool changed(const struct net_device *dev)
{
    for (unsigned i = 0; i < devs_changed; i++)
        if (changed_dev[i] == dev)
            return true;
    return false;
}

int main(void)
{
    const unsigned tx = FT_TC_TX, rx = FT_TC_RX, l4 = FT_TC_RX_L4, esp = FT_TC_RX_ESP;
    atomic64_t retired;

    /* Nothing could use an answer: none is taken, nothing is known, and
     * nothing asks again until a binding does. */
    ft_tc_kick();
    pass();
    assert(!walks && !ft_tc_known() && !ft_tc_any() && !ft_tc_work.queued);

    /* A binding: every device asked under RTNL alone, the ones with
     * something to say published, by pointer and by index, and the next
     * pass queued a second on. */
    ft_bound = true;
    wan.answer = rx | esp;
    ft_tc_kick();
    pass();
    assert(walks && ft_tc_known() && ft_tc_any());
    assert(ft_tc_dev_bits(&wan) == (rx | esp) && ft_tc_index_bits(wan.ifindex) == (rx | esp));
    assert(!ft_tc_dev_bits(&lan) && !ft_tc_index_bits(lan.ifindex) && !ft_tc_dev_bits(NULL));
    assert(ft_tc_work.queued && ft_tc_work.delay == FT_TC_INTERVAL);
    /* Against no sample at all, any answer is a tighter one. */
    assert(changed(&wan) && devs_changed == 1 && !refusal_resets && reports);

    /* Unchanged: nothing said, nothing retired, nobody woken. */
    install(&upload);
    install(&download);
    pass();
    assert(!reports && !devs_changed && !refusal_resets && !mc_kicks && !mr_kicks);
    assert(!up_handle.invalid && !down_handle.invalid);

    /* cake at the WAN root: the answer tightens. The upload, which leaves
     * by the WAN port, is retired and counted; the download is not. Every
     * bridged pair through the port is retired and asked again, and both
     * multicast learners woken. */
    wan.answer = tx | rx | esp;
    retired = ft_tc_invalidations;
    pass();
    assert(up_handle.invalid && !down_handle.invalid && ft_tc_invalidations == retired + 1);
    assert(changed(&wan) && devs_changed == 1 && mc_kicks == 1 && mr_kicks == 1);

    /* cake goes: the answer only loosens. Nothing is retired, and no bridged
     * pair through the port either -- each was admitted by an answer at
     * least as tight, and keeping it is still right. A pair refused lately,
     * perhaps for what went, is asked again. */
    up_handle.invalid = false;
    wan.answer = rx | esp;
    retired = ft_tc_invalidations;
    pass();
    assert(!up_handle.invalid && ft_tc_invalidations == retired);
    assert(!devs_changed && refusal_resets == 1 && mc_kicks == 1 && mr_kicks == 1);

    /* A change only a routed direction meets -- the flower police filter
     * swapped for the matchall -- is no change to a bridged pair either way:
     * a pair meets every filter. Loosening it asks no refusal again. */
    wan.answer = rx;
    pass();
    assert(!devs_changed && !refusal_resets && mc_kicks == 1);
    /* Nor does tightening it retire one. */
    wan.answer = rx | l4 | esp;
    pass();
    assert(!devs_changed && !refusal_resets && mc_kicks == 1);

    /* One device tightening while another loosens: the pairs through the
     * one are retired, none through the other, and the refusals are asked
     * again. */
    wan.answer = tx | rx | l4 | esp;
    pass();
    wan.answer = rx | l4 | esp;
    lan.answer = tx;
    pass();
    assert(changed(&lan) && devs_changed == 1 && refusal_resets == 1);
    /* One device doing both at once: a tighter answer, whatever it also
     * lets go of. Retiring its pairs asks every refusal again with it. */
    lan.answer = rx;
    pass();
    assert(changed(&lan) && devs_changed == 1 && !refusal_resets);

    /* No memory for a new sample: the last answer stands, and the next pass
     * asks again. */
    lan.answer = 0;
    alloc_fails = true;
    pass();
    assert(ft_tc_dev_bits(&lan) == rx && ft_tc_work.queued);
    alloc_fails = false;
    pass();
    assert(!ft_tc_dev_bits(&lan));

    /* The binding goes and no pair is left: the sample is forgotten rather
     * than left to go stale, and the worker stops. A pair alone keeps it. */
    ft_bound = false;
    paired = true;
    pass();
    assert(ft_tc_known() && ft_tc_work.queued);
    paired = false;
    pass();
    assert(!ft_tc_known() && !ft_tc_work.queued);

    /* Unload: disabled, so a binding made after queues nothing. */
    ft_bound = true;
    ft_tc_kick();
    pass();
    assert(ft_tc_known());
    ft_tc_exit();
    assert(!ft_tc_known() && !ft_tc_work.queued);
    ft_tc_kick();
    assert(!ft_tc_work.queued);
    puts("tc sample: ok");
    return 0;
}
