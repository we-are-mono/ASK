/* The FMan policer, the ports and the kernel services cdx's policer layer
 * (cdx_qos.c, with its accessors in dpa_cfg.c) stands on, recorded rather
 * than performed.
 *
 * Every profile is a slot holding what the hardware last took and what it has
 * counted since, so a test can say what a port or a flow is metered by. A
 * write that lands replaces the whole profile and zeroes its colour counters,
 * as BuildProfileRegs() does. A write can also fail the three ways the host
 * command channel fails it: refused without being sent (the channel shut
 * after a timeout, or no free frame), timed out without FMan having applied
 * it, or timed out after FMan applied it -- the outcome a caller cannot see.
 *
 * Delayed work is queued here and run only when the test says so, which is
 * what lets a test stand between a failed write and its retry.
 */
#ifndef PLCR_FIXTURE_H
#define PLCR_FIXTURE_H

#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef uint32_t U32;
typedef uint16_t __be16; typedef uint32_t __be32;
#define SUCCESS 0
#define FAILURE -1
#define EINVAL 22
#define ENOMEM 12
#define EIO 5
#define ENOENT 2
#define ENOSPC 28
#define EOPNOTSUPP 95
#define ERR_QM_INGRESS_POLICER_HANDLE_NULL 507
#define ERR_QM_INGRESS_SET_PROFILE_FAILED 508
#define FMAN_INDEX 0
#define CDX_FT_QOS_MAX_POLICER 7
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define ENABLE_EGRESS_QOS
#define SEC_PROFILE_SUPPORT
#include "cdx_ioctl.h"

/* --- logging: arguments consumed, warnings counted ----------------------- */
static inline int printk(const char *fmt, ...) { (void)fmt; return 0; }
static __attribute__((unused)) unsigned warnings;
#define pr_warn(...) (warnings++, printk(__VA_ARGS__))
#define pr_info(...) printk(__VA_ARGS__)
#define pr_err(...) printk(__VA_ARGS__)
#define DPA_ERROR(...) printk(__VA_ARGS__)
#define cdx_dpa_init_fault() false

/* --- memory, counted so a leak fails the run ----------------------------- */
#define GFP_KERNEL 0
static unsigned allocations;
static inline void *kzalloc(size_t n, int flags) { (void)flags; allocations++; return calloc(1, n); }
static inline void *kmalloc(size_t n, int flags) { (void)flags; allocations++; return malloc(n); }
static inline void kfree(const void *p)
{ if (p) { assert(allocations); allocations--; } free((void *)p); }
#define memcpy_fromio memcpy
#define memcpy_toio memcpy

/* --- locks: a mutex says whether it is held, so lockdep can be asked ----- */
typedef int spinlock_t;
#define DEFINE_SPINLOCK(x) spinlock_t x = 0
static unsigned spinlocks_held, mutexes_held;
static inline void spin_lock_irqsave_(spinlock_t *l, unsigned long *f)
{ assert(!*l); *l = 1; *f = 0; spinlocks_held++; }
static inline void spin_unlock_irqrestore_(spinlock_t *l, unsigned long f)
{ (void)f; assert(*l); *l = 0; spinlocks_held--; }
#define spin_lock_irqsave(l, f) spin_lock_irqsave_(l, &(f))
#define spin_unlock_irqrestore(l, f) spin_unlock_irqrestore_(l, f)

struct mutex { int held; };
#define DEFINE_MUTEX(m) struct mutex m = { 0 }
static inline void mutex_lock(struct mutex *m)
{ assert(!m->held && !spinlocks_held); m->held = 1; mutexes_held++; }
static inline void mutex_unlock(struct mutex *m) { assert(m->held); m->held = 0; mutexes_held--; }
/* Counted rather than fatal: a test may call the hardware layer directly, as
 * its owners do holding the lock, and the locking case asserts none missed. */
static unsigned lockdep_misses;
#define lockdep_assert_held(m) ((void)(lockdep_misses += !(m)->held))

/* --- delayed work: queued here, run when the test says ------------------- */
struct work_struct { void (*func)(struct work_struct *); };
struct delayed_work { struct work_struct work; bool pending; unsigned long delay; };
#define DECLARE_DELAYED_WORK(n, f) struct delayed_work n = { .work = { .func = (f) } }
#define to_delayed_work(w) container_of(w, struct delayed_work, work)
#define system_wq ((void *)0)
#define HZ 250
static inline unsigned long msecs_to_jiffies(unsigned int ms) { return (unsigned long)ms * HZ / 1000; }
static struct delayed_work *work_queued[8];
static unsigned work_count, work_running;
static inline bool queue_delayed_work(void *wq, struct delayed_work *dw, unsigned long delay)
{
    (void)wq;
    if (dw->pending)
        return false;
    assert(work_count < 8);
    dw->pending = true;
    dw->delay = delay;
    work_queued[work_count++] = dw;
    return true;
}
static inline bool cancel_delayed_work_sync(struct delayed_work *dw)
{
    bool was = dw->pending;
    unsigned i;

    for (i = 0; i < work_count; i++)
        if (work_queued[i] == dw) {
            work_queued[i] = work_queued[--work_count];
            break;
        }
    dw->pending = false;
    return was;
}
/* Run everything queued, once, as the workqueue would when its delay passed:
 * work a run re-queues waits for the next call. Returns how many ran. */
static inline unsigned run_queued_work(void)
{
    struct delayed_work *run[8];
    unsigned i, n = work_count;

    memcpy(run, work_queued, sizeof(run));
    work_count = 0;
    for (i = 0; i < n; i++) {
        run[i]->pending = false;
        assert(!mutexes_held && !spinlocks_held);
        work_running++;
        run[i]->work.func(&run[i]->work);
        work_running--;
    }
    return n;
}

/* --- the FMan policer interface, as much of it as cdx touches ----------- */
typedef void *t_Handle;
typedef int t_Error;
#define E_OK 0
typedef enum { e_FM_PCD_PLCR_PORT_PRIVATE, e_FM_PCD_PLCR_SHARED } e_FmPcdProfileTypeSelection;
typedef enum { e_FM_PCD_PLCR_PASS_THROUGH, e_FM_PCD_PLCR_RFC_2698,
               e_FM_PCD_PLCR_RFC_4115 } e_FmPcdPlcrAlgorithmSelection;
typedef enum { e_FM_PCD_PLCR_COLOR_BLIND, e_FM_PCD_PLCR_COLOR_AWARE } e_FmPcdPlcrColorMode;
typedef enum { e_FM_PCD_PLCR_GREEN, e_FM_PCD_PLCR_YELLOW, e_FM_PCD_PLCR_RED,
               e_FM_PCD_PLCR_OVERRIDE } e_FmPcdPlcrColor;
typedef enum { e_FM_PCD_PLCR_BYTE_MODE, e_FM_PCD_PLCR_PACKET_MODE } e_FmPcdPlcrRateMode;
typedef enum { e_FM_PCD_PLCR_L2_FRM_LEN, e_FM_PCD_PLCR_L3_FRM_LEN,
               e_FM_PCD_PLCR_L4_FRM_LEN, e_FM_PCD_PLCR_FULL_FRM_LEN } e_FmPcdPlcrFrameLengthSelect;
typedef enum { e_FM_PCD_PLCR_ROLLBACK_L2_FRM_LEN,
               e_FM_PCD_PLCR_ROLLBACK_FULL_FRM_LEN } e_FmPcdPlcrRollBackFrameSelect;
typedef enum { e_FM_PCD_DONE, e_FM_PCD_KG, e_FM_PCD_CC, e_FM_PCD_PLCR,
               e_FM_PCD_PRS } e_FmPcdEngine;
typedef enum { e_FM_PCD_ENQ_FRAME = 0, e_FM_PCD_DROP_FRAME } e_FmPcdDoneAction;
typedef enum {
    e_FM_PCD_PLCR_PROFILE_GREEN_PACKET_TOTAL_COUNTER,
    e_FM_PCD_PLCR_PROFILE_YELLOW_PACKET_TOTAL_COUNTER,
    e_FM_PCD_PLCR_PROFILE_RED_PACKET_TOTAL_COUNTER,
    e_FM_PCD_PLCR_PROFILE_RECOLOURED_YELLOW_PACKET_TOTAL_COUNTER,
    e_FM_PCD_PLCR_PROFILE_RECOLOURED_RED_PACKET_TOTAL_COUNTER
} e_FmPcdPlcrProfileCounters;
typedef struct {
    bool modify;
    union {
        t_Handle h_Profile;
        struct { e_FmPcdProfileTypeSelection profileType; t_Handle h_FmPort;
                 uint16_t relativeProfileId; } newParams;
    } id;
    e_FmPcdPlcrAlgorithmSelection algSelection;
    e_FmPcdPlcrColorMode colorMode;
    struct { e_FmPcdPlcrColor dfltColor, override; } color;
    struct {
        e_FmPcdPlcrRateMode rateMode;
        struct { e_FmPcdPlcrFrameLengthSelect frameLengthSelection;
                 e_FmPcdPlcrRollBackFrameSelect rollBackFrameSelection; } byteModeParams;
        uint32_t committedInfoRate, committedBurstSize;
        uint32_t peakOrExcessInfoRate, peakOrExcessBurstSize;
    } nonPassthroughAlgParams;
    e_FmPcdEngine nextEngineOnGreen, nextEngineOnYellow, nextEngineOnRed;
    struct { int action; } paramsOnGreen, paramsOnYellow, paramsOnRed;
} t_FmPcdPlcrProfileParams;
typedef struct t_FmPcdPlcrProfileCounterValues {
    uint32_t green, yellow, red, recolouredYellow, recolouredRed;
} t_FmPcdPlcrProfileCounterValues;

/* One slot per profile: what the hardware runs, what it counted since that
 * was written, and how many writes have landed on it. */
static struct profile {
    bool live;
    t_FmPcdPlcrProfileParams params;
    uint32_t green, yellow, red;
    unsigned landed;
} profiles[32];
/* Every set, and every modify of a profile; the last profile a write landed
 * on; and the modifies made with no mutex held. */
static unsigned profile_sets, fail_profile_set, plcr_attempts, plcr_unlocked;
static struct profile *plcr_last;
/* How the next modifies fail: refused unsent, timed out unapplied, timed out
 * applied, or refused for as long as the channel stays shut. */
static unsigned plcr_refuse, plcr_lost, plcr_late;
static bool plcr_shut;

static inline void plcr_land(struct profile *slot, const t_FmPcdPlcrProfileParams *p)
{
    slot->params = *p;
    slot->green = slot->yellow = slot->red = 0;
    slot->landed++;
    plcr_last = slot;
}

static inline t_Handle FM_PCD_PlcrProfileSet(t_Handle pcd, t_FmPcdPlcrProfileParams *p)
{
    struct profile *slot;

    assert(pcd);
    /* The host command busy-waits, which no spinlock holder may do. */
    assert(!spinlocks_held);
    profile_sets++;
    if (fail_profile_set && profile_sets == fail_profile_set)
        return NULL;
    if (!p->modify) {
        for (slot = profiles; slot->live; slot++)
            assert(slot < profiles + 31);
        slot->live = true;
        plcr_land(slot, p);
        return slot;
    }
    slot = p->id.h_Profile;
    assert(slot && slot->live);
    plcr_attempts++;
    plcr_unlocked += !mutexes_held;
    if (plcr_shut)
        return NULL;
    if (plcr_refuse) {
        plcr_refuse--;
        return NULL;
    }
    if (plcr_lost) {
        plcr_lost--;
        return NULL;
    }
    plcr_land(slot, p);
    if (plcr_late) {
        plcr_late--;
        return NULL;
    }
    return slot;
}
static inline t_Error FM_PCD_PlcrProfileDelete(t_Handle h)
{
    struct profile *slot = h;

    assert(slot && slot->live && !spinlocks_held);
    slot->live = false;
    return E_OK;
}
static inline uint8_t FmPcdPlcrProfileGetAbsoluteId(t_Handle h)
{ return (uint8_t)((struct profile *)h - profiles); }

/* A failed read is an error from the new interface, and a zero from the old
 * one, which is what it used to be taken for. */
static bool counters_fail;
static unsigned counter_reads;
static inline t_Error FM_PCD_PlcrProfileReadCounters(t_Handle h, t_FmPcdPlcrProfileCounterValues *v)
{
    struct profile *slot = h;

    assert(slot && slot->live && !spinlocks_held);
    counter_reads++;
    if (counters_fail)
        return 1;
    v->green = slot->green;
    v->yellow = slot->yellow;
    v->red = slot->red;
    v->recolouredYellow = v->recolouredRed = 0;
    return E_OK;
}
static inline uint32_t FM_PCD_PlcrProfileGetCounter(t_Handle h, e_FmPcdPlcrProfileCounters c)
{
    struct profile *slot = h;

    assert(slot && slot->live && !spinlocks_held);
    counter_reads++;
    if (counters_fail)
        return 0;
    switch (c) {
    case e_FM_PCD_PLCR_PROFILE_GREEN_PACKET_TOTAL_COUNTER: return slot->green;
    case e_FM_PCD_PLCR_PROFILE_YELLOW_PACKET_TOTAL_COUNTER: return slot->yellow;
    case e_FM_PCD_PLCR_PROFILE_RED_PACKET_TOTAL_COUNTER: return slot->red;
    default: return 0;
    }
}

/* --- the ports a profile is allocated to ---------------------------------- */
struct fm_port { int id; };
static inline void *fm_port_get_handle(void *port) { return port; }
static inline int FM_PORT_PcdPlcrAllocProfiles(void *port, int n) { (void)port; (void)n; return 0; }
static inline int FM_PORT_PcdPlcrFreeProfiles(void *port) { (void)port; return 0; }

#define IF_TYPE_ETHERNET 1
#define PORT_1G_SPEED 1000
#define RX 0
struct mac_device { struct fm_port *port_dev[2]; };
struct dpa_priv_s { struct mac_device *mac_dev; };
struct net_device { char name[16]; void *priv; };
static inline void *netdev_priv(struct net_device *d) { return d->priv; }
struct eth_iface_info { struct net_device *net_dev; uint32_t speed, hardwarePortId, fman_idx; };
struct dpa_iface_info {
    char name[16];
    uint32_t if_flags;
    struct eth_iface_info eth_info;
    struct dpa_iface_info *next;
};
static struct dpa_iface_info *dpa_interface_info;
static inline struct dpa_iface_info *dpa_get_iface_by_name(char *name)
{
    struct dpa_iface_info *i;

    for (i = dpa_interface_info; i; i = i->next)
        if (!strcmp(i->name, name))
            return i;
    return NULL;
}
static inline int dpa_get_iface_hwid_by_name_and_type(char *name, uint32_t type)
{
    struct dpa_iface_info *i = dpa_get_iface_by_name(name);

    (void)type;
    return i ? (int)i->eth_info.hardwarePortId : -1;
}
static int plcr_pcd;
static inline void *dpa_get_pcdhandle(uint32_t fm) { return fm == FMAN_INDEX ? &plcr_pcd : NULL; }

/* The one FMan cdx configures (dpa_cfg_publish()). */
static struct cdx_fman_info *fman_info;
static uint32_t num_fmans;

#endif /* PLCR_FIXTURE_H */
