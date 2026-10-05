/* What devlink says the two device-wide meters run, from the first `show'.
 *
 * A devlink policer reports the rate and burst it was registered with until a
 * set succeeds, and a set naming only a rate keeps the registered burst. So the
 * registration has to carry what the profiles were actually created with. The
 * chain is the whole point, so it is compiled end to end: CDX's startup defaults, the profiles cdx creates from them, the accessors that read them
 * back, and the policer table built from those. A stub devlink core records
 * what was registered.
 */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef uint32_t U32;
#define SUCCESS 0
#define FAILURE 1
#define EINVAL 22
#define ENOMEM 12
#define EOPNOTSUPP 95
#define ERR_QM_INGRESS_SET_PROFILE_FAILED 0x100
#define ERR_QM_INGRESS_POLICER_HANDLE_NULL 0x101
#define FMAN_INDEX 0
#define ENABLE_EGRESS_QOS
#define SEC_PROFILE_SUPPORT
#include "cdx_ioctl.h"

/* --- the FMAN policer interface, as much of it as the profiles touch ------ */
typedef void *t_Handle;
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

/* One slot per profile the harness hands out, holding what it was last
 * programmed with, so a test can say what the hardware runs. */
static struct profile { bool live; t_FmPcdPlcrProfileParams params; } profiles[32];
static unsigned profile_sets, fail_profile_set;
static t_Handle FM_PCD_PlcrProfileSet(t_Handle pcd, t_FmPcdPlcrProfileParams *p)
{
    struct profile *slot;

    assert(pcd);
    profile_sets++;
    if (fail_profile_set && profile_sets == fail_profile_set)
        return NULL;
    if (p->modify) {
        slot = p->id.h_Profile;
        assert(slot && slot->live);
    } else {
        for (slot = profiles; slot->live; slot++)
            assert(slot < profiles + 31);
        slot->live = true;
    }
    slot->params = *p;
    return slot;
}
static uint8_t FmPcdPlcrProfileGetAbsoluteId(t_Handle h)
{ return (uint8_t)((struct profile *)h - profiles); }
#define cdx_dpa_init_fault() false
#define printk(...) ((void)0)
#define DPA_ERROR(...) ((void)0)

static struct cdx_fman_info *fman_info;
static uint32_t num_fmans;
#include "devlink_policer_profiles.inc"

/* --- the counters, which this file only routes ---------------------------- */
struct cdx_police_counters { uint32_t green, yellow, red; };
static int cdx_expt_rate_counters(uint32_t fm, uint32_t type, struct cdx_police_counters *out)
{ assert(fm == FMAN_INDEX && type == CDX_EXPT_ETH_RATELIMIT); out->red = 11; return SUCCESS; }
static int cdx_ingress_policer_counters(uint32_t fm, uint32_t q, struct cdx_police_counters *out)
{ assert(fm == FMAN_INDEX && q == INGRESS_SEC_POLICER_QUEUE_NUM); out->red = 22; return SUCCESS; }

/* --- the devlink core, recorded ------------------------------------------ */
struct device { int unused; };
struct netlink_ext_ack { const char *msg; };
#define NL_SET_ERR_MSG_MOD(e, m) do { if (e) (e)->msg = (m); } while (0)
static unsigned warnings;
#define pr_warn(...) (warnings++)
struct devlink_trap_policer {
    u32 id; u64 init_rate, init_burst, max_rate, min_rate, max_burst, min_burst;
};
#define DEVLINK_TRAP_POLICER(_id, _rate, _burst, _max_rate, _min_rate,	\
                             _max_burst, _min_burst)			\
    { .id = _id, .init_rate = _rate, .init_burst = _burst,		\
      .max_rate = _max_rate, .min_rate = _min_rate,			\
      .max_burst = _max_burst, .min_burst = _min_burst, }
struct devlink;
struct devlink_ops {
    int (*trap_policer_set)(struct devlink *, const struct devlink_trap_policer *,
                            u64, u64, struct netlink_ext_ack *);
    int (*trap_policer_counter_get)(struct devlink *, const struct devlink_trap_policer *,
                                    u64 *);
};
struct devlink {
    const struct devlink_ops *ops;
    struct device *dev;
    bool locked, registered;
    const struct devlink_trap_policer *policers;
    size_t count;
};
static unsigned instances, fail_alloc, fail_register;
static struct devlink *devlink_alloc(const struct devlink_ops *ops, size_t priv, struct device *dev)
{
    (void)priv;
    if (fail_alloc) return NULL;
    struct devlink *d = calloc(1, sizeof(*d));
    d->ops = ops; d->dev = dev; instances++;
    return d;
}
static void devlink_free(struct devlink *d) { assert(!d->registered && !d->count); instances--; free(d); }
static void devl_lock(struct devlink *d) { assert(!d->locked); d->locked = true; }
static void devl_unlock(struct devlink *d) { assert(d->locked); d->locked = false; }
static int devl_trap_policers_register(struct devlink *d, const struct devlink_trap_policer *p,
                                       size_t n)
{
    assert(d->locked && !d->count && n);
    /* The core's own verification: a descriptor it would WARN on is a bug here. */
    for (size_t i = 0; i < n; i++) {
        assert(p[i].id && p[i].max_rate >= p[i].min_rate && p[i].max_burst >= p[i].min_burst);
        assert(p[i].init_rate >= p[i].min_rate && p[i].init_rate <= p[i].max_rate);
        assert(p[i].init_burst >= p[i].min_burst && p[i].init_burst <= p[i].max_burst);
    }
    if (fail_register) return -ENOMEM;
    d->policers = p; d->count = n;
    return 0;
}
static void devl_trap_policers_unregister(struct devlink *d, const struct devlink_trap_policer *p,
                                          size_t n)
{
    assert(d->locked && d->policers == p && d->count == n);
    d->policers = NULL; d->count = 0;
}
static void devlink_register(struct devlink *d) { assert(d->count && !d->registered); d->registered = true; }
static void devlink_unregister(struct devlink *d) { assert(d->registered); d->registered = false; }

#include "devlink_policer_production.inc"

/* ------------------------------------------------------------------------- */

static struct cdx_fman_info fman;
static struct device fman_dev;
static int pcd;

/* What the loader configures and cdx creates at DPA configuration, with a hook
 * to change the loader's choices first. */
static void configure(void (*change)(struct cdx_fman_info *))
{
    memset(profiles, 0, sizeof(profiles));
    memset(&fman, 0, sizeof(fman));
    fman.pcd_handle = &pcd;
    dpa_cfg_set_expt_defaults(&fman);
    if (change)
        change(&fman);
    fman_info = &fman;
    num_fmans = 1;
    assert(!cdxdrv_create_missaction_policer_profiles(&fman));
    assert(!cdxdrv_create_ingress_qos_policer_profiles(&fman));
    warnings = 0;
}

static const struct devlink_trap_policer *registered(u32 id)
{
    if (!cdx_devlink)
        return NULL;
    for (size_t i = 0; i < cdx_devlink->count; i++)
        if (cdx_devlink->policers[i].id == id)
            return &cdx_devlink->policers[i];
    return NULL;
}

static void byte_mode(struct cdx_fman_info *f) { f->expt_ratelim_mode = EXPT_PKT_LIM_PLCR_MODE_BYTE; }
static void no_punt(struct cdx_fman_info *f)
{ f->expt_rate_limit_info[CDX_EXPT_ETH_RATELIMIT].limit = DISABLE_EXPT_PROFILE; }
static void punt_too_fast(struct cdx_fman_info *f)
{ f->expt_rate_limit_info[CDX_EXPT_ETH_RATELIMIT].limit = CDX_PUNT_RATE_MAX + 1; }
static void punt_burst_too_big(struct cdx_fman_info *f) { f->expt_ratelim_burst_size = 4096; }

int main(void)
{
    const struct devlink_trap_policer *punt, *sec;
    struct netlink_ext_ack ack = { 0 };
    u64 drops;

    /* ---- the defaults the image boots with ---- */
    configure(NULL);
    assert(!cdx_devlink_attach(&fman_dev));
    assert(cdx_devlink && cdx_devlink->registered && cdx_devlink->dev == &fman_dev);
    punt = registered(CDX_DEVLINK_POLICER_PUNT);
    sec = registered(CDX_DEVLINK_POLICER_SEC);
    assert(punt && sec && cdx_devlink->count == 2);
    /* The punt profile the loader asked for: 195312 packets a second in
     * bursts of 64, not the range's ceiling of 5000000 and 2048. */
    assert(punt->init_rate == 195312 && punt->init_burst == 64);
    assert(punt->min_rate == CDX_PUNT_RATE_MIN && punt->max_rate == CDX_PUNT_RATE_MAX);
    assert(punt->min_burst == CDX_PUNT_BURST_MIN && punt->max_burst == CDX_PUNT_BURST_MAX);
    /* The SEC profile's peak pair, which is all it enforces: green and
     * yellow pass alike and only red is dropped. */
    assert(sec->init_rate == 1060000 && sec->init_burst == 64);
    assert(sec->max_rate == CDX_SEC_RATE_MAX && sec->max_burst == CDX_SEC_BURST_MAX);
    /* And that is what the profiles themselves hold. */
    struct profile *p = fman.expt_rate_limit_info[CDX_EXPT_ETH_RATELIMIT].handle;
    assert(p->params.nonPassthroughAlgParams.rateMode == e_FM_PCD_PLCR_PACKET_MODE);
    assert(p->params.nonPassthroughAlgParams.peakOrExcessInfoRate == punt->init_rate);
    assert(p->params.nonPassthroughAlgParams.peakOrExcessBurstSize == punt->init_burst);
    p = fman.ingress_policer_info[INGRESS_SEC_POLICER_QUEUE_NUM].handle;
    assert(p->params.nonPassthroughAlgParams.rateMode == e_FM_PCD_PLCR_PACKET_MODE);
    assert(p->params.nonPassthroughAlgParams.peakOrExcessInfoRate == sec->init_rate);
    assert(p->params.nonPassthroughAlgParams.peakOrExcessBurstSize == sec->init_burst);
    assert(p->params.nextEngineOnYellow == p->params.nextEngineOnGreen);
    assert(p->params.paramsOnRed.action == e_FM_PCD_DROP_FRAME);
    assert(!warnings);

    /* Attaching is once; a second call changes nothing. */
    struct devlink *first = cdx_devlink;
    assert(!cdx_devlink_attach(&fman_dev) && cdx_devlink == first && instances == 1);

    /* ---- the verbs reach the profiles they describe ---- */
    unsigned sets = profile_sets;
    assert(!cdx_devlink->ops->trap_policer_set(cdx_devlink, punt, 100000, 512, &ack));
    p = fman.expt_rate_limit_info[CDX_EXPT_ETH_RATELIMIT].handle;
    assert(profile_sets == sets + 1 && p->params.modify);
    assert(p->params.nonPassthroughAlgParams.committedInfoRate == 100000);
    assert(p->params.nonPassthroughAlgParams.peakOrExcessBurstSize == 512);
    assert(!cdx_devlink->ops->trap_policer_set(cdx_devlink, sec, 200000, 1024, &ack));
    p = fman.ingress_policer_info[INGRESS_SEC_POLICER_QUEUE_NUM].handle;
    assert(p->params.nonPassthroughAlgParams.committedInfoRate == 200000);
    assert(p->params.nonPassthroughAlgParams.peakOrExcessInfoRate == 200000);
    assert(p->params.nonPassthroughAlgParams.committedBurstSize == 1024);
    assert(p->params.nonPassthroughAlgParams.peakOrExcessBurstSize == 1024);
    assert(!cdx_devlink->ops->trap_policer_counter_get(cdx_devlink, punt, &drops) && drops == 11);
    assert(!cdx_devlink->ops->trap_policer_counter_get(cdx_devlink, sec, &drops) && drops == 22);

    /* ---- detach, and again ---- */
    cdx_devlink_detach();
    assert(!cdx_devlink && !instances && !cdx_policer_count);
    cdx_devlink_detach();
    assert(!cdx_devlink && !instances);

    /* ---- a punt profile devlink cannot describe is not registered ---- */
    /* Metering bytes: its rate is not a packet rate. */
    configure(byte_mode);
    assert(!cdx_devlink_attach(&fman_dev));
    assert(!registered(CDX_DEVLINK_POLICER_PUNT) && registered(CDX_DEVLINK_POLICER_SEC));
    assert(cdx_devlink->count == 1 && !warnings);
    cdx_devlink_detach();
    /* Configured off: no profile exists. */
    configure(no_punt);
    assert(!fman.expt_rate_limit_info[CDX_EXPT_ETH_RATELIMIT].handle);
    assert(!cdx_devlink_attach(&fman_dev));
    assert(!registered(CDX_DEVLINK_POLICER_PUNT) && registered(CDX_DEVLINK_POLICER_SEC));
    cdx_devlink_detach();
    /* Outside the range devlink would accept a set in: said, and left out
     * rather than clamped into a value the hardware does not run. */
    configure(punt_too_fast);
    assert(!cdx_devlink_attach(&fman_dev));
    assert(!registered(CDX_DEVLINK_POLICER_PUNT) && warnings == 1);
    cdx_devlink_detach();
    configure(punt_burst_too_big);
    assert(!cdx_devlink_attach(&fman_dev));
    assert(!registered(CDX_DEVLINK_POLICER_PUNT) && warnings == 1);
    cdx_devlink_detach();

    /* ---- a SEC profile that is off is not registered ---- */
    configure(NULL);
    assert(cdx_ingress_enable_or_disable_qos(FMAN_INDEX, INGRESS_SEC_POLICER_QUEUE_NUM,
                                             DISABLE_INGRESS_POLICER) == SUCCESS);
    assert(!cdx_devlink_attach(&fman_dev));
    assert(registered(CDX_DEVLINK_POLICER_PUNT) && !registered(CDX_DEVLINK_POLICER_SEC));
    cdx_devlink_detach();

    /* ---- a tc police action's meter, and the default it returns to ---- */
    configure(NULL);
    assert(cdx_ingress_enable_or_disable_qos(FMAN_INDEX, 1, ENABLE_INGRESS_POLICER) == SUCCESS);
    assert(cdx_ingress_policer_modify_config(FMAN_INDEX, 1, 50000, 100000000, 64000, 2026,
                                             true) == SUCCESS);
    p = fman.ingress_policer_info[1].handle;
    /* IP lengths, as Linux charges a police rate, and only green passes. */
    assert(p->params.nonPassthroughAlgParams.byteModeParams.frameLengthSelection ==
           e_FM_PCD_PLCR_L3_FRM_LEN);
    assert(p->params.nextEngineOnYellow == e_FM_PCD_DONE &&
           p->params.paramsOnYellow.action == e_FM_PCD_DROP_FRAME);
    assert(p->params.nextEngineOnGreen != e_FM_PCD_DONE);
    assert(p->params.nonPassthroughAlgParams.peakOrExcessBurstSize == 2026);
    /* Given back, the profile meters as NXP's do again, whatever enables it
     * next. */
    assert(cdx_ingress_enable_or_disable_qos(FMAN_INDEX, 1, DISABLE_INGRESS_POLICER) == SUCCESS);
    assert(cdx_ingress_enable_or_disable_qos(FMAN_INDEX, 1, ENABLE_INGRESS_POLICER) == SUCCESS);
    assert(p->params.nonPassthroughAlgParams.byteModeParams.frameLengthSelection ==
           e_FM_PCD_PLCR_FULL_FRM_LEN);
    assert(p->params.nextEngineOnYellow == p->params.nextEngineOnGreen);
    assert(cdx_ingress_enable_or_disable_qos(FMAN_INDEX, 1, DISABLE_INGRESS_POLICER) == SUCCESS);

    /* ---- nothing to report, no instance ---- */
    configure(no_punt);
    assert(cdx_ingress_enable_or_disable_qos(FMAN_INDEX, INGRESS_SEC_POLICER_QUEUE_NUM,
                                             DISABLE_INGRESS_POLICER) == SUCCESS);
    assert(!cdx_devlink_attach(&fman_dev) && !cdx_devlink && !instances);
    /* And with no FMAN device to hang it on. */
    configure(NULL);
    assert(!cdx_devlink_attach(NULL) && !cdx_devlink && !instances);

    /* ---- failures leave nothing behind ---- */
    fail_alloc = 1;
    assert(cdx_devlink_attach(&fman_dev) == -ENOMEM && !cdx_devlink && !instances);
    fail_alloc = 0;
    fail_register = 1;
    assert(cdx_devlink_attach(&fman_dev) == -ENOMEM && !cdx_devlink && !instances);
    assert(!cdx_policer_count);
    fail_register = 0;
    assert(!cdx_devlink_attach(&fman_dev) && cdx_devlink->count == 2);
    cdx_devlink_detach();
    assert(!instances);

    puts("devlink policers: boot values, unit and range refusals, verbs, detach passed");
    return 0;
}
