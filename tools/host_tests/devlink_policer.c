/* What devlink says the two device-wide meters run, from the first `show', and
 * what they run once a set has failed to land.
 *
 * A devlink policer reports the rate and burst it was registered with until a
 * set succeeds, and a set naming only a rate keeps the registered burst. So the
 * registration has to carry what the profiles were actually created with. The
 * chain is the whole point, so it is compiled end to end: CDX's startup
 * defaults, the profiles cdx creates from them, the accessors that read them
 * back, and the policer table built from those. A stub devlink core records
 * what was registered, and a stub FMan (plcr_fixture.h) what each profile
 * runs and counts.
 */
#include "plcr_fixture.h"

#include "plcr_types.inc"
#include "plcr_qos.inc"
#include "plcr_cfg.inc"

/* --- the devlink core, recorded ------------------------------------------ */
struct device { int unused; };
struct netlink_ext_ack { const char *msg; };
/* As the kernel's: the message must be a string literal. */
#define NL_SET_ERR_MSG_MOD(e, m) do { static const char __msg[] = m; if (e) (e)->msg = __msg; } while (0)
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

/* What the loader configures and cdx creates at DPA configuration, with a hook
 * to change the loader's choices first. */
static void configure(void (*change)(struct cdx_fman_info *))
{
    memset(profiles, 0, sizeof(profiles));
    memset(&fman, 0, sizeof(fman));
    fman.pcd_handle = &plcr_pcd;
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

static struct profile *punt_profile(void) { return fman.expt_rate_limit_info[CDX_EXPT_ETH_RATELIMIT].handle; }
static struct profile *sec_profile(void) { return fman.ingress_policer_info[INGRESS_SEC_POLICER_QUEUE_NUM].handle; }
#define RATE(s) ((s)->params.nonPassthroughAlgParams)
/* Both pairs, as one devlink rate and burst program them. */
static void assert_runs(struct profile *p, u32 rate, u32 burst)
{
    assert(RATE(p).committedInfoRate == rate && RATE(p).peakOrExcessInfoRate == rate);
    assert(RATE(p).committedBurstSize == burst && RATE(p).peakOrExcessBurstSize == burst);
}

static void byte_mode(struct cdx_fman_info *f) { f->expt_ratelim_mode = EXPT_PKT_LIM_PLCR_MODE_BYTE; }
static void no_punt(struct cdx_fman_info *f)
{ f->expt_rate_limit_info[CDX_EXPT_ETH_RATELIMIT].limit = DISABLE_EXPT_PROFILE; }
static void punt_too_fast(struct cdx_fman_info *f)
{ f->expt_rate_limit_info[CDX_EXPT_ETH_RATELIMIT].limit = CDX_PUNT_RATE_MAX + 1; }
static void punt_burst_too_big(struct cdx_fman_info *f) { f->expt_ratelim_burst_size = 4096; }

static struct netlink_ext_ack ack;

static int set(const struct devlink_trap_policer *policer, u64 rate, u64 burst)
{
    ack.msg = NULL;
    return cdx_devlink->ops->trap_policer_set(cdx_devlink, policer, rate, burst, &ack);
}

static u64 drops_of(const struct devlink_trap_policer *policer)
{
    u64 drops = ~0ULL;

    assert(!cdx_devlink->ops->trap_policer_counter_get(cdx_devlink, policer, &drops));
    return drops;
}

/* ---- registration, the verbs, and detach -------------------------------- */
static void verbs(void)
{
    const struct devlink_trap_policer *punt, *sec;
    struct profile *p;

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
    p = punt_profile();
    assert(RATE(p).rateMode == e_FM_PCD_PLCR_PACKET_MODE);
    assert(RATE(p).peakOrExcessInfoRate == punt->init_rate);
    assert(RATE(p).peakOrExcessBurstSize == punt->init_burst);
    p = sec_profile();
    assert(RATE(p).rateMode == e_FM_PCD_PLCR_PACKET_MODE);
    assert(RATE(p).peakOrExcessInfoRate == sec->init_rate);
    assert(RATE(p).peakOrExcessBurstSize == sec->init_burst);
    assert(p->params.nextEngineOnYellow == p->params.nextEngineOnGreen);
    assert(p->params.paramsOnRed.action == e_FM_PCD_DROP_FRAME);
    assert(!warnings);

    /* Attaching is once; a second call changes nothing. */
    struct devlink *first = cdx_devlink;
    assert(!cdx_devlink_attach(&fman_dev) && cdx_devlink == first && instances == 1);

    /* ---- the verbs reach the profiles they describe ---- */
    unsigned sets = profile_sets;
    assert(!set(punt, 100000, 512) && !ack.msg);
    p = punt_profile();
    assert(profile_sets == sets + 1 && p->params.modify);
    assert_runs(p, 100000, 512);
    assert(!set(sec, 200000, 1024) && !ack.msg);
    assert_runs(sec_profile(), 200000, 1024);
    /* Red is what each drops. */
    punt_profile()->red = 11;
    sec_profile()->red = 22;
    assert(drops_of(punt) == 11 && drops_of(sec) == 22);
    assert(!work_count);

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
    assert(RATE(p).byteModeParams.frameLengthSelection == e_FM_PCD_PLCR_L3_FRM_LEN);
    assert(p->params.nextEngineOnYellow == e_FM_PCD_DONE &&
           p->params.paramsOnYellow.action == e_FM_PCD_DROP_FRAME);
    assert(p->params.nextEngineOnGreen != e_FM_PCD_DONE);
    assert(RATE(p).peakOrExcessBurstSize == 2026);
    /* Given back, the profile meters as NXP's do again, whatever enables it
     * next. */
    assert(cdx_ingress_enable_or_disable_qos(FMAN_INDEX, 1, DISABLE_INGRESS_POLICER) == SUCCESS);
    assert(cdx_ingress_enable_or_disable_qos(FMAN_INDEX, 1, ENABLE_INGRESS_POLICER) == SUCCESS);
    assert(RATE(p).byteModeParams.frameLengthSelection == e_FM_PCD_PLCR_FULL_FRM_LEN);
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
}

/* ---- the SEC policer, set while its write does not land ---------------- */
static void sec_deferred(void)
{
    const struct devlink_trap_policer *sec;
    u32 rate, burst;
    int rc;

    configure(NULL);
    assert(!cdx_devlink_attach(&fman_dev));
    sec = registered(CDX_DEVLINK_POLICER_SEC);

    /* Timed out, never applied. The set is valid, so devlink is told it took
     * -- and so shows the new rate -- and the profile is rewritten until it
     * runs it, rather than devlink keeping a rate the meter may or may not
     * have left behind. */
    plcr_lost = 1;
    rc = set(sec, 300000, 100);
    assert(rc == 0 && ack.msg && strstr(ack.msg, "retried"));
    assert(cdx_ingress_policer_peak(FMAN_INDEX, INGRESS_SEC_POLICER_QUEUE_NUM, &rate, &burst) ==
           SUCCESS && rate == 300000 && burst == 100);
    assert(RATE(sec_profile()).peakOrExcessInfoRate == 1060000 &&
           RATE(sec_profile()).peakOrExcessBurstSize == 64);
    assert(run_queued_work() == 1 && !work_count);
    assert_runs(sec_profile(), 300000, 100);

    /* Refused while the channel is shut: tried again each second, and left
     * alone once it lands. */
    plcr_shut = true;
    assert(!set(sec, 400000, 200) && ack.msg);
    assert(run_queued_work() == 1 && work_count == 1);
    assert(run_queued_work() == 1 && work_count == 1);
    assert_runs(sec_profile(), 300000, 100);
    plcr_shut = false;
    assert(run_queued_work() == 1 && !work_count);
    assert_runs(sec_profile(), 400000, 200);
    assert(!plcr_unlocked);
    cdx_devlink_detach();
}

/* ---- the punt policer, set while its write does not land --------------- */
static void punt_deferred(void)
{
    const struct devlink_trap_policer *punt;
    u32 rate, burst;
    int rc;

    configure(NULL);
    assert(!cdx_devlink_attach(&fman_dev));
    punt = registered(CDX_DEVLINK_POLICER_PUNT);

    plcr_lost = 1;
    rc = set(punt, 100000, 512);
    /* One request, held whole: never the old rate with the new burst. */
    assert(cdx_expt_rate_config(FMAN_INDEX, CDX_EXPT_ETH_RATELIMIT, &rate, &burst) == SUCCESS);
    assert((rate == 100000) == (burst == 512));
    assert(rc == 0 && ack.msg && strstr(ack.msg, "retried"));
    assert(rate == 100000 && burst == 512);
    assert_runs(punt_profile(), 195312, 64);
    assert(run_queued_work() == 1 && !work_count);
    assert_runs(punt_profile(), 100000, 512);

    /* Timed out after FMan applied it: the same whole profile is written
     * again, which leaves the meter as it is. */
    plcr_late = 1;
    assert(!set(punt, 50000, 32) && ack.msg);
    assert_runs(punt_profile(), 50000, 32);
    assert(run_queued_work() == 1 && !work_count);
    assert_runs(punt_profile(), 50000, 32);
    assert(cdx_expt_rate_config(FMAN_INDEX, CDX_EXPT_ETH_RATELIMIT, &rate, &burst) == SUCCESS);
    assert(rate == 50000 && burst == 32);
    assert(!plcr_unlocked);
    cdx_devlink_detach();
}

/* ---- the drop counts, across failed reads and rewrites ----------------- */
static void counters(void)
{
    const struct devlink_trap_policer *punt, *sec;

    configure(NULL);
    assert(!cdx_devlink_attach(&fman_dev));
    punt = registered(CDX_DEVLINK_POLICER_PUNT);
    sec = registered(CDX_DEVLINK_POLICER_SEC);

    punt_profile()->red = 40;
    assert(drops_of(punt) == 40);
    /* A read that fails is no reading: devlink is shown the drops it was
     * shown last, not a zero that would run the count backwards, and the
     * next good read adds only what the meter dropped since. */
    punt_profile()->red += 10;
    counters_fail = true;
    assert(drops_of(punt) == 40);
    counters_fail = false;
    punt_profile()->red += 5;
    assert(drops_of(punt) == 55);

    /* A set rewrites the profile, which zeroes its counters. What the meter
     * dropped is not undone by that: the count goes on from where it was. */
    punt_profile()->red += 3;
    assert(!set(punt, 100000, 512));
    assert(!punt_profile()->red);
    punt_profile()->red = 4;
    assert(drops_of(punt) == 62);
    /* And so does a retry, which rewrites it too. */
    plcr_lost = 1;
    assert(!set(punt, 90000, 512) && ack.msg);
    punt_profile()->red += 1;
    assert(drops_of(punt) == 63);
    assert(run_queued_work() == 1 && !punt_profile()->red);
    punt_profile()->red = 2;
    assert(drops_of(punt) == 65);

    /* The same for the SEC policer. */
    sec_profile()->red = 7;
    assert(drops_of(sec) == 7);
    counters_fail = true;
    assert(drops_of(sec) == 7);
    counters_fail = false;
    sec_profile()->red += 1;
    assert(!set(sec, 300000, 100));
    sec_profile()->red = 2;
    assert(drops_of(sec) == 10);
    assert(!plcr_unlocked && !lockdep_misses);
    cdx_devlink_detach();
}

int main(int argc, char **argv)
{
    static const struct { const char *name; void (*run)(void); } cases[] = {
        { "verbs", verbs },
        { "sec_deferred", sec_deferred },
        { "punt_deferred", punt_deferred },
        { "counters", counters },
    };

    assert(argc == 2);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        if (strcmp(argv[1], cases[i].name))
            continue;
        cases[i].run();
        assert(!work_count && !mutexes_held);
        printf("devlink policers %s: passed\n", cases[i].name);
        return 0;
    }
    fprintf(stderr, "no case %s\n", argv[1]);
    return 2;
}
