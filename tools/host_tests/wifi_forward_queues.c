/* The Wi-Fi VAPs' forwarding queues and the group that bounds them.
 *
 * The classifier enqueues a flow leaving by a VAP to one of that VAP's
 * forwarding queues, and the CPU drains them into the radio's own queue. A
 * frame there holds a buffer of the pool it arrived in -- SEC's output pool for
 * a decrypted flow -- and a stream faster than the drain kept every one: SEC
 * then refused every SA's jobs. So every VAP's queues join one group that
 * counts frames and drops at the tail, set up before any VAP can open and
 * released only after every queue has gone.
 */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

#define NR_CPUS 4
#define GFP_KERNEL 0
#define FMAN_IDX 0
#define TX_DIR 1
#define FQ_TYPE_RX_PCD 3
#define DEFA_VWD_WQ_ID 5
#define NUM_PKT_DATA_LINES_IN_CACHE 2
#define NUM_ANN_LINES_IN_CACHE 1
#define DPAWIFI_ERROR(...) do { } while (0)
#define DPAWIFI_INFO(...) do { } while (0)

#define QMAN_FQ_FLAG_DYNAMIC_FQID 0x20
#define QMAN_INITFQ_FLAG_SCHED 1
#define QM_INITFQ_WE_CGID 0x0040
#define QM_INITFQ_WE_FQCTRL 0x0020
#define QM_INITFQ_WE_DESTWQ 0x0010
#define QM_INITFQ_WE_CONTEXTB 0x0008
#define QM_INITFQ_WE_CONTEXTA 0x0004
#define QM_FQCTRL_CGE 0x0400
#define QM_STASHING_EXCL_ANNOTATION 0x04
#define QM_STASHING_EXCL_DATA 0x02
#define QM_CGR_WE_MODE 0x0001
#define QM_CGR_WE_CS_THRES 0x0002
#define QM_CGR_WE_CSTD_EN 0x0004
#define QM_CGR_WE_CSCN_EN 0x0010
#define QM_CGR_EN 1
#define QMAN_CGR_FLAG_USE_INIT 1
#define QMAN_CGR_MODE_FRAME 1

#include "wifi_forward_queues_limits.inc"

typedef unsigned long cpumask_t;
#define for_each_cpu(cpu, mask) \
    for ((cpu) = 0; (cpu) < NR_CPUS; (cpu)++) if (*(mask) & (1UL << (cpu)))

struct net_device { int unused; };
struct qman_portal;
struct qm_dqrr_entry;
enum qman_cb_dqrr_result { qman_cb_dqrr_consume, qman_cb_dqrr_stop };
struct qman_fq {
    u32 fqid;
    struct {
        enum qman_cb_dqrr_result (*dqrr)(struct qman_portal *, struct qman_fq *,
                                         const struct qm_dqrr_entry *);
    } cb;
    /* The model's own: created, scheduled, the group it joined. */
    bool live, sched;
    int cgid;
};
struct dpa_fq {
    struct qman_fq fq_base;
    u32 fqid, channel, wq;
    int fq_type;
    struct net_device *net_dev;
};
struct qman_cgr { u32 cgrid; };
struct qm_cgr_cs_thres { u64 value; };
struct qm_mcc_initcgr {
    u32 we_mask;
    struct { u32 mode, cstd_en, cscn_en; struct qm_cgr_cs_thres cs_thres; } cgr;
};
struct qm_mcc_initfq {
    u32 fqid, count, we_mask;
    struct {
        u32 fq_ctrl;
        u8 cgid;
        struct { u32 channel, wq; } dest;
        struct { struct { u32 exclusive, data_cl, annotation_cl; } stashing; } context_a;
    } fqd;
};
struct dpaa_vwd_priv_s { struct qman_cgr fwd_cgr; };
struct vap_desc_s {
    struct dpaa_vwd_priv_s *vwd;
    struct net_device *wifi_dev;
    struct dpa_fq *wlan_fq_from_fman[CDX_VWD_FWD_FQ_MAX];
};

static cpumask_t affine = 0xf;
static const cpumask_t *qman_affine_cpus(void) { return &affine; }
static u32 qman_affine_channel(int cpu) { return 0x20 + cpu; }

/* QMan's groups: allocated, set up (with what), and how many queues name each. */
#define CGRS 4
static struct { bool allocated, tail_drop, frames, notify; u64 thres; unsigned members; } cgrs[CGRS];
static unsigned calls, fail, fqids = 0x100, live;
static bool fault(void) { return ++calls == fail; }

static int qman_alloc_cgrid(u32 *id)
{
    if (fault()) return -1;
    for (u32 i = 1; i < CGRS; i++)
        if (!cgrs[i].allocated) {
            cgrs[i].allocated = true;
            *id = i;
            return 0;
        }
    return -1;
}
static void qman_release_cgrid(u32 id)
{
    /* QMan leaks a group a live queue still names. */
    assert(id && id < CGRS && cgrs[id].allocated && !cgrs[id].members);
    memset(&cgrs[id], 0, sizeof(cgrs[id]));
}
static void qm_cgr_cs_thres_set64(struct qm_cgr_cs_thres *th, u64 value, int roundup)
{
    assert(roundup);
    th->value = value;
}
static int qman_modify_cgr(struct qman_cgr *cgr, u32 flags, struct qm_mcc_initcgr *opts)
{
    assert(cgr->cgrid && cgr->cgrid < CGRS && cgrs[cgr->cgrid].allocated);
    if (fault()) return -1;
    assert(flags & QMAN_CGR_FLAG_USE_INIT);
    if (!opts->we_mask) {
        /* Reset to nothing before the release: no member left. */
        assert(!cgrs[cgr->cgrid].members);
        cgrs[cgr->cgrid].tail_drop = false;
        return 0;
    }
    assert((opts->we_mask & (QM_CGR_WE_MODE | QM_CGR_WE_CS_THRES | QM_CGR_WE_CSTD_EN |
                             QM_CGR_WE_CSCN_EN)) ==
           (QM_CGR_WE_MODE | QM_CGR_WE_CS_THRES | QM_CGR_WE_CSTD_EN | QM_CGR_WE_CSCN_EN));
    cgrs[cgr->cgrid].tail_drop = opts->cgr.cstd_en == QM_CGR_EN;
    cgrs[cgr->cgrid].frames = opts->cgr.mode == QMAN_CGR_MODE_FRAME;
    cgrs[cgr->cgrid].notify = opts->cgr.cscn_en;
    cgrs[cgr->cgrid].thres = opts->cgr.cs_thres.value;
    return 0;
}

static void *kzalloc(size_t size, int flags) { (void)flags; return fault() ? NULL : calloc(1, size); }
static void kfree(void *p) { free(p); }
static int cdx_copy_eth_rx_channel_info(int fman, struct dpa_fq *fq)
{
    (void)fman;
    fq->channel = 0x40;
    return 0;
}
static int qman_create_fq(u32 fqid, u32 flags, struct qman_fq *fq)
{
    assert(!fqid && (flags & QMAN_FQ_FLAG_DYNAMIC_FQID));
    if (fault()) return -1;
    fq->fqid = fqids++;
    fq->live = true;
    fq->cgid = -1;
    live++;
    return 0;
}
static int qman_init_fq(struct qman_fq *fq, u32 flags, struct qm_mcc_initfq *opts)
{
    assert(fq->live && (flags & QMAN_INITFQ_FLAG_SCHED) && opts->fqid == fq->fqid);
    if (fault()) return -1;
    if ((opts->we_mask & QM_INITFQ_WE_CGID) && (opts->fqd.fq_ctrl & QM_FQCTRL_CGE)) {
        assert(opts->we_mask & QM_INITFQ_WE_FQCTRL);
        assert(opts->fqd.cgid && opts->fqd.cgid < CGRS && cgrs[opts->fqd.cgid].allocated);
        fq->cgid = opts->fqd.cgid;
        cgrs[fq->cgid].members++;
    }
    fq->sched = true;
    return 0;
}
static void qman_destroy_fq(struct qman_fq *fq, u32 flags)
{
    (void)flags;
    assert(fq->live);
    if (fq->cgid >= 0)
        cgrs[fq->cgid].members--;
    fq->live = fq->sched = false;
    live--;
}
static void cdx_destroy_fq(struct qman_fq *fq)
{
    /* Out of service first, as the release of their group requires. */
    qman_destroy_fq(fq, 0);
}
static void cdx_create_type_fqid_info_in_procfs(struct qman_fq *fq, int dir, void *entry, void *arg)
{
    (void)dir; (void)entry; (void)arg;
    assert(fq->live);
}
static enum qman_cb_dqrr_result vap_rx_fwd_pkt(struct qman_portal *portal, struct qman_fq *fq,
                                               const struct qm_dqrr_entry *dq)
{
    (void)portal; (void)fq; (void)dq;
    return qman_cb_dqrr_consume;
}

#include "wifi_forward_queues_production.inc"

static struct dpaa_vwd_priv_s priv;
static struct net_device radio;

static void open_vap(struct vap_desc_s *vap)
{
    memset(vap, 0, sizeof(*vap));
    vap->vwd = &priv;
    vap->wifi_dev = &radio;
    assert(!create_vap_fwd_from_fman_fqs(vap, NULL));
    for (unsigned i = 0; i < CDX_VWD_FWD_FQ_MAX; i++) {
        struct qman_fq *fq = &vap->wlan_fq_from_fman[i]->fq_base;

        /* Every queue of every VAP is in the one group. */
        assert(fq->sched && fq->cgid == (int)priv.fwd_cgr.cgrid);
    }
}

int main(void)
{
    struct vap_desc_s vaps[2];
    unsigned faults = 0;

    /* A share of SEC's output pool, which the exception queues, the
     * Ethernet ports' queues for its frames and the hardware qdisc trees'
     * class queues have shares of too: all of them full at once, on a board
     * of five ports, still leave SEC some. The fixed shares are 128 frames
     * each, whatever the pool, and the trees have half of it. */
    assert(VWD_FWD_FRAMES == 128 && IPSEC_EXCEPTION_FRAMES == 128 && IPSEC_EGRESS_FRAMES == 128);
    assert(IPSEC_QDISC_FRAMES == IPSEC_BUFCOUNT / 2);
    assert(VWD_FWD_FRAMES + IPSEC_EXCEPTION_FRAMES + 5 * IPSEC_EGRESS_FRAMES +
           IPSEC_QDISC_FRAMES < IPSEC_BUFCOUNT);

    /* The group alone: whichever of its two steps fails, nothing is left. */
    for (fail = 1; fail <= 2; fail++, faults++) {
        calls = 0;
        assert(vwd_fwd_cgr_init(&priv) == (fail == 1 ? -ENOSPC : -EIO));
        for (unsigned i = 0; i < CGRS; i++)
            assert(!cgrs[i].allocated);
    }
    calls = fail = 0;
    assert(!vwd_fwd_cgr_init(&priv));
    /* Frames, tail drop, no notifications for a portal to own. */
    assert(cgrs[priv.fwd_cgr.cgrid].tail_drop && cgrs[priv.fwd_cgr.cgrid].frames);
    assert(!cgrs[priv.fwd_cgr.cgrid].notify && cgrs[priv.fwd_cgr.cgrid].thres == VWD_FWD_FRAMES);

    /* Two VAPs share it. */
    open_vap(&vaps[0]);
    open_vap(&vaps[1]);
    assert(cgrs[priv.fwd_cgr.cgrid].members == 2 * CDX_VWD_FWD_FQ_MAX);

    /* A VAP whose queues fail part way leaves the ones it made for the
     * release vwd_vap_up() runs, and those leave the group again. */
    for (fail = 1; fail <= 3 * CDX_VWD_FWD_FQ_MAX; fail += 7, faults++) {
        struct vap_desc_s partial = { .vwd = &priv, .wifi_dev = &radio };

        calls = 0;
        assert(create_vap_fwd_from_fman_fqs(&partial, NULL));
        release_vap_fqs(&partial);
        assert(cgrs[priv.fwd_cgr.cgrid].members == 2 * CDX_VWD_FWD_FQ_MAX);
    }
    calls = fail = 0;

    /* Unload: every queue goes, then the group, which QMan would leak
     * while one still named it. */
    release_vap_fqs(&vaps[0]);
    release_vap_fqs(&vaps[1]);
    assert(!live);
    vwd_fwd_cgr_exit(&priv);
    for (unsigned i = 0; i < CGRS; i++)
        assert(!cgrs[i].allocated);

    printf("Wi-Fi forwarding queues: %u VAP queues in one frame-counted group of %u, "
           "%u faults unwound\n", 2 * CDX_VWD_FWD_FQ_MAX, (unsigned)VWD_FWD_FRAMES, faults);
    return 0;
}
