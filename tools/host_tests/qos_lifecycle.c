/* Fault injection against the production CEETM acquisition and release paths. */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

typedef uint16_t U16;
typedef uint32_t u32;
typedef struct { int value; } atomic_t;
#define ATOMIC_INIT(v) {v}
static void atomic_set(atomic_t *p, int value) { p->value = value; }
static int atomic_read(atomic_t *p) { return p->value; }
#define ENABLE_EGRESS_QOS
#define CEETM_SUCCESS 0
#define CEETM_FAILURE -1
#define SUCCESS 0
#define FAILURE -1
#define NO_ERR 0
#define GFP_KERNEL 0
#define MAX_PHY_PORTS 10
#define GEM_PORTS 8
#define DPAA_ETH_TX_QUEUES 16
#define CDX_INGRESS_ALL_PROFILES 8
#define DEFAULT_CQ_CIR_VALUE 100
#define DEFAULT_CQ_PIR_VALUE 100
#define DEFAULT_CQ_BYTE_MODE_CBS 2000
#define DEFAULT_CQ_BYTE_MODE_PBS 2000
#define DISABLE_POLICER 0
#define KERN_INFO ""
#define printk(...) ((void)0)
#define ceetm_err(...) ((void)0)
#define ceetm_dbg(...) ((void)0)
#define pr_warn_ratelimited(...) ((void)0)
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define cpu_to_be16(x) (x)
#define CEETM_COMMAND_CHANNEL_MAPPING 0x1000
#define QM_CCGR_WE_TD_EN 1
#define QM_CCGR_WE_MODE 2
#define QM_CCGR_WE_TD_MODE 4
#define QM_CCGR_WE_TD_THRES 8

struct list_head { struct list_head *next, *prev; };
#define INIT_LIST_HEAD(n) ((n)->next = (n)->prev = (n))
static bool list_empty(struct list_head *n) { return n->next == n; }
static void list_add_tail(struct list_head *n, struct list_head *h)
{
    n->next = h; n->prev = h->prev; h->prev->next = n; h->prev = n;
}
static void list_del_init(struct list_head *n)
{
    assert(n->prev->next == n && n->next->prev == n);
    n->prev->next = n->next; n->next->prev = n->prev;
    INIT_LIST_HEAD(n);
}
struct qm_ceetm_rate { uint16_t whole, fraction; };
struct qm_ceetm_weight_code { int x; };
struct qm_ceetm_channel {
    unsigned idx, dcp_idx, lni_idx;
    struct list_head node, class_queues, ccgs;
};
struct qm_ceetm_lni {
    unsigned idx, dcp_idx;
    bool claimed;
    struct list_head channels;
    struct qm_ceetm_sp *sp;
};
struct qm_ceetm_sp { unsigned idx, dcp_idx; bool claimed; struct qm_ceetm_lni *lni; };
struct qm_ceetm_ccg { struct list_head node; struct qm_ceetm_channel *parent; };
struct qm_ceetm_cq {
    unsigned idx;
    struct list_head node, bound_lfqids;
    struct qm_ceetm_channel *parent;
    struct qm_ceetm_ccg *ccg;
};
struct qm_ceetm_lfq {
    struct list_head node;
    unsigned idx;
    void (*ern)(void);
};
struct qman_fq { unsigned fqid; bool created; };
struct qm_ceetm_ccg_params {
    unsigned mode, td_en, td_mode, cscn_en;
    struct { unsigned Tn, TA; } td_thres;
};
struct qm_mcr_ceetm_cq_query { unsigned frm_cnt; };
struct qm_mcc_ceetm_mapping_shaper_tcfc_config {
    unsigned cid, dcpid;
    struct { unsigned map_lni_id, map_shaped; } channel_mapping;
};
struct dpa_priv_s { void *qm_ctx; bool ceetm_en; };
struct net_device { struct dpa_priv_s priv; };
struct qm_fd { unsigned bpid, id; };
struct sk_buff { unsigned id; };
static struct sk_buff packets[4];
static bool packet_live[4], hold_frames, fail_query;
static unsigned pop_calls, pop_errors, pool_releases, skb_releases;
static void dpa_fd_release(struct net_device *dev, const struct qm_fd *fd)
{
    assert(dev && dev->priv.qm_ctx && fd->bpid != 0xff);
    assert(packet_live[fd->id]); packet_live[fd->id] = false; pool_releases++;
}
static struct sk_buff *_dpa_cleanup_tx_fd(const struct dpa_priv_s *priv, const struct qm_fd *fd)
{
    assert(priv && priv->qm_ctx && fd->bpid == 0xff && packet_live[fd->id]);
    return &packets[fd->id];
}
static void dev_kfree_skb_any(struct sk_buff *skb)
{ assert(packet_live[skb->id]); packet_live[skb->id] = false; skb_releases++; }
struct cdx_port_info { unsigned fm_index, portid; };
struct dpa_iface_info {
    char name[16];
    struct { struct net_device *net_dev; unsigned tx_channel_id; } eth_info;
};
#define netdev_priv(dev) (&(dev)->priv)
#include "qos_types.inc"
QM_context_ctl gQMCtx[MAX_PHY_PORTS];

typedef void *t_Handle;
typedef struct {
    struct { struct { unsigned profileType, relativeProfileId; } newParams; } id;
    unsigned algSelection, colorMode, nextEngineOnGreen, nextEngineOnYellow, nextEngineOnRed;
    struct { unsigned dfltColor, override; } color;
    struct { unsigned action; } paramsOnGreen, paramsOnYellow, paramsOnRed;
    struct {
        unsigned rateMode, committedInfoRate, peakOrExcessInfoRate;
        unsigned committedBurstSize, peakOrExcessBurstSize;
        struct { unsigned frameLengthSelection, rollBackFrameSelection; } byteModeParams;
    } nonPassthroughAlgParams;
} t_FmPcdPlcrProfileParams;
enum { e_FM_PCD_PLCR_RFC_2698, e_FM_PCD_PLCR_COLOR_BLIND, e_FM_PCD_PLCR_RED,
       e_FM_PCD_PLCR_BYTE_MODE, e_FM_PCD_PLCR_FULL_FRM_LEN, e_FM_PCD_PLCR_ROLLBACK_FULL_FRM_LEN,
       e_FM_PCD_DONE, e_FM_PCD_ENQ_FRAME, e_FM_PCD_DROP_FRAME, e_FM_PCD_PLCR_SHARED };

static unsigned fail_at, step, allocations, channels, lfqs, fqs, profiles;
static unsigned next_channel, mapping_id;
static unsigned pending_enqueues, pending_frames, pending_erns, queries;
static unsigned long jiffies;
static bool callbacks, command_handler, release_error;
static unsigned release_fail_at;
static struct qm_ceetm_lni lni;
static struct qm_ceetm_sp sp;
static struct cdx_port_info port;
static int hw_step(void) { return ++step == fail_at ? -EIO : 0; }
static void *kzalloc(size_t size, int flags)
{
    void *p;
    if (hw_step()) return NULL;
    p = calloc(1, size); assert(p); allocations++; return p;
}
static void kfree(void *p) { if (p) { assert(allocations); allocations--; free(p); } }
static int qman_alloc_ceetm0_channel(unsigned *id)
{
    if (hw_step()) return -ENOSPC;
    *id = next_channel++; channels++; return 0;
}
static int qman_ceetm_channel_release(struct qm_ceetm_channel *ch)
{
    if (!list_empty(&ch->class_queues) || !list_empty(&ch->ccgs)) return -EBUSY;
    if (release_fail_at == 3) { release_fail_at = 0; return -EIO; }
    assert(channels); channels--; list_del_init(&ch->node); kfree(ch); return 0;
}
static int qman_ceetm_ccg_claim(struct qm_ceetm_ccg **out, struct qm_ceetm_channel *ch,
                               unsigned id, void *cb, void *ctx)
{
    struct qm_ceetm_ccg *p = kzalloc(sizeof(*p), 0);
    if (!p) return -ENOMEM;
    p->parent = ch; list_add_tail(&p->node, &ch->ccgs); *out = p; return 0;
}
static int qman_ceetm_ccg_release(struct qm_ceetm_ccg *p)
{
    struct list_head *n;

    for (n = p->parent->class_queues.next; n != &p->parent->class_queues; n = n->next) {
        struct qm_ceetm_cq *cq = (void *)((char *)n - offsetof(struct qm_ceetm_cq, node));
        assert(cq->ccg != p);
    }
    list_del_init(&p->node); kfree(p); return release_error ? -EIO : 0;
}
static int qman_ceetm_cq_claim(struct qm_ceetm_cq **out, struct qm_ceetm_channel *ch,
                              unsigned id, struct qm_ceetm_ccg *ccg)
{
    struct qm_ceetm_cq *p = kzalloc(sizeof(*p), 0);
    if (!p) return -ENOMEM;
    p->idx = id; p->parent = ch; p->ccg = ccg; INIT_LIST_HEAD(&p->bound_lfqids);
    list_add_tail(&p->node, &ch->class_queues); *out = p; return 0;
}
#define qman_ceetm_cq_claim_A qman_ceetm_cq_claim
static int qman_ceetm_cq_pop(struct qm_ceetm_cq *p, struct qm_fd *fd)
{
    pop_calls++;
    if (pop_errors) return --pop_errors ? -EIO : -EAGAIN;
    if (!pending_frames) return 0;
    unsigned id = --pending_frames;
    assert(packet_live[id]);
    *fd = (struct qm_fd){.bpid = id & 1 ? 0xff : 7, .id = id};
    return 1;
}
static int qman_ceetm_cq_release(struct qm_ceetm_cq *p)
{
    assert(list_empty(&p->bound_lfqids));
    if (release_fail_at == 2) { release_fail_at = 0; return -EIO; }
    list_del_init(&p->node); kfree(p); return 0;
}
static int qman_ceetm_lfq_claim(struct qm_ceetm_lfq **out, struct qm_ceetm_cq *cq)
{
    struct qm_ceetm_lfq *p = kzalloc(sizeof(*p), 0);
    if (!p) return -ENOMEM;
    p->idx = 0xf00000 + lfqs++; list_add_tail(&p->node, &cq->bound_lfqids);
    *out = p; return 0;
}
static int qman_ceetm_lfq_release(struct qm_ceetm_lfq *p)
{
    if (release_fail_at == 1) { release_fail_at = 0; return -EIO; }
    assert(lfqs); lfqs--; list_del_init(&p->node); kfree(p); return 0;
}
static int qman_ceetm_create_fq(struct qm_ceetm_lfq *lfq, struct qman_fq *fq)
{
    if (hw_step()) return -ENOMEM;
    fq->fqid = lfq->idx; fq->created = true; fqs++; return 0;
}
static void qman_destroy_fq(struct qman_fq *fq, unsigned flags)
{
    assert(!pending_enqueues && !pending_frames && !pending_erns);
    assert(fq->created && fqs); fq->created = false; fqs--;
}
static int qman_ceetm_tokenrate2bps(struct qm_ceetm_rate *rate, uint64_t *bps, int rounding)
{ *bps = 1000000; return hw_step(); }
static unsigned fls(unsigned bits) { return bits ? 32 - __builtin_clz(bits) : 0; }
static int ceetm_get_dscp_fq(void) { return 0; }
static void egress_ern_handler(void) {}
static int dpa_register_ceetm_get_egress_fq(void *a, void *b)
{
    if (hw_step()) return -EIO;
    assert(channels == CDX_CEETM_MAX_CHANNELS && fqs == channels * MAX_SCHEDULER_QUEUES);
    assert(!callbacks); callbacks = true; return 0;
}
static void dpa_unregister_ceetm_get_egress_fq(void) { assert(callbacks); callbacks = false; }
static void *dpa_get_pcdhandle(unsigned fm) { return hw_step() ? NULL : (void *)1; }
static void *FM_PCD_PlcrProfileSet(void *pcd, t_FmPcdPlcrProfileParams *params)
{
    void *p = kzalloc(1, 0);
    if (p) profiles++;
    return p;
}
static unsigned FmPcdPlcrProfileGetAbsoluteId(void *p) { return profiles; }
static int FM_PCD_PlcrProfileDelete(void *p)
{ assert(profiles); profiles--; kfree(p); return release_error ? -EIO : 0; }
static int qman_ceetm_sp_claim(struct qm_ceetm_sp **out, unsigned fm, unsigned index)
{
    if (hw_step()) return -ENOMEM;
    assert(!sp.claimed); sp.claimed = true; sp.idx = index; *out = &sp; return 0;
}
static int qman_ceetm_lni_claim(struct qm_ceetm_lni **out, unsigned fm, unsigned index)
{
    if (hw_step()) return -ENOMEM;
    assert(!lni.claimed); lni.claimed = true; lni.idx = index;
    INIT_LIST_HEAD(&lni.channels); *out = &lni; return 0;
}
static int qman_ceetm_lni_release(struct qm_ceetm_lni *p)
{ assert(p->claimed && list_empty(&p->channels)); p->claimed = false; return 0; }
static int qman_ceetm_sp_release(struct qm_ceetm_sp *p)
{ assert(p->claimed && !lni.claimed); p->claimed = false; return 0; }
static int qman_ceetm_configure_mapping_shaper_tcfc(struct qm_mcc_ceetm_mapping_shaper_tcfc_config *cfg)
{ mapping_id = cfg->cid & ~CEETM_COMMAND_CHANNEL_MAPPING; return hw_step(); }
static void dpa_disable_ceetm(struct net_device *dev) { dev->priv.ceetm_en = false; }
static void synchronize_net(void) {}
static int ceetm_enable_or_disable_qos(QM_context_ctl *ctx, unsigned enable)
{ assert(!enable); ctx->qos_enabled = 0; return 0; }
static int qman_ceetm_query_cq(unsigned id, unsigned fm, struct qm_mcr_ceetm_cq_query *query)
{
    assert(id >= (32 << 4));
    queries++;
    if (fail_query) { fail_query = false; return -EIO; }
    if (hw_step()) return -EIO;
    query->frm_cnt = pending_frames;
    if (pending_frames && !hold_frames) pending_frames--;
    return 0;
}
static bool qman_eqcr_is_empty(void)
{ if (pending_enqueues) { pending_enqueues--; return false; } return true; }
static void qman_drain_ern(void) { pending_erns = 0; }
static int qman_affine_cpus(void) { return 1; }
static void on_each_cpu_mask(int mask, void (*func)(void *), void *arg, int wait) { func(arg); }
static void cpus_read_lock(void) {}
static void cpus_read_unlock(void) {}
static void udelay(unsigned delay) {}
static void usleep_range(unsigned low, unsigned high) { jiffies++; }
#define msecs_to_jiffies(ms) (ms)
#define time_after_eq(a, b) ((a) >= (b))
static int disable_dscp_fqid_map(unsigned id) { assert(id < MAX_PHY_PORTS); return 0; }
static struct cdx_port_info *get_dpa_port_info(char *name) { return &port; }
#define qman_ceetm_channel_enable_shaper(...) hw_step()
#define qman_ceetm_channel_set_commit_rate(...) hw_step()
#define qman_ceetm_channel_set_excess_rate(...) hw_step()
#define qman_ceetm_channel_set_cq_cr_eligibility(...) hw_step()
#define qman_ceetm_channel_set_cq_er_eligibility(...) hw_step()
#define qman_ceetm_channel_set_group_cr_eligibility(...) hw_step()
#define qman_ceetm_channel_set_group_er_eligibility(...) hw_step()
#define qman_ceetm_ratio2wbfs(...) hw_step()
#define qman_ceetm_set_queue_weight(...) hw_step()
#define qman_ceetm_lfq_set_context(...) hw_step()
#define qman_ceetm_channel_set_group(...) hw_step()
#define qman_ceetm_ccg_set(...) hw_step()
#define EVENT_QM 1
static void M_qm_cmdproc(void) {}
static void set_cmd_handler(unsigned event, void *handler)
{
    if (handler) assert(callbacks);
    command_handler = !!handler;
}
#include "qos_production.inc"

static void empty(void)
{
    assert(!allocations && !channels && !lfqs && !fqs && !profiles);
    assert(!callbacks && !command_handler && !lni.claimed && !sp.claimed);
    for (unsigned i = 0; i < MAX_PHY_PORTS; i++) assert(!gQMCtx[i].net_dev);
}
static int start(void)
{
    int ret = qm_init();
    if (ret) { empty(); return ret; }
    ret = ceetm_init_cq_plcr();
    if (ret) assert(!profiles);
    return ret;
}
static unsigned cycle(unsigned failure)
{
    unsigned total;
    step = 0; fail_at = failure; next_channel = 32;
    int ret = start();
    total = step;
    assert(failure ? ret < 0 : ret == 0);
    qm_exit(); qm_exit(); empty();
    return total;
}
int main(void)
{
    pending_enqueues = 1001;
    assert(ceetm_sync_portals() == -ETIMEDOUT);
    pending_enqueues = 0;
    assert(ceetm_sync_portals() == 0);
    unsigned count = cycle(0);
    for (unsigned i = 1; i <= count; i++) { cycle(i); cycle(0); }
    fail_at = 0;
    assert(start() == 0);
    struct net_device dev = {0};
    struct dpa_iface_info iface = {.name = "eth0", .eth_info = {&dev, 1}};
    port.portid = MAX_PHY_PORTS - 1;
    for (unsigned failure = 1; failure <= 2; failure++) {
        fail_at = step + failure;
        assert(cdx_enable_ceetm_on_iface(&iface) < 0);
        assert(!lni.claimed && !sp.claimed && !dev.priv.qm_ctx);
        assert(!gQMCtx[port.portid].iface_info && !gQMCtx[port.portid].net_dev);
    }
    fail_at = 0;
    assert(cdx_enable_ceetm_on_iface(&iface) == 0);
    assert(cdx_enable_ceetm_on_iface(&iface) < 0);
    QM_context_ctl *ctx = &gQMCtx[port.portid];
    assert(!ceetm_get_egressfq(ctx, 0, 0, 0));
    assert(!ceetm_get_egressfq(NULL, 1, 0, 0));
    fail_at = step + 1;
    assert(ceetm_assign_chnl(ctx, 0) < 0);
    assert(!ctx->chnl_map && !qm_chnl_info[0].qm_ctx && list_empty(&lni.channels));
    fail_at = 0;
    assert(ceetm_assign_chnl(ctx, 0) == 0);
    assert(mapping_id == qm_chnl_info[0].channel->idx);
    assert(ceetm_get_egressfq(ctx, 0, 0, 0) == &qm_chnl_info[0].cq_info[0].ceetmfq.egress_fq);
    assert(!ceetm_get_egressfq(ctx, 2, 0, 0));
    assert(!ceetm_get_egressfq(ctx, CDX_CEETM_MAX_CHANNELS + 1, 0, 0));
    assert(!ceetm_get_egressfq(ctx, 1, MAX_SCHEDULER_QUEUES, 0));
    assert(!ceetm_get_egressfq(&gQMCtx[0], 1, 0, 0));
    ctx->dscp_fq_map = kzalloc(sizeof(*ctx->dscp_fq_map), 0);
    dev.priv.ceetm_en = true;
    ctx->qos_enabled = true;
    pending_enqueues = pending_frames = pending_erns = 4;
    assert(cdx_disable_ceetm_on_iface(&iface) == 0);
    assert(!dev.priv.ceetm_en && !dev.priv.qm_ctx && !ctx->chnl_map);
    assert(!qm_chnl_info[0].qm_ctx && list_empty(&qm_chnl_info[0].channel->node));
    assert(!ceetm_get_egressfq(ctx, 0, 0, 0));
    assert(!pop_calls && queries >= MAX_SCHEDULER_QUEUES);
    assert(!pending_enqueues && !pending_frames && !pending_erns);
    for (unsigned i = 0; i < MAX_SCHEDULER_QUEUES; i++)
        assert(!qm_chnl_info[0].cq_info[i].ceetmfq.net_dev);
    assert(cdx_disable_ceetm_on_iface(&iface) == 0);
    assert(cdx_enable_ceetm_on_iface(&iface) == 0);
    assert(ceetm_assign_chnl(ctx, 0) == 0);
    for (unsigned query_failure = 0; query_failure < 2; query_failure++) {
        ctx->qos_enabled = dev.priv.ceetm_en = true;
        hold_frames = true; fail_query = query_failure; pop_errors = 2;
        pending_frames = ARRAY_SIZE(packets);
        for (unsigned i = 0; i < ARRAY_SIZE(packets); i++) {
            packets[i].id = i; packet_live[i] = true;
        }
        /* Report the drain timeout/query failure, but reclaim every packet
         * before the interface context or its netdev reference is released. */
        assert(cdx_disable_ceetm_on_iface(&iface) < 0);
        assert(!pending_frames && !pop_errors && pop_calls);
        for (unsigned i = 0; i < ARRAY_SIZE(packets); i++) assert(!packet_live[i]);
        assert(pool_releases == 2 * (query_failure + 1));
        assert(skb_releases == 2 * (query_failure + 1));
        assert(!dev.priv.qm_ctx);
        hold_frames = false;
        assert(cdx_enable_ceetm_on_iface(&iface) == 0);
        assert(ceetm_assign_chnl(ctx, 0) == 0);
    }
    qm_exit(); empty();
    assert(!dev.priv.qm_ctx && !dev.priv.ceetm_en);
    assert(start() == 0);
    release_error = true;
    assert(ceetm_exit() < 0);
    release_error = false;
    qm_exit(); empty();
    for (unsigned failure = 1; failure <= 3; failure++) {
        assert(start() == 0);
        release_fail_at = failure;
        assert(ceetm_exit() < 0);
        assert(allocations);
        qm_exit(); empty();
    }
    printf("%u startup fault points passed, with successful retries, repeated cleanup, interface reassignment and release errors\n", count);
    return 0;
}
