/* Compile the receive callback and secpath initializer with poisoned metadata
 * and independently accounted FD, skb and SA ownership. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>

typedef int gro_result_t;
#define likely(x) (x)
#define unlikely(x) (x)
#define DPAIPSEC_ERROR(...) do {} while (0)
#define DPA_BUG_ON(x) assert(!(x))
#define QM_DQRR_STAT_FD_VALID 1
#define FM_FD_RX_STATUS_ERR_NON_FM 2
#define NETIF_F_GRO 1
#define SKB_EXT_SEC_PATH 1
#define THRESHOLD_IPSEC_BPOOL_REFILL 10
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_IPV6 0x86dd
#define ETH_HLEN 14
#define raw_cpu_ptr(p) (p)
#define phys_to_virt(a) ((void *)(uintptr_t)(a))
#define qm_fd_contig 0
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
#define smp_load_acquire(p) (*(p))
#define smp_store_release(p, v) (*(p) = (v))
#define DMA_BIDIRECTIONAL 0
#define qm_fd_addr(p) ((p)->addr)
typedef int atomic_t;
#define ATOMIC_INIT(v) (v)
static int atomic_read(atomic_t *p) { return *p; }
static void atomic_set(atomic_t *p, int v) { *p = v; }
static int atomic_add_return(int v, atomic_t *p) { *p += v; return *p; }
static void atomic_dec(atomic_t *p) { assert(*p > 0); --*p; }
struct work_struct { int unused; };
struct delayed_work { struct work_struct work; bool queued; unsigned long delay; };
#define DECLARE_DELAYED_WORK(name, fn) struct delayed_work name
static unsigned long msecs_to_jiffies(unsigned long ms) { return ms; }
static bool schedule_delayed_work(struct delayed_work *w, unsigned long delay)
{ if (w->queued) return false; w->queued = true; w->delay = delay; return true; }
#define system_wq NULL
static bool mod_delayed_work(void *q, struct delayed_work *w, unsigned long delay)
{ w->queued = true; w->delay = delay; return true; }
static void cancel_delayed_work_sync(struct delayed_work *w) { w->queued = false; }

enum qman_cb_dqrr_result { qman_cb_dqrr_consume, qman_cb_dqrr_stop };
struct qman_portal { int unused; };
struct qman_fq { int unused; };
struct qm_fd { uintptr_t addr; unsigned offset, length20, bpid, status, format; };
struct qm_dqrr_entry { struct qm_fd fd; unsigned stat, fqid; };
struct qman_portal_config { unsigned index; };
struct dpa_napi_portal { struct qman_portal *p; int napi; };
struct dpa_percpu_priv_s { unsigned rx_sg; struct dpa_napi_portal np[1]; };
struct dpa_priv_s { struct dpa_percpu_priv_s *percpu_priv; int *percpu_count; };
struct net_device { unsigned features; const char *name; };
struct dpa_bp { unsigned count; void *dev; unsigned size; };
struct xfrm_state { struct { unsigned long use_time; } curlft; };
struct sec_path { int len, olen, verified_cnt; struct xfrm_state *xvec[6]; unsigned ovec[24]; };
struct sk_buff { struct net_device *dev; unsigned protocol, mac_len; struct sec_path path; bool has_path; unsigned char *data; };
struct timespec64 { unsigned long tv_sec; };
static unsigned refs, fd_releases, skb_frees, delivered, converted, sg_buffers, added, concurrent, unmapped;
static unsigned char *received_data;
static unsigned int reaped;
static unsigned int dpaa_sec_sg_reap(unsigned int budget)
{ assert(budget == 64); reaped++; return 0; }

static bool no_device, no_state, napi_defer, refill_fail, secpath_fail, short_frame;
static struct xfrm_state state;
static struct sk_buff packet;
static struct net_device device = { .name = "eth4" };
static struct dpa_bp pool;
static struct dpa_bp *dpa_bpid2pool(unsigned id) { (void)id; return &pool; }
static void dma_unmap_single(void *dev, uintptr_t addr, unsigned size, int direction)
{ (void)dev; (void)addr; (void)size; (void)direction; assert(!unmapped && !converted); unmapped++; }
static bool pskb_may_pull(struct sk_buff *skb, unsigned bytes)
{ assert(skb->data && bytes == ETH_HLEN + 1); return !short_frame; }
static struct { struct dpa_bp *ipsec_bp; } ipsecinfo = { .ipsec_bp = &pool };
static void ipsec_pool_consumed(unsigned int count);
static int dpaa_bp_alloc_n_add_buffs(struct dpa_bp *p, unsigned count, bool skb)
{
    assert(p == &pool && count == 1 && skb);
    if (refill_fail) return -ENOMEM;
    if (concurrent) {
        assert(pool.count >= concurrent);
        pool.count -= concurrent;
        ipsec_pool_consumed(concurrent);
        concurrent = 0;
    }
    assert(pool.count < 512);
    pool.count++; added++;
    return 0;
}
static struct dpa_percpu_priv_s cpu;
static int bp_count;
static struct dpa_priv_s priv = { .percpu_priv = &cpu, .percpu_count = &bp_count };
static void *skb_ext_find(struct sk_buff *skb, int kind)
{ (void)kind; return skb->has_path ? &skb->path : NULL; }
static void *skb_ext_add(struct sk_buff *skb, int kind)
{ (void)kind; if (secpath_fail) return NULL; skb->has_path = true; return &skb->path; }
static struct net_device *get_netdev_of_SA_by_fqid(unsigned fqid, unsigned short *handle)
{ (void)fqid; *handle = 7; return no_device ? NULL : &device; }
static void *dev_net(struct net_device *dev) { return dev; }
static struct xfrm_state *xfrm_state_lookup_byhandle(void *net, unsigned handle)
{ (void)net; assert(handle == 7); if (no_state) return NULL; refs++; return &state; }
static void xfrm_state_put(struct xfrm_state *x) { assert(x == &state && refs); refs--; }
static struct dpa_priv_s *netdev_priv(struct net_device *dev) { assert(dev == &device); return &priv; }
#ifndef CONFIG_FSL_ASK_QMAN_PORTAL_NAPI
static bool dpaa_eth_napi_schedule(struct dpa_percpu_priv_s *p, struct qman_portal *q)
{ (void)p; (void)q; return napi_defer; }
#endif
static int vwd_is_no_l2_itf_device(struct net_device *dev) { (void)dev; return 0; }
static struct sk_buff *contig_fd_to_skb(struct dpa_priv_s *p, const struct qm_fd *fd, bool *gro, bool ts)
{ (void)p; (void)fd; (void)gro; (void)ts; assert(unmapped && !converted && pool.count); pool.count--; converted++; packet.data = received_data; return &packet; }
static struct sk_buff *sg_fd_to_skb(struct dpa_priv_s *p, const struct qm_fd *fd, bool *gro, int *count, bool ts)
{
    struct sk_buff *skb = contig_fd_to_skb(p, fd, gro, ts);
    assert(count != priv.percpu_count && pool.count >= sg_buffers - 1);
    pool.count -= sg_buffers - 1;
    *count -= sg_buffers;
    ++*count; /* The SGT returns to BMan. */
    return skb;
}
static void skb_pull(struct sk_buff *skb, int n) { (void)skb; (void)n; }
static void skb_reset_network_header(struct sk_buff *skb) { (void)skb; }
static unsigned eth_type_trans(struct sk_buff *skb, struct net_device *dev)
{ unsigned short type; (void)dev; memcpy(&type, skb->data + 12, 2); return type; }
static void ktime_get_real_ts64(struct timespec64 *t) { t->tv_sec = 1; }
static const struct qman_portal_config *qman_p_get_portal_config(struct qman_portal *q)
{ static struct qman_portal_config pc; (void)q; return &pc; }
static void dev_kfree_skb(struct sk_buff *skb)
{
    assert(skb == &packet && converted == 1 && !skb_frees && !fd_releases);
    skb_frees++;
    if (skb->has_path) {
        assert(skb->path.len >= 0 && skb->path.len <= 1);
        if (skb->path.len) xfrm_state_put(skb->path.xvec[0]);
    }
}
static void netif_receive_skb(struct sk_buff *skb)
{
    assert(skb->path.len == 1 && skb->path.xvec[0] == &state);
    assert(skb->path.olen == 0 && skb->path.verified_cnt == 0);
    for (unsigned i = 0; i < sizeof(skb->path.ovec) / sizeof(skb->path.ovec[0]); i++)
        assert(skb->path.ovec[i] == 0);
    delivered++;
    dev_kfree_skb(skb);
}
static int napi_gro_receive(int *napi, struct sk_buff *skb)
{ (void)napi; netif_receive_skb(skb); return 0; }
static void dpa_fd_release(struct net_device *dev, const struct qm_fd *fd)
{ (void)dev; (void)fd; assert(!unmapped && !converted && !skb_frees && !fd_releases); fd_releases++; }
static void pr_err_ratelimited(const char *fmt, ...) { (void)fmt; }
#include "ipsec_receive_production.inc"

static void reset(void)
{
    assert(!refs);
    refs = fd_releases = skb_frees = delivered = converted = unmapped = 0;
    no_device = no_state = napi_defer = refill_fail = secpath_fail = short_frame = false;
    memset(&packet, 0, sizeof(packet));
    memset(&packet.path, 0xa5, sizeof(packet.path));
    bp_count = 640;
    pool.count = 512;
    added = concurrent = 0;
    sg_buffers = 3;
    ipsec_refill_work.queued = false;
    ipsec_pool_refill_start();
}
static void run_refill(void)
{
    assert(ipsec_refill_work.queued);
    ipsec_refill_work.queued = false;
    ipsec_pool_refill_work(&ipsec_refill_work.work);
}
int main(void)
{
    unsigned char frame[64] = { [12] = 8, [14] = 0x45 };
    unsigned char table[64] = {0};
    received_data = frame;
    struct qm_dqrr_entry dq = { .stat = QM_DQRR_STAT_FD_VALID,
        .fd = { .addr = (uintptr_t)frame, .length20 = sizeof(frame) } };
    struct qman_portal portal;
    struct qman_fq fq;
    for (unsigned sg = 0; sg < 2; sg++) for (unsigned gro = 0; gro < 2; gro++) {
        dq.fd.format = sg;
        dq.fd.addr = (uintptr_t)(sg ? table : frame);
        device.features = gro ? NETIF_F_GRO : 0;
        for (unsigned fault = 0; fault < 8; fault++) {
            reset();
            no_device = fault == 1; no_state = fault == 2;
            refill_fail = fault == 3; secpath_fail = fault == 4;
            short_frame = fault == 7;
            dq.fd.status = fault == 5 ? FM_FD_RX_STATUS_ERR_NON_FM : 0;
            dq.stat = fault == 6 ? 0 : QM_DQRR_STAT_FD_VALID;
            assert(ipsec_exception_pkt_handler(&portal, &fq, &dq) == qman_cb_dqrr_consume);
            assert(!refs);
            if (!fault || fault == 3) assert(delivered == 1 && skb_frees == 1 && !fd_releases);
            if (fault == 4 || fault == 7) assert(!delivered && skb_frees == 1 && !fd_releases);
            if (fault == 1 || fault == 2 || fault == 5) assert(fd_releases == 1 && !skb_frees);
            if (fault == 6) assert(!fd_releases && !skb_frees);
            assert(bp_count == 640);
            if (converted) {
                unsigned consumed = sg ? sg_buffers : 1;
                assert(pool.count == 512 - consumed && ipsec_pool_debt == (int)consumed);
                run_refill();
                if (refill_fail) {
                    assert(!added && ipsec_refill_work.queued && ipsec_refill_work.delay == 20);
                    refill_fail = false;
                    run_refill();
                }
                assert(pool.count == 512 && added == consumed && !ipsec_pool_debt);
            }
        }
        for (unsigned v6 = 0; v6 < 2; v6++) {
            reset(); dq.stat = QM_DQRR_STAT_FD_VALID; dq.fd.status = 0;
            frame[12] = v6 ? 8 : 0x86; frame[13] = v6 ? 0 : 0xdd;
            frame[14] = v6 ? 0x60 : 0x45;
            assert(ipsec_exception_pkt_handler(&portal, &fq, &dq) == qman_cb_dqrr_consume);
            assert(delivered == 1 && packet.protocol == htons(v6 ? ETHERTYPE_IPV6 : ETHERTYPE_IPV4));
            for (unsigned i = 0; i < sizeof(table); i++) assert(table[i] == 0);
            run_refill();
        }
#ifndef CONFIG_FSL_ASK_QMAN_PORTAL_NAPI
        reset(); dq.stat = QM_DQRR_STAT_FD_VALID; dq.fd.status = 0; napi_defer = true;
        assert(ipsec_exception_pkt_handler(&portal, &fq, &dq) == qman_cb_dqrr_stop);
        assert(!refs && !converted && !fd_releases && !skb_frees);
#endif
    }
    /* Exhaust the whole pool under allocation pressure. Only the queued
     * worker can recover it: no receive event or SA recreation follows. */
    reset();
    pool.count = 0;
    ipsec_pool_consumed(512);
    refill_fail = true;
    for (unsigned retry = 0; retry < 5; retry++) {
        run_refill();
        assert(!pool.count && ipsec_pool_debt == 512 && ipsec_refill_work.delay == 20);
    }
    refill_fail = false;
    while (ipsec_pool_debt) run_refill();
    assert(pool.count == 512 && added == 512 && !ipsec_pool_debt);
    assert(ipsec_refill_work.queued && ipsec_refill_work.delay == 20);
    unsigned int previous_reaped = reaped;
    run_refill();
    assert(reaped == previous_reaped + 1 && ipsec_refill_work.queued);
    assert(ipsec_refill_work.delay == 20);
    /* New receive debt during refill is neither lost nor counted twice. */
    pool.count -= 8;
    ipsec_pool_consumed(8);
    assert(ipsec_refill_work.queued && ipsec_refill_work.delay == 0);
    concurrent = 5;
    while (ipsec_pool_debt) run_refill();
    assert(pool.count == 512 && added == 525 && !ipsec_pool_debt);
    ipsec_pool_consumed(1);
    ipsec_pool_refill_stop();
    assert(!ipsec_refill_work.queued);
    ipsec_pool_refill_work(&ipsec_refill_work.work);
    assert(added == 525);
}
