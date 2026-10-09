#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#ifndef DPAA_FWD_TX_QUEUES
#define DPAA_FWD_TX_QUEUES 8
#endif
#define QMAN_FQ_FLAG_DYNAMIC_FQID 1
#define QMAN_FQ_FLAG_TO_DCPORTAL 2
#define QMAN_INITFQ_FLAG_SCHED 1
#define QM_INITFQ_WE_FQCTRL 1
#define QM_INITFQ_WE_DESTWQ 2
#define QM_INITFQ_WE_CONTEXTB 4
#define QM_INITFQ_WE_CONTEXTA 8
#define QM_FQCTRL_PREFERINCACHE 1
#define QMAN_FQ_STATE_CHANGING 1
#define QMAN_FQ_STATE_ORL 2
#define QMAN_FQ_STATE_NE 4
#define QMAN_VOLATILE_FLAG_WAIT 1
#define QMAN_VOLATILE_FLAG_FINISH 2
#define QM_VDQCR_NUMFRAMES_TILLEMPTY 1
#define QM_DQRR_STAT_FD_VALID 0x10
#define QM_DQRR_STAT_UNSCHEDULED 0x02
#define QM_DQRR_STAT_FQ_EMPTY 0x80
#define QM_DQRR_STAT_DQCR_EXPIRED 0x01
#define QM_INITFQ_WE_CGID 0x10
#define QM_INITFQ_WE_OAC 0x20
#define QM_FQCTRL_CGE 2
#define QM_CGR_WE_MODE 1
#define QM_CGR_WE_CS_THRES 2
#define QM_CGR_WE_CSTD_EN 4
#define QM_CGR_WE_CSCN_EN 0x10
#define QM_CGR_EN 1
#define QMAN_CGR_FLAG_USE_INIT 1
#define QMAN_CGR_MODE_FRAME 1
#define SPEED_UNKNOWN (-1)
#define TX_DIR 1
#define FAILURE 1
#define DPA_ERROR(...) do { } while (0)
#define pr_warn_ratelimited(...) do { } while (0)
#define READ_ONCE(x) (x)
#define max_t(t, a, b) ((t)(a) > (t)(b) ? (t)(a) : (t)(b))
#define min_t(t, a, b) ((t)(a) < (t)(b) ? (t)(a) : (t)(b))
#define clamp_t(t, v, lo, hi) min_t(t, max_t(t, v, lo), hi)
#define VLAN_ETH_HLEN 18
#define ETH_DATA_LEN 1500
#define IF_TYPE_ETHERNET 0x1
#define IF_TYPE_PHYSICAL 0x100
#define netdev_warn(...) do { } while (0)
typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
enum qman_fq_state { qman_fq_state_oos, qman_fq_state_sched, qman_fq_state_retired };
enum qman_cb_dqrr_result { qman_cb_dqrr_consume, qman_cb_dqrr_stop };
enum qm_fd_format { qm_fd_contig, qm_fd_sg };
struct qm_fd { enum qm_fd_format format; unsigned bpid; uint64_t addr; };
struct qm_dqrr_entry { unsigned stat; struct qm_fd fd; };
struct qm_mr_entry { struct { struct qm_fd fd; } ern; };
struct qman_portal { unsigned unused; };
struct net_device { bool carrier; u32 speed; unsigned int mtu; };
struct qman_fq {
    unsigned fqid; bool acquired, proc; enum qman_fq_state state; u32 flags;
    struct {
        enum qman_cb_dqrr_result (*dqrr)(struct qman_portal *, struct qman_fq *,
                                       const struct qm_dqrr_entry *);
        void (*ern)(struct qman_portal *, struct qman_fq *, const struct qm_mr_entry *);
    } cb;
};
struct list_head { struct list_head *next; };
struct dpa_fq { struct qman_fq fq_base; struct list_head list; };
struct qm_mcc_initfq {
    unsigned fqid, count, we_mask;
    struct { unsigned fq_ctrl; struct { unsigned channel, wq; } dest;
             struct { unsigned hi, lo; } context_a; u8 cgid; } fqd;
};
struct qm_cgr_cs_thres { u64 bytes; };
struct qm_mcc_initcgr {
    unsigned we_mask;
    struct { unsigned mode, cstd_en, cscn_en; struct qm_cgr_cs_thres cs_thres; } cgr;
};
struct qman_cgr { u32 cgrid; };
struct ethtool_link_ksettings { struct { u32 speed; } base; };
/* What the port seeds the shared Ethernet pool with, for each CPU. */
struct port_bman_pool_info { u32 count; };
struct eth_iface_info {
    struct net_device *net_dev; u32 speed;
    struct qman_fq fwd_tx_fqinfo[DPAA_FWD_TX_QUEUES]; unsigned tx_channel_id, tx_wq;
    struct qman_cgr fwd_cgr; u32 fwd_cgr_speed;
    struct qman_fq sec_tx_fqinfo[DPAA_FWD_TX_QUEUES];
    struct qman_cgr sec_cgr; u32 fwd_cgr_mtu;
    struct port_bman_pool_info pool_info[1];
};
static unsigned cpus = 4;
static unsigned num_possible_cpus(void) { return cpus; }
struct dpa_iface_info {
    struct dpa_iface_info *next; u32 if_flags;
    struct eth_iface_info eth_info; void *tx_proc_entry; const char *name;
};
static struct dpa_iface_info iface;
/* The registered ports the resizers walk: this one. */
static struct dpa_iface_info *dpa_interface_info = &iface;
static struct net_device netdev;
static unsigned calls, fail, live, pending, syncs, drains, pauses;
static bool fault(void);
/* The congestion groups, both counting frames: 77 the forwarding queues', 78
 * the one for SEC's. Allocated, set up (with what), held by a lock. */
#define GROUPS 2
static struct { bool allocated, tail_drop, frames; u64 thres; } groups[GROUPS];
static bool devlist_locked;
static unsigned cgr_releases;
static int dpa_devlist_lock;
static bool any_group(void) { return groups[0].allocated || groups[1].allocated; }
static void spin_lock(int *lock) { assert(lock == &dpa_devlist_lock && !devlist_locked); devlist_locked = true; }
static void spin_unlock(int *lock) { assert(lock == &dpa_devlist_lock && devlist_locked); devlist_locked = false; }
static bool netif_carrier_ok(const struct net_device *dev) { return dev->carrier; }
static int __ethtool_get_link_ksettings(struct net_device *dev, struct ethtool_link_ksettings *ks)
{ assert(!devlist_locked); ks->base.speed = dev->speed; return 0; }
static void qm_cgr_cs_thres_set64(struct qm_cgr_cs_thres *th, u64 value, int roundup)
{ assert(roundup); th->bytes = value; }
static int qman_alloc_cgrid(u32 *id)
{
    if (fault()) return -1;
    /* SEC's group first, set up before the forwarding group publishes a
     * speed the resizers would act on; no queue yet for either. */
    assert(!live);
    if (id == &iface.eth_info.sec_cgr.cgrid) {
        assert(!groups[0].allocated && !groups[1].allocated);
        groups[1].allocated = true; *id = 78;
    } else {
        assert(id == &iface.eth_info.fwd_cgr.cgrid && !groups[0].allocated);
        assert(groups[1].allocated && groups[1].tail_drop);
        groups[0].allocated = true; *id = 77;
    }
    return 0;
}
static void qman_release_cgrid(u32 id)
{
    const struct qman_fq *set = id == 77 ? iface.eth_info.fwd_tx_fqinfo : iface.eth_info.sec_tx_fqinfo;

    /* QMan refuses (leaks) a group a live FQ still names. */
    assert((id == 77 || id == 78) && groups[id - 77].allocated);
    for (unsigned i = 0; i < DPAA_FWD_TX_QUEUES; i++) assert(!set[i].acquired);
    /* SEC's goes only once no resizer can reach it any more. */
    if (id == 78)
        assert(!iface.eth_info.fwd_cgr_speed);
    groups[id - 77].allocated = groups[id - 77].tail_drop = false; cgr_releases++;
}
static int qman_modify_cgr(struct qman_cgr *cgr, u32 flags, struct qm_mcc_initcgr *opts)
{
    assert((cgr->cgrid == 77 || cgr->cgrid == 78) && groups[cgr->cgrid - 77].allocated && opts);
    if (fault()) return -1;
    if (flags & QMAN_CGR_FLAG_USE_INIT) {
        /* Set up from scratch, or reset to nothing before the release. */
        bool tail_drop = (opts->we_mask & QM_CGR_WE_CSTD_EN) && opts->cgr.cstd_en == QM_CGR_EN;

        groups[cgr->cgrid - 77].tail_drop = tail_drop;
        if (tail_drop) {
            assert((opts->we_mask & (QM_CGR_WE_CSCN_EN | QM_CGR_WE_MODE)) ==
                   (QM_CGR_WE_CSCN_EN | QM_CGR_WE_MODE) && !opts->cgr.cscn_en);
            /* Frames, for what a queued frame holds is a buffer. */
            assert(opts->cgr.mode == QMAN_CGR_MODE_FRAME);
            groups[cgr->cgrid - 77].frames = opts->cgr.mode == QMAN_CGR_MODE_FRAME;
        } else {
            const struct qman_fq *set = cgr->cgrid == 77 ? iface.eth_info.fwd_tx_fqinfo
                                                         : iface.eth_info.sec_tx_fqinfo;

            for (unsigned i = 0; i < DPAA_FWD_TX_QUEUES; i++) assert(!set[i].acquired);
        }
    }
    if (opts->we_mask & QM_CGR_WE_CS_THRES) groups[cgr->cgrid - 77].thres = opts->cgr.cs_thres.bytes;
    return 0;
}
static unsigned returned_frames, released_frames, empty_completions;
static const struct qm_fd *expected_fd;
static struct qman_fq *proc_fqs[2 * DPAA_FWD_TX_QUEUES];
static void dpa_fd_release(const struct net_device *dev, const struct qm_fd *fd)
{
    (void)dev;
    assert(expected_fd && fd == expected_fd);
    assert(fd->addr && fd->bpid < 64);
    released_frames++;
}
static enum qman_cb_dqrr_result rx_drain(struct qman_portal *portal,
        struct qman_fq *fq, const struct qm_dqrr_entry *dq)
{
    (void)portal; (void)fq;
    if (dq->stat & QM_DQRR_STAT_FD_VALID) dpa_fd_release(NULL, &dq->fd);
    return qman_cb_dqrr_consume;
}
static void kfree(struct dpa_fq *fq)
{
    assert(!fq->fq_base.acquired);
    for (unsigned i = 0; i < 2 * DPAA_FWD_TX_QUEUES; i++)
        assert(!proc_fqs[i] || proc_fqs[i]->state == qman_fq_state_oos);
    free(fq);
}
static bool fault(void) { return ++calls == fail; }
/* Which of the port's two sets a queue belongs to. */
static bool sec_fq(const struct qman_fq *fq)
{
    return fq >= iface.eth_info.sec_tx_fqinfo &&
           fq < iface.eth_info.sec_tx_fqinfo + DPAA_FWD_TX_QUEUES;
}
static int qman_create_fq(unsigned id, unsigned flags, struct qman_fq *fq)
{
    (void)id; (void)flags;
    if (fault()) return -1;
    assert(!fq->acquired); fq->acquired = true;
    fq->fqid = sec_fq(fq) ? DPAA_FWD_TX_QUEUES + (fq - iface.eth_info.sec_tx_fqinfo)
                          : (unsigned)(fq - iface.eth_info.fwd_tx_fqinfo);
    live++; return 0;
}
static int qman_init_fq(struct qman_fq *fq, unsigned flags, void *arg)
{
    const struct qm_mcc_initfq *opts = arg;

    (void)flags;
    if (fault()) return -1;
    assert(fq->cb.ern && (opts->we_mask & QM_INITFQ_WE_CGID) && (opts->fqd.fq_ctrl & QM_FQCTRL_CGE));
    /* Each set joins its own group, which counts frames, and a per-frame
     * byte overhead would mean nothing to. */
    unsigned group = sec_fq(fq);
    assert(groups[group].allocated && groups[group].tail_drop && groups[group].frames);
    assert(opts->fqd.cgid == 77 + group && !(opts->we_mask & QM_INITFQ_WE_OAC));
    fq->state = qman_fq_state_sched; return 0;
}
static void qman_destroy_fq(struct qman_fq *fq, unsigned flags)
{
    (void)flags; assert(fq->acquired && !fq->proc && fq->state == qman_fq_state_oos);
    fq->acquired = false; assert(live); live--;
}
static int cdx_dpa_init_fault(void) { return fault(); }
static void cdx_create_type_fqid_info_in_procfs(struct qman_fq *fq, int dir, void *entry, void *arg)
{ (void)dir; (void)entry; (void)arg; assert(fq->acquired); fq->proc = true; proc_fqs[fq->fqid] = fq; }
static void cdx_remove_fqid_info_in_procfs(unsigned id)
{ assert(proc_fqs[id] && proc_fqs[id]->proc); proc_fqs[id]->proc = false; proc_fqs[id] = NULL; }
static void qman_fq_state(struct qman_fq *fq, enum qman_fq_state *state, u32 *flags)
{
    assert(fq->acquired);
    if (fq->flags & QMAN_FQ_STATE_CHANGING) {
        if (!pending--) { fq->flags &= ~QMAN_FQ_STATE_CHANGING; fq->state = qman_fq_state_retired; }
    }
    *state = fq->state; *flags = fq->flags;
}
static int qman_retire_fq(struct qman_fq *fq, void *flags)
{ (void)flags; assert(fq->acquired); fq->flags = QMAN_FQ_STATE_CHANGING | QMAN_FQ_STATE_NE; pending = 1; return 1; }
static int qman_volatile_dequeue(struct qman_fq *fq, unsigned flags, unsigned vdqcr)
{
    struct qman_portal portal = {0};
    unsigned frames = drains % 3;

    assert(flags == (QMAN_VOLATILE_FLAG_WAIT | QMAN_VOLATILE_FLAG_FINISH));
    assert(vdqcr == QM_VDQCR_NUMFRAMES_TILLEMPTY);
    assert(fq->state == qman_fq_state_retired && (fq->flags & QMAN_FQ_STATE_NE));
    /* QMan invokes this callback even for an empty VDQCR completion. */
    assert(fq->cb.dqrr);
    for (unsigned i = 0; i < frames; i++) {
        struct qm_dqrr_entry dq = {
            .stat = QM_DQRR_STAT_UNSCHEDULED | QM_DQRR_STAT_FD_VALID,
            .fd = { .format = i ? qm_fd_sg : qm_fd_contig,
                    .bpid = (fq->fqid + i) % 64, .addr = ++returned_frames },
        };
        unsigned before = released_frames;

        if (i + 1 == frames && drains % 2) {
            dq.stat |= QM_DQRR_STAT_FQ_EMPTY | QM_DQRR_STAT_DQCR_EXPIRED;
            fq->flags &= ~QMAN_FQ_STATE_NE;
        }
        expected_fd = &dq.fd;
        assert(fq->cb.dqrr(&portal, fq, &dq) == qman_cb_dqrr_consume);
        assert(released_frames == before + 1);
        expected_fd = NULL;
    }
    if (!frames || !(drains % 2)) {
        struct qm_dqrr_entry dq;
        unsigned before = released_frames;

        /* A completion without FD_VALID must never release its garbage FD. */
        memset(&dq, 0xff, sizeof(dq));
        dq.stat = QM_DQRR_STAT_UNSCHEDULED | QM_DQRR_STAT_FQ_EMPTY
                  | QM_DQRR_STAT_DQCR_EXPIRED;
        fq->flags &= ~QMAN_FQ_STATE_NE;
        assert(fq->cb.dqrr(&portal, fq, &dq) == qman_cb_dqrr_consume);
        assert(released_frames == before);
        empty_completions++;
    }
    drains++;
    return 0;
}
static int qman_oos_fq(struct qman_fq *fq)
{ assert(fq->state == qman_fq_state_retired && !fq->flags); fq->state = qman_fq_state_oos; return 0; }
static void synchronize_net(void) { syncs++; }
static void usleep_range(unsigned min, unsigned max) { (void)min; (void)max; assert(++pauses < 1000); }
#include "cdx_queues.inc"
int main(void)
{
    /* Two calls set up each group, then three per FQ of its set. */
    const unsigned set = DPAA_FWD_TX_QUEUES * 3 + 2;

    /* The largest frames a standard and a jumbo MTU admit, tagged, on the
     * wire; and what a port with four CPUs, each seeded 640 buffers, may hold
     * of the pool: half its own. */
    const unsigned standard = 1500 + 18 + 24, jumbo = 9000 + 18 + 24, share = 4 * 640 / 2;

    for (unsigned n = 1; n <= 2 * set; n++) {
        memset(&iface, 0, sizeof(iface)); calls = pauses = 0; fail = n;
        netdev = (struct net_device){ .carrier = n % 2, .speed = 1000, .mtu = 1500 };
        iface.eth_info.net_dev = &netdev; iface.eth_info.speed = 10000; iface.name = "eth4";
        iface.eth_info.pool_info[0].count = 640;
        unsigned released = cgr_releases;
        assert(create_fwd_tx_fqs(&iface)); assert(!live && !any_group());
        /* A group that was allocated went back exactly once: SEC's from
         * its own setup on, the forwarding group from its setup on. */
        assert(cgr_releases == released + (n > 1) + (n > 3));
        calls = pauses = fail = 0;
        assert(!create_fwd_tx_fqs(&iface)); assert(live == 2 * DPAA_FWD_TX_QUEUES);
        /* Sized for the link as it runs, and for the MAC's fastest while
         * there is none: as many of the largest frames as take 2 ms --
         * microseconds times Mbit/s is bits -- up to the port's share of the
         * pool, which 10 Gbit/s reaches. */
        assert(groups[0].tail_drop && groups[1].tail_drop && !devlist_locked);
        assert(iface.eth_info.fwd_cgr_speed == (netdev.carrier ? 1000u : 10000u));
        assert(iface.eth_info.fwd_cgr_mtu == 1500);
        assert(groups[0].thres == (netdev.carrier ? 1000u * 2000 / 8 / standard : share));
        assert(10000u * 2000 / 8 / standard > share);
        /* SEC's frames from a gigabit up: the port's share of its pool. */
        assert(groups[1].thres == IPSEC_EGRESS_FRAMES && IPSEC_EGRESS_FRAMES < IPSEC_BUFCOUNT);
        unsigned before = syncs;
        destroy_fwd_tx_fqs(&iface);
        assert(!live && syncs == before + 1 && !any_group() && !iface.eth_info.fwd_cgr_speed);
        assert(cgr_releases == released + (n > 1) + (n > 3) + 2);
        for (unsigned i = 0; i < 2 * DPAA_FWD_TX_QUEUES; i++) assert(!proc_fqs[i]);
    }
    /* A slow link still holds a few jumbo frames: no fewer than 64 KiB
     * makes, six of the largest frame sdk_fman lets a port take. */
    memset(&iface, 0, sizeof(iface)); calls = pauses = fail = 0;
    netdev = (struct net_device){ .carrier = true, .speed = 100, .mtu = 1500 };
    iface.eth_info.net_dev = &netdev; iface.eth_info.speed = 1000; iface.name = "eth0";
    iface.if_flags = IF_TYPE_ETHERNET | IF_TYPE_PHYSICAL;
    iface.eth_info.pool_info[0].count = 640;
    assert(64 * 1024 / 9600 == 6);
    assert(!create_fwd_tx_fqs(&iface) && groups[0].thres == 64 * 1024 / standard);
    /* SEC's group is sized the same way, below its own share. */
    assert(groups[1].thres == groups[0].thres && groups[1].thres < IPSEC_EGRESS_FRAMES);
    assert(iface.eth_info.fwd_cgr_mtu == 1500);
    /* Both follow the link: up to a gigabit, then back. */
    spin_lock(&dpa_devlist_lock);
    assert(!fwd_cgr_set(&iface.eth_info, 1000, false));
    spin_unlock(&dpa_devlist_lock);
    assert(groups[0].thres == 1000u * 2000 / 8 / standard && groups[1].thres == IPSEC_EGRESS_FRAMES);
    assert(groups[0].tail_drop && groups[1].tail_drop && groups[0].frames && groups[1].frames);
    spin_lock(&dpa_devlist_lock);
    assert(!fwd_cgr_set(&iface.eth_info, 100, false));
    spin_unlock(&dpa_devlist_lock);
    assert(groups[0].thres == 64 * 1024 / standard && groups[1].thres == 64 * 1024 / standard);
    /* A jumbo MTU: both groups follow the frame size. A gigabit's 2 ms of
     * the largest frames is 27, which a burst of standard ones would
     * overflow, so it holds two such bursts with room to spare instead. The
     * link reports no change, the MTU alone moved. */
    netdev = (struct net_device){ .carrier = true, .speed = 1000, .mtu = 1500 };
    dpa_fwd_cgr_follow_link(&netdev);
    assert(groups[1].thres == IPSEC_EGRESS_FRAMES && iface.eth_info.fwd_cgr_speed == 1000);
    netdev.mtu = 9000;
    dpa_fwd_cgr_follow_link(&netdev);
    assert(iface.eth_info.fwd_cgr_mtu == 9000 && !devlist_locked);
    assert(1000u * 2000 / 8 / jumbo == 27 && groups[0].thres == 128);
    assert(groups[1].thres == (128 < IPSEC_EGRESS_FRAMES ? 128 : IPSEC_EGRESS_FRAMES));
    /* A slower link at that MTU, and its carrier lost: the bound keeps the
     * speed it was sized for and still follows the MTU. */
    netdev.carrier = false;
    netdev.mtu = 1500;
    dpa_fwd_cgr_follow_link(&netdev);
    assert(iface.eth_info.fwd_cgr_speed == 1000 && iface.eth_info.fwd_cgr_mtu == 1500);
    assert(groups[0].thres == 1000u * 2000 / 8 / standard && groups[1].thres == IPSEC_EGRESS_FRAMES);
    /* Slower still, the bursts' floor is the 2 ms of standard frames there
     * are, as on a standard MTU. */
    netdev = (struct net_device){ .carrier = true, .speed = 100, .mtu = 9000 };
    dpa_fwd_cgr_follow_link(&netdev);
    assert(64 * 1024 / jumbo >= 6 && groups[0].thres == 64 * 1024 / standard);
    assert(groups[1].thres == groups[0].thres);
    /* At 10G, 2 ms of jumbo frames is more than the bursts need, and stays
     * below the port's share of the Ethernet pool; SEC's share of its own
     * pool is less. */
    netdev.speed = 10000;
    dpa_fwd_cgr_follow_link(&netdev);
    assert(groups[1].thres == IPSEC_EGRESS_FRAMES);
    assert(groups[0].thres == 10000u * 2000 / 8 / jumbo && groups[0].thres > 128 && groups[0].thres < share);
    /* A standard MTU at 10G reaches the Ethernet share: a paused port holds
     * no more than half of what it seeds, whatever it is sent (A341). */
    netdev.mtu = 1500;
    dpa_fwd_cgr_follow_link(&netdev);
    assert(groups[0].thres == share && groups[1].thres == IPSEC_EGRESS_FRAMES);
    /* With fewer CPUs, fewer buffers seeded, and a smaller share. */
    cpus = 2;
    spin_lock(&dpa_devlist_lock);
    assert(!fwd_cgr_set(&iface.eth_info, 10000, false));
    spin_unlock(&dpa_devlist_lock);
    assert(groups[0].thres == 2 * 640 / 2);
    cpus = 4;
    /* A rejected software enqueue goes back to its pool. */
    struct qm_mr_entry ern = { .ern.fd = { .bpid = 3, .addr = 0x1000 } };
    unsigned released_before = released_frames;
    expected_fd = &ern.ern.fd;
    iface.eth_info.fwd_tx_fqinfo[0].cb.ern(NULL, &iface.eth_info.fwd_tx_fqinfo[0], &ern);
    expected_fd = NULL;
    assert(released_frames == released_before + 1);
    destroy_fwd_tx_fqs(&iface);
    assert(!live && !any_group());
    struct dpa_fq *head = NULL;
    unsigned before = syncs;
    for (unsigned i = 0; i < 3; i++) {
        struct dpa_fq *fq = calloc(1, sizeof(*fq));
        assert(fq);
        fq->fq_base = (struct qman_fq){ .fqid = i, .acquired = true,
            .proc = true, .state = qman_fq_state_sched, .cb.dqrr = rx_drain };
        proc_fqs[i] = &fq->fq_base; live++;
        fq->list.next = (struct list_head *)head; head = fq;
    }
    cdx_destroy_fq_list(&head);
    assert(!head && !live && syncs == before + 1);
    cdx_destroy_fq_list(&head);
    assert(syncs == before + 1);
    assert(drains && syncs && empty_completions && released_frames);
    assert(returned_frames + 1 == released_frames);
    printf("CDX queues: %u partial-creation faults, %u frames released, %u empty completions; congestion groups, asynchronous retirement, drain and retry passed\n",
           2 * set, released_frames, empty_completions);
    return 0;
}
