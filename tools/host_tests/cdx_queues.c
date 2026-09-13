#include <assert.h>
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
#define TX_DIR 1
#define FAILURE 1
#define DPA_ERROR(...) do { } while (0)
#define pr_warn_ratelimited(...) do { } while (0)
typedef uint32_t u32;
enum qman_fq_state { qman_fq_state_oos, qman_fq_state_sched, qman_fq_state_retired };
enum qman_cb_dqrr_result { qman_cb_dqrr_consume, qman_cb_dqrr_stop };
enum qm_fd_format { qm_fd_contig, qm_fd_sg };
struct qm_fd { enum qm_fd_format format; unsigned bpid; uint64_t addr; };
struct qm_dqrr_entry { unsigned stat; struct qm_fd fd; };
struct qman_portal { unsigned unused; };
struct net_device;
struct qman_fq {
    unsigned fqid; bool acquired, proc; enum qman_fq_state state; u32 flags;
    struct {
        enum qman_cb_dqrr_result (*dqrr)(struct qman_portal *, struct qman_fq *,
                                       const struct qm_dqrr_entry *);
    } cb;
};
struct list_head { struct list_head *next; };
struct dpa_fq { struct qman_fq fq_base; struct list_head list; };
struct qm_mcc_initfq {
    unsigned fqid, count, we_mask;
    struct { unsigned fq_ctrl; struct { unsigned channel, wq; } dest;
             struct { unsigned hi, lo; } context_a; } fqd;
};
struct eth_iface_info { struct qman_fq fwd_tx_fqinfo[DPAA_FWD_TX_QUEUES]; unsigned tx_channel_id, tx_wq; };
struct dpa_iface_info { struct eth_iface_info eth_info; void *tx_proc_entry; };
static struct dpa_iface_info iface;
static unsigned calls, fail, live, pending, syncs, drains, pauses;
static unsigned returned_frames, released_frames, empty_completions;
static const struct qm_fd *expected_fd;
static struct qman_fq *proc_fqs[DPAA_FWD_TX_QUEUES];
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
    for (unsigned i = 0; i < DPAA_FWD_TX_QUEUES; i++)
        assert(!proc_fqs[i] || proc_fqs[i]->state == qman_fq_state_oos);
    free(fq);
}
static bool fault(void) { return ++calls == fail; }
static int qman_create_fq(unsigned id, unsigned flags, struct qman_fq *fq)
{
    (void)id; (void)flags;
    if (fault()) return -1;
    assert(!fq->acquired); fq->acquired = true; fq->fqid = fq - iface.eth_info.fwd_tx_fqinfo;
    live++; return 0;
}
static int qman_init_fq(struct qman_fq *fq, unsigned flags, void *opts)
{
    (void)flags; (void)opts;
    if (fault()) return -1;
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
    for (unsigned n = 1; n <= DPAA_FWD_TX_QUEUES * 3; n++) {
        memset(&iface, 0, sizeof(iface)); calls = pauses = 0; fail = n;
        assert(create_fwd_tx_fqs(&iface)); assert(!live);
        calls = pauses = fail = 0;
        assert(!create_fwd_tx_fqs(&iface)); assert(live == DPAA_FWD_TX_QUEUES);
        unsigned before = syncs;
        destroy_fwd_tx_fqs(&iface);
        assert(!live && syncs == before + 1);
        for (unsigned i = 0; i < DPAA_FWD_TX_QUEUES; i++) assert(!proc_fqs[i]);
    }
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
    assert(returned_frames == released_frames);
    printf("CDX queues: %u partial-creation faults, %u frames released, %u empty completions; asynchronous retirement, drain and retry passed\n",
           DPAA_FWD_TX_QUEUES * 3, released_frames, empty_completions);
    return 0;
}
