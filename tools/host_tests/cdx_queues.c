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
#define TX_DIR 1
#define FAILURE 1
#define DPA_ERROR(...) do { } while (0)
#define pr_warn_ratelimited(...) do { } while (0)
typedef uint32_t u32;
enum qman_fq_state { qman_fq_state_oos, qman_fq_state_sched, qman_fq_state_retired };
struct qman_fq { unsigned fqid; bool acquired, proc; enum qman_fq_state state; u32 flags; };
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
static struct qman_fq *proc_fqs[DPAA_FWD_TX_QUEUES];
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
{ (void)flags; (void)vdqcr; assert(fq->flags & QMAN_FQ_STATE_NE); fq->flags &= ~QMAN_FQ_STATE_NE; drains++; return 0; }
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
            .proc = true, .state = qman_fq_state_sched };
        proc_fqs[i] = &fq->fq_base; live++;
        fq->list.next = (struct list_head *)head; head = fq;
    }
    cdx_destroy_fq_list(&head);
    assert(!head && !live && syncs == before + 1);
    cdx_destroy_fq_list(&head);
    assert(syncs == before + 1);
    assert(drains && syncs);
    printf("CDX queues: %u partial-creation faults, asynchronous retirement, drain and retry passed\n", DPAA_FWD_TX_QUEUES * 3);
    return 0;
}
