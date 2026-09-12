/* Execute production transport and wrapper code; only QMan, memory, time and
 * spinlocks are substituted. Static DMA storage fits the FD's 40-bit address. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define __CORE_EXT_H
#define CORE_MemoryBarrier() ((void)0)
#define __ERR_MODULE__ MODULE_FM
#include "fm_pcd.h"
#include "fm_hc.h"
#undef ASSERT_COND
#undef REPORT_ERROR
#undef RETURN_ERROR
#undef DBG
#define ASSERT_COND assert
#define REPORT_ERROR(level, err, msg) ((void)0)
#define RETURN_ERROR(level, err, msg) return ERROR_CODE(err)
#define DBG(level, msg) ((void)0)
#include "hc_layout.inc"

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
enum qm_fd_format { qm_fd_contig, qm_fd_last = 7 };
#define __aligned(n) __attribute__((aligned(n)))
#include "qman_layout.inc"
#define qm_fd_addr(fd) ((fd)->addr)
#define ___constant_swab32 __builtin_bswap32
struct qman_portal { int unused; };
struct qman_fq { int unused; };
struct qm_dqrr_entry { struct qm_fd fd; };
enum qman_cb_dqrr_result { qman_cb_dqrr_consume };
typedef struct { t_Handle h_PcdDev; struct qman_fq *hc_tx_fq; } t_LnxWrpFmDev;
typedef struct { struct qman_fq fq; t_Handle h_Arg; } t_FmTestFq;
static int qman_enqueue(struct qman_fq *, const struct qm_fd *, u32);
#include "hc_wrapper.inc"
#include "hc_production.inc"

struct spin { bool held; };
static unsigned delays, confirm_at, submissions, frees, port_frees;
static int allocation_budget = -1;
static bool reject, inline_confirm, confirm_on_timeout, nested_command;
static t_FmHc *active;
static t_LnxWrpFmDev device;
static t_FmTestFq confirmation_queue;
static struct qm_dqrr_entry pending;
static unsigned char dma[HC_CMD_POOL_SIZE][512] __aligned(16);
static bool allocated[HC_CMD_POOL_SIZE];
static void confirm(void);

void XX_Print(char *format, ...) { assert(!"unexpected SDK assertion"); }
void XX_Exit(int status) { assert(!"unexpected SDK exit"); }
physAddress_t XX_VirtToPhys(void *p) { return (uintptr_t)p; }
void *XX_PhysToVirt(physAddress_t p) { return (void *)(uintptr_t)p; }
void *XX_MallocSmart(uint32_t size, int partition, uint32_t alignment)
{
    assert(size <= sizeof(dma[0]) && alignment == 16);
    if (!allocation_budget) return NULL;
    if (allocation_budget > 0) allocation_budget--;
    for (unsigned i = 0; i < HC_CMD_POOL_SIZE; i++)
        if (!allocated[i]) { allocated[i] = true; return dma[i]; }
    assert(!"DMA pool exhausted");
    return NULL;
}
void XX_FreeSmart(void *p)
{
    for (unsigned i = 0; i < HC_CMD_POOL_SIZE; i++)
        if (p == dma[i]) { assert(allocated[i]); allocated[i] = false; frees++; return; }
    assert(!"not a DMA allocation");
}
void XX_Free(void *p) { free(p); }
void XX_FreeSpinlock(t_Handle p) { assert(!((struct spin *)p)->held); free(p); }
uint32_t XX_LockIntrSpinlock(t_Handle p)
{ struct spin *s = p; assert(s && !s->held); s->held = true; return 0; }
void XX_UnlockIntrSpinlock(t_Handle p, uint32_t flags)
{
    struct spin *s = p;
    assert(s && s->held && !flags); s->held = false;
    if (active && active->failed && confirm_on_timeout) {
        confirm_on_timeout = false;
        confirm(); /* Between the timeout decision and the caller's PutBuf. */
    }
}
t_Error FM_PORT_Free(t_Handle p) { port_frees++; return E_OK; }
void FM_PCD_HcTxConf(t_Handle p, t_DpaaFD *fd) { FmHcTxConf(p, fd); }
static void confirm(void)
{
    assert(qm_tx_conf_dqrr_cb(NULL, &confirmation_queue.fq, &pending) == qman_cb_dqrr_consume);
}
void XX_UDelay(uint32_t usecs)
{
    assert(usecs == HC_CONFIRM_POLL_US && !((struct spin *)active->h_Spinlock)->held);
    if (++delays == confirm_at) confirm();
}
static int qman_enqueue(struct qman_fq *fq, const struct qm_fd *fd, u32 flags)
{
    assert(!flags && !((struct spin *)active->h_Spinlock)->held);
    submissions++;
    pending.fd = *fd;
    const unsigned char *bytes = XX_PhysToVirt(qm_fd_addr(fd));
    assert(fd->length20 == sizeof(t_HcFrame));
    /* The sync command must reach QMan in hardware byte order. */
    assert(bytes[0] == 0x20 && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 2);
    if (reject) return -EBUSY;
    if (nested_command) {
        /* A second caller completes while the first still owns its command.
         * Neither completion may wait for a global outstanding-frame count. */
        struct qm_dqrr_entry outer = pending;
        nested_command = false;
        inline_confirm = true;
        assert(FmHcPcdSync(active) == E_OK);
        assert(active->nextSeqNumLocation == 1 && !delays);
        pending = outer;
    }
    if (inline_confirm) confirm();
    return 0;
}
static t_FmHc *setup(void)
{
    for (unsigned i = 0; i < HC_CMD_POOL_SIZE; i++) assert(!allocated[i]);
    active = calloc(1, sizeof(*active));
    active->h_Spinlock = calloc(1, sizeof(struct spin));
    active->usageAllowed = true;
    active->f_QmEnqueue = QmEnqueueCB;
    active->h_QmArg = &device;
    device.h_PcdDev = active;
    confirmation_queue.h_Arg = &device;
    reject = inline_confirm = confirm_on_timeout = nested_command = false;
    delays = confirm_at = submissions = frees = port_frees = 0;
    allocation_budget = -1;
    assert(FillBufPool(active) == E_OK);
    return active;
}
static void dispose(t_FmHc *hc)
{
    /* Fixture reset only: all hardware ownership must have ended first. The
     * production API deliberately offers no way to clear the failure latch. */
    assert(!hc->nextSeqNumLocation);
    hc->failed = false;
    assert(FmHcFree(hc) == E_OK);
    active = NULL;
    for (unsigned i = 0; i < HC_CMD_POOL_SIZE; i++) assert(!allocated[i]);
}
static void refuses_teardown(t_FmHc *hc)
{
    unsigned before = frees;
    assert(FmHcFree(hc) != E_OK);
    assert(FmHcSetFramesDataMemory(hc, 1) != E_OK);
    assert(FmAllowHcUsage(hc, false) != E_OK);
    assert(FmAllowHcUsage(hc, true) != E_OK);
    assert(FmIsHcUsageAllowed(hc));
    assert(frees == before && !port_frees);
}
static void rejection_and_completion(void)
{
    t_FmHc *hc = setup();
    reject = true;
    for (unsigned n = 0; n < 2 * HC_CMD_POOL_SIZE; n++) {
        assert(GET_ERROR_TYPE(FmHcPcdSync(hc)) == E_INVALID_STATE);
        assert(!hc->nextSeqNumLocation && !hc->failed && !delays);
        t_HcFrame expected = {.opcode = HC_HCOR_GBL | HC_HCOR_OPCODE_SYNC};
        assert(!memcmp(hc->p_Frm[0], &expected, sizeof(expected)));
    }
    reject = false;
    inline_confirm = true;
    assert(FmHcPcdSync(hc) == E_OK && !hc->nextSeqNumLocation && !delays);
    inline_confirm = false;
    confirm_at = HC_CONFIRM_POLLS; /* Completion at the deadline wins. */
    assert(FmHcPcdSync(hc) == E_OK && !hc->failed);
    assert(delays == HC_CONFIRM_POLLS && !hc->nextSeqNumLocation);
    assert(FmAllowHcUsage(hc, false) == E_OK && !FmIsHcUsageAllowed(hc));
    assert(FmAllowHcUsage(hc, true) == E_OK);
    dispose(hc);
}
static void timeout_and_late_confirmation(bool before_return)
{
    t_FmHc *hc = setup();
    confirm_on_timeout = before_return;
    if (before_return) {
        /* Sync uses HC even when register programming was configured direct.
         * Its timeout must close that pre-existing fallback too. */
        assert(FmAllowHcUsage(hc, false) == E_OK);
        assert(!FmIsHcUsageAllowed(hc));
    }
    assert(GET_ERROR_TYPE(FmHcPcdSync(hc)) == E_TIMEOUT);
    assert(hc->failed && delays == HC_CONFIRM_POLLS && submissions == 1);
    assert(hc->nextSeqNumLocation == (before_return ? 0 : 1));
    refuses_teardown(hc);
    t_HcFrame snapshot = *hc->p_Frm[0];
    for (unsigned n = 0; n < 2 * HC_CMD_POOL_SIZE; n++) {
        assert(GET_ERROR_TYPE(FmHcPcdSync(hc)) == E_INVALID_STATE);
        assert(submissions == 1);
        if (!before_return) assert(!memcmp(hc->p_Frm[0], &snapshot, sizeof(snapshot)));
    }
    if (!before_return) {
        /* Exhaust all remaining buffers and return them out of order. The
         * orphan may only rejoin the pool after its own confirmation. */
        t_HcFrame *borrowed[HC_CMD_POOL_SIZE];
        uint32_t seq[HC_CMD_POOL_SIZE], unused;
        for (unsigned n = 1; n < HC_CMD_POOL_SIZE; n++) {
            borrowed[n] = GetBuf(hc, &seq[n]);
            assert(borrowed[n] && borrowed[n] != hc->p_Frm[0]);
        }
        assert(!GetBuf(hc, &unused));
        confirm();
        assert(hc->nextSeqNumLocation == HC_CMD_POOL_SIZE - 1);
        t_HcFrame *reclaimed = GetBuf(hc, &unused);
        assert(reclaimed == hc->p_Frm[0] && unused == 0);
        for (unsigned n = 1; n < HC_CMD_POOL_SIZE; n++) PutBuf(hc, borrowed[n], seq[n]);
        PutBuf(hc, reclaimed, unused);
        /* SDK rejects a duplicate CPU-order confirmation without double free. */
        FmHcTxConf(hc, (t_DpaaFD *)&pending.fd);
    }
    assert(!hc->nextSeqNumLocation && hc->failed);
    refuses_teardown(hc); /* A late confirmation does not repair caller state. */
    dispose(hc);
}
static void pool_and_cleanup(void)
{
    t_FmHc *hc = setup();
    uint32_t seq;
    t_HcFrame *frame = GetBuf(hc, &seq);
    refuses_teardown(hc); /* Even a CPU borrower prevents pool replacement. */
    PutBuf(hc, frame, seq);
    assert(FmHcSetFramesDataMemory(hc, 1) == E_OK && frees == HC_CMD_POOL_SIZE);
    assert(!hc->quiescing);
    allocation_budget = 1;
    assert(GET_ERROR_TYPE(FmHcSetFramesDataMemory(hc, 2)) == E_NO_MEMORY);
    assert(!GetBuf(hc, &seq));
    dispose(hc); /* Partial replacement allocation is freed exactly once. */

    hc = setup();
    assert(FmHcQuiesce(hc) == E_OK && !GetBuf(hc, &seq));
    hc->h_HcPortDev = hc;
    assert(FmHcFree(hc) == E_OK && port_frees == 1 && frees == HC_CMD_POOL_SIZE);
    active = NULL;
}
static void independent_commands_and_invalid_confirmation(void)
{
    t_FmHc *hc = setup();
    nested_command = true;
    assert(FmHcPcdSync(hc) == E_OK);
    assert(submissions == 2 && !delays && !hc->nextSeqNumLocation);
    uint32_t seq;
    t_HcFrame *frame = GetBuf(hc, &seq);
    t_DpaaFD fd = {0};
    DPAA_FD_SET_ADDR(&fd, frame);
    frame->commandSequence = HC_CMD_POOL_SIZE + 1;
    FmHcTxConf(hc, &fd);
    frame->commandSequence = seq;
    FmHcTxConf(hc, &fd); /* READY belongs to the caller, not a confirmation. */
    DPAA_FD_SET_ADDR(&fd, (void *)16);
    FmHcTxConf(hc, &fd); /* Unknown address must not be dereferenced. */
    assert(hc->nextSeqNumLocation == 1);
    PutBuf(hc, frame, seq);
    dispose(hc);
}
int main(void)
{
    _Static_assert(sizeof(struct qm_fd) == sizeof(t_DpaaFD), "QMan / SDK FD layout");
    rejection_and_completion();
    timeout_and_late_confirmation(false);
    timeout_and_late_confirmation(true);
    pool_and_cleanup();
    independent_commands_and_invalid_confirmation();
    puts("SDK HC transport: rejection/retry, deadline, timeout, late confirmation, pool and teardown passed");
    return 0;
}
