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
/* Every line the transport would print, counted: a run of failures a caller
 * retries on a timer must report its first only, and the command that ends
 * the run one line more. */
static unsigned reports, recoveries, lates, stacks;
#define REPORT_ERROR(level, err, msg) (reports++)
#define RETURN_ERROR(level, err, msg) do { reports++; return ERROR_CODE(err); } while (0)
#define pr_info(...) (recoveries++)
/* The confirmation of the command that timed out says how late it came. */
#define pr_warn(...) (lates++)
/* A timeout shows who asked for its command. */
#define dump_stack() (stacks++)
/* Time advances only with the transport's own polling, at a modelled HZ of
 * 250: a jiffy is 40 polls of 100 us. */
static unsigned long jiffies;
static uint32_t jiffies_to_msecs(unsigned long j) { return j * 4; }
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
/* The opcode the next submission must carry. */
static uint32_t command;
#define SYNC (HC_HCOR_GBL | HC_HCOR_OPCODE_SYNC)
#define CC_CHANGE (HC_HCOR_GBL | HC_HCOR_OPCODE_CC)
static t_FmHc *active;
static t_LnxWrpFmDev device;
static t_FmTestFq confirmation_queue;
static struct qm_dqrr_entry pending;
static unsigned char dma[HC_CMD_POOL_SIZE][512] __aligned(16);
static bool allocated[HC_CMD_POOL_SIZE];
static void confirm(void);
/* A timeout asks the wrapper where its frame is, once. */
static unsigned describes;
static void describe(t_Handle arg, char *buf, uint32_t size)
{
    assert(arg == &device && buf && size >= 64);
    describes++;
    snprintf(buf, size, "frames queued: command 0, answer 1, error 0");
}

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
    if (active && confirm_on_timeout && active->timedOut[0]) {
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
    if (!(++delays % 40)) jiffies++;
    if (delays == confirm_at) confirm();
}
static int qman_enqueue(struct qman_fq *fq, const struct qm_fd *fd, u32 flags)
{
    assert(!flags && !((struct spin *)active->h_Spinlock)->held);
    submissions++;
    pending.fd = *fd;
    const unsigned char *bytes = XX_PhysToVirt(qm_fd_addr(fd));
    assert(fd->length20 == (command == SYNC ? sizeof(t_HcFrame)
                                            : SIZE_OF_HC_FRAME_READ_OR_CC_DYNAMIC));
    /* The command must reach QMan in hardware byte order. */
    assert(bytes[0] == command >> 24 && bytes[1] == (uint8_t)(command >> 16) &&
           bytes[2] == (uint8_t)(command >> 8) && bytes[3] == (uint8_t)command);
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
    active->f_QmDescribe = describe;
    device.h_PcdDev = active;
    confirmation_queue.h_Arg = &device;
    reject = inline_confirm = confirm_on_timeout = nested_command = false;
    command = SYNC;
    delays = confirm_at = submissions = frees = port_frees = 0;
    allocation_budget = -1;
    assert(FillBufPool(active) == E_OK);
    return active;
}
static void dispose(t_FmHc *hc)
{
    /* All hardware ownership must have ended first: nothing borrowed, nothing
     * unanswered. */
    assert(!hc->nextSeqNumLocation && !HcUnanswered(hc));
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
    unsigned reported = reports, recovered = recoveries;
    reject = true;
    for (unsigned n = 0; n < 2 * HC_CMD_POOL_SIZE; n++) {
        assert(GET_ERROR_TYPE(FmHcPcdSync(hc)) == E_INVALID_STATE);
        /* A refused sync was never sent: nothing is left unanswered, and
         * the next can complete. */
        assert(!hc->nextSeqNumLocation && !HcUnanswered(hc) && !delays);
        t_HcFrame expected = {.opcode = HC_HCOR_GBL | HC_HCOR_OPCODE_SYNC};
        assert(!memcmp(hc->p_Frm[0], &expected, sizeof(expected)));
        /* A run of rejections reports its first only: neither a later
         * rejection nor the sync it failed adds a line. */
        assert(reports == reported + 1 && hc->failures == n + 1 && recoveries == recovered);
    }
    reject = false;
    inline_confirm = true;
    assert(FmHcPcdSync(hc) == E_OK && !hc->nextSeqNumLocation && !delays);
    /* The command that ends the run says so, once, and a new run reports
     * again from its first failure. */
    assert(recoveries == recovered + 1 && !hc->failures && reports == reported + 1);
    assert(FmHcPcdSync(hc) == E_OK && recoveries == recovered + 1);
    reject = true;
    assert(GET_ERROR_TYPE(FmHcPcdSync(hc)) == E_INVALID_STATE && reports == reported + 2);
    reject = false;
    assert(FmHcPcdSync(hc) == E_OK && recoveries == recovered + 2 && reports == reported + 2);
    inline_confirm = false;
    confirm_at = HC_CONFIRM_POLLS; /* Completion at the deadline wins. */
    assert(FmHcPcdSync(hc) == E_OK && !HcUnanswered(hc));
    assert(delays == HC_CONFIRM_POLLS && !hc->nextSeqNumLocation);
    /* Commands confirmed in time, even at the deadline, were never late. */
    assert(!lates && !stacks);
    assert(FmAllowHcUsage(hc, false) == E_OK && !FmIsHcUsageAllowed(hc));
    assert(FmAllowHcUsage(hc, true) == E_OK);
    dispose(hc);
}
static void sync_timeout_and_late_confirmation(bool before_return)
{
    t_FmHc *hc = setup();
    confirm_on_timeout = before_return;
    /* Sync uses HC even when register programming was configured direct.
     * Its timeout must close that pre-existing fallback while the sync may
     * still be inside the FMan. */
    assert(FmAllowHcUsage(hc, false) == E_OK);
    assert(!FmIsHcUsageAllowed(hc));
    unsigned reported = reports, late = lates, stacked = stacks, recovered = recoveries;
    unsigned described = describes;
    assert(GET_ERROR_TYPE(FmHcPcdSync(hc)) == E_TIMEOUT);
    assert(stacks == stacked + 1 && describes == described + 1);
    assert(delays == HC_CONFIRM_POLLS && submissions == 1);
    /* The timeout names its command: the sync, taken in CPU order before the
     * enqueue swapped the frame, sent a full deadline ago. */
    assert(hc->sentOpcode[0] == SYNC);
    assert(hc->timedOut[0] == !before_return);
    assert(jiffies_to_msecs(jiffies - hc->sentAt[0]) == 1000);
    /* Confirmed before the caller's PutBuf, the command was still late. */
    assert(lates == late + before_return);
    /* Unanswered until its confirmation, and no longer than that. */
    assert(HcUnanswered(hc) == !before_return);
    assert(hc->nextSeqNumLocation == (before_return ? 0 : 1));
    /* The timeout is reported unconditionally, and starts the run every
     * retry after it belongs to. */
    assert(reports == reported + 1 && hc->failures == 1);
    if (!before_return) {
        /* Until it answers, nothing more goes to a port that has not: each
         * retry fails at once, without a second's wait, adds no line, and
         * leaves the orphan's frame as the hardware may still read it. */
        refuses_teardown(hc);
        t_HcFrame snapshot = *hc->p_Frm[0];
        reported = reports;
        for (unsigned n = 0; n < 2 * HC_CMD_POOL_SIZE; n++) {
            assert(GET_ERROR_TYPE(FmHcPcdSync(hc)) == E_INVALID_STATE);
            assert(submissions == 1 && delays == HC_CONFIRM_POLLS);
            assert(!memcmp(hc->p_Frm[0], &snapshot, sizeof(snapshot)));
            assert(reports == reported && hc->failures == n + 2);
            assert(describes == described + 1);
        }
        /* Exhaust all remaining buffers and return them out of order. The
         * orphan may only rejoin the pool after its own confirmation. */
        t_HcFrame *borrowed[HC_CMD_POOL_SIZE];
        uint32_t seq[HC_CMD_POOL_SIZE], unused;
        for (unsigned n = 1; n < HC_CMD_POOL_SIZE; n++) {
            borrowed[n] = GetBuf(hc, &seq[n]);
            assert(borrowed[n] && borrowed[n] != hc->p_Frm[0]);
        }
        assert(!GetBuf(hc, &unused));
        assert(lates == late);
        confirm();
        /* The orphan's own confirmation says it was late, once. */
        assert(lates == late + 1 && !hc->timedOut[0]);
        assert(hc->nextSeqNumLocation == HC_CMD_POOL_SIZE - 1);
        t_HcFrame *reclaimed = GetBuf(hc, &unused);
        assert(reclaimed == hc->p_Frm[0] && unused == 0);
        for (unsigned n = 1; n < HC_CMD_POOL_SIZE; n++) PutBuf(hc, borrowed[n], seq[n]);
        PutBuf(hc, reclaimed, unused);
        /* SDK rejects a duplicate CPU-order confirmation without double free,
         * and without calling it late a second time. */
        FmHcTxConf(hc, (t_DpaaFD *)&pending.fd);
        assert(lates == late + 1);
    }
    /* Answered, the sync has left nothing in the FMan: the channel is open
     * again, the direct fallback as it was configured, and the next command
     * completes and says it ended the run. */
    assert(!hc->nextSeqNumLocation && !HcUnanswered(hc));
    assert(!FmIsHcUsageAllowed(hc));
    assert(FmAllowHcUsage(hc, true) == E_OK);
    inline_confirm = true;
    unsigned sent = submissions;
    assert(FmHcPcdSync(hc) == E_OK && submissions == sent + 1);
    assert(recoveries == recovered + 1 && !hc->failures);
    dispose(hc);
}
static void state_change_timeout_reopens_once_answered(bool before_return)
{
    /* A change that times out may yet be made: its caller hears E_TIMEOUT,
     * an outcome unknown, and puts its own record right once the channel
     * opens again -- as it does for a sync, on the answer. Until then
     * nothing else is sent, nor may a register be written directly. */
    t_FmHc *hc = setup();
    confirm_on_timeout = before_return;
    unsigned late = lates, stacked = stacks, recovered = recoveries;
    command = CC_CHANGE;
    assert(GET_ERROR_TYPE(FmHcPcdCcDoDynamicChange(hc, 0x100, 0x200)) == E_TIMEOUT);
    assert(stacks == stacked + 1 && submissions == 1 && delays == HC_CONFIRM_POLLS);
    assert(hc->sentOpcode[0] == CC_CHANGE);
    assert(hc->timedOut[0] == !before_return && lates == late + before_return);
    if (!before_return) {
        refuses_teardown(hc);
        command = SYNC;
        assert(GET_ERROR_TYPE(FmHcPcdSync(hc)) == E_INVALID_STATE && submissions == 1);
        command = CC_CHANGE;
        assert(GET_ERROR_TYPE(FmHcPcdCcDoDynamicChange(hc, 0x100, 0x200)) == E_INVALID_STATE);
        assert(submissions == 1 && delays == HC_CONFIRM_POLLS);
        confirm();
        assert(lates == late + 1 && !hc->timedOut[0]);
    }
    assert(!hc->nextSeqNumLocation && !HcUnanswered(hc));
    /* The owner's re-assertion goes out, and is answered. */
    inline_confirm = true;
    assert(FmHcPcdCcDoDynamicChange(hc, 0x100, 0x200) == E_OK && submissions == 2);
    assert(recoveries == recovered + 1 && !hc->failures);
    dispose(hc);
}
static void timeout_on_a_later_command(void)
{
    /* The command that times out is not the first frame: its own record is
     * the one that says it was late, and its confirmation reopens the
     * channel although another frame is still borrowed. */
    t_FmHc *hc = setup();
    uint32_t seq;
    t_HcFrame *frame = GetBuf(hc, &seq);
    unsigned late = lates;
    assert(seq == 0);
    assert(GET_ERROR_TYPE(FmHcPcdSync(hc)) == E_TIMEOUT);
    assert(hc->timedOut[1] && !hc->timedOut[0] && lates == late);
    assert(GET_ERROR_TYPE(FmHcPcdSync(hc)) == E_INVALID_STATE && submissions == 1);
    confirm();
    assert(!hc->timedOut[1] && lates == late + 1);
    inline_confirm = true;
    assert(FmHcPcdSync(hc) == E_OK && submissions == 2);
    PutBuf(hc, frame, seq);
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
static void exhausted_pool(void)
{
    t_FmHc *hc = setup();
    t_HcFrame *borrowed[HC_CMD_POOL_SIZE];
    uint32_t seq[HC_CMD_POOL_SIZE];
    unsigned reported = reports, recovered = recoveries;
    for (unsigned n = 0; n < HC_CMD_POOL_SIZE; n++) assert((borrowed[n] = GetBuf(hc, &seq[n])));
    /* No frame to build a sync in fails every retry the same way, and the
     * run reports its first only. */
    for (unsigned n = 0; n < 2 * HC_CMD_POOL_SIZE; n++)
        assert(GET_ERROR_TYPE(FmHcPcdSync(hc)) == E_NO_MEMORY && reports == reported + 1);
    assert(!submissions && recoveries == recovered);
    for (unsigned n = 0; n < HC_CMD_POOL_SIZE; n++) PutBuf(hc, borrowed[n], seq[n]);
    inline_confirm = true;
    assert(FmHcPcdSync(hc) == E_OK && recoveries == recovered + 1 && !hc->failures);
    dispose(hc);
}
static void independent_commands_and_invalid_confirmation(void)
{
    t_FmHc *hc = setup();
    unsigned late = lates;
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
    /* Neither the nested completions nor rejected frames were late. */
    assert(lates == late);
    PutBuf(hc, frame, seq);
    dispose(hc);
}
int main(void)
{
    _Static_assert(sizeof(struct qm_fd) == sizeof(t_DpaaFD), "QMan / SDK FD layout");
    rejection_and_completion();
    sync_timeout_and_late_confirmation(false);
    sync_timeout_and_late_confirmation(true);
    state_change_timeout_reopens_once_answered(false);
    state_change_timeout_reopens_once_answered(true);
    timeout_on_a_later_command();
    pool_and_cleanup();
    exhausted_pool();
    independent_commands_and_invalid_confirmation();
    puts("SDK HC transport: rejection/retry, deadline, a late sync reopening the channel, a late change failing it, pool, teardown and failure reporting passed");
    return 0;
}
