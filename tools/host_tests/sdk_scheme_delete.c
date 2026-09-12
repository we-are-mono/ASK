/* Real scheme, netenv, lock-pool and HC-builder code; command completion is
 * injected at the transport boundary. This does not model late HC callbacks. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#define __CORE_EXT_H
#define CORE_MemoryBarrier() ((void)0)
#define SINGLE_DEPTH_NESTING 1
#define __ERR_MODULE__ MODULE_FM_PCD
#include "fm_pcd.h"
#include "fm_hc.h"
#include "fm_kg.h"
#include "fsl_fman_kg.h"
#undef ASSERT_COND
#undef REPORT_ERROR
#undef RETURN_ERROR
#undef DBG
#define ASSERT_COND assert
#define REPORT_ERROR(level, err, msg) ((void)0)
#define RETURN_ERROR(level, err, msg) return ERROR_CODE(err)
#define DBG(level, msg) ((void)0)
#include "scheme_hc_layout.inc"

struct spin { bool held; };
static unsigned irq_depth, hardware_calls;
static t_Error command_error;
static t_FmPcdKgScheme *active_scheme;
static t_FmPcdLock *active_lock;
static t_FmPcd *active_pcd;
static bool use_hc;

void XX_Print(char *format, ...) { assert(!"unexpected SDK assertion"); }
void XX_Exit(int status) { assert(!"unexpected SDK exit"); }
physAddress_t XX_VirtToPhys(void *address) { return (uintptr_t)address; }
void *XX_PhysToVirt(physAddress_t address) { return (void *)(uintptr_t)address; }

uint32_t XX_LockIntrSpinlock(t_Handle handle)
{
    struct spin *spin = handle;
    assert(spin && !spin->held);
    spin->held = true;
    return irq_depth++;
}
uint32_t XX_LockIntrSpinlockNested(t_Handle handle, int subclass)
{ assert(subclass == SINGLE_DEPTH_NESTING); return XX_LockIntrSpinlock(handle); }
void XX_UnlockIntrSpinlock(t_Handle handle, uint32_t flags)
{
    struct spin *spin = handle;
    assert(spin && spin->held && irq_depth == flags + 1);
    spin->held = false;
    irq_depth = flags;
}
bool FmIsHcUsageAllowed(t_Handle handle) { return use_hc; }

static void hardware_entry(void)
{
    hardware_calls++;
    assert(active_scheme->valid && !active_scheme->owners);
    assert(active_scheme->p_Lock == active_lock && active_lock->flag);
    assert(active_scheme->requiredActionFlag && active_scheme->requiredAction == 0x1234);
    assert(active_scheme->netEnvId == ILLEGAL_NETENV || active_pcd->netEnvs[0].owners == 2);
    /* Binding and recursive deletion must refuse while the command runs. */
    if (use_hc) {
        assert(!FmPcdLockTryLockAll(active_pcd));
        assert(GET_ERROR_TYPE(FM_PCD_KgSchemeDelete(active_scheme)) == E_BUSY);
    }
}
int fman_kg_write_ar_wait(struct fman_kg_regs *regs, uint32_t action)
{
    assert(!use_hc && irq_depth == 1);
    assert(action == FmPcdKgBuildWriteSchemeActionReg(active_scheme->schemeId, false));
    assert(active_pcd->p_FmPcdKg->p_IndirectAccessRegs->schemeRegs.kgse_mode == 0);
    hardware_entry();
    return command_error ? -1 : 0;
}
static t_Error EnQFrm(t_FmHc *hc, t_DpaaFD *fd, uint32_t seq)
{
    assert(use_hc && !irq_depth);
    assert(DPAA_FD_GET_ADDR(fd) == hc->p_Frm[seq]);
    t_HcFrame *frame = hc->p_Frm[seq];
    assert(frame->commandSequence == seq);
    assert(frame->opcode == (HC_HCOR_GBL | HC_HCOR_OPCODE_KG_SCM));
    assert(frame->actionReg == FmPcdKgBuildWriteSchemeActionReg(active_scheme->schemeId, true));
    assert(frame->extraReg == HC_HCOR_KG_SCHEME_REGS_MASK);
    struct fman_kg_scheme_regs zero = {0};
    assert(!memcmp(&frame->hcSpecificData.schemeRegs, &zero, sizeof(zero)));
    hardware_entry();
    return command_error;
}
#include "scheme_delete_production.inc"

static void unchanged(const t_FmPcdKgScheme *before)
{
    assert(!memcmp(active_scheme, before, sizeof(*before)));
    assert(active_scheme->netEnvId == ILLEGAL_NETENV || active_pcd->netEnvs[0].owners == 2);
    assert(LIST_IsEmpty(&active_pcd->freeLocksLst));
    assert(active_pcd->acquiredLocksLst.p_Next == &active_lock->node);
    assert(!active_lock->flag && !irq_depth);
}

int main(void)
{
    for (unsigned hc_mode = 0; hc_mode < 2; hc_mode++) {
        for (unsigned direct = 0; direct < 2; direct++) {
            struct spin pcd_spin = {0}, kg_spin = {0}, scheme_spin = {0}, env_spin = {0};
            struct fman_kg_regs regs = {0};
            u_FmPcdKgIndirectAccessRegs indirect = {0};
            t_FmPcdKg kg = {.p_FmPcdKgRegs = &regs, .p_IndirectAccessRegs = &indirect,
                           .h_HwSpinlock = &kg_spin};
            t_FmPcd pcd = {.p_FmPcdKg = &kg, .h_Spinlock = &pcd_spin};
            t_FmPcdLock lock = {.h_Spinlock = &scheme_spin};
            t_FmHc hc = {.h_FmPcd = &pcd, .h_Spinlock = &pcd_spin};
            /* DPAA FDs hold 40-bit physical addresses; non-PIE static storage
             * fits the identity-mapped host address boundary used here. */
            static t_HcFrame frames[HC_CMD_POOL_SIZE];
            for (unsigned i = 0; i < HC_CMD_POOL_SIZE; i++) {
                hc.seqNum[i] = i;
                hc.p_Frm[i] = &frames[i];
            }
            pcd.h_Hc = &hc;
            pcd.netEnvs[0].h_Spinlock = &env_spin;
            pcd.netEnvs[0].owners = 1; /* Another scheme owns this netenv. */
            INIT_LIST(&pcd.freeLocksLst);
            INIT_LIST(&pcd.acquiredLocksLst);
            LIST_AddToTail(&lock.node, &pcd.acquiredLocksLst);
            t_FmPcdKgScheme scheme = {.h_FmPcd = &pcd, .schemeId = 7, .p_Lock = &lock,
                .netEnvId = direct ? ILLEGAL_NETENV : 0, .owners = 1,
                .requiredActionFlag = true, .requiredAction = 0x1234};
            ValidateSchemeSw(&scheme);
            active_scheme = &scheme; active_lock = &lock; active_pcd = &pcd;
            use_hc = hc_mode; hardware_calls = 0;

            t_FmPcdKgScheme before = scheme;
            assert(FM_PCD_KgSchemeDelete(&scheme) != E_OK);
            unchanged(&before);
            assert(!hardware_calls);
            scheme.owners = 0;
            before = scheme;
            assert(FmPcdLockTryLockAll(&pcd));
            assert(GET_ERROR_TYPE(FM_PCD_KgSchemeDelete(&scheme)) == E_BUSY);
            assert(lock.flag && !hardware_calls);
            FmPcdLockUnlockAll(&pcd);
            unchanged(&before);

            if (use_hc) {
                hc.nextSeqNumLocation = HC_CMD_POOL_SIZE;
                assert(GET_ERROR_TYPE(FM_PCD_KgSchemeDelete(&scheme)) == E_NO_MEMORY);
                assert(!hardware_calls && hc.nextSeqNumLocation == HC_CMD_POOL_SIZE);
                unchanged(&before);
                hc.nextSeqNumLocation = 0;
            }
            t_Error errors[] = {E_BUSY, E_TIMEOUT, E_INVALID_STATE};
            for (unsigned i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
                command_error = ERROR_CODE(errors[i]);
                t_Error err = FM_PCD_KgSchemeDelete(&scheme);
                assert(GET_ERROR_TYPE(err) == (use_hc ? errors[i] : E_INVALID_STATE));
                unchanged(&before);
                assert(!hc.nextSeqNumLocation);
            }
            assert(hardware_calls == 3);
            command_error = E_OK;
            assert(FM_PCD_KgSchemeDelete(&scheme) == E_OK);
            assert(hardware_calls == 4 && !hc.nextSeqNumLocation && !irq_depth);
            assert(!scheme.valid && !scheme.p_Lock && !scheme.requiredActionFlag && !scheme.requiredAction);
            assert(pcd.netEnvs[0].owners == 1 && !lock.flag);
            assert(LIST_IsEmpty(&pcd.acquiredLocksLst));
            assert(pcd.freeLocksLst.p_Next == &lock.node && pcd.freeLocksLst.p_Prev == &lock.node);

            /* A stale delete must not touch a lock now assigned elsewhere. */
            LIST_DelAndInit(&lock.node);
            LIST_AddToTail(&lock.node, &pcd.acquiredLocksLst);
            assert(FmPcdLockTryLockAll(&pcd));
            assert(GET_ERROR_TYPE(FM_PCD_KgSchemeDelete(&scheme)) == E_INVALID_STATE);
            assert(lock.flag && hardware_calls == 4 && pcd.netEnvs[0].owners == 1);
            FmPcdLockUnlockAll(&pcd);
            assert(!irq_depth);
        }
    }
    puts("SDK scheme deletion: owner/lock refusal, command failure, retry and lock reuse passed");
    return 0;
}
