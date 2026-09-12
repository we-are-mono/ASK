/* Production scheme builder, lock pool, netenv references and HC transport.
 * Faults enter at allocation, QMan acceptance/completion and register I/O. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define __CORE_EXT_H
#define CORE_MemoryBarrier() ((void)0)
#define SINGLE_DEPTH_NESTING 1
#define __ERR_MODULE__ MODULE_FM_PCD
#define pr_debug(...) ((void)0)
#define fallthrough __attribute__((fallthrough))
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
#include "scheme_set_production.inc"

struct spin { bool held; };
static t_FmPcd pcd;
static t_FmPcdKg kg;
static t_FmHc hc;
static struct fman_kg_regs registers;
static u_FmPcdKgIndirectAccessRegs indirect;
static struct fman_kg_scheme_regs hardware;
static t_HcFrame frames[HC_CMD_POOL_SIZE];
static struct spin pcd_spin, kg_spin, hc_spin, env_spins[2];
static unsigned allocations, spin_allocations, irq_depth, hardware_calls, qman_calls;
static bool fail_alloc, fail_spin, reject_command, omit_confirmation, reenter;
static uint32_t fail_size;
static t_DpaaFD pending;
static t_FmPcdKgScheme before_programming;
static bool check_live;
#define SCHEME (&kg.schemes[0])

void XX_Print(char *format, ...) { assert(!"unexpected SDK assertion"); }
void XX_Exit(int status) { assert(!"unexpected SDK exit"); }
void *XX_Malloc(uint32_t size)
{
    if (fail_alloc || size == fail_size) return NULL;
    void *p = malloc(size); assert(p); allocations++; return p;
}
void XX_Free(void *p) { assert(p && allocations); allocations--; free(p); }
t_Handle XX_InitSpinlock(void)
{
    if (fail_spin) return NULL;
    struct spin *p = calloc(1, sizeof(*p)); assert(p); spin_allocations++; return p;
}
void XX_FreeSpinlock(t_Handle p)
{ assert(p && !((struct spin *)p)->held && spin_allocations); spin_allocations--; free(p); }
uint32_t XX_LockIntrSpinlock(t_Handle p)
{ struct spin *s = p; assert(s && !s->held); s->held = true; return irq_depth++; }
uint32_t XX_LockIntrSpinlockNested(t_Handle p, int subclass)
{ assert(subclass == SINGLE_DEPTH_NESTING); return XX_LockIntrSpinlock(p); }
void XX_UnlockIntrSpinlock(t_Handle p, uint32_t flags)
{ struct spin *s = p; assert(s && s->held && irq_depth == flags + 1); s->held = false; irq_depth = flags; }
physAddress_t XX_VirtToPhys(void *p) { return (uintptr_t)p; }
void *XX_PhysToVirt(physAddress_t p) { return (void *)(uintptr_t)p; }
void XX_UDelay(uint32_t usecs) { assert(usecs == HC_CONFIRM_POLL_US && !irq_depth); }
e_NetHeaderType FmPcdGetAliasHdr(t_FmPcd *p, uint8_t env, e_NetHeaderType hdr)
{ assert(!"alias extraction not part of this fixture"); return hdr; }
t_Error FmPcdCcGetGrpParams(t_Handle tree, uint8_t group, uint32_t *bits, uint8_t *base)
{ *bits = 0x12340000; *base = 2; return E_OK; }
t_Error FmPcdPlcrGetAbsoluteIdByProfileParams(t_Handle p, e_FmPcdProfileTypeSelection type,
                                            t_Handle port, uint16_t relative, uint16_t *absolute)
{ *absolute = relative; return E_OK; }
bool FmPcdPlcrIsProfileValid(t_Handle p, uint16_t id) { return true; }
bool FmPcdIsAdvancedOffloadSupported(t_Handle p) { return true; }

static t_FmPcdKgSchemeParams parameters(int env, bool modify)
{
    t_FmPcdKgSchemeParams p = {0};
    p.modify = modify;
    if (modify) p.id.h_Scheme = SCHEME;
    p.alwaysDirect = env < 0;
    if (env >= 0) {
        p.netEnvParams.h_NetEnv = &pcd.netEnvs[env];
        p.netEnvParams.numOfDistinctionUnits = 1;
    }
    p.baseFqid = 8;
    p.nextEngine = e_FM_PCD_DONE;
    p.kgNextEngineParams.doneAction = e_FM_PCD_DROP_FRAME;
    p.schemeCounter.update = true;
    return p;
}
static void entering_hardware(void)
{
    hardware_calls++;
    assert(SCHEME->p_Lock && SCHEME->p_Lock->flag);
    if (check_live) assert(!memcmp(SCHEME, &before_programming, sizeof(*SCHEME)));
    if (reenter) {
        assert(!irq_depth);
        reenter = false;
        t_FmPcdKgScheme snapshot = *SCHEME;
        /* Binding, a second creator, and modification must not observe or
         * replace a partly built scheme while programming is outstanding. */
        assert(!FmPcdLockTryLockAll(&pcd));
        t_FmPcdKgSchemeParams p = parameters(0, false);
        assert(!FM_PCD_KgSchemeSet(&pcd, &p));
        p = parameters(0, true);
        assert(!FM_PCD_KgSchemeSet(&pcd, &p));
        assert(!memcmp(SCHEME, &snapshot, sizeof(snapshot)));
    }
}
static t_Error enqueue(t_Handle arg, void *descriptor)
{
    t_DpaaFD *fd = descriptor;
    t_HcFrame *frame = DPAA_FD_GET_ADDR(fd);
    assert(!irq_depth && arg == &hc);
    qman_calls++;
    entering_hardware();
    if (reject_command) return ERROR_CODE(E_BUSY);
    pending = *fd;
    hardware = frame->hcSpecificData.schemeRegs;
    if (!omit_confirmation) FmHcTxConf(&hc, fd);
    return E_OK;
}
int fman_kg_write_ar_wait(struct fman_kg_regs *regs, uint32_t action)
{
    assert(regs == &registers && irq_depth == 1);
    assert(action == FmPcdKgBuildWriteSchemeActionReg(7, true) ||
           action == FmPcdKgBuildWriteSchemeActionReg(7, false));
    entering_hardware();
    if (reject_command) return -1;
    hardware = indirect.schemeRegs;
    return 0;
}
static void setup(bool use_hc)
{
    assert(!allocations && !spin_allocations && !irq_depth);
    memset(&pcd, 0, sizeof(pcd)); memset(&kg, 0, sizeof(kg));
    memset(&hc, 0, sizeof(hc)); memset(&hardware, 0, sizeof(hardware));
    fail_alloc = fail_spin = reject_command = omit_confirmation = reenter = check_live = false;
    hardware_calls = qman_calls = fail_size = 0;
    pcd.p_FmPcdKg = &kg; pcd.h_Spinlock = &pcd_spin; pcd.h_Hc = &hc;
    pcd.fmRevInfo.majorRev = 6;
    kg.h_HwSpinlock = &kg_spin; kg.p_FmPcdKgRegs = &registers;
    kg.p_IndirectAccessRegs = &indirect; kg.numOfSchemes = 1; kg.schemesIds[0] = 7;
    INIT_LIST(&pcd.freeLocksLst); INIT_LIST(&pcd.acquiredLocksLst);
    for (unsigned n = 0; n < 2; n++) {
        pcd.netEnvs[n].h_Spinlock = &env_spins[n];
        pcd.netEnvs[n].netEnvId = n;
        pcd.netEnvs[n].owners = 1; /* Independent owner. */
        pcd.netEnvs[n].units[0].hdrs[0].hdr = HEADER_TYPE_ETH;
        pcd.netEnvs[n].unitsVectors[0] = 1U << (31 - n);
    }
    hc.h_Spinlock = &hc_spin; hc.h_FmPcd = &pcd;
    hc.f_QmEnqueue = enqueue; hc.h_QmArg = &hc; hc.usageAllowed = use_hc;
    for (unsigned n = 0; n < HC_CMD_POOL_SIZE; n++) { hc.seqNum[n] = n; hc.p_Frm[n] = &frames[n]; }
}
static void cleanup(void)
{
    assert(!hc.nextSeqNumLocation && !irq_depth);
    /* Fixture reset after confirmation only; production requires board reset. */
    hc.failed = false; reject_command = omit_confirmation = check_live = reenter = false;
    if (SCHEME->valid) { SCHEME->owners = 0; assert(FM_PCD_KgSchemeDelete(SCHEME) == E_OK); }
    assert(!SCHEME->p_Lock && LIST_IsEmpty(&pcd.acquiredLocksLst));
    assert(pcd.netEnvs[0].owners == 1 && pcd.netEnvs[1].owners == 1);
    ReleaseFreeLocksLst(&pcd);
    assert(!allocations && !spin_allocations);
}
static void unchanged(const t_FmPcdKgScheme *before, const struct fman_kg_scheme_regs *regs)
{
    assert(!memcmp(SCHEME, before, sizeof(*before)));
    assert(!memcmp(&hardware, regs, sizeof(hardware)));
    assert(!SCHEME->p_Lock->flag && !irq_depth);
    assert(pcd.netEnvs[0].owners == 2 && pcd.netEnvs[1].owners == 1);
}
static void failed_creation(bool use_hc)
{
    setup(use_hc);
    t_FmPcdKgSchemeParams p = parameters(0, false);
    fail_alloc = true;
    assert(!FM_PCD_KgSchemeSet(&pcd, &p));
    fail_alloc = false; fail_spin = true;
    assert(!FM_PCD_KgSchemeSet(&pcd, &p));
    fail_spin = false;
    assert(!SCHEME->valid && !SCHEME->p_Lock && !hardware_calls && !allocations);
    for (unsigned fault = 0; fault < 4; fault++) {
        p = parameters(0, false);
        if (fault == 0) p.nextEngine = e_FM_PCD_INVALID;
        if (fault == 1) p.baseFqid = 0x1000000;
        if (fault == 2) { p.useHash = true; p.keyExtractAndHashParams.hashDistributionNumOfFqids = 1;
                         fail_size = sizeof(t_FmPcdKgSchemesExtracts); }
        reject_command = fault == 3;
        assert(!FM_PCD_KgSchemeSet(&pcd, &p));
        assert(!SCHEME->valid && !SCHEME->p_Lock && LIST_IsEmpty(&pcd.acquiredLocksLst));
        assert(pcd.netEnvs[0].owners == 1 && !hc.nextSeqNumLocation && !hc.failed);
        /* Reassign the failed acquisition to someone else. A stale scheme
         * must not unlock or release that lock on a later delete or retry. */
        t_FmPcdLock *other = FmPcdAcquireLock(&pcd);
        assert(other && FmPcdLockTryLock(other));
        assert(FM_PCD_KgSchemeDelete(SCHEME) != E_OK && other->flag);
        fail_size = 0; reject_command = false;
        p = parameters(0, false);
        assert(FM_PCD_KgSchemeSet(&pcd, &p) == SCHEME && other->flag);
        assert(FM_PCD_KgSchemeDelete(SCHEME) == E_OK && other->flag);
        FmPcdReleaseLock(&pcd, other);
    }
    cleanup();
}
static void failed_and_successful_modification(bool use_hc)
{
    setup(use_hc);
    t_FmPcdKgSchemeParams p = parameters(0, false);
    reenter = use_hc;
    assert(FM_PCD_KgSchemeSet(&pcd, &p) == SCHEME);
    SCHEME->owners = 2;
    SCHEME->requiredActionFlag = true; SCHEME->requiredAction = 0x1234;
    t_FmPcdKgScheme original = *SCHEME;
    struct fman_kg_scheme_regs old_regs = hardware;
    assert(FmPcdLockTryLock(SCHEME->p_Lock));
    p = parameters(1, true);
    assert(!FM_PCD_KgSchemeSet(&pcd, &p) && !p.id.h_Scheme);
    FmPcdLockUnlock(SCHEME->p_Lock);
    for (unsigned fault = 0; fault < 4; fault++) {
        p = parameters(1, true);
        p.overrideStorageProfile = true; p.storageProfile.direct = true;
        p.useHash = true; p.keyExtractAndHashParams.hashDistributionNumOfFqids = 1;
        p.keyExtractAndHashParams.numOfUsedExtracts = 1;
        p.keyExtractAndHashParams.extractArray[0].type = e_FM_PCD_KG_EXTRACT_PORT_PRIVATE_INFO;
        if (fault == 0) p.nextEngine = e_FM_PCD_INVALID;
        if (fault == 1) p.baseFqid = 0x1000000; /* Fail after order/VSP construction. */
        fail_size = fault == 2 ? sizeof(t_FmPcdKgSchemesExtracts) : 0;
        reject_command = fault == 3;
        before_programming = original; check_live = true;
        assert(!FM_PCD_KgSchemeSet(&pcd, &p));
        unchanged(&original, &old_regs);
    }
    fail_size = 0; reject_command = false; reenter = use_hc;
    assert(FM_PCD_KgSchemeSet(&pcd, &p) == SCHEME);
    check_live = false;
    assert(SCHEME->vspe && SCHEME->owners == 2 && SCHEME->p_Lock == original.p_Lock);
    assert(SCHEME->requiredActionFlag && SCHEME->requiredAction == 0x1234);
    assert(SCHEME->netEnvId == 1 && pcd.netEnvs[0].owners == 1 && pcd.netEnvs[1].owners == 2);
    assert(hardware.kgse_mv == pcd.netEnvs[1].unitsVectors[0]);
    p = parameters(-1, true);
    assert(FM_PCD_KgSchemeSet(&pcd, &p) == SCHEME);
    assert(!SCHEME->vspe && SCHEME->netEnvId == ILLEGAL_NETENV);
    assert(pcd.netEnvs[0].owners == 1 && pcd.netEnvs[1].owners == 1);
    p = parameters(0, true);
    assert(FM_PCD_KgSchemeSet(&pcd, &p) == SCHEME && pcd.netEnvs[0].owners == 2);
    cleanup();
}
static void ambiguous_timeout(bool modify)
{
    setup(true);
    t_FmPcdKgSchemeParams p = parameters(0, false);
    if (modify) assert(FM_PCD_KgSchemeSet(&pcd, &p) == SCHEME);
    t_FmPcdKgScheme original = *SCHEME;
    p = parameters(1, modify);
    omit_confirmation = true;
    assert(!FM_PCD_KgSchemeSet(&pcd, &p));
    assert(hc.failed && hc.nextSeqNumLocation == 1);
    if (modify) assert(!memcmp(SCHEME, &original, sizeof(original)));
    else assert(!SCHEME->valid && !SCHEME->p_Lock);
    /* Hardware may have applied the candidate even though software did not
     * publish it. Retries must never program over that uncertain result. */
    assert(hardware.kgse_mv == pcd.netEnvs[1].unitsVectors[0]);
    unsigned sent = qman_calls;
    assert(FmAllowHcUsage(&hc, false) != E_OK);
    assert(!FM_PCD_KgSchemeSet(&pcd, &p) && qman_calls == sent);
    FmHcTxConf(&hc, &pending);
    assert(!hc.nextSeqNumLocation && hc.failed);
    assert(!FM_PCD_KgSchemeSet(&pcd, &p) && qman_calls == sent);
    cleanup();
}
int main(void)
{
    for (unsigned mode = 0; mode < 2; mode++) {
        failed_creation(mode);
        failed_and_successful_modification(mode);
    }
    ambiguous_timeout(false); ambiguous_timeout(true);
    puts("SDK scheme set: allocation/build/programming failures, ownership, retry and HC timeout passed");
    return 0;
}
