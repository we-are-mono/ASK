/* Exercise public PCD setup/delete, actual MMIO transitions and resource helpers. */
#define TEST_PUBLIC_API
#include "sdk_port_fixture.h"

static bool all_locked, use_fe;
static unsigned env_owners, heap_allocs, muram_allocs, muram_calls, muram_fail;
static unsigned settings_calls, settings_fail, cases;
static int pcd_token;
static t_Error RealGetSetCcParams(t_Handle port, t_FmPortGetSetCcParams *params);
static bool port_try_lock(volatile bool *lock)
{ if (*lock || failure == PORT_LOCK) return false; *lock = true; return true; }
#define TRY_LOCK(spinlock, flag) port_try_lock(flag)
#undef DBG
#define DBG(level, args) ((void)0)

t_Handle FmGetPcdHandle(t_Handle fm) { return &pcd_token; }
bool FmPcdLockTryLockAll(t_Handle pcd)
{ assert(!all_locked); if (failure == ALL_LOCK) return false; all_locked = true; return true; }
void FmPcdLockUnlockAll(t_Handle pcd) { assert(all_locked); all_locked = false; }
void FmPcdIncNetEnvOwners(t_Handle pcd, uint8_t env) { env_owners++; }
void FmPcdDecNetEnvOwners(t_Handle pcd, uint8_t env) { assert(env_owners); env_owners--; }
void *XX_Malloc(uint32_t size)
{ void *p = malloc(size); assert(p); heap_allocs++; return p; }
void XX_Free(void *p) { assert(p && heap_allocs); heap_allocs--; free(p); }
void *FM_MURAM_AllocMem(t_Handle muram, uint32_t size, uint32_t align)
{
    if (++muram_calls == muram_fail) return NULL;
    void *p = calloc(1, size); assert(p); muram_allocs++; return p;
}
t_Error FM_MURAM_FreeMem(t_Handle muram, void *p)
{ assert(p && muram_allocs); free(p); muram_allocs--; return E_OK; }
physAddress_t XX_VirtToPhys(void *p) { return (physAddress_t)(uintptr_t)p; }
void *IOMemSet32(void *p, uint8_t value, uint32_t size) { return memset(p, value, size); }

bool FmPcdIsHcUsageAllowed(t_Handle pcd) { return true; }
t_Error FmPcdHcSync(t_Handle pcd) { return failure == HC_SYNC ? E_BUSY : E_OK; }
t_Error FmSetNumOfRiscsPerPort(t_Handle fm, uint8_t id, uint8_t count, t_FmFmanCtrl ctrl)
{ return (count == 1 && failure == RISC_ATTACH) || (count == 2 && failure == RISC_DETACH) ? E_BUSY : E_OK; }
t_Error FmPortGetSetCcParams(t_Handle port, t_FmPortGetSetCcParams *params)
{
    if (++settings_calls == settings_fail) return E_INVALID_STATE;
    return RealGetSetCcParams(port, params);
}
static t_Error bind_port_resources(t_Handle handle)
{
    t_FmPort *port = handle;
    assert(all_locked && env_owners);
    port->requiredAction |= UPDATE_FMFP_PRC_WITH_ONE_RISC_ONLY;
    return use_fe ? FmPortSetFESupport(port) : E_OK;
}
/* Port destruction must refuse pending PCD ownership before reaching these. */
static void FmPortDriverParamFree(t_FmPort *port) { assert(!"pending port was freed"); }
void FmPortImFree(t_FmPort *port) { assert(!"independent-mode port in PCD fixture"); }
t_Error FM_PORT_Disable(t_Handle port) { assert(!"unexpected disable"); return E_OK; }
void FmFreePortParams(t_Handle fm, t_FmInterModulePortFreeParams *params) { assert(!"pending port resources freed"); }
t_Error FmVSPFreeForPort(t_Handle fm, e_FmPortType type, uint8_t id) { assert(!"pending VSP freed"); return E_OK; }
void XX_FreeSpinlock(t_Handle lock) { assert(!"pending port lock freed"); }
#include "port_api_production.inc"

struct fixture {
    t_FmPort port;
    union fman_port_bmi_regs bmi;
    struct fman_port_qmi_regs qmi;
    u_FmPortBmiRegs bmi_sdk;
    t_FmPortPrsRegs prs_regs;
    t_FmPortPcdPrsParams prs;
    t_FmPortPcdKgParams kg;
    t_FmPortPcdCcParams cc;
    t_FmPortPcdParams params;
};
static void init(struct fixture *f, bool oh, bool stats)
{
    assert(!all_locked && !env_owners && !muram_allocs && !heap_allocs);
    assert(!roots && !plans && !schemes && !statistics);
    memset(f, 0, sizeof(*f));
    failure = cleanup_failure = NONE; muram_calls = muram_fail = settings_calls = settings_fail = 0;
    reports = 0; use_fe = false;
    f->port.portType = oh ? e_FM_PORT_TYPE_OH_OFFLINE_PARSING : e_FM_PORT_TYPE_RX;
    f->port.port.bmi_regs = &f->bmi; f->port.port.qmi_regs = &f->qmi;
    f->port.p_FmPortBmiRegs = &f->bmi_sdk; f->port.p_FmPortPrsRegs = &f->prs_regs;
    f->port.tasks.num = 2; f->port.fmRevInfo.majorRev = 6;
    if (oh) f->bmi.oh.fmbm_ofne = GET_NO_PCD_NIA_BMI_AC_ENQ_FRAME();
    else f->bmi.rx.fmbm_rfne = GET_NO_PCD_NIA_BMI_AC_ENQ_FRAME();
    f->prs.firstPrsHdr = HEADER_TYPE_ETH; f->prs.includeInPrsStatistics = stats;
    f->kg.numOfSchemes = 1; f->kg.h_Schemes[0] = (void *)1;
    f->cc.h_CcTree = (void *)2;
    f->params = (t_FmPortPcdParams){.pcdSupport = e_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_CC,
        .h_NetEnv = &pcd_token, .p_PrsParams = &f->prs, .p_KgParams = &f->kg, .p_CcParams = &f->cc};
}
static void unlocked(struct fixture *f) { assert(!f->port.lock && !all_locked && !heap_allocs); }
static void clean(struct fixture *f)
{
    unlocked(f);
    assert(!env_owners && !roots && !plans && !schemes && !statistics);
    assert(!f->port.pcdEngines && !f->port.pcdConfigured && !f->port.pcdNetEnvOwner);
    assert(!f->port.requiredAction && !f->port.supportFE);
    assert(!f->port.pcdBindings.cc && !f->port.pcdBindings.clsPlan && !f->port.pcdBindings.schemes);
    assert(muram_allocs == !!f->port.p_ParamsPage); /* page belongs to port lifetime */
}
static void finish(struct fixture *f)
{
    clean(f);
    if (f->port.p_ParamsPage) FM_MURAM_FreeMem(NULL, f->port.p_ParamsPage);
    assert(!muram_allocs); cases++;
}
static void retry(struct fixture *f)
{
    failure = cleanup_failure = NONE; settings_fail = muram_fail = 0;
    t_Error ret = FM_PORT_SetPCD(&f->port, &f->params);
    if (ret) fprintf(stderr, "retry failed case %u mode %u err %u\n", cases, f->params.pcdSupport, ret);
    assert(ret == E_OK); unlocked(f);
    assert(f->port.pcdConfigured && f->port.pcdNetEnvOwner);
    unsigned owners = env_owners;
    assert(FM_PORT_SetPCD(&f->port, &f->params) != E_OK); unlocked(f); assert(env_owners == owners);
    assert(FM_PORT_DeletePCD(&f->port) == E_OK); clean(f);
    assert(FM_PORT_DeletePCD(&f->port) != E_OK); clean(f);
}
int main(void)
{
    struct fixture f;
    /* Reserved replacement API must not inspect handles or change a live
     * classifier, including already-held locks. */
    for (unsigned oh = 0; oh < 2; oh++) {
        for (unsigned detached = 0; detached < 2; detached++) {
            init(&f, oh, true);
            assert(FM_PORT_SetPCD(&f.port, &f.params) == E_OK);
            if (detached) assert(FM_PORT_DetachPCD(&f.port) == E_OK);
            f.port.lock = all_locked = true;
            struct fixture before; memcpy(&before, &f, sizeof(f));
            unsigned r = roots, rb = root_binds, owners = env_owners;
            unsigned settings = settings_calls;
            t_Handle trees[] = {f.port.ccTreeId, (void *)1, NULL};
            for (unsigned i = 0; i < sizeof(trees) / sizeof(trees[0]); i++) {
                assert(GET_ERROR_TYPE(FM_PORT_PcdCcModifyTree(&f.port, trees[i])) == E_NOT_SUPPORTED);
                assert(!memcmp(&before, &f, sizeof(f)));
                assert(roots == r && root_binds == rb && env_owners == owners);
                assert(settings_calls == settings && all_locked);
            }
            f.port.lock = all_locked = false;
            assert(FM_PORT_DeletePCD(&f.port) == E_OK); finish(&f);
        }
    }
    assert(GET_ERROR_TYPE(FM_PORT_PcdCcModifyTree(NULL, NULL)) == E_NOT_SUPPORTED);
    assert(GET_ERROR_TYPE(FM_PORT_PcdCcModifyTree((void *)1, (void *)1)) == E_NOT_SUPPORTED);
    /* Reassembly requests cannot change an unconfigured or live port, even
     * when their nested CC pointer is unreadable and the port lock is held. */
    for (unsigned configured = 0; configured < 2; configured++) {
        for (unsigned type = 1; type < 4; type++) {
            init(&f, false, true);
            if (configured) assert(FM_PORT_SetPCD(&f.port, &f.params) == E_OK);
            t_FmPortPcdParams valid = f.params;
            f.params.h_IpReassemblyManip = (type & 1) ? (void *)1 : NULL;
            f.params.h_CapwapReassemblyManip = (type & 2) ? (void *)1 : NULL;
            f.params.p_CcParams = (void *)1;
            f.port.lock = true;
            struct fixture before = f;
            unsigned owners = env_owners, binds = root_binds, calls = settings_calls;
            assert(GET_ERROR_TYPE(FM_PORT_SetPCD(&f.port, &f.params)) == E_NOT_SUPPORTED);
            assert(!memcmp(&f, &before, sizeof(f)));
            assert(owners == env_owners && binds == root_binds && calls == settings_calls);
            f.port.lock = false; f.params = valid;
            if (configured) assert(FM_PORT_DeletePCD(&f.port) == E_OK);
            else retry(&f);
            finish(&f);
        }
    }
    /* Real API validation failures must leave the same port available. */
    for (unsigned invalid = 0; invalid < 6; invalid++) {
        init(&f, false, true);
        t_FmPortPcdParams valid = f.params;
        if (invalid == 0) f.cc.h_CcTree = NULL;
        if (invalid == 1) f.params.h_IpReassemblyManip = f.params.h_CapwapReassemblyManip = (void *)3;
        if (invalid == 2) f.params.h_CapwapReassemblyManip = (void *)3;
        if (invalid == 3) { f.params.h_IpReassemblyManip = (void *)3; f.params.pcdSupport = e_FM_PORT_PCD_SUPPORT_PRS_ONLY; }
        if (invalid == 4) { f.params.h_IpReassemblyManip = (void *)3; f.params.p_CcParams = NULL; }
        if (invalid == 5) f.params.p_PrsParams = NULL;
        assert(FM_PORT_SetPCD(&f.port, &f.params) != E_OK); clean(&f);
        f.params = valid; f.cc.h_CcTree = (void *)2; retry(&f); finish(&f);
    }
    for (unsigned offload = 0; offload < 2; offload++) {
        advanced = offload;
        for (unsigned oh = 0; oh < 2; oh++) {
            for (enum fault fault = CC_BIND; fault <= RISC_ATTACH; fault++) {
                if (fault == PARSER || fault == SETTINGS) continue;
                init(&f, oh, true); failure = fault;
                assert(FM_PORT_SetPCD(&f.port, &f.params) != E_OK); clean(&f);
                retry(&f); finish(&f);
            }
            /* Fail each post-binding settings call, including the last MURAM setup. */
            for (unsigned call = 1; call <= (offload ? (oh ? 3 : 2) : 1); call++) {
                init(&f, oh, true); settings_fail = call;
                assert(FM_PORT_SetPCD(&f.port, &f.params) != E_OK); clean(&f);
                retry(&f); finish(&f);
            }
            for (unsigned fe = 0; fe < 2; fe++) {
                for (unsigned allocation = 1; allocation <= (fe ? 3 : 1); allocation++) {
                    init(&f, oh, true); use_fe = fe; muram_fail = allocation;
                    assert(FM_PORT_SetPCD(&f.port, &f.params) != E_OK); clean(&f);
                    retry(&f); finish(&f);
                }
            }
            for (enum fault cleanup = STATS_DISABLE; cleanup <= CC_UNBIND; cleanup++) {
                for (unsigned setup_fail = 0; setup_fail < 2; setup_fail++) {
                    for (unsigned next_set = 0; next_set < 2; next_set++) {
                        init(&f, oh, true); use_fe = true;
                        cleanup_failure = cleanup;
                        if (setup_fail) {
                            failure = RISC_ATTACH;
                            assert(FM_PORT_SetPCD(&f.port, &f.params) != E_OK);
                        } else {
                            assert(FM_PORT_SetPCD(&f.port, &f.params) == E_OK);
                            assert(FM_PORT_DeletePCD(&f.port) != E_OK);
                        }
                        unlocked(&f); assert(env_owners && f.port.pcdNetEnvOwner && !f.port.pcdConfigured);
                        unsigned owners = env_owners, r = roots, p = plans, s = schemes;
                        assert(FM_PORT_DeletePCD(&f.port) != E_OK); unlocked(&f);
                        assert(env_owners == owners && roots == r && plans == p && schemes == s);
                        assert(FM_PORT_AttachPCD(&f.port) != E_OK); unlocked(&f);
                        assert(FM_PORT_Free(&f.port) != E_OK); unlocked(&f);
                        t_FmPcdPortSchemesParams bind = {.numOfSchemes = 1, .h_Schemes = {(void *)1}};
                        assert(FM_PORT_PcdKgBindSchemes(&f.port, &bind) != E_OK); unlocked(&f);
                        failure = cleanup_failure = NONE;
                        if (!next_set) { assert(FM_PORT_DeletePCD(&f.port) == E_OK); clean(&f); }
                        retry(&f); finish(&f);
                    }
                }
            }
            /* A refused global delete lock changes neither registers nor owners. */
            init(&f, oh, false); assert(FM_PORT_SetPCD(&f.port, &f.params) == E_OK);
            t_FmPort saved = f.port; union fman_port_bmi_regs bmi = f.bmi; unsigned owners = env_owners;
            failure = ALL_LOCK;
            assert(FM_PORT_DeletePCD(&f.port) != E_OK); unlocked(&f);
            assert(env_owners == owners && !memcmp(&saved, &f.port, sizeof(saved)) && !memcmp(&bmi, &f.bmi, sizeof(bmi)));
            failure = HC_SYNC;
            assert(FM_PORT_DeletePCD(&f.port) != E_OK); unlocked(&f);
            assert(env_owners == owners && f.port.pcdConfigured && roots == 1 && schemes == 1 && plans == 1);
            failure = RISC_DETACH;
            assert(FM_PORT_DeletePCD(&f.port) != E_OK); unlocked(&f); assert(env_owners == owners);
            failure = NONE;
            assert(FM_PORT_DetachPCD(&f.port) == E_OK);
            assert(FM_PORT_DeletePCD(&f.port) == E_OK); clean(&f); retry(&f); finish(&f);
        }
    }
    /* Inner rollback can fail too; the outer retry must retain its remainder. */
    for (unsigned test = 0; test < 3; test++) {
        init(&f, false, true);
        failure = test == 0 ? PLAN_BIND : test == 1 ? SCHEME_BIND : PARSER;
        if (test == 2) { f.prs.numOfHdrsWithAdditionalParams = 1; f.prs.additionalParams[0].hdr = HEADER_TYPE_ETH; }
        cleanup_failure = test == 0 ? CC_UNBIND : test == 1 ? PLAN_UNBIND : SCHEME_UNBIND;
        assert(FM_PORT_SetPCD(&f.port, &f.params) != E_OK); unlocked(&f);
        assert(f.port.pcdNetEnvOwner && env_owners && reports == 2);
        retry(&f); finish(&f);
    }
    /* Dynamic scheme removal/rebinding must agree with later port deletion. */
    for (unsigned rebind = 0; rebind < 2; rebind++) {
        init(&f, false, true);
        assert(FM_PORT_SetPCD(&f.port, &f.params) == E_OK);
        t_FmPcdPortSchemesParams bind = {.numOfSchemes = 1, .h_Schemes = {(void *)1}};
        assert(FM_PORT_PcdKgUnbindSchemes(&f.port, &bind) == E_OK);
        assert(!f.port.pcdBindings.schemes && !schemes);
        if (rebind) {
            assert(FM_PORT_PcdKgBindSchemes(&f.port, &bind) == E_OK);
            assert(f.port.pcdBindings.schemes && schemes == 1);
        }
        assert(FM_PORT_DeletePCD(&f.port) == E_OK); finish(&f);
    }
    /* Minimal engine configurations do not acquire nonexistent bindings. */
    e_FmPortPcdSupport modes[] = {e_FM_PORT_PCD_SUPPORT_PRS_ONLY,
        e_FM_PORT_PCD_SUPPORT_CC_ONLY, e_FM_PORT_PCD_SUPPORT_PLCR_ONLY,
        e_FM_PORT_PCD_SUPPORT_PRS_AND_PLCR, e_FM_PORT_PCD_SUPPORT_PRS_AND_KG};
    for (unsigned mode = 0; mode < sizeof(modes) / sizeof(modes[0]); mode++) {
        init(&f, mode == 1, true);
        t_FmPortPcdPlcrParams plcr = {.h_Profile = (void *)4};
        f.params.pcdSupport = modes[mode];
        if (mode != 1) f.params.p_CcParams = NULL;
        if (mode != 4) f.params.p_KgParams = NULL;
        if (mode == 1 || mode == 2) f.params.p_PrsParams = NULL;
        if (mode == 2 || mode == 3) f.params.p_PlcrParams = &plcr;
        retry(&f); finish(&f);
    }
    printf("SDK public PCD API: %u setup, cleanup, allocation, lock and retry cases passed\n", cases);
    return 0;
}
