/* Actual native/compat ioctl, SDK scheme-set validation and fmlib code.
 * Register construction, locks, transport and cookie registry are boundaries. */
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#define __CORE_EXT_H
#define __ERR_MODULE__ MODULE_FM
#include "fm_pcd.h"
#include "fm_kg.h"
#include "fm_hc.h"
#define CONFIG_COMPAT
#define FM_COMPAT
#include "fm_pcd_ioctls.h"
#include "fm_port_ioctls.h"
#include "lnxwrp_ioctls_fm_compat.h"
#undef ASSERT_COND
#undef REPORT_ERROR
#undef RETURN_ERROR
#undef DBG
#define ASSERT_COND assert
#define REPORT_ERROR(level, err, msg) ((void)0)
#define RETURN_ERROR(level, err, msg) return ERROR_CODE(err)
#define DBG(level, msg) ((void)0)
#define BUILD_BUG_ON(condition) _Static_assert(!(condition), #condition)
typedef struct { t_Handle h_PcdDev; } t_LnxWrpFmDev;
typedef struct { uintptr_t id; int fd; t_Handle h_UserPriv; uint32_t owners; } t_Device;
#define DEV_TO_ID(p) do { t_Device *dev = (p); (p) = UINT_TO_PTR(dev->id); } while (0)
#define _fml_dbg(...) ((void)0)
enum fm_pcd_cookie_type { FM_PCD_COOKIE_NET_ENV, FM_PCD_COOKIE_SCHEME, FM_PCD_COOKIE_CC_TREE };
static unsigned allocations, allocation_calls, fail_allocation, sdk_calls;
static bool want_direct, want_modify, refuse_sdk;
static uint32_t want_fqid;
static ioc_fm_pcd_engine want_engine;
static t_FmPcdKg kg;
static t_FmPcd pcd = {.p_FmPcdKg = &kg};
static t_FmPcdLock scheme_lock;
static unsigned lock_calls, hardware_calls;
static unsigned char cc_tree;
#define SCHEME (&kg.schemes[7])

static void prepare_sdk(void)
{
    memset(&kg, 0, sizeof(kg));
    memset(&scheme_lock, 0, sizeof(scheme_lock));
    kg.numOfSchemes = 8;
    kg.schemesIds[7] = 7;
    SCHEME->h_FmPcd = &pcd;
    SCHEME->p_Lock = want_modify ? &scheme_lock : NULL;
    SCHEME->valid = want_modify;
    SCHEME->netEnvId = want_direct ? ILLEGAL_NETENV : 0;
    lock_calls = hardware_calls = 0;
}
void *XX_Malloc(uint32_t size)
{ if (++allocation_calls == fail_allocation) return NULL; void *p = malloc(size); assert(p); allocations++; return p; }
void XX_Free(void *p) { assert(p && allocations); allocations--; free(p); }
static int copy_from_user(void *dest, const void *src, size_t size) { memcpy(dest, src, size); return 0; }
static int copy_to_user(void *dest, const void *src, size_t size) { memcpy(dest, src, size); return 0; }
static t_Error fm_pcd_cookie_to_handle(void **field, enum fm_pcd_cookie_type type)
{
    if (!*field) return E_OK;
    uintptr_t id = (uintptr_t)*field;
    if (id != (uintptr_t)type + 1) return E_INVALID_SELECTION;
    void *handles[] = {&pcd.netEnvs[0], SCHEME, &cc_tree};
    *field = handles[type];
    return E_OK;
}
static uint64_t fm_pcd_cookie_create(void *handle, enum fm_pcd_cookie_type type)
{ assert(handle == SCHEME && type == FM_PCD_COOKIE_SCHEME); return 2; }
compat_uptr_t compat_get_ptr2id(void *p, enum fm_map_node_type type) { return (uintptr_t)p; }
compat_uptr_t compat_add_ptr2id(void *p, enum fm_map_node_type type) { return (uintptr_t)p; }
void *compat_get_id2ptr(compat_uptr_t id, enum fm_map_node_type type) { return (void *)(uintptr_t)id; }

static t_Error BuildSchemeRegs(t_Handle scheme, t_FmPcdKgSchemeParams *params,
                               struct fman_kg_scheme_regs *regs)
{
    sdk_calls++;
    t_FmPcdKgScheme *candidate = scheme;
    assert(candidate != SCHEME && candidate->h_FmPcd == &pcd);
    assert(candidate->p_Lock == &scheme_lock && scheme_lock.flag);
    assert(!params->shared && params->alwaysDirect == want_direct && params->modify == want_modify);
    assert(params->netEnvParams.h_NetEnv == (want_direct ? NULL : &pcd.netEnvs[0]));
    assert(params->baseFqid == want_fqid && (int)params->nextEngine == (int)want_engine);
    if (want_modify) assert(params->id.h_Scheme == SCHEME);
    else assert(params->id.relativeSchemeId == 7);
    if (want_engine == e_IOC_FM_PCD_CC) assert(params->kgNextEngineParams.cc.h_CcTree == &cc_tree);
    else assert(params->kgNextEngineParams.doneAction == e_FM_PCD_DROP_FRAME);
    memset(regs, 0, sizeof(*regs));
    candidate->netEnvId = want_direct ? ILLEGAL_NETENV : 0;
    return refuse_sdk ? E_INVALID_VALUE : E_OK;
}
void XX_Print(char *format, ...) { assert(!"unexpected SDK assertion"); }
void XX_Exit(int status) { assert(!"unexpected SDK exit"); }
uint32_t XX_LockIntrSpinlock(t_Handle handle) { return 0; }
void XX_UnlockIntrSpinlock(t_Handle handle, uint32_t flags) {}
uint32_t FmPcdLock(t_Handle handle) { assert(handle == &pcd); return 0; }
void FmPcdUnlock(t_Handle handle, uint32_t flags) { assert(handle == &pcd); }
void FmPcdIncNetEnvOwners(t_Handle handle, uint8_t id) { assert(handle == &pcd && !id); }
void FmPcdDecNetEnvOwners(t_Handle handle, uint8_t id) { assert(handle == &pcd && !id); }
bool FmPcdKgIsSchemeValidSw(t_Handle scheme) { return ((t_FmPcdKgScheme *)scheme)->valid; }
t_FmPcdLock *FmPcdAcquireLock(t_Handle handle)
{ assert(handle == &pcd); lock_calls++; return &scheme_lock; }
void FmPcdReleaseLock(t_Handle handle, t_FmPcdLock *lock)
{ assert(handle == &pcd && lock == &scheme_lock); lock_calls++; lock->flag = false; }
static bool KgSchemeFlagTryLock(t_FmPcdKgScheme *scheme)
{ assert(scheme == SCHEME && !scheme_lock.flag); lock_calls++; scheme_lock.flag = true; return true; }
static void KgSchemeFlagUnlock(t_FmPcdKgScheme *scheme)
{ assert(scheme == SCHEME && scheme_lock.flag); scheme_lock.flag = false; }
static void ValidateSchemeSw(t_FmPcdKgScheme *scheme) { scheme->valid = true; }
bool FmIsHcUsageAllowed(t_Handle handle) { return true; }
t_Error FmHcPcdKgSetScheme(t_Handle hc, t_Handle scheme, struct fman_kg_scheme_regs *regs, bool counter)
{ assert(scheme == SCHEME); hardware_calls++; return E_OK; }
static uint32_t KgHwLock(t_FmPcdKg *kg) { assert(!"unexpected direct-register write"); return 0; }
static void KgHwUnlock(t_FmPcdKg *kg, uint32_t flags) { assert(!"unexpected direct-register write"); }
static t_Error WriteKgarWait(t_FmPcd *pcd, uint32_t value) { assert(!"unexpected direct-register write"); return E_OK; }
uint32_t FmPcdKgBuildWriteSchemeActionReg(uint8_t scheme, bool counter) { return 0; }
#include "scheme_set_production.inc"
t_Error FM_PCD_KgSchemeDelete(t_Handle scheme) { assert(!"unexpected cookie exhaustion"); return E_OK; }
#include "scheme_compat_production.inc"
#include "scheme_ioctl_production.inc"
static t_LnxWrpFmDev device = {.h_PcdDev = &pcd};
static int library_ioctl(int fd, unsigned long command, void *params)
{
    assert(fd == 10 && command == FM_PCD_IOC_KG_SCHEME_SET);
    ioc_fm_pcd_kg_scheme_params_t *p = params;
    assert(p->always_direct == want_direct);
    /* The old SDK bool in byte 17 must not become an undocumented flag. */
    assert(!((unsigned char *)params)[17]);
    prepare_sdk();
    return scheme_ioctl(&device, command, (uintptr_t)params, false) ? -1 : 0;
}
#define ioctl library_ioctl
#include "scheme_fmlib_production.inc"
#undef ioctl

int main(void)
{
    assert(FM_PCD_IOC_KG_SCHEME_SET == 0xc558e12c && sizeof(ioc_fm_pcd_kg_scheme_params_t) == 1368);
    assert(offsetof(t_FmPcdKgSchemeParams, shared) == 16 && offsetof(t_FmPcdKgSchemeParams, alwaysDirect) == 17);
    for (unsigned direct = 0; direct < 2; direct++) {
        for (unsigned modify = 0; modify < 2; modify++) {
            for (unsigned cc = 0; cc < 2; cc++) {
                want_direct = direct; want_modify = modify;
                want_fqid = 0x12345; want_engine = cc ? e_IOC_FM_PCD_CC : e_IOC_FM_PCD_DONE;
                for (unsigned compat = 0; compat < 2; compat++) {
                    static ioc_fm_pcd_kg_scheme_params_t p;
                    static ioc_compat_fm_pcd_kg_scheme_params_t cp;
                    memset(&p, 0, sizeof(p)); memset(&cp, 0, sizeof(cp));
                    p.modify = modify; p.always_direct = direct;
                    p.scm_id.scheme_id = (void *)(uintptr_t)(modify ? 2 : 7);
                    p.net_env_params.net_env_id = direct ? NULL : (void *)1;
                    p.base_fqid = want_fqid; p.next_engine = want_engine;
                    if (cc) p.kg_next_engine_params.cc.tree_id = (void *)3;
                    else p.kg_next_engine_params.done_action = e_IOC_FM_PCD_DROP_FRAME;
                    if (compat) compat_copy_fm_pcd_kg_scheme(&cp, &p, COMPAT_K_TO_US);
                    /* Poison SDK flag padding: only the public flag counts. */
                    ((unsigned char *)&p)[17] = !direct;
                    unsigned cmd = compat ? FM_PCD_IOC_KG_SCHEME_SET_COMPAT : FM_PCD_IOC_KG_SCHEME_SET;
                    void *arg = compat ? (void *)&cp : (void *)&p;
                    unsigned before = sdk_calls;
                    prepare_sdk();
                    assert(scheme_ioctl(&device, cmd, (uintptr_t)arg, compat) == E_OK);
                    assert(sdk_calls == before + 1 && !allocations);
                    assert(compat ? cp.id == 2 : p.id == (void *)2);
                    assert(compat ? cp.always_direct == direct : p.always_direct == direct);
                    assert(compat ? cp.net_env_params.net_env_id == !direct : p.net_env_params.net_env_id == (void *)(uintptr_t)!direct);
                    if (cc) assert(compat ? cp.kg_next_engine_params.cc.tree_id == 3 : p.kg_next_engine_params.cc.tree_id == (void *)3);
                    else assert(compat ? cp.kg_next_engine_params.done_action == 1 : p.kg_next_engine_params.done_action == 1);
                    refuse_sdk = true;
                    prepare_sdk();
                    assert(scheme_ioctl(&device, cmd, (uintptr_t)arg, compat) != E_OK);
                    refuse_sdk = false; assert(!allocations);
                    for (unsigned failure = 1; failure <= (compat ? 4 : 2); failure++) {
                        allocation_calls = 0; fail_allocation = failure;
                        prepare_sdk();
                        assert(scheme_ioctl(&device, cmd, (uintptr_t)arg, compat) != E_OK);
                        assert(!allocations);
                    }
                    fail_allocation = 0;
                    if (!direct) {
                        /* Reject through the real SDK entry before acquiring a
                         * lock, altering an existing scheme or building regs. */
                        p.net_env_params.net_env_id = NULL;
                        cp.net_env_params.net_env_id = 0;
                        prepare_sdk();
                        t_FmPcdKgScheme saved = *SCHEME;
                        before = sdk_calls;
                        assert(scheme_ioctl(&device, cmd, (uintptr_t)arg, compat) != E_OK);
                        assert(sdk_calls == before && !allocations && !lock_calls && !hardware_calls);
                        assert(!memcmp(SCHEME, &saved, sizeof(saved)));
                    }
                }
                for (unsigned shared = 0; shared < 2; shared++) {
                    t_Device pcd = {.fd = 10}, env = {.id = 1}, scheme = {.id = 2}, tree = {.id = 3};
                    t_FmPcdKgSchemeParams p = {.modify = modify, .shared = shared, .alwaysDirect = direct,
                        .baseFqid = want_fqid, .nextEngine = (e_FmPcdEngine)want_engine};
                    if (modify) p.id.h_Scheme = &scheme; else p.id.relativeSchemeId = 7;
                    p.netEnvParams.h_NetEnv = direct ? NULL : &env;
                    if (cc) p.kgNextEngineParams.cc.h_CcTree = &tree;
                    else p.kgNextEngineParams.doneAction = e_FM_PCD_DROP_FRAME;
                    t_Device *result = LibrarySchemeSet(&pcd, &p);
                    assert(result && result->id == 2 && !allocations);
                    assert(pcd.owners == !modify && p.alwaysDirect == direct && p.shared == shared);
                    if (modify) assert(result == &scheme);
                    else free(result);
                }
            }
        }
    }
    puts("Scheme ioctl: native/compat flags, missing-netenv rejection, cookies, copy-out, allocation failure and fmlib shared/direct combinations passed");
}
