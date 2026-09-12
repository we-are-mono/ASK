/* Actual classification-plan acquisition with allocation and HC failures. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define __CORE_EXT_H
#define __ERR_MODULE__ MODULE_FM_PCD
#include "fm_pcd.h"
#include "fm_hc.h"
#include "fm_pcd_ipc.h"
#include "fm_kg.h"
#undef ASSERT_COND
#undef REPORT_ERROR
#undef RETURN_ERROR
#define ASSERT_COND assert
#define REPORT_ERROR(level, err, msg) assert(!"unexpected cleanup failure")
#define RETURN_ERROR(level, err, msg) return (err)

static unsigned failure, options, allocations, entries;
static bool hc;
void *XX_Malloc(uint32_t size)
{ if (failure == 1) return NULL; void *p = malloc(size); assert(p); allocations++; return p; }
void XX_Free(void *p) { assert(p && allocations); allocations--; free(p); }
t_Error XX_IpcSendMessage(t_Handle session, uint8_t *msg, uint32_t length,
                         uint8_t *reply, uint32_t *reply_length,
                         t_IpcMsgCompletion *complete, t_Handle arg)
{ assert(!"guest IPC is outside this fixture"); return E_NOT_SUPPORTED; }
void FmPcdIncNetEnvOwners(t_Handle handle, uint8_t id)
{ t_FmPcd *pcd = handle; pcd->netEnvs[id].owners++; }
void FmPcdDecNetEnvOwners(t_Handle handle, uint8_t id)
{ t_FmPcd *pcd = handle; assert(pcd->netEnvs[id].owners); pcd->netEnvs[id].owners--; }
void FmPcdSetClsPlanGrpId(t_FmPcd *pcd, uint8_t env, uint8_t id)
{ pcd->netEnvs[env].clsPlanGrpId = id; }
t_Error PcdGetClsPlanGrpParams(t_FmPcd *pcd, t_FmPcdKgInterModuleClsPlanGrpParams *params)
{
    params->numOfOptions = options;
    params->options[0] = ETH_BROADCAST; params->optVectors[0] = 1;
    params->grpExists = pcd->p_FmPcdKg->clsPlanGrps[0].used;
    if (params->grpExists) params->clsPlanGrpId = 0;
    return E_OK;
}
t_Error KgAllocClsPlanEntries(t_Handle pcd, uint16_t count, uint8_t guest, uint8_t *base)
{ if (failure == 2) return E_NO_MEMORY; assert(!entries); entries = count; *base = 8; return E_OK; }
void KgFreeClsPlanEntries(t_Handle pcd, uint16_t count, uint8_t guest, uint8_t base)
{ assert(entries == count && base == 8); entries = 0; }
bool FmIsHcUsageAllowed(t_Handle handle) { return hc; }
t_Error FmHcPcdKgSetClsPlan(t_Handle handle, t_FmPcdKgInterModuleClsPlanSet *set)
{ assert(entries && set->baseEntry == 8); return failure == 3 ? E_NO_MEMORY : E_OK; }
void KgSetClsPlan(t_Handle pcd, t_FmPcdKgInterModuleClsPlanSet *set)
{ assert(entries && set->baseEntry == 8); }
static t_Error BindPortToClsPlanGrp(t_FmPcd *pcd, uint8_t port, uint8_t id)
{ assert(entries && pcd->p_FmPcdKg->clsPlanGrps[id].used); return failure == 4 ? E_NO_MEMORY : E_OK; }
#include "kg_plan_production.inc"

static void release(t_FmPcd *pcd, uint8_t id)
{
    t_FmPcdKgClsPlanGrp *grp = &pcd->p_FmPcdKg->clsPlanGrps[id];
    assert(grp->owners);
    if (!--grp->owners) FmPcdKgDestroyClsPlanGrp(pcd, id);
}

int main(void)
{
    for (options = 0; options < 2; options++) {
        for (unsigned host_command = 0; host_command < 2; host_command++) {
            for (unsigned shared = 0; shared < 2; shared++) {
                for (unsigned fault = 0; fault <= 4; fault++) {
                    if ((shared && fault && fault != 4) || (!host_command && fault == 3)) continue;
                    t_FmPcdKg kg = {.emptyClsPlanGrpId = ILLEGAL_CLS_PLAN};
                    t_FmPcd pcd = {.guestId = NCSW_MASTER_ID, .p_FmPcdKg = &kg};
                    pcd.netEnvs[0].clsPlanGrpId = ILLEGAL_CLS_PLAN;
                    protocolOpt_t opts[FM_PCD_MAX_NUM_OF_OPTIONS(FM_PCD_MAX_NUM_OF_CLS_PLANS)] = {0};
                    uint8_t id = ILLEGAL_CLS_PLAN; bool empty = false;
                    failure = 0; hc = host_command;
                    if (shared) assert(FmPcdKgSetOrBindToClsPlanGrp(&pcd, 1, 0, opts, &id, &empty) == E_OK);
                    failure = fault;
                    t_Error ret = FmPcdKgSetOrBindToClsPlanGrp(&pcd, 2, 0, opts, &id, &empty);
                    assert(fault ? ret != E_OK : ret == E_OK);
                    if (!fault) {
                        assert(kg.clsPlanGrps[id].owners == shared + 1);
                        assert(empty == !options);
                        release(&pcd, id);
                    }
                    assert(!allocations);
                    assert(kg.clsPlanGrps[0].owners == shared && kg.clsPlanGrps[0].used == (bool)shared);
                    assert(pcd.netEnvs[0].owners == (shared && options));
                    assert(shared ? entries != 0 : entries == 0);
                    assert(shared || (kg.emptyClsPlanGrpId == ILLEGAL_CLS_PLAN && pcd.netEnvs[0].clsPlanGrpId == ILLEGAL_CLS_PLAN));
                    failure = 0;
                    assert(FmPcdKgSetOrBindToClsPlanGrp(&pcd, 2, 0, opts, &id, &empty) == E_OK);
                    release(&pcd, id);
                    if (shared) release(&pcd, id);
                    assert(!entries && !allocations && !pcd.netEnvs[0].owners);
                }
            }
        }
    }
    puts("SDK classification plans: allocation, programming, binding, shared owners and retry passed");
    return 0;
}
