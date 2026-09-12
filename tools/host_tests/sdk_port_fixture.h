/* Actual port configuration/rollback with counted classifier bindings. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define __CORE_EXT_H
#define __ERR_MODULE__ MODULE_FM_PORT
#include "fm_port.h"
#include "fm_prs.h"
#undef ASSERT_COND
#undef REPORT_ERROR
#undef RETURN_ERROR
#undef SANITY_CHECK_RETURN_ERROR
#define ASSERT_COND assert
#define REPORT_ERROR(level, err, msg) (reports++)
#define RETURN_ERROR(level, err, msg) return (err)
#define SANITY_CHECK_RETURN_ERROR(cond, err) do { if (!(cond)) return (err); } while (0)
#define fallthrough __attribute__((fallthrough))

enum fault { NONE, CC_BIND, PLAN_BIND, SCHEME_BIND, VSPE, PARSER,
    PORT_LOCK, ALL_LOCK, STATS_ENABLE,
    SETTINGS, RISC_ATTACH, RISC_DETACH, STATS_DISABLE, SCHEME_UNBIND,
    PLAN_UNBIND, CC_UNBIND, HC_SYNC };
static enum fault failure, cleanup_failure;
static unsigned reports, statistics;
static bool advanced;
static unsigned roots, plans, schemes;
static unsigned root_binds, plan_binds, scheme_binds;
uint8_t FmPcdGetNetEnvId(t_Handle env) { return 0; }
uint8_t FmPcdKgGetSchemeId(t_Handle scheme) { return 3; }
bool FmPcdKgGetVspe(t_Handle scheme) { return failure == VSPE; }
bool FmPcdIsAdvancedOffloadSupported(t_Handle pcd) { return advanced; }
bool FmPcdNetEnvIsHdrExist(t_Handle pcd, uint8_t env, e_NetHeaderType hdr) { return false; }
uint32_t FmPcdGetLcv(t_Handle pcd, uint32_t env, uint8_t hdr) { return 0; }
uint32_t FmPcdGetSwPrsOffset(t_Handle pcd, e_NetHeaderType hdr, uint8_t index) { return ILLEGAL_BASE; }
uint16_t FmPcdPlcrProfileGetAbsoluteId(t_Handle profile) { return 0; }
bool FmPcdPlcrIsProfileValid(t_Handle pcd, uint16_t id) { return true; }
#ifdef TEST_PUBLIC_API
static t_Error bind_port_resources(t_Handle port);
#else
static t_Error bind_port_resources(t_Handle port) { return E_OK; }
#endif
t_Error FmPcdCcBindTree(t_Handle pcd, t_Handle params, t_Handle tree,
                      uint32_t *offset, t_Handle port)
{
    root_binds++;
    if (failure == CC_BIND) return E_NO_MEMORY;
    t_Error err = bind_port_resources(port); if (err) return err;
    roots++; *offset = 0x100; return E_OK;
}
t_Error FmPcdCcUnbindTree(t_Handle pcd, t_Handle tree)
{ assert(roots); if (cleanup_failure == CC_UNBIND) return E_BUSY; roots--; return E_OK; }
t_Error FmPcdKgSetOrBindToClsPlanGrp(t_Handle pcd, uint8_t port, uint8_t env,
                                   protocolOpt_t *opts, uint8_t *id, bool *empty)
{
    plan_binds++;
    if (failure == PLAN_BIND) return E_NO_MEMORY;
    plans++; *id = 2; *empty = false; opts[0] = ETH_BROADCAST; opts[1] = 0;
    return E_OK;
}
t_Error FmPcdKgDeleteOrUnbindPortToClsPlanGrp(t_Handle pcd, uint8_t port, uint8_t id)
{ assert(plans && id == 2); if (cleanup_failure == PLAN_UNBIND) return E_BUSY; plans--; return E_OK; }
t_Error FmPcdKgBindPortToSchemes(t_Handle pcd, t_FmPcdKgInterModuleBindPortToSchemes *bind)
{
    scheme_binds++; assert(plans && bind->numOfSchemes == 1);
    if (failure == SCHEME_BIND) return E_NO_MEMORY;
    schemes++; return E_OK;
}
t_Error FmPcdKgUnbindPortToSchemes(t_Handle pcd, t_FmPcdKgInterModuleBindPortToSchemes *bind)
{ assert(schemes && bind->numOfSchemes == 1 && bind->schemesIds[0] == 3); if (cleanup_failure == SCHEME_UNBIND) return E_BUSY; schemes--; return E_OK; }
t_Error FmPcdPrsIncludePortInStatistics(t_Handle pcd, uint8_t port, bool enable)
{
    if (enable) { if (failure == STATS_ENABLE) return E_NO_MEMORY; assert(!statistics); statistics++; }
    else { assert(statistics); if (cleanup_failure == STATS_DISABLE) return E_BUSY; statistics--; }
    return E_OK;
}
static t_Error AdditionalPrsParams(t_FmPort *port, t_FmPcdPrsAdditionalHdrParams *params, uint32_t *reg)
{ return failure == PARSER ? E_INVALID_VALUE : E_OK; }
static void FmPortCheckNApplyMacsec(t_Handle port) {}
