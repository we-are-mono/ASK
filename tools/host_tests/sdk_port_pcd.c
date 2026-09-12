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
#define REPORT_ERROR(level, err, msg) assert(!"unexpected cleanup failure")
#define RETURN_ERROR(level, err, msg) return (err)
#define SANITY_CHECK_RETURN_ERROR(cond, err) do { if (!(cond)) return (err); } while (0)
#define fallthrough __attribute__((fallthrough))

enum fault { NONE, CC_BIND, PLAN_BIND, SCHEME_BIND, VSPE, PARSER };
static enum fault failure;
static unsigned roots, plans, schemes;
static unsigned root_binds, plan_binds, scheme_binds;
uint8_t FmPcdGetNetEnvId(t_Handle env) { return 0; }
uint8_t FmPcdKgGetSchemeId(t_Handle scheme) { return 3; }
bool FmPcdKgGetVspe(t_Handle scheme) { return failure == VSPE; }
bool FmPcdIsAdvancedOffloadSupported(t_Handle pcd) { return false; }
bool FmPcdNetEnvIsHdrExist(t_Handle pcd, uint8_t env, e_NetHeaderType hdr) { return false; }
uint32_t FmPcdGetLcv(t_Handle pcd, uint32_t env, uint8_t hdr) { return 0; }
uint32_t FmPcdGetSwPrsOffset(t_Handle pcd, e_NetHeaderType hdr, uint8_t index) { return ILLEGAL_BASE; }
uint16_t FmPcdPlcrProfileGetAbsoluteId(t_Handle profile) { return 0; }
bool FmPcdPlcrIsProfileValid(t_Handle pcd, uint16_t id) { return true; }
t_Error FmPcdCcBindTree(t_Handle pcd, t_Handle params, t_Handle tree,
                      uint32_t *offset, t_Handle port)
{
    root_binds++;
    if (failure == CC_BIND) return E_NO_MEMORY;
    roots++; *offset = 0x100; return E_OK;
}
t_Error FmPcdCcUnbindTree(t_Handle pcd, t_Handle tree)
{ assert(roots); roots--; return E_OK; }
t_Error FmPcdKgSetOrBindToClsPlanGrp(t_Handle pcd, uint8_t port, uint8_t env,
                                   protocolOpt_t *opts, uint8_t *id, bool *empty)
{
    plan_binds++; assert(roots);
    if (failure == PLAN_BIND) return E_NO_MEMORY;
    plans++; *id = 2; *empty = false; opts[0] = ETH_BROADCAST; opts[1] = 0;
    return E_OK;
}
t_Error FmPcdKgDeleteOrUnbindPortToClsPlanGrp(t_Handle pcd, uint8_t port, uint8_t id)
{ assert(plans && id == 2); plans--; return E_OK; }
t_Error FmPcdKgBindPortToSchemes(t_Handle pcd, t_FmPcdKgInterModuleBindPortToSchemes *bind)
{
    scheme_binds++; assert(plans && bind->numOfSchemes == 1);
    if (failure == SCHEME_BIND) return E_NO_MEMORY;
    schemes++; return E_OK;
}
t_Error FmPcdKgUnbindPortToSchemes(t_Handle pcd, t_FmPcdKgInterModuleBindPortToSchemes *bind)
{ assert(schemes && bind->numOfSchemes == 1 && bind->schemesIds[0] == 3); schemes--; return E_OK; }
t_Error FmPcdPrsIncludePortInStatistics(t_Handle pcd, uint8_t port, bool enable) { return E_OK; }
static t_Error AdditionalPrsParams(t_FmPort *port, t_FmPcdPrsAdditionalHdrParams *params, uint32_t *reg)
{ return failure == PARSER ? E_INVALID_VALUE : E_OK; }
static void FmPortCheckNApplyMacsec(t_Handle port) {}
#include "port_pcd_production.inc"

int main(void)
{
    for (unsigned shared = 0; shared < 2; shared++) {
        for (unsigned test = 0; test < 11; test++) {
            union fman_port_bmi_regs bmi = {0};
            t_FmPortPrsRegs prs_regs = {0};
            t_FmPort port = {.portType = e_FM_PORT_TYPE_RX, .p_FmPortPrsRegs = &prs_regs};
            port.port.bmi_regs = &bmi;
            bmi.rx.fmbm_rfne = GET_NO_PCD_NIA_BMI_AC_ENQ_FRAME();
            t_FmPortPcdPrsParams prs = {.firstPrsHdr = HEADER_TYPE_ETH};
            t_FmPortPcdKgParams kg = {.numOfSchemes = 1, .h_Schemes = {(void *)1}};
            t_FmPortPcdCcParams cc = {.h_CcTree = (void *)2};
            t_FmPortPcdParams params = {.pcdSupport = e_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_CC,
                                      .p_PrsParams = &prs, .p_KgParams = &kg, .p_CcParams = &cc};
            roots = plans = schemes = shared;
            root_binds = plan_binds = scheme_binds = 0;
            failure = test <= PARSER ? test : NONE;
            if (test == PARSER) { prs.numOfHdrsWithAdditionalParams = 1; prs.additionalParams[0].hdr = HEADER_TYPE_ETH; }
            if (test == 6) kg.numOfSchemes = 0;
            if (test == 7) prs.firstPrsHdr = HEADER_TYPE_NONE;
            if (test == 8) { kg.directScheme = true; kg.h_DirectScheme = (void *)3; }
            if (test == 9) prs.numOfHdrsWithAdditionalParams = FM_PCD_PRS_NUM_OF_HDRS + 1;
            if (test == 10) params.p_PrsParams = NULL;
            int ret = SetPcd(&port, &params);
            assert(test ? ret != E_OK : ret == E_OK);
            if (!test) {
                assert(roots == shared + 1 && plans == shared + 1 && schemes == shared + 1);
                assert(SetPcd(&port, &params) != E_OK);
                assert(DeletePcd(&port) == E_OK);
            } else {
                assert(!port.pcdEngines && !port.schemesPerPortVector && !port.ccTreeId && !port.useClsPlan);
                for (unsigned i = 0; i < sizeof(port.optArray) / sizeof(port.optArray[0]); i++) assert(!port.optArray[i]);
            }
            assert(roots == shared && plans == shared && schemes == shared);
            /* Retry on the same port object, without resetting its state. */
            failure = NONE; params.p_PrsParams = &prs; prs.firstPrsHdr = HEADER_TYPE_ETH;
            prs.numOfHdrsWithAdditionalParams = 0; kg.numOfSchemes = 1; kg.directScheme = false;
            assert(SetPcd(&port, &params) == E_OK);
            assert(DeletePcd(&port) == E_OK);
            assert(roots == shared && plans == shared && schemes == shared);
        }
    }
    puts("SDK port PCD: partial bindings, validation failures, shared owners and same-port retry passed");
    return 0;
}
