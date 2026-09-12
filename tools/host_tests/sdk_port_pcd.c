#include "sdk_port_fixture.h"
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
    assert(!reports);
    puts("SDK port PCD: partial bindings, validation failures, shared owners and same-port retry passed");
    return 0;
}
