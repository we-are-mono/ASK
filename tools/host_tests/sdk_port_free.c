/* Exercise actual init/free across the lifetime of initialization parameters. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define __CORE_EXT_H
#define __ERR_MODULE__ MODULE_FM_PORT
#include "fm_port.h"
#undef ASSERT_COND
#undef RETURN_ERROR
#undef SANITY_CHECK_RETURN_ERROR
#define ASSERT_COND assert
#define RETURN_ERROR(level, err, msg) return (err)
#define SANITY_CHECK_RETURN_ERROR(cond, err) do { if (!(cond)) return (err); } while (0)
#ifdef TEST_LEGACY_DEQ
#undef FM_DEQ_PIPELINE_PARAMS_FOR_OP
#endif

enum fault { NONE, BUFFER_LAYOUT, VALIDATION, POOLS, FIFO, FM_RESOURCES,
             LOW_LEVEL, DISABLE, VSP };
static enum fault failure;
static unsigned allocations, resource_gets, resource_frees, charged_depth, cases;
static unsigned muram_allocations, locks, disables;
static bool resources_owned;
static t_FmInterModulePortInitParams acquired;
static t_FmRevisionInfo revision;
static u_FmPortBmiRegs bmi;
static int fm_token;

void *XX_Malloc(uint32_t size)
{ void *p = calloc(1, size); assert(p); allocations++; return p; }
void XX_Free(void *p) { assert(p && allocations); allocations--; free(p); }
void XX_FreeSpinlock(t_Handle lock) { assert(lock == &fm_token && locks); locks--; }
t_Error FM_GetRevision(t_Handle fm, t_FmRevisionInfo *rev)
{ assert(fm == &fm_token); *rev = revision; return E_OK; }
t_Handle FmGetMuramHandle(t_Handle fm) { assert(fm == &fm_token); return fm; }
t_Error FmSpBuildBufferStructure(t_FmSpIntContextDataCopy *context,
    t_FmBufferPrefixContent *prefix, t_FmSpBufMargins *margins,
    t_FmSpBufferOffsets *offsets, uint8_t *internal)
{ return failure == BUFFER_LAYOUT ? E_INVALID_VALUE : E_OK; }
static t_Error CheckInitParameters(t_FmPort *port)
{ return failure == VALIDATION ? E_INVALID_VALUE : E_OK; }
static t_Error SetExtBufferPools(t_FmPort *port)
{ port->rxPoolsParams.largestBufSize = 2048; return failure == POOLS ? E_INVALID_VALUE : E_OK; }
static t_Error VerifySizeOfFifo(t_FmPort *port)
{ return failure == FIFO ? E_INVALID_VALUE : E_OK; }
t_Error FmGetSetPortParams(t_Handle fm, t_FmInterModulePortInitParams *params)
{
    assert(fm == &fm_token && !resources_owned);
    resource_gets++;
    /* This boundary models refusal before allocation. Partial failures inside
     * the FM resource allocator require their own transaction coverage. */
    if (failure == FM_RESOURCES) return E_NOT_AVAILABLE;
    acquired = *params; resources_owned = true;
    charged_depth += params->deqPipelineDepth;
    return E_OK;
}
void FmFreePortParams(t_Handle fm, t_FmInterModulePortFreeParams *params)
{
    assert(fm == &fm_token && resources_owned);
    assert(params->hardwarePortId == acquired.hardwarePortId);
    assert(params->portType == acquired.portType);
    assert(params->deqPipelineDepth == acquired.deqPipelineDepth);
    assert(charged_depth >= params->deqPipelineDepth);
    charged_depth -= params->deqPipelineDepth;
    resources_owned = false; resource_frees++;
}
static t_Error InitLowLevelDriver(t_FmPort *port)
{ assert(resources_owned); return failure == LOW_LEVEL ? E_NO_DEVICE : E_OK; }
t_Error FmPortSetGprFunc(t_Handle handle, e_FmPortGprFuncType type, void **out)
{
    t_FmPort *port = handle;
    assert(type == e_FM_PORT_GPR_MURAM_PAGE && !port->p_ParamsPage);
    port->p_ParamsPage = calloc(1, sizeof(*port->p_ParamsPage));
    assert(port->p_ParamsPage); muram_allocations++;
    *out = port->p_ParamsPage; return E_OK;
}
t_Error FM_MURAM_FreeMem(t_Handle muram, void *p)
{ assert(muram == &fm_token && p && muram_allocations); muram_allocations--; free(p); return E_OK; }
t_Error FmVSPFreeForPort(t_Handle fm, e_FmPortType type, uint8_t id)
{ assert(fm == &fm_token); return failure == VSP ? E_BUSY : E_OK; }
void FmPortImFree(t_FmPort *port) { assert(!"independent mode outside this fixture"); }
t_Error FM_PORT_Disable(t_Handle handle)
{
    t_FmPort *port = handle; disables++;
    if (failure == DISABLE) return E_BUSY;
    port->enabled = false; return E_OK;
}
#include "port_free_production.inc"

static t_FmPort *create(e_FmPortType type, uint8_t depth, uint8_t rev)
{
    assert(!allocations && !muram_allocations && !locks && !resources_owned && !charged_depth);
    failure = NONE; resource_gets = resource_frees = disables = 0;
    t_FmPort *port = XX_Malloc(sizeof(*port));
    port->p_FmPortDriverParam = XX_Malloc(sizeof(*port->p_FmPortDriverParam));
    port->h_Fm = &fm_token; port->portType = type; port->portId = 1;
    port->hardwarePortId = 0x29; port->fmRevInfo.majorRev = rev;
    memset(&bmi, 0, sizeof(bmi)); port->p_FmPortBmiRegs = &bmi;
    revision = port->fmRevInfo;
    port->fifoBufs.num = 2048; port->h_Spinlock = &fm_token; locks++;
    if (type == e_FM_PORT_TYPE_RX || type == e_FM_PORT_TYPE_RX_10G) {
        assert(FM_PORT_ConfigFifoDeqPipelineDepth(port, depth) != E_OK);
    } else {
        assert(FM_PORT_ConfigFifoDeqPipelineDepth(port, depth) == E_OK);
    }
    return port;
}
static void finish(t_FmPort *port, unsigned expected_frees)
{
    assert(FM_PORT_Free(port) == E_OK);
    assert(resource_frees == expected_frees);
    assert(!allocations && !muram_allocations && !locks && !resources_owned && !charged_depth);
    cases++;
}
int main(void)
{
    e_FmPortType types[] = {e_FM_PORT_TYPE_TX, e_FM_PORT_TYPE_TX_10G,
        e_FM_PORT_TYPE_RX, e_FM_PORT_TYPE_RX_10G,
        e_FM_PORT_TYPE_OH_OFFLINE_PARSING, e_FM_PORT_TYPE_OH_HOST_COMMAND};
    for (unsigned t = 0; t < sizeof(types) / sizeof(types[0]); t++) {
        for (uint8_t rev = 3; rev <= 6; rev++) {
            for (uint8_t depth = 1; depth <= 4; depth++) {
                t_FmPort *port = create(types[t], depth, rev);
                assert(FM_PORT_Init(port) == E_OK);
                assert(!port->p_FmPortDriverParam && allocations == 1);
                uint8_t expected = (types[t] == e_FM_PORT_TYPE_RX || types[t] == e_FM_PORT_TYPE_RX_10G) ? 0 : depth;
#ifdef TEST_LEGACY_DEQ
                if ((types[t] == e_FM_PORT_TYPE_OH_OFFLINE_PARSING || types[t] == e_FM_PORT_TYPE_OH_HOST_COMMAND)
                    && rev != 4 && rev < 6) expected = 2;
#endif
                assert(acquired.deqPipelineDepth == expected);
                port->enabled = true;
                finish(port, 1); assert(disables == 1);
            }
        }
        /* Never initialized, rejected before allocation, and failed after it. */
        finish(create(types[t], 3, 6), 0);
        for (enum fault fault = BUFFER_LAYOUT; fault <= LOW_LEVEL; fault++) {
            if (fault == POOLS && types[t] != e_FM_PORT_TYPE_RX && types[t] != e_FM_PORT_TYPE_RX_10G
                && types[t] != e_FM_PORT_TYPE_OH_OFFLINE_PARSING) continue;
            t_FmPort *port = create(types[t], 3, fault == POOLS ? 4 : 6);
            port->p_FmPortDriverParam->enBufPoolDepletion = true;
            failure = fault;
            t_Error err = FM_PORT_Init(port);
            if (!err) fprintf(stderr, "init accepted fault %u on port type %u\n", fault, types[t]);
            assert(err != E_OK && port->p_FmPortDriverParam);
            unsigned gets = resource_gets;
            if (fault == LOW_LEVEL) {
                /* A second init must not charge already acquired resources. */
                failure = NONE;
                assert(FM_PORT_Init(port) != E_OK && resource_gets == gets);
                /* Destruction uses the charged value, even if configuration
                 * was changed after the failed initialization. */
                port->p_FmPortDriverParam->dfltCfg.tx_fifo_deq_pipeline_depth = 4;
            }
            failure = NONE; finish(port, fault == LOW_LEVEL);
        }
    }
    /* Refused teardown retains the port; retry returns resources once. */
    for (enum fault fault = DISABLE; fault <= VSP; fault++) {
        t_FmPort *port = create(e_FM_PORT_TYPE_TX, 4, 6);
        assert(FM_PORT_Init(port) == E_OK); port->enabled = true; failure = fault;
        assert(FM_PORT_Free(port) != E_OK && allocations == 1 && locks == 1);
        failure = NONE; finish(port, 1);
    }
    printf("SDK port destruction: %u initialized, failed-init and retry cases passed\n", cases);
    return 0;
}
