/* Real FM resource transactions and flib bitfields over a checked MMIO model. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define __CORE_EXT_H
#define __ERR_MODULE__ MODULE_FM
#include "fm_common.h"
#include "fm.h"
#include "fm_port.h"
#undef ASSERT_COND
#undef RETURN_ERROR
#undef REPORT_ERROR
#undef DBG
#define ASSERT_COND assert
#define RETURN_ERROR(level, err, msg) return (err)
#define REPORT_ERROR(level, err, msg) ((void)0)
#define DBG(level, msg) ((void)0)
static bool locked, irq_disabled, seed_registers;
static unsigned locks, writes, cases;
uint32_t XX_LockIntrSpinlock(t_Handle handle)
{
    assert(handle && !locked);
    uint32_t flags = irq_disabled;
    locked = irq_disabled = true; locks++;
    return flags;
}
void XX_UnlockIntrSpinlock(t_Handle handle, uint32_t flags)
{
    assert(handle && locked && irq_disabled);
    locked = false; irq_disabled = flags;
}
static uint32_t ioread32be(const volatile uint32_t *reg)
{ assert(locked || seed_registers); return *reg; }
static void iowrite32be(uint32_t value, volatile uint32_t *reg)
{ assert(locked || seed_registers); *reg = value; writes++; }
#include "resources_flib.inc"
void FmGetPhysicalMuramBase(t_Handle fm, t_FmPhysAddr *address)
{ assert(fm && locked); address->high = 1; address->low = 0x12340000; }
static unsigned ipc_mode;
t_Error XX_IpcSendMessage(t_Handle session, uint8_t *msg, uint32_t length,
    uint8_t *reply, uint32_t *reply_length, t_IpcMsgCompletion *done, t_Handle arg)
{
    assert(!locked && session);
    if (!ipc_mode) return E_NOT_AVAILABLE;
    assert(reply && reply_length);
    t_FmIpcReply *response = (t_FmIpcReply *)reply;
    response->error = ipc_mode == 1 ? E_NOT_AVAILABLE : E_OK;
    memset(response->replyBody, 0xa5, *reply_length - sizeof(uint32_t));
    if (ipc_mode == 2) --*reply_length;
    return E_OK;
}
#include "resources_production.inc"

struct fixture {
    t_Fm fm;
    t_FmStateStruct state;
    struct fman_bmi_regs bmi;
    struct fman_qmi_regs qmi;
    struct fman_fpm_regs fpm;
    struct fman_dma_regs dma;
};
static struct fixture f, saved;
static void init(void)
{
    assert(!locked && !irq_disabled);
    memset(&f, 0, sizeof(f));
    f.fm.p_FmStateStruct = &f.state;
    f.fm.p_FmBmiRegs = &f.bmi; f.fm.p_FmQmiRegs = &f.qmi;
    f.fm.p_FmFpmRegs = &f.fpm; f.fm.p_FmDmaRegs = &f.dma;
    f.fm.h_Spinlock = &f;
    f.fm.guestId = NCSW_MASTER_ID;
    for (unsigned id = 0; id < FM_MAX_NUM_OF_HW_PORT_IDS; id++)
        f.state.portsTypes[id] = e_FM_PORT_TYPE_DUMMY;
    f.state.totalNumOfTasks = 128; f.state.totalFifoSize = 128 * 1024;
    f.state.maxNumOfOpenDmas = 32;
    f.state.revInfo.majorRev = 6; f.state.revInfo.minorRev = 1;
#ifdef TEST_LEGACY
    f.state.revInfo.majorRev = 3;
#endif
    f.qmi.fmqm_gc = (32 << 8) | 16;
    f.fpm.fmfp_mxd = 0x87654321;
    writes = locks = 0;
}
static t_FmInterModulePortInitParams request(e_FmPortType type, uint8_t id)
{
    return (t_FmInterModulePortInitParams){.hardwarePortId = id, .portType = type,
        .numOfTasks = 4, .numOfExtraTasks = 2, .numOfOpenDmas = 3,
        .numOfExtraOpenDmas = 1, .sizeOfFifo = 2048, .extraSizeOfFifo = 512,
        .deqPipelineDepth = 3, .maxFrameLength = 2048, .liodnBase = 3, .liodnOffset = 5};
}
static void refused(t_FmInterModulePortInitParams *params)
{
    t_FmInterModulePortInitParams before;
    memcpy(&before, params, sizeof(before));
    memcpy(&saved, &f, sizeof(f));
    unsigned calls = locks, count = writes;
    assert(FmGetSetPortParams(&f.fm, params) != E_OK);
    assert(!locked && !irq_disabled && locks == calls + 1);
    assert(writes == count && !memcmp(&f, &saved, sizeof(f)));
    assert(!memcmp(params, &before, sizeof(before))); cases++;
}
static void allocated(t_FmInterModulePortInitParams *params)
{
    assert(FmGetSetPortParams(&f.fm, params) == E_OK);
    assert(!locked && !irq_disabled);
    assert(f.state.portsTypes[params->hardwarePortId] == params->portType);
}
static void released(const t_FmInterModulePortInitParams *params)
{
    t_FmInterModulePortFreeParams free_params = {.hardwarePortId = params->hardwarePortId,
        .portType = params->portType, .deqPipelineDepth = params->deqPipelineDepth};
    FmFreePortParams(&f.fm, &free_params);
    assert(!locked && !irq_disabled);
    assert(f.state.portsTypes[params->hardwarePortId] == e_FM_PORT_TYPE_DUMMY);
}
int main(void)
{
    /* Reject at each allocation stage while another port owns resources. */
    for (unsigned fault = 0; fault < 6; fault++) {
        init();
        t_FmInterModulePortInitParams live = request(e_FM_PORT_TYPE_RX, BASE_1G_RX_PORTID);
        allocated(&live);
        t_FmInterModulePortInitParams params = request(e_FM_PORT_TYPE_OH_HOST_COMMAND, BASE_OH_PORTID);
        params.independentMode = true;
        uint8_t tasks = f.state.totalNumOfTasks, dmas = f.state.maxNumOfOpenDmas;
        uint32_t fifo = f.state.totalFifoSize;
        if (fault == 0) f.state.totalNumOfTasks = f.state.accumulatedNumOfTasks;
        if (fault == 1) f.state.totalFifoSize = f.state.accumulatedFifoSize;
        if (fault == 2) params.numOfOpenDmas = 255;
        if (fault == 3) params.deqPipelineDepth = 255;
        if (fault == 4) params.numOfExtraTasks = 255;
        if (fault == 5) params.extraSizeOfFifo = UINT32_MAX;
        refused(&params);
        f.state.totalNumOfTasks = tasks; f.state.totalFifoSize = fifo; f.state.maxNumOfOpenDmas = dmas;
        params = request(e_FM_PORT_TYPE_OH_HOST_COMMAND, BASE_OH_PORTID);
        allocated(&params);
        assert(f.fm.hcPortInitialized);
        refused(&params); /* A repeated allocation cannot charge it twice. */
        released(&params); assert(!f.fm.hcPortInitialized);
        assert(f.state.accumulatedNumOfTasks == live.numOfTasks);
        assert(f.state.accumulatedFifoSize == live.sizeOfFifo);
        assert(f.state.accumulatedNumOfOpenDmas == live.numOfOpenDmas);
        released(&live);
        assert(!f.state.accumulatedNumOfTasks && !f.state.accumulatedFifoSize &&
               !f.state.accumulatedNumOfOpenDmas && !f.state.accumulatedNumOfDeqTnums);
    }
    /* Both MAC classes used to return from MTU rejection with IRQs disabled. */
    e_FmPortType types[] = {e_FM_PORT_TYPE_RX, e_FM_PORT_TYPE_TX,
                           e_FM_PORT_TYPE_RX_10G, e_FM_PORT_TYPE_TX_10G};
    uint8_t ids[] = {BASE_1G_RX_PORTID, BASE_1G_TX_PORTID,
                     BASE_10G_RX_PORTID, BASE_10G_TX_PORTID};
    for (unsigned type = 0; type < 4; type++) {
        init();
        t_FmInterModulePortInitParams params = request(types[type], ids[type]);
        params.independentMode = true;
        if (type < 2) f.state.macMaxFrameLengths1G[0] = 4096;
        else f.state.macMaxFrameLengths10G[0] = 4096;
        refused(&params);
        params.maxFrameLength = 4096;
        allocated(&params);
        assert(f.fm.independentMode && !f.fpm.fmfp_mxd);
        released(&params);
    }

    /* Preserve the caller's interrupt state on success and on refusal. */
    init();
    t_FmInterModulePortInitParams params = request(e_FM_PORT_TYPE_RX, BASE_1G_RX_PORTID);
    irq_disabled = true;
    assert(FmGetSetPortParams(&f.fm, &params) == E_OK && irq_disabled && !locked);
    assert(FmGetSetPortParams(&f.fm, &params) != E_OK && irq_disabled && !locked);
    irq_disabled = false; released(&params);

    /* Reset-derived DMA reservations must obey the same capacity checks. */
    for (unsigned reject = 0; reject < 2; reject++) {
        init();
        params = request(e_FM_PORT_TYPE_RX, BASE_1G_RX_PORTID);
        params.numOfOpenDmas = params.numOfExtraOpenDmas = 0;
        seed_registers = true;
        fman_set_num_of_open_dmas(&f.bmi, params.hardwarePortId, 8, 2, 0);
        seed_registers = false;
        unsigned dma_baseline = reject ? 250 : 5;
        f.state.accumulatedNumOfOpenDmas = dma_baseline;
        f.state.extraOpenDmasPoolSize = 1;
        if (reject) {
            refused(&params);
            assert(!params.numOfOpenDmas && !params.numOfExtraOpenDmas);
            f.state.accumulatedNumOfOpenDmas = dma_baseline = 5;
        }
        allocated(&params);
        assert(params.numOfOpenDmas == 8 && params.numOfExtraOpenDmas == 2);
        assert(f.state.accumulatedNumOfOpenDmas == dma_baseline + 8);
        released(&params);
        assert(f.state.accumulatedNumOfOpenDmas == dma_baseline);
    }

    /* A representable DMA request can still exhaust the hardware budget. */
    init();
    params = request(e_FM_PORT_TYPE_RX, BASE_1G_RX_PORTID);
#ifdef TEST_LEGACY
    f.state.accumulatedNumOfOpenDmas = f.state.maxNumOfOpenDmas;
#else
    f.state.accumulatedNumOfOpenDmas = DMA_THRESH_MAX_COMMQ + 1;
#endif
    refused(&params);
    f.state.accumulatedNumOfOpenDmas = 0;
    allocated(&params); released(&params);

    /* Runtime updates share the FM lock and leave all state untouched on
     * refusal; FIFO replacement subtracts bytes, not the raw register units. */
    init();
    t_FmInterModulePortInitParams live = request(e_FM_PORT_TYPE_RX, BASE_1G_RX_PORTID);
    params = request(e_FM_PORT_TYPE_RX, BASE_1G_RX_PORTID + 1);
    allocated(&live); allocated(&params);
    uint8_t tasks = 6, extra_tasks = 3, dmas = 5, extra_dmas = 2;
    uint32_t fifo = 4096, extra_fifo = 1024;
    assert(FmSetNumOfTasks(&f.fm, params.hardwarePortId, &tasks, &extra_tasks, false) == E_OK);
    assert(f.state.accumulatedNumOfTasks == live.numOfTasks + tasks);
    assert(FmSetNumOfOpenDmas(&f.fm, params.hardwarePortId, &dmas, &extra_dmas, false) == E_OK);
    assert(f.state.accumulatedNumOfOpenDmas == live.numOfOpenDmas + dmas);
    assert(FmSetSizeOfFifo(&f.fm, params.hardwarePortId, &fifo, &extra_fifo, false) == E_OK);
    assert(f.state.accumulatedFifoSize == live.sizeOfFifo + fifo);
    assert(!locked && !irq_disabled);
    for (unsigned resource = 0; resource < 3; resource++) {
        memcpy(&saved, &f, sizeof(f));
        unsigned count = writes, calls = locks;
        uint8_t num = 255, extra = 255;
        uint32_t size = UINT32_MAX, reserve = UINT32_MAX;
        t_Error err;
        if (resource == 0) err = FmSetNumOfTasks(&f.fm, params.hardwarePortId, &num, &extra, false);
        else if (resource == 1) err = FmSetNumOfOpenDmas(&f.fm, params.hardwarePortId, &num, &extra, false);
        else err = FmSetSizeOfFifo(&f.fm, params.hardwarePortId, &size, &reserve, false);
        assert(err != E_OK && !locked && !irq_disabled && locks == calls + 1);
        assert(writes == count && !memcmp(&saved, &f, sizeof(f)));
        assert(num == 255 && extra == 255 && size == UINT32_MAX && reserve == UINT32_MAX);
    }
    /* Retry a smaller FIFO allocation and then free both ports. */
    fifo = 1024; extra_fifo = 256;
    assert(FmSetSizeOfFifo(&f.fm, params.hardwarePortId, &fifo, &extra_fifo, false) == E_OK);
    assert(f.state.accumulatedFifoSize == live.sizeOfFifo + fifo);
    released(&params);
    assert(f.state.accumulatedFifoSize == live.sizeOfFifo);
    released(&live);
    assert(!f.state.accumulatedFifoSize && !f.state.accumulatedNumOfTasks && !f.state.accumulatedNumOfOpenDmas);

    /* The QMI budget must leave both thresholds representable. */
    init();
    params = request(e_FM_PORT_TYPE_TX, BASE_1G_TX_PORTID);
    f.state.accumulatedNumOfDeqTnums = QMI_MAX_NUM_OF_TNUMS - 4;
    refused(&params);
    params.deqPipelineDepth = 2;
    allocated(&params);
    assert(f.state.accumulatedNumOfDeqTnums == QMI_MAX_NUM_OF_TNUMS - 2);
    assert((f.qmi.fmqm_gc & 0xff) == QMI_MAX_NUM_OF_TNUMS - 1);
    released(&params);

#ifdef FM_LOW_END_RESTRICTION
    init();
    params = request(e_FM_PORT_TYPE_OH_HOST_COMMAND, 0x1);
    f.state.lowEndRestriction = true;
    refused(&params);
    f.state.lowEndRestriction = false;
    allocated(&params); assert(f.state.lowEndRestriction);
    released(&params); assert(!f.state.lowEndRestriction);
#endif

    /* Exercise the public FIFO API after its initialization parameters are
     * gone, including TX/OH validation and cached values after refusal. */
    e_FmPortType resize_types[] = {e_FM_PORT_TYPE_TX, e_FM_PORT_TYPE_TX_10G,
                                   e_FM_PORT_TYPE_RX, e_FM_PORT_TYPE_OH_OFFLINE_PARSING};
    uint8_t resize_ids[] = {BASE_1G_TX_PORTID, BASE_10G_TX_PORTID,
                            BASE_1G_RX_PORTID, BASE_OH_PORTID};
    for (unsigned i = 0; i < 4; i++) {
        init();
        params = request(resize_types[i], resize_ids[i]);
        allocated(&params);
        t_FmPort port = {.h_Fm = &f.fm, .hardwarePortId = params.hardwarePortId,
            .portType = params.portType, .maxFrameLength = params.maxFrameLength,
            .deqPipelineDepth = params.deqPipelineDepth, .fmRevInfo = f.state.revInfo,
            .fifoBufs = {.num = params.sizeOfFifo, .extra = params.extraSizeOfFifo}};
        t_FmPort before_port;
        memcpy(&before_port, &port, sizeof(port));
        memcpy(&saved, &f, sizeof(f));
        unsigned count = writes;
        t_FmPortRsrc resize = {.num = 4096};
        f.state.totalFifoSize = 2048;
        assert(FM_PORT_SetSizeOfFifo(&port, &resize) != E_OK);
        assert(!memcmp(&port, &before_port, sizeof(port)) && writes == count);
        f.state.totalFifoSize = saved.state.totalFifoSize;
        assert(!memcmp(&saved, &f, sizeof(f)));
        assert(FM_PORT_SetSizeOfFifo(&port, &resize) == E_OK);
        assert(port.fifoBufs.num == resize.num && f.state.accumulatedFifoSize == resize.num);
        released(&params); assert(!f.state.accumulatedFifoSize);
    }

    /* A remote failure must not publish an uncommitted reply into input. */
    init();
    f.fm.guestId = 1; f.fm.h_IpcSessions[0] = &f;
    params = request(e_FM_PORT_TYPE_RX, BASE_1G_RX_PORTID);
    t_FmInterModulePortInitParams before;
    memcpy(&before, &params, sizeof(before));
    memcpy(&saved, &f, sizeof(saved));
    for (ipc_mode = 0; ipc_mode < 3; ipc_mode++) {
        assert(FmGetSetPortParams(&f.fm, &params) != E_OK);
        assert(!locks && !writes && !memcmp(&saved, &f, sizeof(f)));
        assert(!memcmp(&before, &params, sizeof(params)));
    }
    assert(FmGetSetPortParams(&f.fm, &params) == E_OK);
    assert(params.numOfOpenDmas == 0xa5 && params.fmMuramPhysBaseAddr.low == 0xa5a5a5a5);
    assert(!locks && !writes && !memcmp(&saved, &f, sizeof(f)));
    ipc_mode = 0;

    /* A mapped guest can program its own registers without inventing master
     * resource charges from its unpopulated accounting copy. */
    init(); f.fm.guestId = 1; f.fm.baseAddr = 1;
    memcpy(&saved, &f, sizeof(f));
    tasks = 4; extra_tasks = 1; fifo = 2048; extra_fifo = 256;
    dmas = 3; extra_dmas = 1;
    seed_registers = true;
    assert(FmSetNumOfTasks(&f.fm, BASE_1G_RX_PORTID, &tasks, &extra_tasks, true) == E_OK);
    assert(FmSetSizeOfFifo(&f.fm, BASE_1G_RX_PORTID, &fifo, &extra_fifo, true) == E_OK);
#ifdef FM_HAS_TOTAL_DMAS
    assert(FmSetNumOfOpenDmas(&f.fm, BASE_1G_RX_PORTID, &dmas, &extra_dmas, true) == E_NOT_SUPPORTED);
#else
    assert(FmSetNumOfOpenDmas(&f.fm, BASE_1G_RX_PORTID, &dmas, &extra_dmas, true) == E_OK);
    dmas = extra_dmas = 0;
    assert(FmSetNumOfOpenDmas(&f.fm, BASE_1G_RX_PORTID, &dmas, &extra_dmas, true) == E_OK);
    assert(dmas == 3 && extra_dmas == 1);
#endif
    seed_registers = false;
    assert(!locks && !locked && !irq_disabled && writes);
    assert(!memcmp(&saved.state, &f.state, sizeof(f.state)));
    assert(!memcmp(&saved.fm, &f.fm, sizeof(f.fm)));

    puts("FM resource allocation: failure leaves state/registers unchanged, retry and release succeed");
}
