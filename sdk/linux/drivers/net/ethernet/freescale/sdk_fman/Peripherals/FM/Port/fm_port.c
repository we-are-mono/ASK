/*
 * Copyright 2008-2012 Freescale Semiconductor Inc.
 * Copyright 2021 NXP
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


/******************************************************************************
 @File          fm_port.c

 @Description   FM driver routines implementation.
 *//***************************************************************************/
#define __ERR_MODULE__  MODULE_FM_PORT

#include "error_ext.h"
#include "std_ext.h"
#include "string_ext.h"
#include "sprint_ext.h"
#include "debug_ext.h"
#include "fm_muram_ext.h"

#include "../Pcd/fm_prs.h"
#include "fman_common.h"
#include "fm_port.h"

/****************************************/
/*       static functions               */
/****************************************/
static t_Error CheckInitParameters(t_FmPort *p_FmPort)
{
    t_FmPortDriverParam *p_Params = p_FmPort->p_FmPortDriverParam;
    struct fman_port_cfg *p_DfltConfig = &p_Params->dfltCfg;
    t_Error ans = E_OK;
    uint32_t unusedMask;

    if (p_FmPort->imEn)
    {
        if (p_FmPort->portType == e_FM_PORT_TYPE_RX_10G)
            if (p_FmPort->p_FmPortDriverParam->dfltCfg.tx_fifo_deq_pipeline_depth
                    > 2)
                RETURN_ERROR(
                        MAJOR,
                        E_INVALID_VALUE,
                        ("fifoDeqPipelineDepth for IM 10G can't be larger than 2"));

        if ((ans = FmPortImCheckInitParameters(p_FmPort)) != E_OK)
            return ERROR_CODE(ans);
    }
    else
    {
        /****************************************/
        /*   Rx only                            */
        /****************************************/
        if ((p_FmPort->portType == e_FM_PORT_TYPE_RX)
                || (p_FmPort->portType == e_FM_PORT_TYPE_RX_10G))
        {
            /* external buffer pools */
            if (!p_Params->extBufPools.numOfPoolsUsed)
                RETURN_ERROR(
                        MAJOR,
                        E_INVALID_VALUE,
                        ("extBufPools.numOfPoolsUsed=0. At least one buffer pool must be defined"));

            if (FmSpCheckBufPoolsParams(&p_Params->extBufPools,
                                        p_Params->p_BackupBmPools,
                                        &p_Params->bufPoolDepletion) != E_OK)
                RETURN_ERROR(MAJOR, E_INVALID_VALUE, NO_MSG);

            /* Check that part of IC that needs copying is small enough to enter start margin */
            if (p_Params->intContext.size
                    && (p_Params->intContext.size
                            + p_Params->intContext.extBufOffset
                            > p_Params->bufMargins.startMargins))
                RETURN_ERROR(MAJOR, E_INVALID_VALUE,
                             ("intContext.size is larger than start margins"));

            if ((p_Params->liodnOffset != (uint16_t)DPAA_LIODN_DONT_OVERRIDE)
                    && (p_Params->liodnOffset & ~FM_LIODN_OFFSET_MASK))
                RETURN_ERROR(
                        MAJOR,
                        E_INVALID_VALUE,
                        ("liodnOffset is larger than %d", FM_LIODN_OFFSET_MASK+1));

        }

        /****************************************/
        /*   Non Rx ports                       */
        /****************************************/
        else
        {
            if (p_Params->deqSubPortal >= FM_MAX_NUM_OF_SUB_PORTALS)
                RETURN_ERROR(
                        MAJOR,
                        E_INVALID_VALUE,
                        (" deqSubPortal has to be in the range of 0 - %d", FM_MAX_NUM_OF_SUB_PORTALS));

            /* to protect HW internal-context from overwrite */
            if ((p_Params->intContext.size)
                    && (p_Params->intContext.intContextOffset
                            < MIN_TX_INT_OFFSET))
                RETURN_ERROR(
                        MAJOR,
                        E_INVALID_VALUE,
                        ("non-Rx intContext.intContextOffset can't be smaller than %d", MIN_TX_INT_OFFSET));

            if ((p_FmPort->portType == e_FM_PORT_TYPE_TX)
                    || (p_FmPort->portType == e_FM_PORT_TYPE_TX_10G)
                    /* in O/H DEFAULT_notSupported indicates that it is not supported and should not be checked */
                    || (p_FmPort->p_FmPortDriverParam->dfltCfg.tx_fifo_deq_pipeline_depth
                            != DEFAULT_notSupported))
            {
                /* Check that not larger than 8 */
                if ((!p_FmPort->p_FmPortDriverParam->dfltCfg.tx_fifo_deq_pipeline_depth)
                        || (p_FmPort->p_FmPortDriverParam->dfltCfg.tx_fifo_deq_pipeline_depth
                                > MAX_FIFO_PIPELINE_DEPTH))
                    RETURN_ERROR(
                            MAJOR,
                            E_INVALID_VALUE,
                            ("fifoDeqPipelineDepth can't be larger than %d", MAX_FIFO_PIPELINE_DEPTH));
            }
        }

        /****************************************/
        /*   Rx Or Offline Parsing              */
        /****************************************/
        if ((p_FmPort->portType == e_FM_PORT_TYPE_RX)
                || (p_FmPort->portType == e_FM_PORT_TYPE_RX_10G)
                || (p_FmPort->portType == e_FM_PORT_TYPE_OH_OFFLINE_PARSING))
        {
            if (!p_Params->dfltFqid)
                RETURN_ERROR(MAJOR, E_INVALID_VALUE,
                             ("dfltFqid must be between 1 and 2^24-1"));
        }

        /****************************************/
        /*   All ports                          */
        /****************************************/
        /* common BMI registers values */
        /* Check that Queue Id is not larger than 2^24, and is not 0 */
        if ((p_Params->errFqid & ~0x00FFFFFF) || !p_Params->errFqid)
            RETURN_ERROR(MAJOR, E_INVALID_VALUE,
                         ("errFqid must be between 1 and 2^24-1"));
        if (p_Params->dfltFqid & ~0x00FFFFFF)
            RETURN_ERROR(MAJOR, E_INVALID_VALUE,
                         ("dfltFqid must be between 1 and 2^24-1"));
    }

    /****************************************/
    /*   Rx only                            */
    /****************************************/
    if ((p_FmPort->portType == e_FM_PORT_TYPE_RX)
            || (p_FmPort->portType == e_FM_PORT_TYPE_RX_10G))
    {
        if (p_DfltConfig->rx_pri_elevation % BMI_FIFO_UNITS)
            RETURN_ERROR(
                    MAJOR,
                    E_INVALID_VALUE,
                    ("rxFifoPriElevationLevel has to be divisible by %d", BMI_FIFO_UNITS));
        if ((p_DfltConfig->rx_pri_elevation < BMI_FIFO_UNITS)
                || (p_DfltConfig->rx_pri_elevation > MAX_PORT_FIFO_SIZE))
            RETURN_ERROR(
                    MAJOR,
                    E_INVALID_VALUE,
                    ("rxFifoPriElevationLevel has to be in the range of 256 - %lu", MAX_PORT_FIFO_SIZE));
        if (p_DfltConfig->rx_fifo_thr % BMI_FIFO_UNITS)
            RETURN_ERROR(
                    MAJOR,
                    E_INVALID_VALUE,
                    ("rxFifoThreshold has to be divisible by %d", BMI_FIFO_UNITS));
        if ((p_DfltConfig->rx_fifo_thr < BMI_FIFO_UNITS)
                || (p_DfltConfig->rx_fifo_thr > MAX_PORT_FIFO_SIZE))
            RETURN_ERROR(
                    MAJOR,
                    E_INVALID_VALUE,
                    ("rxFifoThreshold has to be in the range of 256 - %lu", MAX_PORT_FIFO_SIZE));

        /* Check that not larger than 16 */
        if (p_DfltConfig->rx_cut_end_bytes > FRAME_END_DATA_SIZE)
            RETURN_ERROR(
                    MAJOR,
                    E_INVALID_VALUE,
                    ("cutBytesFromEnd can't be larger than %d", FRAME_END_DATA_SIZE));

        if (FmSpCheckBufMargins(&p_Params->bufMargins) != E_OK)
            RETURN_ERROR(MAJOR, E_INVALID_VALUE, NO_MSG);

        /* extra FIFO size (allowed only to Rx ports) */
        if (p_Params->setSizeOfFifo
                && (p_FmPort->fifoBufs.extra % BMI_FIFO_UNITS))
            RETURN_ERROR(
                    MAJOR,
                    E_INVALID_VALUE,
                    ("fifoBufs.extra has to be divisible by %d", BMI_FIFO_UNITS));

        if (p_Params->bufPoolDepletion.poolsGrpModeEnable
                && !p_Params->bufPoolDepletion.numOfPools)
            RETURN_ERROR(
                    MAJOR,
                    E_INVALID_VALUE,
                    ("bufPoolDepletion.numOfPools can not be 0 when poolsGrpModeEnable=TRUE"));
    }

    /****************************************/
    /*   Non Rx ports                       */
    /****************************************/
    /* extra FIFO size (allowed only to Rx ports) */
    else
        if (p_FmPort->fifoBufs.extra)
            RETURN_ERROR(MAJOR, E_INVALID_VALUE,
                         (" No fifoBufs.extra for non Rx ports"));

    /****************************************/
    /*   Tx only                            */
    /****************************************/
    if ((p_FmPort->portType == e_FM_PORT_TYPE_TX)
            || (p_FmPort->portType == e_FM_PORT_TYPE_TX_10G))
    {
        if (p_DfltConfig->tx_fifo_min_level % BMI_FIFO_UNITS)
            RETURN_ERROR(
                    MAJOR,
                    E_INVALID_VALUE,
                    ("txFifoMinFillLevel has to be divisible by %d", BMI_FIFO_UNITS));
        if (p_DfltConfig->tx_fifo_min_level > (MAX_PORT_FIFO_SIZE - 256))
            RETURN_ERROR(
                    MAJOR,
                    E_INVALID_VALUE,
                    ("txFifoMinFillLevel has to be in the range of 0 - %lu", (MAX_PORT_FIFO_SIZE - 256)));
        if (p_DfltConfig->tx_fifo_low_comf_level % BMI_FIFO_UNITS)
            RETURN_ERROR(
                    MAJOR,
                    E_INVALID_VALUE,
                    ("txFifoLowComfLevel has to be divisible by %d", BMI_FIFO_UNITS));
        if ((p_DfltConfig->tx_fifo_low_comf_level < BMI_FIFO_UNITS)
                || (p_DfltConfig->tx_fifo_low_comf_level > MAX_PORT_FIFO_SIZE))
            RETURN_ERROR(
                    MAJOR,
                    E_INVALID_VALUE,
                    ("txFifoLowComfLevel has to be in the range of 256 - %lu", MAX_PORT_FIFO_SIZE));

        if (p_FmPort->portType == e_FM_PORT_TYPE_TX)
            if (p_FmPort->p_FmPortDriverParam->dfltCfg.tx_fifo_deq_pipeline_depth
                    > 2)
                RETURN_ERROR(
                        MAJOR, E_INVALID_VALUE,
                        ("fifoDeqPipelineDepth for 1G can't be larger than 2"));
    }

    /****************************************/
    /*   Non Tx Ports                       */
    /****************************************/
    /* If discard override was selected , no frames may be discarded. */
    else
        if (p_DfltConfig->discard_override && p_Params->errorsToDiscard)
            RETURN_ERROR(
                    MAJOR,
                    E_CONFLICT,
                    ("errorsToDiscard is not empty, but frmDiscardOverride selected (all discarded frames to be enqueued to error queue)."));

    /****************************************/
    /*   Rx and Offline parsing             */
    /****************************************/
    if ((p_FmPort->portType == e_FM_PORT_TYPE_RX)
            || (p_FmPort->portType == e_FM_PORT_TYPE_RX_10G)
            || (p_FmPort->portType == e_FM_PORT_TYPE_OH_OFFLINE_PARSING))
    {
        if (p_FmPort->portType == e_FM_PORT_TYPE_OH_OFFLINE_PARSING)
            unusedMask = BMI_STATUS_OP_MASK_UNUSED;
        else
            unusedMask = BMI_STATUS_RX_MASK_UNUSED;

        /* Check that no common bits with BMI_STATUS_MASK_UNUSED */
        if (p_Params->errorsToDiscard & unusedMask)
            RETURN_ERROR(MAJOR, E_INVALID_SELECTION,
                         ("errorsToDiscard contains undefined bits"));
    }

    /****************************************/
    /*   Offline Ports                      */
    /****************************************/
    if ((p_FmPort->fmRevInfo.majorRev >= 6)
            && (p_FmPort->portType == e_FM_PORT_TYPE_OH_OFFLINE_PARSING)
            && p_Params->setNumOfOpenDmas
            && (p_FmPort->openDmas.num < MIN_NUM_OF_OP_DMAS))
        RETURN_ERROR(
                MAJOR,
                E_INVALID_VALUE,
                ("For Offline port, openDmas.num can't be smaller than %d", MIN_NUM_OF_OP_DMAS));

    /****************************************/
    /*   Offline & HC Ports                 */
    /****************************************/
    if ((p_FmPort->portType == e_FM_PORT_TYPE_OH_OFFLINE_PARSING)
            || (p_FmPort->portType == e_FM_PORT_TYPE_OH_HOST_COMMAND))
    {

    }

    /****************************************/
    /*   All ports                          */
    /****************************************/
    /* Check that not larger than 16 */
    if ((p_Params->cheksumLastBytesIgnore > FRAME_END_DATA_SIZE)
            && ((p_Params->cheksumLastBytesIgnore != DEFAULT_notSupported)))
        RETURN_ERROR(
                MAJOR,
                E_INVALID_VALUE,
                ("cheksumLastBytesIgnore can't be larger than %d", FRAME_END_DATA_SIZE));

    if (FmSpCheckIntContextParams(&p_Params->intContext) != E_OK)
        RETURN_ERROR(MAJOR, E_INVALID_VALUE, NO_MSG);

    /* common BMI registers values */
    if (p_Params->setNumOfTasks
            && ((!p_FmPort->tasks.num)
                    || (p_FmPort->tasks.num > MAX_NUM_OF_TASKS)))
        RETURN_ERROR(MAJOR, E_INVALID_VALUE,
                     ("tasks.num can't be larger than %d", MAX_NUM_OF_TASKS));
    if (p_Params->setNumOfTasks
            && (p_FmPort->tasks.extra > MAX_NUM_OF_EXTRA_TASKS))
        RETURN_ERROR(
                MAJOR,
                E_INVALID_VALUE,
                ("tasks.extra can't be larger than %d", MAX_NUM_OF_EXTRA_TASKS));
    if (p_Params->setNumOfOpenDmas
            && ((!p_FmPort->openDmas.num)
                    || (p_FmPort->openDmas.num > MAX_NUM_OF_DMAS)))
        RETURN_ERROR(MAJOR, E_INVALID_VALUE,
                     ("openDmas.num can't be larger than %d", MAX_NUM_OF_DMAS));
    if (p_Params->setNumOfOpenDmas
            && (p_FmPort->openDmas.extra > MAX_NUM_OF_EXTRA_DMAS))
        RETURN_ERROR(
                MAJOR,
                E_INVALID_VALUE,
                ("openDmas.extra can't be larger than %d", MAX_NUM_OF_EXTRA_DMAS));
    if (p_Params->setSizeOfFifo
            && (!p_FmPort->fifoBufs.num
                    || (p_FmPort->fifoBufs.num > MAX_PORT_FIFO_SIZE)))
        RETURN_ERROR(
                MAJOR,
                E_INVALID_VALUE,
                ("fifoBufs.num has to be in the range of 256 - %lu", MAX_PORT_FIFO_SIZE));
    if (p_Params->setSizeOfFifo && (p_FmPort->fifoBufs.num % BMI_FIFO_UNITS))
        RETURN_ERROR(
                MAJOR, E_INVALID_VALUE,
                ("fifoBufs.num has to be divisible by %d", BMI_FIFO_UNITS));


    return E_OK;
}

static t_Error VerifySizeOfFifo(t_FmPort *p_FmPort)
{
    uint32_t minFifoSizeRequired = 0, optFifoSizeForB2B = 0;
    /* Called only from FM_PORT_Init(), which the port's initialization
     * parameters outlive. */
    uint8_t deqDepth = p_FmPort->p_FmPortDriverParam->dfltCfg.tx_fifo_deq_pipeline_depth;

    /*************************/
    /*    TX PORTS           */
    /*************************/
    if ((p_FmPort->portType == e_FM_PORT_TYPE_TX)
            || (p_FmPort->portType == e_FM_PORT_TYPE_TX_10G))
    {
        minFifoSizeRequired =
                (uint32_t)(ROUND_UP(p_FmPort->maxFrameLength, BMI_FIFO_UNITS)
                        + (3 * BMI_FIFO_UNITS));
        if (!p_FmPort->imEn)
            minFifoSizeRequired +=
                    deqDepth * BMI_FIFO_UNITS;

        optFifoSizeForB2B = minFifoSizeRequired;

        /* Add some margin for back-to-back capability to improve performance,
         allows the hardware to pipeline new frame dma while the previous
         frame not yet transmitted. */
        if (p_FmPort->portType == e_FM_PORT_TYPE_TX_10G)
            optFifoSizeForB2B += 3 * BMI_FIFO_UNITS;
        else
            optFifoSizeForB2B += 2 * BMI_FIFO_UNITS;
    }

    /*************************/
    /*    RX IM PORTS        */
    /*************************/
    else
        if (((p_FmPort->portType == e_FM_PORT_TYPE_RX)
                || (p_FmPort->portType == e_FM_PORT_TYPE_RX_10G))
                && p_FmPort->imEn)
        {
            optFifoSizeForB2B =
                    minFifoSizeRequired =
                            (uint32_t)(ROUND_UP(p_FmPort->maxFrameLength, BMI_FIFO_UNITS)
                                    + (4 * BMI_FIFO_UNITS));
        }

        /*************************/
        /*    RX non-IM PORTS    */
        /*************************/
        else
            if (((p_FmPort->portType == e_FM_PORT_TYPE_RX)
                    || (p_FmPort->portType == e_FM_PORT_TYPE_RX_10G))
                    && !p_FmPort->imEn)
            {
                if (p_FmPort->fmRevInfo.majorRev == 4)
                {
                    if (p_FmPort->rxPoolsParams.numOfPools == 1)
                        minFifoSizeRequired = 8 * BMI_FIFO_UNITS;
                    else
                        minFifoSizeRequired =
                                (uint32_t)(ROUND_UP(p_FmPort->rxPoolsParams.secondLargestBufSize, BMI_FIFO_UNITS)
                                        + (7 * BMI_FIFO_UNITS));
                }
                else
                {
                    minFifoSizeRequired =
                            (uint32_t)(ROUND_UP(p_FmPort->maxFrameLength, BMI_FIFO_UNITS)
                                    + (5 * BMI_FIFO_UNITS));
                    /* 4 according to spec + 1 for FOF>0 */
                }

                optFifoSizeForB2B = minFifoSizeRequired;

                /* Add some margin for back-to-back capability to improve performance,
                 allows the hardware to pipeline new frame dma while the previous
                 frame not yet transmitted. */
                if (p_FmPort->portType == e_FM_PORT_TYPE_RX_10G)
                    optFifoSizeForB2B += 8 * BMI_FIFO_UNITS;
                else
                    optFifoSizeForB2B += 3 * BMI_FIFO_UNITS;
            }

            /* For O/H ports, check fifo size and update if necessary */
            else
                if ((p_FmPort->portType == e_FM_PORT_TYPE_OH_OFFLINE_PARSING)
                        || (p_FmPort->portType == e_FM_PORT_TYPE_OH_HOST_COMMAND))
                {
                    optFifoSizeForB2B =
                            minFifoSizeRequired =
                                    (uint32_t)(ROUND_UP(p_FmPort->maxFrameLength, BMI_FIFO_UNITS)
                                            + ((deqDepth + 5) * BMI_FIFO_UNITS));
                    /* 4 according to spec + 1 for FOF>0 */
                }

    ASSERT_COND(minFifoSizeRequired > 0);
    ASSERT_COND(optFifoSizeForB2B >= minFifoSizeRequired);

    /* Verify the size  */
    if (p_FmPort->fifoBufs.num < minFifoSizeRequired)
        DBG(INFO,
           ("FIFO size is %d and should be enlarged to %d bytes",p_FmPort->fifoBufs.num, minFifoSizeRequired));
    else if (p_FmPort->fifoBufs.num < optFifoSizeForB2B)
        DBG(INFO,
	    ("For back-to-back frames processing, FIFO size is %d and needs to enlarge to %d bytes", p_FmPort->fifoBufs.num, optFifoSizeForB2B));

    return E_OK;
}

static void FmPortDriverParamFree(t_FmPort *p_FmPort)
{
    if (p_FmPort->p_FmPortDriverParam)
    {
        XX_Free(p_FmPort->p_FmPortDriverParam);
        p_FmPort->p_FmPortDriverParam = NULL;
    }
}

static t_Error SetExtBufferPools(t_FmPort *p_FmPort)
{
    t_FmExtPools *p_ExtBufPools = &p_FmPort->p_FmPortDriverParam->extBufPools;
    t_FmBufPoolDepletion *p_BufPoolDepletion =
            &p_FmPort->p_FmPortDriverParam->bufPoolDepletion;
    uint8_t orderedArray[FM_PORT_MAX_NUM_OF_EXT_POOLS];
    uint16_t sizesArray[BM_MAX_NUM_OF_POOLS];
    int i = 0, j = 0, err;
    struct fman_port_bpools bpools;

    memset(&orderedArray, 0, sizeof(uint8_t) * FM_PORT_MAX_NUM_OF_EXT_POOLS);
    memset(&sizesArray, 0, sizeof(uint16_t) * BM_MAX_NUM_OF_POOLS);
    memcpy(&p_FmPort->extBufPools, p_ExtBufPools, sizeof(t_FmExtPools));

    FmSpSetBufPoolsInAscOrderOfBufSizes(p_ExtBufPools, orderedArray,
                                        sizesArray);

    /* Prepare flibs bpools structure */
    memset(&bpools, 0, sizeof(struct fman_port_bpools));
    bpools.count = p_ExtBufPools->numOfPoolsUsed;
    bpools.counters_enable = TRUE;
    for (i = 0; i < p_ExtBufPools->numOfPoolsUsed; i++)
    {
        bpools.bpool[i].bpid = orderedArray[i];
        bpools.bpool[i].size = sizesArray[orderedArray[i]];
        /* functionality available only for some derivatives (limited by config) */
        if (p_FmPort->p_FmPortDriverParam->p_BackupBmPools)
            for (j = 0;
                    j
                            < p_FmPort->p_FmPortDriverParam->p_BackupBmPools->numOfBackupPools;
                    j++)
                if (orderedArray[i]
                        == p_FmPort->p_FmPortDriverParam->p_BackupBmPools->poolIds[j])
                {
                    bpools.bpool[i].is_backup = TRUE;
                    break;
                }
    }

    /* save pools parameters for later use */
    p_FmPort->rxPoolsParams.numOfPools = p_ExtBufPools->numOfPoolsUsed;
    p_FmPort->rxPoolsParams.largestBufSize =
            sizesArray[orderedArray[p_ExtBufPools->numOfPoolsUsed - 1]];
    if (p_ExtBufPools->numOfPoolsUsed > 1)
        p_FmPort->rxPoolsParams.secondLargestBufSize =
            sizesArray[orderedArray[p_ExtBufPools->numOfPoolsUsed - 2]];

    /* FMBM_RMPD reg. - pool depletion */
    if (p_BufPoolDepletion->poolsGrpModeEnable)
    {
        bpools.grp_bp_depleted_num = p_BufPoolDepletion->numOfPools;
        for (i = 0; i < BM_MAX_NUM_OF_POOLS; i++)
        {
            if (p_BufPoolDepletion->poolsToConsider[i])
            {
                for (j = 0; j < p_ExtBufPools->numOfPoolsUsed; j++)
                {
                    if (i == orderedArray[j])
                    {
                        bpools.bpool[j].grp_bp_depleted = TRUE;
                        break;
                    }
                }
            }
        }
    }

    if (p_BufPoolDepletion->singlePoolModeEnable)
    {
        for (i = 0; i < BM_MAX_NUM_OF_POOLS; i++)
        {
            if (p_BufPoolDepletion->poolsToConsiderForSingleMode[i])
            {
                for (j = 0; j < p_ExtBufPools->numOfPoolsUsed; j++)
                {
                    if (i == orderedArray[j])
                    {
                        bpools.bpool[j].single_bp_depleted = TRUE;
                        break;
                    }
                }
            }
        }
    }

    /* fill QbbPEV */
    if (p_BufPoolDepletion->poolsGrpModeEnable
            || p_BufPoolDepletion->singlePoolModeEnable)
    {
        for (i = 0; i < FM_MAX_NUM_OF_PFC_PRIORITIES; i++)
        {
            if (p_BufPoolDepletion->pfcPrioritiesEn[i] == TRUE)
            {
                bpools.bpool[i].pfc_priorities_en = TRUE;
            }
        }
    }

    /* Issue flibs function */
    err = fman_port_set_bpools(&p_FmPort->port, &bpools);
    if (err != 0)
        RETURN_ERROR(MAJOR, E_INVALID_VALUE, ("fman_port_set_bpools"));

    if (p_FmPort->p_FmPortDriverParam->p_BackupBmPools)
        XX_Free(p_FmPort->p_FmPortDriverParam->p_BackupBmPools);

    return E_OK;
}

static t_Error InitLowLevelDriver(t_FmPort *p_FmPort)
{
    t_FmPortDriverParam *p_DriverParams = p_FmPort->p_FmPortDriverParam;
    struct fman_port_params portParams;
    uint32_t tmpVal;
    t_Error err;

    /* Set up flibs parameters and issue init function */

    memset(&portParams, 0, sizeof(struct fman_port_params));
    portParams.discard_mask = p_DriverParams->errorsToDiscard;
    portParams.dflt_fqid = p_DriverParams->dfltFqid;
    portParams.err_fqid = p_DriverParams->errFqid;
    portParams.deq_sp = p_DriverParams->deqSubPortal;
    portParams.dont_release_buf = p_DriverParams->dontReleaseBuf;
    switch (p_FmPort->portType)
    {
        case (e_FM_PORT_TYPE_RX_10G):
        case (e_FM_PORT_TYPE_RX):
	    //not required to enqueue error frames
            portParams.err_mask = 0;
            if (!p_FmPort->imEn)
            {
                if (p_DriverParams->forwardReuseIntContext)
                    p_DriverParams->dfltCfg.rx_fd_bits =
                            (uint8_t)(BMI_PORT_RFNE_FRWD_RPD >> 24);
            }
            break;

        case (e_FM_PORT_TYPE_OH_OFFLINE_PARSING):
            portParams.err_mask = (OP_ERRS_TO_ENQ & ~portParams.discard_mask);
            break;
            break;

        default:
            break;
    }

    tmpVal =
            (uint32_t)(
                    (p_FmPort->internalBufferOffset % OFFSET_UNITS) ? (p_FmPort->internalBufferOffset
                            / OFFSET_UNITS + 1) :
                            (p_FmPort->internalBufferOffset / OFFSET_UNITS));
    p_FmPort->internalBufferOffset = (uint8_t)(tmpVal * OFFSET_UNITS);
    p_DriverParams->dfltCfg.int_buf_start_margin =
            p_FmPort->internalBufferOffset;

    p_DriverParams->dfltCfg.ext_buf_start_margin =
            p_DriverParams->bufMargins.startMargins;
    p_DriverParams->dfltCfg.ext_buf_end_margin =
            p_DriverParams->bufMargins.endMargins;

    p_DriverParams->dfltCfg.ic_ext_offset =
            p_DriverParams->intContext.extBufOffset;
    p_DriverParams->dfltCfg.ic_int_offset =
            p_DriverParams->intContext.intContextOffset;
    p_DriverParams->dfltCfg.ic_size = p_DriverParams->intContext.size;

    p_DriverParams->dfltCfg.stats_counters_enable = TRUE;
    p_DriverParams->dfltCfg.perf_counters_enable = TRUE;
    p_DriverParams->dfltCfg.queue_counters_enable = TRUE;

    p_DriverParams->dfltCfg.perf_cnt_params.task_val =
            (uint8_t)p_FmPort->tasks.num;
    if (p_FmPort->portType == e_FM_PORT_TYPE_OH_OFFLINE_PARSING ||
    p_FmPort->portType == e_FM_PORT_TYPE_OH_HOST_COMMAND)p_DriverParams->dfltCfg.perf_cnt_params.queue_val = 0;
    else
    p_DriverParams->dfltCfg.perf_cnt_params.queue_val = 1;
    p_DriverParams->dfltCfg.perf_cnt_params.dma_val =
            (uint8_t)p_FmPort->openDmas.num;
    p_DriverParams->dfltCfg.perf_cnt_params.fifo_val = p_FmPort->fifoBufs.num;

    if (0
            != fman_port_init(&p_FmPort->port, &p_DriverParams->dfltCfg,
                              &portParams))
        RETURN_ERROR(MAJOR, E_NO_DEVICE, ("fman_port_init"));

    if (p_FmPort->imEn && ((err = FmPortImInit(p_FmPort)) != E_OK))
        RETURN_ERROR(MAJOR, err, NO_MSG);
    else
    {
        //  from QMIInit
        if ((p_FmPort->portType != e_FM_PORT_TYPE_RX_10G)
                && (p_FmPort->portType != e_FM_PORT_TYPE_RX))
        {
            if (p_DriverParams->deqPrefetchOption == e_FM_PORT_DEQ_NO_PREFETCH)
                FmSetPortPreFetchConfiguration(p_FmPort->h_Fm, p_FmPort->portId,
                                               FALSE);
            else
                FmSetPortPreFetchConfiguration(p_FmPort->h_Fm, p_FmPort->portId,
                                               TRUE);
        }
    }
    /* The code bellow is a trick so the FM will not release the buffer
     to BM nor will try to enqueue the frame to QM */
    if (((p_FmPort->portType == e_FM_PORT_TYPE_TX_10G)
            || (p_FmPort->portType == e_FM_PORT_TYPE_TX)) && (!p_FmPort->imEn))
    {
        if (!p_DriverParams->dfltFqid && p_DriverParams->dontReleaseBuf)
        {
            /* override fmbm_tcfqid 0 with a false non-0 value. This will force FM to
             * act according to tfene. Otherwise, if fmbm_tcfqid is 0 the FM will release
             * buffers to BM regardless of fmbm_tfene
             */
            WRITE_UINT32(p_FmPort->port.bmi_regs->tx.fmbm_tcfqid, 0xFFFFFF);
            WRITE_UINT32(p_FmPort->port.bmi_regs->tx.fmbm_tfene,
                         NIA_ENG_BMI | NIA_BMI_AC_TX_RELEASE);
        }
    }

    return E_OK;
}

static bool CheckRxBmiCounter(t_FmPort *p_FmPort, e_FmPortCounters counter)
{
    UNUSED(p_FmPort);

    switch (counter)
    {
        case (e_FM_PORT_COUNTERS_CYCLE):
        case (e_FM_PORT_COUNTERS_TASK_UTIL):
        case (e_FM_PORT_COUNTERS_QUEUE_UTIL):
        case (e_FM_PORT_COUNTERS_DMA_UTIL):
        case (e_FM_PORT_COUNTERS_FIFO_UTIL):
        case (e_FM_PORT_COUNTERS_RX_PAUSE_ACTIVATION):
        case (e_FM_PORT_COUNTERS_FRAME):
        case (e_FM_PORT_COUNTERS_DISCARD_FRAME):
        case (e_FM_PORT_COUNTERS_RX_BAD_FRAME):
        case (e_FM_PORT_COUNTERS_RX_LARGE_FRAME):
        case (e_FM_PORT_COUNTERS_RX_FILTER_FRAME):
        case (e_FM_PORT_COUNTERS_RX_LIST_DMA_ERR):
        case (e_FM_PORT_COUNTERS_RX_OUT_OF_BUFFERS_DISCARD):
        case (e_FM_PORT_COUNTERS_DEALLOC_BUF):
        case (e_FM_PORT_COUNTERS_PREPARE_TO_ENQUEUE_COUNTER):
            return TRUE;
        default:
            return FALSE;
    }
}

static bool CheckTxBmiCounter(t_FmPort *p_FmPort, e_FmPortCounters counter)
{
    UNUSED(p_FmPort);

    switch (counter)
    {
        case (e_FM_PORT_COUNTERS_CYCLE):
        case (e_FM_PORT_COUNTERS_TASK_UTIL):
        case (e_FM_PORT_COUNTERS_QUEUE_UTIL):
        case (e_FM_PORT_COUNTERS_DMA_UTIL):
        case (e_FM_PORT_COUNTERS_FIFO_UTIL):
        case (e_FM_PORT_COUNTERS_FRAME):
        case (e_FM_PORT_COUNTERS_DISCARD_FRAME):
        case (e_FM_PORT_COUNTERS_LENGTH_ERR):
        case (e_FM_PORT_COUNTERS_UNSUPPRTED_FORMAT):
        case (e_FM_PORT_COUNTERS_DEALLOC_BUF):
            return TRUE;
        default:
            return FALSE;
    }
}

static bool CheckOhBmiCounter(t_FmPort *p_FmPort, e_FmPortCounters counter)
{
    switch (counter)
    {
        case (e_FM_PORT_COUNTERS_CYCLE):
        case (e_FM_PORT_COUNTERS_TASK_UTIL):
        case (e_FM_PORT_COUNTERS_DMA_UTIL):
        case (e_FM_PORT_COUNTERS_FIFO_UTIL):
        case (e_FM_PORT_COUNTERS_FRAME):
        case (e_FM_PORT_COUNTERS_DISCARD_FRAME):
        case (e_FM_PORT_COUNTERS_RX_LIST_DMA_ERR):
        case (e_FM_PORT_COUNTERS_WRED_DISCARD):
        case (e_FM_PORT_COUNTERS_LENGTH_ERR):
        case (e_FM_PORT_COUNTERS_UNSUPPRTED_FORMAT):
        case (e_FM_PORT_COUNTERS_DEALLOC_BUF):
        case (e_FM_PORT_COUNTERS_RX_OUT_OF_BUFFERS_DISCARD):
            return TRUE;
        case (e_FM_PORT_COUNTERS_RX_FILTER_FRAME):
            if (p_FmPort->portType == e_FM_PORT_TYPE_OH_HOST_COMMAND)
                return FALSE;
            else
                return TRUE;
        default:
            return FALSE;
    }
}

static t_Error BmiPortCheckAndGetCounterType(
        t_FmPort *p_FmPort, e_FmPortCounters counter,
        enum fman_port_stats_counters *p_StatsType,
        enum fman_port_perf_counters *p_PerfType, bool *p_IsStats)
{
    volatile uint32_t *p_Reg;
    bool isValid;

    switch (p_FmPort->portType)
    {
        case (e_FM_PORT_TYPE_RX_10G):
        case (e_FM_PORT_TYPE_RX):
            p_Reg = &p_FmPort->port.bmi_regs->rx.fmbm_rstc;
            isValid = CheckRxBmiCounter(p_FmPort, counter);
            break;
        case (e_FM_PORT_TYPE_TX_10G):
        case (e_FM_PORT_TYPE_TX):
            p_Reg = &p_FmPort->port.bmi_regs->tx.fmbm_tstc;
            isValid = CheckTxBmiCounter(p_FmPort, counter);
            break;
        case (e_FM_PORT_TYPE_OH_OFFLINE_PARSING):
        case (e_FM_PORT_TYPE_OH_HOST_COMMAND):
            p_Reg = &p_FmPort->port.bmi_regs->oh.fmbm_ostc;
            isValid = CheckOhBmiCounter(p_FmPort, counter);
            break;
        default:
            RETURN_ERROR(MINOR, E_INVALID_STATE, ("Unsupported port type"));
    }

    if (!isValid)
        RETURN_ERROR(MINOR, E_INVALID_STATE,
                     ("Requested counter is not available for this port type"));

    /* check that counters are enabled */
    switch (counter)
    {
        case (e_FM_PORT_COUNTERS_CYCLE):
        case (e_FM_PORT_COUNTERS_TASK_UTIL):
        case (e_FM_PORT_COUNTERS_QUEUE_UTIL):
        case (e_FM_PORT_COUNTERS_DMA_UTIL):
        case (e_FM_PORT_COUNTERS_FIFO_UTIL):
        case (e_FM_PORT_COUNTERS_RX_PAUSE_ACTIVATION):
            /* performance counters - may be read when disabled */
            *p_IsStats = FALSE;
            break;
        case (e_FM_PORT_COUNTERS_FRAME):
        case (e_FM_PORT_COUNTERS_DISCARD_FRAME):
        case (e_FM_PORT_COUNTERS_DEALLOC_BUF):
        case (e_FM_PORT_COUNTERS_RX_BAD_FRAME):
        case (e_FM_PORT_COUNTERS_RX_LARGE_FRAME):
        case (e_FM_PORT_COUNTERS_RX_FILTER_FRAME):
        case (e_FM_PORT_COUNTERS_RX_LIST_DMA_ERR):
        case (e_FM_PORT_COUNTERS_RX_OUT_OF_BUFFERS_DISCARD):
        case (e_FM_PORT_COUNTERS_LENGTH_ERR):
        case (e_FM_PORT_COUNTERS_UNSUPPRTED_FORMAT):
        case (e_FM_PORT_COUNTERS_WRED_DISCARD):
            *p_IsStats = TRUE;
            if (!(GET_UINT32(*p_Reg) & BMI_COUNTERS_EN))
                RETURN_ERROR(MINOR, E_INVALID_STATE,
                             ("Requested counter was not enabled"));
            break;
        default:
            break;
    }

    /* Set counter */
    switch (counter)
    {
        case (e_FM_PORT_COUNTERS_CYCLE):
            *p_PerfType = E_FMAN_PORT_PERF_CNT_CYCLE;
            break;
        case (e_FM_PORT_COUNTERS_TASK_UTIL):
            *p_PerfType = E_FMAN_PORT_PERF_CNT_TASK_UTIL;
            break;
        case (e_FM_PORT_COUNTERS_QUEUE_UTIL):
            *p_PerfType = E_FMAN_PORT_PERF_CNT_QUEUE_UTIL;
            break;
        case (e_FM_PORT_COUNTERS_DMA_UTIL):
            *p_PerfType = E_FMAN_PORT_PERF_CNT_DMA_UTIL;
            break;
        case (e_FM_PORT_COUNTERS_FIFO_UTIL):
            *p_PerfType = E_FMAN_PORT_PERF_CNT_FIFO_UTIL;
            break;
        case (e_FM_PORT_COUNTERS_RX_PAUSE_ACTIVATION):
            *p_PerfType = E_FMAN_PORT_PERF_CNT_RX_PAUSE;
            break;
        case (e_FM_PORT_COUNTERS_FRAME):
            *p_StatsType = E_FMAN_PORT_STATS_CNT_FRAME;
            break;
        case (e_FM_PORT_COUNTERS_DISCARD_FRAME):
            *p_StatsType = E_FMAN_PORT_STATS_CNT_DISCARD;
            break;
        case (e_FM_PORT_COUNTERS_DEALLOC_BUF):
            *p_StatsType = E_FMAN_PORT_STATS_CNT_DEALLOC_BUF;
            break;
        case (e_FM_PORT_COUNTERS_RX_BAD_FRAME):
            *p_StatsType = E_FMAN_PORT_STATS_CNT_RX_BAD_FRAME;
            break;
        case (e_FM_PORT_COUNTERS_RX_LARGE_FRAME):
            *p_StatsType = E_FMAN_PORT_STATS_CNT_RX_LARGE_FRAME;
            break;
        case (e_FM_PORT_COUNTERS_RX_OUT_OF_BUFFERS_DISCARD):
            *p_StatsType = E_FMAN_PORT_STATS_CNT_RX_OUT_OF_BUF;
            break;
        case (e_FM_PORT_COUNTERS_RX_FILTER_FRAME):
            *p_StatsType = E_FMAN_PORT_STATS_CNT_FILTERED_FRAME;
            break;
        case (e_FM_PORT_COUNTERS_RX_LIST_DMA_ERR):
            *p_StatsType = E_FMAN_PORT_STATS_CNT_DMA_ERR;
            break;
        case (e_FM_PORT_COUNTERS_WRED_DISCARD):
            *p_StatsType = E_FMAN_PORT_STATS_CNT_WRED_DISCARD;
            break;
        case (e_FM_PORT_COUNTERS_LENGTH_ERR):
            *p_StatsType = E_FMAN_PORT_STATS_CNT_LEN_ERR;
            break;
        case (e_FM_PORT_COUNTERS_UNSUPPRTED_FORMAT):
            *p_StatsType = E_FMAN_PORT_STATS_CNT_UNSUPPORTED_FORMAT;
            break;
        default:
            break;
    }

    return E_OK;
}

static t_Error AdditionalPrsParams(t_FmPort *p_FmPort,
                                   t_FmPcdPrsAdditionalHdrParams *p_HdrParams,
                                   uint32_t *p_SoftSeqAttachReg)
{
    uint8_t hdrNum, Ipv4HdrNum;
    u_FmPcdHdrPrsOpts *p_prsOpts;
    uint32_t tmpReg = *p_SoftSeqAttachReg, tmpPrsOffset;

    if (IS_PRIVATE_HEADER(p_HdrParams->hdr)
            || IS_SPECIAL_HEADER(p_HdrParams->hdr))
        RETURN_ERROR(
                MAJOR, E_NOT_SUPPORTED,
                ("No additional parameters for private or special headers."));

    if (p_HdrParams->errDisable)
        tmpReg |= PRS_HDR_ERROR_DIS;

    /* Set parser options */
    if (p_HdrParams->usePrsOpts)
    {
        p_prsOpts = &p_HdrParams->prsOpts;
        switch (p_HdrParams->hdr)
        {
            case (HEADER_TYPE_MPLS):
                if (p_prsOpts->mplsPrsOptions.labelInterpretationEnable)
                    tmpReg |= PRS_HDR_MPLS_LBL_INTER_EN;
                hdrNum = GetPrsHdrNum(p_prsOpts->mplsPrsOptions.nextParse);
                if (hdrNum == ILLEGAL_HDR_NUM)
                    RETURN_ERROR(MAJOR, E_INVALID_VALUE, NO_MSG);
                Ipv4HdrNum = GetPrsHdrNum(HEADER_TYPE_IPv4);
                if (hdrNum < Ipv4HdrNum)
                    RETURN_ERROR(MAJOR, E_INVALID_VALUE,
                                 ("Header must be equal or higher than IPv4"));
                tmpReg |= ((uint32_t)hdrNum * PRS_HDR_ENTRY_SIZE)
                        << PRS_HDR_MPLS_NEXT_HDR_SHIFT;
                break;
            case (HEADER_TYPE_PPPoE):
                if (p_prsOpts->pppoePrsOptions.enableMTUCheck)
                    tmpReg |= PRS_HDR_PPPOE_MTU_CHECK_EN;
                break;
            case (HEADER_TYPE_IPv6):
                if (p_prsOpts->ipv6PrsOptions.routingHdrEnable)
                    tmpReg |= PRS_HDR_IPV6_ROUTE_HDR_EN;
                break;
            case (HEADER_TYPE_TCP):
                if (p_prsOpts->tcpPrsOptions.padIgnoreChecksum)
                    tmpReg |= PRS_HDR_TCP_PAD_REMOVAL;
                else
                    tmpReg &= ~PRS_HDR_TCP_PAD_REMOVAL;
                break;
            case (HEADER_TYPE_UDP):
                if (p_prsOpts->udpPrsOptions.padIgnoreChecksum)
                    tmpReg |= PRS_HDR_UDP_PAD_REMOVAL;
                else
                    tmpReg &= ~PRS_HDR_UDP_PAD_REMOVAL;
                break;
            default:
                RETURN_ERROR(MAJOR, E_INVALID_STATE, ("Invalid header"));
        }
    }

    /* set software parsing (address is divided in 2 since parser uses 2 byte access. */
    if (p_HdrParams->swPrsEnable)
    {
        tmpPrsOffset = FmPcdGetSwPrsOffset(p_FmPort->h_FmPcd, p_HdrParams->hdr,
                                           p_HdrParams->indexPerHdr);
        if (tmpPrsOffset == ILLEGAL_BASE)
            RETURN_ERROR(MAJOR, E_INVALID_VALUE, NO_MSG);
        tmpReg |= (PRS_HDR_SW_PRS_EN | tmpPrsOffset);
    }
    *p_SoftSeqAttachReg = tmpReg;

    return E_OK;
}

static uint32_t GetPortSchemeBindParams(
        t_Handle h_FmPort, t_FmPcdKgInterModuleBindPortToSchemes *p_SchemeBind)
{
    t_FmPort *p_FmPort = (t_FmPort*)h_FmPort;
    uint32_t walking1Mask = 0x80000000, tmp;
    uint8_t idx = 0;

    p_SchemeBind->netEnvId = p_FmPort->netEnvId;
    p_SchemeBind->hardwarePortId = p_FmPort->hardwarePortId;
    p_SchemeBind->useClsPlan = p_FmPort->useClsPlan;
    p_SchemeBind->numOfSchemes = 0;
    tmp = p_FmPort->schemesPerPortVector;
    if (tmp)
    {
        while (tmp)
        {
            if (tmp & walking1Mask)
            {
                p_SchemeBind->schemesIds[p_SchemeBind->numOfSchemes] = idx;
                p_SchemeBind->numOfSchemes++;
                tmp &= ~walking1Mask;
            }
            walking1Mask >>= 1;
            idx++;
        }
    }

    return tmp;
}

static void FmPortCheckNApplyMacsec(t_Handle h_FmPort)
{
    t_FmPort *p_FmPort = (t_FmPort*)h_FmPort;
    volatile uint32_t *p_BmiCfgReg = NULL;
    uint32_t macsecEn = BMI_PORT_CFG_EN_MACSEC;
    uint32_t lcv, walking1Mask = 0x80000000;
    uint8_t cnt = 0;

    ASSERT_COND(p_FmPort);
    ASSERT_COND(p_FmPort->h_FmPcd);
    ASSERT_COND(!p_FmPort->p_FmPortDriverParam);

    if ((p_FmPort->portType != e_FM_PORT_TYPE_RX_10G)
            && (p_FmPort->portType != e_FM_PORT_TYPE_RX))
        return;

    p_BmiCfgReg = &p_FmPort->port.bmi_regs->rx.fmbm_rcfg;
    /* get LCV for MACSEC */
    if ((lcv = FmPcdGetMacsecLcv(p_FmPort->h_FmPcd, p_FmPort->netEnvId))
                    != 0)
    {
        while (!(lcv & walking1Mask))
        {
            cnt++;
            walking1Mask >>= 1;
        }

        macsecEn |= (uint32_t)cnt << BMI_PORT_CFG_MS_SEL_SHIFT;
        WRITE_UINT32(*p_BmiCfgReg, GET_UINT32(*p_BmiCfgReg) | macsecEn);
    }
}

static t_Error DeletePcd(t_FmPort *p_FmPort);

static t_Error ConfigurePcd(t_FmPort *p_FmPort, t_FmPortPcdParams *p_PcdParams,
                           struct fm_port_pcd_bindings *bindings)
{
    t_Error err = E_OK;
    uint32_t tmpReg;
    volatile uint32_t *p_BmiNia = NULL;
    volatile uint32_t *p_BmiPrsNia = NULL;
    volatile uint32_t *p_BmiPrsStartOffset = NULL;
    volatile uint32_t *p_BmiInitPrsResult = NULL;
    volatile uint32_t *p_BmiCcBase = NULL;
    uint16_t hdrNum, L3HdrNum, greHdrNum;
    int i;
    bool isEmptyClsPlanGrp;
    uint32_t tmpHxs[FM_PCD_PRS_NUM_OF_HDRS];
    uint16_t absoluteProfileId;
    uint8_t physicalSchemeId;
    uint32_t ccTreePhysOffset;
    t_FmPcdKgInterModuleBindPortToSchemes schemeBind;
    uint32_t initialSwPrs = 0;

    ASSERT_COND(p_FmPort);
    SANITY_CHECK_RETURN_ERROR(!p_FmPort->p_FmPortDriverParam, E_INVALID_STATE);

    if (p_FmPort->imEn)
        RETURN_ERROR(MAJOR, E_INVALID_OPERATION,
                     ("available for non-independant mode ports only"));

    if ((p_FmPort->portType != e_FM_PORT_TYPE_RX_10G)
            && (p_FmPort->portType != e_FM_PORT_TYPE_RX)
            && (p_FmPort->portType != e_FM_PORT_TYPE_OH_OFFLINE_PARSING))
        RETURN_ERROR(MAJOR, E_INVALID_OPERATION,
                     ("available for Rx and offline parsing ports only"));

    p_FmPort->netEnvId = FmPcdGetNetEnvId(p_PcdParams->h_NetEnv);

    p_FmPort->pcdEngines = 0;

    /* initialize p_FmPort->pcdEngines field in port's structure */
    switch (p_PcdParams->pcdSupport)
    {
        case (e_FM_PORT_PCD_SUPPORT_NONE):
            RETURN_ERROR(
                    MAJOR,
                    E_INVALID_STATE,
                    ("No PCD configuration required if e_FM_PORT_PCD_SUPPORT_NONE selected"));
        case (e_FM_PORT_PCD_SUPPORT_PRS_ONLY):
            p_FmPort->pcdEngines |= FM_PCD_PRS;
            break;
        case (e_FM_PORT_PCD_SUPPORT_PLCR_ONLY):
            p_FmPort->pcdEngines |= FM_PCD_PLCR;
            break;
        case (e_FM_PORT_PCD_SUPPORT_PRS_AND_PLCR):
            p_FmPort->pcdEngines |= FM_PCD_PRS;
            p_FmPort->pcdEngines |= FM_PCD_PLCR;
            break;
        case (e_FM_PORT_PCD_SUPPORT_PRS_AND_KG):
            p_FmPort->pcdEngines |= FM_PCD_PRS;
            p_FmPort->pcdEngines |= FM_PCD_KG;
            break;
        case (e_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_CC):
            p_FmPort->pcdEngines |= FM_PCD_PRS;
            p_FmPort->pcdEngines |= FM_PCD_CC;
            p_FmPort->pcdEngines |= FM_PCD_KG;
            break;
        case (e_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_CC_AND_PLCR):
            p_FmPort->pcdEngines |= FM_PCD_PRS;
            p_FmPort->pcdEngines |= FM_PCD_KG;
            p_FmPort->pcdEngines |= FM_PCD_CC;
            p_FmPort->pcdEngines |= FM_PCD_PLCR;
            break;
        case (e_FM_PORT_PCD_SUPPORT_PRS_AND_CC):
            p_FmPort->pcdEngines |= FM_PCD_PRS;
            p_FmPort->pcdEngines |= FM_PCD_CC;
            break;
        case (e_FM_PORT_PCD_SUPPORT_PRS_AND_CC_AND_PLCR):
            p_FmPort->pcdEngines |= FM_PCD_PRS;
            p_FmPort->pcdEngines |= FM_PCD_CC;
            p_FmPort->pcdEngines |= FM_PCD_PLCR;
            break;
        case (e_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_PLCR):
            p_FmPort->pcdEngines |= FM_PCD_PRS;
            p_FmPort->pcdEngines |= FM_PCD_KG;
            p_FmPort->pcdEngines |= FM_PCD_PLCR;
            break;
        case (e_FM_PORT_PCD_SUPPORT_CC_ONLY):
            p_FmPort->pcdEngines |= FM_PCD_CC;
            break;

        default:
            RETURN_ERROR(MAJOR, E_INVALID_STATE, ("invalid pcdSupport"));
    }

    /* check that parameters exist for each and only each defined engine */
    if ((!!(p_FmPort->pcdEngines & FM_PCD_PRS) != !!p_PcdParams->p_PrsParams)
            || (!!(p_FmPort->pcdEngines & FM_PCD_KG)
                    != !!p_PcdParams->p_KgParams)
            || (!!(p_FmPort->pcdEngines & FM_PCD_CC)
                    != !!p_PcdParams->p_CcParams))
        RETURN_ERROR(
                MAJOR,
                E_INVALID_STATE,
                ("PCD initialization structure is not consistent with pcdSupport"));

    if ((p_FmPort->pcdEngines & FM_PCD_PRS)
            && (p_PcdParams->p_PrsParams->numOfHdrsWithAdditionalParams
                    > FM_PCD_PRS_NUM_OF_HDRS))
        RETURN_ERROR(
                MAJOR,
                E_INVALID_VALUE,
                ("Port parser numOfHdrsWithAdditionalParams may not exceed %d", FM_PCD_PRS_NUM_OF_HDRS));

    /* get PCD registers pointers */
    switch (p_FmPort->portType)
    {
        case (e_FM_PORT_TYPE_RX_10G):
        case (e_FM_PORT_TYPE_RX):
            p_BmiNia = &p_FmPort->port.bmi_regs->rx.fmbm_rfne;
            p_BmiPrsNia = &p_FmPort->port.bmi_regs->rx.fmbm_rfpne;
            p_BmiPrsStartOffset = &p_FmPort->port.bmi_regs->rx.fmbm_rpso;
            p_BmiInitPrsResult = &p_FmPort->port.bmi_regs->rx.fmbm_rprai[0];
            p_BmiCcBase = &p_FmPort->port.bmi_regs->rx.fmbm_rccb;
            break;
        case (e_FM_PORT_TYPE_OH_OFFLINE_PARSING):
            p_BmiNia = &p_FmPort->port.bmi_regs->oh.fmbm_ofne;
            p_BmiPrsNia = &p_FmPort->port.bmi_regs->oh.fmbm_ofpne;
            p_BmiPrsStartOffset = &p_FmPort->port.bmi_regs->oh.fmbm_opso;
            p_BmiInitPrsResult = &p_FmPort->port.bmi_regs->oh.fmbm_oprai[0];
            p_BmiCcBase = &p_FmPort->port.bmi_regs->oh.fmbm_occb;
            break;
        default:
            RETURN_ERROR(MAJOR, E_INVALID_STATE, ("Invalid port type"));
    }

    /* set PCD port parameter */
    if (p_FmPort->pcdEngines & FM_PCD_CC)
    {
        err = FmPcdCcBindTree(p_FmPort->h_FmPcd, p_PcdParams,
                              p_PcdParams->p_CcParams->h_CcTree,
                              &ccTreePhysOffset, p_FmPort);
        if (err)
            RETURN_ERROR(MAJOR, err, NO_MSG);

        WRITE_UINT32(*p_BmiCcBase, ccTreePhysOffset);
        p_FmPort->ccTreeId = p_PcdParams->p_CcParams->h_CcTree;
        bindings->cc = TRUE;
    }

    if (p_FmPort->pcdEngines & FM_PCD_KG)
    {
        if (p_PcdParams->p_KgParams->numOfSchemes == 0)
            RETURN_ERROR(
                    MAJOR,
                    E_INVALID_VALUE,
                    ("For ports using Keygen, at least one scheme must be bound. "));

        err = FmPcdKgSetOrBindToClsPlanGrp(p_FmPort->h_FmPcd,
                                           p_FmPort->hardwarePortId,
                                           p_FmPort->netEnvId,
                                           p_FmPort->optArray,
                                           &p_FmPort->clsPlanGrpId,
                                           &isEmptyClsPlanGrp);
        if (err)
            RETURN_ERROR(MAJOR, E_INVALID_VALUE,
                         ("FmPcdKgSetOrBindToClsPlanGrp failed. "));

        bindings->clsPlan = TRUE;
        p_FmPort->useClsPlan = !isEmptyClsPlanGrp;

        schemeBind.netEnvId = p_FmPort->netEnvId;
        schemeBind.hardwarePortId = p_FmPort->hardwarePortId;
        schemeBind.numOfSchemes = p_PcdParams->p_KgParams->numOfSchemes;
        schemeBind.useClsPlan = p_FmPort->useClsPlan;

        /* for each scheme */
        for (i = 0; i < p_PcdParams->p_KgParams->numOfSchemes; i++)
        {
            ASSERT_COND(p_PcdParams->p_KgParams->h_Schemes[i]);
            physicalSchemeId = FmPcdKgGetSchemeId(
                    p_PcdParams->p_KgParams->h_Schemes[i]);
            schemeBind.schemesIds[i] = physicalSchemeId;
            /* build vector */
            p_FmPort->schemesPerPortVector |= 1
                    << (31 - (uint32_t)physicalSchemeId);
            /*because of the state that VSPE is defined per port - all PCD path should be according to this requirement
             if !VSPE - in port, for relevant scheme VSPE can not be set*/
            if (!p_FmPort->vspe
                    && FmPcdKgGetVspe((p_PcdParams->p_KgParams->h_Schemes[i])))
                RETURN_ERROR(MAJOR, E_INVALID_STATE,
                             ("VSPE is not at port level"));
        }

        err = FmPcdKgBindPortToSchemes(p_FmPort->h_FmPcd, &schemeBind);
        if (err)
            RETURN_ERROR(MAJOR, err, NO_MSG);
        bindings->schemes = TRUE;
    }

    /***************************/
    /* configure NIA after BMI */
    /***************************/
    /* rfne may contain FDCS bits, so first we read them. */
    p_FmPort->savedBmiNia = GET_UINT32(*p_BmiNia) & BMI_RFNE_FDCS_MASK;

    /* If policer is used directly after BMI or PRS */
    if ((p_FmPort->pcdEngines & FM_PCD_PLCR)
            && ((p_PcdParams->pcdSupport == e_FM_PORT_PCD_SUPPORT_PLCR_ONLY)
                    || (p_PcdParams->pcdSupport
                            == e_FM_PORT_PCD_SUPPORT_PRS_AND_PLCR)))
    {
        if (!p_PcdParams->p_PlcrParams->h_Profile)
            RETURN_ERROR(MAJOR, E_INVALID_STATE,
                         ("Profile should be initialized"));

        absoluteProfileId = (uint16_t)FmPcdPlcrProfileGetAbsoluteId(
                p_PcdParams->p_PlcrParams->h_Profile);

        if (!FmPcdPlcrIsProfileValid(p_FmPort->h_FmPcd, absoluteProfileId))
            RETURN_ERROR(MAJOR, E_INVALID_STATE,
                         ("Private port profile not valid."));

        tmpReg = (uint32_t)(absoluteProfileId | NIA_PLCR_ABSOLUTE);

        if (p_FmPort->pcdEngines & FM_PCD_PRS) /* e_FM_PCD_SUPPORT_PRS_AND_PLCR */
            /* update BMI HPNIA */
            WRITE_UINT32(*p_BmiPrsNia, (uint32_t)(NIA_ENG_PLCR | tmpReg));
        else
            /* e_FM_PCD_SUPPORT_PLCR_ONLY */
            /* update BMI NIA */
            p_FmPort->savedBmiNia |= (uint32_t)(NIA_ENG_PLCR);
    }

    /* if CC is used directly after BMI */
    if (p_PcdParams->pcdSupport == e_FM_PORT_PCD_SUPPORT_CC_ONLY)
    {
        if (p_FmPort->portType != e_FM_PORT_TYPE_OH_OFFLINE_PARSING)
            RETURN_ERROR(
                    MAJOR,
                    E_INVALID_OPERATION,
                    ("e_FM_PORT_PCD_SUPPORT_CC_xx available for offline parsing ports only"));
        p_FmPort->savedBmiNia |= (uint32_t)(NIA_ENG_FM_CTL | NIA_FM_CTL_AC_CC);
        /* check that prs start offset == RIM[FOF] */
    }

    if (p_FmPort->pcdEngines & FM_PCD_PRS)
    {
        ASSERT_COND(p_PcdParams->p_PrsParams);
        if (p_PcdParams->p_PrsParams->firstPrsHdr == HEADER_TYPE_CAPWAP)
            hdrNum = OFFLOAD_SW_PATCH_CAPWAP_LABEL;
        else
        {
            /* if PRS is used it is always first */
                hdrNum = GetPrsHdrNum(p_PcdParams->p_PrsParams->firstPrsHdr);
            if (hdrNum == ILLEGAL_HDR_NUM)
                RETURN_ERROR(MAJOR, E_NOT_SUPPORTED, ("Unsupported header."));
        }
        p_FmPort->savedBmiNia |= (uint32_t)(NIA_ENG_PRS | (uint32_t)(hdrNum));
        /* set after parser NIA */
        tmpReg = 0;
        switch (p_PcdParams->pcdSupport)
        {
            case (e_FM_PORT_PCD_SUPPORT_PRS_ONLY):
                WRITE_UINT32(*p_BmiPrsNia,
                             GET_NIA_BMI_AC_ENQ_FRAME(p_FmPort->h_FmPcd));
                break;
            case (e_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_CC):
            case (e_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_CC_AND_PLCR):
                tmpReg = NIA_KG_CC_EN;
                fallthrough;
            case (e_FM_PORT_PCD_SUPPORT_PRS_AND_KG):
            case (e_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_PLCR):
                if (p_PcdParams->p_KgParams->directScheme)
                {
                    physicalSchemeId = FmPcdKgGetSchemeId(
                            p_PcdParams->p_KgParams->h_DirectScheme);
                    /* check that this scheme was bound to this port */
                    for (i = 0; i < p_PcdParams->p_KgParams->numOfSchemes; i++)
                        if (p_PcdParams->p_KgParams->h_DirectScheme
                                == p_PcdParams->p_KgParams->h_Schemes[i])
                            break;
                    if (i == p_PcdParams->p_KgParams->numOfSchemes)
                        RETURN_ERROR(
                                MAJOR,
                                E_INVALID_VALUE,
                                ("Direct scheme is not one of the port selected schemes."));
                    tmpReg |= (uint32_t)(NIA_KG_DIRECT | physicalSchemeId);
                }
                WRITE_UINT32(*p_BmiPrsNia, NIA_ENG_KG | tmpReg);
                break;
            case (e_FM_PORT_PCD_SUPPORT_PRS_AND_CC):
            case (e_FM_PORT_PCD_SUPPORT_PRS_AND_CC_AND_PLCR):
                WRITE_UINT32(*p_BmiPrsNia,
                             (uint32_t)(NIA_ENG_FM_CTL | NIA_FM_CTL_AC_CC));
                break;
            case (e_FM_PORT_PCD_SUPPORT_PRS_AND_PLCR):
                break;
            default:
                RETURN_ERROR(MAJOR, E_INVALID_STATE, ("Invalid PCD support"));
        }

        /* set start parsing offset */
        WRITE_UINT32(*p_BmiPrsStartOffset,
                     p_PcdParams->p_PrsParams->parsingOffset);

        /************************************/
        /* Parser port parameters           */
        /************************************/
        /* stop before configuring */
        WRITE_UINT32(p_FmPort->p_FmPortPrsRegs->pcac, PRS_CAC_STOP);
        /* wait for parser to be in idle state */
        while (GET_UINT32(p_FmPort->p_FmPortPrsRegs->pcac) & PRS_CAC_ACTIVE)
            ;

        /* set soft seq attachment register */
        memset(tmpHxs, 0, FM_PCD_PRS_NUM_OF_HDRS * sizeof(uint32_t));

        /* set protocol options */
        for (i = 0; p_FmPort->optArray[i]; i++)
            switch (p_FmPort->optArray[i])
            {
                case (ETH_BROADCAST):
                    hdrNum = GetPrsHdrNum(HEADER_TYPE_ETH);
                    tmpHxs[hdrNum] |= (i + 1) << PRS_HDR_ETH_BC_SHIFT;
                    break;
                case (ETH_MULTICAST):
                    hdrNum = GetPrsHdrNum(HEADER_TYPE_ETH);
                    tmpHxs[hdrNum] |= (i + 1) << PRS_HDR_ETH_MC_SHIFT;
                    break;
                case (VLAN_STACKED):
                    hdrNum = GetPrsHdrNum(HEADER_TYPE_VLAN);
                    tmpHxs[hdrNum] |= (i + 1) << PRS_HDR_VLAN_STACKED_SHIFT;
                    break;
                case (MPLS_STACKED):
                    hdrNum = GetPrsHdrNum(HEADER_TYPE_MPLS);
                    tmpHxs[hdrNum] |= (i + 1) << PRS_HDR_MPLS_STACKED_SHIFT;
                    break;
                case (IPV4_BROADCAST_1):
                    hdrNum = GetPrsHdrNum(HEADER_TYPE_IPv4);
                    tmpHxs[hdrNum] |= (i + 1) << PRS_HDR_IPV4_1_BC_SHIFT;
                    break;
                case (IPV4_MULTICAST_1):
                    hdrNum = GetPrsHdrNum(HEADER_TYPE_IPv4);
                    tmpHxs[hdrNum] |= (i + 1) << PRS_HDR_IPV4_1_MC_SHIFT;
                    break;
                case (IPV4_UNICAST_2):
					hdrNum = GetPrsHdrNum(HEADER_TYPE_IPv4);
                    tmpHxs[hdrNum] |= (i + 1) << PRS_HDR_IPV4_2_UC_SHIFT;
                    break;
                case (IPV4_MULTICAST_BROADCAST_2):
					hdrNum = GetPrsHdrNum(HEADER_TYPE_IPv4);
                    tmpHxs[hdrNum] |= (i + 1) << PRS_HDR_IPV4_2_MC_BC_SHIFT;
                    break;
                case (IPV6_MULTICAST_1):
                    hdrNum = GetPrsHdrNum(HEADER_TYPE_IPv6);
                    tmpHxs[hdrNum] |= (i + 1) << PRS_HDR_IPV6_1_MC_SHIFT;
                    break;
                case (IPV6_UNICAST_2):
                    hdrNum = GetPrsHdrNum(HEADER_TYPE_IPv6);
                    tmpHxs[hdrNum] |= (i + 1) << PRS_HDR_IPV6_2_UC_SHIFT;
                    break;
                case (IPV6_MULTICAST_2):
                    hdrNum = GetPrsHdrNum(HEADER_TYPE_IPv6);
                    tmpHxs[hdrNum] |= (i + 1) << PRS_HDR_IPV6_2_MC_SHIFT;
                    break;
            }

        if (FmPcdNetEnvIsHdrExist(p_FmPort->h_FmPcd, p_FmPort->netEnvId,
                                  HEADER_TYPE_UDP_ENCAP_ESP))
        {
            if (p_PcdParams->p_PrsParams->numOfHdrsWithAdditionalParams == FM_PCD_PRS_NUM_OF_HDRS)
                RETURN_ERROR(
                         MINOR, E_INVALID_VALUE,
                         ("If HEADER_TYPE_UDP_ENCAP_ESP is used, numOfHdrsWithAdditionalParams may be up to FM_PCD_PRS_NUM_OF_HDRS - 1"));

            p_PcdParams->p_PrsParams->additionalParams[p_PcdParams->p_PrsParams->numOfHdrsWithAdditionalParams].hdr =
                    HEADER_TYPE_UDP;
            p_PcdParams->p_PrsParams->additionalParams[p_PcdParams->p_PrsParams->numOfHdrsWithAdditionalParams].swPrsEnable =
                    TRUE;
            p_PcdParams->p_PrsParams->numOfHdrsWithAdditionalParams++;
        }

        /* set MPLS default next header - HW reset workaround  */
        hdrNum = GetPrsHdrNum(HEADER_TYPE_MPLS);
        tmpHxs[hdrNum] |= PRS_HDR_MPLS_LBL_INTER_EN;
        L3HdrNum = GetPrsHdrNum(HEADER_TYPE_USER_DEFINED_L3);
        tmpHxs[hdrNum] |= (uint32_t)L3HdrNum << PRS_HDR_MPLS_NEXT_HDR_SHIFT;

        /* for GRE, disable errors */
        greHdrNum = GetPrsHdrNum(HEADER_TYPE_GRE);
        tmpHxs[greHdrNum] |= PRS_HDR_ERROR_DIS;

        /* For UDP remove PAD from L4 checksum calculation */
        hdrNum = GetPrsHdrNum(HEADER_TYPE_UDP);
        tmpHxs[hdrNum] |= PRS_HDR_UDP_PAD_REMOVAL;
        /* For TCP remove PAD from L4 checksum calculation */
        hdrNum = GetPrsHdrNum(HEADER_TYPE_TCP);
        tmpHxs[hdrNum] |= PRS_HDR_TCP_PAD_REMOVAL;

        /* config additional params for specific headers */
        for (i = 0; i < p_PcdParams->p_PrsParams->numOfHdrsWithAdditionalParams;
                i++)
        {
            /* case for using sw parser as the initial NIA address, before
               * HW parsing
               */
            if ((p_PcdParams->p_PrsParams->additionalParams[i].hdr == HEADER_TYPE_NONE) &&
                    p_PcdParams->p_PrsParams->additionalParams[i].swPrsEnable)
            {
                initialSwPrs = FmPcdGetSwPrsOffset(p_FmPort->h_FmPcd, HEADER_TYPE_NONE,
                               p_PcdParams->p_PrsParams->additionalParams[i].indexPerHdr);
                if (initialSwPrs == ILLEGAL_BASE)
                    RETURN_ERROR(MAJOR, E_INVALID_VALUE, NO_MSG);

                /* clear parser first HXS */
                p_FmPort->savedBmiNia &= ~BMI_RFNE_HXS_MASK; /* 0x000000FF */
                /* rewrite with soft parser start */
                p_FmPort->savedBmiNia |= initialSwPrs;
                continue;
            }

            hdrNum =
                GetPrsHdrNum(p_PcdParams->p_PrsParams->additionalParams[i].hdr);
            if (hdrNum == ILLEGAL_HDR_NUM)
                RETURN_ERROR(MAJOR, E_INVALID_VALUE, NO_MSG);
            if (hdrNum == NO_HDR_NUM)
                RETURN_ERROR(
                        MAJOR, E_INVALID_VALUE,
                        ("Private headers may not use additional parameters"));

            err = AdditionalPrsParams(
                    p_FmPort, &p_PcdParams->p_PrsParams->additionalParams[i],
                    &tmpHxs[hdrNum]);
            if (err)
                RETURN_ERROR(MAJOR, E_INVALID_VALUE, NO_MSG);
        }

        if (FmPcdNetEnvIsHdrExist(p_FmPort->h_FmPcd, p_FmPort->netEnvId, HEADER_TYPE_UDP_LITE))
        {
            hdrNum = GetPrsHdrNum(HEADER_TYPE_IPv6);
            if (!(tmpHxs[hdrNum] & PRS_HDR_SW_PRS_EN))
                tmpHxs[hdrNum] |= (PRS_HDR_SW_PRS_EN | OFFLOAD_SW_PATCH_IPv6_IPF_LABEL);
        } else if ((FmPcdIsAdvancedOffloadSupported(p_FmPort->h_FmPcd)
                   && (p_FmPort->portType == e_FM_PORT_TYPE_OH_OFFLINE_PARSING)))
            {
                hdrNum = GetPrsHdrNum(HEADER_TYPE_IPv6);
                if (!(tmpHxs[hdrNum] & PRS_HDR_SW_PRS_EN))
                    tmpHxs[hdrNum] |= (PRS_HDR_SW_PRS_EN | OFFLOAD_SW_PATCH_IPv6_IPF_LABEL);
            }



        for (i = 0; i < FM_PCD_PRS_NUM_OF_HDRS; i++)
        {
            /* For all header set LCV as taken from netEnv*/
            WRITE_UINT32(
                    p_FmPort->p_FmPortPrsRegs->hdrs[i].lcv,
                    FmPcdGetLcv(p_FmPort->h_FmPcd, p_FmPort->netEnvId, (uint8_t)i));
            /* set HXS register according to default+Additional params+protocol options */
            WRITE_UINT32(p_FmPort->p_FmPortPrsRegs->hdrs[i].softSeqAttach,
                         tmpHxs[i]);
        }

        /* set tpid. */
        tmpReg = PRS_TPID_DFLT;
        if (p_PcdParams->p_PrsParams->setVlanTpid1)
        {
            tmpReg &= PRS_TPID2_MASK;
            tmpReg |= (uint32_t)p_PcdParams->p_PrsParams->vlanTpid1
                    << PRS_PCTPID_SHIFT;
        }
        if (p_PcdParams->p_PrsParams->setVlanTpid2)
        {
            tmpReg &= PRS_TPID1_MASK;
            tmpReg |= (uint32_t)p_PcdParams->p_PrsParams->vlanTpid2;
        }WRITE_UINT32(p_FmPort->p_FmPortPrsRegs->pctpid, tmpReg);

        /* enable parser */
        WRITE_UINT32(p_FmPort->p_FmPortPrsRegs->pcac, 0);

        if (p_PcdParams->p_PrsParams->prsResultPrivateInfo)
            p_FmPort->privateInfo =
                    p_PcdParams->p_PrsParams->prsResultPrivateInfo;

    } /* end parser */
    else {
        if (FmPcdIsAdvancedOffloadSupported(p_FmPort->h_FmPcd)
            && (p_FmPort->portType == e_FM_PORT_TYPE_OH_OFFLINE_PARSING))
        {
            hdrNum = GetPrsHdrNum(HEADER_TYPE_IPv6);
            WRITE_UINT32(p_FmPort->p_FmPortPrsRegs->hdrs[hdrNum].softSeqAttach,
                         (PRS_HDR_SW_PRS_EN | OFFLOAD_SW_PATCH_IPv6_IPF_LABEL));
        }

        WRITE_UINT32(*p_BmiPrsStartOffset, 0);

        p_FmPort->privateInfo = 0;
    }

    FmPortCheckNApplyMacsec(p_FmPort);

    WRITE_UINT32(
            *p_BmiPrsStartOffset,
            GET_UINT32(*p_BmiPrsStartOffset) + p_FmPort->internalBufferOffset);

    /* set initial parser result - used for all engines */
    for (i = 0; i < FM_PORT_PRS_RESULT_NUM_OF_WORDS; i++)
    {
        if (!i)
            WRITE_UINT32(
                    *(p_BmiInitPrsResult),
                    (uint32_t)(((uint32_t)p_FmPort->privateInfo << BMI_PR_PORTID_SHIFT) | BMI_PRS_RESULT_HIGH));
        else
        {
            if (i < FM_PORT_PRS_RESULT_NUM_OF_WORDS / 2)
                WRITE_UINT32(*(p_BmiInitPrsResult+i), BMI_PRS_RESULT_HIGH);
            else
                WRITE_UINT32(*(p_BmiInitPrsResult+i), BMI_PRS_RESULT_LOW);
        }
    }

    return E_OK;
}

/* Keep any bindings whose rollback failed so the public API can retry. */
static t_Error SetPcd(t_FmPort *p_FmPort, t_FmPortPcdParams *p_PcdParams)
{
    t_Error err, cleanupErr;

    if (p_FmPort->pcdEngines)
        RETURN_ERROR(MAJOR, E_INVALID_STATE, ("PCD is already configured"));

    err = ConfigurePcd(p_FmPort, p_PcdParams, &p_FmPort->pcdBindings);
    if (err && p_FmPort->pcdEngines)
    {
        cleanupErr = DeletePcd(p_FmPort);
        if (cleanupErr)
            REPORT_ERROR(MAJOR, cleanupErr, ("Failed to roll back port PCD bindings"));
    }
    return err;
}

static t_Error DeletePcd(t_FmPort *p_FmPort)
{
    t_Error err = E_OK;
    volatile uint32_t *p_BmiNia = NULL;
    volatile uint32_t *p_BmiPrsStartOffset = NULL;

    ASSERT_COND(p_FmPort);
    SANITY_CHECK_RETURN_ERROR(!p_FmPort->p_FmPortDriverParam, E_INVALID_STATE);

    if (p_FmPort->imEn)
        RETURN_ERROR(MAJOR, E_INVALID_OPERATION,
                     ("available for non-independant mode ports only"));

    if ((p_FmPort->portType != e_FM_PORT_TYPE_RX_10G)
            && (p_FmPort->portType != e_FM_PORT_TYPE_RX)
            && (p_FmPort->portType != e_FM_PORT_TYPE_OH_OFFLINE_PARSING))
        RETURN_ERROR( MAJOR, E_INVALID_OPERATION,
                     ("available for Rx and offline parsing ports only"));

    if (!p_FmPort->pcdEngines)
        return E_OK;

    /* get PCD registers pointers */
    switch (p_FmPort->portType)
    {
        case (e_FM_PORT_TYPE_RX_10G):
        case (e_FM_PORT_TYPE_RX):
            p_BmiNia = &p_FmPort->port.bmi_regs->rx.fmbm_rfne;
            p_BmiPrsStartOffset = &p_FmPort->port.bmi_regs->rx.fmbm_rpso;
            break;
        case (e_FM_PORT_TYPE_OH_OFFLINE_PARSING):
            p_BmiNia = &p_FmPort->port.bmi_regs->oh.fmbm_ofne;
            p_BmiPrsStartOffset = &p_FmPort->port.bmi_regs->oh.fmbm_opso;
            break;
        default:
            RETURN_ERROR(MAJOR, E_INVALID_STATE, ("Invalid port type"));
    }

    if ((GET_UINT32(*p_BmiNia) & GET_NO_PCD_NIA_BMI_AC_ENQ_FRAME())
            != GET_NO_PCD_NIA_BMI_AC_ENQ_FRAME())
        RETURN_ERROR(MAJOR, E_INVALID_OPERATION,
                     ("port has to be detached previousely"));

    WRITE_UINT32(*p_BmiPrsStartOffset, 0);

    /* "cut" PCD out of the port's flow - go to BMI */
    /* WRITE_UINT32(*p_BmiNia, (p_FmPort->savedBmiNia & BMI_RFNE_FDCS_MASK) | (NIA_ENG_BMI | NIA_BMI_AC_ENQ_FRAME)); */

    if (p_FmPort->pcdEngines & FM_PCD_PRS)
    {
        /* stop parser */
        WRITE_UINT32(p_FmPort->p_FmPortPrsRegs->pcac, PRS_CAC_STOP);
        /* wait for parser to be in idle state */
        while (GET_UINT32(p_FmPort->p_FmPortPrsRegs->pcac) & PRS_CAC_ACTIVE)
            ;
    }

    if (p_FmPort->includeInPrsStatistics)
    {
        err = FmPcdPrsIncludePortInStatistics(p_FmPort->h_FmPcd,
                                             p_FmPort->hardwarePortId, FALSE);
        if (err)
            return err;
        p_FmPort->includeInPrsStatistics = FALSE;
    }

    if (p_FmPort->pcdBindings.schemes)
    {
        t_FmPcdKgInterModuleBindPortToSchemes schemeBind;

        GetPortSchemeBindParams(p_FmPort, &schemeBind);
        err = FmPcdKgUnbindPortToSchemes(p_FmPort->h_FmPcd, &schemeBind);
        if (err)
            return err;
        p_FmPort->pcdBindings.schemes = FALSE;
        p_FmPort->schemesPerPortVector = 0;
    }
    if (p_FmPort->pcdBindings.clsPlan)
    {
        err = FmPcdKgDeleteOrUnbindPortToClsPlanGrp(p_FmPort->h_FmPcd,
                                p_FmPort->hardwarePortId, p_FmPort->clsPlanGrpId);
        if (err)
            return err;
        p_FmPort->pcdBindings.clsPlan = FALSE;
        p_FmPort->useClsPlan = FALSE;
    }
    if (p_FmPort->pcdBindings.cc)
    {
        err = FmPcdCcUnbindTree(p_FmPort->h_FmPcd, p_FmPort->ccTreeId);
        if (err)
            return err;
        p_FmPort->pcdBindings.cc = FALSE;
        p_FmPort->ccTreeId = NULL;
    }

    p_FmPort->schemesPerPortVector = 0;
    p_FmPort->useClsPlan = FALSE;
    memset(p_FmPort->optArray, 0, sizeof(p_FmPort->optArray));
    p_FmPort->pcdEngines = 0;

    return E_OK;
}

static t_Error AttachPCD(t_FmPort *p_FmPort)
{
    volatile uint32_t *p_BmiNia = NULL;

    ASSERT_COND(p_FmPort);

    /* get PCD registers pointers */
    if (p_FmPort->portType == e_FM_PORT_TYPE_OH_OFFLINE_PARSING)
        p_BmiNia = &p_FmPort->port.bmi_regs->oh.fmbm_ofne;
    else
        p_BmiNia = &p_FmPort->port.bmi_regs->rx.fmbm_rfne;

    /* check that current NIA is BMI to BMI */
    if ((GET_UINT32(*p_BmiNia) & ~BMI_RFNE_FDCS_MASK)
            != GET_NO_PCD_NIA_BMI_AC_ENQ_FRAME())
        RETURN_ERROR( MAJOR, E_INVALID_OPERATION,
                     ("may be called only for ports in BMI-to-BMI state."));

    if (p_FmPort->requiredAction & UPDATE_FMFP_PRC_WITH_ONE_RISC_ONLY)
        if (FmSetNumOfRiscsPerPort(p_FmPort->h_Fm, p_FmPort->hardwarePortId, 1,
                                   p_FmPort->orFmanCtrl) != E_OK)
            RETURN_ERROR(MAJOR, E_INVALID_STATE, NO_MSG);

    if (p_FmPort->requiredAction & UPDATE_NIA_CMNE)
    {
        if (p_FmPort->portType == e_FM_PORT_TYPE_OH_OFFLINE_PARSING)
            WRITE_UINT32(p_FmPort->port.bmi_regs->oh.fmbm_ocmne,
                         p_FmPort->savedBmiCmne);
        else
            WRITE_UINT32(p_FmPort->port.bmi_regs->rx.fmbm_rcmne,
                         p_FmPort->savedBmiCmne);
    }

    if (p_FmPort->requiredAction & UPDATE_NIA_PNEN)
        WRITE_UINT32(p_FmPort->p_FmPortQmiRegs->fmqm_pnen,
                     p_FmPort->savedQmiPnen);

    if (p_FmPort->requiredAction & UPDATE_NIA_FENE)
    {
        if (p_FmPort->portType == e_FM_PORT_TYPE_OH_OFFLINE_PARSING)
            WRITE_UINT32(p_FmPort->port.bmi_regs->oh.fmbm_ofene,
                         p_FmPort->savedBmiFene);
        else
            WRITE_UINT32(p_FmPort->port.bmi_regs->rx.fmbm_rfene,
                         p_FmPort->savedBmiFene);
    }

    if (p_FmPort->requiredAction & UPDATE_NIA_FPNE)
    {
        if (p_FmPort->portType == e_FM_PORT_TYPE_OH_OFFLINE_PARSING)
            WRITE_UINT32(p_FmPort->port.bmi_regs->oh.fmbm_ofpne,
                         p_FmPort->savedBmiFpne);
        else
            WRITE_UINT32(p_FmPort->port.bmi_regs->rx.fmbm_rfpne,
                         p_FmPort->savedBmiFpne);
    }

    if (p_FmPort->requiredAction & UPDATE_OFP_DPTE)
    {
        ASSERT_COND(p_FmPort->portType == e_FM_PORT_TYPE_OH_OFFLINE_PARSING);

        WRITE_UINT32(p_FmPort->port.bmi_regs->oh.fmbm_ofp,
                     p_FmPort->savedBmiOfp);
    }

    WRITE_UINT32(*p_BmiNia, p_FmPort->savedBmiNia);

    if (p_FmPort->requiredAction & UPDATE_NIA_PNDN)
    {
        p_FmPort->origNonRxQmiRegsPndn =
                GET_UINT32(p_FmPort->port.qmi_regs->fmqm_pndn);
        WRITE_UINT32(p_FmPort->port.qmi_regs->fmqm_pndn,
                     p_FmPort->savedNonRxQmiRegsPndn);
    }

    return E_OK;
}

/* The first half of a detach: new frames go straight to the port's default
 * queue rather than to its PCD. */
static void DetachPCDEntry(t_FmPort *p_FmPort)
{
    volatile uint32_t *p_BmiNia = NULL;

    ASSERT_COND(p_FmPort);

    /* get PCD registers pointers */
    if (p_FmPort->requiredAction & UPDATE_NIA_PNDN)
        WRITE_UINT32(p_FmPort->port.qmi_regs->fmqm_pndn,
                     p_FmPort->origNonRxQmiRegsPndn);

    if (p_FmPort->portType == e_FM_PORT_TYPE_OH_OFFLINE_PARSING)
        p_BmiNia = &p_FmPort->port.bmi_regs->oh.fmbm_ofne;
    else
        p_BmiNia = &p_FmPort->port.bmi_regs->rx.fmbm_rfne;

    WRITE_UINT32(
            *p_BmiNia,
            (p_FmPort->savedBmiNia & BMI_RFNE_FDCS_MASK) | GET_NO_PCD_NIA_BMI_AC_ENQ_FRAME());
}

/* The second half: what a frame does once the PCD would have handed it back,
 * which frames the PCD already had still need until they are done. */
static t_Error DetachPCDActions(t_FmPort *p_FmPort)
{
    if (p_FmPort->requiredAction & UPDATE_NIA_FENE)
    {
        if (p_FmPort->portType == e_FM_PORT_TYPE_OH_OFFLINE_PARSING)
            WRITE_UINT32(p_FmPort->port.bmi_regs->oh.fmbm_ofene,
                         NIA_ENG_QMI_ENQ | NIA_ORDER_RESTOR);
        else
            WRITE_UINT32(p_FmPort->port.bmi_regs->rx.fmbm_rfene,
                         NIA_ENG_QMI_ENQ | NIA_ORDER_RESTOR);
    }

    if (p_FmPort->requiredAction & UPDATE_NIA_PNEN)
        WRITE_UINT32(p_FmPort->port.qmi_regs->fmqm_pnen,
                     NIA_ENG_BMI | NIA_BMI_AC_RELEASE);

    if (p_FmPort->requiredAction & UPDATE_FMFP_PRC_WITH_ONE_RISC_ONLY)
        if (FmSetNumOfRiscsPerPort(p_FmPort->h_Fm, p_FmPort->hardwarePortId, 2,
                                   p_FmPort->orFmanCtrl) != E_OK)
            RETURN_ERROR(MAJOR, E_INVALID_STATE, NO_MSG);

    return E_OK;
}

static t_Error DetachPCD(t_FmPort *p_FmPort)
{
    t_Error err;

    DetachPCDEntry(p_FmPort);

    if (FmPcdIsHcUsageAllowed(p_FmPort->h_FmPcd))
    {
        err = FmPcdHcSync(p_FmPort->h_FmPcd);
        if (err)
            return err;
    }

    err = DetachPCDActions(p_FmPort);
    if (err)
        return err;

    p_FmPort->requiredAction = 0;
    p_FmPort->pcdBypassed = FALSE;

    return E_OK;
}

uint8_t FmPortGetHardwarePortId(t_Handle h_FmPort)
{
    return ((t_FmPort*)h_FmPort)->hardwarePortId;
}

t_Error FmPortSetGprFunc(t_Handle h_FmPort, e_FmPortGprFuncType gprFunc,
                         void **p_Value)
{
    t_FmPort *p_FmPort = (t_FmPort*)h_FmPort;
    uint32_t muramPageOffset;

    ASSERT_COND(p_FmPort);
    ASSERT_COND(p_Value);

    if (p_FmPort->gprFunc != e_FM_PORT_GPR_EMPTY)
    {
        if (p_FmPort->gprFunc != gprFunc)
            RETURN_ERROR(MAJOR, E_INVALID_STATE,
                         ("gpr was assigned with different func"));
    }
    else
    {
        switch (gprFunc)
        {
            case (e_FM_PORT_GPR_MURAM_PAGE):
                p_FmPort->p_ParamsPage = FM_MURAM_AllocMem(p_FmPort->h_FmMuram,
                                                           256, 8);
                if (!p_FmPort->p_ParamsPage)
                    RETURN_ERROR(MAJOR, E_NO_MEMORY, ("MURAM alloc for page"));

                IOMemSet32(p_FmPort->p_ParamsPage, 0, 256);
                muramPageOffset =
                        (uint32_t)(XX_VirtToPhys(p_FmPort->p_ParamsPage)
                                - p_FmPort->fmMuramPhysBaseAddr);
                switch (p_FmPort->portType)
                {
                    case (e_FM_PORT_TYPE_RX_10G):
                    case (e_FM_PORT_TYPE_RX):
                        WRITE_UINT32(
                                p_FmPort->p_FmPortBmiRegs->rxPortBmiRegs.fmbm_rgpr,
                                muramPageOffset);
                        break;
                    case (e_FM_PORT_TYPE_OH_OFFLINE_PARSING):
                        WRITE_UINT32(
                                p_FmPort->p_FmPortBmiRegs->ohPortBmiRegs.fmbm_ogpr,
                                muramPageOffset);
                        break;
                    default:
                        RETURN_ERROR(MAJOR, E_INVALID_STATE,
                                     ("Invalid port type"));
                }
                break;
            default:
                RETURN_ERROR(MAJOR, E_INVALID_SELECTION, NO_MSG);
        }
        p_FmPort->gprFunc = gprFunc;
    }

    switch (p_FmPort->gprFunc)
    {
        case (e_FM_PORT_GPR_MURAM_PAGE):
            *p_Value = p_FmPort->p_ParamsPage;
            break;
        default:
            RETURN_ERROR(MAJOR, E_INVALID_SELECTION, NO_MSG);
    }

    return E_OK;
}

t_Error FmPortGetSetCcParams(t_Handle h_FmPort,
                             t_FmPortGetSetCcParams *p_CcParams)
{
    t_FmPort *p_FmPort = (t_FmPort*)h_FmPort;
    int tmpInt;
    volatile uint32_t *p_BmiPrsStartOffset = NULL;

    /* this function called from Cc for pass and receive parameters port params between CC and PORT*/

    if ((p_CcParams->getCcParams.type & OFFSET_OF_PR)
            && (p_FmPort->bufferOffsets.prsResultOffset != ILLEGAL_BASE))
    {
        p_CcParams->getCcParams.prOffset =
                (uint8_t)p_FmPort->bufferOffsets.prsResultOffset;
        p_CcParams->getCcParams.type &= ~OFFSET_OF_PR;
    }
    if (p_CcParams->getCcParams.type & HW_PORT_ID)
    {
        p_CcParams->getCcParams.hardwarePortId =
                (uint8_t)p_FmPort->hardwarePortId;
        p_CcParams->getCcParams.type &= ~HW_PORT_ID;
    }
    if ((p_CcParams->getCcParams.type & OFFSET_OF_DATA)
            && (p_FmPort->bufferOffsets.dataOffset != ILLEGAL_BASE))
    {
        p_CcParams->getCcParams.dataOffset =
                (uint16_t)p_FmPort->bufferOffsets.dataOffset;
        p_CcParams->getCcParams.type &= ~OFFSET_OF_DATA;
    }
    if (p_CcParams->getCcParams.type & NUM_OF_TASKS)
    {
        p_CcParams->getCcParams.numOfTasks = (uint8_t)p_FmPort->tasks.num;
        p_CcParams->getCcParams.type &= ~NUM_OF_TASKS;
    }
    if (p_CcParams->getCcParams.type & NUM_OF_EXTRA_TASKS)
    {
        p_CcParams->getCcParams.numOfExtraTasks =
                (uint8_t)p_FmPort->tasks.extra;
        p_CcParams->getCcParams.type &= ~NUM_OF_EXTRA_TASKS;
    }
    if (p_CcParams->getCcParams.type & FM_REV)
    {
        p_CcParams->getCcParams.revInfo.majorRev = p_FmPort->fmRevInfo.majorRev;
        p_CcParams->getCcParams.revInfo.minorRev = p_FmPort->fmRevInfo.minorRev;
        p_CcParams->getCcParams.type &= ~FM_REV;
    }
    if (p_CcParams->getCcParams.type & DISCARD_MASK)
    {
        if (p_FmPort->portType == e_FM_PORT_TYPE_OH_OFFLINE_PARSING)
            p_CcParams->getCcParams.discardMask =
                    GET_UINT32(p_FmPort->p_FmPortBmiRegs->ohPortBmiRegs.fmbm_ofsdm);
        else
            p_CcParams->getCcParams.discardMask =
                    GET_UINT32(p_FmPort->p_FmPortBmiRegs->rxPortBmiRegs.fmbm_rfsdm);
        p_CcParams->getCcParams.type &= ~DISCARD_MASK;
    }
    if (p_CcParams->getCcParams.type & MANIP_EXTRA_SPACE)
    {
        p_CcParams->getCcParams.internalBufferOffset =
                p_FmPort->internalBufferOffset;
        p_CcParams->getCcParams.type &= ~MANIP_EXTRA_SPACE;
    }
    if (p_CcParams->getCcParams.type & GET_NIA_FPNE)
    {
        if (p_FmPort->portType == e_FM_PORT_TYPE_OH_OFFLINE_PARSING)
            p_CcParams->getCcParams.nia =
                    GET_UINT32(p_FmPort->port.bmi_regs->oh.fmbm_ofpne);
        else
            p_CcParams->getCcParams.nia =
                    GET_UINT32(p_FmPort->port.bmi_regs->rx.fmbm_rfpne);
        p_CcParams->getCcParams.type &= ~GET_NIA_FPNE;
    }
    if (p_CcParams->getCcParams.type & GET_NIA_PNDN)
    {
        if (p_FmPort->portType != e_FM_PORT_TYPE_OH_OFFLINE_PARSING)
            RETURN_ERROR(MAJOR, E_INVALID_STATE, ("Invalid port type"));
        p_CcParams->getCcParams.nia =
                GET_UINT32(p_FmPort->p_FmPortQmiRegs->nonRxQmiRegs.fmqm_pndn);
        p_CcParams->getCcParams.type &= ~GET_NIA_PNDN;
    }

    if ((p_CcParams->setCcParams.type & UPDATE_FMFP_PRC_WITH_ONE_RISC_ONLY)
            && !(p_FmPort->requiredAction & UPDATE_FMFP_PRC_WITH_ONE_RISC_ONLY))
    {
        p_FmPort->requiredAction |= UPDATE_FMFP_PRC_WITH_ONE_RISC_ONLY;
        p_FmPort->orFmanCtrl = p_CcParams->setCcParams.orFmanCtrl;
    }

    if ((p_CcParams->setCcParams.type & UPDATE_NIA_PNEN)
            && !(p_FmPort->requiredAction & UPDATE_NIA_PNEN))
    {
        p_FmPort->savedQmiPnen = p_CcParams->setCcParams.nia;
        p_FmPort->requiredAction |= UPDATE_NIA_PNEN;
    }
    else
        if (p_CcParams->setCcParams.type & UPDATE_NIA_PNEN)
        {
            if (p_FmPort->savedQmiPnen != p_CcParams->setCcParams.nia)
                RETURN_ERROR(MAJOR, E_INVALID_STATE,
                             ("PNEN was defined previously different"));
        }

    if ((p_CcParams->setCcParams.type & UPDATE_NIA_PNDN)
            && !(p_FmPort->requiredAction & UPDATE_NIA_PNDN))
    {
        p_FmPort->savedNonRxQmiRegsPndn = p_CcParams->setCcParams.nia;
        p_FmPort->requiredAction |= UPDATE_NIA_PNDN;
    }
    else
        if (p_CcParams->setCcParams.type & UPDATE_NIA_PNDN)
        {
            if (p_FmPort->savedNonRxQmiRegsPndn != p_CcParams->setCcParams.nia)
                RETURN_ERROR(MAJOR, E_INVALID_STATE,
                             ("PNDN was defined previously different"));
        }

    if ((p_CcParams->setCcParams.type & UPDATE_NIA_FENE)
            && (p_CcParams->setCcParams.overwrite
                    || !(p_FmPort->requiredAction & UPDATE_NIA_FENE)))
    {
        p_FmPort->savedBmiFene = p_CcParams->setCcParams.nia;
        p_FmPort->requiredAction |= UPDATE_NIA_FENE;
    }
    else
        if (p_CcParams->setCcParams.type & UPDATE_NIA_FENE)
        {
            if (p_FmPort->savedBmiFene != p_CcParams->setCcParams.nia)
                RETURN_ERROR( MAJOR, E_INVALID_STATE,
                             ("xFENE was defined previously different"));
        }

    if ((p_CcParams->setCcParams.type & UPDATE_NIA_FPNE)
            && !(p_FmPort->requiredAction & UPDATE_NIA_FPNE))
    {
        p_FmPort->savedBmiFpne = p_CcParams->setCcParams.nia;
        p_FmPort->requiredAction |= UPDATE_NIA_FPNE;
    }
    else
        if (p_CcParams->setCcParams.type & UPDATE_NIA_FPNE)
        {
            if (p_FmPort->savedBmiFpne != p_CcParams->setCcParams.nia)
                RETURN_ERROR( MAJOR, E_INVALID_STATE,
                             ("xFPNE was defined previously different"));
        }

    if ((p_CcParams->setCcParams.type & UPDATE_NIA_CMNE)
            && !(p_FmPort->requiredAction & UPDATE_NIA_CMNE))
    {
        p_FmPort->savedBmiCmne = p_CcParams->setCcParams.nia;
        p_FmPort->requiredAction |= UPDATE_NIA_CMNE;
    }
    else
        if (p_CcParams->setCcParams.type & UPDATE_NIA_CMNE)
        {
            if (p_FmPort->savedBmiCmne != p_CcParams->setCcParams.nia)
                RETURN_ERROR( MAJOR, E_INVALID_STATE,
                             ("xCMNE was defined previously different"));
        }

    if ((p_CcParams->setCcParams.type & UPDATE_PSO)
            && !(p_FmPort->requiredAction & UPDATE_PSO))
    {
        /* get PCD registers pointers */
        switch (p_FmPort->portType)
        {
            case (e_FM_PORT_TYPE_RX_10G):
            case (e_FM_PORT_TYPE_RX):
                p_BmiPrsStartOffset = &p_FmPort->port.bmi_regs->rx.fmbm_rpso;
                break;
            case (e_FM_PORT_TYPE_OH_OFFLINE_PARSING):
                p_BmiPrsStartOffset = &p_FmPort->port.bmi_regs->oh.fmbm_opso;
                break;
            default:
                RETURN_ERROR(MAJOR, E_INVALID_STATE, ("Invalid port type"));
        }

        /* set start parsing offset */
        tmpInt = (int)GET_UINT32(*p_BmiPrsStartOffset)
                + p_CcParams->setCcParams.psoSize;
        if (tmpInt > 0)
            WRITE_UINT32(*p_BmiPrsStartOffset, (uint32_t)tmpInt);

        p_FmPort->requiredAction |= UPDATE_PSO;
        p_FmPort->savedPrsStartOffset = p_CcParams->setCcParams.psoSize;
    }
    else
        if (p_CcParams->setCcParams.type & UPDATE_PSO)
        {
            if (p_FmPort->savedPrsStartOffset
                    != p_CcParams->setCcParams.psoSize)
                RETURN_ERROR(
                        MAJOR,
                        E_INVALID_STATE,
                        ("parser start offset was defoned previousley different"));
        }

    if ((p_CcParams->setCcParams.type & UPDATE_OFP_DPTE)
            && !(p_FmPort->requiredAction & UPDATE_OFP_DPTE))
    {
        if (p_FmPort->portType != e_FM_PORT_TYPE_OH_OFFLINE_PARSING)
            RETURN_ERROR(MAJOR, E_INVALID_STATE, ("Invalid port type"));
        p_FmPort->savedBmiOfp = GET_UINT32(p_FmPort->port.bmi_regs->oh.fmbm_ofp);
        p_FmPort->savedBmiOfp &= ~BMI_FIFO_PIPELINE_DEPTH_MASK;
        p_FmPort->savedBmiOfp |= p_CcParams->setCcParams.ofpDpde
                << BMI_FIFO_PIPELINE_DEPTH_SHIFT;
        p_FmPort->requiredAction |= UPDATE_OFP_DPTE;
    }

    return E_OK;
}

/*********************** End of inter-module routines ************************/

/****************************************/
/*       API Init unit functions        */
/****************************************/

t_Handle FM_PORT_Config(t_FmPortParams *p_FmPortParams)
{
    t_FmPort *p_FmPort;
    uintptr_t baseAddr = p_FmPortParams->baseAddr;
    uint32_t tmpReg;

    /* Allocate FM structure */
    p_FmPort = (t_FmPort *)XX_Malloc(sizeof(t_FmPort));
    if (!p_FmPort)
    {
        REPORT_ERROR(MAJOR, E_NO_MEMORY, ("FM Port driver structure"));
        return NULL;
    }
    memset(p_FmPort, 0, sizeof(t_FmPort));

    /* Allocate the FM driver's parameters structure */
    p_FmPort->p_FmPortDriverParam = (t_FmPortDriverParam *)XX_Malloc(
            sizeof(t_FmPortDriverParam));
    if (!p_FmPort->p_FmPortDriverParam)
    {
        XX_Free(p_FmPort);
        REPORT_ERROR(MAJOR, E_NO_MEMORY, ("FM Port driver parameters"));
        return NULL;
    }
    memset(p_FmPort->p_FmPortDriverParam, 0, sizeof(t_FmPortDriverParam));

    /* Initialize FM port parameters which will be kept by the driver */
    p_FmPort->portType = p_FmPortParams->portType;
    p_FmPort->portId = p_FmPortParams->portId;
    p_FmPort->pcdEngines = FM_PCD_NONE;
    p_FmPort->f_Exception = p_FmPortParams->f_Exception;
    p_FmPort->h_App = p_FmPortParams->h_App;
    p_FmPort->h_Fm = p_FmPortParams->h_Fm;

    /* get FM revision */
    FM_GetRevision(p_FmPort->h_Fm, &p_FmPort->fmRevInfo);

    /* calculate global portId number */
    p_FmPort->hardwarePortId = SwPortIdToHwPortId(p_FmPort->portType,
                                    p_FmPortParams->portId,
                                    p_FmPort->fmRevInfo.majorRev,
                                    p_FmPort->fmRevInfo.minorRev);

    if (p_FmPort->fmRevInfo.majorRev >= 6)
    {
        if ((p_FmPort->portType == e_FM_PORT_TYPE_OH_HOST_COMMAND)
                && (p_FmPortParams->portId != FM_OH_PORT_ID))
            DBG(WARNING,
                    ("Port ID %d is recommended for HC port. Overwriting HW defaults to be suitable for HC.",
                            FM_OH_PORT_ID));

        if ((p_FmPort->portType == e_FM_PORT_TYPE_OH_OFFLINE_PARSING)
                && (p_FmPortParams->portId == FM_OH_PORT_ID))
            DBG(WARNING, ("Use non-zero portId for OP port due to insufficient resources on portId 0."));
    }

    /* Set up FM port parameters for initialization phase only */

    /* First, fill in flibs struct */
    fman_port_defconfig(&p_FmPort->p_FmPortDriverParam->dfltCfg,
                        (enum fman_port_type)p_FmPort->portType);
    /* Overwrite some integration specific parameters */
    p_FmPort->p_FmPortDriverParam->dfltCfg.rx_pri_elevation =
            DEFAULT_PORT_rxFifoPriElevationLevel;
    p_FmPort->p_FmPortDriverParam->dfltCfg.rx_fifo_thr =
            DEFAULT_PORT_rxFifoThreshold;

    p_FmPort->p_FmPortDriverParam->dfltCfg.errata_A006675 = TRUE;
    if ((p_FmPort->fmRevInfo.majorRev == 6)
            && (p_FmPort->fmRevInfo.minorRev == 0))
        p_FmPort->p_FmPortDriverParam->dfltCfg.errata_A006320 = TRUE;
    else
        p_FmPort->p_FmPortDriverParam->dfltCfg.errata_A006320 = FALSE;

    /* Excessive Threshold register - exists for pre-FMv3 chips only */
    if (p_FmPort->fmRevInfo.majorRev < 6)
    {
        p_FmPort->p_FmPortDriverParam->dfltCfg.excessive_threshold_register =
                TRUE;
        p_FmPort->p_FmPortDriverParam->dfltCfg.fmbm_rebm_has_sgd = FALSE;
        p_FmPort->p_FmPortDriverParam->dfltCfg.fmbm_tfne_has_features = FALSE;
    }
    else
    {
        p_FmPort->p_FmPortDriverParam->dfltCfg.excessive_threshold_register =
                FALSE;
        p_FmPort->p_FmPortDriverParam->dfltCfg.fmbm_rebm_has_sgd = TRUE;
        p_FmPort->p_FmPortDriverParam->dfltCfg.fmbm_tfne_has_features = TRUE;
    }
    if (p_FmPort->fmRevInfo.majorRev == 4)
        p_FmPort->p_FmPortDriverParam->dfltCfg.qmi_deq_options_support = FALSE;
    else
        p_FmPort->p_FmPortDriverParam->dfltCfg.qmi_deq_options_support = TRUE;

    /* Continue with other parameters */
    p_FmPort->p_FmPortDriverParam->baseAddr = baseAddr;
    /* set memory map pointers */
    p_FmPort->p_FmPortQmiRegs =
            (t_FmPortQmiRegs *)UINT_TO_PTR(baseAddr + QMI_PORT_REGS_OFFSET);
    p_FmPort->p_FmPortBmiRegs =
            (u_FmPortBmiRegs *)UINT_TO_PTR(baseAddr + BMI_PORT_REGS_OFFSET);
    p_FmPort->p_FmPortPrsRegs =
            (t_FmPortPrsRegs *)UINT_TO_PTR(baseAddr + PRS_PORT_REGS_OFFSET);

    p_FmPort->p_FmPortDriverParam->bufferPrefixContent.privDataSize =
            DEFAULT_PORT_bufferPrefixContent_privDataSize;
    p_FmPort->p_FmPortDriverParam->bufferPrefixContent.passPrsResult =
            DEFAULT_PORT_bufferPrefixContent_passPrsResult;
    p_FmPort->p_FmPortDriverParam->bufferPrefixContent.passTimeStamp =
            DEFAULT_PORT_bufferPrefixContent_passTimeStamp;
    p_FmPort->p_FmPortDriverParam->bufferPrefixContent.passAllOtherPCDInfo =
            DEFAULT_PORT_bufferPrefixContent_passTimeStamp;
    p_FmPort->p_FmPortDriverParam->bufferPrefixContent.dataAlign =
            DEFAULT_PORT_bufferPrefixContent_dataAlign;
    /*    p_FmPort->p_FmPortDriverParam->dmaSwapData                      = (e_FmDmaSwapOption)DEFAULT_PORT_dmaSwapData;
     p_FmPort->p_FmPortDriverParam->dmaIntContextCacheAttr           = (e_FmDmaCacheOption)DEFAULT_PORT_dmaIntContextCacheAttr;
     p_FmPort->p_FmPortDriverParam->dmaHeaderCacheAttr               = (e_FmDmaCacheOption)DEFAULT_PORT_dmaHeaderCacheAttr;
     p_FmPort->p_FmPortDriverParam->dmaScatterGatherCacheAttr        = (e_FmDmaCacheOption)DEFAULT_PORT_dmaScatterGatherCacheAttr;
     p_FmPort->p_FmPortDriverParam->dmaWriteOptimize                 = DEFAULT_PORT_dmaWriteOptimize;
     */
    p_FmPort->p_FmPortDriverParam->liodnBase = p_FmPortParams->liodnBase;
    p_FmPort->p_FmPortDriverParam->cheksumLastBytesIgnore =
            DEFAULT_PORT_cheksumLastBytesIgnore;

    p_FmPort->maxFrameLength = DEFAULT_PORT_maxFrameLength;
    /* resource distribution. */
	p_FmPort->fifoBufs.num = DEFAULT_PORT_numOfFifoBufs(p_FmPort->portType)
			* BMI_FIFO_UNITS;
	p_FmPort->fifoBufs.extra = DEFAULT_PORT_extraNumOfFifoBufs
			* BMI_FIFO_UNITS;
	p_FmPort->openDmas.num = DEFAULT_PORT_numOfOpenDmas(p_FmPort->portType);
	p_FmPort->openDmas.extra =
			DEFAULT_PORT_extraNumOfOpenDmas(p_FmPort->portType);
	p_FmPort->tasks.num = DEFAULT_PORT_numOfTasks(p_FmPort->portType);
	p_FmPort->tasks.extra = DEFAULT_PORT_extraNumOfTasks(p_FmPort->portType);


    if ((p_FmPort->fmRevInfo.majorRev == 6)
            && (p_FmPort->fmRevInfo.minorRev == 0)
            && ((p_FmPort->portType == e_FM_PORT_TYPE_OH_OFFLINE_PARSING)
                    || (p_FmPort->portType == e_FM_PORT_TYPE_TX)))
    {
        p_FmPort->openDmas.num = 16;
        p_FmPort->openDmas.extra = 0;
    }

    /* Port type specific initialization: */
    switch (p_FmPort->portType)
    {
        case (e_FM_PORT_TYPE_RX):
        case (e_FM_PORT_TYPE_RX_10G):
            /* Initialize FM port parameters for initialization phase only */
            p_FmPort->p_FmPortDriverParam->cutBytesFromEnd =
                    DEFAULT_PORT_cutBytesFromEnd;
            p_FmPort->p_FmPortDriverParam->enBufPoolDepletion = FALSE;
            p_FmPort->p_FmPortDriverParam->frmDiscardOverride =
                    DEFAULT_PORT_frmDiscardOverride;

                tmpReg =
                        GET_UINT32(p_FmPort->p_FmPortBmiRegs->rxPortBmiRegs.fmbm_rfp);
			p_FmPort->p_FmPortDriverParam->rxFifoPriElevationLevel =
                        (((tmpReg & BMI_RX_FIFO_PRI_ELEVATION_MASK)
                                >> BMI_RX_FIFO_PRI_ELEVATION_SHIFT) + 1)
                                * BMI_FIFO_UNITS;
                p_FmPort->p_FmPortDriverParam->rxFifoThreshold = (((tmpReg
                        & BMI_RX_FIFO_THRESHOLD_MASK)
                        >> BMI_RX_FIFO_THRESHOLD_SHIFT) + 1) * BMI_FIFO_UNITS;

            p_FmPort->p_FmPortDriverParam->bufMargins.endMargins =
                    DEFAULT_PORT_BufMargins_endMargins;
            p_FmPort->p_FmPortDriverParam->errorsToDiscard =
                    DEFAULT_PORT_errorsToDiscard;
            p_FmPort->p_FmPortDriverParam->forwardReuseIntContext =
                    DEFAULT_PORT_forwardIntContextReuse;
            p_FmPort->p_FmPortDriverParam->noScatherGather =
                    DEFAULT_PORT_noScatherGather;
            break;

        case (e_FM_PORT_TYPE_TX):
            p_FmPort->p_FmPortDriverParam->dontReleaseBuf = FALSE;
            tmpReg = 0x00001013;
            WRITE_UINT32( p_FmPort->p_FmPortBmiRegs->txPortBmiRegs.fmbm_tfp,
                         tmpReg);

            fallthrough;
        case (e_FM_PORT_TYPE_TX_10G):
                tmpReg =
                        GET_UINT32(p_FmPort->p_FmPortBmiRegs->txPortBmiRegs.fmbm_tfp);
                p_FmPort->p_FmPortDriverParam->txFifoMinFillLevel = ((tmpReg
                        & BMI_TX_FIFO_MIN_FILL_MASK)
                        >> BMI_TX_FIFO_MIN_FILL_SHIFT) * BMI_FIFO_UNITS;
			p_FmPort->p_FmPortDriverParam->dfltCfg.tx_fifo_deq_pipeline_depth =
                        (uint8_t)(((tmpReg & BMI_FIFO_PIPELINE_DEPTH_MASK)
                                >> BMI_FIFO_PIPELINE_DEPTH_SHIFT) + 1);
                p_FmPort->p_FmPortDriverParam->txFifoLowComfLevel = (((tmpReg
                        & BMI_TX_LOW_COMF_MASK) >> BMI_TX_LOW_COMF_SHIFT) + 1)
                        * BMI_FIFO_UNITS;

            p_FmPort->p_FmPortDriverParam->deqType = DEFAULT_PORT_deqType;
            p_FmPort->p_FmPortDriverParam->deqPrefetchOption =
                    DEFAULT_PORT_deqPrefetchOption;
            p_FmPort->p_FmPortDriverParam->deqHighPriority =
                    (bool)((p_FmPort->portType == e_FM_PORT_TYPE_TX) ? DEFAULT_PORT_deqHighPriority_1G :
                            DEFAULT_PORT_deqHighPriority_10G);
            p_FmPort->p_FmPortDriverParam->deqByteCnt =
                    (uint16_t)(
                            (p_FmPort->portType == e_FM_PORT_TYPE_TX) ? DEFAULT_PORT_deqByteCnt_1G :
                                    DEFAULT_PORT_deqByteCnt_10G);
            break;
        case (e_FM_PORT_TYPE_OH_OFFLINE_PARSING):
            p_FmPort->p_FmPortDriverParam->errorsToDiscard =
                    DEFAULT_PORT_errorsToDiscard;
            p_FmPort->p_FmPortDriverParam->noScatherGather =
                    DEFAULT_PORT_noScatherGather;
            fallthrough;
        case (e_FM_PORT_TYPE_OH_HOST_COMMAND):
            p_FmPort->p_FmPortDriverParam->deqPrefetchOption =
                    DEFAULT_PORT_deqPrefetchOption_HC;
            p_FmPort->p_FmPortDriverParam->deqHighPriority =
                    DEFAULT_PORT_deqHighPriority_1G;
            p_FmPort->p_FmPortDriverParam->deqType = DEFAULT_PORT_deqType;
            p_FmPort->p_FmPortDriverParam->deqByteCnt =
                    DEFAULT_PORT_deqByteCnt_1G;

                tmpReg =
                        GET_UINT32(p_FmPort->p_FmPortBmiRegs->ohPortBmiRegs.fmbm_ofp);
                p_FmPort->p_FmPortDriverParam->dfltCfg.tx_fifo_deq_pipeline_depth =
                        (uint8_t)(((tmpReg & BMI_FIFO_PIPELINE_DEPTH_MASK)
                                >> BMI_FIFO_PIPELINE_DEPTH_SHIFT) + 1);
                if ((p_FmPort->portType == e_FM_PORT_TYPE_OH_HOST_COMMAND)
                        && (p_FmPortParams->portId != FM_OH_PORT_ID))
                {
                    /* Overwrite HC defaults */
			p_FmPort->p_FmPortDriverParam->dfltCfg.tx_fifo_deq_pipeline_depth =
					DEFAULT_PORT_fifoDeqPipelineDepth_OH;
                }


            break;

        default:
            XX_Free(p_FmPort->p_FmPortDriverParam);
            XX_Free(p_FmPort);
            REPORT_ERROR(MAJOR, E_INVALID_STATE, ("Invalid port type"));
            return NULL;
    }

    p_FmPort->imEn = p_FmPortParams->independentModeEnable;

    if (p_FmPort->imEn)
    {
        if ((p_FmPort->portType == e_FM_PORT_TYPE_TX)
                || (p_FmPort->portType == e_FM_PORT_TYPE_TX_10G))
            p_FmPort->p_FmPortDriverParam->dfltCfg.tx_fifo_deq_pipeline_depth =
                    DEFAULT_PORT_fifoDeqPipelineDepth_IM;
        FmPortConfigIM(p_FmPort, p_FmPortParams);
    }
    else
    {
        switch (p_FmPort->portType)
        {
            case (e_FM_PORT_TYPE_RX):
            case (e_FM_PORT_TYPE_RX_10G):
                /* Initialize FM port parameters for initialization phase only */
                memcpy(&p_FmPort->p_FmPortDriverParam->extBufPools,
                       &p_FmPortParams->specificParams.rxParams.extBufPools,
                       sizeof(t_FmExtPools));
                p_FmPort->p_FmPortDriverParam->errFqid =
                        p_FmPortParams->specificParams.rxParams.errFqid;
                p_FmPort->p_FmPortDriverParam->dfltFqid =
                        p_FmPortParams->specificParams.rxParams.dfltFqid;
                p_FmPort->p_FmPortDriverParam->liodnOffset =
                        p_FmPortParams->specificParams.rxParams.liodnOffset;
                break;
            case (e_FM_PORT_TYPE_OH_OFFLINE_PARSING):
            case (e_FM_PORT_TYPE_TX):
            case (e_FM_PORT_TYPE_TX_10G):
            case (e_FM_PORT_TYPE_OH_HOST_COMMAND):
                p_FmPort->p_FmPortDriverParam->errFqid =
                        p_FmPortParams->specificParams.nonRxParams.errFqid;
                p_FmPort->p_FmPortDriverParam->deqSubPortal =
                        (uint8_t)(p_FmPortParams->specificParams.nonRxParams.qmChannel
                                & QMI_DEQ_CFG_SUBPORTAL_MASK);
                p_FmPort->p_FmPortDriverParam->dfltFqid =
                        p_FmPortParams->specificParams.nonRxParams.dfltFqid;
                p_FmPort->p_FmPortDriverParam->liodnOffset =
                        p_FmPortParams->specificParams.nonRxParams.liodnOffset;
                break;
            default:
                XX_Free(p_FmPort->p_FmPortDriverParam);
                XX_Free(p_FmPort);
                REPORT_ERROR(MAJOR, E_INVALID_STATE, ("Invalid port type"));
                return NULL;
        }
    }

    memset(p_FmPort->name, 0, (sizeof(char)) * MODULE_NAME_SIZE);
    if (Sprint(
            p_FmPort->name,
            "FM-%d-port-%s-%d",
            FmGetId(p_FmPort->h_Fm),
            ((p_FmPort->portType == e_FM_PORT_TYPE_OH_OFFLINE_PARSING
                    || (p_FmPort->portType == e_FM_PORT_TYPE_OH_HOST_COMMAND)) ? "OH" :
                    (p_FmPort->portType == e_FM_PORT_TYPE_RX ? "1g-RX" :
                            (p_FmPort->portType == e_FM_PORT_TYPE_TX ? "1g-TX" :
                                    (p_FmPort->portType
                                            == e_FM_PORT_TYPE_RX_10G ? "10g-RX" :
                                            "10g-TX")))),
            p_FmPort->portId) == 0)
    {
        XX_Free(p_FmPort->p_FmPortDriverParam);
        XX_Free(p_FmPort);
        REPORT_ERROR(MAJOR, E_INVALID_STATE, ("Sprint failed"));
        return NULL;
    }

    p_FmPort->h_Spinlock = XX_InitSpinlock();
    if (!p_FmPort->h_Spinlock)
    {
        XX_Free(p_FmPort->p_FmPortDriverParam);
        XX_Free(p_FmPort);
        REPORT_ERROR(MAJOR, E_INVALID_STATE, ("Sprint failed"));
        return NULL;
    }

    return p_FmPort;
}

t_FmPort *rx_port = 0;
t_FmPort *tx_port = 0;

/**************************************************************************//**
 @Function      FM_PORT_Init

 @Description   Initializes the FM module

 @Param[in]     h_FmPort - FM module descriptor

 @Return        E_OK on success; Error code otherwise.
 *//***************************************************************************/
t_Error FM_PORT_Init(t_Handle h_FmPort)
{
    t_FmPort *p_FmPort = (t_FmPort*)h_FmPort;
    t_FmPortDriverParam *p_DriverParams;
    t_Error errCode;
    t_FmInterModulePortInitParams fmParams;
    t_FmRevisionInfo revInfo;

    SANITY_CHECK_RETURN_ERROR(h_FmPort, E_INVALID_HANDLE);
    SANITY_CHECK_RETURN_ERROR(p_FmPort->p_FmPortDriverParam, E_INVALID_HANDLE);
    if (p_FmPort->fmPortParamsAllocated)
        RETURN_ERROR(MAJOR, E_INVALID_STATE,
                     ("Port resources already allocated; free the failed port before retrying."));

    errCode = FmSpBuildBufferStructure(
            &p_FmPort->p_FmPortDriverParam->intContext,
            &p_FmPort->p_FmPortDriverParam->bufferPrefixContent,
            &p_FmPort->p_FmPortDriverParam->bufMargins,
            &p_FmPort->bufferOffsets, &p_FmPort->internalBufferOffset);
    if (errCode != E_OK)
        RETURN_ERROR(MAJOR, errCode, NO_MSG);
    if ((p_FmPort->p_FmPortDriverParam->bcbWorkaround) &&
            (p_FmPort->portType == e_FM_PORT_TYPE_RX))
    {
        p_FmPort->p_FmPortDriverParam->errorsToDiscard |= FM_PORT_FRM_ERR_PHYSICAL;
        if (!p_FmPort->fifoBufs.num)
        p_FmPort->fifoBufs.num = DEFAULT_PORT_numOfFifoBufs(p_FmPort->portType)*BMI_FIFO_UNITS;
        p_FmPort->fifoBufs.num += 4*KILOBYTE;
    }

    CHECK_INIT_PARAMETERS(p_FmPort, CheckInitParameters);

    p_DriverParams = p_FmPort->p_FmPortDriverParam;

    /* Set up flibs port structure */
    memset(&p_FmPort->port, 0, sizeof(struct fman_port));
    p_FmPort->port.type = (enum fman_port_type)p_FmPort->portType;
    FM_GetRevision(p_FmPort->h_Fm, &revInfo);
    p_FmPort->port.fm_rev_maj = revInfo.majorRev;
    p_FmPort->port.fm_rev_min = revInfo.minorRev;
    p_FmPort->port.bmi_regs =
            (union fman_port_bmi_regs *)UINT_TO_PTR(p_DriverParams->baseAddr + BMI_PORT_REGS_OFFSET);
    p_FmPort->port.qmi_regs =
            (struct fman_port_qmi_regs *)UINT_TO_PTR(p_DriverParams->baseAddr + QMI_PORT_REGS_OFFSET);
    p_FmPort->port.ext_pools_num = (uint8_t)((revInfo.majorRev == 4) ? 4 : 8);
    p_FmPort->port.im_en = p_FmPort->imEn;
    p_FmPort->p_FmPortPrsRegs =
            (t_FmPortPrsRegs *)UINT_TO_PTR(p_DriverParams->baseAddr + PRS_PORT_REGS_OFFSET);

    if (((p_FmPort->portType == e_FM_PORT_TYPE_RX_10G)
            || (p_FmPort->portType == e_FM_PORT_TYPE_RX)) && !p_FmPort->imEn)
    {
        /* Call the external Buffer routine which also checks fifo
         size and updates it if necessary */
        /* define external buffer pools and pool depletion*/
        errCode = SetExtBufferPools(p_FmPort);
        if (errCode)
            RETURN_ERROR(MAJOR, errCode, NO_MSG);
        /* check if the largest external buffer pool is large enough */
        if (p_DriverParams->bufMargins.startMargins + MIN_EXT_BUF_SIZE
                + p_DriverParams->bufMargins.endMargins
                > p_FmPort->rxPoolsParams.largestBufSize)
            RETURN_ERROR(
                    MAJOR,
                    E_INVALID_VALUE,
                    ("bufMargins.startMargins (%d) + minimum buf size (64) + bufMargins.endMargins (%d) is larger than maximum external buffer size (%d)", p_DriverParams->bufMargins.startMargins, p_DriverParams->bufMargins.endMargins, p_FmPort->rxPoolsParams.largestBufSize));
    }
    if (p_FmPort->portType == e_FM_PORT_TYPE_OH_OFFLINE_PARSING)
    {
        {
            t_FmRevisionInfo revInfo;

            FM_GetRevision(p_FmPort->h_Fm, &revInfo);
            if ((revInfo.majorRev == 4) && (p_DriverParams->enBufPoolDepletion))
            {
                /* define external buffer pools */
                errCode = SetExtBufferPools(p_FmPort);
                if (errCode)
                    RETURN_ERROR(MAJOR, errCode, NO_MSG);
            }
        }
    }

    /************************************************************/
    /* Call FM module routine for communicating parameters      */
    /************************************************************/
    memset(&fmParams, 0, sizeof(fmParams));
    fmParams.hardwarePortId = p_FmPort->hardwarePortId;
    fmParams.portType = (e_FmPortType)p_FmPort->portType;
    fmParams.numOfTasks = (uint8_t)p_FmPort->tasks.num;
    fmParams.numOfExtraTasks = (uint8_t)p_FmPort->tasks.extra;
    fmParams.numOfOpenDmas = (uint8_t)p_FmPort->openDmas.num;
    fmParams.numOfExtraOpenDmas = (uint8_t)p_FmPort->openDmas.extra;

    if (p_FmPort->fifoBufs.num)
    {
        errCode = VerifySizeOfFifo(p_FmPort);
        if (errCode != E_OK)
            RETURN_ERROR(MAJOR, errCode, NO_MSG);
    }
    fmParams.sizeOfFifo = p_FmPort->fifoBufs.num;
    fmParams.extraSizeOfFifo = p_FmPort->fifoBufs.extra;
    fmParams.independentMode = p_FmPort->imEn;
    fmParams.liodnOffset = p_DriverParams->liodnOffset;
    fmParams.liodnBase = p_DriverParams->liodnBase;
    fmParams.deqPipelineDepth =
            p_FmPort->p_FmPortDriverParam->dfltCfg.tx_fifo_deq_pipeline_depth;
    fmParams.maxFrameLength = p_FmPort->maxFrameLength;

    errCode = FmGetSetPortParams(p_FmPort->h_Fm, &fmParams);
    if (errCode)
        RETURN_ERROR(MAJOR, errCode, NO_MSG);

    /* Keep the charged depth, including the revision override, after the
     * initialization parameters are freed or low-level initialization fails. */
    p_FmPort->deqPipelineDepth = fmParams.deqPipelineDepth;
    p_FmPort->fmPortParamsAllocated = TRUE;

    /* get params for use in init */
    p_FmPort->fmMuramPhysBaseAddr =
            (uint64_t)((uint64_t)(fmParams.fmMuramPhysBaseAddr.low)
                    | ((uint64_t)(fmParams.fmMuramPhysBaseAddr.high) << 32));
    p_FmPort->h_FmMuram = FmGetMuramHandle(p_FmPort->h_Fm);

    errCode = InitLowLevelDriver(p_FmPort);
    if (errCode != E_OK)
        RETURN_ERROR(MAJOR, errCode, NO_MSG);

    FmPortDriverParamFree(p_FmPort);

    if ((p_FmPort->portType == e_FM_PORT_TYPE_RX_10G)
            || (p_FmPort->portType == e_FM_PORT_TYPE_RX)
            || (p_FmPort->portType == e_FM_PORT_TYPE_OH_OFFLINE_PARSING))
    {
        t_FmPcdCtrlParamsPage *p_ParamsPage;

        FmPortSetGprFunc(p_FmPort, e_FM_PORT_GPR_MURAM_PAGE,
                         (void**)&p_ParamsPage);
        ASSERT_COND(p_ParamsPage);

        WRITE_UINT32(p_ParamsPage->misc, FM_CTL_PARAMS_PAGE_ALWAYS_ON);
        if (p_FmPort->portType == e_FM_PORT_TYPE_OH_OFFLINE_PARSING)
        {
            WRITE_UINT32(
                    p_ParamsPage->misc,
                    (GET_UINT32(p_ParamsPage->misc) | FM_CTL_PARAMS_PAGE_OP_FIX_EN));
            WRITE_UINT32(
                    p_ParamsPage->discardMask,
                    GET_UINT32(p_FmPort->p_FmPortBmiRegs->ohPortBmiRegs.fmbm_ofsdm));
        }
        if (p_FmPort->portType == e_FM_PORT_TYPE_OH_OFFLINE_PARSING)
            WRITE_UINT32(
                    p_ParamsPage->errorsDiscardMask,
                    (GET_UINT32(p_FmPort->p_FmPortBmiRegs->ohPortBmiRegs.fmbm_ofsdm) | GET_UINT32(p_FmPort->p_FmPortBmiRegs->ohPortBmiRegs.fmbm_ofsem)));
        else
            WRITE_UINT32(
                    p_ParamsPage->errorsDiscardMask,
                    (GET_UINT32(p_FmPort->p_FmPortBmiRegs->rxPortBmiRegs.fmbm_rfsdm) | GET_UINT32(p_FmPort->p_FmPortBmiRegs->rxPortBmiRegs.fmbm_rfsem)));
    }

    return E_OK;
}

/**************************************************************************//**
 @Function      FM_PORT_Free

 @Description   Frees all resources that were assigned to FM module.

 Calling this routine invalidates the descriptor.

 @Param[in]     h_FmPort - FM module descriptor

 @Return        E_OK on success; Error code otherwise.
 *//***************************************************************************/
t_Error FM_PORT_Free(t_Handle h_FmPort)
{
    t_FmPort *p_FmPort = (t_FmPort*)h_FmPort;
    t_FmInterModulePortFreeParams fmParams;

    SANITY_CHECK_RETURN_ERROR(p_FmPort, E_INVALID_HANDLE);

    if (p_FmPort->pcdEngines || p_FmPort->pcdNetEnvOwner)
        RETURN_ERROR(
                MAJOR,
                E_INVALID_STATE,
                ("Trying to free a port with PCD. FM_PORT_DeletePCD must be called first."));

    if (p_FmPort->enabled)
    {
        if (FM_PORT_Disable(p_FmPort) != E_OK)
            RETURN_ERROR(MAJOR, E_INVALID_STATE, ("FM_PORT_Disable FAILED"));
    }

    if (p_FmPort->imEn)
        FmPortImFree(p_FmPort);

    FmPortDriverParamFree(p_FmPort);

    if (p_FmPort->fmPortParamsAllocated)
    {
        memset(&fmParams, 0, sizeof(fmParams));
        fmParams.hardwarePortId = p_FmPort->hardwarePortId;
        fmParams.portType = (e_FmPortType)p_FmPort->portType;
        fmParams.deqPipelineDepth = p_FmPort->deqPipelineDepth;

        FmFreePortParams(p_FmPort->h_Fm, &fmParams);
        p_FmPort->fmPortParamsAllocated = FALSE;
    }

    if (FmVSPFreeForPort(p_FmPort->h_Fm, p_FmPort->portType, p_FmPort->portId)
            != E_OK)
        RETURN_ERROR(MAJOR, E_INVALID_STATE, ("VSP free of port FAILED"));

    if (p_FmPort->p_ParamsPage)
        FM_MURAM_FreeMem(p_FmPort->h_FmMuram, p_FmPort->p_ParamsPage);

    if (p_FmPort->h_Spinlock)
        XX_FreeSpinlock(p_FmPort->h_Spinlock);

    XX_Free(p_FmPort);

    return E_OK;
}

/*************************************************/
/*       API Advanced Init unit functions        */
/*************************************************/

t_Error FM_PORT_ConfigNumOfOpenDmas(t_Handle h_FmPort, t_FmPortRsrc *p_OpenDmas)
{
    t_FmPort *p_FmPort = (t_FmPort*)h_FmPort;

    SANITY_CHECK_RETURN_ERROR(p_FmPort, E_INVALID_HANDLE);
    SANITY_CHECK_RETURN_ERROR(p_FmPort->p_FmPortDriverParam, E_INVALID_HANDLE);

    p_FmPort->p_FmPortDriverParam->setNumOfOpenDmas = TRUE;
    memcpy(&p_FmPort->openDmas, p_OpenDmas, sizeof(t_FmPortRsrc));

    return E_OK;
}

t_Error FM_PORT_ConfigNumOfTasks(t_Handle h_FmPort, t_FmPortRsrc *p_NumOfTasks)
{
    t_FmPort *p_FmPort = (t_FmPort*)h_FmPort;

    SANITY_CHECK_RETURN_ERROR(p_FmPort, E_INVALID_HANDLE);
    SANITY_CHECK_RETURN_ERROR(p_FmPort->p_FmPortDriverParam, E_INVALID_HANDLE);

    memcpy(&p_FmPort->tasks, p_NumOfTasks, sizeof(t_FmPortRsrc));
    p_FmPort->p_FmPortDriverParam->setNumOfTasks = TRUE;
    return E_OK;
}

t_Error FM_PORT_ConfigSizeOfFifo(t_Handle h_FmPort, t_FmPortRsrc *p_SizeOfFifo)
{
    t_FmPort *p_FmPort = (t_FmPort*)h_FmPort;

    SANITY_CHECK_RETURN_ERROR(p_FmPort, E_INVALID_HANDLE);
    SANITY_CHECK_RETURN_ERROR(p_FmPort->p_FmPortDriverParam, E_INVALID_HANDLE);

    p_FmPort->p_FmPortDriverParam->setSizeOfFifo = TRUE;
    memcpy(&p_FmPort->fifoBufs, p_SizeOfFifo, sizeof(t_FmPortRsrc));

    return E_OK;
}

t_Error FM_PORT_ConfigDeqHighPriority(t_Handle h_FmPort, bool highPri)
{
    t_FmPort *p_FmPort = (t_FmPort*)h_FmPort;

    SANITY_CHECK_RETURN_ERROR(p_FmPort, E_INVALID_HANDLE);
    SANITY_CHECK_RETURN_ERROR(p_FmPort->p_FmPortDriverParam, E_INVALID_HANDLE);
    if ((p_FmPort->portType == e_FM_PORT_TYPE_RX_10G)
            || (p_FmPort->portType == e_FM_PORT_TYPE_RX))
        RETURN_ERROR(MAJOR, E_NO_MEMORY, ("not available for Rx ports"));

    p_FmPort->p_FmPortDriverParam->dfltCfg.deq_high_pri = highPri;

    return E_OK;
}

t_Error FM_PORT_ConfigDeqPrefetchOption(
        t_Handle h_FmPort, e_FmPortDeqPrefetchOption deqPrefetchOption)
{
    t_FmPort *p_FmPort = (t_FmPort*)h_FmPort;

    SANITY_CHECK_RETURN_ERROR(p_FmPort, E_INVALID_HANDLE);
    SANITY_CHECK_RETURN_ERROR(p_FmPort->p_FmPortDriverParam, E_INVALID_HANDLE);
    if ((p_FmPort->portType == e_FM_PORT_TYPE_RX_10G)
            || (p_FmPort->portType == e_FM_PORT_TYPE_RX))
        RETURN_ERROR(MAJOR, E_INVALID_OPERATION,
                     ("not available for Rx ports"));
    p_FmPort->p_FmPortDriverParam->dfltCfg.deq_prefetch_opt =
            (enum fman_port_deq_prefetch)deqPrefetchOption;

    return E_OK;
}

t_Error FM_PORT_ConfigBufferPrefixContent(
        t_Handle h_FmPort, t_FmBufferPrefixContent *p_FmBufferPrefixContent)
{
    t_FmPort *p_FmPort = (t_FmPort*)h_FmPort;

    SANITY_CHECK_RETURN_ERROR(p_FmPort, E_INVALID_HANDLE);
    SANITY_CHECK_RETURN_ERROR(p_FmPort->p_FmPortDriverParam, E_INVALID_HANDLE);

    memcpy(&p_FmPort->p_FmPortDriverParam->bufferPrefixContent,
           p_FmBufferPrefixContent, sizeof(t_FmBufferPrefixContent));
    /* if dataAlign was not initialized by user, we return to driver's default */
    if (!p_FmPort->p_FmPortDriverParam->bufferPrefixContent.dataAlign)
        p_FmPort->p_FmPortDriverParam->bufferPrefixContent.dataAlign =
                DEFAULT_PORT_bufferPrefixContent_dataAlign;

    return E_OK;
}

t_Error FM_PORT_ConfigExtBufPools(t_Handle h_FmPort, t_FmExtPools *p_FmExtPools)
{
    t_FmPort *p_FmPort = (t_FmPort*)h_FmPort;

    SANITY_CHECK_RETURN_ERROR(p_FmPort, E_INVALID_HANDLE);
    SANITY_CHECK_RETURN_ERROR(p_FmPort->p_FmPortDriverParam, E_INVALID_HANDLE);

    if (p_FmPort->portType != e_FM_PORT_TYPE_OH_OFFLINE_PARSING)
        RETURN_ERROR(MAJOR, E_INVALID_OPERATION,
                     ("available for OP ports only"));

    memcpy(&p_FmPort->p_FmPortDriverParam->extBufPools, p_FmExtPools,
           sizeof(t_FmExtPools));

    return E_OK;
}

t_Error FM_PORT_ConfigErrorsToDiscard(t_Handle h_FmPort,
                                      fmPortFrameErrSelect_t errs)
{
    t_FmPort *p_FmPort = (t_FmPort*)h_FmPort;

    SANITY_CHECK_RETURN_ERROR(p_FmPort, E_INVALID_HANDLE);
    SANITY_CHECK_RETURN_ERROR(p_FmPort->p_FmPortDriverParam, E_INVALID_HANDLE);
    if ((p_FmPort->portType != e_FM_PORT_TYPE_RX_10G)
            && (p_FmPort->portType != e_FM_PORT_TYPE_RX)
            && (p_FmPort->portType != e_FM_PORT_TYPE_OH_OFFLINE_PARSING))
        RETURN_ERROR( MAJOR, E_INVALID_OPERATION,
                     ("available for Rx and offline parsing ports only"));

    p_FmPort->p_FmPortDriverParam->errorsToDiscard = errs;

    return E_OK;
}

t_Error FM_PORT_ConfigMaxFrameLength(t_Handle h_FmPort, uint16_t length)
{
    t_FmPort *p_FmPort = (t_FmPort*)h_FmPort;

    SANITY_CHECK_RETURN_ERROR(p_FmPort, E_INVALID_HANDLE);
    SANITY_CHECK_RETURN_ERROR(p_FmPort->p_FmPortDriverParam, E_INVALID_HANDLE);

    p_FmPort->maxFrameLength = length;

    return E_OK;
}

/****************************************************/
/*       Hidden-DEBUG Only API                      */
/****************************************************/

/****************************************************/
/*       API Run-time Control unit functions        */
/****************************************************/

uint64_t * FM_PORT_GetBufferTimeStamp(t_Handle h_FmPort, char *p_Data)
{
    t_FmPort *p_FmPort = (t_FmPort*)h_FmPort;

    SANITY_CHECK_RETURN_VALUE(p_FmPort, E_INVALID_HANDLE, NULL);
    SANITY_CHECK_RETURN_VALUE(!p_FmPort->p_FmPortDriverParam, E_INVALID_STATE,
                              NULL);

    if (p_FmPort->bufferOffsets.timeStampOffset == ILLEGAL_BASE)
        return NULL;

    return (uint64_t *)PTR_MOVE(p_Data, p_FmPort->bufferOffsets.timeStampOffset);
}

t_Error FM_PORT_Disable(t_Handle h_FmPort)
{
    t_FmPort *p_FmPort = (t_FmPort*)h_FmPort;
    int err;

    SANITY_CHECK_RETURN_ERROR(p_FmPort, E_INVALID_HANDLE);
    SANITY_CHECK_RETURN_ERROR(!p_FmPort->p_FmPortDriverParam, E_INVALID_STATE);

    if (p_FmPort->imEn)
        FmPortImDisable(p_FmPort);

    err = fman_port_disable(&p_FmPort->port);
    if (err == -EBUSY)
    {
        DBG(WARNING, ("%s: BMI or QMI is Busy. Port forced down",
               p_FmPort->name));
    }
    else
        if (err != 0)
        {
            RETURN_ERROR(MAJOR, E_INVALID_VALUE, ("fman_port_disable"));
        }

    p_FmPort->enabled = FALSE;

    return E_OK;
}

t_Error FM_PORT_GetEnabled(t_Handle h_FmPort, bool *p_Enabled)
{
    t_FmPort *p_FmPort = (t_FmPort *)h_FmPort;

    SANITY_CHECK_RETURN_ERROR(p_FmPort, E_INVALID_HANDLE);
    SANITY_CHECK_RETURN_ERROR(p_Enabled, E_NULL_POINTER);
    SANITY_CHECK_RETURN_ERROR(!p_FmPort->p_FmPortDriverParam, E_INVALID_STATE);
    *p_Enabled = p_FmPort->enabled;
    return E_OK;
}

t_Error FM_PORT_GetStopped(t_Handle h_FmPort, bool *p_Stopped)
{
    t_FmPort *p_FmPort = (t_FmPort *)h_FmPort;

    SANITY_CHECK_RETURN_ERROR(p_FmPort, E_INVALID_HANDLE);
    SANITY_CHECK_RETURN_ERROR(p_Stopped, E_NULL_POINTER);
    SANITY_CHECK_RETURN_ERROR(!p_FmPort->p_FmPortDriverParam, E_INVALID_STATE);
    *p_Stopped = !p_FmPort->enabled && fman_port_is_stopped(&p_FmPort->port);
    return E_OK;
}

t_Error FM_PORT_IsPcdAttached(t_Handle h_FmPort, bool *p_Attached)
{
    t_FmPort *p_FmPort = (t_FmPort *)h_FmPort;
    volatile uint32_t *p_BmiNia;

    SANITY_CHECK_RETURN_ERROR(p_FmPort, E_INVALID_HANDLE);
    SANITY_CHECK_RETURN_ERROR(p_Attached, E_NULL_POINTER);
    SANITY_CHECK_RETURN_ERROR(!p_FmPort->p_FmPortDriverParam, E_INVALID_STATE);
    switch (p_FmPort->portType)
    {
        case (e_FM_PORT_TYPE_RX_10G):
        case (e_FM_PORT_TYPE_RX):
            p_BmiNia = &p_FmPort->port.bmi_regs->rx.fmbm_rfne;
            break;
        case (e_FM_PORT_TYPE_OH_OFFLINE_PARSING):
            p_BmiNia = &p_FmPort->port.bmi_regs->oh.fmbm_ofne;
            break;
        default:
            /* No other port type can be given a PCD (FM_PORT_SetPCD()). */
            *p_Attached = FALSE;
            return E_OK;
    }
    /* The test AttachPCD() makes of a port in the BMI-to-BMI state. */
    *p_Attached = (GET_UINT32(*p_BmiNia) & ~BMI_RFNE_FDCS_MASK)
            != GET_NO_PCD_NIA_BMI_AC_ENQ_FRAME();
    return E_OK;
}

t_Error FM_PORT_SetFenced(t_Handle h_FmPort, bool fenced)
{
    t_FmPort *p_FmPort = (t_FmPort *)h_FmPort;
    uint32_t intFlags;

    SANITY_CHECK_RETURN_ERROR(p_FmPort, E_INVALID_HANDLE);
    SANITY_CHECK_RETURN_ERROR(!p_FmPort->p_FmPortDriverParam, E_INVALID_STATE);
    /* Under the lock FM_PORT_Enable() reads the fence and enables under: an
     * enable either finished before this, and the disable a fencing caller
     * issues next stops the port again, or it finds the fence. */
    intFlags = XX_LockIntrSpinlock(p_FmPort->h_Spinlock);
    p_FmPort->fenced = fenced;
    XX_UnlockIntrSpinlock(p_FmPort->h_Spinlock, intFlags);
    return E_OK;
}

t_Error FM_PORT_Enable(t_Handle h_FmPort)
{
    t_FmPort *p_FmPort = (t_FmPort*)h_FmPort;
    uint32_t intFlags;
    int err;

    SANITY_CHECK_RETURN_ERROR(p_FmPort, E_INVALID_HANDLE);
    SANITY_CHECK_RETURN_ERROR(!p_FmPort->p_FmPortDriverParam, E_INVALID_STATE);

    /* A port whose owner has stopped it to inspect the classifier stays
     * stopped, whoever asks: a netdev's open, a resume. The fence is read
     * and the port enabled under one hold of the lock FM_PORT_SetFenced()
     * takes, so no enable that found the fence open lands after the
     * owner's stop. */
    intFlags = XX_LockIntrSpinlock(p_FmPort->h_Spinlock);
    if (p_FmPort->fenced)
    {
        XX_UnlockIntrSpinlock(p_FmPort->h_Spinlock, intFlags);
        return ERROR_CODE(E_BUSY);
    }

    /* Used by FM_PORT_Free routine as indication
     if to disable port. Thus set it to TRUE prior
     to enabling itself. This way if part of enable
     process fails there will be still things
     to disable during Free. For example, if BMI
     enable succeeded but QMI failed, still  BMI
     needs to be disabled by Free. */
    p_FmPort->enabled = TRUE;

    if (p_FmPort->imEn)
        FmPortImEnable(p_FmPort);

    err = fman_port_enable(&p_FmPort->port);
    XX_UnlockIntrSpinlock(p_FmPort->h_Spinlock, intFlags);
    if (err != 0)
        RETURN_ERROR(MAJOR, E_INVALID_VALUE, ("fman_port_enable"));

    return E_OK;
}

#if defined(CONFIG_INET_IPSEC_OFFLOAD) || defined(CONFIG_INET6_IPSEC_OFFLOAD)
t_Error FM_PORT_SetDiscardMask(t_Handle h_FmPort, fmPortFrameErrSelect_t errs)
{
    t_FmPort *p_FmPort = (t_FmPort*)h_FmPort;
    int err;

    err = fman_port_set_discard_mask(&p_FmPort->port, (uint32_t)errs);
    if (err != 0)
        RETURN_ERROR(MAJOR, E_INVALID_VALUE, ("fman_port_set_discard_mask"));

    return E_OK;
}
EXPORT_SYMBOL(FM_PORT_SetDiscardMask);
#endif

uint32_t FM_PORT_GetCounter(t_Handle h_FmPort, e_FmPortCounters counter)
{
    t_FmPort *p_FmPort = (t_FmPort*)h_FmPort;
    bool bmiCounter = FALSE;
    enum fman_port_stats_counters statsType;
    enum fman_port_perf_counters perfType;
    enum fman_port_qmi_counters queueType;
    bool isStats;
    t_Error errCode;

    SANITY_CHECK_RETURN_VALUE(p_FmPort, E_INVALID_HANDLE, 0);
    SANITY_CHECK_RETURN_ERROR(!p_FmPort->p_FmPortDriverParam, E_INVALID_STATE);

    switch (counter)
    {
        case (e_FM_PORT_COUNTERS_DEQ_TOTAL):
        case (e_FM_PORT_COUNTERS_DEQ_FROM_DEFAULT):
        case (e_FM_PORT_COUNTERS_DEQ_CONFIRM):
            /* check that counter is available for the port type */
            if ((p_FmPort->portType == e_FM_PORT_TYPE_RX)
                    || (p_FmPort->portType == e_FM_PORT_TYPE_RX_10G))
            {
                REPORT_ERROR(MINOR, E_INVALID_STATE,
                        ("Requested counter is not available for Rx ports"));
                return 0;
            }
            bmiCounter = FALSE;
            break;
        case (e_FM_PORT_COUNTERS_ENQ_TOTAL):
            bmiCounter = FALSE;
            break;
        default: /* BMI counters (or error - will be checked in BMI routine )*/
            bmiCounter = TRUE;
            break;
    }

    if (bmiCounter)
    {
        errCode = BmiPortCheckAndGetCounterType(p_FmPort, counter, &statsType,
                                                &perfType, &isStats);
        if (errCode != E_OK)
        {
            REPORT_ERROR(MINOR, errCode, NO_MSG);
            return 0;
        }
        if (isStats)
            return fman_port_get_stats_counter(&p_FmPort->port, statsType);
        else
            return fman_port_get_perf_counter(&p_FmPort->port, perfType);
    }
    else /* QMI counter */
    {
        /* check that counters are enabled */
        if (!(GET_UINT32(p_FmPort->port.qmi_regs->fmqm_pnc)
                & QMI_PORT_CFG_EN_COUNTERS))

        {
            REPORT_ERROR(MINOR, E_INVALID_STATE, ("Requested counter was not enabled"));
            return 0;
        }

        /* Set counter */
        switch (counter)
        {
            case (e_FM_PORT_COUNTERS_ENQ_TOTAL):
                queueType = E_FMAN_PORT_ENQ_TOTAL;
                break;
            case (e_FM_PORT_COUNTERS_DEQ_TOTAL):
                queueType = E_FMAN_PORT_DEQ_TOTAL;
                break;
            case (e_FM_PORT_COUNTERS_DEQ_FROM_DEFAULT):
                queueType = E_FMAN_PORT_DEQ_FROM_DFLT;
                break;
            case (e_FM_PORT_COUNTERS_DEQ_CONFIRM):
                queueType = E_FMAN_PORT_DEQ_CONFIRM;
                break;
            default:
                REPORT_ERROR(MINOR, E_INVALID_STATE, ("Requested counter is not available"));
                return 0;
        }

        return fman_port_get_qmi_counter(&p_FmPort->port, queueType);
    }

    return 0;
}

t_Error FM_PORT_SetRxL4ChecksumVerify(t_Handle h_FmPort, bool enable)
{
    t_FmPort *p_FmPort = (t_FmPort*)h_FmPort;
    int err;

    SANITY_CHECK_RETURN_ERROR(p_FmPort, E_INVALID_HANDLE);
    SANITY_CHECK_RETURN_ERROR(!p_FmPort->p_FmPortDriverParam, E_INVALID_STATE);

    if ((p_FmPort->portType != e_FM_PORT_TYPE_RX_10G)
            && (p_FmPort->portType != e_FM_PORT_TYPE_RX))
        RETURN_ERROR(MAJOR, E_INVALID_OPERATION,
                     ("available for Rx ports only"));

    /* Bits 0-7 in the Rx FD Status are initialized by the user configurable
     * FMBM_RFNE[FDCS]. A bit which is set by the user in FMBM_RFNE[FDCS] is
     * reflected in the corresponding bit, and is not reset by the FMan
     * hardware. So to let the hardware do its job, we need to clear the FMBM
     * bit, and vice versa.
     */
    if (!enable)
        err = fman_port_modify_rx_fd_bits(
                &p_FmPort->port, (uint8_t)(BMI_PORT_RFNE_FRWD_DCL4C >> 24),
                TRUE);
    else
        err = fman_port_modify_rx_fd_bits(
                &p_FmPort->port, (uint8_t)(BMI_PORT_RFNE_FRWD_DCL4C >> 24),
                FALSE);
    if (err != 0)
        RETURN_ERROR(MAJOR, E_INVALID_VALUE, ("fman_port_modify_rx_fd_bits"));

    return E_OK;
}

/*****************************************************************************/
/*       API Run-time PCD Control unit functions                             */
/*****************************************************************************/

t_Error FM_PORT_VSPAlloc(t_Handle h_FmPort, t_FmPortVSPAllocParams *p_VSPParams)
{
    t_FmPort *p_FmPort = (t_FmPort*)h_FmPort;
    t_Error err = E_OK;
    volatile uint32_t *p_BmiStorageProfileId = NULL, *p_BmiVspe = NULL;
    uint32_t tmpReg = 0, tmp = 0;
    uint16_t hwStoragePrflId;

    SANITY_CHECK_RETURN_ERROR(p_FmPort, E_INVALID_HANDLE);
    SANITY_CHECK_RETURN_ERROR(p_FmPort->h_Fm, E_INVALID_HANDLE);
    /*for numOfProfiles = 0 don't call this function*/
    SANITY_CHECK_RETURN_ERROR(p_VSPParams->numOfProfiles, E_INVALID_VALUE);
    /*dfltRelativeId should be in the range of numOfProfiles*/
    SANITY_CHECK_RETURN_ERROR(
            p_VSPParams->dfltRelativeId < p_VSPParams->numOfProfiles,
            E_INVALID_VALUE);
    /*p_FmPort should be from Rx type or OP*/
    SANITY_CHECK_RETURN_ERROR(
            ((p_FmPort->portType == e_FM_PORT_TYPE_RX_10G) || (p_FmPort->portType == e_FM_PORT_TYPE_RX) || (p_FmPort->portType == e_FM_PORT_TYPE_OH_OFFLINE_PARSING)),
            E_INVALID_VALUE);
    /*port should be disabled*/
    SANITY_CHECK_RETURN_ERROR(!p_FmPort->enabled, E_INVALID_STATE);
    /*if its called for Rx port relevant Tx Port should be passed (initialized) too and it should be disabled*/
    SANITY_CHECK_RETURN_ERROR(
            ((p_VSPParams->h_FmTxPort && !((t_FmPort *)(p_VSPParams->h_FmTxPort))->enabled) || (p_FmPort->portType == e_FM_PORT_TYPE_OH_OFFLINE_PARSING)),
            E_INVALID_VALUE);
    /*should be called before SetPCD - this port should be without PCD*/
    SANITY_CHECK_RETURN_ERROR(!p_FmPort->pcdEngines, E_INVALID_STATE);

    /*alloc window of VSPs for this port*/
    err = FmVSPAllocForPort(p_FmPort->h_Fm, p_FmPort->portType,
                            p_FmPort->portId, p_VSPParams->numOfProfiles);
    if (err != E_OK)
        RETURN_ERROR(MAJOR, err, NO_MSG);

    /*get absolute VSP ID for dfltRelative*/
    err = FmVSPGetAbsoluteProfileId(p_FmPort->h_Fm, p_FmPort->portType,
                                    p_FmPort->portId,
                                    p_VSPParams->dfltRelativeId,
                                    &hwStoragePrflId);
    if (err != E_OK)
        RETURN_ERROR(MAJOR, err, NO_MSG);

    /*fill relevant registers for p_FmPort and relative TxPort in the case p_FmPort from Rx type*/
    switch (p_FmPort->portType)
    {
        case (e_FM_PORT_TYPE_RX_10G):
        case (e_FM_PORT_TYPE_RX):
            p_BmiStorageProfileId =
                    &(((t_FmPort *)(p_VSPParams->h_FmTxPort))->p_FmPortBmiRegs->txPortBmiRegs.fmbm_tcfqid);
            p_BmiVspe =
                    &(((t_FmPort *)(p_VSPParams->h_FmTxPort))->p_FmPortBmiRegs->txPortBmiRegs.fmbm_tfne);

            tmpReg = GET_UINT32(*p_BmiStorageProfileId) & ~BMI_SP_ID_MASK;
            tmpReg |= (uint32_t)hwStoragePrflId << BMI_SP_ID_SHIFT;
            WRITE_UINT32(*p_BmiStorageProfileId, tmpReg);

            tmpReg = GET_UINT32(*p_BmiVspe);
            WRITE_UINT32(*p_BmiVspe, tmpReg | BMI_SP_EN);

            p_BmiStorageProfileId =
                    &p_FmPort->p_FmPortBmiRegs->rxPortBmiRegs.fmbm_rfqid;
            p_BmiVspe = &p_FmPort->p_FmPortBmiRegs->rxPortBmiRegs.fmbm_rpp;
            hwStoragePrflId = p_VSPParams->dfltRelativeId;
            break;

        case (e_FM_PORT_TYPE_OH_OFFLINE_PARSING):
            tmpReg = NIA_ENG_BMI | NIA_BMI_AC_FETCH_ALL_FRAME;
            WRITE_UINT32( p_FmPort->p_FmPortQmiRegs->nonRxQmiRegs.fmqm_pndn,
                         tmpReg);

            p_BmiStorageProfileId =
                    &p_FmPort->p_FmPortBmiRegs->ohPortBmiRegs.fmbm_ofqid;
            p_BmiVspe = &p_FmPort->p_FmPortBmiRegs->ohPortBmiRegs.fmbm_opp;
            tmp |= BMI_EBD_EN;
            break;

        default:
            RETURN_ERROR( MAJOR, E_INVALID_OPERATION,
                         ("available for Rx and offline parsing ports only"));
    }

    p_FmPort->vspe = TRUE;
    p_FmPort->dfltRelativeId = p_VSPParams->dfltRelativeId;

    tmpReg = GET_UINT32(*p_BmiStorageProfileId) & ~BMI_SP_ID_MASK;
    tmpReg |= (uint32_t)hwStoragePrflId << BMI_SP_ID_SHIFT;
    WRITE_UINT32(*p_BmiStorageProfileId, tmpReg);

    tmpReg = GET_UINT32(*p_BmiVspe);
    WRITE_UINT32(*p_BmiVspe, tmpReg | BMI_SP_EN | tmp);
    return E_OK;
}

t_Error FM_PORT_PcdPlcrAllocProfiles(t_Handle h_FmPort, uint16_t numOfProfiles)
{
    t_FmPort *p_FmPort = (t_FmPort*)h_FmPort;
    t_Error err = E_OK;

    p_FmPort->h_FmPcd = FmGetPcdHandle(p_FmPort->h_Fm);
    ASSERT_COND(p_FmPort->h_FmPcd);

    if (!TRY_LOCK(p_FmPort->h_Spinlock, &p_FmPort->lock))
    {
        DBG(TRACE, ("FM Port Try Lock - BUSY"));
        return ERROR_CODE(E_BUSY);
    }

    if (numOfProfiles)
    {
        err = FmPcdPlcrAllocProfiles(p_FmPort->h_FmPcd,
                                     p_FmPort->hardwarePortId, numOfProfiles);
        if (err)
            RETURN_ERROR(MAJOR, err, NO_MSG);
    }
    /* set the port handle within the PCD policer, even if no profiles defined */
    FmPcdPortRegister(p_FmPort->h_FmPcd, h_FmPort, p_FmPort->hardwarePortId);

    RELEASE_LOCK(p_FmPort->lock);

    return E_OK;
}
EXPORT_SYMBOL(FM_PORT_PcdPlcrAllocProfiles);


t_Error FM_PORT_PcdPlcrFreeProfiles(t_Handle h_FmPort)
{
    t_FmPort *p_FmPort = (t_FmPort*)h_FmPort;
    t_Error err = E_OK;

    if (!TRY_LOCK(p_FmPort->h_Spinlock, &p_FmPort->lock))
    {
        DBG(TRACE, ("FM Port Try Lock - BUSY"));
        return ERROR_CODE(E_BUSY);
    }

    err = FmPcdPlcrFreeProfiles(p_FmPort->h_FmPcd, p_FmPort->hardwarePortId);

    RELEASE_LOCK(p_FmPort->lock);

    if (err)
        RETURN_ERROR(MAJOR, err, NO_MSG);

    return E_OK;
}

t_Error FM_PORT_DetachPCD(t_Handle h_FmPort)
{
    t_FmPort *p_FmPort = (t_FmPort*)h_FmPort;
    t_Error err = E_OK;

    SANITY_CHECK_RETURN_ERROR(h_FmPort, E_INVALID_HANDLE);
    SANITY_CHECK_RETURN_ERROR(!p_FmPort->p_FmPortDriverParam, E_INVALID_STATE);

    if (p_FmPort->imEn)
        RETURN_ERROR(MAJOR, E_INVALID_OPERATION,
                     ("available for non-independent mode ports only"));

    if ((p_FmPort->portType != e_FM_PORT_TYPE_RX_10G)
            && (p_FmPort->portType != e_FM_PORT_TYPE_RX)
            && (p_FmPort->portType != e_FM_PORT_TYPE_OH_OFFLINE_PARSING))
        RETURN_ERROR( MAJOR, E_INVALID_OPERATION,
                     ("available for Rx and offline parsing ports only"));

    if (!TRY_LOCK(p_FmPort->h_Spinlock, &p_FmPort->lock))
    {
        DBG(TRACE, ("FM Port Try Lock - BUSY"));
        return ERROR_CODE(E_BUSY);
    }

    if (!p_FmPort->pcdConfigured)
    {
        /* A port without a policy already uses its default path. Keep
         * incomplete setup/cleanup failures distinct from this no-op. */
        bool unconfigured = !p_FmPort->pcdEngines && !p_FmPort->pcdNetEnvOwner;

        RELEASE_LOCK(p_FmPort->lock);
        if (unconfigured)
            return E_OK;
        RETURN_ERROR(MAJOR, E_INVALID_STATE, ("PCD setup is not complete"));
    }

    err = DetachPCD(h_FmPort);
    if (err != E_OK)
    {
        RELEASE_LOCK(p_FmPort->lock);
        RETURN_ERROR(MAJOR, err, NO_MSG);
    }

    RELEASE_LOCK(p_FmPort->lock);

    return E_OK;
}

t_Error FM_PORT_BypassPCD(t_Handle h_FmPort, bool bypass)
{
    t_FmPort *p_FmPort = (t_FmPort*)h_FmPort;
    t_Error err = E_OK;

    SANITY_CHECK_RETURN_ERROR(h_FmPort, E_INVALID_HANDLE);
    SANITY_CHECK_RETURN_ERROR(!p_FmPort->p_FmPortDriverParam, E_INVALID_STATE);

    if (p_FmPort->imEn)
        RETURN_ERROR(MAJOR, E_INVALID_OPERATION,
                     ("available for non-independent mode ports only"));

    if ((p_FmPort->portType != e_FM_PORT_TYPE_RX_10G)
            && (p_FmPort->portType != e_FM_PORT_TYPE_RX)
            && (p_FmPort->portType != e_FM_PORT_TYPE_OH_OFFLINE_PARSING))
        RETURN_ERROR( MAJOR, E_INVALID_OPERATION,
                     ("available for Rx and offline parsing ports only"));

    if (!TRY_LOCK(p_FmPort->h_Spinlock, &p_FmPort->lock))
    {
        DBG(TRACE, ("FM Port Try Lock - BUSY"));
        return ERROR_CODE(E_BUSY);
    }

    /* Switched only while the port takes no frame, so none sees half of
     * either set of registers and none needs a barrier to finish. */
    if (!p_FmPort->pcdConfigured || p_FmPort->enabled)
    {
        RELEASE_LOCK(p_FmPort->lock);
        RETURN_ERROR(MAJOR, E_INVALID_STATE,
                     ("PCD not configured, or the port is enabled"));
    }

    /* The flag follows the entry register: once new frames bypass the PCD,
     * a later call with bypass false gives it back, even if the rest of
     * the bypass failed. AttachPCD() writes that register last. */
    if (bypass && !p_FmPort->pcdBypassed)
    {
        DetachPCDEntry(p_FmPort);
        p_FmPort->pcdBypassed = TRUE;
        err = DetachPCDActions(p_FmPort);
    }
    else if (!bypass && p_FmPort->pcdBypassed)
    {
        err = AttachPCD(p_FmPort);
        if (err == E_OK)
            p_FmPort->pcdBypassed = FALSE;
    }

    RELEASE_LOCK(p_FmPort->lock);
    if (err != E_OK)
        RETURN_ERROR(MAJOR, err, NO_MSG);
    return E_OK;
}

static int FM_PORT_ConfigureMuramPage(t_Handle h_FmPort)
{
	t_FmPort *p_FmPort = (t_FmPort*)h_FmPort;
	t_FmPortGetSetCcParams fmPortGetSetCcParams;
	t_FmPcdCtrlParamsPage *p_ParamsPage;
	uint32_t nia;
	int err;

	memset(&fmPortGetSetCcParams, 0, sizeof(t_FmPortGetSetCcParams));

	/* Set up the Next Invoked Action to do frame processing through the
	 * FMan Controller. If advanced offload support has been previously
	 * enabled through ioctl, set up this NIA's Action Code to "Pop To
	 * Next Step" (0x0e), otherwise to "Pop to Next Step NonIPACCOffload"
	 * (0x2c).
	 */
	fmPortGetSetCcParams.setCcParams.type = UPDATE_NIA_CMNE;
	if (FmPcdIsAdvancedOffloadSupported(p_FmPort->h_FmPcd))
		nia = NIA_FM_CTL_AC_POP_TO_N_STEP | NIA_ENG_FM_CTL;
	else
		nia = NIA_FM_CTL_AC_NO_IPACC_POP_TO_N_STEP | NIA_ENG_FM_CTL;

	fmPortGetSetCcParams.setCcParams.nia = nia;

	err = FmPortGetSetCcParams(h_FmPort, &fmPortGetSetCcParams);
	if (err)
		return err;

	/* Allocate the microcode control page for offload and VSP settings. */
	err = FmPortSetGprFunc(p_FmPort, e_FM_PORT_GPR_MURAM_PAGE,
			 (void**)&p_ParamsPage);
	if (err)
		return err;
	ASSERT_COND(p_ParamsPage);

	if (FmPcdIsAdvancedOffloadSupported(p_FmPort->h_FmPcd)) {
		WRITE_UINT32(p_ParamsPage->misc,
			     GET_UINT32(p_ParamsPage->misc) |
			     FM_CTL_PARAMS_PAGE_OFFLOAD_SUPPORT_EN);
	}

	if (p_FmPort->vspe) {
		WRITE_UINT32(p_ParamsPage->misc,
			     GET_UINT32(p_ParamsPage->misc) |
			     (p_FmPort->dfltRelativeId & FM_CTL_PARAMS_PAGE_ERROR_VSP_MASK));
	}

	return 0;
}

/* The port is detached (or setup never attached it). Keep every remaining
 * owner recorded if cleanup fails so DeletePCD or the next SetPCD can retry.
 * Hold all PCD object locks while removing bindings. Release them before
 * deleting private objects: the SDK returns their locks to its reuse pool
 * without clearing the flags. */
static t_Error DeletePortPcd(t_FmPort *p_FmPort, bool *allLocked)
{
    t_Error err;

    err = DeletePcd(p_FmPort);
    if (err)
        return err;
    if (*allLocked)
    {
        FmPcdLockUnlockAll(p_FmPort->h_FmPcd);
        *allLocked = FALSE;
    }
    if (p_FmPort->pcdNetEnvOwner)
    {
        FmPcdDecNetEnvOwners(p_FmPort->h_FmPcd, p_FmPort->netEnvId);
        p_FmPort->pcdNetEnvOwner = FALSE;
    }
    p_FmPort->requiredAction = 0;
    p_FmPort->pcdConfigured = FALSE;
    return E_OK;
}

t_Error FM_PORT_SetPCD(t_Handle h_FmPort, t_FmPortPcdParams *p_PcdParam)
{
    t_FmPort *p_FmPort = (t_FmPort *)h_FmPort;
    t_Error err = E_OK, cleanupErr;
    t_FmPortPcdParams modifiedPcdParams, *p_PcdParams = &modifiedPcdParams;
    t_FmPortGetSetCcParams fmPortGetSetCcParams;
    bool allLocked = FALSE;

    SANITY_CHECK_RETURN_ERROR(h_FmPort, E_INVALID_HANDLE);
    SANITY_CHECK_RETURN_ERROR(p_PcdParam, E_NULL_POINTER);
    if (p_PcdParam->h_IpReassemblyManip || p_PcdParam->h_CapwapReassemblyManip)
        RETURN_ERROR(MAJOR, E_NOT_SUPPORTED, ("Hardware reassembly is unsupported in Mono"));
    SANITY_CHECK_RETURN_ERROR(!p_FmPort->p_FmPortDriverParam, E_INVALID_STATE);
    if (p_FmPort->imEn)
        RETURN_ERROR(MAJOR, E_INVALID_OPERATION, ("Not available in independent mode"));
    if (p_FmPort->portType != e_FM_PORT_TYPE_RX_10G &&
        p_FmPort->portType != e_FM_PORT_TYPE_RX &&
        p_FmPort->portType != e_FM_PORT_TYPE_OH_OFFLINE_PARSING)
        RETURN_ERROR(MAJOR, E_INVALID_OPERATION, ("Available for Rx and offline ports only"));

    /* Validate combinations before acquiring the port lock or saving handles. */
    if (!p_PcdParam->h_NetEnv)
        RETURN_ERROR(MAJOR, E_INVALID_HANDLE, ("Network environment is required"));
    if (p_PcdParam->p_CcParams && !p_PcdParam->p_CcParams->h_CcTree)
        RETURN_ERROR(MAJOR, E_INVALID_HANDLE, ("Tree handle is required for CC"));
    if (!TRY_LOCK(p_FmPort->h_Spinlock, &p_FmPort->lock))
        return ERROR_CODE(E_BUSY);
    if (p_FmPort->pcdConfigured)
    {
        err = ERROR_CODE(E_INVALID_STATE);
        goto out;
    }
    p_FmPort->h_FmPcd = FmGetPcdHandle(p_FmPort->h_Fm);
    ASSERT_COND(p_FmPort->h_FmPcd);

    /* A previous rollback may have retained ownership after a second error. */
    if (p_FmPort->pcdNetEnvOwner || p_FmPort->pcdEngines)
    {
        if (!FmPcdLockTryLockAll(p_FmPort->h_FmPcd))
        {
            err = ERROR_CODE(E_BUSY);
            goto out;
        }
        allLocked = TRUE;
        err = DeletePortPcd(p_FmPort, &allLocked);
        if (err)
            goto out;
    }

    modifiedPcdParams = *p_PcdParam;
    p_FmPort->netEnvId = FmPcdGetNetEnvId(p_PcdParams->h_NetEnv);
    FmPcdIncNetEnvOwners(p_FmPort->h_FmPcd, p_FmPort->netEnvId);
    p_FmPort->pcdNetEnvOwner = TRUE;
    if (!FmPcdLockTryLockAll(p_FmPort->h_FmPcd))
    {
        err = ERROR_CODE(E_BUSY);
        goto fail;
    }
    allLocked = TRUE;
    err = SetPcd(p_FmPort, p_PcdParams);
    if (err)
        goto fail;
    if ((p_FmPort->pcdEngines & FM_PCD_PRS) &&
        p_PcdParams->p_PrsParams->includeInPrsStatistics)
    {
        err = FmPcdPrsIncludePortInStatistics(p_FmPort->h_FmPcd,
                                             p_FmPort->hardwarePortId, TRUE);
        if (err)
            goto fail;
        p_FmPort->includeInPrsStatistics = TRUE;
    }

	if (FmPcdIsAdvancedOffloadSupported(p_FmPort->h_FmPcd)) {
		memset(&fmPortGetSetCcParams, 0, sizeof(t_FmPortGetSetCcParams));

		if (p_FmPort->portType == e_FM_PORT_TYPE_OH_OFFLINE_PARSING) {
			t_FmPcdCtrlParamsPage *p_ParamsPage;


			err = FmPortSetGprFunc(p_FmPort, e_FM_PORT_GPR_MURAM_PAGE,
					 (void**)&p_ParamsPage);
			if (err)
			goto fail;
			ASSERT_COND(p_ParamsPage);
			WRITE_UINT32(p_ParamsPage->postBmiFetchNia, p_FmPort->savedBmiNia);

			/* Set post-bmi-fetch nia */
			p_FmPort->savedBmiNia &= BMI_RFNE_FDCS_MASK;
			p_FmPort->savedBmiNia |= NIA_FM_CTL_AC_POST_BMI_FETCH | NIA_ENG_FM_CTL;

			/* Set pre-bmi-fetch nia */
			fmPortGetSetCcParams.setCcParams.type = UPDATE_NIA_PNDN;
			fmPortGetSetCcParams.setCcParams.nia = NIA_FM_CTL_AC_PRE_BMI_FETCH_FULL_FRAME |
							       NIA_ENG_FM_CTL;

			err = FmPortGetSetCcParams(p_FmPort, &fmPortGetSetCcParams);
			if (err)
			goto fail;
		}


		/* Set post-bmi-prepare-to-enq nia */
		fmPortGetSetCcParams.setCcParams.type = UPDATE_NIA_FENE;
		fmPortGetSetCcParams.setCcParams.nia = NIA_FM_CTL_AC_POST_BMI_ENQ | NIA_ENG_FM_CTL;

		err = FmPortGetSetCcParams(h_FmPort, &fmPortGetSetCcParams);
		if (err)
			goto fail;


	}

    err = FM_PORT_ConfigureMuramPage(p_FmPort);
    if (err)
        goto fail;
    err = AttachPCD(p_FmPort);
    if (err)
        goto fail;
    p_FmPort->pcdConfigured = TRUE;
    goto out;

fail:
    cleanupErr = DeletePortPcd(p_FmPort, &allLocked);
    if (cleanupErr)
        REPORT_ERROR(MAJOR, cleanupErr, ("Port PCD cleanup is pending; retry delete or setup"));
out:
    if (allLocked)
        FmPcdLockUnlockAll(p_FmPort->h_FmPcd);
    RELEASE_LOCK(p_FmPort->lock);
    return err;
}

t_Error FM_PORT_DeletePCD(t_Handle h_FmPort)
{
    t_FmPort *p_FmPort = (t_FmPort *)h_FmPort;
    t_Error err;
    bool allLocked = FALSE;

    SANITY_CHECK_RETURN_ERROR(h_FmPort, E_INVALID_HANDLE);
    SANITY_CHECK_RETURN_ERROR(!p_FmPort->p_FmPortDriverParam, E_INVALID_STATE);
    if (p_FmPort->imEn)
        RETURN_ERROR(MAJOR, E_INVALID_OPERATION, ("Not available in independent mode"));
    if (p_FmPort->portType != e_FM_PORT_TYPE_RX_10G &&
        p_FmPort->portType != e_FM_PORT_TYPE_RX &&
        p_FmPort->portType != e_FM_PORT_TYPE_OH_OFFLINE_PARSING)
        RETURN_ERROR(MAJOR, E_INVALID_OPERATION, ("Available for Rx and offline ports only"));
    if (!TRY_LOCK(p_FmPort->h_Spinlock, &p_FmPort->lock))
        return ERROR_CODE(E_BUSY);
    if (!p_FmPort->pcdNetEnvOwner && !p_FmPort->pcdEngines)
    {
        err = ERROR_CODE(E_INVALID_STATE);
        goto out;
    }
    /* A refused lock must not detach the port or consume any references. */
    if (!FmPcdLockTryLockAll(p_FmPort->h_FmPcd))
    {
        err = ERROR_CODE(E_BUSY);
        goto out;
    }
    allLocked = TRUE;
    if (p_FmPort->pcdConfigured)
    {
        err = DetachPCD(p_FmPort);
        if (err)
            goto unlock;
        p_FmPort->pcdConfigured = FALSE;
    }
    err = DeletePortPcd(p_FmPort, &allLocked);
unlock:
    if (allLocked)
        FmPcdLockUnlockAll(p_FmPort->h_FmPcd);
out:
    RELEASE_LOCK(p_FmPort->lock);
    return err;
}

