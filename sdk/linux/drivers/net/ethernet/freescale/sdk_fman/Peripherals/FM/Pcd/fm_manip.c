/*
 * Copyright 2008-2012 Freescale Semiconductor Inc.
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
 @File          fm_manip.c

 @Description   FM PCD manip ...
 *//***************************************************************************/
#define __ERR_MODULE__ MODULE_FM_PCD

#include "std_ext.h"
#include "error_ext.h"
#include "string_ext.h"
#include "debug_ext.h"
#include "fm_pcd_ext.h"
#include "fm_port_ext.h"
#include "fm_muram_ext.h"
#include "memcpy_ext.h"

#include "fm_common.h"
#include "fm_hc.h"
#include "fm_manip.h"

/****************************************/
/*       static functions               */
/****************************************/
static t_Handle GetManipInfo(t_FmPcdManip *p_Manip, e_ManipInfo manipInfo)
{
    t_FmPcdManip *p_CurManip = p_Manip;

    if (!MANIP_IS_UNIFIED(p_Manip))
        p_CurManip = p_Manip;
    else
    {
        /* go to first unified */
        while (MANIP_IS_UNIFIED_NON_FIRST(p_CurManip))
            p_CurManip = p_CurManip->h_PrevManip;
    }

    switch (manipInfo)
    {
        case (e_MANIP_HMCT):
            return p_CurManip->p_Hmct;
        case (e_MANIP_HMTD):
            return p_CurManip->h_Ad;
        case (e_MANIP_HANDLER_TABLE_OWNER):
            return (t_Handle)p_CurManip;
        default:
            return NULL;
    }
}

static uint16_t GetHmctSize(t_FmPcdManip *p_Manip)
{
    uint16_t size = 0;
    t_FmPcdManip *p_CurManip = p_Manip;

    if (!MANIP_IS_UNIFIED(p_Manip))
        return p_Manip->tableSize;

    /* accumulate sizes, starting with the first node */
    while (MANIP_IS_UNIFIED_NON_FIRST(p_CurManip))
        p_CurManip = p_CurManip->h_PrevManip;

    while (MANIP_IS_UNIFIED_NON_LAST(p_CurManip))
    {
        size += p_CurManip->tableSize;
        p_CurManip = (t_FmPcdManip *)p_CurManip->h_NextManip;
    }
    size += p_CurManip->tableSize; /* add last size */

    return (size);
}

static uint16_t GetDataSize(t_FmPcdManip *p_Manip)
{
    uint16_t size = 0;
    t_FmPcdManip *p_CurManip = p_Manip;

    if (!MANIP_IS_UNIFIED(p_Manip))
        return p_Manip->dataSize;

    /* accumulate sizes, starting with the first node */
    while (MANIP_IS_UNIFIED_NON_FIRST(p_CurManip))
        p_CurManip = p_CurManip->h_PrevManip;

    while (MANIP_IS_UNIFIED_NON_LAST(p_CurManip))
    {
        size += p_CurManip->dataSize;
        p_CurManip = (t_FmPcdManip *)p_CurManip->h_NextManip;
    }
    size += p_CurManip->dataSize; /* add last size */

    return (size);
}

static t_Error CalculateTableSize(t_FmPcdManipParams *p_FmPcdManipParams,
                                  uint16_t *p_TableSize, uint8_t *p_DataSize)
{
    uint8_t localDataSize, remain, tableSize = 0, dataSize = 0;

    if (p_FmPcdManipParams->u.hdr.rmv)
    {
        switch (p_FmPcdManipParams->u.hdr.rmvParams.type)
        {
            case (e_FM_PCD_MANIP_RMV_GENERIC):
                tableSize += HMCD_BASIC_SIZE;
                break;
            case (e_FM_PCD_MANIP_RMV_BY_HDR):
                switch (p_FmPcdManipParams->u.hdr.rmvParams.u.byHdr.type)
                {
                    case (e_FM_PCD_MANIP_RMV_BY_HDR_SPECIFIC_L2):
                    case (e_FM_PCD_MANIP_RMV_BY_HDR_CAPWAP):
                    case (e_FM_PCD_MANIP_RMV_BY_HDR_FROM_START):
                        tableSize += HMCD_BASIC_SIZE;
                        break;
                    default:
                        RETURN_ERROR(MINOR, E_INVALID_SELECTION,
                                     ("Unknown byHdr.type"));
                }
                break;
            default:
                RETURN_ERROR(MINOR, E_INVALID_SELECTION,
                             ("Unknown rmvParams.type"));
        }
    }

    if (p_FmPcdManipParams->u.hdr.insrt)
    {
        switch (p_FmPcdManipParams->u.hdr.insrtParams.type)
        {
            case (e_FM_PCD_MANIP_INSRT_GENERIC):
                remain =
                        (uint8_t)(p_FmPcdManipParams->u.hdr.insrtParams.u.generic.size
                                % 4);
                if (remain)
                    localDataSize =
                            (uint8_t)(p_FmPcdManipParams->u.hdr.insrtParams.u.generic.size
                                    + 4 - remain);
                else
                    localDataSize =
                            p_FmPcdManipParams->u.hdr.insrtParams.u.generic.size;
                tableSize += (uint8_t)(HMCD_BASIC_SIZE + localDataSize);
                break;
            case (e_FM_PCD_MANIP_INSRT_BY_HDR):
            {
                switch (p_FmPcdManipParams->u.hdr.insrtParams.u.byHdr.type)
                {

                    case (e_FM_PCD_MANIP_INSRT_BY_HDR_SPECIFIC_L2):
                        tableSize += HMCD_BASIC_SIZE + HMCD_PTR_SIZE;
                        switch (p_FmPcdManipParams->u.hdr.insrtParams.u.byHdr.u.specificL2Params.specificL2)
                        {
                            case (e_FM_PCD_MANIP_HDR_INSRT_MPLS):
                            case (e_FM_PCD_MANIP_HDR_INSRT_PPPOE):
                                dataSize +=
                                        p_FmPcdManipParams->u.hdr.insrtParams.u.byHdr.u.specificL2Params.size;
                                break;
                            default:
                                RETURN_ERROR(MINOR, E_NOT_SUPPORTED, NO_MSG);
                        }
                        break;
                    case (e_FM_PCD_MANIP_INSRT_BY_HDR_IP):
                        tableSize +=
                                (HMCD_BASIC_SIZE + HMCD_PTR_SIZE
                                        + HMCD_PARAM_SIZE
                                        + p_FmPcdManipParams->u.hdr.insrtParams.u.byHdr.u.ipParams.insrt.size);
                        dataSize += 2;
                        break;

                    case (e_FM_PCD_MANIP_INSRT_BY_HDR_UDP):
                    case (e_FM_PCD_MANIP_INSRT_BY_HDR_UDP_LITE):
                        tableSize += (HMCD_BASIC_SIZE + HMCD_L4_HDR_SIZE);

                        break;

                    case (e_FM_PCD_MANIP_INSRT_BY_HDR_CAPWAP):
                        tableSize +=
                                (HMCD_BASIC_SIZE
                                        + p_FmPcdManipParams->u.hdr.insrtParams.u.byHdr.u.insrt.size);
                        break;
                    default:
                        RETURN_ERROR(MINOR, E_INVALID_SELECTION,
                                     ("Unknown byHdr.type"));
                }
            }
                break;
            default:
                RETURN_ERROR(MINOR, E_INVALID_SELECTION,
                             ("Unknown insrtParams.type"));
        }
    }

    if (p_FmPcdManipParams->u.hdr.fieldUpdate)
    {
        switch (p_FmPcdManipParams->u.hdr.fieldUpdateParams.type)
        {
            case (e_FM_PCD_MANIP_HDR_FIELD_UPDATE_VLAN):
                tableSize += HMCD_BASIC_SIZE;
                if (p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.vlan.updateType
                        == e_FM_PCD_MANIP_HDR_FIELD_UPDATE_DSCP_TO_VLAN)
                {
                    tableSize += HMCD_PTR_SIZE;
                    dataSize += DSCP_TO_VLAN_TABLE_SIZE;
                }
                break;
            case (e_FM_PCD_MANIP_HDR_FIELD_UPDATE_IPV4):
                tableSize += HMCD_BASIC_SIZE;
                if (p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.ipv4.validUpdates
                        & HDR_MANIP_IPV4_ID)
                {
                    tableSize += HMCD_PARAM_SIZE;
                    dataSize += 2;
                }
                if (p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.ipv4.validUpdates
                        & HDR_MANIP_IPV4_SRC)
                    tableSize += HMCD_IPV4_ADDR_SIZE;
                if (p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.ipv4.validUpdates
                        & HDR_MANIP_IPV4_DST)
                    tableSize += HMCD_IPV4_ADDR_SIZE;
                break;
            case (e_FM_PCD_MANIP_HDR_FIELD_UPDATE_IPV6):
                tableSize += HMCD_BASIC_SIZE;
                if (p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.ipv4.validUpdates
                        & HDR_MANIP_IPV6_SRC)
                    tableSize += HMCD_IPV6_ADDR_SIZE;
                if (p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.ipv4.validUpdates
                        & HDR_MANIP_IPV6_DST)
                    tableSize += HMCD_IPV6_ADDR_SIZE;
                break;
            case (e_FM_PCD_MANIP_HDR_FIELD_UPDATE_TCP_UDP):
                if (p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.tcpUdp.validUpdates
                        == HDR_MANIP_TCP_UDP_CHECKSUM)
                    /* we implement this case with the update-checksum descriptor */
                    tableSize += HMCD_BASIC_SIZE;
                else
                    /* we implement this case with the TCP/UDP-update descriptor */
                    tableSize += HMCD_BASIC_SIZE + HMCD_PARAM_SIZE;
                break;
            default:
                RETURN_ERROR(MINOR, E_INVALID_SELECTION,
                             ("Unknown fieldUpdateParams.type"));
        }
    }

    if (p_FmPcdManipParams->u.hdr.custom)
    {
        switch (p_FmPcdManipParams->u.hdr.customParams.type)
        {
            case (e_FM_PCD_MANIP_HDR_CUSTOM_IP_REPLACE):
            {
                tableSize += HMCD_BASIC_SIZE + HMCD_PARAM_SIZE + HMCD_PARAM_SIZE;
                dataSize +=
                        p_FmPcdManipParams->u.hdr.customParams.u.ipHdrReplace.hdrSize;
                if ((p_FmPcdManipParams->u.hdr.customParams.u.ipHdrReplace.replaceType
                        == e_FM_PCD_MANIP_HDR_CUSTOM_REPLACE_IPV6_BY_IPV4)
                        && (p_FmPcdManipParams->u.hdr.customParams.u.ipHdrReplace.updateIpv4Id))
                    dataSize += 2;
            }
                break;
            case (e_FM_PCD_MANIP_HDR_CUSTOM_GEN_FIELD_REPLACE):
                tableSize += HMCD_BASIC_SIZE + HMCD_PARAM_SIZE;
            break;
            default:
                RETURN_ERROR(MINOR, E_INVALID_SELECTION,
                             ("Unknown customParams.type"));
        }
    }

    *p_TableSize = tableSize;
    *p_DataSize = dataSize;

    return E_OK;
}

static t_Error GetPrOffsetByHeaderOrField(t_FmManipHdrInfo *p_HdrInfo,
                                          uint8_t *parseArrayOffset)
{
    e_NetHeaderType hdr = p_HdrInfo->hdr;
    e_FmPcdHdrIndex hdrIndex = p_HdrInfo->hdrIndex;
    bool byField = p_HdrInfo->byField;
    t_FmPcdFields field;

    if (byField)
        field = p_HdrInfo->fullField;

    if (byField)
    {
        switch (hdr)
        {
            case (HEADER_TYPE_ETH):
                switch (field.eth)
                {
                    case (NET_HEADER_FIELD_ETH_TYPE):
                        *parseArrayOffset = CC_PC_PR_ETYPE_LAST_OFFSET;
                        break;
                    default:
                        RETURN_ERROR(
                                MAJOR,
                                E_NOT_SUPPORTED,
                                ("Header manipulation of the type Ethernet with this field not supported"));
                }
                break;
            case (HEADER_TYPE_VLAN):
                switch (field.vlan)
                {
                    case (NET_HEADER_FIELD_VLAN_TCI):
                        if ((hdrIndex == e_FM_PCD_HDR_INDEX_NONE)
                                || (hdrIndex == e_FM_PCD_HDR_INDEX_1))
                            *parseArrayOffset = CC_PC_PR_VLAN1_OFFSET;
                        else
                            if (hdrIndex == e_FM_PCD_HDR_INDEX_LAST)
                                *parseArrayOffset = CC_PC_PR_VLAN2_OFFSET;
                        break;
                    default:
                        RETURN_ERROR(
                                MAJOR,
                                E_NOT_SUPPORTED,
                                ("Header manipulation of the type VLAN with this field not supported"));
                }
                break;
            default:
                RETURN_ERROR(
                        MAJOR,
                        E_NOT_SUPPORTED,
                        ("Header manipulation of this header by field not supported"));
        }
    }
    else
    {
        switch (hdr)
        {
            case (HEADER_TYPE_ETH):
                *parseArrayOffset = (uint8_t)CC_PC_PR_ETH_OFFSET;
                break;
            case (HEADER_TYPE_USER_DEFINED_SHIM1):
                *parseArrayOffset = (uint8_t)CC_PC_PR_USER_DEFINED_SHIM1_OFFSET;
                break;
            case (HEADER_TYPE_USER_DEFINED_SHIM2):
                *parseArrayOffset = (uint8_t)CC_PC_PR_USER_DEFINED_SHIM2_OFFSET;
                break;
            case (HEADER_TYPE_LLC_SNAP):
                *parseArrayOffset = CC_PC_PR_USER_LLC_SNAP_OFFSET;
                break;
            case (HEADER_TYPE_PPPoE):
                *parseArrayOffset = CC_PC_PR_PPPOE_OFFSET;
                break;
            case (HEADER_TYPE_MPLS):
                if ((hdrIndex == e_FM_PCD_HDR_INDEX_NONE)
                        || (hdrIndex == e_FM_PCD_HDR_INDEX_1))
                    *parseArrayOffset = CC_PC_PR_MPLS1_OFFSET;
                else
                    if (hdrIndex == e_FM_PCD_HDR_INDEX_LAST)
                        *parseArrayOffset = CC_PC_PR_MPLS_LAST_OFFSET;
                break;
            case (HEADER_TYPE_IPv4):
            case (HEADER_TYPE_IPv6):
                if ((hdrIndex == e_FM_PCD_HDR_INDEX_NONE)
                        || (hdrIndex == e_FM_PCD_HDR_INDEX_1))
                    *parseArrayOffset = CC_PC_PR_IP1_OFFSET;
                else
                    if (hdrIndex == e_FM_PCD_HDR_INDEX_2)
                        *parseArrayOffset = CC_PC_PR_IP_LAST_OFFSET;
                break;
            case (HEADER_TYPE_MINENCAP):
                *parseArrayOffset = CC_PC_PR_MINENC_OFFSET;
                break;
            case (HEADER_TYPE_GRE):
                *parseArrayOffset = CC_PC_PR_GRE_OFFSET;
                break;
            case (HEADER_TYPE_TCP):
            case (HEADER_TYPE_UDP):
            case (HEADER_TYPE_IPSEC_AH):
            case (HEADER_TYPE_IPSEC_ESP):
            case (HEADER_TYPE_DCCP):
            case (HEADER_TYPE_SCTP):
                *parseArrayOffset = CC_PC_PR_L4_OFFSET;
                break;
            case (HEADER_TYPE_CAPWAP):
            case (HEADER_TYPE_CAPWAP_DTLS):
                *parseArrayOffset = CC_PC_PR_NEXT_HEADER_OFFSET;
                break;
            default:
                RETURN_ERROR(
                        MAJOR,
                        E_NOT_SUPPORTED,
                        ("Header manipulation of this header is not supported"));
        }
    }
    return E_OK;
}

static t_Error BuildHmct(t_FmPcdManip *p_Manip,
                         t_FmPcdManipParams *p_FmPcdManipParams,
                         uint8_t *p_DestHmct, uint8_t *p_DestData, bool new)
{
    uint32_t *p_TmpHmct = (uint32_t*)p_DestHmct, *p_LocalData;
    uint32_t tmpReg = 0, *p_Last = NULL, tmp_ipv6_addr;
    uint8_t remain, i, size = 0, origSize, *p_UsrData = NULL, *p_TmpData =
            p_DestData;
    t_Handle h_FmPcd = p_Manip->h_FmPcd;
    uint8_t j = 0;

    if (p_FmPcdManipParams->u.hdr.rmv)
    {
        if (p_FmPcdManipParams->u.hdr.rmvParams.type
                == e_FM_PCD_MANIP_RMV_GENERIC)
        {
            /* initialize HMCD */
            tmpReg = (uint32_t)(HMCD_OPCODE_GENERIC_RMV) << HMCD_OC_SHIFT;
            /* tmp, should be conditional */
            tmpReg |= p_FmPcdManipParams->u.hdr.rmvParams.u.generic.offset
                    << HMCD_RMV_OFFSET_SHIFT;
            tmpReg |= p_FmPcdManipParams->u.hdr.rmvParams.u.generic.size
                    << HMCD_RMV_SIZE_SHIFT;
        }
        else
            if (p_FmPcdManipParams->u.hdr.rmvParams.type
                    == e_FM_PCD_MANIP_RMV_BY_HDR)
            {
                switch (p_FmPcdManipParams->u.hdr.rmvParams.u.byHdr.type)
                {
                    case (e_FM_PCD_MANIP_RMV_BY_HDR_SPECIFIC_L2):
                    {
                        uint8_t hmcdOpt;

                        /* initialize HMCD */
                        tmpReg = (uint32_t)(HMCD_OPCODE_L2_RMV) << HMCD_OC_SHIFT;

                        switch (p_FmPcdManipParams->u.hdr.rmvParams.u.byHdr.u.specificL2)
                        {
                            case (e_FM_PCD_MANIP_HDR_RMV_ETHERNET):
                                hmcdOpt = HMCD_RMV_L2_ETHERNET;
                                break;
                            case (e_FM_PCD_MANIP_HDR_RMV_STACKED_QTAGS):
                                hmcdOpt = HMCD_RMV_L2_STACKED_QTAGS;
                                break;
                            case (e_FM_PCD_MANIP_HDR_RMV_ETHERNET_AND_MPLS):
                                hmcdOpt = HMCD_RMV_L2_ETHERNET_AND_MPLS;
                                break;
                            case (e_FM_PCD_MANIP_HDR_RMV_MPLS):
                                hmcdOpt = HMCD_RMV_L2_MPLS;
                                break;
                            case (e_FM_PCD_MANIP_HDR_RMV_PPPOE):
                                hmcdOpt = HMCD_RMV_L2_PPPOE;
                                break;
                            default:
                                RETURN_ERROR(MINOR, E_NOT_SUPPORTED, NO_MSG);
                        }
                        tmpReg |= hmcdOpt << HMCD_L2_MODE_SHIFT;
                        break;
                    }
                    case (e_FM_PCD_MANIP_RMV_BY_HDR_CAPWAP):
                        tmpReg = (uint32_t)(HMCD_OPCODE_CAPWAP_RMV)
                                << HMCD_OC_SHIFT;
                        break;
                    case (e_FM_PCD_MANIP_RMV_BY_HDR_FROM_START):
                    {
                        uint8_t prsArrayOffset = 0;
                        t_Error err = E_OK;

                        tmpReg = (uint32_t)(HMCD_OPCODE_RMV_TILL)
                                << HMCD_OC_SHIFT;

                        err =
                                GetPrOffsetByHeaderOrField(
                                        &p_FmPcdManipParams->u.hdr.rmvParams.u.byHdr.u.hdrInfo,
                                        &prsArrayOffset);
                        ASSERT_COND(!err);
                        /* was previously checked */

                        tmpReg |= ((uint32_t)prsArrayOffset << 16);
                    }
                        break;
                    default:
                        RETURN_ERROR(MINOR, E_NOT_SUPPORTED,
                                     ("manip header remove by hdr type!"));
                }
            }

        WRITE_UINT32(*p_TmpHmct, tmpReg);
        /* save a pointer to the "last" indication word */
        p_Last = p_TmpHmct;
        /* advance to next command */
        p_TmpHmct += HMCD_BASIC_SIZE / 4;
    }

    if (p_FmPcdManipParams->u.hdr.insrt)
    {
        if (p_FmPcdManipParams->u.hdr.insrtParams.type
                == e_FM_PCD_MANIP_INSRT_GENERIC)
        {
            /* initialize HMCD */
            if (p_FmPcdManipParams->u.hdr.insrtParams.u.generic.replace)
                tmpReg = (uint32_t)(HMCD_OPCODE_GENERIC_REPLACE)
                        << HMCD_OC_SHIFT;
            else
                tmpReg = (uint32_t)(HMCD_OPCODE_GENERIC_INSRT) << HMCD_OC_SHIFT;

            tmpReg |= p_FmPcdManipParams->u.hdr.insrtParams.u.generic.offset
                    << HMCD_INSRT_OFFSET_SHIFT;
            tmpReg |= p_FmPcdManipParams->u.hdr.insrtParams.u.generic.size
                    << HMCD_INSRT_SIZE_SHIFT;

            size = p_FmPcdManipParams->u.hdr.insrtParams.u.generic.size;
            p_UsrData = p_FmPcdManipParams->u.hdr.insrtParams.u.generic.p_Data;

            WRITE_UINT32(*p_TmpHmct, tmpReg);
            /* save a pointer to the "last" indication word */
            p_Last = p_TmpHmct;

            p_TmpHmct += HMCD_BASIC_SIZE / 4;

            /* initialize data to be inserted */
            /* if size is not a multiple of 4, padd with 0's */
            origSize = size;
            remain = (uint8_t)(size % 4);
            if (remain)
            {
                size += (uint8_t)(4 - remain);
                p_LocalData = (uint32_t *)XX_Malloc(size);
                memset((uint8_t *)p_LocalData, 0, size);
                memcpy((uint8_t *)p_LocalData, p_UsrData, origSize);
            }
            else
                p_LocalData = (uint32_t*)p_UsrData;

            /* initialize data and advance pointer to next command */
            MemCpy8(p_TmpHmct, p_LocalData, size);
            p_TmpHmct += size / sizeof(uint32_t);

            if (remain)
                XX_Free(p_LocalData);
        }

        else
            if (p_FmPcdManipParams->u.hdr.insrtParams.type
                    == e_FM_PCD_MANIP_INSRT_BY_HDR)
            {
                switch (p_FmPcdManipParams->u.hdr.insrtParams.u.byHdr.type)
                {
                    case (e_FM_PCD_MANIP_INSRT_BY_HDR_SPECIFIC_L2):
                    {
                        uint8_t hmcdOpt;

                        /* initialize HMCD */
                        tmpReg = (uint32_t)(HMCD_OPCODE_L2_INSRT)
                                << HMCD_OC_SHIFT;

                        switch (p_FmPcdManipParams->u.hdr.insrtParams.u.byHdr.u.specificL2Params.specificL2)
                        {
                            case (e_FM_PCD_MANIP_HDR_INSRT_MPLS):
                                if (p_FmPcdManipParams->u.hdr.insrtParams.u.byHdr.u.specificL2Params.update)
                                    hmcdOpt = HMCD_INSRT_N_UPDATE_L2_MPLS;
                                else
                                    hmcdOpt = HMCD_INSRT_L2_MPLS;
                                break;
                            case (e_FM_PCD_MANIP_HDR_INSRT_PPPOE):
                                hmcdOpt = HMCD_INSRT_L2_PPPOE;
                                break;
                            default:
                                RETURN_ERROR(MINOR, E_NOT_SUPPORTED, NO_MSG);
                        }
                        tmpReg |= hmcdOpt << HMCD_L2_MODE_SHIFT;

                        WRITE_UINT32(*p_TmpHmct, tmpReg);
                        /* save a pointer to the "last" indication word */
                        p_Last = p_TmpHmct;

                        p_TmpHmct += HMCD_BASIC_SIZE / 4;

                        /* set size and pointer of user's data */
                        size =
                                (uint8_t)p_FmPcdManipParams->u.hdr.insrtParams.u.byHdr.u.specificL2Params.size;

                        ASSERT_COND(p_TmpData);
                        MemCpy8(
                                p_TmpData,
                                p_FmPcdManipParams->u.hdr.insrtParams.u.byHdr.u.specificL2Params.p_Data,
                                size);
                        tmpReg =
                                (size << HMCD_INSRT_L2_SIZE_SHIFT)
                                        | (uint32_t)(XX_VirtToPhys(p_TmpData)
                                                - (((t_FmPcd*)h_FmPcd)->physicalMuramBase));
                        WRITE_UINT32(*p_TmpHmct, tmpReg);
                        p_TmpHmct += HMCD_PTR_SIZE / 4;
                        p_TmpData += size;
                    }
                        break;
                    case (e_FM_PCD_MANIP_INSRT_BY_HDR_IP):
                        tmpReg = (uint32_t)(HMCD_OPCODE_IP_INSRT)
                                << HMCD_OC_SHIFT;
                        if (p_FmPcdManipParams->u.hdr.insrtParams.u.byHdr.u.ipParams.calcL4Checksum)
                            tmpReg |= HMCD_IP_L4_CS_CALC;
                        if (p_FmPcdManipParams->u.hdr.insrtParams.u.byHdr.u.ipParams.mappingMode
                                == e_FM_PCD_MANIP_HDR_QOS_MAPPING_AS_IS)
                            tmpReg |= HMCD_IP_OR_QOS;
                        tmpReg |=
                                p_FmPcdManipParams->u.hdr.insrtParams.u.byHdr.u.ipParams.lastPidOffset
                                        & HMCD_IP_LAST_PID_MASK;
                        tmpReg |=
                                ((p_FmPcdManipParams->u.hdr.insrtParams.u.byHdr.u.ipParams.insrt.size
                                        << HMCD_IP_SIZE_SHIFT)
                                        & HMCD_IP_SIZE_MASK);
                        if (p_FmPcdManipParams->u.hdr.insrtParams.u.byHdr.u.ipParams.dontFragOverwrite)
                            tmpReg |= HMCD_IP_DF_MODE;

                        WRITE_UINT32(*p_TmpHmct, tmpReg);

                        /* save a pointer to the "last" indication word */
                        p_Last = p_TmpHmct;

                        p_TmpHmct += HMCD_BASIC_SIZE / 4;

                        /* set IP id */
                        ASSERT_COND(p_TmpData);
                        WRITE_UINT16(
                                *(uint16_t*)p_TmpData,
                                p_FmPcdManipParams->u.hdr.insrtParams.u.byHdr.u.ipParams.id);
                        WRITE_UINT32(
                                *p_TmpHmct,
                                (uint32_t)(XX_VirtToPhys(p_TmpData) - (((t_FmPcd*)p_Manip->h_FmPcd)->physicalMuramBase)));
                        p_TmpData += 2;
                        p_TmpHmct += HMCD_PTR_SIZE / 4;

                        WRITE_UINT8(*p_TmpHmct, p_FmPcdManipParams->u.hdr.insrtParams.u.byHdr.u.ipParams.lastDstOffset);
                        p_TmpHmct += HMCD_PARAM_SIZE / 4;

                        MemCpy8(
                                p_TmpHmct,
                                p_FmPcdManipParams->u.hdr.insrtParams.u.byHdr.u.ipParams.insrt.p_Data,
                                p_FmPcdManipParams->u.hdr.insrtParams.u.byHdr.u.ipParams.insrt.size);
                        p_TmpHmct +=
                                p_FmPcdManipParams->u.hdr.insrtParams.u.byHdr.u.ipParams.insrt.size
                                        / 4;
                        break;
                    case (e_FM_PCD_MANIP_INSRT_BY_HDR_UDP_LITE):
                        tmpReg = HMCD_INSRT_UDP_LITE;
                        fallthrough;
                    case (e_FM_PCD_MANIP_INSRT_BY_HDR_UDP):
                        tmpReg |= (uint32_t)(HMCD_OPCODE_UDP_INSRT)
                                << HMCD_OC_SHIFT;

                        WRITE_UINT32(*p_TmpHmct, tmpReg);

                        /* save a pointer to the "last" indication word */
                        p_Last = p_TmpHmct;

                        p_TmpHmct += HMCD_BASIC_SIZE / 4;

                        MemCpy8(
                                p_TmpHmct,
                                p_FmPcdManipParams->u.hdr.insrtParams.u.byHdr.u.insrt.p_Data,
                                p_FmPcdManipParams->u.hdr.insrtParams.u.byHdr.u.insrt.size);
                        p_TmpHmct +=
                                p_FmPcdManipParams->u.hdr.insrtParams.u.byHdr.u.insrt.size
                                        / 4;
                        break;
                    case (e_FM_PCD_MANIP_INSRT_BY_HDR_CAPWAP):
                        tmpReg = (uint32_t)(HMCD_OPCODE_CAPWAP_INSRT)
                                << HMCD_OC_SHIFT;
                        tmpReg |= HMCD_CAPWAP_INSRT;

                        WRITE_UINT32(*p_TmpHmct, tmpReg);

                        /* save a pointer to the "last" indication word */
                        p_Last = p_TmpHmct;

                        p_TmpHmct += HMCD_BASIC_SIZE / 4;

                        MemCpy8(
                                p_TmpHmct,
                                p_FmPcdManipParams->u.hdr.insrtParams.u.byHdr.u.insrt.p_Data,
                                p_FmPcdManipParams->u.hdr.insrtParams.u.byHdr.u.insrt.size);
                        p_TmpHmct +=
                                p_FmPcdManipParams->u.hdr.insrtParams.u.byHdr.u.insrt.size
                                        / 4;
                        break;
                    default:
                        RETURN_ERROR(MINOR, E_NOT_SUPPORTED,
                                     ("manip header insert by header type!"));

                }
            }
    }

    if (p_FmPcdManipParams->u.hdr.fieldUpdate)
    {
        switch (p_FmPcdManipParams->u.hdr.fieldUpdateParams.type)
        {
            case (e_FM_PCD_MANIP_HDR_FIELD_UPDATE_VLAN):
                /* set opcode */
                tmpReg = (uint32_t)(HMCD_OPCODE_VLAN_PRI_UPDATE)
                        << HMCD_OC_SHIFT;

                /* set mode & table pointer */
                if (p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.vlan.updateType
                        == e_FM_PCD_MANIP_HDR_FIELD_UPDATE_DSCP_TO_VLAN)
                {
                    /* set Mode */
                    tmpReg |= (uint32_t)(HMCD_VLAN_PRI_UPDATE_DSCP_TO_VPRI)
                            << HMCD_VLAN_PRI_REP_MODE_SHIFT;
                    /* set VPRI default */
                    tmpReg |=
                            p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.vlan.u.dscpToVpri.vpriDefVal;
                    WRITE_UINT32(*p_TmpHmct, tmpReg);
                    /* save a pointer to the "last" indication word */
                    p_Last = p_TmpHmct;
                    /* write the table pointer into the Manip descriptor */
                    p_TmpHmct += HMCD_BASIC_SIZE / 4;

                    tmpReg = 0;
                    ASSERT_COND(p_TmpData);
                    for (i = 0; i < HMCD_DSCP_VALUES; i++)
                    {
                        /* first we build from each 8 values a 32bit register */
                        tmpReg |=
                                (p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.vlan.u.dscpToVpri.dscpToVpriTable[i])
                                        << (32 - 4 * (j + 1));
                        j++;
                        /* Than we write this register to the next table word
                         * (i=7-->word 0, i=15-->word 1,... i=63-->word 7) */
                        if ((i % 8) == 7)
                        {
                            WRITE_UINT32(*((uint32_t*)p_TmpData + (i+1)/8-1),
                                         tmpReg);
                            tmpReg = 0;
                            j = 0;
                        }
                    }

                    WRITE_UINT32(
                            *p_TmpHmct,
                            (uint32_t)(XX_VirtToPhys(p_TmpData) - (((t_FmPcd*)h_FmPcd)->physicalMuramBase)));
                    p_TmpHmct += HMCD_PTR_SIZE / 4;

                    p_TmpData += DSCP_TO_VLAN_TABLE_SIZE;
                }
                else
                    if (p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.vlan.updateType
                            == e_FM_PCD_MANIP_HDR_FIELD_UPDATE_VLAN_VPRI)
                    {
                        /* set Mode */
                        /* line commented out as it has no-side-effect ('0' value). */
                        /*tmpReg |= HMCD_VLAN_PRI_UPDATE << HMCD_VLAN_PRI_REP_MODE_SHIFT*/;
                        /* set VPRI parameter */
                        tmpReg |=
                                p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.vlan.u.vpri;
                        WRITE_UINT32(*p_TmpHmct, tmpReg);
                        /* save a pointer to the "last" indication word */
                        p_Last = p_TmpHmct;
                        p_TmpHmct += HMCD_BASIC_SIZE / 4;
                    }
                break;

            case (e_FM_PCD_MANIP_HDR_FIELD_UPDATE_IPV4):
                /* set opcode */
                tmpReg = (uint32_t)(HMCD_OPCODE_IPV4_UPDATE) << HMCD_OC_SHIFT;
                if (p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.ipv4.validUpdates
                        & HDR_MANIP_IPV4_TTL)
                    tmpReg |= HMCD_IPV4_UPDATE_TTL;
                if (p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.ipv4.validUpdates
                        & HDR_MANIP_IPV4_TOS)
                {
                    tmpReg |= HMCD_IPV4_UPDATE_TOS;
                    tmpReg |=
                            p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.ipv4.tos
                                    << HMCD_IPV4_UPDATE_TOS_SHIFT;
                }
                if (p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.ipv4.validUpdates
                        & HDR_MANIP_IPV4_ID)
                    tmpReg |= HMCD_IPV4_UPDATE_ID;
                if (p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.ipv4.validUpdates
                        & HDR_MANIP_IPV4_SRC)
                    tmpReg |= HMCD_IPV4_UPDATE_SRC;
                if (p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.ipv4.validUpdates
                        & HDR_MANIP_IPV4_DST)
                    tmpReg |= HMCD_IPV4_UPDATE_DST;
                /* write the first 4 bytes of the descriptor */
                WRITE_UINT32(*p_TmpHmct, tmpReg);
                /* save a pointer to the "last" indication word */
                p_Last = p_TmpHmct;

                p_TmpHmct += HMCD_BASIC_SIZE / 4;

                if (p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.ipv4.validUpdates
                        & HDR_MANIP_IPV4_ID)
                {
                    ASSERT_COND(p_TmpData);
                    WRITE_UINT16(
                            *(uint16_t*)p_TmpData,
                            p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.ipv4.id);
                    WRITE_UINT32(
                            *p_TmpHmct,
                            (uint32_t)(XX_VirtToPhys(p_TmpData) - (((t_FmPcd*)p_Manip->h_FmPcd)->physicalMuramBase)));
                    p_TmpData += 2;
                    p_TmpHmct += HMCD_PTR_SIZE / 4;
                }

                if (p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.ipv4.validUpdates
                        & HDR_MANIP_IPV4_SRC)
                {
                    WRITE_UINT32(
                            *p_TmpHmct,
                            p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.ipv4.src);
                    p_TmpHmct += HMCD_IPV4_ADDR_SIZE / 4;
                }

                if (p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.ipv4.validUpdates
                        & HDR_MANIP_IPV4_DST)
                {
                    WRITE_UINT32(
                            *p_TmpHmct,
                            p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.ipv4.dst);
                    p_TmpHmct += HMCD_IPV4_ADDR_SIZE / 4;
                }
                break;

            case (e_FM_PCD_MANIP_HDR_FIELD_UPDATE_IPV6):
                /* set opcode */
                tmpReg = (uint32_t)(HMCD_OPCODE_IPV6_UPDATE) << HMCD_OC_SHIFT;
                if (p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.ipv6.validUpdates
                        & HDR_MANIP_IPV6_HL)
                    tmpReg |= HMCD_IPV6_UPDATE_HL;
                if (p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.ipv6.validUpdates
                        & HDR_MANIP_IPV6_TC)
                {
                    tmpReg |= HMCD_IPV6_UPDATE_TC;
                    tmpReg |=
                            p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.ipv6.trafficClass
                                    << HMCD_IPV6_UPDATE_TC_SHIFT;
                }
                if (p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.ipv6.validUpdates
                        & HDR_MANIP_IPV6_SRC)
                    tmpReg |= HMCD_IPV6_UPDATE_SRC;
                if (p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.ipv6.validUpdates
                        & HDR_MANIP_IPV6_DST)
                    tmpReg |= HMCD_IPV6_UPDATE_DST;
                /* write the first 4 bytes of the descriptor */
                WRITE_UINT32(*p_TmpHmct, tmpReg);
                /* save a pointer to the "last" indication word */
                p_Last = p_TmpHmct;

                p_TmpHmct += HMCD_BASIC_SIZE / 4;
                if (p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.ipv6.validUpdates
                        & HDR_MANIP_IPV6_SRC)
                {
                    for (i = 0; i < NET_HEADER_FIELD_IPv6_ADDR_SIZE; i += 4)
                    {
                        memcpy(&tmp_ipv6_addr,
                               &p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.ipv6.src[i],
                               sizeof(uint32_t));
                        WRITE_UINT32(*p_TmpHmct, tmp_ipv6_addr);
                        p_TmpHmct += HMCD_PTR_SIZE / 4;
                    }
                }
                if (p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.ipv6.validUpdates
                        & HDR_MANIP_IPV6_DST)
                {
                    for (i = 0; i < NET_HEADER_FIELD_IPv6_ADDR_SIZE; i += 4)
                    {
                        memcpy(&tmp_ipv6_addr,
                               &p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.ipv6.dst[i],
                               sizeof(uint32_t));
                        WRITE_UINT32(*p_TmpHmct, tmp_ipv6_addr);
                        p_TmpHmct += HMCD_PTR_SIZE / 4;
                    }
                }
                break;

            case (e_FM_PCD_MANIP_HDR_FIELD_UPDATE_TCP_UDP):
                if (p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.tcpUdp.validUpdates
                        == HDR_MANIP_TCP_UDP_CHECKSUM)
                {
                    /* we implement this case with the update-checksum descriptor */
                    /* set opcode */
                    tmpReg = (uint32_t)(HMCD_OPCODE_TCP_UDP_CHECKSUM)
                            << HMCD_OC_SHIFT;
                    /* write the first 4 bytes of the descriptor */
                    WRITE_UINT32(*p_TmpHmct, tmpReg);
                    /* save a pointer to the "last" indication word */
                    p_Last = p_TmpHmct;

                    p_TmpHmct += HMCD_BASIC_SIZE / 4;
                }
                else
                {
                    /* we implement this case with the TCP/UDP update descriptor */
                    /* set opcode */
                    tmpReg = (uint32_t)(HMCD_OPCODE_TCP_UDP_UPDATE)
                            << HMCD_OC_SHIFT;
                    if (p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.tcpUdp.validUpdates
                            & HDR_MANIP_TCP_UDP_DST)
                        tmpReg |= HMCD_TCP_UDP_UPDATE_DST;
                    if (p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.tcpUdp.validUpdates
                            & HDR_MANIP_TCP_UDP_SRC)
                        tmpReg |= HMCD_TCP_UDP_UPDATE_SRC;
                    /* write the first 4 bytes of the descriptor */
                    WRITE_UINT32(*p_TmpHmct, tmpReg);
                    /* save a pointer to the "last" indication word */
                    p_Last = p_TmpHmct;

                    p_TmpHmct += HMCD_BASIC_SIZE / 4;

                    tmpReg = 0;
                    if (p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.tcpUdp.validUpdates
                            & HDR_MANIP_TCP_UDP_SRC)
                        tmpReg |=
                                ((uint32_t)p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.tcpUdp.src)
                                        << HMCD_TCP_UDP_UPDATE_SRC_SHIFT;
                    if (p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.tcpUdp.validUpdates
                            & HDR_MANIP_TCP_UDP_DST)
                        tmpReg |=
                                ((uint32_t)p_FmPcdManipParams->u.hdr.fieldUpdateParams.u.tcpUdp.dst);
                    WRITE_UINT32(*p_TmpHmct, tmpReg);
                    p_TmpHmct += HMCD_PTR_SIZE / 4;
                }
                break;

            default:
                RETURN_ERROR(MINOR, E_INVALID_SELECTION,
                             ("Unknown fieldUpdateParams.type"));
        }
    }

    if (p_FmPcdManipParams->u.hdr.custom)
    {
        switch (p_FmPcdManipParams->u.hdr.customParams.type)
        {
            case (e_FM_PCD_MANIP_HDR_CUSTOM_IP_REPLACE):
                /* set opcode */
                tmpReg = (uint32_t)(HMCD_OPCODE_REPLACE_IP) << HMCD_OC_SHIFT;

                if (p_FmPcdManipParams->u.hdr.customParams.u.ipHdrReplace.decTtlHl)
                    tmpReg |= HMCD_IP_REPLACE_TTL_HL;
                if (p_FmPcdManipParams->u.hdr.customParams.u.ipHdrReplace.replaceType
                        == e_FM_PCD_MANIP_HDR_CUSTOM_REPLACE_IPV4_BY_IPV6)
                    /* line commented out as it has no-side-effect ('0' value). */
                    /*tmpReg |= HMCD_IP_REPLACE_REPLACE_IPV4*/;
                else
                    if (p_FmPcdManipParams->u.hdr.customParams.u.ipHdrReplace.replaceType
                            == e_FM_PCD_MANIP_HDR_CUSTOM_REPLACE_IPV6_BY_IPV4)
                    {
                        tmpReg |= HMCD_IP_REPLACE_REPLACE_IPV6;
                        if (p_FmPcdManipParams->u.hdr.customParams.u.ipHdrReplace.updateIpv4Id)
                            tmpReg |= HMCD_IP_REPLACE_ID;
                    }
                    else
                        RETURN_ERROR(
                                MINOR,
                                E_NOT_SUPPORTED,
                                ("One flag out of HDR_MANIP_IP_REPLACE_IPV4, HDR_MANIP_IP_REPLACE_IPV6 - must be set."));

                /* write the first 4 bytes of the descriptor */
                WRITE_UINT32(*p_TmpHmct, tmpReg);
                /* save a pointer to the "last" indication word */
                p_Last = p_TmpHmct;

                p_TmpHmct += HMCD_BASIC_SIZE / 4;

                size =
                        p_FmPcdManipParams->u.hdr.customParams.u.ipHdrReplace.hdrSize;
                ASSERT_COND(p_TmpData);
                MemCpy8(
                        p_TmpData,
                        p_FmPcdManipParams->u.hdr.customParams.u.ipHdrReplace.hdr,
                        size);
                tmpReg = (uint32_t)(size << HMCD_IP_REPLACE_L3HDRSIZE_SHIFT);
                tmpReg |= (uint32_t)(XX_VirtToPhys(p_TmpData)
                        - (((t_FmPcd*)h_FmPcd)->physicalMuramBase));
                WRITE_UINT32(*p_TmpHmct, tmpReg);
                p_TmpHmct += HMCD_PTR_SIZE / 4;
                p_TmpData += size;

                if ((p_FmPcdManipParams->u.hdr.customParams.u.ipHdrReplace.replaceType
                        == e_FM_PCD_MANIP_HDR_CUSTOM_REPLACE_IPV6_BY_IPV4)
                        && (p_FmPcdManipParams->u.hdr.customParams.u.ipHdrReplace.updateIpv4Id))
                {
                    WRITE_UINT16(
                            *(uint16_t*)p_TmpData,
                            p_FmPcdManipParams->u.hdr.customParams.u.ipHdrReplace.id);
                    WRITE_UINT32(
                            *p_TmpHmct,
                            (uint32_t)(XX_VirtToPhys(p_TmpData) - (((t_FmPcd*)h_FmPcd)->physicalMuramBase)));
                    p_TmpData += 2;
                }
                p_TmpHmct += HMCD_PTR_SIZE / 4;
                break;
            case (e_FM_PCD_MANIP_HDR_CUSTOM_GEN_FIELD_REPLACE):
                /* set opcode */
                tmpReg = (uint32_t)(HMCD_OPCODE_GEN_FIELD_REPLACE) << HMCD_OC_SHIFT;
                tmpReg |= p_FmPcdManipParams->u.hdr.customParams.u.genFieldReplace.size << HMCD_GEN_FIELD_SIZE_SHIFT;
                tmpReg |= p_FmPcdManipParams->u.hdr.customParams.u.genFieldReplace.srcOffset << HMCD_GEN_FIELD_SRC_OFF_SHIFT;
                tmpReg |= p_FmPcdManipParams->u.hdr.customParams.u.genFieldReplace.dstOffset << HMCD_GEN_FIELD_DST_OFF_SHIFT;
                if (p_FmPcdManipParams->u.hdr.customParams.u.genFieldReplace.mask)
                    tmpReg |= HMCD_GEN_FIELD_MASK_EN;

                /* write the first 4 bytes of the descriptor */
                WRITE_UINT32(*p_TmpHmct, tmpReg);
                /* save a pointer to the "last" indication word */
                p_Last = p_TmpHmct;

                p_TmpHmct += HMCD_BASIC_SIZE/4;

                if (p_FmPcdManipParams->u.hdr.customParams.u.genFieldReplace.mask)
                {
                    tmpReg = p_FmPcdManipParams->u.hdr.customParams.u.genFieldReplace.mask << HMCD_GEN_FIELD_MASK_SHIFT;
                    tmpReg |= p_FmPcdManipParams->u.hdr.customParams.u.genFieldReplace.maskOffset << HMCD_GEN_FIELD_MASK_OFF_SHIFT;
                    /* write the next 4 bytes of the descriptor */
                    WRITE_UINT32(*p_TmpHmct, tmpReg);
                }
                p_TmpHmct += HMCD_PARAM_SIZE/4;
                break;
            default:
                RETURN_ERROR(MINOR, E_INVALID_SELECTION,
                             ("Unknown customParams.type"));
        }
    }

    /* If this node has a nextManip, and no parsing is required, the old table must be copied to the new table
     the old table and should be freed */
    if (p_FmPcdManipParams->h_NextManip
            && (p_Manip->nextManipType == e_FM_PCD_MANIP_HDR)
            && (MANIP_DONT_REPARSE(p_Manip)))
    {
        if (new)
        {
            /* If this is the first time this manip is created we need to free unused memory. If it
             * is a dynamic changes case, the memory used is either the CC shadow or the existing
             * table - no allocation, no free */
            MANIP_UPDATE_UNIFIED_POSITION(p_FmPcdManipParams->h_NextManip);

            p_Manip->unifiedPosition = e_MANIP_UNIFIED_FIRST;
        }
    }
    else
    {
        ASSERT_COND(p_Last);
        /* set the "last" indication on the last command of the current table */
        WRITE_UINT32(*p_Last, GET_UINT32(*p_Last) | HMCD_LAST);
    }

    return E_OK;
}

static t_Error CreateManipActionNew(t_FmPcdManip *p_Manip,
                                    t_FmPcdManipParams *p_FmPcdManipParams)
{
    t_FmPcdManip *p_CurManip;
    t_Error err;
    uint32_t nextSize = 0, totalSize;
    uint16_t tmpReg;
    uint8_t *p_OldHmct, *p_TmpHmctPtr, *p_TmpDataPtr;

    /* set Manip structure */

    p_Manip->dontParseAfterManip =
            p_FmPcdManipParams->u.hdr.dontParseAfterManip;

    if (p_FmPcdManipParams->h_NextManip)
    {   /* Next Header manipulation exists */
        p_Manip->nextManipType = MANIP_GET_TYPE(p_FmPcdManipParams->h_NextManip);

        if ((p_Manip->nextManipType == e_FM_PCD_MANIP_HDR) && p_Manip->dontParseAfterManip)
            nextSize = (uint32_t)(GetHmctSize(p_FmPcdManipParams->h_NextManip)
                    + GetDataSize(p_FmPcdManipParams->h_NextManip));
        else /* either parsing is required or next manip is Frag; no table merging. */
            p_Manip->cascaded = TRUE;
        /* pass up the "cascaded" attribute. The whole chain is cascaded
         * if something is cascaded along the way. */
        if (MANIP_IS_CASCADED(p_FmPcdManipParams->h_NextManip))
            p_Manip->cascaded = TRUE;
    }

    /* Allocate new table */
    /* calculate table size according to manip parameters */
    err = CalculateTableSize(p_FmPcdManipParams, &p_Manip->tableSize,
                             &p_Manip->dataSize);
    if (err)
        RETURN_ERROR(MINOR, err, NO_MSG);

    totalSize = (uint16_t)(p_Manip->tableSize + p_Manip->dataSize + nextSize);

    p_Manip->p_Hmct = (uint8_t*)FM_MURAM_AllocMem(
            ((t_FmPcd *)p_Manip->h_FmPcd)->h_FmMuram, totalSize, 4);
    if (!p_Manip->p_Hmct)
        RETURN_ERROR(MAJOR, E_NO_MEMORY, ("MURAM alloc failed"));

    if (p_Manip->dataSize)
        p_Manip->p_Data =
                (uint8_t*)PTR_MOVE(p_Manip->p_Hmct, (p_Manip->tableSize + nextSize));

    /* update shadow size to allow runtime replacement of Header manipulation */
    /* The allocated shadow is divided as follows:
     0 . . .       16 . . .
     --------------------------------
     |   Shadow   |   Shadow HMTD   |
     |   HMTD     |   Match Table   |
     | (16 bytes) | (maximal size)  |
     --------------------------------
     */

    err = FmPcdUpdateCcShadow(p_Manip->h_FmPcd, (uint32_t)(totalSize + 16),
                              (uint16_t)FM_PCD_CC_AD_TABLE_ALIGN);
    if (err != E_OK)
    {
        FM_MURAM_FreeMem(p_Manip->h_FmPcd, p_Manip->p_Hmct);
        RETURN_ERROR(MAJOR, E_NO_MEMORY,
                     ("MURAM allocation for HdrManip node shadow"));
    }

    if (p_FmPcdManipParams->h_NextManip
            && (p_Manip->nextManipType == e_FM_PCD_MANIP_HDR)
            && (MANIP_DONT_REPARSE(p_Manip)))
    {
        p_OldHmct = (uint8_t *)GetManipInfo(p_FmPcdManipParams->h_NextManip,
                                            e_MANIP_HMCT);
        p_CurManip = p_FmPcdManipParams->h_NextManip;
        /* Run till the last Manip (which is the first to configure) */
        while (MANIP_IS_UNIFIED_NON_LAST(p_CurManip))
            p_CurManip = p_CurManip->h_NextManip;

        while (p_CurManip)
        {
            /* If this is a unified table, point to the part of the table
             * which is the relative offset in HMCT.
             */
            p_TmpHmctPtr = (uint8_t*)PTR_MOVE(p_Manip->p_Hmct,
                    (p_Manip->tableSize +
                            (PTR_TO_UINT(p_CurManip->p_Hmct) -
                                    PTR_TO_UINT(p_OldHmct))));
            if (p_CurManip->p_Data)
                p_TmpDataPtr = (uint8_t*)PTR_MOVE(p_Manip->p_Hmct,
                        (p_Manip->tableSize +
                                (PTR_TO_UINT(p_CurManip->p_Data) -
                                        PTR_TO_UINT(p_OldHmct))));
            else
                p_TmpDataPtr = NULL;

            BuildHmct(p_CurManip, &p_CurManip->manipParams, p_TmpHmctPtr,
                      p_TmpDataPtr, FALSE);
            /* update old manip table pointer */
            MANIP_SET_HMCT_PTR(p_CurManip, p_TmpHmctPtr);
            MANIP_SET_DATA_PTR(p_CurManip, p_TmpDataPtr);

            p_CurManip = p_CurManip->h_PrevManip;
        }
        /* We copied the HMCT to create a new large HMCT so we can free the old one */
        FM_MURAM_FreeMem(MANIP_GET_MURAM(p_FmPcdManipParams->h_NextManip),
                         p_OldHmct);
    }

    /* Fill table */
    err = BuildHmct(p_Manip, p_FmPcdManipParams, p_Manip->p_Hmct,
                    p_Manip->p_Data, TRUE);
    if (err)
    {
        FM_MURAM_FreeMem(p_Manip->h_FmPcd, p_Manip->p_Hmct);
        RETURN_ERROR(MINOR, err, NO_MSG);
    }

    /* Build HMTD (table descriptor) */
     tmpReg = HMTD_CFG_TYPE; /* NADEN = 0 */

     /* add parseAfterManip */
      if (!p_Manip->dontParseAfterManip)
          tmpReg |= HMTD_CFG_PRS_AFTER_HM;

    /* create cascade */
    /*if (p_FmPcdManipParams->h_NextManip
            && (!MANIP_DONT_REPARSE(p_Manip) || (p_Manip->nextManipType != e_FM_PCD_MANIP_HDR)))*/
    if (p_Manip->cascaded)
    {
        uint16_t nextAd;
        /* indicate that there's another HM table descriptor */
        tmpReg |= HMTD_CFG_NEXT_AD_EN;
        /* get address of next HMTD (table descriptor; h_Ad).
         * If the next HMTD was removed due to table unifing, get the address
         * of the "next next" as written in the h_Ad of the next h_Manip node.
         */
        if (p_Manip->unifiedPosition != e_MANIP_UNIFIED_FIRST)
            nextAd = (uint16_t)((uint32_t)(XX_VirtToPhys(MANIP_GET_HMTD_PTR(p_FmPcdManipParams->h_NextManip)) - (((t_FmPcd*)p_Manip->h_FmPcd)->physicalMuramBase)) >> 4);
        else
            nextAd = ((t_Hmtd *)((t_FmPcdManip *)p_FmPcdManipParams->h_NextManip)->h_Ad)->nextAdIdx;

        WRITE_UINT16(((t_Hmtd *)p_Manip->h_Ad)->nextAdIdx, nextAd);
    }

    WRITE_UINT16(((t_Hmtd *)p_Manip->h_Ad)->cfg, tmpReg);
    WRITE_UINT32(
            ((t_Hmtd *)p_Manip->h_Ad)->hmcdBasePtr,
            (uint32_t)(XX_VirtToPhys(p_Manip->p_Hmct) - (((t_FmPcd*)p_Manip->h_FmPcd)->physicalMuramBase)));

    WRITE_UINT8(((t_Hmtd *)p_Manip->h_Ad)->opCode, HMAN_OC);

    if (p_Manip->unifiedPosition == e_MANIP_UNIFIED_FIRST)
    {
        /* The HMTD of the next Manip is never going to be used */
        if (((t_FmPcdManip *)p_FmPcdManipParams->h_NextManip)->muramAllocate)
            FM_MURAM_FreeMem(
                    ((t_FmPcd *)((t_FmPcdManip *)p_FmPcdManipParams->h_NextManip)->h_FmPcd)->h_FmMuram,
                    ((t_FmPcdManip *)p_FmPcdManipParams->h_NextManip)->h_Ad);
        else
            XX_Free(((t_FmPcdManip *)p_FmPcdManipParams->h_NextManip)->h_Ad);
        ((t_FmPcdManip *)p_FmPcdManipParams->h_NextManip)->h_Ad = NULL;
    }

    return E_OK;
}

static t_Error CreateManipActionShadow(t_FmPcdManip *p_Manip,
                                       t_FmPcdManipParams *p_FmPcdManipParams)
{
    uint8_t *p_WholeHmct, *p_TmpHmctPtr, newDataSize, *p_TmpDataPtr = NULL;
    uint16_t newSize;
    t_FmPcd *p_FmPcd = (t_FmPcd *)p_Manip->h_FmPcd;
    t_Error err;
    t_FmPcdManip *p_CurManip = p_Manip;

    err = CalculateTableSize(p_FmPcdManipParams, &newSize, &newDataSize);
    if (err)
        RETURN_ERROR(MINOR, err, NO_MSG);

    /* check coherency of new table parameters */
    if (newSize > p_Manip->tableSize)
        RETURN_ERROR(
                MINOR,
                E_INVALID_VALUE,
                ("New Hdr Manip configuration requires larger size than current one (command table)."));
    if (newDataSize > p_Manip->dataSize)
        RETURN_ERROR(
                MINOR,
                E_INVALID_VALUE,
                ("New Hdr Manip configuration requires larger size than current one (data)."));
    if (p_FmPcdManipParams->h_NextManip)
        RETURN_ERROR(
                MINOR, E_INVALID_VALUE,
                ("New Hdr Manip configuration can not contain h_NextManip."));
    if (MANIP_IS_UNIFIED(p_Manip) && (newSize != p_Manip->tableSize))
        RETURN_ERROR(
                MINOR,
                E_INVALID_VALUE,
                ("New Hdr Manip configuration in a chained manipulation requires different size than current one."));
    if (p_Manip->dontParseAfterManip
            != p_FmPcdManipParams->u.hdr.dontParseAfterManip)
        RETURN_ERROR(
                MINOR,
                E_INVALID_VALUE,
                ("New Hdr Manip configuration differs in dontParseAfterManip value."));

    p_Manip->tableSize = newSize;
    p_Manip->dataSize = newDataSize;

    /* Build the new table in the shadow */
    if (!MANIP_IS_UNIFIED(p_Manip))
    {
        p_TmpHmctPtr = (uint8_t*)PTR_MOVE(p_FmPcd->p_CcShadow, 16);
        if (p_Manip->p_Data)
            p_TmpDataPtr =
                    (uint8_t*)PTR_MOVE(p_TmpHmctPtr,
                            (PTR_TO_UINT(p_Manip->p_Data) - PTR_TO_UINT(p_Manip->p_Hmct)));

        BuildHmct(p_Manip, p_FmPcdManipParams, p_TmpHmctPtr, p_Manip->p_Data,
                  FALSE);
    }
    else
    {
        p_WholeHmct = (uint8_t *)GetManipInfo(p_Manip, e_MANIP_HMCT);
        ASSERT_COND(p_WholeHmct);

        /* Run till the last Manip (which is the first to configure) */
        while (MANIP_IS_UNIFIED_NON_LAST(p_CurManip))
            p_CurManip = p_CurManip->h_NextManip;

        while (p_CurManip)
        {
            /* If this is a non-head node in a unified table, point to the part of the shadow
             * which is the relative offset in HMCT.
             * else, point to the beginning of the
             * shadow table (we save 16 for the HMTD.
             */
            p_TmpHmctPtr =
                    (uint8_t*)PTR_MOVE(p_FmPcd->p_CcShadow,
                            (16 + PTR_TO_UINT(p_CurManip->p_Hmct) - PTR_TO_UINT(p_WholeHmct)));
            if (p_CurManip->p_Data)
                p_TmpDataPtr =
                        (uint8_t*)PTR_MOVE(p_FmPcd->p_CcShadow,
                                (16 + PTR_TO_UINT(p_CurManip->p_Data) - PTR_TO_UINT(p_WholeHmct)));

            BuildHmct(p_CurManip, &p_CurManip->manipParams, p_TmpHmctPtr,
                      p_TmpDataPtr, FALSE);
            p_CurManip = p_CurManip->h_PrevManip;
        }
    }

    return E_OK;
}

static t_Error CreateManipActionBackToOrig(
        t_FmPcdManip *p_Manip, t_FmPcdManipParams *p_FmPcdManipParams)
{
    uint8_t *p_WholeHmct = NULL, *p_TmpHmctPtr, *p_TmpDataPtr;
    t_FmPcdManip *p_CurManip = p_Manip;

    /* Build the new table in the shadow */
    if (!MANIP_IS_UNIFIED(p_Manip))
        BuildHmct(p_Manip, p_FmPcdManipParams, p_Manip->p_Hmct, p_Manip->p_Data,
                  FALSE);
    else
    {
        p_WholeHmct = (uint8_t *)GetManipInfo(p_Manip, e_MANIP_HMCT);
        ASSERT_COND(p_WholeHmct);

        /* Run till the last Manip (which is the first to configure) */
        while (MANIP_IS_UNIFIED_NON_LAST(p_CurManip))
            p_CurManip = p_CurManip->h_NextManip;

        while (p_CurManip)
        {
            /* If this is a unified table, point to the part of the table
             * which is the relative offset in HMCT.
             */
            p_TmpHmctPtr = p_CurManip->p_Hmct; /*- (uint32_t)p_WholeHmct*/
            p_TmpDataPtr = p_CurManip->p_Data; /*- (uint32_t)p_WholeHmct*/

            BuildHmct(p_CurManip, &p_CurManip->manipParams, p_TmpHmctPtr,
                      p_TmpDataPtr, FALSE);

            p_CurManip = p_CurManip->h_PrevManip;
        }
    }

    return E_OK;
}

static void ReleaseManipHandler(t_FmPcdManip *p_Manip, t_FmPcd *p_FmPcd)
{
    if (p_Manip->h_Ad)
    {
        if (p_Manip->muramAllocate)
            FM_MURAM_FreeMem(p_FmPcd->h_FmMuram, p_Manip->h_Ad);
        else
            XX_Free(p_Manip->h_Ad);
        p_Manip->h_Ad = NULL;
    }
    if (p_Manip->p_Template)
    {
        FM_MURAM_FreeMem(p_FmPcd->h_FmMuram, p_Manip->p_Template);
        p_Manip->p_Template = NULL;
    }
    if (p_Manip->frag)
    {
        if (p_Manip->fragParams.p_Frag)
        {
            FM_MURAM_FreeMem(p_FmPcd->h_FmMuram, p_Manip->fragParams.p_Frag);
        }
    }

    if (p_Manip->p_StatsTbl)
        FM_MURAM_FreeMem(p_FmPcd->h_FmMuram, p_Manip->p_StatsTbl);
}

static t_Error CheckManipParamsAndSetType(t_FmPcdManip *p_Manip,
                                          t_FmPcdManipParams *p_ManipParams)
{
    switch (p_ManipParams->type)
    {
        case e_FM_PCD_MANIP_HDR:
            /* Check that next-manip is not already used */
            if (p_ManipParams->h_NextManip)
            {
                if (!MANIP_IS_FIRST(p_ManipParams->h_NextManip))
                    RETURN_ERROR(
                            MAJOR, E_INVALID_STATE,
                            ("h_NextManip is already a part of another chain"));
                if ((MANIP_GET_TYPE(p_ManipParams->h_NextManip)
                        != e_FM_PCD_MANIP_HDR) &&
                        (MANIP_GET_TYPE(p_ManipParams->h_NextManip)
                        != e_FM_PCD_MANIP_FRAG))
                    RETURN_ERROR(
                            MAJOR,
                            E_NOT_SUPPORTED,
                            ("For a Header Manipulation node - no support of h_NextManip of type other than Header Manipulation or Fragmentation."));
            }

            if (p_ManipParams->u.hdr.rmv)
            {
                switch (p_ManipParams->u.hdr.rmvParams.type)
                {
                    case (e_FM_PCD_MANIP_RMV_BY_HDR):
                        switch (p_ManipParams->u.hdr.rmvParams.u.byHdr.type)
                        {
                            case (e_FM_PCD_MANIP_RMV_BY_HDR_SPECIFIC_L2):
                                break;
                            case (e_FM_PCD_MANIP_RMV_BY_HDR_CAPWAP):
                                break;
                            case (e_FM_PCD_MANIP_RMV_BY_HDR_FROM_START):
                            {
                                t_Error err;
                                uint8_t prsArrayOffset;

                                err =
                                        GetPrOffsetByHeaderOrField(
                                                &p_ManipParams->u.hdr.rmvParams.u.byHdr.u.hdrInfo,
                                                &prsArrayOffset);
                                if (err)
                                    RETURN_ERROR(MAJOR, err, NO_MSG);
                                break;
                            }
                            default:
                                RETURN_ERROR(
                                        MAJOR,
                                        E_INVALID_STATE,
                                        ("invalid type of remove manipulation"));
                        }
                        break;
                    case (e_FM_PCD_MANIP_RMV_GENERIC):
                        break;
                    default:
                        RETURN_ERROR(MAJOR, E_INVALID_STATE,
                                     ("invalid type of remove manipulation"));
                }
                p_Manip->opcode = HMAN_OC;
                p_Manip->muramAllocate = TRUE;
                p_Manip->rmv = TRUE;
            }
            else
                if (p_ManipParams->u.hdr.insrt)
                {
                    switch (p_ManipParams->u.hdr.insrtParams.type)
                    {
                        case (e_FM_PCD_MANIP_INSRT_BY_HDR):
                        {
                            switch (p_ManipParams->u.hdr.insrtParams.u.byHdr.type)
                            {
                                case (e_FM_PCD_MANIP_INSRT_BY_HDR_SPECIFIC_L2):
                                    /* nothing to check */
                                    break;
                                case (e_FM_PCD_MANIP_INSRT_BY_HDR_IP):
                                    if (p_ManipParams->u.hdr.insrtParams.u.byHdr.u.ipParams.insrt.size
                                            % 4)
                                        RETURN_ERROR(
                                                MAJOR,
                                                E_INVALID_VALUE,
                                                ("IP inserted header must be of size which is a multiple of four bytes"));
                                    break;
                                case (e_FM_PCD_MANIP_INSRT_BY_HDR_CAPWAP):
                                    if (p_ManipParams->u.hdr.insrtParams.u.byHdr.u.insrt.size
                                            % 4)
                                        RETURN_ERROR(
                                                MAJOR,
                                                E_INVALID_VALUE,
                                                ("CAPWAP inserted header must be of size which is a multiple of four bytes"));
                                    break;
                                case (e_FM_PCD_MANIP_INSRT_BY_HDR_UDP):
                                case (e_FM_PCD_MANIP_INSRT_BY_HDR_UDP_LITE):
                                    if (p_ManipParams->u.hdr.insrtParams.u.byHdr.u.insrt.size
                                            != 8)
                                        RETURN_ERROR(
                                                MAJOR,
                                                E_INVALID_VALUE,
                                                ("Inserted header must be of size 8"));
                                    break;
                                default:
                                    RETURN_ERROR(
                                            MAJOR,
                                            E_INVALID_STATE,
                                            ("unsupported insert by header type"));
                            }
                            break;
                        }
                        case (e_FM_PCD_MANIP_INSRT_GENERIC):
                            break;
                        default:
                            RETURN_ERROR(
                                    MAJOR,
                                    E_INVALID_STATE,
                                    ("for only insert manipulation unsupported type"));
                    }
                    p_Manip->opcode = HMAN_OC;
                    p_Manip->muramAllocate = TRUE;
                    p_Manip->insrt = TRUE;
                }
                else
                    if (p_ManipParams->u.hdr.fieldUpdate)
                    {
                        /* Check parameters */
                        if (p_ManipParams->u.hdr.fieldUpdateParams.type
                                == e_FM_PCD_MANIP_HDR_FIELD_UPDATE_VLAN)
                        {
                            if ((p_ManipParams->u.hdr.fieldUpdateParams.u.vlan.updateType
                                    == e_FM_PCD_MANIP_HDR_FIELD_UPDATE_VLAN_VPRI)
                                    && (p_ManipParams->u.hdr.fieldUpdateParams.u.vlan.u.vpri
                                            > 7))
                                RETURN_ERROR(
                                        MAJOR, E_INVALID_VALUE,
                                        ("vpri should get values of 0-7 "));
                            if (p_ManipParams->u.hdr.fieldUpdateParams.u.vlan.updateType
                                    == e_FM_PCD_MANIP_HDR_FIELD_UPDATE_DSCP_TO_VLAN)
                            {
                                int i;

                                if (p_ManipParams->u.hdr.fieldUpdateParams.u.vlan.u.dscpToVpri.vpriDefVal
                                        > 7)
                                    RETURN_ERROR(
                                            MAJOR,
                                            E_INVALID_VALUE,
                                            ("vpriDefVal should get values of 0-7 "));
                                for (i = 0; i < FM_PCD_MANIP_DSCP_TO_VLAN_TRANS;
                                        i++)
                                    if (p_ManipParams->u.hdr.fieldUpdateParams.u.vlan.u.dscpToVpri.dscpToVpriTable[i]
                                            & 0xf0)
                                        RETURN_ERROR(
                                                MAJOR,
                                                E_INVALID_VALUE,
                                                ("dscpToVpriTabl value out of range (0-15)"));
                            }

                        }

                        p_Manip->opcode = HMAN_OC;
                        p_Manip->muramAllocate = TRUE;
                        p_Manip->fieldUpdate = TRUE;
                    }
                    else
                        if (p_ManipParams->u.hdr.custom)
                        {
                            if (p_ManipParams->u.hdr.customParams.type == e_FM_PCD_MANIP_HDR_CUSTOM_GEN_FIELD_REPLACE)
                            {

                            if ((p_ManipParams->u.hdr.customParams.u.genFieldReplace.size == 0) ||
                                    (p_ManipParams->u.hdr.customParams.u.genFieldReplace.size > 8))
                                RETURN_ERROR(
                                        MAJOR, E_INVALID_VALUE,
                                        ("size should get values of 1-8 "));

                            if (p_ManipParams->u.hdr.customParams.u.genFieldReplace.srcOffset > 7)
                                RETURN_ERROR(
                                        MAJOR, E_INVALID_VALUE,
                                        ("srcOffset should be <= 7"));

                            if ((p_ManipParams->u.hdr.customParams.u.genFieldReplace.srcOffset +
                                    p_ManipParams->u.hdr.customParams.u.genFieldReplace.size) > 8)
                                RETURN_ERROR(
                                        MAJOR, E_INVALID_VALUE,
                                        ("(srcOffset + size) should be <= 8"));

                            if ((p_ManipParams->u.hdr.customParams.u.genFieldReplace.dstOffset +
                                    p_ManipParams->u.hdr.customParams.u.genFieldReplace.size) > 256)
                                RETURN_ERROR(
                                        MAJOR, E_INVALID_VALUE,
                                        ("(dstOffset + size) should be <= 256"));

                            }

                            p_Manip->opcode = HMAN_OC;
                            p_Manip->muramAllocate = TRUE;
                            p_Manip->custom = TRUE;
                        }
            break;
        case e_FM_PCD_MANIP_REASSEM:
            RETURN_ERROR(MAJOR, E_NOT_SUPPORTED, ("Hardware reassembly is unsupported in Mono"));
        case e_FM_PCD_MANIP_FRAG:
            if (p_ManipParams->h_NextManip)
                RETURN_ERROR(MAJOR, E_NOT_SUPPORTED,
                             ("next manip with fragmentation"));
            switch (p_ManipParams->u.frag.hdr)
            {
                case (HEADER_TYPE_IPv4):
                case (HEADER_TYPE_IPv6):
                    p_Manip->opcode = HMAN_OC_IP_FRAGMENTATION;
                    break;
                case (HEADER_TYPE_CAPWAP):
                    p_Manip->opcode = HMAN_OC_CAPWAP_FRAGMENTATION;
                    break;
                default:
                    RETURN_ERROR(MAJOR, E_NOT_SUPPORTED,
                                 ("header for fragmentation"));
            }
            p_Manip->muramAllocate = TRUE;
            break;
        case e_FM_PCD_MANIP_SPECIAL_OFFLOAD:
            switch (p_ManipParams->u.specialOffload.type)
            {
                case (e_FM_PCD_MANIP_SPECIAL_OFFLOAD_IPSEC):
                    p_Manip->opcode = HMAN_OC_IPSEC_MANIP;
                    p_Manip->muramAllocate = TRUE;
                    break;
                case (e_FM_PCD_MANIP_SPECIAL_OFFLOAD_CAPWAP):
                    p_Manip->opcode = HMAN_OC_CAPWAP_MANIP;
                    p_Manip->muramAllocate = TRUE;
                    break;
                default:
                    RETURN_ERROR(MAJOR, E_NOT_SUPPORTED,
                                 ("special offload type"));
            }
            break;
        default:
            RETURN_ERROR(MAJOR, E_NOT_SUPPORTED, ("manip type"));
    }

    return E_OK;
}

static t_Error IpFragmentationStats(t_FmPcdManip *p_Manip,
                                    t_FmPcdManipFragIpStats *p_Stats)
{
    t_AdOfTypeContLookup *p_Ad;

    ASSERT_COND(p_Manip);
    ASSERT_COND(p_Stats);
    ASSERT_COND(p_Manip->h_Ad);
    ASSERT_COND(p_Manip->fragParams.p_Frag);

    p_Ad = (t_AdOfTypeContLookup *)p_Manip->h_Ad;

    p_Stats->totalFrames = GET_UINT32(p_Ad->gmask);
    p_Stats->fragmentedFrames = GET_UINT32(p_Manip->fragParams.p_Frag->ccAdBase)
            & 0x00ffffff;
    p_Stats->generatedFragments =
            GET_UINT32(p_Manip->fragParams.p_Frag->matchTblPtr);

    return E_OK;
}

static t_Error IpFragmentation(t_FmPcdManipFragIpParams *p_ManipParams,
                               t_FmPcdManip *p_Manip)
{
    uint32_t pcAndOffsetsReg = 0, ccAdBaseReg = 0, gmaskReg = 0;
    t_FmPcd *p_FmPcd;

    SANITY_CHECK_RETURN_ERROR(p_Manip->h_Ad, E_INVALID_HANDLE);
    SANITY_CHECK_RETURN_ERROR(p_ManipParams->sizeForFragmentation != 0xFFFF,
                              E_INVALID_VALUE);

    p_FmPcd = p_Manip->h_FmPcd;
    /* Allocation of fragmentation Action Descriptor */
    p_Manip->fragParams.p_Frag = (t_AdOfTypeContLookup *)FM_MURAM_AllocMem(
            p_FmPcd->h_FmMuram, FM_PCD_CC_AD_ENTRY_SIZE,
            FM_PCD_CC_AD_TABLE_ALIGN);
    if (!p_Manip->fragParams.p_Frag)
        RETURN_ERROR(MAJOR, E_NO_MEMORY,
                     ("MURAM alloc for Fragmentation table descriptor"));
    MemSet8(p_Manip->fragParams.p_Frag, 0, FM_PCD_CC_AD_ENTRY_SIZE);

    /* Prepare the third Ad register (pcAndOffsets)- OperationCode */
    pcAndOffsetsReg = (uint32_t)HMAN_OC_IP_FRAGMENTATION;

    /* Prepare the first Ad register (ccAdBase) - Don't frag action and Action descriptor type*/
    ccAdBaseReg = FM_PCD_AD_CONT_LOOKUP_TYPE;
    ccAdBaseReg |= (p_ManipParams->dontFragAction
            << FM_PCD_MANIP_IP_FRAG_DF_SHIFT);


    /* Set Scatter/Gather BPid */
    if (p_ManipParams->sgBpidEn)
    {
        ccAdBaseReg |= FM_PCD_MANIP_IP_FRAG_SG_BDID_EN;
        pcAndOffsetsReg |= ((p_ManipParams->sgBpid
                << FM_PCD_MANIP_IP_FRAG_SG_BDID_SHIFT)
                & FM_PCD_MANIP_IP_FRAG_SG_BDID_MASK);
    }

    /* Prepare the first Ad register (gmask) - scratch buffer pool id and Pointer to fragment ID */
    gmaskReg = (uint32_t)(XX_VirtToPhys(UINT_TO_PTR(p_FmPcd->ipv6FrameIdAddr))
            - p_FmPcd->physicalMuramBase);
    gmaskReg |= (0xFF) << FM_PCD_MANIP_IP_FRAG_SCRATCH_BPID;

    /* Set all Ad registers */
    WRITE_UINT32(p_Manip->fragParams.p_Frag->pcAndOffsets, pcAndOffsetsReg);
    WRITE_UINT32(p_Manip->fragParams.p_Frag->ccAdBase, ccAdBaseReg);
    WRITE_UINT32(p_Manip->fragParams.p_Frag->gmask, gmaskReg);

    /* Saves user's fragmentation manipulation parameters */
    p_Manip->frag = TRUE;
    p_Manip->sizeForFragmentation = p_ManipParams->sizeForFragmentation;

    return E_OK;
}

static t_Error IPManip(t_FmPcdManip *p_Manip)
{
    t_Error err = E_OK;
    t_FmPcd *p_FmPcd;
    t_AdOfTypeContLookup *p_Ad;
    uint32_t tmpReg32 = 0, tmpRegNia = 0;

    SANITY_CHECK_RETURN_ERROR(p_Manip, E_INVALID_HANDLE);
    p_FmPcd = p_Manip->h_FmPcd;
    SANITY_CHECK_RETURN_ERROR(p_FmPcd, E_INVALID_HANDLE);

    p_Ad = (t_AdOfTypeContLookup *)p_Manip->h_Ad;

    tmpReg32 = FM_PCD_MANIP_IP_NO_FRAGMENTATION;
    if (p_Manip->frag == TRUE)
    {
        tmpRegNia = (uint32_t)(XX_VirtToPhys(p_Manip->fragParams.p_Frag)
                - (p_FmPcd->physicalMuramBase));
        tmpReg32 = (uint32_t)p_Manip->sizeForFragmentation
                << FM_PCD_MANIP_IP_MTU_SHIFT;
    }

    tmpRegNia |= FM_PCD_AD_CONT_LOOKUP_TYPE | FM_PCD_MANIP_IP_CNIA;
    tmpReg32 |= HMAN_OC_IP_MANIP;

    WRITE_UINT32(p_Ad->pcAndOffsets, tmpReg32);
    WRITE_UINT32(p_Ad->ccAdBase, tmpRegNia);
    WRITE_UINT32(p_Ad->gmask, 0);
    /* Total frame counter - MUST be initialized to zero.*/

    return err;
}

static t_Error IPSecManip(t_FmPcdManipParams *p_ManipParams,
                          t_FmPcdManip *p_Manip)
{
    t_AdOfTypeContLookup *p_Ad;
    t_FmPcdManipSpecialOffloadIPSecParams *p_IPSecParams;
    t_Error err = E_OK;
    uint32_t tmpReg32 = 0;
    uint32_t power;

    SANITY_CHECK_RETURN_ERROR(p_Manip, E_INVALID_HANDLE);
    SANITY_CHECK_RETURN_ERROR(p_ManipParams, E_INVALID_HANDLE);

    p_IPSecParams = &p_ManipParams->u.specialOffload.u.ipsec;

    SANITY_CHECK_RETURN_ERROR(
            !p_IPSecParams->variableIpHdrLen || p_IPSecParams->decryption,
            E_INVALID_VALUE);
    SANITY_CHECK_RETURN_ERROR(
            !p_IPSecParams->variableIpVersion || !p_IPSecParams->decryption,
            E_INVALID_VALUE);
    SANITY_CHECK_RETURN_ERROR(
            !p_IPSecParams->variableIpVersion || p_IPSecParams->outerIPHdrLen,
            E_INVALID_VALUE);
    SANITY_CHECK_RETURN_ERROR(
            !p_IPSecParams->arwSize || p_IPSecParams->arwAddr,
            E_INVALID_VALUE);
    SANITY_CHECK_RETURN_ERROR(
            !p_IPSecParams->arwSize || p_IPSecParams->decryption,
            E_INVALID_VALUE);
    SANITY_CHECK_RETURN_ERROR((p_IPSecParams->arwSize % 16) == 0, E_INVALID_VALUE);

    p_Ad = (t_AdOfTypeContLookup *)p_Manip->h_Ad;

    tmpReg32 |= FM_PCD_AD_CONT_LOOKUP_TYPE;
    tmpReg32 |= (p_IPSecParams->decryption) ? FM_PCD_MANIP_IPSEC_DEC : 0;
    tmpReg32 |= (p_IPSecParams->ecnCopy) ? FM_PCD_MANIP_IPSEC_ECN_EN : 0;
    tmpReg32 |= (p_IPSecParams->dscpCopy) ? FM_PCD_MANIP_IPSEC_DSCP_EN : 0;
    tmpReg32 |=
            (p_IPSecParams->variableIpHdrLen) ? FM_PCD_MANIP_IPSEC_VIPL_EN : 0;
    tmpReg32 |=
            (p_IPSecParams->variableIpVersion) ? FM_PCD_MANIP_IPSEC_VIPV_EN : 0;
    if (p_IPSecParams->arwSize)
        tmpReg32 |= (uint32_t)((XX_VirtToPhys(UINT_TO_PTR(p_IPSecParams->arwAddr))-FM_MM_MURAM)
                & (FM_MURAM_SIZE-1));
    WRITE_UINT32(p_Ad->ccAdBase, tmpReg32);

    tmpReg32 = 0;
    if (p_IPSecParams->arwSize) {
        NEXT_POWER_OF_2((p_IPSecParams->arwSize + 32), power);
        LOG2(power, power);
        tmpReg32 = (p_IPSecParams->arwSize | (power - 5)) << FM_PCD_MANIP_IPSEC_ARW_SIZE_SHIFT;
    }

    if (p_ManipParams->h_NextManip)
        tmpReg32 |=
                (uint32_t)(XX_VirtToPhys(((t_FmPcdManip *)p_ManipParams->h_NextManip)->h_Ad)-
                        (((t_FmPcd *)p_Manip->h_FmPcd)->physicalMuramBase)) >> 4;
    WRITE_UINT32(p_Ad->matchTblPtr, tmpReg32);

    tmpReg32 = HMAN_OC_IPSEC_MANIP;
    tmpReg32 |= p_IPSecParams->outerIPHdrLen
            << FM_PCD_MANIP_IPSEC_IP_HDR_LEN_SHIFT;
    if (p_ManipParams->h_NextManip)
        tmpReg32 |= FM_PCD_MANIP_IPSEC_NADEN;
    WRITE_UINT32(p_Ad->pcAndOffsets, tmpReg32);

    return err;
}

static t_Error CapwapFragmentationStats(t_FmPcdManip *p_Manip,
		t_FmPcdManipFragCapwapStats *p_Stats)
{
	t_AdOfTypeContLookup *p_Ad;

	ASSERT_COND(p_Manip);
	ASSERT_COND(p_Stats);
	ASSERT_COND(p_Manip->h_Ad);
	ASSERT_COND(p_Manip->fragParams.p_Frag);

	p_Ad = (t_AdOfTypeContLookup *)p_Manip->h_Ad;

	p_Stats->totalFrames = GET_UINT32(p_Ad->gmask);

	return E_OK;
}

static t_Error CapwapFragmentation(t_FmPcdManipFragCapwapParams *p_ManipParams,
                                   t_FmPcdManip *p_Manip)
{
    t_FmPcd *p_FmPcd;
    t_AdOfTypeContLookup *p_Ad;
    uint32_t pcAndOffsetsReg = 0, ccAdBaseReg = 0, gmaskReg = 0;
    uint32_t tmpReg32 = 0, tmpRegNia = 0;

    SANITY_CHECK_RETURN_ERROR(p_Manip->h_Ad, E_INVALID_HANDLE);
    SANITY_CHECK_RETURN_ERROR(p_ManipParams->sizeForFragmentation != 0xFFFF,
                              E_INVALID_VALUE);
    p_FmPcd = p_Manip->h_FmPcd;
    SANITY_CHECK_RETURN_ERROR(p_FmPcd, E_INVALID_HANDLE);

    /* Allocation of fragmentation Action Descriptor */
    p_Manip->fragParams.p_Frag = (t_AdOfTypeContLookup *)FM_MURAM_AllocMem(
            p_FmPcd->h_FmMuram, FM_PCD_CC_AD_ENTRY_SIZE,
            FM_PCD_CC_AD_TABLE_ALIGN);
    if (!p_Manip->fragParams.p_Frag)
        RETURN_ERROR(MAJOR, E_NO_MEMORY,
                     ("MURAM alloc for Fragmentation table descriptor"));
    MemSet8(p_Manip->fragParams.p_Frag, 0, FM_PCD_CC_AD_ENTRY_SIZE);

    /* Prepare the third Ad register (pcAndOffsets)- OperationCode */
    pcAndOffsetsReg = (uint32_t)HMAN_OC_CAPWAP_FRAGMENTATION;

    /* Prepare the first Ad register (ccAdBase) - Don't frag action and Action descriptor type*/
    ccAdBaseReg = FM_PCD_AD_CONT_LOOKUP_TYPE;
    ccAdBaseReg |=
            (p_ManipParams->compressModeEn) ? FM_PCD_MANIP_CAPWAP_FRAG_COMPRESS_EN :
                    0;

    /* Set Scatter/Gather BPid */
    if (p_ManipParams->sgBpidEn)
    {
        ccAdBaseReg |= FM_PCD_MANIP_CAPWAP_FRAG_SG_BDID_EN;
        pcAndOffsetsReg |= ((p_ManipParams->sgBpid
                << FM_PCD_MANIP_CAPWAP_FRAG_SG_BDID_SHIFT)
                & FM_PCD_MANIP_CAPWAP_FRAG_SG_BDID_MASK);
    }

    /* Prepare the first Ad register (gmask) - scratch buffer pool id and Pointer to fragment ID */
    gmaskReg = (uint32_t)(XX_VirtToPhys(UINT_TO_PTR(p_FmPcd->capwapFrameIdAddr))
            - p_FmPcd->physicalMuramBase);
    gmaskReg |= (0xFF) << FM_PCD_MANIP_IP_FRAG_SCRATCH_BPID;

    /* Set all Ad registers */
    WRITE_UINT32(p_Manip->fragParams.p_Frag->pcAndOffsets, pcAndOffsetsReg);
    WRITE_UINT32(p_Manip->fragParams.p_Frag->ccAdBase, ccAdBaseReg);
    WRITE_UINT32(p_Manip->fragParams.p_Frag->gmask, gmaskReg);

    /* Saves user's fragmentation manipulation parameters */
    p_Manip->frag = TRUE;
    p_Manip->sizeForFragmentation = p_ManipParams->sizeForFragmentation;

    p_Ad = (t_AdOfTypeContLookup *)p_Manip->h_Ad;

    tmpRegNia = (uint32_t)(XX_VirtToPhys(p_Manip->fragParams.p_Frag)
            - (p_FmPcd->physicalMuramBase));
    tmpReg32 = (uint32_t)p_Manip->sizeForFragmentation
            << FM_PCD_MANIP_CAPWAP_FRAG_CHECK_MTU_SHIFT;

    tmpRegNia |= FM_PCD_AD_CONT_LOOKUP_TYPE;
    tmpReg32 |= HMAN_OC_CAPWAP_FRAG_CHECK;

    tmpRegNia |= FM_PCD_MANIP_CAPWAP_FRAG_CHECK_CNIA;

    WRITE_UINT32(p_Ad->pcAndOffsets, tmpReg32);
    WRITE_UINT32(p_Ad->ccAdBase, tmpRegNia);
    WRITE_UINT32(p_Ad->gmask, 0);
    /* Total frame counter - MUST be initialized to zero.*/

    return E_OK;
}

static t_Error CapwapManip(t_FmPcdManipParams *p_ManipParams,
                           t_FmPcdManip *p_Manip)
{
    t_AdOfTypeContLookup *p_Ad;
    t_FmPcdManipSpecialOffloadCapwapParams *p_Params;
    t_Error err = E_OK;
    uint32_t tmpReg32 = 0;

    SANITY_CHECK_RETURN_ERROR(p_Manip, E_INVALID_HANDLE);
    SANITY_CHECK_RETURN_ERROR(p_ManipParams, E_INVALID_HANDLE);

    p_Params = &p_ManipParams->u.specialOffload.u.capwap;

    p_Ad = (t_AdOfTypeContLookup *)p_Manip->h_Ad;
    tmpReg32 |= FM_PCD_AD_CONT_LOOKUP_TYPE;
    tmpReg32 |= (p_Params->dtls) ? FM_PCD_MANIP_CAPWAP_DTLS : 0;
    /* TODO - add 'qosSrc' */
    WRITE_UINT32(p_Ad->ccAdBase, tmpReg32);

    tmpReg32 = HMAN_OC_CAPWAP_MANIP;
    if (p_ManipParams->h_NextManip)
    {
        WRITE_UINT32(
                p_Ad->matchTblPtr,
                (uint32_t)(XX_VirtToPhys(((t_FmPcdManip *)p_ManipParams->h_NextManip)->h_Ad)- (((t_FmPcd *)p_Manip->h_FmPcd)->physicalMuramBase)) >> 4);

        tmpReg32 |= FM_PCD_MANIP_CAPWAP_NADEN;
    }

    WRITE_UINT32(p_Ad->pcAndOffsets, tmpReg32);

    return err;
}

static t_Handle ManipOrStatsSetNode(t_Handle h_FmPcd, t_Handle *p_Params,
                                    bool stats)
{
    t_FmPcdManip *p_Manip;
    t_Error err;
    t_FmPcd *p_FmPcd = (t_FmPcd *)h_FmPcd;

    p_Manip = (t_FmPcdManip*)XX_Malloc(sizeof(t_FmPcdManip));
    if (!p_Manip)
    {
        REPORT_ERROR(MAJOR, E_NO_MEMORY, ("No memory"));
        return NULL;
    }
    memset(p_Manip, 0, sizeof(t_FmPcdManip));

    p_Manip->type = ((t_FmPcdManipParams *)p_Params)->type;
    memcpy((uint8_t*)&p_Manip->manipParams, p_Params,
           sizeof(p_Manip->manipParams));

    if (!stats)
        err = CheckManipParamsAndSetType(p_Manip,
                                         (t_FmPcdManipParams *)p_Params);
    else
    {
        REPORT_ERROR(MAJOR, E_NOT_SUPPORTED, ("Statistics node!"));
        XX_Free(p_Manip);
        return NULL;
    }
    if (err)
    {
        REPORT_ERROR(MAJOR, E_INVALID_VALUE, ("Invalid header manipulation type"));
        XX_Free(p_Manip);
        return NULL;
    }

    if (p_Manip->muramAllocate)
    {
        p_Manip->h_Ad = (t_Handle)FM_MURAM_AllocMem(
                p_FmPcd->h_FmMuram, FM_PCD_CC_AD_ENTRY_SIZE,
                FM_PCD_CC_AD_TABLE_ALIGN);
        if (!p_Manip->h_Ad)
        {
            REPORT_ERROR(MAJOR, E_NO_MEMORY, ("MURAM alloc for Manipulation action descriptor"));
            ReleaseManipHandler(p_Manip, p_FmPcd);
            XX_Free(p_Manip);
            return NULL;
        }

        MemSet8(p_Manip->h_Ad, 0, FM_PCD_CC_AD_ENTRY_SIZE);
    }
    else
    {
        p_Manip->h_Ad = (t_Handle)XX_Malloc(
                FM_PCD_CC_AD_ENTRY_SIZE * sizeof(uint8_t));
        if (!p_Manip->h_Ad)
        {
            REPORT_ERROR(MAJOR, E_NO_MEMORY, ("Allocation of Manipulation action descriptor"));
            ReleaseManipHandler(p_Manip, p_FmPcd);
            XX_Free(p_Manip);
            return NULL;
        }

        memset(p_Manip->h_Ad, 0, FM_PCD_CC_AD_ENTRY_SIZE * sizeof(uint8_t));
    }


    p_Manip->h_FmPcd = h_FmPcd;

    return p_Manip;
}

static void UpdateAdPtrOfNodesWhichPointsOnCrntMdfManip(
        t_FmPcdManip *p_CrntMdfManip, t_List *h_NodesLst)
{
    t_CcNodeInformation *p_CcNodeInformation;
    t_FmPcdCcNode *p_NodePtrOnCurrentMdfManip = NULL;
    t_List *p_Pos;
    int i = 0;
    t_Handle p_AdTablePtOnCrntCurrentMdfNode/*, p_AdTableNewModified*/;
    t_CcNodeInformation ccNodeInfo;

    LIST_FOR_EACH(p_Pos, &p_CrntMdfManip->nodesLst)
    {
        p_CcNodeInformation = CC_NODE_F_OBJECT(p_Pos);
        p_NodePtrOnCurrentMdfManip =
                (t_FmPcdCcNode *)p_CcNodeInformation->h_CcNode;

        ASSERT_COND(p_NodePtrOnCurrentMdfManip);

        /* Search in the previous node which exact index points on this current modified node for getting AD */
        for (i = 0; i < p_NodePtrOnCurrentMdfManip->numOfKeys + 1; i++)
        {
            if (p_NodePtrOnCurrentMdfManip->keyAndNextEngineParams[i].nextEngineParams.nextEngine
                    == e_FM_PCD_CC)
            {
                if (p_NodePtrOnCurrentMdfManip->keyAndNextEngineParams[i].nextEngineParams.h_Manip
                        == (t_Handle)p_CrntMdfManip)
                {
                    if (p_NodePtrOnCurrentMdfManip->keyAndNextEngineParams[i].p_StatsObj)
                        p_AdTablePtOnCrntCurrentMdfNode =
                                p_NodePtrOnCurrentMdfManip->keyAndNextEngineParams[i].p_StatsObj->h_StatsAd;
                    else
                        p_AdTablePtOnCrntCurrentMdfNode =
                                PTR_MOVE(p_NodePtrOnCurrentMdfManip->h_AdTable, i*FM_PCD_CC_AD_ENTRY_SIZE);

                    memset(&ccNodeInfo, 0, sizeof(t_CcNodeInformation));
                    ccNodeInfo.h_CcNode = p_AdTablePtOnCrntCurrentMdfNode;
                    EnqueueNodeInfoToRelevantLst(h_NodesLst, &ccNodeInfo, NULL);
                }
            }
        }

        ASSERT_COND(i != p_NodePtrOnCurrentMdfManip->numOfKeys);
    }
}

static void BuildHmtd(uint8_t *p_Dest, uint8_t *p_Src, uint8_t *p_Hmcd,
                      t_FmPcd *p_FmPcd)
{
    t_Error err;

    /* Copy the HMTD */
    MemCpy8(p_Dest, (uint8_t*)p_Src, 16);
    /* Replace the HMCT table pointer  */
    WRITE_UINT32(
            ((t_Hmtd *)p_Dest)->hmcdBasePtr,
            (uint32_t)(XX_VirtToPhys(p_Hmcd) - ((t_FmPcd*)p_FmPcd)->physicalMuramBase));
    /* Call Host Command to replace HMTD by a new HMTD */
    err = FmHcPcdCcDoDynamicChange(
            p_FmPcd->h_Hc,
            (uint32_t)(XX_VirtToPhys(p_Src) - p_FmPcd->physicalMuramBase),
            (uint32_t)(XX_VirtToPhys(p_Dest) - p_FmPcd->physicalMuramBase));
    if (err)
        REPORT_ERROR(MINOR, err, ("Failed in dynamic manip change, continued to the rest of the owners."));
}

void FmPcdManipUpdateOwner(t_Handle h_Manip, bool add)
{

    uint32_t intFlags;

    intFlags = XX_LockIntrSpinlock(((t_FmPcdManip *)h_Manip)->h_Spinlock);
    if (add)
        ((t_FmPcdManip *)h_Manip)->owner++;
    else
    {
        ASSERT_COND(((t_FmPcdManip *)h_Manip)->owner);
        ((t_FmPcdManip *)h_Manip)->owner--;
    }
    XX_UnlockIntrSpinlock(((t_FmPcdManip *)h_Manip)->h_Spinlock, intFlags);
}

t_List *FmPcdManipGetNodeLstPointedOnThisManip(t_Handle h_Manip)
{
    ASSERT_COND(h_Manip);
    return &((t_FmPcdManip *)h_Manip)->nodesLst;
}

t_List *FmPcdManipGetSpinlock(t_Handle h_Manip)
{
    ASSERT_COND(h_Manip);
    return ((t_FmPcdManip *)h_Manip)->h_Spinlock;
}

t_Error FmPcdManipCheckParamsForCcNextEngine(
        t_FmPcdCcNextEngineParams *p_FmPcdCcNextEngineParams,
        uint32_t *requiredAction)
{
    t_FmPcdManip *p_Manip;
    bool pointFromCc = TRUE;

    SANITY_CHECK_RETURN_ERROR(p_FmPcdCcNextEngineParams, E_NULL_POINTER);
    SANITY_CHECK_RETURN_ERROR(p_FmPcdCcNextEngineParams->h_Manip,
                              E_NULL_POINTER);

    p_Manip = (t_FmPcdManip *)(p_FmPcdCcNextEngineParams->h_Manip);
    *requiredAction = 0;

    while (p_Manip)
    {
        switch (p_Manip->opcode)
        {
            case (HMAN_OC_IP_FRAGMENTATION):
            case (HMAN_OC_CAPWAP_FRAGMENTATION):
                if (p_FmPcdCcNextEngineParams->nextEngine != e_FM_PCD_DONE)
                    RETURN_ERROR(
                            MAJOR,
                            E_INVALID_STATE,
                            ("For this type of header manipulation has to be nextEngine e_FM_PCD_DONE"));
                p_Manip->ownerTmp++;
                break;
            case (HMAN_OC_IPSEC_MANIP):
            case (HMAN_OC_CAPWAP_MANIP):
                p_Manip->ownerTmp++;
                break;
            case (HMAN_OC):
                if ((p_FmPcdCcNextEngineParams->nextEngine == e_FM_PCD_CC)
                        && MANIP_IS_CASCADED(p_Manip))
                    RETURN_ERROR(
                            MINOR,
                            E_INVALID_STATE,
                            ("Can't have a cascaded manipulation when and Next Engine is CC"));
                if (!MANIP_IS_FIRST(p_Manip) && pointFromCc)
                    RETURN_ERROR(
                            MAJOR,
                            E_INVALID_STATE,
                            ("h_Manip is already used and may not be shared (no sharing of non-head manip nodes)"));
                break;
            default:
                RETURN_ERROR(
                        MAJOR, E_INVALID_STATE,
                        ("invalid type of header manipulation for this state"));
        }
        p_Manip = p_Manip->h_NextManip;
        pointFromCc = FALSE;
    }
    return E_OK;
}


t_Error FmPcdManipCheckParamsWithCcNodeParams(t_Handle h_Manip,
                                              t_Handle h_FmPcdCcNode)
{
    t_FmPcdManip *p_Manip = (t_FmPcdManip *)h_Manip;
    t_Error err = E_OK;

    SANITY_CHECK_RETURN_ERROR(h_Manip, E_INVALID_HANDLE);
    SANITY_CHECK_RETURN_ERROR(h_FmPcdCcNode, E_INVALID_HANDLE);

    switch (p_Manip->opcode)
    {
        default:
            break;
    }

    return err;
}

void FmPcdManipUpdateAdResultForCc(
        t_Handle h_Manip, t_FmPcdCcNextEngineParams *p_CcNextEngineParams,
        t_Handle p_Ad, t_Handle *p_AdNewPtr)
{
    t_FmPcdManip *p_Manip = (t_FmPcdManip *)h_Manip;

    /* This routine creates a Manip AD and can return in "p_AdNewPtr"
     * either the new descriptor or NULL if it writes the Manip AD into p_AD (into the match table) */

    ASSERT_COND(p_Manip);
    ASSERT_COND(p_CcNextEngineParams);
    ASSERT_COND(p_Ad);
    ASSERT_COND(p_AdNewPtr);

    FmPcdManipUpdateOwner(h_Manip, TRUE);

    /* According to "type", either build & initialize a new AD (p_AdNew) or initialize
     * p_Ad ( the AD in the match table) and set p_AdNew = NULL. */
    switch (p_Manip->opcode)
    {
        case (HMAN_OC_IPSEC_MANIP):
        case (HMAN_OC_CAPWAP_MANIP):
            *p_AdNewPtr = p_Manip->h_Ad;
            break;
        case (HMAN_OC_IP_FRAGMENTATION):
        case (HMAN_OC_CAPWAP_FRAGMENTATION):
            if ((p_CcNextEngineParams->nextEngine == e_FM_PCD_DONE)
                    && (!p_CcNextEngineParams->params.enqueueParams.overrideFqid))
            {
                memcpy((uint8_t *)p_Ad, (uint8_t *)p_Manip->h_Ad,
                       sizeof(t_AdOfTypeContLookup));
                WRITE_UINT32(
                        ((t_AdOfTypeContLookup *)p_Ad)->ccAdBase,
                        GET_UINT32(((t_AdOfTypeContLookup *)p_Ad)->ccAdBase) & ~FM_PCD_MANIP_IP_CNIA);
                *p_AdNewPtr = NULL;
            }
            else
                *p_AdNewPtr = p_Manip->h_Ad;
            break;
        case (HMAN_OC):
            /* Allocate and initialize HMTD */
            *p_AdNewPtr = p_Manip->h_Ad;
            break;
        default:
            break;
    }
}

void FmPcdManipUpdateAdContLookupForCc(t_Handle h_Manip, t_Handle p_Ad,
                                       t_Handle *p_AdNewPtr,
                                       uint32_t adTableOffset)
{
    t_FmPcdManip *p_Manip = (t_FmPcdManip *)h_Manip;

    /* This routine creates a Manip AD and can return in "p_AdNewPtr"
     * either the new descriptor or NULL if it writes the Manip AD into p_AD (into the match table) */
    ASSERT_COND(p_Manip);

    FmPcdManipUpdateOwner(h_Manip, TRUE);

    switch (p_Manip->opcode)
    {
        case (HMAN_OC):
            /* Initialize HMTD within the match table*/
            MemSet8(p_Ad, 0, FM_PCD_CC_AD_ENTRY_SIZE);
            /* copy the existing HMTD *//* ask Alla - memcpy??? */
            memcpy((uint8_t*)p_Ad, p_Manip->h_Ad, sizeof(t_Hmtd));
            /* update NADEN to be "1"*/
            WRITE_UINT16(
                    ((t_Hmtd *)p_Ad)->cfg,
                    (uint16_t)(GET_UINT16(((t_Hmtd *)p_Ad)->cfg) | HMTD_CFG_NEXT_AD_EN));
            /* update next action descriptor */
            WRITE_UINT16(((t_Hmtd *)p_Ad)->nextAdIdx,
                         (uint16_t)(adTableOffset >> 4));
            /* mark that Manip's HMTD is not used */
            *p_AdNewPtr = NULL;
            break;

        default:
            break;
    }
}

/*********************** End of inter-module routines ************************/

/****************************************/
/*       API Init unit functions        */
/****************************************/

t_Handle FM_PCD_ManipNodeSet(t_Handle h_FmPcd,
                             t_FmPcdManipParams *p_ManipParams)
{
    t_FmPcd *p_FmPcd = (t_FmPcd *)h_FmPcd;
    t_FmPcdManip *p_Manip;
    t_Error err;

    SANITY_CHECK_RETURN_VALUE(h_FmPcd, E_INVALID_HANDLE, NULL);
    SANITY_CHECK_RETURN_VALUE(p_ManipParams, E_INVALID_HANDLE, NULL);

    if (p_ManipParams->type == e_FM_PCD_MANIP_REASSEM)
    {
        REPORT_ERROR(MAJOR, E_NOT_SUPPORTED, ("Hardware reassembly is unsupported in Mono"));
        return NULL;
    }

    p_Manip = ManipOrStatsSetNode(h_FmPcd, (t_Handle)p_ManipParams, FALSE);
    if (!p_Manip)
        return NULL;

    if (((p_Manip->opcode == HMAN_OC_IP_FRAGMENTATION)
            || (p_Manip->opcode == HMAN_OC)
            || (p_Manip->opcode == HMAN_OC_IPSEC_MANIP)
            || (p_Manip->opcode == HMAN_OC_CAPWAP_MANIP)
            || (p_Manip->opcode == HMAN_OC_CAPWAP_FRAGMENTATION)
            ) && (!FmPcdIsAdvancedOffloadSupported(p_FmPcd)))
    {
        REPORT_ERROR(MAJOR, E_INVALID_STATE, ("Advanced-offload must be enabled"));
        XX_Free(p_Manip);
        return NULL;
    }
    p_Manip->h_Spinlock = XX_InitSpinlock();
    if (!p_Manip->h_Spinlock)
    {
        REPORT_ERROR(MAJOR, E_INVALID_VALUE, ("UNSUPPORTED HEADER MANIPULATION TYPE"));
        ReleaseManipHandler(p_Manip, p_FmPcd);
        XX_Free(p_Manip);
        return NULL;
    }

    INIT_LIST(&p_Manip->nodesLst);

    switch (p_Manip->opcode)
    {
        case (HMAN_OC_IP_FRAGMENTATION):
            /* IpFragmentation */
            err = IpFragmentation(&p_ManipParams->u.frag.u.ipFrag, p_Manip);
            if (err)
                break;
            err = IPManip(p_Manip);
            break;
        case (HMAN_OC_IPSEC_MANIP):
            err = IPSecManip(p_ManipParams, p_Manip);
            break;
        case (HMAN_OC_CAPWAP_FRAGMENTATION):
            /* CapwapFragmentation */
            err = CapwapFragmentation(&p_ManipParams->u.frag.u.capwapFrag,
                                      p_Manip);
            break;
        case (HMAN_OC_CAPWAP_MANIP):
            err = CapwapManip(p_ManipParams, p_Manip);
            break;
        case (HMAN_OC):
            /* New Manip */
            err = CreateManipActionNew(p_Manip, p_ManipParams);
            break;
        default:
            REPORT_ERROR(MAJOR, E_INVALID_VALUE, ("UNSUPPORTED HEADER MANIPULATION TYPE"));
            goto err_out;
    }

    if (err)
    {
        REPORT_ERROR(MAJOR, err, NO_MSG);
        goto err_out;
    }

    if (p_ManipParams->h_NextManip)
    {
        /* in the check routine we've verified that h_NextManip has no owners
         * and that only supported types are allowed. */
        p_Manip->h_NextManip = p_ManipParams->h_NextManip;
        /* save a "prev" pointer in h_NextManip */
        MANIP_SET_PREV(p_Manip->h_NextManip, p_Manip);
        FmPcdManipUpdateOwner(p_Manip->h_NextManip, TRUE);
    }

    return p_Manip;

err_out:
    XX_FreeSpinlock(p_Manip->h_Spinlock);
    ReleaseManipHandler(p_Manip, p_FmPcd);
    XX_Free(p_Manip);
    return NULL;
}

t_Error FM_PCD_ManipNodeReplace(t_Handle h_Manip,
                                t_FmPcdManipParams *p_ManipParams)
{
    t_FmPcdManip *p_Manip = (t_FmPcdManip *)h_Manip, *p_FirstManip;
    t_FmPcd *p_FmPcd = (t_FmPcd *)(p_Manip->h_FmPcd);
    t_Error err;
    uint8_t *p_WholeHmct = NULL, *p_ShadowHmct = NULL, *p_Hmtd = NULL;
    t_List lstOfNodeshichPointsOnCrntMdfManip, *p_Pos;
    t_CcNodeInformation *p_CcNodeInfo;
    SANITY_CHECK_RETURN_ERROR(h_Manip, E_INVALID_HANDLE);
    SANITY_CHECK_RETURN_ERROR(p_ManipParams, E_INVALID_HANDLE);

    INIT_LIST(&lstOfNodeshichPointsOnCrntMdfManip);

    if ((p_ManipParams->type != e_FM_PCD_MANIP_HDR)
            || (p_Manip->type != e_FM_PCD_MANIP_HDR))
        RETURN_ERROR(
                MINOR,
                E_NOT_SUPPORTED,
                ("FM_PCD_ManipNodeReplace Functionality supported only for Header Manipulation."));

    ASSERT_COND(p_Manip->opcode == HMAN_OC);
    ASSERT_COND(p_Manip->manipParams.h_NextManip == p_Manip->h_NextManip);
    memcpy((uint8_t*)&p_Manip->manipParams, p_ManipParams,
           sizeof(p_Manip->manipParams));
    p_Manip->manipParams.h_NextManip = p_Manip->h_NextManip;

    /* The replacement of the HdrManip depends on the node type.*/
    /*
     * (1) If this is an independent node, all its owners should be updated.
     *
     * (2) If it is the head of a cascaded chain (it does not have a "prev" but
     * it has a "next" and it has a "cascaded" indication), the next
     * node remains unchanged, and the behavior is as in (1).
     *
     * (3) If it is not the head, but a part of a cascaded chain, in can be
     * also replaced as a regular node with just one owner.
     *
     * (4) If it is a part of a chain implemented as a unified table, the
     * whole table is replaced and the owners of the head node must be updated.
     *
     */
    /* lock shadow */
    if (!p_FmPcd->p_CcShadow)
        RETURN_ERROR(MAJOR, E_NO_MEMORY, ("CC Shadow not allocated"));

    if (!TRY_LOCK(p_FmPcd->h_ShadowSpinlock, &p_FmPcd->shadowLock))
        return ERROR_CODE(E_BUSY);

    /* this routine creates a new manip action in the CC Shadow. */
    err = CreateManipActionShadow(p_Manip, p_ManipParams);
    if (err)
        RETURN_ERROR(MINOR, err, NO_MSG);

    /* If the owners list is empty (these are NOT the "owners" counter, but pointers from CC)
     * replace only HMTD and no lcok is required. Otherwise
     * lock the whole PCD
     * In case 4 MANIP_IS_UNIFIED_NON_FIRST(p_Manip) - Use the head node instead. */
    if (!FmPcdLockTryLockAll(p_FmPcd))
    {
        DBG(TRACE, ("FmPcdLockTryLockAll failed"));
        return ERROR_CODE(E_BUSY);
    }

    p_ShadowHmct = (uint8_t*)PTR_MOVE(p_FmPcd->p_CcShadow, 16);

    p_FirstManip = (t_FmPcdManip*)GetManipInfo(p_Manip,
                                               e_MANIP_HANDLER_TABLE_OWNER);
    ASSERT_COND(p_FirstManip);

    if (!LIST_IsEmpty(&p_FirstManip->nodesLst))
        UpdateAdPtrOfNodesWhichPointsOnCrntMdfManip(
                p_FirstManip, &lstOfNodeshichPointsOnCrntMdfManip);

    p_Hmtd = (uint8_t *)GetManipInfo(p_Manip, e_MANIP_HMTD);
    ASSERT_COND(p_Hmtd);
    BuildHmtd(p_FmPcd->p_CcShadow, (uint8_t *)p_Hmtd, p_ShadowHmct,
              ((t_FmPcd*)(p_Manip->h_FmPcd)));

    LIST_FOR_EACH(p_Pos, &lstOfNodeshichPointsOnCrntMdfManip)
    {
        p_CcNodeInfo = CC_NODE_F_OBJECT(p_Pos);
        BuildHmtd(p_FmPcd->p_CcShadow, (uint8_t *)p_CcNodeInfo->h_CcNode,
                  p_ShadowHmct, ((t_FmPcd*)(p_Manip->h_FmPcd)));
    }

    p_WholeHmct = (uint8_t *)GetManipInfo(p_Manip, e_MANIP_HMCT);
    ASSERT_COND(p_WholeHmct);

    /* re-build the HMCT n the original location */
    err = CreateManipActionBackToOrig(p_Manip, p_ManipParams);
    if (err)
    {
        RELEASE_LOCK(p_FmPcd->shadowLock);
        RETURN_ERROR(MINOR, err, NO_MSG);
    }

    p_Hmtd = (uint8_t *)GetManipInfo(p_Manip, e_MANIP_HMTD);
    ASSERT_COND(p_Hmtd);
    BuildHmtd(p_FmPcd->p_CcShadow, (uint8_t *)p_Hmtd, p_WholeHmct,
              ((t_FmPcd*)p_Manip->h_FmPcd));

    /* If LIST > 0, create a list of p_Ad's that point to the HMCT. Join also t_HMTD to this list.
     * For each p_Hmct (from list+fixed):
     * call Host Command to replace HMTD by a new one */LIST_FOR_EACH(p_Pos, &lstOfNodeshichPointsOnCrntMdfManip)
    {
        p_CcNodeInfo = CC_NODE_F_OBJECT(p_Pos);
        BuildHmtd(p_FmPcd->p_CcShadow, (uint8_t *)p_CcNodeInfo->h_CcNode,
                  p_WholeHmct, ((t_FmPcd*)(p_Manip->h_FmPcd)));
    }


    ReleaseLst(&lstOfNodeshichPointsOnCrntMdfManip);

    FmPcdLockUnlockAll(p_FmPcd);

    /* unlock shadow */
    RELEASE_LOCK(p_FmPcd->shadowLock);

    return E_OK;
}

t_Error FM_PCD_ManipNodeDelete(t_Handle h_ManipNode)
{
    t_FmPcdManip *p_Manip = (t_FmPcdManip *)h_ManipNode;

    SANITY_CHECK_RETURN_ERROR(p_Manip, E_INVALID_HANDLE);

    if (p_Manip->owner)
        RETURN_ERROR(
                MAJOR,
                E_INVALID_STATE,
                ("This manipulation node not be removed because this node is occupied, first - unbind this node "));

    if (p_Manip->h_NextManip)
    {
        MANIP_SET_PREV(p_Manip->h_NextManip, NULL);
        FmPcdManipUpdateOwner(p_Manip->h_NextManip, FALSE);
    }

    if (p_Manip->p_Hmct
            && (MANIP_IS_UNIFIED_FIRST(p_Manip) || !MANIP_IS_UNIFIED(p_Manip)))
        FM_MURAM_FreeMem(((t_FmPcd *)p_Manip->h_FmPcd)->h_FmMuram,
                         p_Manip->p_Hmct);

    if (p_Manip->h_Spinlock)
    {
        XX_FreeSpinlock(p_Manip->h_Spinlock);
        p_Manip->h_Spinlock = NULL;
    }

    ReleaseManipHandler(p_Manip, p_Manip->h_FmPcd);

    XX_Free(h_ManipNode);

    return E_OK;
}

t_Error FM_PCD_ManipGetStatistics(t_Handle h_ManipNode,
                                  t_FmPcdManipStats *p_FmPcdManipStats)
{
    t_FmPcdManip *p_Manip = (t_FmPcdManip *)h_ManipNode;

    SANITY_CHECK_RETURN_ERROR(p_Manip, E_INVALID_HANDLE);
    SANITY_CHECK_RETURN_ERROR(p_FmPcdManipStats, E_NULL_POINTER);

    switch (p_Manip->opcode)
    {
        case (HMAN_OC_IP_FRAGMENTATION):
            return IpFragmentationStats(p_Manip,
                                        &p_FmPcdManipStats->u.frag.u.ipFrag);
	case (HMAN_OC_CAPWAP_FRAGMENTATION):
		return CapwapFragmentationStats(
			p_Manip, &p_FmPcdManipStats->u.frag.u.capwapFrag);
        default:
            RETURN_ERROR(MAJOR, E_NOT_SUPPORTED,
                         ("no statistics to this type of manip"));
    }

    return E_OK;
}
