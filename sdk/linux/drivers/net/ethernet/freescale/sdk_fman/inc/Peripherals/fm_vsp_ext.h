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


/**************************************************************************//**
 @File          fm_vsp_ext.h

 @Description   FM Virtual Storage-Profile ...
*//***************************************************************************/
#ifndef __FM_VSP_EXT_H
#define __FM_VSP_EXT_H

#include "std_ext.h"
#include "error_ext.h"
#include "string_ext.h"
#include "debug_ext.h"

#include "fm_ext.h"


/**************************************************************************//**

 @Group         FM_grp Frame Manager API

 @Description   FM API functions, definitions and enums

 @{
*//***************************************************************************/

/**************************************************************************//**
 @Group         FM_VSP_grp FM Virtual-Storage-Profile

 @Description   FM Virtual-Storage-Profile API

 @{
*//***************************************************************************/

/**************************************************************************//**
 @Group         FM_VSP_init_grp FM VSP Initialization Unit

 @Description   FM VSP initialization API.

 @{
*//***************************************************************************/

/**************************************************************************//**
 @Description   Virtual Storage Profile
*//***************************************************************************/
typedef struct t_FmVspParams {
    t_Handle            h_Fm;               /**< A handle to the FM object this VSP related to */
    t_FmExtPools        extBufPools;        /**< Which external buffer pools are used
                                                 (up to FM_PORT_MAX_NUM_OF_EXT_POOLS), and their sizes.
                                                 parameter associated with Rx / OP port */
    uint16_t            liodnOffset;        /**< VSP's LIODN offset */
    struct {
        e_FmPortType    portType;           /**< Port type */
        uint8_t         portId;             /**< Port Id - relative to type */
    } portParams;
    uint8_t             relativeProfileId;  /**< VSP Id - relative to VSP's range
                                                 defined in relevant FM object */
} t_FmVspParams;


/**************************************************************************//**
 @Function      FM_VSP_Config

 @Description   Creates descriptor for the FM VSP module.

                The routine returns a handle (descriptor) to the FM VSP object.
                This descriptor must be passed as first parameter to all other
                FM VSP function calls.

                No actual initialization or configuration of FM hardware is
                done by this routine.

@Param[in]      p_FmVspParams   Pointer to data structure of parameters

 @Retval        Handle to FM VSP object, or NULL for Failure.
*//***************************************************************************/
t_Handle FM_VSP_Config(t_FmVspParams *p_FmVspParams);

/**************************************************************************//**
 @Function      FM_VSP_Init

 @Description   Initializes the FM VSP module

 @Param[in]     h_FmVsp - FM VSP module descriptor

 @Return        E_OK on success; Error code otherwise.
*//***************************************************************************/
t_Error FM_VSP_Init(t_Handle h_FmVsp);

/**************************************************************************//**
 @Function      FM_VSP_Free

 @Description   Frees all resources that were assigned to FM VSP module.

                Calling this routine invalidates the descriptor.

 @Param[in]     h_FmVsp - FM VSP module descriptor

 @Return        E_OK on success; Error code otherwise.
*//***************************************************************************/
t_Error FM_VSP_Free(t_Handle h_FmVsp);


/**************************************************************************//**
 @Group         FM_VSP_adv_config_grp  FM VSP Advanced Configuration Unit

 @Description   FM VSP advanced configuration functions.

 @{
*//***************************************************************************/

/**************************************************************************//**
 @Function      FM_VSP_ConfigBufferPrefixContent

 @Description   Defines the structure, size and content of the application buffer.

                The prefix will
                In VSPs defined for Tx ports, if 'passPrsResult', the application
                should set a value to their offsets in the prefix of
                the FM will save the first 'privDataSize', than,
                depending on 'passPrsResult' and 'passTimeStamp', copy parse result
                and timeStamp, and the packet itself (in this order), to the
                application buffer, and to offset.

                Calling this routine changes the buffer margins definitions
                in the internal driver data base from its default
                configuration: Data size:  [DEFAULT_FM_SP_bufferPrefixContent_privDataSize]
                               Pass Parser result: [DEFAULT_FM_SP_bufferPrefixContent_passPrsResult].
                               Pass timestamp: [DEFAULT_FM_SP_bufferPrefixContent_passTimeStamp].

 @Param[in]     h_FmVsp                         A handle to a FM VSP module.
 @Param[in,out] p_FmBufferPrefixContent         A structure of parameters describing the
                                                structure of the buffer.
                                                Out parameter: Start margin - offset
                                                of data from start of external buffer.

 @Return        E_OK on success; Error code otherwise.

 @Cautions      Allowed only following FM_VSP_Config() and before FM_VSP_Init().
*//***************************************************************************/
t_Error FM_VSP_ConfigBufferPrefixContent(t_Handle                   h_FmVsp,
                                         t_FmBufferPrefixContent    *p_FmBufferPrefixContent);

/** @} */ /* end of FM_VSP_adv_config_grp group */
/** @} */ /* end of FM_VSP_init_grp group */


/**************************************************************************//**
 @Group         FM_VSP_control_grp FM VSP Control Unit

 @Description   FM VSP runtime control API.

 @{
*//***************************************************************************/

/**************************************************************************//**
 @Function      FM_VSP_GetRelativeProfileId

 @Description   Given the VSP handle, the configured relative storage profile
		id is returned.

 @Param[in]     h_FmVsp    - FM PORT module descriptor

 @Return        Relative storage Profile ID.

 @Cautions      Allowed only following FM_VSP_Init().
*//***************************************************************************/

uint8_t FM_VSP_GetRelativeProfileId(t_Handle h_FmVsp);

/** @} */ /* end of FM_VSP_control_grp group */
/** @} */ /* end of FM_VSP_grp group */
/** @} */ /* end of FM_grp group */


#endif /* __FM_VSP_EXT_H */
