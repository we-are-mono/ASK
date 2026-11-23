/* Copyright (c) 2008-2012 Freescale Semiconductor, Inc
 * All rights reserved.
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

 @File          memcpy_ext.h

 @Description   Efficient functions for copying and setting blocks of memory.
*//***************************************************************************/

#ifndef __MEMCPY_EXT_H
#define __MEMCPY_EXT_H

#include "std_ext.h"


/**************************************************************************//**
 @Group         etc_id   Utility Library Application Programming Interface

 @Description   External routines.

 @{
*//***************************************************************************/

/**************************************************************************//**
 @Group         mem_cpy Memory Copy

 @Description   Memory Copy module functions,definitions and enums.

 @{
*//***************************************************************************/

void * IOMemSet32(void* pDst, uint8_t val, uint32_t size);

/**************************************************************************//**
 @Function      MemDisp

 @Description   Displays a block of memory in chunks of 32 bits.

 @Param[in]     addr    - The address of the memory to display.
 @Param[in]     size    - The number of bytes that will be displayed.

 @Return        None.

 @Cautions      There is no parameter or boundary checking! It is up to the user
                to supply non null parameter as destination and size
                that actually fits into the destination buffer.
*//***************************************************************************/
void MemDisp(uint8_t *addr, int size);

/**************************************************************************//**
 @Function      MemCpy8

 @Description   Trivial copy one memory buffer into another byte by byte

 @Param[in]     pDst    - The address of the destination buffer.
 @Param[in]     pSrc    - The address of the source buffer.
 @Param[in]     size    - The number of bytes that will be copied from pSrc to pDst.

 @Return        pDst (the address of the destination buffer).

 @Cautions      There is no parameter or boundary checking! It is up to the user
                to supply non-null parameters as source & destination and size
                that actually fits into the destination buffer.
*//***************************************************************************/
void * MemCpy8(void* pDst,void* pSrc, uint32_t size);

/**************************************************************************//**
 @Function      MemSet8

 @Description   Sets all bytes of a memory buffer to a specific value byte by byte.

 @Param[in]     pDst    - The address of the destination buffer.
 @Param[in]     c       - Value to set destination bytes to.
 @Param[in]     size    - The number of bytes that will be set to val.

 @Return        pDst (the address of the destination buffer).

 @Cautions      There is no parameter or boundary checking! It is up to the user
                to supply non null parameter as destination and size
                that actually fits into the destination buffer.
*//***************************************************************************/
void * MemSet8(void* pDst, int c, uint32_t size);

/** @} */ /* end of mem_cpy group */
/** @} */ /* end of etc_id group */


#endif /* __MEMCPY_EXT_H */
