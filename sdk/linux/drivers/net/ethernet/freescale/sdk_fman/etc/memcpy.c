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



#include "std_ext.h"
#include "xx_ext.h"
#include "memcpy_ext.h"

void * MemCpy8(void* pDst, void* pSrc, uint32_t size)
{
    int i;

    for(i = 0; i < size; ++i)
        *(((uint8_t*)(pDst)) + i) = *(((uint8_t*)(pSrc)) + i);

    return pDst;
}

void * MemSet8(void* pDst, int c, uint32_t size)
{
    int i;

    for(i = 0; i < size; ++i)
        *(((uint8_t*)(pDst)) + i) = (uint8_t)(c);

    return pDst;
}

void * IOMemSet32(void* pDst, uint8_t val, uint32_t size)
{
    uint32_t val32;
    uint32_t *p_Dst32;
    uint8_t  *p_Dst8;

    p_Dst8 = (uint8_t*)(pDst);

    /* generate four 8-bit val's in 32-bit container */
    val32  = (uint32_t) val;
    val32 |= (val32 <<  8);
    val32 |= (val32 << 16);

    /* align destination to 32 */
    while((PTR_TO_UINT(p_Dst8) & 3) && size) /* (pDst mod 4) > 0 and size > 0 */
    {
        WRITE_UINT8(*p_Dst8, val);
        p_Dst8++;
        size--;
    }

    /* 32-bit chunks */
    p_Dst32 = (uint32_t*)(p_Dst8);
    while (size >> 2) /* size >= 4 */
    {
        WRITE_UINT32(*p_Dst32, val32);
        p_Dst32++;
        size -= 4;
    }

    /* complete the leftovers */
    p_Dst8 = (uint8_t*)(p_Dst32);
    while (size--)
    {
        WRITE_UINT8(*p_Dst8, val);
        p_Dst8++;
    }

    return pDst;
}

void MemDisp(uint8_t *p, int size)
{
    uint32_t    space = (uint32_t)(PTR_TO_UINT(p) & 0x3);
    uint8_t     *p_Limit;

    if (space)
    {
        p_Limit = (p - space + 4);

        XX_Print("0x%p: ", (p - space));

        while (space--)
        {
            XX_Print("--");
        }
        while (size  && (p < p_Limit))
        {
            XX_Print("%02x", *(uint8_t*)p);
            size--;
            p++;
        }

        XX_Print(" ");
        p_Limit += 12;

        while ((size > 3) && (p < p_Limit))
        {
            XX_Print("%08x ", *(uint32_t*)p);
            size -= 4;
            p += 4;
        }
        XX_Print("\r\n");
    }

    while (size > 15)
    {
        XX_Print("0x%p: %08x %08x %08x %08x\r\n",
                 p, *(uint32_t *)p, *(uint32_t *)(p + 4),
                 *(uint32_t *)(p + 8), *(uint32_t *)(p + 12));
        size -= 16;
        p += 16;
    }

    if (size)
    {
        XX_Print("0x%p: ", p);

        while (size > 3)
        {
            XX_Print("%08x ", *(uint32_t *)p);
            size -= 4;
            p += 4;
        }
        while (size)
        {
            XX_Print("%02x", *(uint8_t *)p);
            size--;
            p++;
        }

        XX_Print("\r\n");
    }
}
