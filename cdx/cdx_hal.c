/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

/* OS abstraction functions used by CDX control code */

#include "cdx.h"

void *Heap_Alloc(int size)
{
	/* FIXME we may want to use dma API's and use non cacheable memory */
	return kmalloc(size, GFP_KERNEL);
}


void Heap_Free(void *p)
{
	kfree(p);
}
