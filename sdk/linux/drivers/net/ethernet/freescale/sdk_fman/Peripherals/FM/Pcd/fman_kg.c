/*
 * Copyright 2008-2012 Freescale Semiconductor Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *	 notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *	 notice, this list of conditions and the following disclaimer in the
 *	 documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *	 names of its contributors may be used to endorse or promote products
 *	 derived from this software without specific prior written permission.
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
#define __ERR_MODULE__ MODULE_FM_PCD

#include "std_ext.h"
#include "error_ext.h"
#include "fsl_fman_kg.h"

/****************************************/
/*       static functions               */
/****************************************/


static uint32_t build_ar_bind_scheme(uint8_t hwport_id, bool write)
{
	uint32_t rw;

	rw = write ? (uint32_t)FM_KG_KGAR_WRITE : (uint32_t)FM_KG_KGAR_READ;

	return (uint32_t)(FM_KG_KGAR_GO |
			rw |
			FM_PCD_KG_KGAR_SEL_PORT_ENTRY |
			hwport_id |
			FM_PCD_KG_KGAR_SEL_PORT_WSEL_SP);
}

static void clear_pe_all_scheme(struct fman_kg_regs *regs, uint8_t hwport_id)
{
	uint32_t ar;

	fman_kg_write_sp(regs, 0xffffffff, 0);

	ar = build_ar_bind_scheme(hwport_id, TRUE);
	fman_kg_write_ar_wait(regs, ar);
}

static uint32_t build_ar_bind_cls_plan(uint8_t hwport_id, bool write)
{
	uint32_t rw;

	rw = write ? (uint32_t)FM_KG_KGAR_WRITE : (uint32_t)FM_KG_KGAR_READ;

	return (uint32_t)(FM_KG_KGAR_GO |
			rw |
			FM_PCD_KG_KGAR_SEL_PORT_ENTRY |
			hwport_id |
			FM_PCD_KG_KGAR_SEL_PORT_WSEL_CPP);
}

static void clear_pe_all_cls_plan(struct fman_kg_regs *regs, uint8_t hwport_id)
{
	uint32_t ar;

	fman_kg_write_cpp(regs, 0);

	ar = build_ar_bind_cls_plan(hwport_id, TRUE);
	fman_kg_write_ar_wait(regs, ar);
}

int fman_kg_write_ar_wait(struct fman_kg_regs *regs, uint32_t fmkg_ar)
{
	iowrite32be(fmkg_ar, &regs->fmkg_ar);
	/* Wait for GO to be idle and read error */
	while ((fmkg_ar = ioread32be(&regs->fmkg_ar)) & FM_KG_KGAR_GO) ;
	if (fmkg_ar & FM_PCD_KG_KGAR_ERR)
		return -EINVAL;
	return 0;
}

void fman_kg_write_sp(struct fman_kg_regs *regs, uint32_t sp, bool add)
{

	struct fman_kg_pe_regs *kgpe_regs;
	uint32_t tmp;

	kgpe_regs = (struct fman_kg_pe_regs *)&(regs->fmkg_indirect[0]);
	tmp = ioread32be(&kgpe_regs->fmkg_pe_sp);

	if (add)
		tmp |= sp;
	else /* clear */
		tmp &= ~sp;

	iowrite32be(tmp, &kgpe_regs->fmkg_pe_sp);

}

void fman_kg_write_cpp(struct fman_kg_regs *regs, uint32_t cpp)
{
	struct fman_kg_pe_regs *kgpe_regs;

	kgpe_regs = (struct fman_kg_pe_regs *)&(regs->fmkg_indirect[0]);

	iowrite32be(cpp, &kgpe_regs->fmkg_pe_cpp);
}

void fman_kg_get_event(struct fman_kg_regs *regs,
			uint32_t *event,
			uint32_t *scheme_idx)
{
	uint32_t mask, force;

	*event = ioread32be(&regs->fmkg_eer);
	mask = ioread32be(&regs->fmkg_eeer);
	*scheme_idx = ioread32be(&regs->fmkg_seer);
	*scheme_idx &= ioread32be(&regs->fmkg_seeer);

	*event &= mask;

	/* clear the forced events */
	force = ioread32be(&regs->fmkg_feer);
	if (force & *event)
		iowrite32be(force & ~*event ,&regs->fmkg_feer);

	iowrite32be(*event, &regs->fmkg_eer);
	iowrite32be(*scheme_idx, &regs->fmkg_seer);
}


void fman_kg_init(struct fman_kg_regs *regs,
			uint32_t exceptions,
			uint32_t dflt_nia)
{
	uint32_t tmp;
	int i;

	iowrite32be(FM_EX_KG_DOUBLE_ECC | FM_EX_KG_KEYSIZE_OVERFLOW,
			&regs->fmkg_eer);

	tmp = 0;
	if (exceptions & FM_EX_KG_DOUBLE_ECC)
        	tmp |= FM_EX_KG_DOUBLE_ECC;

	if (exceptions & FM_EX_KG_KEYSIZE_OVERFLOW)
		tmp |= FM_EX_KG_KEYSIZE_OVERFLOW;

	iowrite32be(tmp, &regs->fmkg_eeer);
	iowrite32be(0, &regs->fmkg_fdor);
	iowrite32be(0, &regs->fmkg_gdv0r);
	iowrite32be(0, &regs->fmkg_gdv1r);
	iowrite32be(dflt_nia, &regs->fmkg_gcr);

	/* Clear binding between ports to schemes and classification plans
	 * so that all ports are not bound to any scheme/classification plan */
	for (i = 0; i < FMAN_MAX_NUM_OF_HW_PORTS; i++) {
		clear_pe_all_scheme(regs, (uint8_t)i);
		clear_pe_all_cls_plan(regs, (uint8_t)i);
	}
}

void fman_kg_enable_scheme_interrupts(struct fman_kg_regs *regs)
{
	/* enable and enable all scheme interrupts */
	iowrite32be(0xFFFFFFFF, &regs->fmkg_seer);
	iowrite32be(0xFFFFFFFF, &regs->fmkg_seeer);
}

void fman_kg_enable(struct fman_kg_regs *regs)
{
	iowrite32be(ioread32be(&regs->fmkg_gcr) | FM_KG_KGGCR_EN,
			&regs->fmkg_gcr);
}

void fman_kg_disable(struct fman_kg_regs *regs)
{
	iowrite32be(ioread32be(&regs->fmkg_gcr) & ~FM_KG_KGGCR_EN,
			&regs->fmkg_gcr);
}



