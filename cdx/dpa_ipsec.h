/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

#include <linux/types.h>
#include "pdb.h"

#ifndef DPA_IPSEC_H
#define DPA_IPSEC_H

/* following flags are used to set in context A field of FQD */
#define CDX_FQD_CTX_A_OVERRIDE_FQ	0x80
#define CDX_FQD_CTX_A_IGNORE_CMD	0x40
#define CDX_FQD_CTX_A_A1_FIELD_VALID	0x20
#define CDX_FQD_CTX_A_A2_FIELD_VALID	0x10
#define CDX_FQD_CTX_A_A0_FIELD_VALID	0x08
#define CDX_FQD_CTX_A_B0_FIELD_VALID	0x04
#define CDX_FQD_CTX_A_OVERRIDE_OMB	0x02
#define CDX_FQD_CTX_A_SHIFT_BITS	24 /* the above flags are set in most
					significant byte of context A field */

/* A1 field setting in context A field of FQD */
#define CDX_FQD_CTX_A_A1_VAL_TO_CHECK_SECERR 2

#define MAX_SHARED_DESC_SIZE 	62	
#define PRE_HDR_ALIGN		64

#define FQ_FROM_SEC		0
#define FQ_TO_SEC		1
#define FQ_TO_CP		2 /* creating a frame queue to receive a packet to CP */


/*If we have to avoid adding sagd in packet, we need to use this
  logic, currently some issue with this ,
  so adding this code under a macro */
#define NUM_FQS_PER_SA	3 /* creating 3 frame queues per SA */


#define IPSEC_FMAN_IDX		0
#define DEFA_WQ_ID              0
struct desc_hdr {
        uint32_t sd_hdr;
        union {
                struct ipsec_encap_pdb pdb_encrypt;
                struct ipsec_decap_pdb pdb_decrypt;
        };
};

#define AES_GCM_SALT_LEN	4
#define AES_CCM_SALT_LEN	3
#define AES_CTR_SALT_LEN	4	/* RFC 3686 */
#define AES_CCM_INIT_COUNTER	0x0
#define AES_CCM_ICV8_IV_FLAG	0x5B
#define AES_CCM_ICV12_IV_FLAG	0x6B
#define AES_CCM_ICV16_IV_FLAG	0x7B
#define AES_CCM_CTR_FLAG	0x03
struct encap_ccm_opt {
	u8 b0_flags;
	u8 ctr_flags;
	u16 ctr_initial;
};
struct decap_ccm_opt {
	u8 b0_flags;
	u8 ctr_flags;
	u16 ctr_initial;
};
struct sec_descriptor {
        uint64_t preheader;
        /* SEC Shared Descriptor */
        union {
                uint32_t shared_desc[MAX_SHARED_DESC_SIZE];
                struct desc_hdr desc_hdr;
#define hdr_word        desc_hdr.sd_hdr
#define pdb_en          desc_hdr.pdb_encrypt
#define pdb_dec         desc_hdr.pdb_decrypt
        };
};

/* For all Buffer pools using the ethernet driver seed routine,
 * we'll be using the same   BPOOL size */
#define IPSEC_BUFSIZE	dpa_bp_size(NULL)
/* SEC's output pool. A frame holds one of its buffers from SEC's job until the
 * frame leaves: sent by a port, dropped, or copied out by the CPU. Every queue
 * such a frame can wait on is bounded in frames, and the bounds add up to the
 * pool:
 *
 *   - fixed shares of IPSEC_SHARE_FRAMES each: the exception queues
 *     (IPSEC_EXCEPTION_FRAMES), the Wi-Fi VAPs' queues (VWD_FWD_FRAMES) and
 *     each Ethernet port's queues for these frames (IPSEC_EGRESS_FRAMES) --
 *     896 on a board of five ports;
 *   - four shares for the SAs' input queues (IPSEC_TO_SEC_FRAMES), where a
 *     frame one SA decrypted waits for the SA that encrypts it again, among
 *     frames holding the Ethernet pool's buffers it cannot be told from;
 *   - eight for the class queues of hardware qdisc trees, all of them
 *     together (IPSEC_QDISC_FRAMES, cdx_htb.c), which carry SEC's frames among
 *     the rest and cannot tell them apart either;
 *   - and what is left, 128 on five ports, for SEC's own jobs in flight and
 *     their output on its way to the offline port, of which it has a few
 *     dozen at line rate -- twice that where a relayed job's input is a
 *     buffer of this pool too.
 *
 * So all of them full at once still leave SEC its own. Each buffer is an
 * order-2 allocation, 16 KiB with jumbo frames, so the pool takes 40 MiB:
 * 16 MiB more than before the qdisc trees had their eight shares (A337), and
 * 8 MiB more for the SAs' input (A345). */
#define IPSEC_BUFCOUNT  2560
#define	THRESHOLD_IPSEC_BPOOL_REFILL 16
/* One share of the pool, in frames. A literal rather than a fraction of
 * IPSEC_BUFCOUNT: what a share holds is also how long a frame may wait on its
 * queues, and the pool grew for the qdisc trees and the SAs' input without
 * any queue growing longer. */
#define IPSEC_SHARE_FRAMES	128
/* A frame the IPsec offline port sends the CPU, having missed its flow table,
 * waits on an exception queue in a buffer of SEC's output pool. Together the
 * exception queues hold at most this many; QMan refuses the port's enqueue
 * past it and FMan drops the frame. Unbounded, a burst of misses faster than
 * the CPU drains them -- the tail of a flow being torn down, the head of one
 * not yet offloaded, a flow never offloaded -- held the whole pool, and SEC
 * refused every job of every SA, offloaded flows' included, for want of an
 * output buffer. */
#define IPSEC_EXCEPTION_FRAMES	IPSEC_SHARE_FRAMES
/* The same for what the offline port sends out of one Ethernet port: at most
 * this many frames wait in that port's queues for SEC's buffers (devman.c),
 * whatever the link does -- paused by its partner, slower than the tunnel; a
 * slow link's share is smaller, for its latency. A port's own forwarding
 * queues hold a share of the Ethernet pool, more than this whole pool, and
 * when they bounded bytes held thousands of these. */
#define IPSEC_EGRESS_FRAMES	IPSEC_SHARE_FRAMES
/* What every hardware qdisc tree's class queues together may hold of the
 * pool, which cdx_htb.c divides between the trees that are live. */
#define IPSEC_QDISC_FRAMES	(8 * IPSEC_SHARE_FRAMES)
/* A frame waiting on an SA's input queue holds a buffer until SEC has read it,
 * and nothing replaces it meanwhile: one of the pool every DPAA port receives
 * into, or, decrypted by one SA and sent on into another, one of this pool.
 * Offered faster than SEC encrypts or decrypts, the queues took the whole
 * Ethernet pool, and every port missed whatever it received, the kernel's own
 * frames included (A344); a hub relaying between tunnels could take this one
 * and starve every SA as A333 did (A345). So every SA's input queue joins one
 * group that drops at the tail past this many frames, which both pools budget
 * for: four shares of this one, and less than the share of the Ethernet pool
 * one port's forwarding queues may hold (fwd_pool_frames()). That is some
 * 2.5 ms of SEC's work in full-size frames. */
#define IPSEC_TO_SEC_FRAMES	(4 * IPSEC_SHARE_FRAMES)

struct ipsec_info; 
void *  dpa_get_ipsec_instance(void);
void *cdx_dpa_ipsecsa_alloc(struct ipsec_info *info, uint32_t handle); 
int dpa_ipsec_ofport_td(struct ipsec_info *info, uint32_t table_type, void **td, 
			uint32_t* portid);
int cdx_dpa_ipsecsa_release(void *handle) ;
/* Hold the SA's FQIDs when its queues are released: a classifier entry naming
 * one may still be linked. The hold lasts until the datapath restart that
 * settles that entry; control mutex held. */
void cdx_dpa_ipsecsa_keep_fqids(void *handle);
/* The restart's part: give back every FQID range held so far. Returns how many
 * ranges went back. Control mutex held. */
unsigned int cdx_dpa_ipsec_release_held_fqids(void);
/* Unload, after CDX has settled what it recorded as possibly linked: settled,
 * every range still held goes back, since nothing can name it any more;
 * otherwise each stays allocated for the reset that alone can prove its entry
 * gone, and only the bookkeeping goes. Control mutex held. */
void cdx_dpa_ipsec_held_fqids_exit(bool settled);
uint32_t get_fqid_to_sec(void *handle);
uint32_t ipsec_get_to_cp_fqid(void *handle);
uint32_t ipsec_get_key_tag(void *handle);
void ipsec_share_key_tag(void *handle, void *other);

struct sec_descriptor *get_shared_desc(void *handle);

struct qman_fq *get_to_sec_fq(void *handle);

int cdx_dpa_get_ipsec_pool_info(uint32_t *bpid, uint32_t *buf_size);
int cdx_dpa_ipsec_offline_port_rejected(u32 *count);
u32 cdx_dpa_ipsec_input_refused(void);
int cdx_dpa_ipsec_init(void);
void cdx_dpa_ipsec_exit(void);
bool cdx_dpa_ipsec_ready(void);

int cdx_init_scatter_gather_bpool(void);
int cdx_init_skb_2bfreed_bpool(void);

int cdx_init_fqid_procfs(void);
void cdx_deinit_fqid_procfs(void);

/* SA frame queue management */
int cdx_dpa_ipsec_retire_fq(void *handle, int fq_num);
int cdx_ipsec_sa_fq_check_if_retired_state(void *dpa_ipsecsa_handle, int fq_num);
/* One step towards an SA queue out of service: 0 out of service, 1 retired,
 * -EBUSY retiring. Never waits. Control mutex held. */
int cdx_dpa_ipsec_fq_stop(void *handle, int fq_num);

#endif
