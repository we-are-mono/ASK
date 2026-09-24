/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

#ifndef _MODULE_QM_H_
#define _MODULE_QM_H_

#include "types.h"
#include <linux/if.h>

struct ceetm_fq {
	struct net_device  *net_dev;
	struct qman_fq    egress_fq;
};

#define NO_PORT		-1

#define NUM_PQS			8
#define NUM_WBFQS		8
#define NUM_CHANNEL_SHAPERS	8
#define MAX_SCHEDULER_QUEUES	(NUM_PQS + NUM_WBFQS)
#define GET_CEETM_PRIORITY(x)	((x) < NUM_PQS) ? ((x) ^ (NUM_PQS - 1)) : (x)
#define EGRESS_MAX_CQ_PROFILES  (MAX_SCHEDULER_QUEUES * NUM_CHANNEL_SHAPERS)


/* For byte mode this is the max expected pkt size */
#define DEFAULT_INGRESS_BYTE_MODE_CBS 2000
#define DEFAULT_INGRESS_BYTE_MODE_PBS 2000

enum {
	CDX_EGRESS_MIN_CQ_PROFILE=CDX_INGRESS_ALL_PROFILES + 1,
	CDX_EGRESS_MAX_CQ_PROFILES=(CDX_EGRESS_MIN_CQ_PROFILE + (EGRESS_MAX_CQ_PROFILES -1))
};

struct shaper_info {
	uint64_t rate;
	uint32_t enable;
	uint32_t bsize;
	struct qm_ceetm_rate token_cr;
	/* The excess rate belongs with the committed one. It used to be a local
	 * in each programming site, always zero for an LNI and always the
	 * maximum for a channel -- except in ceetm_enable_or_disable_qos(),
	 * which passed zero for a channel whose shaper was already enabled and
	 * so took away the excess bandwidth its class queues are eligible for.
	 * Holding it here is what makes every site program the same value, and
	 * lets a qdisc name a ceil that is neither of those two. */
	struct qm_ceetm_rate token_er;
};

struct classque_info {
	struct ceetm_fq ceetmfq;
	bool fq_created;
	bool drain_failed;
	uint32_t ceetm_idx;
	void *ccg;			
	void *cq;
	void *lfq;			
	union {
		uint32_t ch_shaper_enable;	/* for Priority queues */
		uint32_t weight;	/* for WBFQs */
	};
	uint32_t qdepth;		/* CQ depths */
	uint32_t shaper_rate;	/* shaper rate in Kbps */
	uint32_t cq_shaper_enable;	/* cq shaper */
	uint8_t  pp_num;		/* policer profile number */
	void     *pp_handle;	/* policer profile handle */
	void     *pcd_handle;       /* handle to fm_pcd device for this fman */
};

#define MAX_DSCP	64
/* The software Tx path's copy of a port's DSCP map. Freed after a grace
 * period: cpe_fp_tx() reads it under the transmit path's RCU-bh section. */
struct qm_dscp_fq_map {
	struct rcu_head rcu;
	struct qman_fq  *dscp_fq[MAX_DSCP];
};

typedef struct cdx_dscp_fqid_s
{
	uint32_t	fqid[MAX_DSCP];
}cdx_dscp_fqid_t;

typedef struct tQM_context_ctl {
        struct cdx_port_info *port_info;
	struct dpa_iface_info *iface_info;
	struct net_device *net_dev;
	struct qm_ceetm_lni *lni;
	struct qm_ceetm_sp *sp;
	/* The DSCP map, in two stages. `dscp_fq_claimed' is the table this
	 * port owns while it holds the microcode's single map, from the claim
	 * to the release; the per-DSCP setters write into it. `dscp_fq_map' is
	 * the same table once published, and NULL otherwise: it is what the
	 * software Tx path reads, and whether it is set is what gives a new
	 * classifier entry the microcode's DSCP bit. A port can hold the claim
	 * unpublished -- before its first filter is programmed, and after its
	 * last is gone while entries installed under it are still retiring. */
	struct qm_dscp_fq_map __rcu *dscp_fq_map;
	struct qm_dscp_fq_map *dscp_fq_claimed;
	uint32_t qos_enabled;		/* port qos control */
	uint32_t chnl_map;
	struct shaper_info shaper_info; /* port shaper config */
} __attribute__((aligned(32))) QM_context_ctl, *PQM_context_ctl;

struct ceetm_chnl_info {
	struct qm_ceetm_channel *channel;
	uint32_t idx;
	uint32_t wbfq_priority;
	uint32_t wbfq_chshaper;
	void *pcd_handle;	/* handle to fm_pcd device for this fman */
	struct shaper_info shaper_info; 
	PQM_context_ctl qm_ctx;
	struct classque_info cq_info[MAX_SCHEDULER_QUEUES]; 
};
#define QM_GET_CONTEXT(output_port) (&gQMCtx[output_port])

/* return values */
#define QOS_ENERR_NOT_CONFIGURED 	1
#define QOS_ENERR_IO	          	2

#define SHAPER_ON               1
#define SHAPER_OFF              2

#define DISABLE_POLICER         0
#define DEFAULT_CQ_CIR_VALUE 0xffffffff
#define DEFAULT_CQ_PIR_VALUE 0xffffffff
/* For byte mode this is the max expected pkt size */
#define DEFAULT_CQ_BYTE_MODE_CBS 2000
#define DEFAULT_CQ_BYTE_MODE_PBS 2000

int qm_init(void);
void qm_exit(void);
extern QM_context_ctl gQMCtx[MAX_PHY_PORTS];

cdx_dscp_fqid_t* get_dscp_fqid_map(uint32_t portid);
int ceetm_dscp_map_claim(struct tQM_context_ctl *qm_ctx);
void ceetm_dscp_map_publish(struct tQM_context_ctl *qm_ctx);
void ceetm_dscp_map_unpublish(struct tQM_context_ctl *qm_ctx);
int ceetm_dscp_map_release(struct tQM_context_ctl *qm_ctx);
int enable_dscp_fqid_map(uint32_t portid);
int disable_dscp_fqid_map(uint32_t portid);
int reset_dscp_fq_map_ff(cdx_dscp_fqid_t *muram_dscp_fqid_map, uint8_t dscp);
int reset_all_dscp_fq_map_ff(cdx_dscp_fqid_t *muram_dscp_fqid_map);

#endif /* _MODULE_QM_H_ */
