/*
 *
 *  Copyright (C) 2007 Mindspeed Technologies, Inc.
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 *
 */
#ifndef __KEYTRACK_H__
#define __KEYTRACK_H__

#include "list.h"
#include "conntrack.h"
#include "module_ipsec.h"


#define MAX_SA_BUNDLE 4
typedef struct netkey_sa_update_cmd{
	unsigned short sagd;
	unsigned short rsvd;
	unsigned long long bytes;
	unsigned long long packets;
}netkey_sa_update_cmd_t;

#define FLOW_DIR_IN     0  //  Input flow  for all local traffic
#define FLOW_DIR_OUT    1  // Output flow to be sent out with ipsec policy applied 
#define FLOW_DIR_FWD    2  // Forwarded flow for all traffic getting forwarded

#define FLOW_DIR_OUT_BITVAL (1 << FLOW_DIR_OUT)
#define FLOW_DIR_FWD_BITVAL (1 << FLOW_DIR_FWD)

#define SAQUERY_UNKNOWN_CMD	0
#define SAQUERY_ENABLE_CMD	1
#define SAQUERY_TIMER_CMD	2

#define NETKEY_CMD_SA_INFO_UPDATE	0x0a0c

/* Authentication algorithms */
#define SADB_AALG_NONE                  0
#define SADB_AALG_MD5HMAC               2
#define SADB_AALG_SHA1HMAC              3
#define SADB_X_AALG_SHA2_256HMAC        5
#define SADB_X_AALG_SHA2_384HMAC        6
#define SADB_X_AALG_SHA2_512HMAC        7
#define SADB_X_AALG_RIPEMD160HMAC       8
#define SADB_X_AALG_AES_XCBC_MAC        9
#define SADB_X_AALG_NULL                251     /* kame */
#define SADB_AALG_MAX                   251


/* Encryption algorithms */
#define SADB_EALG_NONE                  0
#define SADB_EALG_DESCBC                2
#define SADB_EALG_3DESCBC               3
#define SADB_X_EALG_CASTCBC             6
#define SADB_X_EALG_BLOWFISHCBC         7
#define SADB_EALG_NULL                  11
#define SADB_X_EALG_AESCBC              12
#define SADB_X_EALG_AESCTR              13
#define SADB_X_EALG_AES_CCM_ICV8        14
#define SADB_X_EALG_AES_CCM_ICV12       15
#define SADB_X_EALG_AES_CCM_ICV16       16
#define SADB_X_EALG_AES_GCM_ICV8        18
#define SADB_X_EALG_AES_GCM_ICV12       19
#define SADB_X_EALG_AES_GCM_ICV16       20
#define SADB_X_EALG_NULL_AES_GMAC	23


/* AESGCM - 18/19/20 */
#define SADB_X_EALG_CAMELLIACBC         22
/* private allocations should use 249-255 (RFC2407) */
#define SADB_X_EALG_SERPENTCBC  252     /* draft-ietf-ipsec-ciph-aes-cbc-00 */
#define SADB_X_EALG_TWOFISHCBC  253     /* draft-ietf-ipsec-ciph-aes-cbc-00 */

#define SADB_EALG_MAX                   253 /* last EALG */


extern pthread_mutex_t flowMutex;

int cmmKeyCatch(unsigned short fcode, unsigned short len, unsigned short *payload);
int cmmKeyEnginetoIPSec(FCI_CLIENT *fci_handle, unsigned short fcode, unsigned short len, void *payload);
int cmmIPSectoKeyEngine(FCI_CLIENT *fci_handle, unsigned short fcode, unsigned short len, void *payload);
int cmmUpdateFlows(struct SATable *pSAEntry);
int cmmUpdateFlowsWithNewSAInfo(struct SATable *pNewSAEntry,unsigned short old_xfrm_handle);

int cmmDPDSaQuerySetProcess(char ** keywords, int tabStart, daemon_handle_t daemon_handle);
int cmmSaQueryTimerShow(struct cli_def * cli, const char *command, char *argv[], int argc);
int cmmDPDSAQUERYProcessClientCmd(u_int8_t *cmd_buf, u_int16_t *res_buf, u_int16_t *res_len);
#endif
