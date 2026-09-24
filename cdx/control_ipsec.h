/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

#ifndef _MODULE_IPSEC_H_
#define _MODULE_IPSEC_H_

#include "fe.h"
#include "dpa_ipsec.h"

#define IPSEC_MAX_KEY_SIZE (512 /8)

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

/* AESGCM - 18/19/20 */
#define SADB_X_EALG_CAMELLIACBC         22
#define SADB_EALG_MAX                   253 /* last EALG */
/* private allocations should use 249-255 (RFC2407) */
#define SADB_X_EALG_SERPENTCBC  252     /* draft-ietf-ipsec-ciph-aes-cbc-00 */
#define SADB_X_EALG_TWOFISHCBC  253     /* draft-ietf-ipsec-ciph-aes-cbc-00 */

#define SA_MAX_OP		2	// maximum of stackable SA (ESP+AH)

#define SA_MODE_TUNNEL 0x1
#define SA_MODE_TRANSPORT 0x0

#define IS_NATT_SA(entry) (entry->natt.sport && entry->natt.dport)

typedef struct _tSAID {
	union
	{
	       /*Unused	U32		a4; */
		U32 			a6[4];
		U32			top[4]; // alias
	} daddr;		
	U32		saddr[4];	// added for NAT-T transport mode
	U32		spi;
	U8		proto;
	U8		unused[3];
} SAID, *PSAID;


/*
 * _TSAEntry.flags values
 */
#define SA_NOECN	1
#define SA_DECAP_DSCP	2
#define SA_NOPMTUDISC	4
#define SA_WILDRECV	8
/* Local mirror of the sa flags.  */
#define	SA_ENABLED 	0x10		
#define SA_ALLOW_SEQ_ROLL 0x20
#define SA_ALLOW_EXT_SEQ_NUM 0x40
/* flag to indicate in SA whether the shared descriptor already built or not */
#define SA_SH_DESC_BUILT	0x80
#define SA_DELETE		0x100
#define SA_FQ_WAIT_B4_FREE	0x400 /* reserve 3 bits starting from 0x400 */

/* Words of anti-replay scorecard in the ESP decapsulation PDB, enough for
 * SEC's widest, 128-entry window (struct ipsec_decap_pdb's anti_replay). */
#define SA_REPLAY_SEEN_WORDS	4

#define SA_HDR_COPY_TOS  1
#define SA_HDR_DEC_TTL   2
#define SA_HDR_COPY_DF   4

/*Adding the below defintion to resolve some compilation issue for the time being
 * Should resolve later with proper value Rajendran 06/Oct/2016.
*/ 
#define IPV4_HDR_SIZE  20
#define CDX_DPA_IPSEC_INBOUND     1
#define CDX_DPA_IPSEC_OUTBOUND    0


struct cipher_params {
        U16 cipher_type;    /* Algorithm type as defined by SEC driver   */
        U8 *cipher_key;     /* Address to the encryption key             */
        U32 cipher_key_len; /* Length in bytes of the normal key         */
};

/* DPA IPsec Authentication Parameters */
struct auth_params {
        U16 auth_type;     /* Algorithm type as defined by SEC driver    */
        U8 *auth_key;      /* Address to the normal key                  */
        U32 auth_key_len;  /* Length in bytes of the normal key          */
        U8 *split_key;     /* Address to the generated split key         */
        U32 split_key_len; /* Length in bytes of the split key           */
        U32 split_key_pad_len;/* Length in bytes of the padded split key */
};

/* timer value for defered release of SA resources */
#define SA_CTX_RELEASE_TIMER_VAL (1 * HZ)
/* A24b: cap the FQ-retire poll loop so a wedged FQ doesn't pin the SAEntry
 * forever. SA_CTX_RELEASE_TIMER_VAL is 1s, so this is a 30s wall-clock cap.
 * On cap-hit, the deferred-release callback logs and skips the final free —
 * SA resources leak, but the system stays observable and recoverable for
 * the rest of cdx. */
#define SA_RELEASE_MAX_ITER 30
typedef struct dpa_sec_sa_context_s{
	U32   to_sec_fqid;
	U32   to_cp_fqid;

        void  *dpa_ipsecsa_handle;
	struct cipher_params cipher_data;   /* Encryption parameters          */
        struct auth_params auth_data;       /* Authentication key parameters  */
        struct sec_descriptor  *sec_desc; /* 64 byte aligned address where is
                                          * computed the SEC 4.x descriptor
                                          * according to the SA information.
                                          * do not free this pointer!         */
        U32  *sec_desc_extra_cmds_unaligned;
        U32   *sec_desc_extra_cmds; /* aligned to CORE cache line size     */
        U8  job_desc_len; /* Number of words CAAM Job Descriptor occupies
                                * form the CAAM Descriptor length
                                * MAX_CAAM_DESCSIZE                           */

	/* The descriptor's KEY commands DMA-read these bus addresses on
	 * every SEC job, so the mappings must live as long as the SA —
	 * created in cdx_ipsec_create_shareddescriptor, released in
	 * cdx_ipsec_sec_sa_context_free. 0 = never mapped. */
	dma_addr_t crypto_key_dma;
	dma_addr_t auth_key_dma;
} DpaSecSAContext , *PDpaSecSAContext;

typedef struct _tSAEntry {
	struct slist_entry      list_h;
	struct slist_entry      list_fqid;
	TIMER_ENTRY 		deletion_timer;
	U32			deletion_iter;	/* A24b: poll count for FQ-retire wait; capped via SA_RELEASE_MAX_ITER */
	U16			hash_by_h;
	struct _tSAID           id;             // SA 3-tuple
	U8                      family;         // v4/v6
	U8                      header_len;     // ipv4/ipv6 tunnel header
	U8                      mode;           // Tunnel / transport mode
	U8                      direction;      // inbound / outbound
	U8                      blocksz;
	U8			icvsz;
	U16                      flags;          // ECN, TOS ...
	U16                     handle;
	U16                     mtu;            // used for Transport mode
	union                           // keep union 32 bits aligned !!!
	{
		ipv4_hdr_t      ip4;
		ipv6_hdr_t      ip6;
	} tunnel;
	U16			dev_mtu;
	/*NAT-T modifications*/
	struct
	{
		unsigned short sport;
		unsigned short dport;
	}natt;
	int			natt_arr_index;    /* Array index to spi info in inbound table entry*/
	PDpaSecSAContext 	pSec_sa_context;    /*pointer to the context entry for fqid pair */
	PRouteEntry 		pRtEntry;
	U64 			seq;
	/* The anti-replay window an inbound SA asked for, in packets, when
	 * SA_ALLOW_SEQ_ROLL is clear. Zero only with SA_ALLOW_SEQ_ROLL set:
	 * cdx_ipsec_backend.c asks for no replay checking exactly when the
	 * state has no window. */
	U16			replay_window;
	/* The anti-replay scorecard an inbound SA starts from, in the
	 * orientation SEC keeps it: bit k of word k / 32 stands for seq - k.
	 * Clear unless its creator carried history in with it; the
	 * decapsulation PDB holds SA_REPLAY_SEEN_WORDS of them. */
	U32			replay_seen[SA_REPLAY_SEEN_WORDS];
	U8                      enable_stats;
	U8                      hdr_flags;          // copy DF,TOS  
	U16                     stats_offset;
	struct hw_ct 		*ct;
	U16                    	stats_indx;
	U16                    	next_cmd_indx;
	void 			*netdev;
} SAEntry, *PSAEntry;

void* M_ipsec_sa_cache_lookup_by_h(U16 handle);
void* M_ipsec_get_matched_natt_tunnel(PSAEntry sa);

/* SA construction, which cdx_ipsec_backend.c drives in one pass from a
 * complete description, under the control mutex. Keys are named in the
 * PF_KEY numbering (SADB_AALG_* / SADB_EALG_*). */
void *M_ipsec_sa_cache_create(U32 *saddr, U32 *daddr, U32 spi, U8 proto,
			      U8 family, U16 handle, U8 replay, U8 esn,
			      U16 mtu, U16 dev_mtu, U8 dir);
int M_ipsec_sa_cache_delete(U16 handle);
int M_ipsec_sa_set_digest_key(PSAEntry sa, U16 key_alg, U16 key_bits, U8 *key);
int M_ipsec_sa_set_cipher_key(PSAEntry sa, U16 key_alg, U16 key_bits, U8 *key);
int ipsec_install_fp_entry(PSAEntry sa);
extern struct slist_head sa_cache_by_h[];

void sa_remove_from_list_fqid(PSAEntry pSA);
void sa_free(PSAEntry pSA);
struct net_device *get_netdev_of_SA_by_fqid(uint32_t fqid, uint16_t *sagd_pkt);

int ipsec_init(void);
void ipsec_exit(void);

#endif
