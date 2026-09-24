/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

#ifdef DPA_IPSEC_OFFLOAD
#include "dpaa_eth_common.h"
#include "cdx.h"
#include "cdx_common.h"
#include "control_ipv4.h"
#include "control_ipv6.h"
#include "layer2.h"
#include "control_ipsec.h"
#include "cdx_dpa_ipsec.h"
#include "misc.h"

//#define CONTROL_IPSEC_DEBUG 1

struct slist_head sa_cache_by_h[NUM_SA_ENTRIES];
struct slist_head sa_cache_by_fqid[NUM_SA_ENTRIES];

void sa_free(PSAEntry pSA)
{
	Heap_Free(pSA);
}

static PSAEntry sa_alloc(void)
{
	PSAEntry pSA = NULL;
	pSA = Heap_Alloc_ARAM(sizeof(SAEntry));	
	if(pSA)
		memset(pSA, 0, sizeof(SAEntry));
	return (pSA);
}

/* Two SA-cache readers run OUTSIDE ctrl.mutex, both in atomic context:
 * get_netdev_of_SA_by_fqid() walks by_fqid from the QMan portal dqrr
 * callback (softirq, or hardirq via the portal ISR when portal NAPI is
 * off), and cdx_get_to_sec_fq_handler() — the registered datapath hook —
 * walks by_h from the DPAA submit paths (softirq). Both race the SA
 * add/remove sites, which run in process context under ctrl.mutex and
 * free the SAEntry right after unlinking. This irqsave spinlock closes
 * both races: writers take it around every list mutation (by_h and
 * by_fqid), the two atomic readers take it across their walk and
 * copy out what they need before unlocking. Walkers already under
 * ctrl.mutex are serialized against the writers by the mutex and stay
 * lock-free. Never nests inside another lock; contention is nil
 * (writers are SA install/teardown only). */
static DEFINE_SPINLOCK(sa_cache_lock);

static int sa_add(PSAEntry pSA)
{
	unsigned long irqflags;

	spin_lock_irqsave(&sa_cache_lock, irqflags);
	slist_add(&sa_cache_by_h[pSA->hash_by_h], &pSA->list_h);
	spin_unlock_irqrestore(&sa_cache_lock, irqflags);

	return NO_ERR;
}

void sa_remove_from_list_fqid(PSAEntry pSA)
{
	unsigned long irqflags;
	U16 hash;

	hash = (pSA->pSec_sa_context->to_cp_fqid & (NUM_SA_ENTRIES - 1));
	/* Once unlinked under the lock, no atomic walker can reach the
	 * entry, so the frees that follow in the callers need no grace
	 * period. */
	spin_lock_irqsave(&sa_cache_lock, irqflags);
	slist_remove(&sa_cache_by_fqid[hash], &pSA->list_fqid);
	spin_unlock_irqrestore(&sa_cache_lock, irqflags);
}
static void sa_remove(PSAEntry pSA)
{
	unsigned long irqflags;

	/* The route is the owner's, embedded in it (cdx_ipsec_backend.c);
	 * nothing is released through the pointer. */
	pSA->pRtEntry = NULL;

	/* Unlink under the lock so the softirq by_h walker
	 * (cdx_get_to_sec_fq_handler) can never hold this entry across the
	 * release/free chain that follows. */
	spin_lock_irqsave(&sa_cache_lock, irqflags);
	slist_remove(&sa_cache_by_h[pSA->hash_by_h], &pSA->list_h);
	spin_unlock_irqrestore(&sa_cache_lock, irqflags);

	/*
	 * remove the table entry and free the Sec_SA context
	 */
	cdx_ipsec_release_sa_resources(pSA);
}

void*  M_ipsec_sa_cache_lookup_by_h( U16 handle)
{
	U16 hash = handle & (NUM_SA_ENTRIES -1);
	PSAEntry pEntry;
	PSAEntry pSA = NULL;
	struct slist_entry *entry;

	slist_for_each(pEntry, entry, &sa_cache_by_h[hash], list_h)
	{
		if (pEntry->handle == handle)
			pSA = pEntry;
	}
	return pSA;
}

/* This function matches if there is a NATT SA with the same 5-tuple info but different spi */
void* M_ipsec_get_matched_natt_tunnel(PSAEntry sa)
{
	int i;
	struct slist_entry *entry;
	PSAEntry pEntry;

	/* Only a NAT-T SA can have a NAT-T twin. */
	if (!IS_NATT_SA(sa))
		return NULL;

	for (i = 0; i < NUM_SA_ENTRIES; i++)
	{
		slist_for_each(pEntry, entry, &sa_cache_by_h[i], list_h)
		{
			/* Filter the CANDIDATE: a non-NAT-T entry's natt
			 * fields are never initialized, so comparing them
			 * below would read meaningless bytes. (This test
			 * previously named `sa`, re-checking the argument
			 * on every iteration and never filtering entries.) */
			if (!IS_NATT_SA(pEntry))
				continue;
#ifdef CONTROL_IPSEC_DEBUG
			printk("%x:%x - %x:%x - %x:%x - %x:%x - %x:%x - %x:%x - %x:%x - %x:%x - %x:%x - %x:%x - %x:%x - %x:%x\n", \
				pEntry->natt.sport,  sa->natt.sport, pEntry->natt.dport,  \
				sa->natt.dport, pEntry->family, sa->family, pEntry->id.spi, sa->id.spi, \
				pEntry->id.saddr[0], sa->id.saddr[0], pEntry->id.saddr[1], sa->id.saddr[1], \
				pEntry->id.saddr[2],  sa->id.saddr[2], pEntry->id.saddr[3], sa->id.saddr[3], \
				pEntry->id.daddr.a6[0], sa->id.daddr.a6[0], pEntry->id.daddr.a6[1],  sa->id.daddr.a6[1], \
				pEntry->id.daddr.a6[2], sa->id.daddr.a6[2], pEntry->id.daddr.a6[3], sa->id.daddr.a6[3]);

#endif
			if ( (pEntry->natt.sport == sa->natt.sport) &&
					(pEntry->natt.dport == sa->natt.dport) &&
					(pEntry->family == sa->family) &&
					(pEntry->id.spi != sa->id.spi) &&
					(pEntry->id.saddr[0] == sa->id.saddr[0]) &&
					(pEntry->id.saddr[1] == sa->id.saddr[1]) &&
					(pEntry->id.saddr[2] == sa->id.saddr[2]) &&
					(pEntry->id.saddr[3] == sa->id.saddr[3]) &&
					(pEntry->id.daddr.a6[0] == sa->id.daddr.a6[0]) &&
					(pEntry->id.daddr.a6[1] == sa->id.daddr.a6[1]) &&
					(pEntry->id.daddr.a6[2] == sa->id.daddr.a6[2]) &&
					(pEntry->id.daddr.a6[3] == sa->id.daddr.a6[3]) ) 
				return pEntry;
		}
	}
	return NULL;
}


/* The SEC protocol operation that authenticates as PF_KEY algorithm `alg`
 * with an ICV of `icv_bits`, or -1 when SEC has none.
 *
 * PF_KEY numbers an authenticator by its algorithm alone, but the ICV it
 * leaves on each frame is the SA's own truncation, and peers choose it: RFC
 * 4868 gives SHA-2 half its digest, while older Linux and strongSwan's
 * sha256_96 cut SHA-256 to 96 bits. SEC's IPsec protocol fixes the ICV in the
 * operation itself (SEC RM table 7-54, PROTINFO[7:0]), so each pair below is
 * one operation and no pair missing from it can be carried: the frames would
 * leave with an ICV of the wrong length and every one received would fail
 * SEC's check. Null authentication leaves no ICV at all. */
int cdx_ipsec_auth_op(u16 alg, unsigned int icv_bits)
{
	static const struct {
		u16 alg;
		u16 icv_bits;
		u16 op;
	} ops[] = {
		{ SADB_AALG_MD5HMAC,		 96, OP_PCL_IPSEC_HMAC_MD5_96 },
		{ SADB_AALG_MD5HMAC,		128, OP_PCL_IPSEC_HMAC_MD5_128 },
		{ SADB_AALG_SHA1HMAC,		 96, OP_PCL_IPSEC_HMAC_SHA1_96 },
		{ SADB_AALG_SHA1HMAC,		160, OP_PCL_IPSEC_HMAC_SHA1_160 },
		{ SADB_X_AALG_SHA2_256HMAC,	128, OP_PCL_IPSEC_HMAC_SHA2_256_128 },
		{ SADB_X_AALG_SHA2_384HMAC,	192, OP_PCL_IPSEC_HMAC_SHA2_384_192 },
		{ SADB_X_AALG_SHA2_512HMAC,	256, OP_PCL_IPSEC_HMAC_SHA2_512_256 },
		{ SADB_X_AALG_AES_XCBC_MAC,	 96, OP_PCL_IPSEC_AES_XCBC_MAC_96 },
		{ SADB_X_AALG_NULL,		  0, OP_PCL_IPSEC_HMAC_NULL },
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(ops); i++)
		if (ops[i].alg == alg && ops[i].icv_bits == icv_bits)
			return ops[i].op;
	return -1;
}

int M_ipsec_sa_set_digest_key(PSAEntry sa, U16 key_alg, unsigned int icv_bits,
			      U16 key_bits, U8 *key)
{
	int      algo;

	if ((key_bits/8) > IPSEC_MAX_KEY_SIZE)
	{
		DPA_ERROR("%s (%d) key_bits %u higher than max key size\n",__func__,__LINE__, key_bits);
		return -1;
	}

	algo = cdx_ipsec_auth_op(key_alg, icv_bits);
	if (algo < 0)
		return -1;
	sa->pSec_sa_context->auth_data.auth_type = algo;
	sa->pSec_sa_context->auth_data.auth_key_len = (key_bits/8);
	memcpy(sa->pSec_sa_context->auth_data.auth_key,	key, (key_bits/8));
	/* Generate the split key from the normal auth key. XCBC-MAC derives
	 * its keys inside the SEC program and null auth has no key at all, so
	 * neither has a split key to compute. Compare in the OP_PCL namespace
	 * that the mapping above produced, not the SADB one it consumed. A
	 * truncation changes only the operation, never the split key: MD5 and
	 * SHA-1 derive the same one at either ICV length. */
	if (algo != OP_PCL_IPSEC_AES_XCBC_MAC_96 && algo != OP_PCL_IPSEC_HMAC_NULL)
		cdx_ipsec_generate_split_key(&sa->pSec_sa_context->auth_data );
	return 0;
}


int M_ipsec_sa_set_cipher_key(PSAEntry sa, U16 key_alg, U16 key_bits, U8* key)
{
	U16      algo;
	uint8_t	 comb_mode=0, extra_size=0;

	if ((key_bits/8) > IPSEC_MAX_KEY_SIZE)
	{
		DPA_ERROR("%s (%d) key_bits %u higher than max key size\n",__func__,__LINE__, key_bits);
		return -1;
	}

	switch (key_alg) {
		case SADB_X_EALG_AESCTR:
			algo = OP_PCL_IPSEC_AES_CTR;
			sa->blocksz = 16;
			comb_mode = 1;
			extra_size = 4;	/* RFC 3686 nonce trails the AES key */
			break;
		case SADB_X_EALG_AESCBC:
			algo = OP_PCL_IPSEC_AES_CBC;
			sa->blocksz = 16;
			break;
		case SADB_X_EALG_AES_CCM_ICV8:
			algo = OP_PCL_IPSEC_AES_CCM8;
			comb_mode = 1;
			extra_size = 3;
			sa->blocksz = 16;
			sa->icvsz = 8;
			sa->pSec_sa_context->auth_data.split_key_len = 0;
			break;
		case SADB_X_EALG_AES_CCM_ICV12:
			algo = OP_PCL_IPSEC_AES_CCM12;
			comb_mode = 1;
			extra_size = 3;
			sa->blocksz = 16;
			sa->icvsz = 12;
			sa->pSec_sa_context->auth_data.split_key_len = 0;
			break;
		case SADB_X_EALG_AES_CCM_ICV16:
			algo = OP_PCL_IPSEC_AES_CCM16;
			sa->blocksz = 16;
			comb_mode = 1;
			extra_size = 3;
			sa->icvsz = 16;
			sa->pSec_sa_context->auth_data.split_key_len = 0;
			break;
		/* GCM offload re-enabled: the shared-descriptor sharing
		 * policy now keeps GHASH context and PDB.seq coherent across
		 * DECOs — see cdx_ipsec_sh_desc_hdr_flags() in
		 * cdx_dpa_ipsec.c. RFC 4106: 4-byte salt trails the AES
		 * key, hence comb_mode with extra_size 4.
		 *
		 * SADB_X_EALG_NULL_AES_GMAC has no arm: SEC's AES-GMAC leaves
		 * out of its ICV the IV that RFC 4543 authenticates, so no
		 * peer would accept a frame it produced (ft_ipsec_spec()). */
		case SADB_X_EALG_AES_GCM_ICV8:
			algo = OP_PCL_IPSEC_AES_GCM8;
			sa->blocksz = 16;
			comb_mode = 1;
			extra_size = 4;
			sa->icvsz = 8;
			sa->pSec_sa_context->auth_data.split_key_len = 0;
			break;
		case SADB_X_EALG_AES_GCM_ICV12:
			algo = OP_PCL_IPSEC_AES_GCM12;
			comb_mode = 1;
			extra_size = 4;
			sa->blocksz = 16;
			sa->icvsz = 12;
			sa->pSec_sa_context->auth_data.split_key_len = 0;
			break;
		case SADB_X_EALG_AES_GCM_ICV16:
			algo = OP_PCL_IPSEC_AES_GCM16;
			sa->blocksz = 16;
			comb_mode = 1;
			extra_size = 4;
			sa->icvsz = 16;
			sa->pSec_sa_context->auth_data.split_key_len = 0;
			break;
		case SADB_EALG_3DESCBC:
			algo = OP_PCL_IPSEC_3DES;
			sa->blocksz = 8;
			break;
		case SADB_EALG_DESCBC:
			algo = OP_PCL_IPSEC_DES;
			sa->blocksz = 8;
			break;
		case SADB_EALG_NULL:
			algo  = OP_PCL_IPSEC_NULL_ENC;
			sa->blocksz = 0;
			break;
		default:
			return -1;
	}
	sa->pSec_sa_context->cipher_data.cipher_type =algo ;
	sa->pSec_sa_context->cipher_data.cipher_key_len = (key_bits/8);
	memcpy(sa->pSec_sa_context->cipher_data.cipher_key, key, (key_bits/8));
	if (comb_mode)
	{
		sa->pSec_sa_context->cipher_data.cipher_key_len -= extra_size;
	}

	return 0;
}

void *M_ipsec_sa_cache_create(U32 *saddr, U32 *daddr, U32 spi, U8 proto, U8 family, U16 handle, U8 replay, U8 esn, U16 mtu, U16 dev_mtu, U8 dir)
{
	PSAEntry sa;

	sa = sa_alloc();
	if (sa) {
		memset(sa, 0, sizeof(SAEntry));
		sa->id.saddr[0] = saddr[0];
		sa->id.saddr[1] = saddr[1];
		sa->id.saddr[2] = saddr[2];
		sa->id.saddr[3] = saddr[3];

		sa->id.daddr.a6[0] = daddr[0];
		sa->id.daddr.a6[1] = daddr[1];
		sa->id.daddr.a6[2] = daddr[2];
		sa->id.daddr.a6[3] = daddr[3];
		sa->id.spi = spi;
		sa->id.proto = proto;
		sa->family = family;
		sa->handle = handle;
		sa->mtu = mtu;
		sa->dev_mtu = dev_mtu;
		if (dir)
			sa->direction = CDX_DPA_IPSEC_INBOUND;
		else
			sa->direction = CDX_DPA_IPSEC_OUTBOUND;
#ifdef CONTROL_IPSEC_DEBUG
		printk("%s(%d) dir %s, handle %x\n",
				__func__,__LINE__,(dir)?"INBOUND" : "OUTBOUND", sa->handle);
#endif
		/* Look like staring seq number is not passed
			 In the shared descriptor we need to set this value.
			 hence for the time being setting to zero*/
		sa->seq = 0;
		sa->pSec_sa_context=cdx_ipsec_sec_sa_context_alloc(handle);
		if(!sa->pSec_sa_context)
		{
			sa_free(sa);
			return NULL;
		}
		if (!replay)
			sa->flags |= SA_ALLOW_SEQ_ROLL;

		//Per RFC 4304 - Should be used by default for IKEv2, unless specified by SA configuration.

		sa->pSec_sa_context->auth_data.auth_type = OP_PCL_IPSEC_HMAC_NULL;
		sa->pSec_sa_context->cipher_data.cipher_type =OP_PCL_IPSEC_NULL_ENC;
		if(esn)
			sa->flags |= SA_ALLOW_EXT_SEQ_NUM;
		sa->hash_by_h   =  handle & (NUM_SA_ENTRIES - 1);

		/* The fqid list is what the data path walks to find an SA, so it
		 * is linked last: until the entry is in the handle table it
		 * cannot be looked up or torn down by the control path, and a
		 * failure here has to leave nothing behind for either path to
		 * reach. */
		if (sa_add(sa) != NO_ERR)
		{
#ifdef CONTROL_IPSEC_DEBUG
			printk(KERN_INFO "%s sa_add failed\n", __func__);
#endif
			cdx_ipsec_sec_sa_context_free(sa->pSec_sa_context);
			sa->pSec_sa_context = NULL;
			sa_free(sa);
			return NULL;

		}

		/* maintaining SA table with cp_to_fqids; published under
		 * sa_cache_lock so the dqrr walker never sees a half-linked
		 * node. */
		{
			unsigned long irqflags;

			spin_lock_irqsave(&sa_cache_lock, irqflags);
			slist_add(&sa_cache_by_fqid[(sa->pSec_sa_context->to_cp_fqid & (NUM_SA_ENTRIES - 1))],
					&sa->list_fqid);
			spin_unlock_irqrestore(&sa_cache_lock, irqflags);
		}
#ifdef CONTROL_IPSEC_DEBUG
		printk("%s(%d) SA pointer %p, FQID hash %d, fqid %d(%x)\n",__func__,__LINE__,sa,
				(sa->pSec_sa_context->to_cp_fqid & (NUM_SA_ENTRIES - 1)), sa->pSec_sa_context->to_cp_fqid,
				sa->pSec_sa_context->to_cp_fqid);
		printk("%s::sa %p, context %p handle %d dir %d\n",
				__func__, sa, sa->pSec_sa_context, sa->hash_by_h, sa->direction);
#endif

	}
	return sa;
}

int M_ipsec_sa_cache_delete(U16 handle)
{
	PSAEntry pSA;

	pSA = M_ipsec_sa_cache_lookup_by_h(handle);
	if (!pSA)
		return ERR_SA_UNKNOWN;

	sa_remove(pSA);
	return NO_ERR;
}




/* Called from the QMan portal dqrr callback (atomic context) — one of
 * the two SA-cache readers outside ctrl.mutex (see sa_cache_lock's
 * definition). The lock spans the whole walk: every SAEntry field read
 * here (flags, pSec_sa_context, handle, netdev) is on memory the
 * teardown path frees right after its locked unlink, so the values must
 * be copied out before unlocking. The returned net_device's own
 * lifetime is the SA teardown discipline's concern (NETDEV_UNREGISTER
 * handling), not this lock's. */
struct net_device *get_netdev_of_SA_by_fqid(uint32_t fqid,uint16_t *sagd_pkt)
{
	PSAEntry sa_ptr;
	struct slist_entry *tmp;
	struct net_device *netdev = NULL;
	unsigned long irqflags;
	uint16_t fqid_hash = (fqid & (NUM_SA_ENTRIES - 1));

	spin_lock_irqsave(&sa_cache_lock, irqflags);
	slist_for_each(sa_ptr,tmp,&sa_cache_by_fqid[fqid_hash],list_fqid)
	{
		if (sa_ptr->flags & SA_DELETE)
		{
			/* Skip just this SA: it is mid-teardown and its frame
			 * queues are being retired. Other SAs sharing the
			 * bucket must still resolve (aborting the whole walk
			 * here used to drop unrelated SAs' packets for the
			 * length of a neighbor's teardown). */
			printk_ratelimited("%s(%d) SA marked for deletion , fqid %x, handle %x\n",
					__func__,__LINE__,fqid, sa_ptr->handle);
			continue;
		}
		if (sa_ptr->pSec_sa_context->to_cp_fqid ==  fqid)
		{
			*sagd_pkt = sa_ptr->handle;
			netdev = sa_ptr->netdev;
			break;
		}
	}
	spin_unlock_irqrestore(&sa_cache_lock, irqflags);
	return netdev;
}

/* Install the SA's classifier entry: the UDP-encapsulated one for a NAT-T SA,
 * the ESP one otherwise. */
int ipsec_install_fp_entry(PSAEntry sa)
{
	int rc;

	if (IS_NATT_SA(sa))
		rc = cdx_ipsec_process_udp_classification_table_entry(sa);
	else
		rc = cdx_ipsec_add_classification_table_entry(sa);

	return rc ? ERR_CREATION_FAILED : NO_ERR;
}

#if defined(CONFIG_INET_IPSEC_OFFLOAD) || defined(CONFIG_INET6_IPSEC_OFFLOAD)
/* The registered datapath hook (dpa_register_ipsec_fq_handler): called
 * from the DPAA submit paths in softirq — the second SA-cache reader
 * outside ctrl.mutex. The walk and every SAEntry deref happen under
 * sa_cache_lock, and the fq pointer is copied out before unlocking. A
 * teardown that wins the race after the unlock can still retire the
 * frame queue while the caller is enqueuing; QMan then rejects the
 * enqueue and the ERN/enqueue-failure unwinds handle the FRAME. The fq
 * POINTER itself aims into the sainfo, whose free is deferred a full
 * second behind the unlink (SA_CTX_RELEASE_TIMER_VAL) — that deferral,
 * not a refcount, is what keeps a microsecond-scale post-unlock enqueue
 * off freed memory. The SA_DELETE gate keeps mid-teardown SAs from
 * being offered at all. */
static struct qman_fq *cdx_get_to_sec_fq_handler(uint32_t handle)
{
	PSAEntry sa;
	struct qman_fq *fq = NULL;
	unsigned long irqflags;

#ifdef CDX_DPA_DEBUG
	net_crit_ratelimited("%s:: handle %d \n", __func__, handle);
#endif

	spin_lock_irqsave(&sa_cache_lock, irqflags);
	sa = M_ipsec_sa_cache_lookup_by_h(handle);
	if (sa && !(sa->flags & SA_DELETE) && sa->pSec_sa_context)
		fq = get_to_sec_fq(sa->pSec_sa_context->dpa_ipsecsa_handle);
	spin_unlock_irqrestore(&sa_cache_lock, irqflags);

	return fq;
}
#endif
int ipsec_init(void)
{
	int i;

	for (i = 0; i < NUM_SA_ENTRIES; i++)
	{
		slist_head_init(&sa_cache_by_h[i]);
		slist_head_init(&sa_cache_by_fqid[i]);
	}
	/* Not fatal. What failed is the CAAM job ring, and a board without one
	 * is a gateway without IPsec offload, not a gateway without offload:
	 * cdx_ipsec_ready() stays false, so the XFRM provider refuses every SA
	 * and nothing below ever reaches SEC. The rest of this init is
	 * bookkeeping that ipsec_exit() expects to find in place. */
	if (cdx_ipsec_init())
		pr_warn("%s: IPsec offload unavailable, no SEC job ring\n",
			__func__);
#if defined(CONFIG_INET_IPSEC_OFFLOAD) || defined(CONFIG_INET6_IPSEC_OFFLOAD)
	//register hook function for intercepting ipsec packets from ethernet driver
	if (dpa_register_ipsec_fq_handler(cdx_get_to_sec_fq_handler)) {
		printk(KERN_INFO "%s unable to registeri ipsec hook func\n",
				__func__);
		/* ipsec_exit() won't run when init fails — release the JR
		 * and the reboot notifier here or the notifier would point
		 * into freed module text after an unload. */
		cdx_ipsec_deinit();
		return -1;
	}
#endif
	return 0;
}

void ipsec_exit(void)
{
#if defined(CONFIG_INET_IPSEC_OFFLOAD) || defined(CONFIG_INET6_IPSEC_OFFLOAD)
	/* Clear the ethernet-driver hook first: it waits out in-flight
	 * datapath readers, so nothing can enter this module or look up SA
	 * state while it is torn down below. Without this, a cdx init
	 * failure after ipsec_init left the hook pointing into freed module
	 * text and every later load failed here until reboot. */
	dpa_unregister_ipsec_fq_handler();
#endif
	cdx_ipsec_deinit();
}
#endif  // DPA_IPSEC_OFFLOAD
