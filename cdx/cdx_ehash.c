/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017-2018,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */
        
/**     
 * @file                cdx_ehash.c     
 * @description         cdx DPAA external hash functions
 */             
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include "linux/netdevice.h"
#include "portdefs.h"
#include "dpaa_eth.h"
#include "dpaa_eth_common.h"
#include "misc.h"
#include "types.h"
#include "cdx.h"
#include "cdx_common.h"
#include "list.h"
#include "cdx_ioctl.h"
#include "layer2.h"
#include "control_ipv4.h"
#include "control_ipv6.h"
#include "control_ipsec.h"
#include "control_tunnel.h"
#include "fm_ehash.h"
#include "dpa_control_mc.h"
#include "cdx_dpa_ipsec.h"
#include "dpa_wifi.h"
#include "module_qm.h"
#include "control_tx.h"

//#define CDX_DPA_DEBUG 1

#ifdef CDX_DPA_DEBUG
#define CDX_DPA_DPRINT(fmt, args...) printk(KERN_ERR "%s:: " fmt, __func__, ##args)
#else
#define CDX_DPA_DPRINT(fmt, args...) do { } while(0)
#endif

#define PAD(val, padsize) ((val) % (padsize)) ? ((padsize) - ((val) % (padsize))) : 0

//db entry for reusing a hm chain
#define TTL_HM_VALID            (1 << 0)
#define NAT_HM_REPLACE_SIP      (1 << 1)
#define NAT_HM_REPLACE_DIP      (1 << 2)
#define NAT_HM_REPLACE_SPORT    (1 << 3)
#define NAT_HM_REPLACE_DPORT    (1 << 4)
#define NAT_HM_VALID            ( NAT_HM_REPLACE_SIP | NAT_HM_REPLACE_DIP | NAT_HM_REPLACE_SPORT | NAT_HM_REPLACE_DPORT)
#define VLAN_STRIP_HM_VALID     (1 << 5)
#define VLAN_ADD_HM_VALID       (1 << 6)
#define PPPoE_STRIP_HM_VALID    (1 << 8)
#define NAT_V6	                (1 << 10)
#define EHASH_IPV6_FLOW		(1 << 11)

#define L2_HDR_OPS(l2_info) ((l2_info.vlan_present) || (l2_info.pppoe_present) || (l2_info.num_egress_vlan_hdrs) || (l2_info.add_pppoe_hdr)) 
#define L3_HDR_OPS(l3_info) (l3_info.tnl_header_present || l3_info.add_tnl_header || l3_info.ipsec_inbound_flow)
#define L2_L3_HDR_OPS(info) (info->sec_tag || L3_HDR_OPS(info->l3_info) || L2_HDR_OPS(info->l2_info))
#define IS_IPV4_NAT(entry) ( IS_IPV4(entry) && (entry->status & CONNTRACK_NAT) )
#define IS_IPV6_NAT(entry) ( IS_IPV6(entry) && ( entry->status & ( CONNTRACK_SNAT | CONNTRACK_DNAT) ))

#define MURAM_VIRT_TO_PHYS_ADDR(addr)	((uint32_t)((uint8_t *)addr - (uint8_t *)FmMurambaseAddr) & 0xffffff)

void cdx_deinit_fragment_bufpool(void);

static int insert_opcodeonly_hm(struct ins_entry_info *info, uint8_t opcode);
static int create_nat_hm(struct ins_entry_info *info);
static int create_tunnel_insert_hm(struct ins_entry_info *info);
static int create_ethernet_hm(struct ins_entry_info *info, uint32_t rebuild_hdr);
static int create_ttl_hm(struct ins_entry_info *info);
static int create_hoplimit_hm(struct ins_entry_info *info);
static int create_update_dscp_hm(struct ins_entry_info *info,uint8_t opcode);
static int create_strip_eth_hm(struct ins_entry_info *info);
static int create_enque_hm(struct ins_entry_info *info);
static int create_replicate_hm(struct ins_entry_info *info);
static int fill_mcast_member_actions(RouteEntry *pRtEntry, struct ins_entry_info *info);
static int create_tunnel_remove_hm(struct ins_entry_info *info);
static int create_pppoe_ins_hm(struct ins_entry_info *info);
static int insert_remove_pppoe_hm(struct ins_entry_info *info);
static int insert_remove_vlan_hm(struct ins_entry_info *info, uint32_t iif_index, uint32_t underlying_iif_index);
static int create_vlan_ins_hm(struct ins_entry_info *info);
static int create_eth_rx_stats_hm(struct ins_entry_info *info, uint32_t iif_index, uint32_t underlying_iif_index);
static int cdx_create_fragment_bufpool(void);
#ifdef ENABLE_INGRESS_QOS
static int create_preemptive_checks_hm(struct ins_entry_info *info,uint16_t queue_no);
#else
static int create_preemptive_checks_hm(struct ins_entry_info *info);
#endif
extern uint32_t get_logical_ifstats_base(void);

extern t_Error FM_MURAM_FreeMem(t_Handle h_FmMuram, void *ptr);
extern void  * FM_MURAM_AllocMem(t_Handle h_FmMuram, uint32_t size, uint32_t align);
extern uint64_t SYS_VirtToPhys(uint64_t addr);
extern void *FmMurambaseAddr;

#define create_ethernet_remove_hm(info) insert_opcodeonly_hm(info, STRIP_ETH_HDR)
#define create_pppoe_remove_hm(info) insert_opcodeonly_hm(info, STRIP_PPPoE_HDR)

#define CDX_FRAG_BUFFERS_CNT	2048
#define CDX_FRAG_BUFF_SIZE	1500

/* Flags that reside in MSB of t_IPF_TD.FragmentedFramesCounter field       */
#define DF_ACTION_MASK          0x30  /* DFAction mask                */
#define DF_ACTION_ERROR         0x00  /* DFAction: treat as error     */
#define DF_ACTION_IGNORE        0x10  /* DFAction: ignore DF bit      */
#define DF_ACTION_DONT_FRAG     0x20  /* DFAction: don't fragment     */

#define BPID_ENABLE              0x08  /* BufferPoolIDEn field         */
#define OPT_COUNTER_EN           0x04  /* IP options copy or not            */
#define CDX_FRAG_USE_BUFF_POOL

typedef struct __attribute__ ((packed)) cdx_ucode_frag_info_s
{
	uint16_t frag_options; // configure the dfAction whether to ignore or honor the DF bit
	uint16_t pad;
	uint32_t alloc_buff_failures;
	uint32_t v4_frames_counter;
	uint32_t v6_frames_counter;
	uint32_t v4_frags_counter;
	uint32_t v6_frags_counter;
	uint32_t v6_identification;
}cdx_ucode_frag_info_t;

typedef struct cdx_muram_memory_cmn_db_s
{
	cdx_ucode_frag_info_t	muram_frag_params;
	cdx_dscp_fqid_t		dscp_fqid_map;
}cdx_muram_memory_cmn_db_t;

typedef struct cdx_dscp_fq_map_fp_s
{
	int32_t				port_id;
	cdx_muram_memory_cmn_db_t	*muram_addr;
}cdx_dscp_fq_map_fp_t;

typedef struct cdx_frag_info_s
{
	struct dpa_bp 			*frag_bufpool;
	cdx_ucode_frag_info_t		*muram_frag_params;
	struct port_bman_pool_info	parent_pool_info;
	uint8_t				frag_bp_id;
} cdx_frag_info_t;

cdx_frag_info_t  		frag_info_g;
cdx_dscp_fq_map_fp_t		dscp_fq_map_ff_g;

struct dpa_bp* get_frag_bp(void)
{
	return (frag_info_g.frag_bufpool);
}

/*
 * This function returns the muRam address of dscp fqid mapping.
 * In failure case it returns NULL.
*/
cdx_dscp_fqid_t* get_dscp_fqid_map(uint32_t portid)
{
		/* No port id is configured. */
	if (dscp_fq_map_ff_g.port_id == NO_PORT)
		return NULL;
	
		/* Given port is matching */
	if (dscp_fq_map_ff_g.port_id != portid)
		return NULL;

		/* At this place, this should not be NULL */
	if (!dscp_fq_map_ff_g.muram_addr)
		return NULL;

	return &(dscp_fq_map_ff_g.muram_addr->dscp_fqid_map);
}

/*
 * This function to enable dscp fqid mapping on new interface, it updates
 * port id and resets the earlier port dscp fqid mappings. It returns
 * SUCCESS in success case, otherwise returns FAILURE.
*/
int enable_dscp_fqid_map(uint32_t portid)
{
	cdx_dscp_fqid_t *dscp_fqid_map = NULL;

	if (dscp_fq_map_ff_g.port_id != portid)
	{
		/* Now supporting only one interface, so directly updating the portid. */
		if (dscp_fq_map_ff_g.port_id == NO_PORT)
		{
			/* Make sure reset the dscp fqid map */
			if (dscp_fq_map_ff_g.muram_addr)
			{
				dscp_fqid_map =(cdx_dscp_fqid_t *) &(dscp_fq_map_ff_g.muram_addr->dscp_fqid_map);
			}

			DPA_INFO("%s()::%d muram_addr %p dscp_fqid_map %p \n", __func__, __LINE__, dscp_fq_map_ff_g.muram_addr, dscp_fqid_map);
			if ((!dscp_fqid_map) || (reset_all_dscp_fq_map_ff(dscp_fqid_map)))
				return FAILURE;

			dscp_fq_map_ff_g.port_id = portid;
		}
		else
		{
			DPA_ERROR("%s()::%d Before enable dscp fq map on portid %u, first disable on  portid %u\n",
				__func__, __LINE__, portid, dscp_fq_map_ff_g.port_id);
			return FAILURE;
		}
	}
	else
	{
		DPA_ERROR("%s()::%d dscp fq map already mapped to the given port id %u\n",
				__func__, __LINE__, portid);
	}

	return SUCCESS;
}

/*
 * This function to disable dscp fqid mapping on an interface, it resets the port id to -1
 * and resets all the dscp fqid mapings. It returns SUCCESS in success case otherwise returns
 * FAILURE.
*/
int disable_dscp_fqid_map(uint32_t portid)
{
	cdx_dscp_fqid_t *dscp_fqid_map = NULL;

	if (dscp_fq_map_ff_g.port_id != portid)
	{
		if (dscp_fq_map_ff_g.port_id == NO_PORT)
		{
			DPA_ERROR("%s()::%d Presently dscp fqid map is not enabled on any interface\n", __func__, __LINE__);
		}
		else
		{
			DPA_ERROR("%s()::%d dscp fqid mapping not enabled on user input portid %u(enabled on portid %u)\n",
				__func__, __LINE__, portid, dscp_fq_map_ff_g.port_id);
		}
		return FAILURE;
	}
	if (dscp_fq_map_ff_g.muram_addr)
		dscp_fqid_map = &(dscp_fq_map_ff_g.muram_addr->dscp_fqid_map);

	if ((!dscp_fqid_map) || (reset_all_dscp_fq_map_ff(dscp_fqid_map)))
		return FAILURE;
	/* Now supporting only one interface, so directly updating the portid. */
	dscp_fq_map_ff_g.port_id = NO_PORT;

	return SUCCESS;
}

#define PTR_TO_UINT(_ptr)           ((uintptr_t)(_ptr))
uint64_t XX_VirtToPhys(void * addr)
{
    return (uint64_t)SYS_VirtToPhys(PTR_TO_UINT(addr));
}

static int Get_Tnl_Ethertype(int mode )
{
	/* Unsigned literals: 0x86dd << 16 does not fit a signed int, and the
	 * caller keeps only the low half anyway (the inner ethertype the strip
	 * exposes). */
	switch(mode)
	{
		case TNL_MODE_6O4:
			return ( (0x0800u << 16) | 0x86ddu);
		case TNL_MODE_4O6:
			return ( (0x86ddu << 16) | 0x0800u);
		default:
			return 0;
	}
}

static int fill_key_info(PCtEntry entry, uint8_t *keymem, uint32_t port_id)
{
	union dpa_key *key;
	unsigned char *saddr, *daddr;
	int i;
	uint32_t key_size;

	key = (union dpa_key *)keymem;
	//portid added to key
	key->portid = port_id;
	switch (entry->proto) {
		case IPPROTOCOL_TCP: 
			if (IS_IPV6_FLOW(entry))
			{
				saddr = (unsigned char*)entry->Saddr_v6;
				daddr = (unsigned char*)entry->Daddr_v6;
				key_size = (sizeof(struct ipv6_tcpudp_key) + 1);;
				for (i = 0; i < 16; i++)
					key->ipv6_tcpudp_key.ipv6_saddr[i] = saddr[i];
				for (i = 0; i < 16; i++)
					key->ipv6_tcpudp_key.ipv6_daddr[i] = daddr[i];
				key->ipv6_tcpudp_key.ipv6_protocol = entry->proto;
				key->ipv6_tcpudp_key.ipv6_sport = entry->Sport;
				key->ipv6_tcpudp_key.ipv6_dport = entry->Dport;
			}
			else
			{

				key_size = (sizeof(struct ipv4_tcpudp_key) + 1);
				key->ipv4_tcpudp_key.ipv4_saddr = entry->Saddr_v4;
				key->ipv4_tcpudp_key.ipv4_daddr = entry->Daddr_v4;
				key->ipv4_tcpudp_key.ipv4_protocol = entry->proto;
				key->ipv4_tcpudp_key.ipv4_sport = entry->Sport;
				key->ipv4_tcpudp_key.ipv4_dport = entry->Dport;
			}
			break;

		case IPPROTOCOL_UDP:
			if (IS_IPV6_FLOW(entry))
			{
				saddr = (unsigned char*)entry->Saddr_v6;
				daddr = (unsigned char*)entry->Daddr_v6;
				key_size = (sizeof(struct ipv6_tcpudp_key) + 1);
				for (i = 0; i < 16; i++)
					key->ipv6_tcpudp_key.ipv6_saddr[i] = saddr[i];
				for (i = 0; i < 16; i++)
					key->ipv6_tcpudp_key.ipv6_daddr[i] = daddr[i];

				key->ipv6_tcpudp_key.ipv6_protocol = entry->proto;
				key->ipv6_tcpudp_key.ipv6_sport = entry->Sport;
				key->ipv6_tcpudp_key.ipv6_dport = entry->Dport;
                                if(entry->Sport == 0 && entry->Dport == 0)
				  	key_size -= 4;
			}
			else
			{
				key_size = (sizeof(struct ipv4_tcpudp_key) + 1);
				key->ipv4_tcpudp_key.ipv4_saddr = entry->Saddr_v4;
				key->ipv4_tcpudp_key.ipv4_daddr = entry->Daddr_v4;
				key->ipv4_tcpudp_key.ipv4_protocol = entry->proto;
				key->ipv4_tcpudp_key.ipv4_sport = entry->Sport;
				key->ipv4_tcpudp_key.ipv4_dport = entry->Dport;
                                if(entry->Sport == 0 && entry->Dport == 0)
					key_size -= 4;
			}
			break;
		case IPPROTOCOL_ESP:
			if (IS_IPV6_FLOW(entry))
			{
				saddr = (unsigned char*)entry->Saddr_v6;
				daddr = (unsigned char*)entry->Daddr_v6;
				key_size = (sizeof(struct ipv6_tcpudp_key) + 1);
				for (i = 0; i < 16; i++)
					key->ipv6_tcpudp_key.ipv6_saddr[i] = saddr[i];
				for (i = 0; i < 16; i++)
					key->ipv6_tcpudp_key.ipv6_daddr[i] = daddr[i];

				key->ipv6_tcpudp_key.ipv6_protocol = IPPROTOCOL_ESP;
				key_size -= 4;
			}
			else
			{
				key_size = (sizeof(struct ipv4_tcpudp_key) + 1);
				key->ipv4_tcpudp_key.ipv4_saddr = entry->Saddr_v4;
				key->ipv4_tcpudp_key.ipv4_daddr = entry->Daddr_v4;
				key->ipv4_tcpudp_key.ipv4_protocol = IPPROTOCOL_ESP;
				key_size -= 4;
			}
			break;
		default:
			DPA_ERROR("%s::protocol %d not supported\n",
					__func__, entry->proto);
			key_size = 0;
	}
#ifdef CDX_DPA_DEBUG
	if (key_size) {
		DPA_INFO("keysize %d\n", key_size);
		display_buf(key, key_size);
	}
#endif
	return key_size;
}

/* A bridged multicast root's key: the port, the frame's own Ethernet pair, and
 * the routed multicast key's fields, in the key generator's extraction order.
 *
 * The pair is part of the key rather than something read at replication time
 * because the listeners rebuild Ethernet with a literal header: the only way a
 * listener can write the sender's source address back is to have matched on
 * it. A frame of the same (S,G) from another sender misses this entry and is
 * bridged in software, which is what a second source MAC deserves until the
 * learner has an entry for it. `mac_pair` is the destination then the source,
 * the order the header carries them in. */
static uint32_t fill_mcast_mac_key(PCtEntry entry, const uint8_t *mac_pair,
				   uint8_t *keymem, uint32_t port_id)
{
	union dpa_key *key = (union dpa_key *)keymem;

	key->portid = port_id;
	if (IS_IPV6_FLOW(entry)) {
		struct ipv6_mcast_mac_key *k = &key->ipv6_mcast_mac_key;

		memcpy(k->ether_da, mac_pair, ETHER_ADDR_LEN);
		memcpy(k->ether_sa, mac_pair + ETHER_ADDR_LEN, ETHER_ADDR_LEN);
		memcpy(k->ipv6_saddr, entry->Saddr_v6, IPV6_ADDRESS_LENGTH);
		memcpy(k->ipv6_daddr, entry->Daddr_v6, IPV6_ADDRESS_LENGTH);
		k->ipv6_protocol = entry->proto;
		return sizeof(*k) + 1;
	}
	memcpy(key->ipv4_mcast_mac_key.ether_da, mac_pair, ETHER_ADDR_LEN);
	memcpy(key->ipv4_mcast_mac_key.ether_sa, mac_pair + ETHER_ADDR_LEN,
	       ETHER_ADDR_LEN);
	key->ipv4_mcast_mac_key.ipv4_saddr = entry->Saddr_v4;
	key->ipv4_mcast_mac_key.ipv4_daddr = entry->Daddr_v4;
	key->ipv4_mcast_mac_key.ipv4_protocol = entry->proto;
	return sizeof(key->ipv4_mcast_mac_key) + 1;
}

/* check activity
 *
 * Returns 0 when the entry's counters were read, and a negative errno when
 * there was no entry or it keeps none. The fields are written either way, as
 * they always were -- zero where nothing was read -- so a caller taking deltas
 * has to know which it got: a zero standing in for a count reads as one that
 * went backwards. */
int hw_ct_get_active(struct hw_ct *ct)
{
	struct en_tbl_entry_stats stats;
	int rc;

	memset(&stats, 0, sizeof(struct en_tbl_entry_stats));
	rc = ExternalHashTableEntryGetStatsAndTS(ct->handle, &stats);
	ct->pkts = stats.pkts;
	ct->bytes = stats.bytes;
	ct->timestamp = stats.timestamp;
#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s::ct %p pkts %lu, bytes %lu, timestamp %x jiffies %x\n",
		__func__, ct, (unsigned long)ct->pkts, (unsigned long)ct->bytes, ct->timestamp,
		JIFFIES32);
#endif
	if (rc)
		return -ENOENT;
	return (stats.flags & STATS_VALID) ? 0 : -ENODATA;
}

/* Pending-free quarantine for external-hash table entries (ISSUES.md
 * A80, generalized to every classifier path by A95).
 *
 * A table entry leaves a live FMAN chain destructively and before any
 * barrier - either inside ExternalHashTableDeleteKey() or, for
 * multicast listeners, through the open-coded splice in
 * dpa_control_mc.c. A host-command sync (ExternalHashTableFmPcdHcSync)
 * is what proves that a ucode walker which entered the chain before the
 * splice has left it; until one succeeds, the unlinked memory may still
 * be dereferenced by hardware, so it must not go back to the allocator.
 *
 * A failed sync therefore leaves an entry that can neither be freed nor
 * re-unlinked (the surgery is not idempotent - replaying it would walk
 * pointers that have already been advanced). Park it here instead: the
 * owning software state is cleared as usual, the memory stays allocated
 * but unreachable, and the backlog is released the next time any sync
 * on this PCD succeeds.
 *
 * One successful sync clears the whole backlog:
 * ExternalHashTableFmPcdHcSync() syncs the table handle's PCD, and
 * LS1046A runs a single FMAN PCD, so a success reached via any table or
 * any flow is a valid barrier for every entry unlinked before it. With a
 * second PCD it would not be. Every entry that reaches here was programmed
 * through the flowtable backend, and its cdx_ft_claim() refuses such a
 * configuration.
 *
 * Each parked entry records the table it was unlinked from, so the backlog
 * can issue its own barrier (cdx_ehash_quarantine_retry()) for a caller
 * that has no table to hand: the flowtable backend refuses admission while
 * anything is parked, and would otherwise wait on some unrelated delete.
 *
 * Concurrency: the quarantine carries no lock of its own. Every touch
 * runs under ctrl.mutex: the flowtable backend and its multicast and
 * IPsec callers (the multicast ones additionally holding
 * mc_mutators_mutex), and module exit, which tears down under
 * cdx_ctrl_deinit()'s hold. Each mutator asserts
 * it (cdx_ehash_quarantine_assert_held()). Nothing in softirq touches
 * it, so no softirq-safe variant is needed.
 * Callers must not hold a spinlock: the barriers reached from here
 * busy-wait on host-command completion.
 */
struct cdx_ehash_pending_free {
	struct list_head list;
	void *td;
	void *tbl_entry;
};

static LIST_HEAD(cdx_ehash_pending_frees);
static unsigned int cdx_ehash_pending_free_cnt;

static void cdx_ehash_quarantine_assert_held(void)
{
	lockdep_assert_held(&cdx_info->ctrl.mutex);
}

/* Advisory snapshot for the debug proc readers, which run outside the
 * mutator serialization. */
unsigned int cdx_ehash_quarantine_pending(void)
{
	return READ_ONCE(cdx_ehash_pending_free_cnt);
}

/* td is the table tbl_entry was unlinked from. Any table on this PCD
 * would do for the barrier; recording the entry's own keeps the handle
 * one whose lifetime the entry already depended on. */
void cdx_ehash_quarantine_entry(void *td, void *tbl_entry)
{
	struct cdx_ehash_pending_free *node;

	cdx_ehash_quarantine_assert_held();
	if (!tbl_entry)
		return;

	node = kmalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
	{
		/* No safe alternative: the entry is already out of the chain,
		 * so it can neither be freed without a barrier nor reached
		 * again through the owning software state. Leak it - the same
		 * outcome the code had before the quarantine existed - and
		 * make the leak visible in the log. */
		DPA_ERROR("%s::quarantine alloc failed, leaking tbl_entry %p\n",
				__func__, tbl_entry);
		return;
	}
	node->td = td;
	node->tbl_entry = tbl_entry;
	list_add_tail(&node->list, &cdx_ehash_pending_frees);
	/* WRITE_ONCE pairs with the debug proc reader's READ_ONCE - the
	 * count is advisory there, but the store should not tear. */
	WRITE_ONCE(cdx_ehash_pending_free_cnt, cdx_ehash_pending_free_cnt + 1);
}

/* Release the whole backlog. Callers must have just observed a
 * successful HC sync on this PCD, or be running at module exit where
 * the PCD teardown has already quiesced the FMAN. Calling it without
 * such a barrier reintroduces the use-after-free the quarantine exists
 * to prevent. */
void cdx_ehash_quarantine_free_all(void)
{
	struct cdx_ehash_pending_free *node, *tmp;

	cdx_ehash_quarantine_assert_held();
	list_for_each_entry_safe(node, tmp, &cdx_ehash_pending_frees, list)
	{
		list_del(&node->list);
		ExternalHashTableEntryFree(node->tbl_entry);
		kfree(node);
	}
	WRITE_ONCE(cdx_ehash_pending_free_cnt, 0);
}

/* Module-exit disposition of a backlog no drain could clear. cdx does
 * NOT tear down the FMAN PCD on unload (sdk_fman owns it and stays
 * loaded), so the only barrier left is one more sync of its own: nothing
 * guarantees an earlier teardown tried one after the last entry was
 * parked. If that fails too, the HC channel is wedged and the ucode may
 * still be walking the parked memory. Leaking a handful of entries at
 * rmmod (test images only; cdx is never unloaded in production) is then
 * the only safe terminal state. The tables the entries name are still
 * configured here: this runs before the DPA configuration is torn down. */
void cdx_ehash_quarantine_abandon(void)
{
	struct cdx_ehash_pending_free *node, *tmp;

	cdx_ehash_quarantine_assert_held();
	if (!READ_ONCE(cdx_ehash_pending_free_cnt) || !cdx_ehash_quarantine_retry())
		return;

	DPA_ERROR("%s::HC channel never recovered, leaking %u quarantined entries\n",
			__func__, READ_ONCE(cdx_ehash_pending_free_cnt));
	/* Only the table entries have to be abandoned. The list nodes are
	 * ordinary kmalloc'd bookkeeping with no hardware reference, so
	 * release them rather than hand kmemleak a pile of reports that
	 * hide a real one. */
	list_for_each_entry_safe(node, tmp, &cdx_ehash_pending_frees, list)
	{
		list_del(&node->list);
		kfree(node);
	}
	WRITE_ONCE(cdx_ehash_pending_free_cnt, 0);
}

/* Retry the barrier for entries parked by an earlier failed sync. HC
 * failures are frequently transient (frame-pool exhaustion rather than a
 * wedged channel), so the reclaim attempt belongs on the next mutator
 * that touches the same PCD. Paths that delete a key get the retry for
 * free through cdx_ehash_delete_entry(); this entry point exists for the
 * ones that only splice (multicast listener REMOVE/UPDATE), which
 * otherwise issue no barrier at all. No-op when nothing is pending,
 * which is the common case. */
void cdx_ehash_quarantine_drain(void *td)
{
	cdx_ehash_quarantine_assert_held();
	if (list_empty(&cdx_ehash_pending_frees))
		return;

	if (ExternalHashTableFmPcdHcSync(td))
	{
		DPA_ERROR("%s::FmPcdHcSync failed, %u entries still quarantined\n",
				__func__, cdx_ehash_pending_free_cnt);
		return;
	}
	cdx_ehash_quarantine_free_all();
}

/* The same retry for a caller with no table of its own to issue the
 * barrier through: one sync through the first parked entry's recorded
 * table. A direct sync, deliberately not routed through the multicast
 * fault knob's funnel, so an armed knob never keeps a backlog alive.
 * Returns 0 when nothing is parked any more, -EAGAIN when the sync
 * failed and everything stays parked. Quiet on failure: the sync itself
 * already logs, and a caller that retries on a timer should not add a
 * line per attempt. */
int cdx_ehash_quarantine_retry(void)
{
	struct cdx_ehash_pending_free *node;

	cdx_ehash_quarantine_assert_held();
	list_for_each_entry(node, &cdx_ehash_pending_frees, list)
	{
		if (!node->td)
			continue;
		if (ExternalHashTableFmPcdHcSync(node->td))
			return -EAGAIN;
		cdx_ehash_quarantine_free_all();
		return 0;
	}
	/* Nothing parked, or nothing that named a table to sync through:
	 * the latter waits for a barrier from a caller that has one. */
	return list_empty(&cdx_ehash_pending_frees) ? 0 : -EAGAIN;
}

/* Table entries a delete could not prove it unlinked.
 *
 * Every arm of ExternalHashTableDeleteKey() that returns -1 does so before it
 * changes anything, and the test knob below fails a delete without calling it
 * at all, so such an entry is linked exactly where it was or in no bucket. No
 * barrier makes freeing it safe while a port walks the tables. Once every port
 * that does is stopped and idle (dpa_cfg_stop()), though, nothing races a
 * second look: the delete is tried again, and an entry no bucket links any
 * more can simply go. That is what lets the datapath restart rather than wait
 * for a reboot (cdx_ft_restart()).
 *
 * A root is an entry the tables may link -- a flow's, a multicast group's, an
 * SA's -- recorded with the table and the bucket it was added to. A dependent
 * is one only a root reaches -- a multicast group's listeners, chained behind
 * the group's entry -- and goes once every root has been settled.
 *
 * A record is allocated when the delete fails, and that can fail too. A root
 * without one may still be linked with nothing that knows where, so no restart
 * can be proven safe, and the latch is left for a reboot as before these
 * records existed. A dependent without one is leaked: whatever reached it is a
 * root, settled or not.
 *
 * Same serialization as the quarantine above.
 */
struct cdx_ehash_abandoned {
	struct list_head list;
	void *td;
	void *tbl_entry;
	uint16_t index;
	/* Deletes the table refused this root during a restart. */
	unsigned int attempts;
};

static LIST_HEAD(cdx_ehash_abandoned_roots);
static LIST_HEAD(cdx_ehash_abandoned_dependents);
static bool cdx_ehash_abandoned_unrecorded;

/* How many restarts a root still linked may hold up, its delete refused each
 * time, most likely for want of a cumulative node, before the doubt is taken as
 * permanent. */
#define CDX_EHASH_RESOLVE_ATTEMPTS	8

static struct cdx_ehash_abandoned *cdx_ehash_abandoned_record(void *td,
		uint16_t index, void *tbl_entry, struct list_head *list)
{
	struct cdx_ehash_abandoned *node;

	node = kmalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return NULL;
	node->td = td;
	node->tbl_entry = tbl_entry;
	node->index = index;
	node->attempts = 0;
	list_add_tail(&node->list, list);
	return node;
}

void cdx_ehash_abandon(void *td, uint16_t index, void *tbl_entry)
{
	cdx_ehash_quarantine_assert_held();
	if (!tbl_entry || cdx_ehash_abandoned_record(td, index, tbl_entry,
						     &cdx_ehash_abandoned_roots))
		return;
	DPA_ERROR("%s::cannot record possibly linked tbl_entry %p; only a reboot frees it\n",
			__func__, tbl_entry);
	cdx_ehash_abandoned_unrecorded = true;
}

void cdx_ehash_abandon_dependent(void *tbl_entry)
{
	cdx_ehash_quarantine_assert_held();
	if (!tbl_entry || cdx_ehash_abandoned_record(NULL, 0, tbl_entry,
						     &cdx_ehash_abandoned_dependents))
		return;
	DPA_ERROR("%s::cannot record tbl_entry %p behind a possibly linked root, leaking it\n",
			__func__, tbl_entry);
}

bool cdx_ehash_abandoned_lost(void)
{
	cdx_ehash_quarantine_assert_held();
	return cdx_ehash_abandoned_unrecorded;
}

/* One root, with nothing walking the tables: 0 once it is unlinked, or found
 * in no bucket, and its entry the caller's to free. Asks the SDK directly,
 * never through the knob that fails deletes, so an armed knob cannot hold a
 * restart up. */
static int cdx_ehash_resolve_root(struct cdx_ehash_abandoned *node)
{
	uint16_t where = node->index;
	int rc;

	rc = ExternalHashTableFindEntry(node->td, node->tbl_entry, &where);
	if (rc == -ENOENT)
		return 0;
	if (rc) {
		DPA_ERROR("%s::table %p is malformed (%d) around tbl_entry %p\n",
				__func__, node->td, rc, node->tbl_entry);
		return -ENOTRECOVERABLE;
	}
	if (where != node->index)
		DPA_ERROR("%s::tbl_entry %p is linked from bucket %u, added to %u\n",
				__func__, node->tbl_entry, where, node->index);
	rc = ExternalHashTableDeleteKey(node->td, where, node->tbl_entry);
	/* With no walker in the tables an unlink needs no barrier to be
	 * final; the restart issues one anyway before anything starts. */
	if (rc == SUCCESS || rc == EN_EHASH_DELETE_UNSYNCED)
		return 0;
	if (++node->attempts < CDX_EHASH_RESOLVE_ATTEMPTS)
		return -EAGAIN;
	DPA_ERROR("%s::tbl_entry %p still linked after %u deletes\n",
			__func__, node->tbl_entry, node->attempts);
	return -ENOTRECOVERABLE;
}

int cdx_ehash_resolve_abandoned(unsigned int *resolved)
{
	struct cdx_ehash_abandoned *node, *tmp;
	int rc, ret = 0;

	cdx_ehash_quarantine_assert_held();
	*resolved = 0;
	list_for_each_entry_safe(node, tmp, &cdx_ehash_abandoned_roots, list)
	{
		rc = cdx_ehash_resolve_root(node);
		if (rc == -ENOTRECOVERABLE)
			return rc;
		if (rc) {
			ret = rc;
			continue;
		}
		list_del(&node->list);
		ExternalHashTableEntryFree(node->tbl_entry);
		kfree(node);
		(*resolved)++;
	}
	if (ret)
		return ret;
	list_for_each_entry_safe(node, tmp, &cdx_ehash_abandoned_dependents, list)
	{
		list_del(&node->list);
		ExternalHashTableEntryFree(node->tbl_entry);
		kfree(node);
	}
	return 0;
}

/* Unload. With the ports stopped every root that will go is settled and freed,
 * as a restart would; whatever is left, or everything when the ports could not
 * be stopped, stays allocated for the reset that alone can free it, and only
 * the bookkeeping is released. Runs where cdx_ehash_quarantine_abandon() does,
 * with the tables still configured. True when nothing that may still be linked
 * is left, recorded or not. */
bool cdx_ehash_abandoned_exit(bool stopped)
{
	struct cdx_ehash_abandoned *node, *tmp;
	unsigned int resolved, leaked = 0;

	cdx_ehash_quarantine_assert_held();
	if (stopped && !cdx_ehash_abandoned_unrecorded)
		/* Every refusal counts toward the root's attempts, so this
		 * ends. */
		while (cdx_ehash_resolve_abandoned(&resolved) == -EAGAIN)
			;
	list_for_each_entry_safe(node, tmp, &cdx_ehash_abandoned_roots, list)
	{
		list_del(&node->list);
		kfree(node);
		leaked++;
	}
	list_for_each_entry_safe(node, tmp, &cdx_ehash_abandoned_dependents, list)
	{
		list_del(&node->list);
		kfree(node);
		leaked++;
	}
	if (leaked)
		DPA_ERROR("%s::leaking %u possibly linked table entries until reset\n",
				__func__, leaked);
	return !leaked && !cdx_ehash_abandoned_unrecorded;
}

#ifdef CDX_DEBUG_FLOWTABLE
/* Test-only. Classifier deletes to fail before the unlink, for the roots that
 * delete through here -- multicast groups and IPsec SAs; unicast flowtable
 * entries delete directly and have flowtable_fail_unlink. Each leaves its key
 * linked, exactly as the not-provably-unlinked arm below describes, until the
 * datapath restart settles it -- which asks the SDK directly, so an armed count
 * never fails the restart's own deletes. */
static unsigned int ehash_fail_unlink;
module_param_named(ehash_fail_unlink, ehash_fail_unlink, uint, 0600);
MODULE_PARM_DESC(ehash_fail_unlink, "Multicast/IPsec classifier deletes to fail before unlink, leaving the key linked; the datapath stops and restarts");
#endif

static bool cdx_ehash_unlink_fault(void)
{
#ifdef CDX_DEBUG_FLOWTABLE
	unsigned int left = READ_ONCE(ehash_fail_unlink);

	return left && cmpxchg(&ehash_fail_unlink, left, left - 1) == left;
#else
	return false;
#endif
}

/* Delete one key from an external hash table and dispose of its table
 * entry per the ExternalHashTableDeleteKey() tri-state (fm_ehash.h).
 *
 * This function owns `handle` from here on: no caller may free it on any
 * path, and a caller that keeps freeing it reintroduces the A95 defect
 * class (use-after-free on the not-unlinked arm, premature free on the
 * unsynced arm). Callers stay responsible for their own software
 * wrappers only. A NULL handle is tolerated so the "nothing was ever
 * installed" case needs no guard at every site.
 *
 * Returns the raw rc, so callers can still distinguish gone (0) from
 * unlinked-but-unproven (EN_EHASH_DELETE_UNSYNCED) from
 * possibly-still-linked (FAILURE) - the last of which additionally means
 * the key may still resolve in hardware, so re-inserting it would build
 * a duplicate-key bucket. */
int cdx_ehash_delete_entry(void *td, uint16_t index, void *handle)
{
	int rc;

	if (!handle)
		return SUCCESS;

	rc = cdx_ehash_unlink_fault() ? FAILURE :
		ExternalHashTableDeleteKey(td, index, handle);
	if (rc == SUCCESS)
	{
		ExternalHashTableEntryFree(handle);
		/* DeleteKey syncs the PCD before reporting success, and one
		 * sync is a barrier for every entry unlinked before it, so
		 * this same round-trip retires the whole backlog. */
		cdx_ehash_quarantine_free_all();
		return rc;
	}
	if (rc == EN_EHASH_DELETE_UNSYNCED)
	{
		/* Out of the chain, but no proof the ucode has left it. Park
		 * it for the next successful sync on this PCD. */
		cdx_ehash_quarantine_entry(td, handle);
		return rc;
	}
	/* Not provably unlinked, and nothing may retry the unlink while the
	 * ports run: a live chain may still resolve to this entry. Freeing it
	 * - now, or later through the quarantine - is a use-after-free the
	 * hardware commits, so it is recorded for the restart that stops the
	 * ports and settles it (cdx_ehash_resolve_abandoned()); the caller
	 * latches the failure that brings that restart about. */
	DPA_ERROR("%s::DeleteKey rc %d, keeping tbl_entry %p: not provably unlinked\n",
			__func__, rc, handle);
	cdx_ehash_abandon(td, index, handle);
	return rc;
}

/* delete classif entry from table.
 *
 * Returns the ExternalHashTableDeleteKey() rc (fm_ehash.h): SUCCESS, or
 * one of the two failure arms. The table entry's disposition belongs to
 * cdx_ehash_delete_entry() on every arm; what this function owns is the
 * hw_ct wrapper, which is pure software with no hardware reference and
 * so is always released. Keeping ct alive past a failed delete bought
 * nothing and once let a later release free an already-disposed handle
 * (ISSUES.md A95). */
int delete_entry_from_classif_table(PCtEntry entry)
{
	int rc;

	if (!entry)
	{
		DPA_ERROR("%s:: Ct entry is NULL\n", __func__);
		return FAILURE;
	}
	/* ct == NULL is the normal state after ANY earlier delete attempt
	 * (this function disposes of it on every rc), so a second call for
	 * the same conntrack must be a successful no-op, not an oops. */
	if (!entry->ct)
		return SUCCESS;

	CDX_DPA_DPRINT("\n");
	rc = cdx_ehash_delete_entry(entry->ct->td, entry->ct->index,
			entry->ct->handle);
	if (rc)
		DPA_ERROR("%s::unable to remove entry from hash table\n", __func__);

	kfree(entry->ct);
	entry->ct = NULL;
	return rc;
}

static int get_table_type(PCtEntry entry, uint32_t *type)
{
	switch (entry->proto) {
		case IPPROTOCOL_TCP:
			if (IS_IPV6_FLOW(entry)) 
				*type = IPV6_TCP_TABLE;
			else
				*type = IPV4_TCP_TABLE;
			return SUCCESS;

		case IPPROTOCOL_ESP:
			if (IS_IPV6_FLOW(entry))
				*type = IPV6_MULTICAST_TABLE;
			else
				*type = IPV4_MULTICAST_TABLE;
			return SUCCESS;

		case IPPROTOCOL_UDP:
			if (IS_IPV6_FLOW(entry)) {
				if(entry->Sport == 0 && entry->Dport == 0)
					*type = IPV6_MULTICAST_TABLE;
				else 
					*type = IPV6_UDP_TABLE;
			}
			else {
				if(entry->Sport == 0 && entry->Dport == 0)
					*type = IPV4_MULTICAST_TABLE;
				else
					*type = IPV4_UDP_TABLE;
			}
			return SUCCESS;
		default:
			DPA_ERROR("%s::protocol %d not supported\n",
					__func__, entry->proto);
			break;
	}
	return FAILURE;
}

static int fill_actions(PCtEntry entry, struct ins_entry_info *info, bool routed)
{
	PCtEntry twin_entry;
	uint32_t ii; 
	uint32_t rebuild_l2_hdr = 0;
#ifdef ENABLE_INGRESS_QOS
	uint16_t quenum = 0;
	union ctentry_qosmark *qosmark = (union ctentry_qosmark *)&entry->qosmark;
#endif
	uint32_t iif_index = 0, underlying_iif_index = 0;
	struct dpa_iface_info *iface_info;
	uint16_t ethertype = ETHERTYPE_IPV4;

#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s:: entry %p, opc_ptr %p, param_ptr %p, size %d\n", 
			__func__, entry, info->opcptr, info->paramptr, info->param_size);
#endif
	twin_entry = CT_TWIN(entry);

	//mask it as ipv6 flow if required
	if (IS_IPV6_FLOW(entry))
	{
		info->flags |= EHASH_IPV6_FLOW;
		ethertype   =  ETHERTYPE_IPV6;
	}

	/* Bridged multicast reaches this encoder too, but crosses no IP hop. */
	if (routed)
		info->flags |= TTL_HM_VALID;

	//strip vlan on ingress if incoming iface is vlan
	if (info->l2_info.vlan_present)
		info->flags |= VLAN_STRIP_HM_VALID;

	//strip pppoe on ingress if incoming iface is pppoe 
	if (info->l2_info.pppoe_present)
		info->flags |= PPPoE_STRIP_HM_VALID;

	//perform NAT where required
	{
		if (IS_IPV4_NAT(entry) || IS_IPV6_NAT(entry)) {
			switch(entry->proto) {
				case IPPROTOCOL_TCP:
				case IPPROTOCOL_UDP:
					if (entry->Sport != twin_entry->Dport) {
						info->flags |= NAT_HM_REPLACE_SPORT;
						info->nat_sport = (twin_entry->Dport);
					}
					if (entry->Dport != twin_entry->Sport) {
						info->flags |= NAT_HM_REPLACE_DPORT;
						info->nat_dport = (twin_entry->Sport);
					}
					break;
				default:
					break; 
			}
		}
		//check if ip replacement have to be done
		//nat sip if required

		if (IS_IPV6(entry))
		{
			if (entry->status & CONNTRACK_SNAT)
			{
				memcpy(info->v6.nat_sip, twin_entry->Daddr_v6 ,IPV6_ADDRESS_LENGTH);
				info->flags |= NAT_HM_REPLACE_SIP;
			}
			if (entry->status & CONNTRACK_DNAT)
			{
				memcpy(info->v6.nat_dip, twin_entry->Saddr_v6 ,IPV6_ADDRESS_LENGTH);
				info->flags |= NAT_HM_REPLACE_DIP;
			}
		}
		else 
		{
			if (entry->Saddr_v4 != entry->twin_Daddr) {
				info->v4.nat_sip = (entry->twin_Daddr);
				info->flags |= NAT_HM_REPLACE_SIP;
			}
			//nat dip if required
			if (entry->Daddr_v4 != entry->twin_Saddr) {
				info->v4.nat_dip = (entry->twin_Saddr);
				info->flags |= NAT_HM_REPLACE_DIP;
			}
		}
	}
	if (info->l2_info.num_egress_vlan_hdrs) {

		info->flags |= VLAN_ADD_HM_VALID;
		for (ii = 0; ii < info->l2_info.num_egress_vlan_hdrs; ii++) {
			info->vlan_ids[ii] =
				(info->l2_info.egress_vlan_hdrs[ii].tci);
		}
	}
	//fill all opcodes and parameters
	if(L2_L3_HDR_OPS(info))	{
		/*If L2 /L3 Headers need to be stripped off or  enabled, we strip and rebuild the headers */
		rebuild_l2_hdr = 1;
		info->eth_type  = ethertype;
	}


	while(1) {
		if ((!entry->pRtEntry) ||
				(!entry->pRtEntry->underlying_input_itf)) {
			DPA_ERROR("%s::%d RtEntry or underlying_input_itf is NULL\n",
					__func__, __LINE__);
			break;
		}
		/* input_itf may be NULL for VLAN-on-bridge ingress; fall back to
		 * the physical port for the ingress ifstats index. */
		iif_index = (entry->pRtEntry->input_itf ?
				entry->pRtEntry->input_itf :
				entry->pRtEntry->underlying_input_itf)->index;
		underlying_iif_index = entry->pRtEntry->underlying_input_itf->index;

		iface_info = dpa_get_ifinfo_by_itfid(entry->pRtEntry->itf->index);

#ifdef ENABLE_INGRESS_QOS
		if(qosmark->iqid_valid) {
			quenum = (qosmark->iqid & (INGRESS_FLOW_POLICER_QUEUES - 1));
		}
		if(create_preemptive_checks_hm(info,quenum))
#else
		if(create_preemptive_checks_hm(info))
#endif
			break;

#ifdef INCLUDE_ETHER_IFSTATS
		if (create_eth_rx_stats_hm(info, iif_index, underlying_iif_index))
			break;
#endif
		if(rebuild_l2_hdr || info->num_mcast_members) { 
			/* strip Eth hdr */
			if (create_strip_eth_hm(info ))
				break;
		}

		/* strip vlan hdrs is called mandatorily to validate the vlan id's,
		   for vlan traffic receiving on non-vlan interface.
		   Also to strip the vlan header for vlan-0 packets received on non-vlan interface.*/
		if (insert_remove_vlan_hm(info, iif_index, underlying_iif_index))
			break;

		if (info->l2_info.pppoe_present) {
			/* strip pppoe hdrs */
			if (insert_remove_pppoe_hm(info))
				break;
		}

		if (info->l3_info.tnl_header_present) { 
			if (create_tunnel_remove_hm(info))
				break;
		}
		if (info->flags & NAT_HM_VALID) {
			/* needs nat, create nat hm, roll in ttl as well */
			if(create_nat_hm(info))
				break;
		} else {
			/* update L3 with TTL/ HopLimit */
			if (info->flags & TTL_HM_VALID) {
				if (info->flags & EHASH_IPV6_FLOW) {
					if (create_hoplimit_hm(info))
						break;
				} else {
					if (create_ttl_hm(info))
						break;
				}
			}
		}

		if (info->num_mcast_members)
		{
			info->replicate_params =  info->paramptr;
			/* Replicate Packet */
			if (create_replicate_hm(info))
				break;
			/* We're done in the classification part, 
			 * all header manipulation per replica  will happen in the multicast member entry */
			return SUCCESS;
		}

		if (info->l3_info.add_tnl_header) {
			/* Insert Tnl header */
			if (create_tunnel_insert_hm(info)) 
				break;
		}

		if (!info->to_sec_fqid )
		{
			if (info->l2_info.add_pppoe_hdr)  {
				/* TBD why add ethernet header at all for Secure packets, 
				 * today there seems to be an expectation to have ethernet hdr + 
				 * ethertype to be copied in the encrypted packet */
				/* insert PPPoE header */
				if (create_pppoe_ins_hm(info))
					break;
			}

			if (info->l2_info.num_egress_vlan_hdrs) {
				/* insert vlan header */
				if (create_vlan_ins_hm(info))
					break;
			}
		}

		/* insert Ethernet header */
		if(create_ethernet_hm(info, rebuild_l2_hdr))
			break;

		/* enqueue Packet */
		if(create_enque_hm(info))
			break;

		return SUCCESS;	
	}
	return FAILURE;
}

/* Apply a caller-supplied VLAN stack and PPPoE session to the L2 description
 * derived from the interfaces. Only the Linux flowtable owner uses this: its
 * egress is a physical port with the encapsulation named by the flow, so
 * dpa_get_tx_info_by_itf() has no VLAN or PPPoE interface to walk and returns
 * a bare description.
 *
 * The statistics indices come from the description too, and nowhere else:
 * the record the caller allocated for the session, tunnel or tag, or zero for
 * one that has none, which the opcodes then emit as no pointer at all rather
 * than as another owner's record zero. vlan_flow_ifstats marks a VLAN stack as
 * described here, because the strip also runs for a flow that described none.
 *
 * The session's Ethernet destination is written to ac_mac_addr because that is
 * where create_ethernet_hm() reads a PPPoE flow's destination from. It is the
 * same address the route already carries in l2hdr, since a flow reaching here
 * has the concentrator as its destination MAC; writing both keeps this path
 * exercising exactly the branch an interface-derived session does.
 *
 * Refusing a description that already carries tags or a session is a guard:
 * VLAN and PPPoE interfaces no longer register, so the interface walk never
 * fills one in, and a flow naming its own on top of one would describe two.
 */
#ifdef INCLUDE_VLAN_IFSTATS
/* Whether a flow-described stack names a record for every one of its tags.
 * All or none: the opcodes' list form has no way to skip a tag, and zero is
 * not "no record" there but another owner's record. A stack with no tags at
 * all names nothing and so gets nothing, which is the same answer. */
static int vlan_flow_stats_named(const uint8_t *indices, uint32_t count)
{
	uint32_t i;

	if (!count)
		return 0;
	for (i = 0; i < count; i++)
		if (!indices[i])
			return 0;
	return 1;
}
#endif

static int apply_l2_encap(struct ins_entry_info *info, const struct cdx_l2_encap *encap)
{
	struct dpa_l2hdr_info *l2_info = &info->l2_info;

	if (encap->num_ingress > DPA_CLS_HM_MAX_VLANs ||
	    encap->num_egress > DPA_CLS_HM_MAX_VLANs) {
		DPA_ERROR("%s::encapsulation deeper than the hardware supports\n", __func__);
		return FAILURE;
	}
	if (l2_info->num_ingress_vlan_hdrs || l2_info->num_egress_vlan_hdrs ||
	    l2_info->vlan_present || l2_info->pppoe_present || l2_info->add_pppoe_hdr) {
		DPA_ERROR("%s::interfaces already describe an encapsulation\n", __func__);
		return FAILURE;
	}
	memcpy(l2_info->ingress_vlan_hdrs, encap->ingress,
	       encap->num_ingress * sizeof(*encap->ingress));
	l2_info->num_ingress_vlan_hdrs = encap->num_ingress;
	l2_info->vlan_present = !!encap->num_ingress;
	memcpy(l2_info->egress_vlan_hdrs, encap->egress,
	       encap->num_egress * sizeof(*encap->egress));
	l2_info->num_egress_vlan_hdrs = encap->num_egress;
	l2_info->vlan_flow_ifstats = 1;
#ifdef INCLUDE_VLAN_IFSTATS
	memcpy(l2_info->ingress_vlan_stats_offsets, encap->ingress_vlan_stats_index,
	       sizeof(l2_info->ingress_vlan_stats_offsets));
	memcpy(l2_info->vlan_stats_offsets, encap->egress_vlan_stats_index,
	       sizeof(l2_info->vlan_stats_offsets));
#endif
	if (encap->ingress_pppoe)
		l2_info->pppoe_present = 1;
	if (encap->egress_pppoe) {
		l2_info->add_pppoe_hdr = 1;
		l2_info->pppoe_sess_id = encap->egress_session_id;
		memcpy(l2_info->ac_mac_addr, encap->egress_session_mac,
		       ETHER_ADDR_LEN);
	}
#ifdef INCLUDE_PPPoE_IFSTATS
	if (encap->ingress_pppoe || encap->egress_pppoe) {
		l2_info->pppoe_rx_stats_offset = encap->ingress_stats_index;
		l2_info->pppoe_stats_offset = encap->egress_stats_index;
	}
#endif
	if (encap->ingress_tunnel.present || encap->egress_tunnel.present) {
		struct dpa_l3hdr_info *l3_info = &info->l3_info;

		/* The same refusal as for a tag: a route whose interfaces
		 * already describe a tunnel and a flow naming one on top of
		 * it would describe two. */
		if (l3_info->add_tnl_header || l3_info->tnl_header_present) {
			DPA_ERROR("%s::interfaces already describe a tunnel\n", __func__);
			return FAILURE;
		}
		/* One mode and one header size per direction. Both sides of a
		 * direction carry the same inner family, so a direction that
		 * strips one tunnel and inserts another -- a router between two
		 * tunnels -- has the same mode on both, and the encoder's single
		 * description of it is not a limitation. */
		if (encap->ingress_tunnel.present && encap->egress_tunnel.present &&
		    (encap->ingress_tunnel.mode != encap->egress_tunnel.mode ||
		     encap->ingress_tunnel.header_size != encap->egress_tunnel.header_size)) {
			DPA_ERROR("%s::a direction strips one tunnel mode and inserts another\n",
				  __func__);
			return FAILURE;
		}
		if (encap->ingress_tunnel.present) {
			l3_info->tnl_header_present = 1;
			l3_info->mode = encap->ingress_tunnel.mode;
			l3_info->header_size = encap->ingress_tunnel.header_size;
			l3_info->tunnel_flags |= encap->ingress_tunnel.flags;
			l3_info->tunnel_rx_stats_offset = encap->ingress_tunnel.stats_index;
		}
		if (encap->egress_tunnel.present) {
			if (encap->egress_tunnel.header_size > sizeof(l3_info->header)) {
				DPA_ERROR("%s::tunnel header larger than the hardware inserts\n",
					  __func__);
				return FAILURE;
			}
			l3_info->add_tnl_header = 1;
			l3_info->mode = encap->egress_tunnel.mode;
			l3_info->header_size = encap->egress_tunnel.header_size;
			memcpy(l3_info->header, encap->egress_tunnel.header,
			       encap->egress_tunnel.header_size);
			l3_info->tunnel_flags |= encap->egress_tunnel.flags;
			l3_info->tunnel_stats_offset = encap->egress_tunnel.stats_index;
		}
	}
	return SUCCESS;
}

/* Mirrors cdx_pcd_tunnel_key()'s generic first-header extraction, after the known inner
 * tuple fields. SEC's private tables retain their existing keys. */
static unsigned int fill_tunnel_key(PCtEntry entry, const struct cdx_l2_encap *encap,
				   uint8_t *key)
{
	const struct cdx_tunnel_encap *tunnel = encap ? &encap->ingress_tunnel : NULL;
	bool ipv6 = IS_IPV6_FLOW(entry);
	unsigned int size = ipv6 ? 10 : 35;

	memset(key, 0, size);
	if (tunnel && tunnel->present) {
		key[1] = tunnel->header[ipv6 ? 9 : 6];
		memcpy(key + 2, tunnel->header + (ipv6 ? 12 : 8), ipv6 ? 8 : 32);
		if (!ipv6)
			key[34] = key[1] == IPPROTO_DSTOPTS ? IPPROTO_IPIP : 0x45;
	} else {
		key[0] = entry->proto;
	}
	memset(key + size, 0, 8);
	if (encap && encap->ingress_pppoe) {
		__be16 session = cpu_to_be16(encap->ingress_session_id);

		memcpy(key + size, encap->ingress_session_mac, ETHER_ADDR_LEN);
		memcpy(key + size + ETHER_ADDR_LEN, &session, sizeof(session));
	}
	return size + 8;
}

int insert_entry_in_classif_table_encap(PCtEntry entry, const struct cdx_l2_encap *encap)
{
	struct ins_entry_info *info;
	struct en_exthash_tbl_entry *tbl_entry;
	struct _itf *underlying_input_itf;
	uint32_t tbl_type;
	uint16_t flags;
	uint32_t key_size;
	uint8_t *ptr;
	int retval;

#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s::\n", __func__);
	display_ctentry(entry);
#endif

	entry->ct = NULL;
	tbl_entry = NULL;	

	info = kzalloc(sizeof(struct ins_entry_info), GFP_KERNEL);
	if (!info)
		return FAILURE;
	info->entry = entry;
	/* Set when the route was created, but cleared again if the ingress
	 * interface has since been removed while the route stayed referenced. */
	underlying_input_itf = entry->pRtEntry->underlying_input_itf;
	if (!underlying_input_itf) {
		DPA_ERROR("%s::route has no underlying input interface\n",
				__func__);
		goto err_ret1;
	}
	//clear hw entry pointer
	entry->ct = NULL;
	if (add_incoming_iface_info(entry))
	{
		DPA_ERROR("%s::unable to get interface %d\n",__func__,
				entry->inPhyPortNum);
		goto err_ret1;
	}
	//get fman index and port index and port id where this entry need to be added
	if (dpa_get_fm_port_index(entry->inPhyPortNum, underlying_input_itf->index, &info->fm_idx,
				&info->port_idx, &info->port_id)) {
		DPA_ERROR("%s::unable to get fmindex for itfid %d\n",
				__func__, entry->inPhyPortNum);
		goto err_ret;
	}
#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s(%d) inPhyPortNum 0x%x, underlying_input_itf->index %d, fm_idx 0x%x, port_idx %d port_id %d\n",
			__func__, __LINE__, entry->inPhyPortNum, underlying_input_itf->index,
			info->fm_idx, info->port_idx, info->port_id);
#endif // CDX_DPA_DEBUG
	//get pcd handle based on determined fman
	info->fm_pcd = dpa_get_pcdhandle(info->fm_idx);
	if (!info->fm_pcd) {
		DPA_ERROR("%s::unable to get fm_pcd_handle for fmindex %d\n",
				__func__, info->fm_idx);
		goto err_ret;
	}
	if (get_table_type(entry, &tbl_type)) {
		DPA_ERROR("%s::unable to get table type\n",
				__func__);
		goto err_ret;
	}
	info->tbl_type = tbl_type;

	//get table descriptor based on type and port
	info->td = dpa_get_tdinfo(info->fm_idx, info->port_id, tbl_type);
	if (info->td == NULL) {
		DPA_ERROR("%s::unable to get td for itfid %d, type %d\n",
				__func__, entry->inPhyPortNum,
				tbl_type);
		goto err_ret;
	}

	if (dpa_get_tx_info_by_itf(entry->pRtEntry, &info->l2_info,
				&info->l3_info, &entry->qosmark, (uint32_t)entry->hash)) {
		DPA_ERROR("%s::unable to get tx params\n",
				__func__);
		goto err_ret;
	}

	if (encap && apply_l2_encap(info, encap))
		goto err_ret;

#ifdef DPA_IPSEC_OFFLOAD
	/* if the connection is a secure one  and  SA direction is inbound
	 * then, we should add the entry into offline ports's classification
	 * table. cdx_ipsec_fill_sec_info()  will check for the SA direction
	 * and if it is inbound will replace the table id;
	 * if the SA is outbound direction then it will fill sec_fqid in the 
	 * info struture.  
	 */ 
	if(entry->status &  CONNTRACK_SEC)
	{
		if(cdx_ipsec_fill_sec_info(entry,info))
		{
			DPA_ERROR("%s::unable to get td for offline port, type %d\n",
					__func__, info->tbl_type);
			goto err_ret;
		}
	}
#endif

#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s:: td info :%p\n", __func__, info->td);
#endif
	//allocate connection tracker entry
	entry->ct = (struct hw_ct *)kzalloc(sizeof(struct hw_ct), GFP_KERNEL);
	if (!entry->ct) {
		DPA_ERROR("%s::unable to alloc mem for hw_ct\n",
				__func__);
		goto err_ret;
	}
	//save table descriptor for entry release
	entry->ct->td = info->td;
	//get fm context
	entry->ct->fm_ctx = dpa_get_fm_ctx(info->fm_idx);
	if (entry->ct->fm_ctx == NULL) {
		DPA_ERROR("%s::failed to get ctx fro fm idx %d\n",
				__func__, info->fm_idx);
		goto err_ret;
	}

	//allocate hash table entry
#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s::info->td %p\n", __func__, info->td);
#endif
	tbl_entry = ExternalHashTableAllocEntry(info->td);
	if (!tbl_entry) {
		DPA_ERROR("%s::unable to alloc hash tbl memory\n",
				__func__);
		goto err_ret;
	}
#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s:: hash tbl entry %p\n", __func__, tbl_entry);
#endif
	flags = 0;
#ifdef ENABLE_FLOW_TIME_STAMPS
	SET_TIMESTAMP_ENABLE(flags);
	tbl_entry->hashentry.timestamp_counter = 
		cpu_to_be32(dpa_get_timestamp_addr(EXTERNAL_TIMESTAMP_TIMERID));
	tbl_entry->hashentry.timestamp = cpu_to_be32(JIFFIES32);
	entry->ct->timestamp = JIFFIES32;
#endif
#ifdef ENABLE_FLOW_STATISTICS
	SET_STATS_ENABLE(flags);
#endif
	//fill key information from entry
	key_size = fill_key_info(entry, &tbl_entry->hashentry.key[0], info->port_id);
	if (!key_size) {
		DPA_ERROR("%s::unable to compose key\n",
				__func__);
		goto err_ret;
	}	
	if (!info->l3_info.ipsec_inbound_flow &&
	    (tbl_type == IPV4_TCP_TABLE || tbl_type == IPV4_UDP_TABLE ||
	     tbl_type == IPV6_TCP_TABLE || tbl_type == IPV6_UDP_TABLE)) {
		/* The scheme's protocol match selects a TCP or UDP table. */
		unsigned int protocol = IS_IPV6_FLOW(entry) ? 33 : 9;

		memmove(tbl_entry->hashentry.key + protocol,
			tbl_entry->hashentry.key + protocol + 1, 4);
		key_size--;
		key_size += fill_tunnel_key(entry, encap, tbl_entry->hashentry.key + key_size);
	}

	//round off keysize to next 4 bytes boundary 
	ptr = (uint8_t *)&tbl_entry->hashentry.key[0];          
	ptr += ALIGN(key_size, TBLENTRY_OPC_ALIGN);
	//set start of opcode list 
	info->opcptr = ptr;
	//ptr now after opcode section
	ptr += MAX_OPCODES;

	//set offset to first opcode
	SET_OPC_OFFSET(flags, (uint32_t)(info->opcptr - (uint8_t *)tbl_entry));
	//set param offset 
	SET_PARAM_OFFSET(flags, (uint32_t)(ptr - (uint8_t *)tbl_entry));
	//param_ptr now points after timestamp location
	tbl_entry->hashentry.flags = cpu_to_be16(flags);
	//param pointer and opcode pointer now valid
	info->paramptr = ptr;
	info->param_size = (MAX_EN_EHASH_ENTRY_SIZE - 
			GET_PARAM_OFFSET(flags));
	if (fill_actions(entry, info, true)) {
		DPA_ERROR("%s::unable to fill actions\n", __func__);
		goto err_ret;
	}
	tbl_entry->enqueue_params = info->enqueue_params;
	entry->ct->handle = tbl_entry;
#ifdef CDX_DPA_DEBUG
	display_ehash_tbl_entry(&tbl_entry->hashentry, key_size);
#endif // CDX_DPA_DEBUG
	//insert entry into hash table
	retval = ExternalHashTableAddKey(info->td, key_size, tbl_entry); 
	if (retval == -1) {
		DPA_ERROR("%s::unable to add entry in hash table\n", __func__);
		goto err_ret;
	}	
	entry->ct->index = (uint16_t)retval;
	kfree(info);
	return SUCCESS;
err_ret:
	//release all allocated items
	if (entry->ct) {
		kfree(entry->ct);
		entry->ct = NULL;
	}
	if (tbl_entry)
		ExternalHashTableEntryFree(tbl_entry);
err_ret1:
	kfree(info);
	return FAILURE;
}

/* A multicast group's root entry: the classifier key, the ingress validation,
 * and REPLICATE_PKT naming the head of the listener chain.
 *
 * `mac_pair`, when given, keys the root on the frame's own Ethernet pair
 * (destination then source) in the bridged multicast table instead of the
 * routed one; see fill_mcast_mac_key(). `in_encap`, when it names ingress
 * tags, is what the root validates and strips: without it STRIP_ALL_VLAN_HDRS
 * expects an untagged frame, so a tagged one matched the key and was then
 * handed to Linux -- which is how tagged ingress fell back before a group
 * could say what it arrives with. Only its ingress half is read. */
int insert_mcast_entry_in_classif_table(struct _tCtEntry *entry,
					unsigned int num_members, uint64_t first_member_flow_addr,
					void *first_listener_entry, bool bridged,
					const uint8_t *mac_pair,
					const struct cdx_l2_encap *in_encap)
{
	struct ins_entry_info *info;
	struct en_exthash_tbl_entry *tbl_entry;
	struct _itf *underlying_input_itf;
	uint32_t tbl_type;
	uint16_t flags;
	uint32_t key_size;
	uint8_t *ptr;
	int retval;
	
	DPA_INFO("%s::\n", __func__);
#ifdef CDX_DPA_DEBUG
/*	display_ctentry(entry); */
#endif
	
	entry->ct = NULL;
	tbl_entry = NULL;	
	
	info = kzalloc(sizeof(struct ins_entry_info), GFP_KERNEL);
	if (!info)
		return FAILURE;
	
	info->entry = entry;
	/* The root entry also carries the head of the listener chain. */
	info->first_member_flow_addr_hi = cpu_to_be16((first_member_flow_addr >> 32) & 0xffff);
	info->first_member_flow_addr_lo = cpu_to_be32(first_member_flow_addr  & 0xffffffff);
	info->num_mcast_members = num_members;
	info->first_listener_entry = first_listener_entry;
	/* Set when the route was created, but cleared again if the ingress
	 * interface has since been removed while the route stayed referenced. */
	underlying_input_itf = entry->pRtEntry->underlying_input_itf;
	if (!underlying_input_itf) {
		DPA_ERROR("%s::route has no underlying input interface\n",
				__func__);
		goto err_ret1;
	}
	//clear hw entry pointer
	entry->ct = NULL;
	if (add_incoming_iface_info(entry))
	{
		DPA_ERROR("%s::unable to get interface %d\n",__func__,
							entry->inPhyPortNum);
		goto err_ret1;
	}
	//get fman index and port index and port id where this entry need to be added
	if (dpa_get_fm_port_index(entry->inPhyPortNum, underlying_input_itf->index, &info->fm_idx,
			&info->port_idx, &info->port_id)) {
		DPA_ERROR("%s::unable to get fmindex for itfid %d\n",
						__func__, entry->inPhyPortNum);
		goto err_ret;
	}
#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s(%d) inPhyPortNum 0x%x, underlying_input_itf->index %d, fm_idx 0x%x, port_idx %d port_id %d\n",
			__func__, __LINE__, entry->inPhyPortNum, underlying_input_itf->index,
			info->fm_idx, info->port_idx, info->port_id);
#endif // CDX_DPA_DEBUG
	//get pcd handle based on determined fman
	info->fm_pcd = dpa_get_pcdhandle(info->fm_idx);
	if (!info->fm_pcd) {
		DPA_ERROR("%s::unable to get fm_pcd_handle for fmindex %d\n",
					__func__, info->fm_idx);
		goto err_ret;
	}
	if (get_table_type(entry, &tbl_type)) {
		DPA_ERROR("%s::unable to get table type\n",
							__func__);
		goto err_ret;
	}
	if (mac_pair)
		tbl_type = IS_IPV6_FLOW(entry) ? IPV6_BRIDGED_MULTICAST_TABLE :
						 IPV4_BRIDGED_MULTICAST_TABLE;

	//get table descriptor based on type and port
	info->td = dpa_get_tdinfo(info->fm_idx, info->port_id, tbl_type);
	if (info->td == NULL) {
		DPA_ERROR("%s::unable to get td for itfid %d, type %d\n",
							__func__, entry->inPhyPortNum,
								tbl_type);
		goto err_ret;
	}
	DPA_INFO("%s:: td info :%p\n", __func__, info->td);
	//allocate connection tracker entry
	entry->ct = (struct hw_ct *)kzalloc(sizeof(struct hw_ct), GFP_KERNEL);
	if (!entry->ct) {
		DPA_ERROR("%s::unable to alloc mem for hw_ct\n",
								__func__);
		goto err_ret;
	}
	//save table descriptor for entry release
	entry->ct->td = info->td;
	//get fm context
	entry->ct->fm_ctx = dpa_get_fm_ctx(info->fm_idx);
	if (entry->ct->fm_ctx == NULL) {
		DPA_ERROR("%s::failed to get ctx fro fm idx %d\n",
						__func__, info->fm_idx);
		goto err_ret;
	}
	
	if (dpa_get_tx_info_by_itf(entry->pRtEntry, &info->l2_info,
			&info->l3_info, &entry->qosmark, (uint32_t)entry->hash)) {
		DPA_ERROR("%s::unable to get tx params\n",
									__func__);
		goto err_ret;
	}
	/* After the interface walk, as for a flow: the root route names a
	 * physical port, so the walk found no tag and the group's own
	 * description is the only one. An untagged ingress passes nothing and
	 * is validated as untagged. */
	if (in_encap && in_encap->num_ingress &&
	    apply_l2_encap(info, in_encap)) {
		DPA_ERROR("%s::unable to apply the ingress tags\n", __func__);
		goto err_ret;
	}

	//allocate hash table entry
	DPA_INFO("%s::info->td %p\n", __func__, info->td);
	tbl_entry = ExternalHashTableAllocEntry(info->td);
	if (!tbl_entry) {
		DPA_ERROR("%s::unable to alloc hash tbl memory\n",
									__func__);
		goto err_ret;
	}
	DPA_INFO("%s:: hash tbl entry %p\n", __func__, tbl_entry);
		flags = 0;
#ifdef ENABLE_FLOW_TIME_STAMPS
	SET_TIMESTAMP_ENABLE(flags);
	tbl_entry->hashentry.timestamp_counter = 
			cpu_to_be32(dpa_get_timestamp_addr(EXTERNAL_TIMESTAMP_TIMERID));
	tbl_entry->hashentry.timestamp = cpu_to_be32(JIFFIES32);
	entry->ct->timestamp = JIFFIES32;
#endif
#ifdef ENABLE_FLOW_STATISTICS
	SET_STATS_ENABLE(flags);
#endif
//fill key information from entry
	if (mac_pair)
		key_size = fill_mcast_mac_key(entry, mac_pair,
					      &tbl_entry->hashentry.key[0],
					      info->port_id);
	else
		key_size = fill_key_info(entry, &tbl_entry->hashentry.key[0],
					 info->port_id);
	if (!key_size) {
		DPA_ERROR("%s::unable to compose key\n",
								__func__);
		goto err_ret;
	}
	//round off keysize to next 4 bytes boundary
	ptr = (uint8_t *)&tbl_entry->hashentry.key[0];
	ptr += ALIGN(key_size, TBLENTRY_OPC_ALIGN);
	//set start of opcode list
	info->opcptr = ptr;
	//ptr now after opcode section
	ptr += MAX_OPCODES;

	//set offset to first opcode
	SET_OPC_OFFSET(flags, (uint32_t)(info->opcptr - (uint8_t *)tbl_entry));
	//set param offset
	SET_PARAM_OFFSET(flags, (uint32_t)(ptr - (uint8_t *)tbl_entry));
	//param_ptr now points after timestamp location
	tbl_entry->hashentry.flags = cpu_to_be16(flags);
	//param pointer and opcode pointer now valid
	info->paramptr = ptr;
	info->param_size = (MAX_EN_EHASH_ENTRY_SIZE -
		GET_PARAM_OFFSET(flags));
	if (fill_actions(entry, info, !bridged)) {
		DPA_ERROR("%s::unable to fill actions\n", __func__);
		goto err_ret;
	}
	tbl_entry->replicate_params = info->replicate_params;
	tbl_entry->enqueue_params = info->enqueue_params;
	entry->ct->handle = tbl_entry;
#ifdef CDX_DPA_DEBUG
	display_ehash_tbl_entry(&tbl_entry->hashentry, key_size);
#endif // CDX_DPA_DEBUG
	/* The per-listener entries built earlier (their opcodes, params,
	 * and the chain's prev_listener->next_entry pointers) plus this
	 * root entry's REPLICATE_PARAMS were all stored to coherent DDR.
	 * On weak-ordered ARM64 those writes can sit in the CPU's store
	 * buffer when AddKey installs the bucket->head pointer that FMAN
	 * microcode walks. Without a barrier, FMAN can read the new bucket
	 * head and dereference a listener entry whose opcode/chain bytes
	 * are still stale, hitting CC stats but failing to enqueue to the
	 * listener TX FQ. wmb() drains the store buffer, ordering all
	 * prior writes before AddKey's bucket-head publication. */
	wmb();
	//insert entry into hash table
	retval = ExternalHashTableAddKey(info->td, key_size, tbl_entry);
	if (retval == -1) {
		DPA_ERROR("%s::unable to add entry in hash table\n", __func__);
		goto err_ret;
	}	
	entry->ct->index = (uint16_t)retval;
	kfree(info);
	return SUCCESS;
err_ret:
	//release all allocated items
	if (entry->ct) {
		kfree(entry->ct);
		/* the non-mcast sibling NULLs this too; a stale pointer here
		 * is a UAF for any caller that retries or re-inspects entry */
		entry->ct = NULL;
	}
	if (tbl_entry)
		ExternalHashTableEntryFree(tbl_entry);
err_ret1:
	kfree(info);
	return FAILURE;
}

#ifdef INCLUDE_PPPoE_IFSTATS
/* The address of one timestamped statistics record half, from the index a
 * header manipulation carries. Index zero is never a record a PPPoE session
 * owns -- STATS_WITH_TS is always set on a real one -- so it is the caller's
 * way of saying there is none, and the opcode takes a null pointer instead. */
static uint32_t pppoe_stats_pointer(uint8_t index)
{
	if (!index)
		return 0;
	return get_logical_ifstats_base() +
		((index & ~STATS_WITH_TS) * sizeof(struct en_ehash_stats_with_ts));
}
#endif

static int create_pppoe_ins_hm(struct ins_entry_info *info)
{
	struct en_ehash_insert_pppoe_hdr *param;
	uint32_t word;

	if (info->opc_count == MAX_OPCODES)
		return FAILURE;
	if (sizeof(struct en_ehash_insert_pppoe_hdr) > info->param_size)
		return FAILURE;
	param = (struct en_ehash_insert_pppoe_hdr *)info->paramptr;
	info->paramptr += sizeof(struct en_ehash_insert_pppoe_hdr);
	info->param_size -= sizeof(struct en_ehash_insert_pppoe_hdr);
	*(info->opcptr) = INSERT_PPPoE_HDR;
	info->opc_count++;
	info->opcptr++;
	/* Update the Ethertype now PPPoE is the outermost header  */
	info->eth_type = ETHERTYPE_PPPOE;
#ifdef INCLUDE_PPPoE_IFSTATS
	/* The session names its own record in the description, or names none. */
	param->stats_ptr =
		cpu_to_be32(pppoe_stats_pointer(info->l2_info.pppoe_stats_offset));
#else
	param->stats_ptr = 0;
#endif
	word = ((PPPoE_VERSION << 28) | (PPPoE_TYPE << 24) | (PPPoE_CODE << 16) |
			(info->l2_info.pppoe_sess_id));
	param->word = cpu_to_be32(word);
	return SUCCESS;
}

static int create_vlan_ins_hm(struct ins_entry_info *info)
{
	int32_t ii, jj;
	uint32_t word;
	struct en_ehash_insert_vlan_hdr *param;
	struct dpa_l2hdr_info *l2_info;
	uint32_t *ptr;
	uint32_t param_size;
	uint32_t num_egress_vlan_hdrs;

	if (info->opc_count == MAX_OPCODES)
		return FAILURE;
	
	l2_info = &(info->l2_info);
	param = (struct en_ehash_insert_vlan_hdr *)info->paramptr;
	num_egress_vlan_hdrs = l2_info->num_egress_vlan_hdrs;
	/* Bit 30, the microcode's DSCP-to-PCP rewrite, stays clear: nothing
	 * programs that map. */
	word = 0;

	param_size = (sizeof(struct en_ehash_insert_vlan_hdr) +
			(num_egress_vlan_hdrs * sizeof(uint32_t)));
	if (param_size > info->param_size)
		return FAILURE;

	word |= (num_egress_vlan_hdrs << 24);
	/* add vlan headers */
	ptr = (uint32_t *)&param->vlanhdr[0];
	info->vlan_hdrs = ptr;
	for (jj =0 ,ii = num_egress_vlan_hdrs - 1 ; ii >=0 ; ii--) {
		*(ptr + ii) = cpu_to_be32((l2_info->egress_vlan_hdrs[jj++].tci << 16) | (uint32_t )info->eth_type);
		info->eth_type = l2_info->egress_vlan_hdrs[ii].tpid;
	}

#ifdef INCLUDE_VLAN_IFSTATS
	/* If there are no actual vlans, then should not update interface stats pointer */
	/* because there is no vlan interfaces on egress side.*/
	/* vlan id can be 0 when there is only one vlan, and in word stats_ptr bits */
	/* already set to 0(NULL), so we can skip the stats.*/
	if (!l2_info->egress_vlan_hdrs[0].tci)
		goto skip_stats;
	/* Only a flow describes egress tags (apply_l2_encap()), and it names
	 * a record for every tag or names none. */
	if (!vlan_flow_stats_named(l2_info->vlan_stats_offsets, num_egress_vlan_hdrs))
		goto skip_stats;
	{
		uint8_t *st_ptr;

		if (num_egress_vlan_hdrs > 1) {
			/* set pointer last vlan offset */
			st_ptr = (uint8_t *)((uint32_t *)ptr + (num_egress_vlan_hdrs ));
			param_size = ALIGN(param_size + num_egress_vlan_hdrs, sizeof(uint32_t));
			if (param_size > info->param_size)
				return FAILURE;
			/* add stats base */
			word |= (get_logical_ifstats_base());
			/* The ucode inserts the innermost header first and counts
			 * the k-th record with the frame as it stands after the
			 * k-th insertion (measured: a frame ending at 306 bytes
			 * reads 302 in the first record and 306 in the second).
			 * Listing the records innermost first therefore gives each
			 * VLAN device the frame with its own tag on and the tags
			 * inside it, which is what the device's own transmit
			 * counter would have shown. */
			for (ii = 0; ii < (int32_t)num_egress_vlan_hdrs; ii++)
				*st_ptr++ = l2_info->vlan_stats_offsets[ii];
		} else {
			/* single Vlan header, add stats ptr directly */
			word |= (get_logical_ifstats_base() + 
					l2_info->vlan_stats_offsets[0] * sizeof(struct en_ehash_stats));
		}
	}
#else
	DPA_INFO("%s::Vlan statistics disabled\n", __func__);
#endif
skip_stats:
	/* write word */
	param->word = cpu_to_be32(word);
	/* write opcode and update pointers */
	*(info->opcptr) = INSERT_VLAN_HDR;
	info->opc_count++;
	info->opcptr++;
	info->paramptr += param_size;
	info->param_size -= param_size;
	return SUCCESS;
}

static int create_ethernet_hm(struct ins_entry_info *info, uint32_t update_ethtype)
{
	struct dpa_l2hdr_info *l2_info;
	uint32_t ii;
	uint32_t header_padding;
	uint32_t hdrlen;
	struct en_ehash_insert_l2_hdr *l2param;

	if (info->opc_count == MAX_OPCODES)
		return FAILURE;

	l2_info = &info->l2_info;
	l2param = (struct en_ehash_insert_l2_hdr *)info->paramptr;
	hdrlen = (ETHER_ADDR_LEN * 2);
	if (update_ethtype) /* updating ether header here */ 
		hdrlen +=ETHER_TYPE_LEN;
	ii = ALIGN((hdrlen + sizeof(struct en_ehash_insert_l2_hdr)), sizeof(uint32_t));
	if (ii > info->param_size)
		return FAILURE;
	//adjust param ptrs and size
	info->paramptr += ii;
	info->param_size -= ii;
	header_padding =  ((hdrlen + sizeof(struct en_ehash_insert_l2_hdr))% sizeof(uint32_t));
	ii =  hdrlen |(header_padding << 29);
	//add opcode, adjust size and ptr
	l2param->word = cpu_to_be32(ii);
	*(info->opcptr) = INSERT_L2_HDR;
	info->opc_count++;
	info->opcptr++;
	/* l2param->l2hdr is a flexible array member (uint8_t l2hdr[0]) so
	 * FORTIFY_SOURCE sees it as zero-size. Use unsafe_memcpy to bypass
	 * FORTIFY checks - actual buffer allocated beyond struct with size
	 * validated by hdrlen calculation above. */
	if (l2_info->add_pppoe_hdr) {
		//if pppoe header required, replace dest with ac conc address
		unsafe_memcpy(l2param->l2hdr, l2_info->ac_mac_addr, ETHER_ADDR_LEN,
			"flexible array with caller-validated allocation");
	} else {
		//if no pppoe header required, replace dest with gw address
		unsafe_memcpy(l2param->l2hdr, l2_info->l2hdr, ETHER_ADDR_LEN,
			"flexible array with caller-validated allocation");
	}
	// write source address
	unsafe_memcpy(l2param->l2hdr + ETHER_ADDR_LEN,
			l2_info->l2hdr + ETHER_ADDR_LEN, ETHER_ADDR_LEN,
			"flexible array with caller-validated allocation");
	/* Use pointer arithmetic rather than l2hdr[2*ETHER_ADDR_LEN] — UBSAN
	 * bounds-checks the subscript form against l2hdr's declared size
	 * (flexible array = 0) and would flag this even though the buffer
	 * is allocated past the struct by the caller. Same rationale as the
	 * surrounding unsafe_memcpy calls. */
	*(uint16_t *)(l2param->l2hdr + 2 * ETHER_ADDR_LEN) = htons(info->eth_type);

	return SUCCESS;
}

static int insert_remove_pppoe_hm(struct ins_entry_info *info)
{
	uint32_t param_size;
	struct en_ehash_strip_pppoe_hdr *param;
	uint32_t stats_ptr;

	param = (struct en_ehash_strip_pppoe_hdr *)info->paramptr;
	param_size = sizeof(struct en_ehash_strip_pppoe_hdr);
	if (param_size > info->param_size)
		return FAILURE;
#ifdef INCLUDE_PPPoE_IFSTATS
	/* The session names its receive record in the description, or names
	 * none. */
	stats_ptr = pppoe_stats_pointer(info->l2_info.pppoe_rx_stats_offset);
#else
	stats_ptr = 0;
	DPA_INFO("%s:PPPoE ingress stats disabled\n", __func__);
#endif
	param->stats_ptr = cpu_to_be32(stats_ptr);
	//add opcode
	*(info->opcptr) = STRIP_PPPoE_HDR;
	//adjust opc, param ptrs and size
	info->opc_count++;
	info->opcptr++;
	info->param_size -= param_size;
	info->paramptr += param_size;
	return SUCCESS;
}

static int insert_remove_vlan_hm(struct ins_entry_info *info, uint32_t iif_index, uint32_t underlying_iif_index)
{
	uint32_t param_size;
	struct en_ehash_strip_all_vlan_hdrs *param;
	uint32_t num_entries;
	uint32_t word;
	int i = 0;

	if (info->opc_count >= MAX_OPCODES)
		return FAILURE;
	param = (struct en_ehash_strip_all_vlan_hdrs *)info->paramptr;
	param_size = sizeof(struct en_ehash_strip_all_vlan_hdrs);
	if (info->sec_tag) {
		/* SEC already removed the ingress encapsulation. Validate and
		 * strip only its internal identity; no user VLAN statistics. */
		if (param_size > info->param_size)
			return FAILURE;
		memset(param, 0, param_size);
		param->vlan_id[0] = cpu_to_be16(info->sec_tag);
		goto emit_strip_vlan;
	}

#ifdef INCLUDE_VLAN_IFSTATS
	if (info->l2_info.vlan_flow_ifstats) {
		/* The flow names its own records, or none. The list is laid out
		 * outermost first, the order vlan_id[] below uses: the ucode
		 * strips the outer tag first and counts the k-th record with
		 * the frame as it stands after the k-th strip (measured: a
		 * 306-byte double-tagged frame reads 302 in the first record
		 * and 298 in the second), so this order gives each VLAN device
		 * the frame with its own tag off, which is what the device's own
		 * receive counter would have shown once the Ethernet header is
		 * taken off too. Without records the word is the vendor's own
		 * statistics-disabled encoding. */
		uint32_t padding;

		num_entries = info->l2_info.num_ingress_vlan_hdrs;
		if (!vlan_flow_stats_named(info->l2_info.ingress_vlan_stats_offsets,
					   num_entries))
			num_entries = 0;
		if (num_entries > 1) {
			padding = PAD(num_entries, sizeof(uint32_t));
			param_size += (padding + num_entries);
			if (param_size > info->param_size)
				return FAILURE;
			for (i = 0; i < num_entries; i++)
				param->stats_offsets[i] =
					info->l2_info.ingress_vlan_stats_offsets[num_entries - 1 - i];
			word = ((padding << 30) | (num_entries << 24) | get_logical_ifstats_base());
		} else {
			if (param_size > info->param_size)
				return FAILURE;
			word = 0;
			if (num_entries == 1)
				word = ((1 << 24) | (get_logical_ifstats_base() +
					(info->l2_info.ingress_vlan_stats_offsets[0] *
					 sizeof(struct en_ehash_stats))));
		}
	} else {
		/* A flow that named no encapsulation at all, or a multicast group
		 * with an untagged ingress: nothing to strip and no record to
		 * count. The port must still be a registered one, which has no
		 * VLAN records of its own (dpa_get_num_vlan_iface_stats_entries()
		 * counts none and refuses anything else), so the word is the
		 * statistics base with a count of zero. */
		if (dpa_get_num_vlan_iface_stats_entries(iif_index,underlying_iif_index,
					&num_entries)) {
			DPA_ERROR("%s::unable to get number on vlan iface on ingress\n",
					__func__);
			return FAILURE;
		}
		if (param_size > info->param_size)
			return FAILURE;
		word = get_logical_ifstats_base();
	}
#else
	if (param_size > info->param_size)
		return FAILURE;
	word = 0;
	DPA_INFO("%s::Vlan ingress stats disabled\n", __func__);
#endif
	param->word = cpu_to_be32(word);
	if( info->l2_info.num_ingress_vlan_hdrs)
	{
		/* Outer vlan id is stored first in param ptr and then inner vlan id.
		This is for convenience in writing ucode to validate the vlan's.
		In ucode first outer vlan is validated and then inner vlan */
		for (i = 0 ; i < info->l2_info.num_ingress_vlan_hdrs; i++) {
			param->vlan_id[i] = cpu_to_be16(info->l2_info.ingress_vlan_hdrs[info->l2_info.num_ingress_vlan_hdrs-i-1].tci);
		}
	}

emit_strip_vlan:
	//add opcode
	*(info->opcptr) = STRIP_ALL_VLAN_HDRS;
	//adjust opc, param ptrs and size
	info->opc_count++;
	info->opcptr++;
	info->param_size -= param_size;
	info->paramptr += param_size;
	return SUCCESS;
}


/* Strip every header between the Ethernet header, which SEC wants kept, and
 * the outer IP one. Only an inbound SA's entry takes this, and nothing
 * describes a tag or a session for one -- dpa_get_l2l3_info_by_itf_id() fills
 * in neither -- so there are no VLAN ids to validate and no records to list:
 * the word is the statistics base with a count of zero, on a port that must be
 * a registered one. */
static int insert_remove_l2_hm(struct ins_entry_info *info, uint32_t iif_index, uint32_t underlying_iif_index)
{
	uint32_t param_size;
	struct en_ehash_strip_l2_hdrs *param;
	uint32_t num_entries;
	uint32_t word;

	param = (struct en_ehash_strip_l2_hdrs*)info->paramptr;
	param_size = sizeof(struct en_ehash_strip_l2_hdrs);
#ifdef INCLUDE_VLAN_IFSTATS
	if (dpa_get_num_vlan_iface_stats_entries(iif_index,underlying_iif_index,
				&num_entries)) {
		DPA_ERROR("%s::unable to get number on vlan iface on ingress\n",
				__func__);
		return FAILURE;
	}
	if (param_size > info->param_size)
		return FAILURE;
	word = get_logical_ifstats_base();
#else
	if (param_size > info->param_size)
		return FAILURE;
	word = 0;
	DPA_INFO("%s::Vlan / PPPoE ingress stats disabled\n", __func__);
#endif
	param->word = cpu_to_be32(word);
	*(info->opcptr) = STRIP_L2_HDR;
	info->opc_count++;
	info->opcptr++;
	info->param_size -= param_size;
	info->paramptr += param_size;
	return SUCCESS;
}

static int create_ttl_hm(struct ins_entry_info *info)
{
	if(insert_opcodeonly_hm(info,UPDATE_TTL) == SUCCESS)
		return create_update_dscp_hm(info,UPDATE_TTL);

	return FAILURE;
}

static int create_hoplimit_hm(struct ins_entry_info *info)
{
	if(insert_opcodeonly_hm(info,UPDATE_HOPLIMIT) == SUCCESS)
		return create_update_dscp_hm(info,UPDATE_HOPLIMIT);

	return FAILURE;
}

static int create_update_dscp_hm(struct ins_entry_info *info,uint8_t opcode)
{
	struct en_ehash_update_dscp *ptr;
	PCtEntry ctentry = info->entry;
	union ctentry_qosmark *qosmark = (union ctentry_qosmark *)&ctentry->qosmark;
	uint32_t dscp_mark = 0;

	/* do dscp marking in the disguise of ttl/hoplimit since V3 subclass has only 3 bits */
	if((opcode == UPDATE_TTL) || (opcode == UPDATE_HOPLIMIT)) {

		if (info->param_size < sizeof(struct en_ehash_update_dscp))
			return FAILURE;

		ptr = (struct en_ehash_update_dscp *)info->paramptr;

		if(qosmark->dscp_mark_flag) {

			dscp_mark |= ((qosmark->dscp_mark_value << 2) | 0x2); /* mark the 2nd bit for dscp marking */
			ptr->dscp = cpu_to_be32(dscp_mark);
		}
		else
			ptr->dscp = 0;

		info->paramptr += sizeof(struct en_ehash_update_dscp);
		info->param_size -= sizeof(struct en_ehash_update_dscp);
	}
	return SUCCESS;
}

static int insert_opcodeonly_hm(struct ins_entry_info *info, uint8_t opcode)
{
	if (info->opc_count == MAX_OPCODES)
		return FAILURE;
	*(info->opcptr) = opcode;
	info->opc_count++;
	info->opcptr++;
	return SUCCESS;
}

static int create_nat_hm(struct ins_entry_info *info)
{
	uint8_t opcode;
	uint32_t size;
	int ret = SUCCESS;

	if (info->opc_count == MAX_OPCODES)
		return FAILURE;
	opcode = 0;
	if (info->flags & NAT_HM_REPLACE_SPORT) {
		opcode = UPDATE_SPORT;
	}
	if (info->flags & NAT_HM_REPLACE_DPORT) {
		opcode |= UPDATE_DPORT;
	}
	//add port translation info
	if (opcode) {
		struct en_ehash_update_port *natport;

		if (info->param_size < sizeof(struct en_ehash_update_port))
			return FAILURE;
		*(info->opcptr) = opcode;
		info->opcptr++;
		info->opc_count++;
		natport = (struct en_ehash_update_port *)info->paramptr;

		natport->sport = (info->nat_sport);
		natport->dport = (info->nat_dport);

		info->paramptr += sizeof(struct en_ehash_update_port);
		info->param_size -= sizeof(struct en_ehash_update_port);
	}

	if (info->opc_count == MAX_OPCODES)
		return FAILURE;

	size = 0;
	opcode = 0;
	if(info->flags & TTL_HM_VALID) {
		if (info->flags & EHASH_IPV6_FLOW)
		{
			opcode |= UPDATE_HOPLIMIT;
			ret = create_update_dscp_hm(info,UPDATE_HOPLIMIT);
		} else {
			opcode |= UPDATE_TTL;
			ret = create_update_dscp_hm(info,UPDATE_TTL);
		}
	}

	if (info->flags & NAT_HM_REPLACE_SIP) {
		if (info->flags & EHASH_IPV6_FLOW) {
			opcode |= UPDATE_SIP_V6;
			size += sizeof(struct en_ehash_update_ipv6_ip);
		} else {
			opcode |= UPDATE_SIP_V4;
			size += sizeof(struct en_ehash_update_ipv4_ip);
		}
	}
	if (info->flags & NAT_HM_REPLACE_DIP) {
		if (info->flags & EHASH_IPV6_FLOW) {
			opcode |= UPDATE_DIP_V6;
			size += sizeof(struct en_ehash_update_ipv6_ip);
		} else {
			opcode |= UPDATE_DIP_V4;
			size += sizeof(struct en_ehash_update_ipv4_ip);
		}
	}
	if (opcode) {
		uint8_t *ptr;
		if (size > info->param_size)
			return FAILURE;
		ptr = info->paramptr;
		if (info->flags & NAT_HM_REPLACE_SIP) {
			if (info->flags & EHASH_IPV6_FLOW) {
				memcpy(ptr, &info->v6.nat_sip[0], sizeof(struct en_ehash_update_ipv6_ip));
				ptr += sizeof(struct en_ehash_update_ipv6_ip);
			} else {
				memcpy(ptr, &info->v4.nat_sip, sizeof(struct en_ehash_update_ipv4_ip));
				ptr += sizeof(struct en_ehash_update_ipv4_ip);
			}
		}	
		if (info->flags & NAT_HM_REPLACE_DIP) {
			if (info->flags & EHASH_IPV6_FLOW) {
				memcpy(ptr, &info->v6.nat_dip[0], sizeof(struct en_ehash_update_ipv6_ip));
				ptr += sizeof(struct en_ehash_update_ipv6_ip);
			} else {
				memcpy(ptr, &info->v4.nat_dip, sizeof(struct en_ehash_update_ipv4_ip));
				ptr += sizeof(struct en_ehash_update_ipv4_ip);
			}
		}
		info->paramptr = ptr;
		info->param_size -= size;
	}
	*(info->opcptr) = opcode;
	info->opcptr++;
	return ret;
}
#ifdef INCLUDE_TUNNEL_IFSTATS
/* The statistics pointer a flow-described tunnel's opcodes carry: the record
 * at the given index of the plain pool, or the null pointer for no record.
 * Index zero is another owner's record, never "none". */
static uint32_t tunnel_stats_pointer(uint8_t index)
{
	if (!index)
		return 0;
	return (get_logical_ifstats_base() +
		(index * sizeof(struct en_ehash_stats))) & 0xffffff;
}
#endif

static int create_tunnel_insert_hm(struct ins_entry_info *info)
{
	uint32_t size;
	uint32_t word;

	struct en_ehash_insert_l3_hdr *ptr;

	if (info->opc_count == MAX_OPCODES)
		return FAILURE;
	size = (sizeof(struct en_ehash_insert_l3_hdr) + 
			info->l3_info.header_size);
	size = ALIGN(size, sizeof(uint32_t));
	if (size > info->param_size)
		return FAILURE;

	ptr = (struct en_ehash_insert_l3_hdr *)info->paramptr;
	switch (info->l3_info.mode) {
		case TNL_MODE_4O6:
			word = (TYPE_4o6 << 24);		
			memcpy(&ptr->l3hdr[0], &info->l3_info.header_v6, 
					info->l3_info.header_size);
			info->eth_type = ETHERTYPE_IPV6;	
			if(info->l3_info.tunnel_flags & INHERIT_TC)
				word |= (1 << 27); /* propagate tos */
			break;
		case TNL_MODE_6O4:
			word = (TYPE_6o4 << 24);		
			memcpy(&ptr->l3hdr[0], &info->l3_info.header_v4, 
					info->l3_info.header_size);
			info->eth_type = ETHERTYPE_IPV4;	
			break;
		default:
			//other types to be supported later
			return FAILURE;
	}
	word |= ((info->l3_info.header_size << 16) | IPID_STARTVAL);
	//TODO:CCS, DF, not handled now
	ptr->word = cpu_to_be32(word);
	//TODO: routing destination offset is now 0
	word = 0;
#ifdef INCLUDE_TUNNEL_IFSTATS
	/* The tunnel names its own record in the description, or names none. */
	word |= tunnel_stats_pointer(info->l3_info.tunnel_stats_offset);
#endif
	info->tnl_hdr_size += info->l3_info.header_size;
	ptr->word_1 = cpu_to_be32(word);
	*(info->opcptr) = INSERT_L3_HDR;
	info->opcptr++;
	info->opc_count++;
	info->param_size -= size;
	info->paramptr += size;
	return SUCCESS;
}

static int create_tunnel_remove_hm(struct ins_entry_info *info)
{
	struct en_ehash_remove_first_ip_hdr *param;
	uint32_t word = 0;

	if (info->opc_count == MAX_OPCODES)
		return FAILURE;
	if (sizeof(struct en_ehash_remove_first_ip_hdr) > info->param_size)
		return FAILURE;
	param = (struct en_ehash_remove_first_ip_hdr *)info->paramptr;

#ifdef INCLUDE_TUNNEL_IFSTATS
	/* The tunnel names its receive record in the description, or names
	 * none. */
	word |= tunnel_stats_pointer(info->l3_info.tunnel_rx_stats_offset);
#endif
	info->eth_type = Get_Tnl_Ethertype(info->l3_info.mode) & 0xFFFF;	
	if (info->l3_info.tunnel_flags & DSCP_COPY)
		word |= COPY_DSCP_OUTER_INNER;
	/* Serialize flags and the 24-bit MURAM offset as one BE word. */
	param->word = cpu_to_be32(word);
	//update opcode and param ptr
	*(info->opcptr) = REMOVE_FIRST_IP_HDR;
	info->opcptr++;
	info->opc_count++;
	info->param_size -= sizeof(struct en_ehash_remove_first_ip_hdr);
	info->paramptr += sizeof(struct en_ehash_remove_first_ip_hdr);
	return SUCCESS;
}

/* The preemptive checks header manipulation is one that can only be sealed when we know 
   where we are enqueueing the packet (opcode: ENQUEUE_PKT) which is the very last OPCODE 
   a packet manipulation goes through. The purpose of the PREEMPTIVE_CHECKS_ON_PKT is to 
   identify preemptive failures before enqueue and handle them gracefully.

   Since the opcode params are heavily dependent on other params, that might or might not be set 
   through the process of HM config, create_preemptive_checks_hm only serves as a place holder 
   for the OPcode params they will be appropriately sealed in the corresponding coupled HM  */

#ifdef ENABLE_INGRESS_QOS
static int create_preemptive_checks_hm(struct ins_entry_info *info,uint16_t queue_no)
#else
static int create_preemptive_checks_hm(struct ins_entry_info *info)
#endif
{
	struct en_ehash_preempt_op *param;

	if (info->opc_count == MAX_OPCODES)
		return FAILURE;
	if (sizeof(struct en_ehash_preempt_op) > info->param_size)
		return FAILURE;
	param = (struct en_ehash_preempt_op *)info->paramptr;
	*(info->opcptr) = PREEMPTIVE_CHECKS_ON_PKT;
	info->opcptr++;
	info->opc_count++;
	info->preempt_params = info->paramptr;
	info->param_size -= sizeof(struct en_ehash_preempt_op);
	info->paramptr += sizeof(struct en_ehash_preempt_op);
#ifdef ENABLE_INGRESS_QOS
#ifdef SEC_PROFILE_SUPPORT
	if(info->to_sec_fqid) {
		if((param->pp_no = cdx_get_policer_profile_id(info->fm_idx, 
				INGRESS_SEC_POLICER_QUEUE_NUM))) {
			param->OpMask |= PREEMPT_POLICE_PKT;
		}
	}
	else
#endif /* endif for SEC_PROFILE_SUPPORT */
	{
		if((param->pp_no = cdx_get_policer_profile_id(info->fm_idx,queue_no))) {
			param->OpMask |= PREEMPT_POLICE_PKT;
		}
	}
#endif

	return SUCCESS;
}

/* This function creates preeemptive checks for NATT packets */
static int create_ipsec_preemptive_checks_hm(struct ins_entry_info *info, uint32_t spi)
{
	struct en_ehash_ipsec_preempt_op *param;

	if (info->opc_count == MAX_OPCODES)
		return FAILURE;
	if (sizeof(struct en_ehash_ipsec_preempt_op) > info->param_size)
		return FAILURE;
	param = (struct en_ehash_ipsec_preempt_op *)info->paramptr;
	param->op_flags = VALIDATE_SPI;
	param->spi_param[0].spi = spi;
	param->spi_param[0].fqid = cpu_to_be32(info->to_sec_fqid);
	param->natt_arr_mask = cpu_to_be16(0x1 << 0);
	*(info->opcptr) = PREEMPTIVE_CHECKS_ON_IPSEC_PKT;
	info->opcptr++;
	info->opc_count++;
	info->preempt_params = info->paramptr;
	info->param_size -= sizeof(struct en_ehash_ipsec_preempt_op);
	info->paramptr += sizeof(struct en_ehash_ipsec_preempt_op);
	return SUCCESS;
}


static int seal_preemptive_checks_hm(struct ins_entry_info *info)
{
	struct en_ehash_preempt_op *param;
	if (!info->enqueue_params || !info->preempt_params)
		return FAILURE;
	param = (struct en_ehash_preempt_op *)info->preempt_params;
	param->mtu_offset = (info->enqueue_params - info->preempt_params); /* Offset to MTU in Param Array */

	if (!info->l2_info.is_wlan_iface)
		param->OpMask |= PREEMPT_TX_VALIDATE;

	if(!(info->flags & EHASH_IPV6_FLOW))
		param->OpMask |= PREEMPT_DFBIT_HONOR;
	return SUCCESS;	
}

static int create_eth_rx_stats_hm(struct ins_entry_info *info, uint32_t iif_index, uint32_t underlying_iif_index)
{
#ifdef INCLUDE_ETHER_IFSTATS
	uint8_t offset;
	uint32_t stats_ptr;
	struct en_ehash_update_ether_rx_stats *param;

	if(dpaa_is_oh_port(info->port_id))
		return SUCCESS;

	if (info->opc_count == MAX_OPCODES)
		return FAILURE;
	if (sizeof(struct en_ehash_update_ether_rx_stats) > info->param_size)
		return FAILURE;

	param = (struct en_ehash_update_ether_rx_stats *)info->paramptr;

	if (dpa_get_iface_stats_entries(iif_index, underlying_iif_index,
				&offset, RX_IFSTATS, IF_TYPE_ETHERNET)) {
		DPA_ERROR("%s::unable to get stats offset on ethernet iface on ingress\n",
				__func__);
		return FAILURE;
	}
	stats_ptr = (get_logical_ifstats_base() + (offset * sizeof(struct en_ehash_stats)));

#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s::stats ptr %x\n", __func__, stats_ptr);
#endif
	param->stats_ptr = cpu_to_be32(stats_ptr);
	//update opcode and param ptr
	*(info->opcptr) = UPDATE_ETH_RX_STATS;
	info->opcptr++;
	info->opc_count++;
	info->param_size -= sizeof(struct en_ehash_update_ether_rx_stats);
	info->paramptr += sizeof(struct en_ehash_update_ether_rx_stats);
#endif
	return SUCCESS;
}

static int create_strip_eth_hm(struct ins_entry_info *info)
{
	return (insert_opcodeonly_hm(info, STRIP_ETH_HDR));
}

static inline int create_enque_only_hm(struct ins_entry_info *info)
{
        return (insert_opcodeonly_hm(info, ENQUEUE_ONLY));
}

static int create_enque_hm(struct ins_entry_info *info)
{
	struct en_ehash_enqueue_param *param;
#ifdef ENABLE_EGRESS_QOS
	PCtEntry entry = (PCtEntry)info->entry;
#endif
	uint32_t word = 0;

	if (info->l2_info.mtu == 0) {
		DPA_ERROR("%s::mtu is null\n", __func__);
		return FAILURE;
	}
	if (info->opc_count == MAX_OPCODES)
		return FAILURE;
	if (sizeof(struct en_ehash_enqueue_param) > info->param_size)
		return FAILURE;
	info->enqueue_params = info->paramptr;
	param = (struct en_ehash_enqueue_param *)info->paramptr;
	param->mtu = cpu_to_be16(info->l2_info.mtu);
	//param->bpid = cpu_to_be16(frag_info_g.frag_bp_id);
	param->bpid = frag_info_g.frag_bp_id;
	word = 0;
#ifdef ENABLE_EGRESS_QOS	
	/* dscp_to_fq_map should be applied to packets which are getting 
	   transmitted on xmit_fqs of interface and not for pkts 
	   transmitted to secure frame queues */
	if ((info->l2_info.is_dscp_fq_map) && (!info->to_sec_fqid))
		word = DSCP_FQ_MAP_ENABLE;

	/* info->entry will be set when adding l2 or l3 flow */
	if ((info->to_sec_fqid) && (info->entry))
	{
		/* Disable PRE FRAGMENTATION when packets are destined to SEC*/
		word |= (FRAG_DISABLE);
		/* Enabling DPOVRD setting either the flow is ipv4 or ipv6 only. */
		if (IS_IPV4_FLOW(entry))
			word |= (IPSEC_DPOVRD_ENABLE|IPSEC_IPV4_ENCAPSULATION);
		else if (IS_IPV6_FLOW(entry))
			word |= (IPSEC_DPOVRD_ENABLE|IPSEC_IPV6_ENCAPSULATION);
	}
	word = word << 24;
#endif
	word |= MURAM_VIRT_TO_PHYS_ADDR(dscp_fq_map_ff_g.muram_addr);
	param->word2 = cpu_to_be32(word);
	word = 0;
	if(info->to_sec_fqid) {
		param->stats_ptr = 0;
		param->fqid = cpu_to_be32(info->to_sec_fqid);
	} else if (info->l2_info.is_wlan_iface){ /* Don't increment stats if wifi is the tx interface */
		param->stats_ptr = 0;
		word |= (uint32_t)info->l2_info.rspid << 24;
		param->word = cpu_to_be32(word);
		param->fqid = cpu_to_be32(info->l2_info.fqid);
	} else if (info->l2_info.no_tx_stats) {
		/* Counted at enqueue, before QMan rejects it: a dropped frame
		 * would read as one the port transmitted. No storage profile
		 * either, which is the rest of the word. */
		param->word = 0;
		param->fqid = cpu_to_be32(info->l2_info.fqid);
	} else {
#ifdef INCLUDE_ETHER_IFSTATS
		uint8_t offset;

		offset = info->l2_info.ether_stats_offset;
		word = ((get_logical_ifstats_base() +
			(offset * sizeof(struct en_ehash_stats))) & 0xffffff);
		param->word  = cpu_to_be32(word);
#ifdef CDX_DPA_DEBUG
		DPA_INFO("%s::stats ptr %x\n", __func__, (word & 0xffffff));
#endif

#else
		param->stats_ptr = 0;
#endif

		param->fqid = cpu_to_be32(info->l2_info.fqid);
	}

	param->hdr_xpnd_sz = info->tnl_hdr_size;
	seal_preemptive_checks_hm(info);
	*(info->opcptr) = ENQUEUE_PKT;
	info->opcptr++;
	info->param_size -= sizeof(struct en_ehash_enqueue_param);
	info->paramptr += sizeof(struct en_ehash_enqueue_param);
	return SUCCESS;
}

static int create_replicate_hm(struct ins_entry_info *info)
{
	struct en_ehash_replicate_param *param;

	if (info->opc_count == MAX_OPCODES)
		return FAILURE;
	if (sizeof(struct en_ehash_replicate_param) > info->param_size)
		return FAILURE;
	param = (struct en_ehash_replicate_param *)info->paramptr;
	param->first_member_flow_addr_hi = info->first_member_flow_addr_hi;
	param->first_member_flow_addr_lo = info->first_member_flow_addr_lo;
	param->first_listener_entry =  info->first_listener_entry;
	*(info->opcptr) = REPLICATE_PKT;
	info->opcptr++;
	info->param_size -= 8;
	info->paramptr += 8;
	return SUCCESS;
}

int fill_ipsec_actions(PSAEntry entry, struct ins_entry_info *info, 
			uint32_t sa_dir_in)
{
	uint32_t ii;
	uint32_t rebuild_l2_hdr = 0;

	if (sa_dir_in)
	{
		//strip vlan on ingress if incoming iface is vlan
		if (info->l2_info.vlan_present)
			info->flags |= VLAN_STRIP_HM_VALID;

		//strip pppoe on ingress if incoming iface is pppoe
		if (info->l2_info.pppoe_present)
			info->flags |= PPPoE_STRIP_HM_VALID;
	} else {
		//routing and ttl decr are mandatory
		info->flags = (TTL_HM_VALID);

		if (info->l2_info.num_egress_vlan_hdrs ) {
			info->flags |= VLAN_ADD_HM_VALID;
			for (ii = 0; ii < info->l2_info.num_egress_vlan_hdrs; ii++) {
				info->vlan_ids[ii] =
					(info->l2_info.egress_vlan_hdrs[ii].tci);
			}
		}

	}

	info->eth_type = (entry->family == PROTO_IPV4) ? (ETHERTYPE_IPV4) : (ETHERTYPE_IPV6);


	/*  Addition of IP header requires the header to be inserted at
	 * the start of the packet. So we need to strip and rebuild the
	 * l2 header after tunnel header insertion. */
	if (L2_L3_HDR_OPS(info))
		rebuild_l2_hdr = 1;

	if(!sa_dir_in) {
		if(rebuild_l2_hdr) { 
			/* strip Eth hdr */
			if (create_strip_eth_hm(info ))
				return FAILURE;
		}

		if (info->sec_tag && insert_remove_vlan_hm(info, 0, 0))
			return FAILURE;

		if (info->l3_info.add_tnl_header) {
			/* Insert Tnl header */
			if (create_tunnel_insert_hm(info)) 
				return FAILURE;
		}

		if (info->l2_info.add_pppoe_hdr)  {
			/* insert PPPoE header */
			if (create_pppoe_ins_hm(info))
				return FAILURE;
		}

		if (info->l2_info.num_egress_vlan_hdrs) {
			/* insert vlan header */
			if (create_vlan_ins_hm(info))
				return FAILURE;
		}

		/* insert Ethernet header */
		if(create_ethernet_hm(info, 1 ))
			return FAILURE;

	} 
	else {
		if(IS_NATT_SA(entry))
		{
			if (create_ipsec_preemptive_checks_hm(info, entry->id.spi))
			{
				DPA_ERROR("%s::unable to add ipsec preemptive checks\n",
						__func__);
				return FAILURE;
			}
		}

#ifdef INCLUDE_ETHER_IFSTATS
		/*update fast path ethernet stats for ESP packets
		TODO: underlying_iif_index needs to be taken care
		in sa_itf_id tunnel type cases*/
		if (create_eth_rx_stats_hm(info,info->sa_itf_id, 0)) {
			DPA_ERROR("%s::unable to add ethernet stats\n",
					__func__);
			return FAILURE;
		}
#endif

		/* strip Eth hdrs is called mandatorily to validate the vlan id's,
		   for vlan traffic receiving on non-vlan interface.
		   Also to strip the vlan header for vlan-0 packets received on non-vlan interface.*/
		if (insert_remove_l2_hm(info, info->sa_itf_id, 0 ))
			return FAILURE;

		if(IS_NATT_SA(entry))
		{
			if(create_enque_only_hm(info)) {
				DPA_ERROR("%s::unable to add enque hm\n",
						__func__);
				return FAILURE;
			}
			return SUCCESS;
		}

	}
	//enqueue
	if(create_enque_hm(info)) {
		DPA_ERROR("%s::unable to add enque hm\n",
				__func__);
		return FAILURE;
	}
	return SUCCESS;
}

/* Apply what a listener's copy owes to something other than its egress
 * interface to the description create_ethernet_hm() writes the header from.
 *
 * A copy's Ethernet pair -- the one a bridged copy's root matched, or a routed
 * copy's own, from the device ipmr sends it through -- replaces the egress
 * port's address and the group's mapped destination the interface walk filled
 * in. It is written over the walk's result rather than instead of the walk,
 * because the walk still decides the transmit queue and the tags. A routed
 * copy in a group whose root kept the hop count decrements it itself; see
 * fill_mcast_member_actions(). */
static void mcast_member_frame(struct ins_entry_info *info,
			       const struct cdx_mc_member_frame *frame)
{
	if (!frame)
		return;
	if (frame->mac_pair)
		memcpy(info->l2_info.l2hdr, frame->mac_pair, 2 * ETHER_ADDR_LEN);
	if (frame->hop)
		info->flags |= TTL_HM_VALID;
}

/* One copy's own hop-count decrement.
 *
 * The same opcode a routed root emits, emitted per copy instead: the root of
 * a group that also bridges preserves the hop count for its bridged copies,
 * so a routed copy in it has to take its hop off in its own entry. It runs
 * first, while the frame still starts at its IP header -- the root stripped
 * Ethernet and every insert below moves the start. The opcode's parameter is
 * also the DSCP marking a flow's conntrack mark can ask for, which a replica
 * has none of, so it is written zero, as a routed root without a mark writes
 * it. */
static int create_member_hop_hm(struct ins_entry_info *info)
{
	struct en_ehash_update_dscp *param;

	if (info->param_size < sizeof(*param))
		return FAILURE;
	if (insert_opcodeonly_hm(info, (info->flags & EHASH_IPV6_FLOW) ?
				 UPDATE_HOPLIMIT : UPDATE_TTL))
		return FAILURE;
	param = (struct en_ehash_update_dscp *)info->paramptr;
	param->dscp = 0;
	info->paramptr += sizeof(*param);
	info->param_size -= sizeof(*param);
	return SUCCESS;
}

/* Builds one listener's entry in a multicast group's replication chain.
 *
 * The scratch state is allocated here rather than supplied by the caller, and
 * that is load-bearing rather than tidiness. struct ins_entry_info carries the
 * write cursor into *one* entry's fixed opcode and parameter area -- opcptr,
 * paramptr, param_size and opc_count together -- so it describes the entry
 * being built and nothing that outlives it. Both mcast callers used to declare
 * one on the stack, memset it once, and hand the same pointer to every listener
 * in the group; three quarters of that cursor were then re-based per entry and
 * opc_count was not, so the opcode budget of a 16-slot area was shared across
 * every listener of the group. It never tripped, because each command that
 * built a group then named at most five listeners and came with a fresh
 * struct -- but the headroom was six opcodes and the accounting was wrong.
 *
 * Owning it here removes the class rather than the four instances of it:
 * tnl_hdr_size accumulates with +=, flags is only ever OR-ed, and preempt_params
 * would be left pointing into the previous listener's entry for any future path
 * that emitted a preemptive check. Every other entry builder in this file
 * already allocates its own; this was the only loop that did not.
 *
 * `encap` names the VLAN tags this listener's frames leave with, or is NULL to
 * take them from the egress interface. No VLAN interface is registered for a
 * tagged listener to walk, so the caller says what it wants instead -- the same
 * reasoning, and the same struct, as a flowtable direction's tag stack.
 *
 * The listener arrives already resolved, as an onif and the netdev whose MTU
 * the enqueue opcode carries: the caller holds a netdev and finds the onif by
 * index. `dev` is borrowed and the caller holds it across the call.
 *
 * `frame` is what the copy's framing owes to something other than its egress
 * interface; see struct cdx_mc_member_frame.
 */
struct en_exthash_tbl_entry* create_exthash_entry4mcast_member(RouteEntry *pRtEntry,
	POnifDesc onif_desc, struct net_device *dev, const struct cdx_l2_encap *encap,
	const struct cdx_mc_member_frame *frame,
	struct en_exthash_tbl_entry* prev_tbl_entry, uint32_t tbl_type,
	uint32_t discard_fqid)
{
	struct ins_entry_info *pInsEntryInfo;
	struct dpa_l2hdr_info *pL2Info;
	struct dpa_l3hdr_info *pL3Info;
	struct en_exthash_tbl_entry *tbl_entry = NULL;
	uint64_t phyaddr;
	uint16_t flags;
	uint8_t *ptr;

	if (!onif_desc || !onif_desc->itf || !dev)
		return NULL;

	pInsEntryInfo = kzalloc(sizeof(struct ins_entry_info), GFP_KERNEL);
	if (!pInsEntryInfo)
		return NULL;

	DPA_INFO("%s(%d) listener output device %s\n",__func__,__LINE__,dev->name);
	DPA_INFO("%s(%d) onif_desc->itf->index %d\n",__func__,__LINE__,onif_desc->itf->index);
	/* Into the struct's own fields, not into locals copied over afterwards:
	 * dpa_get_tdinfo() below reads fm_idx, and the copy used to happen ten
	 * lines later. Every entry therefore selected its table descriptor with
	 * the previous listener's FMAN index, or with zero on the first one.
	 * Invisible on a single-FMAN part and wrong on any other. */
	if(dpa_get_fm_port_index(onif_desc->itf->index, 0, &pInsEntryInfo->fm_idx,
				&pInsEntryInfo->port_idx, &pInsEntryInfo->port_id))
	{
		DPA_ERROR("%s::unable to get fmindex for itfid %d\n",__func__, onif_desc->itf->index);
		goto err_ret;
	}

	DPA_INFO("%s(%d) fm_idx %d, port_idx %d, port_id %d\n",__func__,__LINE__,
			pInsEntryInfo->fm_idx, pInsEntryInfo->port_idx, pInsEntryInfo->port_id);
	pInsEntryInfo->fm_pcd = dpa_get_pcdhandle(pInsEntryInfo->fm_idx);
	if (!pInsEntryInfo->fm_pcd)
	{
		DPA_ERROR("%s::unable to get fm_pcd_handle for fmindex %d\n",__func__,
				pInsEntryInfo->fm_idx);
		goto err_ret;
	}

	DPA_INFO("%s(%d) fm_pcd %p \n",__func__,__LINE__, pInsEntryInfo->fm_pcd);
	//get table descriptor based on type and port
	pInsEntryInfo->td = dpa_get_tdinfo(pInsEntryInfo->fm_idx, pInsEntryInfo->port_id, tbl_type);
	if (pInsEntryInfo->td == NULL) {
		DPA_ERROR("%s::unable to get td for itfid %d, type %d\n",
				__func__, onif_desc->itf->index,tbl_type);
		goto err_ret;
	}
	DPA_INFO("%s(%d) td %p \n",__func__,__LINE__, pInsEntryInfo->td);

	//Code to create hm for mcast single member

	pL2Info = &pInsEntryInfo->l2_info;
	pL3Info = &pInsEntryInfo->l3_info;


	//Code to get Tx fqid of given interface

	pRtEntry->itf = onif_desc->itf;
	pRtEntry->input_itf = onif_desc->itf;
	pRtEntry->underlying_input_itf =  pRtEntry->input_itf;

	//Using default queue for multicast packets
	{
		union ctentry_qosmark qosmark;

		qosmark.markval = 0;
		if (dpa_get_tx_info_by_itf(pRtEntry, pL2Info, pL3Info, &qosmark, 0))
		{
			DPA_ERROR("%s::unable to get tx params\n",__func__);
			goto err_ret;
		}
	}
	DPA_INFO("dpa_get_tx_info_by_itf success\n");
	/* After the interface walk, which is what apply_l2_encap() refuses to
	 * overwrite: a listener either names its tags or is described by an
	 * interface that carries them, never both. */
	if (encap && apply_l2_encap(pInsEntryInfo, encap))
		goto err_ret;
	mcast_member_frame(pInsEntryInfo, frame);
	pL2Info->mtu = dev->mtu;
	/* A discard member: the entry a listener's would be, built on the
	 * group's own ingress port, enqueueing to the discard queue instead of
	 * the port's. No frame of any size is excepted to the CPU, which is what
	 * the member exists to spare, and the DSCP map, which picks a queue of
	 * the port's, stays out of it. */
	if (discard_fqid) {
		pL2Info->fqid = discard_fqid;
		pL2Info->is_dscp_fq_map = 0;
		pL2Info->mtu = 0xffff;
		pL2Info->no_tx_stats = 1;
	}
#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s:: mtu %d\n", __func__, dev->mtu);
#endif

	//allocate hash table entry
	tbl_entry = ExternalHashTableAllocEntry(pInsEntryInfo->td);
	if (!tbl_entry) {
		DPA_ERROR("%s::unable to alloc hash tbl memory\n",__func__);
		goto err_ret;
	}

	//#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s:: hash tbl entry %p\n", __func__, tbl_entry);
	//#endif
	flags = 0;
	//round off keysize to next 4 bytes boundary 
	ptr = (uint8_t *)&tbl_entry->hashentry.key[0];			
	//set start of opcode list 
	pInsEntryInfo->opcptr = ptr;
	//ptr now after opcode section
	ptr += MAX_OPCODES;

	//set offset to first opcode
	SET_OPC_OFFSET(flags, (uint32_t)(pInsEntryInfo->opcptr - (uint8_t *)tbl_entry));
	//set param offset 
	SET_PARAM_OFFSET(flags, (uint32_t)(ptr - (uint8_t *)tbl_entry));
	//param_ptr now points after timestamp location
	tbl_entry->hashentry.flags = cpu_to_be16(flags);
	//param pointer and opcode pointer now valid
	pInsEntryInfo->paramptr = ptr;
	pInsEntryInfo->param_size = (MAX_EN_EHASH_ENTRY_SIZE -
			GET_PARAM_OFFSET(flags));
	/* The family is the table's, and a bridged group's listeners come from
	 * the bridged tables: the rebuilt header's EtherType is chosen by it. */
	if (tbl_type == IPV6_MULTICAST_TABLE ||
	    tbl_type == IPV6_BRIDGED_MULTICAST_TABLE)
		pInsEntryInfo->flags |= EHASH_IPV6_FLOW;

	if (fill_mcast_member_actions(pRtEntry, pInsEntryInfo)) {
		DPA_ERROR("%s::unable to fill actions\n", __func__);
		goto err_ret;
	}
#ifdef CDX_DPA_DEBUG
	display_ehash_tbl_entry(&tbl_entry->hashentry, 0);
#endif // CDX_DPA_DEBUG
	phyaddr = XX_VirtToPhys(tbl_entry);
	//fill next pointer info and link into chain
	if (prev_tbl_entry)
	{
		prev_tbl_entry->next = tbl_entry;
		tbl_entry->prev = prev_tbl_entry;
		//adjust the prev pointer in the old entry
		//fill next pointer physaddr for uCode
		prev_tbl_entry->hashentry.next_entry_hi = cpu_to_be16((phyaddr >> 32) & 0xffff);
		prev_tbl_entry->hashentry.next_entry_lo = cpu_to_be32((phyaddr & 0xffffffff));
	}
	kfree(pInsEntryInfo);
	return tbl_entry;
err_ret:
	kfree(pInsEntryInfo);
	if (tbl_entry)
		ExternalHashTableEntryFree(tbl_entry);
	return NULL;
}

static int fill_mcast_member_actions(RouteEntry *pRtEntry, struct ins_entry_info *info)
{
	uint32_t ii; 
	uint32_t rebuild_l2_hdr = 0;
	//POnifDesc onif_desc;


#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s:: entry %p, opc_ptr %p, param_ptr %p, size %d\n", 
			__func__, pRtEntry, info->opcptr, info->paramptr, info->param_size);
#endif

	/*  Addition of IP header requires the header to be inserted at the start of the packet.
			So we need to strip and rebuild the l2 header after tunnel header insertion. */
	rebuild_l2_hdr = 1;
	//		info->l2_info.add_eth_type = 1;
	if(info->flags & EHASH_IPV6_FLOW)
		info->eth_type = ETHERTYPE_IPV6;
	else
		info->eth_type = ETHERTYPE_IPV4;

	DPA_INFO("%s(%d) rebuild_l2_hdr  %d\n",__func__,__LINE__,rebuild_l2_hdr);
	if (info->l2_info.num_egress_vlan_hdrs) {
		DPA_INFO("%s(%d) num egress vlan hdrs %d\n",
				__func__,__LINE__, info->l2_info.num_egress_vlan_hdrs);
		info->flags |= VLAN_ADD_HM_VALID;
		for (ii = 0; ii < info->l2_info.num_egress_vlan_hdrs; ii++) {
			info->vlan_ids[ii] =
				(info->l2_info.egress_vlan_hdrs[ii].tci);
		}
	}
	//fill all opcodes and parameters
	while(1) {
		/* A routed copy of a group whose root kept the hop count. */
		if ((info->flags & TTL_HM_VALID) && create_member_hop_hm(info))
			break;

		if (info->l3_info.add_tnl_header) {
			/* Insert Tnl header */
			if (create_tunnel_insert_hm(info))
				break;
		}

		if (info->l2_info.add_pppoe_hdr)  {
			/* insert PPPoE header */
			if (create_pppoe_ins_hm(info))
				break;
		}

		if (info->l2_info.num_egress_vlan_hdrs) {
			/* insert vlan header */
			if (create_vlan_ins_hm(info))
				break;
		}


		/* insert Ethernet header */
		if(create_ethernet_hm(info, rebuild_l2_hdr))
			return FAILURE;

		/* enqueue Packet */
		if(create_enque_hm(info))
			break;
		DPA_INFO("%s(%d) create_enque_hm\n",__func__,__LINE__);

		return SUCCESS;
	}
	return FAILURE;
}

int cdx_init_frag_procfs(void);


int cdx_init_frag_module(void)
{
	int ret;
	uint16_t frag_options;
	t_Handle h_FmMuram;
	uint64_t physicalMuramBase;
	uint32_t MuramSize;
	cdx_ucode_frag_info_t  *ucode_frag_args;


#ifdef CDX_FRAG_USE_BUFF_POOL
	ret = cdx_create_fragment_bufpool();
	if (ret)
	{
		DPA_ERROR("%s(%d) create_fragment_bufpool failed\n",__func__,__LINE__);
		return -1;
	}
	frag_options = BPID_ENABLE;
#endif //CDX_FRAG_USE_BUFF_POOL

	h_FmMuram = dpa_get_fm_MURAM_handle(0, &physicalMuramBase, &MuramSize);
	if (!h_FmMuram)
	{
		DPA_ERROR("%s(%d) Error in getting MURAM handle\n", __func__,__LINE__);
#ifdef CDX_FRAG_USE_BUFF_POOL
		cdx_deinit_fragment_bufpool();
#endif //CDX_FRAG_USE_BUFF_POOL
		return -1;
	}

	dscp_fq_map_ff_g.muram_addr = (cdx_muram_memory_cmn_db_t *)FM_MURAM_AllocMem(h_FmMuram, 
					sizeof(cdx_muram_memory_cmn_db_t), 32);
	if (!dscp_fq_map_ff_g.muram_addr)
	{
#ifdef CDX_FRAG_USE_BUFF_POOL
		cdx_deinit_fragment_bufpool();
#endif /*CDX_FRAG_USE_BUFF_POOL*/
		return -1;
	}
	frag_info_g.muram_frag_params = (cdx_ucode_frag_info_t *)dscp_fq_map_ff_g.muram_addr;
	dscp_fq_map_ff_g.port_id = NO_PORT;
	if ((ucode_frag_args = kmalloc(sizeof(cdx_ucode_frag_info_t), GFP_KERNEL)) == NULL)
	{
		DPA_ERROR("%s(%d) Failed to allocate memory:\n", __func__, __LINE__);
		FM_MURAM_FreeMem(h_FmMuram, (void *)dscp_fq_map_ff_g.muram_addr);
		dscp_fq_map_ff_g.muram_addr = NULL;
		frag_info_g.muram_frag_params = NULL;
#ifdef CDX_FRAG_USE_BUFF_POOL
		cdx_deinit_fragment_bufpool();
#endif /* CDX_FRAG_USE_BUFF_POOL */
		return -1;
	}

	ucode_frag_args->alloc_buff_failures = 0;
	ucode_frag_args->v4_frames_counter = 0;
	ucode_frag_args->v6_frames_counter = 0;
	ucode_frag_args->v6_frags_counter = 0;
	ucode_frag_args->v4_frags_counter = 0;
	ucode_frag_args->v6_identification = cpu_to_be32(1);
	frag_options |= OPT_COUNTER_EN;
	ucode_frag_args->frag_options = cpu_to_be16(frag_options); 

	copy_ddr_to_muram_and_free_ddr((void *)frag_info_g.muram_frag_params, (void **)&ucode_frag_args, sizeof(cdx_ucode_frag_info_t));

	cdx_init_frag_procfs();
	register_cdx_deinit_func(cdx_deinit_frag_module);
	return 0;
}

#define PROC_FRAG_DIR "ucode_frag"

static struct proc_dir_entry *frag_proc_dir, *stats_file, *alloc_free_test_file;

static int frag_stats_show(struct seq_file *m, void *v)
{
	cdx_ucode_frag_info_t  *ucode_frag_args;

	if (!frag_info_g.muram_frag_params) {
		seq_puts(m, "fragmentation module not initialized\n");
		return 0;
	}

	if (!create_ddr_and_copy_from_muram((void *)frag_info_g.muram_frag_params, (void **)&ucode_frag_args, sizeof(cdx_ucode_frag_info_t)))
		return -ENOMEM;

	seq_printf(m, "IPv4 frames received : %u\n", be32_to_cpu(ucode_frag_args->v4_frames_counter));
	seq_printf(m, "IPv6 frames received : %u\n", be32_to_cpu(ucode_frag_args->v6_frames_counter));
	seq_printf(m, "Number of IPv4 fragments sent : %u\n", be32_to_cpu(ucode_frag_args->v4_frags_counter));
	seq_printf(m, "Number of IPv6 fragments sent : %u\n", be32_to_cpu(ucode_frag_args->v6_frags_counter));
	seq_printf(m, "Failures in allocating buffers: %u\n", be32_to_cpu(ucode_frag_args->alloc_buff_failures));

	kfree(ucode_frag_args);
	return 0;
}

static int frag_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, frag_stats_show, NULL);
}

static const struct proc_ops frag_stats_fp = {
	.proc_open	= frag_stats_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static int buff_alloc_test_show(struct seq_file *m, void *v)
{
	int ii, acquired = 0;
	struct bm_buffer bmb[128];

	if (!frag_info_g.frag_bufpool) {
		seq_puts(m, "fragment buffer pool not initialized\n");
		return 0;
	}

	for (ii =0; ii< 128; ii++)
	{
		if (bman_acquire(frag_info_g.frag_bufpool->pool, &bmb[ii], 1, 0) != 1) {
			DPA_INFO("%s(%d) bman_acquire failed \n", __func__,__LINE__);
			bmb[ii].addr = 0;
		}
		else
		{
			DPA_INFO("%s(%d) bman_acquire success (ii %d) ,%lx \n",
					__func__,__LINE__,ii,(long unsigned int)bmb[ii].opaque);
			acquired++;
		}
	}
	for (ii =0; ii< 128; ii++)
	{
		if (bmb[ii].addr) {
			if (bman_release(frag_info_g.frag_bufpool->pool, &bmb[ii], 1, 0))
				DPA_ERROR("%s::bman release failed\n", __func__);
		}
	}
	seq_printf(m, "%d of 128 buffers allocated and freed\n", acquired);
	return 0;
}

static int buff_alloc_test_open(struct inode *inode, struct file *file)
{
	return single_open(file, buff_alloc_test_show, NULL);
}

static const struct proc_ops buf_alloc_test_fp = {
	.proc_open	= buff_alloc_test_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static void cdx_deinit_frag_procfs(void)
{
	proc_remove(frag_proc_dir);
	frag_proc_dir = NULL;
	stats_file = NULL;
	alloc_free_test_file = NULL;
}

int cdx_init_frag_procfs(void)
{
	frag_proc_dir = proc_mkdir(PROC_FRAG_DIR, NULL);
	if (!frag_proc_dir)
	{
		DPA_INFO("%s(%d) proc_mkdir failed \n",__func__,__LINE__);
		return -1;
	}

	stats_file = proc_create("stats", 0444, frag_proc_dir, &frag_stats_fp);
	if (!stats_file)
	{
		DPA_INFO("%s(%d) proc_create failed\n",__func__,__LINE__);
		goto err_remove;
	}

	/* Exercises 128 bman acquire/release cycles per read - root only */
	alloc_free_test_file = proc_create("test_alloc_buf_n_free", 0400, frag_proc_dir, &buf_alloc_test_fp);
	if (!alloc_free_test_file)
	{
		DPA_INFO("%s(%d) proc_create failed\n",__func__,__LINE__);
		goto err_remove;
	}

	return 0;

err_remove:
	cdx_deinit_frag_procfs();
	return -1;
}

void cdx_deinit_frag_module(void)
{
	t_Handle h_FmMuram;
	uint64_t physicalMuramBase;
	uint32_t MuramSize;

	/* remove the proc entries first; proc_remove waits out in-flight
	 * readers, so nothing can touch the bufpool/MURAM state torn down
	 * below (or run this module's text after unload) */
	cdx_deinit_frag_procfs();
#ifdef CDX_FRAG_USE_BUFF_POOL
	cdx_deinit_fragment_bufpool();
#endif //CDX_FRAG_USE_BUFF_POOL
	h_FmMuram = dpa_get_fm_MURAM_handle(0, &physicalMuramBase, &MuramSize);
	if (!h_FmMuram)
	{
		DPA_ERROR("%s(%d) Error in getting MURAM handle\n", __func__,__LINE__);
		return;
	}
	FM_MURAM_FreeMem(h_FmMuram, (void *)dscp_fq_map_ff_g.muram_addr);
	dscp_fq_map_ff_g.muram_addr = NULL;
	frag_info_g.muram_frag_params = NULL;
	return;
}

static int cdx_create_fragment_bufpool(void)
{
	struct dpa_bp *bp, *bp_parent;
	int buffer_count = 0, ret = 0, refill_cnt ;

	bp = kzalloc(sizeof(struct dpa_bp), GFP_KERNEL);
	if (unlikely(bp == NULL)) {
		DPA_ERROR("%s::failed to allocate mem for bman pool \n",
				__func__);
		return -1;
	}

	bp->size = CDX_FRAG_BUFF_SIZE;
	bp->config_count = CDX_FRAG_BUFFERS_CNT;

	//find pools used by ethernet devices and borrow buffers from it
	if (get_phys_port_poolinfo_bysize(CDX_FRAG_BUFF_SIZE, &frag_info_g.parent_pool_info)) {
		DPA_ERROR("%s::failed to locate eth bman pool\n",
				__func__);
		/* bp->pool is still NULL here (pool is created by dpa_bp_alloc
		 * below) and bman_free_pool derefs its argument */
		kfree(bp);
		return -1;
	}

	bp_parent = dpa_bpid2pool(frag_info_g.parent_pool_info.pool_id);
	bp->dev = bp_parent->dev;
	if (dpa_bp_alloc(bp, bp->dev)) {
		DPA_ERROR("%s::dpa_bp_alloc failed\n",
				__func__);
		kfree(bp);
		return -1;
	}
	DPA_INFO("%s::bp->size :%zu, bpid %d\n", __func__, bp->size, bp->bpid);


	frag_info_g.frag_bufpool = bp;
	frag_info_g.frag_bp_id = bp->bpid;

	while (buffer_count < CDX_FRAG_BUFFERS_CNT)
	{
		refill_cnt = 0;
		ret = dpaa_eth_refill_bpools(bp, &refill_cnt,
			CONFIG_FSL_DPAA_ETH_REFILL_THRESHOLD);
		if (ret < 0)
		{
			DPA_ERROR("%s:: Error returned for dpaa_eth_refill_bpools %d\n", __func__,ret);
			break;
		}

		buffer_count += refill_cnt;
	}
	bp->config_count = buffer_count;

	DPA_INFO("%s::buffers_allocated %d\n", __func__,bp->config_count);
	return 0;
}

void cdx_deinit_fragment_bufpool()
{
	if (frag_info_g.frag_bufpool)
	{
		drain_tx_bp_pool(frag_info_g.frag_bufpool);
		frag_info_g.frag_bufpool = NULL;
		frag_info_g.frag_bp_id = 0;
	}
	return;
}
