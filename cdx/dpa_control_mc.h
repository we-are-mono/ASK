/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */
#ifndef _DPA_CONTROL_MC_H_
#define _DPA_CONTROL_MC_H_

/* Defined in control_ipv4.h, which this header deliberately does not pull in:
 * the tag stack crosses the interface as a pointer and nothing here reads it. */
struct cdx_l2_encap;

#define MC4_NUM_HASH_ENTRIES 16
#define MC6_NUM_HASH_ENTRIES 16
#define MC_MAX_LISTENERS_PER_GROUP 8

struct mcast_group_member
{
  int member_id;
  char if_info[IF_NAME_SIZE];
  char bIsValidEntry;
  void *tbl_entry;
} ;

struct mcast_group_info
{
  struct list_head list;
  union
  {
    struct
    {
      uint32_t ipv4_saddr;     //ipv4 source addr
      uint32_t ipv4_daddr;     //ipv4 dest addr
    };
    struct
    {
      uint32_t ipv6_saddr[4];  //ipv6 src addr
      uint32_t ipv6_daddr[4];  //ipv6 dest addr
    };
  };
  int grpid;
  unsigned int uiListenerCnt;
  struct mcast_group_member members[MC_MAX_LISTENERS_PER_GROUP];
  struct _tCtEntry *pCtEntry;
  char ucIngressIface[IF_NAME_SIZE];
  /* The ingress device.
   *
   * A group installed through cdx_mcast_backend.h is identified by its ports,
   * which the caller pins for the group's life, so it is keyed on the device
   * itself -- and must be: nothing in cdx handles NETDEV_CHANGENAME, so a
   * renamed ingress would otherwise stop matching its own group and freeze its
   * listener set forever. ucIngressIface is only for the log. */
  struct net_device *in_dev;
  uint8_t mctype;
  bool bridged;
  /* Both set only for a group that describes the frame it arrives as; one
   * that leaves them zero gets its routed root.
   *
   * `mac_keyed`: the root is keyed on `mac_pair` -- destination then source,
   * the frame's own -- in the bridged multicast table, and every bridged
   * copy rebuilds Ethernet with that pair. `in_vlan` is the tag stack the root
   * validates and strips, innermost first as struct cdx_l2_encap orders it. */
  bool mac_keyed;
  uint8_t mac_pair[2 * ETHER_ADDR_LEN];
  uint8_t in_vlans;
  struct vlan_header in_vlan[DPA_CLS_HM_MAX_VLANs];
};

int insert_mcast_entry_in_classif_table(struct _tCtEntry *pCtEntry,
		unsigned int num_members, uint64_t first_member_flow_addr,
						void *first_listener_entry, bool bridged,
						const uint8_t *mac_pair,
						const struct cdx_l2_encap *in_encap);
void *dpa_get_pcdhandle(uint32_t fm_index);
int dpa_get_tx_info_by_itf(PRouteEntry rt_entry, struct dpa_l2hdr_info *l2_info,
		struct dpa_l3hdr_info *l3_info, void *queinfo, uint32_t hash);
void AddToMcastGrpList(struct mcast_group_info *pMcastGrpInfo);
/* Clears the references the multicast group routes hold on an interface that
 * is being removed; remove_onif_by_index() calls it. Process context only. */
void cdx_mcast_clear_itf_refs(U32 if_index);
extern struct list_head mc4_grp_list[MC4_NUM_HASH_ENTRIES];
extern struct list_head mc6_grp_list[MC6_NUM_HASH_ENTRIES];
extern spinlock_t *mc4_spinlocks;
extern spinlock_t *mc6_spinlocks;

/* How one listener's copy is framed beyond what its egress interface and tags
 * give it.
 *
 * `mac_pair` is the destination and source the copy is written with, in the
 * order the header carries them, over the header the interface walk filled
 * in. A bridged copy's is the pair its root matched, written back verbatim: a
 * bridge forwards a frame with the addresses it arrived with, and the root is
 * keyed on this pair precisely so that the listener can know them. A routed
 * copy's is the group's mapped address and the address of the device ipmr
 * sends it through, which is the port's own only when that device is the
 * port. NULL leaves the walk's header: the egress port's own address to the
 * group's mapped one, which the group interface never asks for.
 *
 * `hop` is a routed copy's in a group whose root preserves the hop count for
 * its bridged copies: the entry decrements it itself, ahead of its header
 * inserts, where a routed root would have for every copy. */
struct cdx_mc_member_frame {
	const uint8_t *mac_pair;
	bool hop;
};

/* Builds one listener's entry. The listener is already resolved -- an onif and
 * the netdev whose MTU the enqueue carries, borrowed for the call. `encap`
 * names the tags this listener's frames leave with, or is NULL to take them
 * from the egress interface. The scratch state is the builder's own; see the
 * definition for why that is not merely tidiness. */
struct en_exthash_tbl_entry* create_exthash_entry4mcast_member(RouteEntry *pRtEntry,
	POnifDesc onif_desc, struct net_device *dev, const struct cdx_l2_encap *encap,
	const struct cdx_mc_member_frame *frame,
	struct en_exthash_tbl_entry* prev_tbl_entry, uint32_t tbl_type);

/* Module init/exit functions */
int mc4_init(void);
int mc6_init(void);
void mc4_exit(void);
void mc6_exit(void);

#ifdef CDX_DEBUG_MC_HCSYNC_FAIL
/* HC-sync fault-injection knob - see dpa_control_mc.c for the design
 * rationale. Both functions exist only when CDX_DEBUG_MC_HCSYNC_FAIL is
 * defined; the meta-ask test image sets it via CFG_FLAGS, production
 * builds do not.
 */
int  cdx_mc_init_hcsync_fail_probe(void);
void cdx_mc_remove_hcsync_fail_probe(void);
#endif

static inline u32 HASH_MC4(u32 destaddr)  // pass in IPv4 dest addr
{
  u32 hash;
  destaddr = ntohl(destaddr);
  hash = destaddr + (destaddr >> 16);
  hash = hash ^ (hash >> 4) ^ (hash >> 8) ^ (hash >> 12);
  return hash & (MC4_NUM_HASH_ENTRIES - 1);
}

static inline u32 HASH_MC6(void *pdestaddr)  // pass in ptr to IPv6 dest addr
{
  u16 *p = (u16 *)pdestaddr;
  u32 hash;
  hash = ntohs(p[4]) + ntohs(p[5]) + ntohs(p[6]) + ntohs(p[7]);
  hash = hash ^ (hash >> 4) ^ (hash >> 8) ^ (hash >> 12);
  return hash & (MC6_NUM_HASH_ENTRIES - 1);
}

#endif /* _DPA_CONTROL_MC_H_ */
