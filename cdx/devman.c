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
 * @file                devman.c     
 * @description         device management routines.
 */

#include <linux/module.h>
#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/fsl_qman.h>
#include <linux/fsl_bman.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <net/if_inet6.h>
#include <uapi/linux/in6.h> 
#include <linux/spinlock.h>
#include <linux/if_arp.h>
#include "fm_vsp_ext.h"
#include "fm_port_ext.h"
#include "lnxwrp_fm.h"
#include <linux/fsl_oh_port.h>
#include "dpaa_eth.h"
#include "dpaa_eth_common.h"
#include "fm_ehash.h"
#include "portdefs.h"
#include "layer2.h"
#include "cdx_ioctl.h"
#include "misc.h"
#include "mac.h"
#include "cdx.h"
#include "cdx_common.h"
#include "module_qm.h"
#include "fe.h"
#include "control_tunnel.h"
#include "control_ipv6.h"
#include "endian_ext.h" 
#include "dpa_control_mc.h"
#include "dpa_wifi.h"
#include "cdx_ceetm_gdef.h" 
#include "cdx_defs.h"
#include "devman.h"
#include "control_tx.h"
#include "procfs.h"
#include "cdx_flowtable_hw.h"

//#define DEVMAN_DEBUG	1

#define NULL_MAC_ADDR(mac) (mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5] )


/*
 * Concurrency:
 *   dpa_devlist_lock (spinlock, exported)
 *      - Guards the dpa_interface_info singly-linked list of
 *        registered interfaces, plus their eth/wlan/oh
 *        sub-structures in place. Taken by readers (e.g.
 *        dpa_get_ifinfo_by_itfid callers, virt_iface_stats_callback)
 *        and writers (interface add/remove) alike. All takers run
 *        in process context (the flowtable transaction /
 *        dev_get_stats), which is why plain spin_lock() is
 *        sufficient — there are no softirq takers; do not add one
 *        without switching the discipline to _bh.
 *        Serialization invariant (remove-side): every UNLINK/FREE
 *        of a live node holds the ctrl mutex
 *        (dpa_release_interface runs from remove_onif_by_index,
 *        whose callers are the Wi-Fi VAP backend, inside the
 *        flowtable transaction, and the deinit-path tx_exit, under
 *        the same mutex via cdx_ctrl_deinit). ADDS are not all
 *        mutex-covered — the boot-time set_dpa_params injection
 *        ioctl publishes fresh nodes under dpa_cfg_lock only — but
 *        fresh-node publication can't invalidate a reader. The
 *        spinlock covers readers outside the mutex
 *        (virt_iface_stats_callback via dev_get_stats) and any
 *        reader that wants local invariants. Lock-free lookups
 *        under the mutex lean on the remove-side invariant; see
 *        dpa_get_iface_stats_entries. The lock-free walkers that
 *        run outside it (dpa_get_ohifinfo_by_portid,
 *        cdx_copy_eth_rx_channel_info) take the spinlock.
 *        The boot injection ioctl (set_dpa_params) adds entries
 *        outside the ctrl mutex, but it runs exactly once,
 *        synchronously inside cdx module init (dpa_app via
 *        UMH_WAIT_PROC, re-runs rejected with -EBUSY) — before the
 *        flowtable adapter can load — so injection adds cannot
 *        overlap a transaction. (The ctrl timer thread does run
 *        during injection, under ctrl->mutex, but its handlers
 *        touch only the then-empty SA table, not this list.) The
 *        u8 iface counters are therefore mutator-serialized in
 *        every reachable schedule.
 *   dpa_interface_info (file-scope head pointer)
 *      - Protected by dpa_devlist_lock.
 *
 * Cross-file users:
 *   dpa_devlist_lock is the innermost lock its takers hold. The one
 *   lock taken inside it is cdx_ifstats.c's dpa_statslist_lock, by
 *   virt_iface_stats_callback reading a record; nothing holding
 *   that lock takes this one.
 *
 * Contexts:
 *   dpa_add_*, dpa_remove_*    - process, ioctl configuration.
 *   dpa_get_ifinfo_by_itfid    - any context (stats callbacks).
 *   get_eth_iface_info         - process, ioctl.
 */
DEFINE_SPINLOCK(dpa_devlist_lock);
struct dpa_iface_info *dpa_interface_info;

static int dpa_get_tx_fqid_devinfo_by_iface(struct dpa_iface_info *iface_info,
		uint32_t *fqid, uint8_t *is_dscp_fq_map, uint32_t *portid, uint32_t hash);

extern struct net init_net;
extern int fm_port_get_hwid(const struct fm_port *port);


struct dpa_iface_info *dpa_get_phys_iface(struct dpa_iface_info *iface_info);

/*count for registered interfaces.*/
uint8_t iface_count;
#define PORTID_SHIFT_VAL	8


static enum qman_cb_dqrr_result fwd_tx_drain_dqrr(struct qman_portal *portal,
		struct qman_fq *fq, const struct qm_dqrr_entry *dq)
{
	/* These FQs carry pool-backed forwarding frames normally freed by
	 * FMan (EBD). Retirement returns any unsent frames to software.
	 * No interface or NAPI state is needed to return them to BMan.
	 */
	if (dq->stat & QM_DQRR_STAT_FD_VALID)
		dpa_fd_release(NULL, &dq->fd);
	return qman_cb_dqrr_consume;
}

//create frame queues for the port used to transmit packets from ENQ action
static int create_fwd_tx_fqs(struct dpa_iface_info *iface_info)
{
	struct eth_iface_info *eth_info = &(iface_info->eth_info);
	struct qman_fq *fq;
	struct qm_mcc_initfq opts;
	uint32_t ii, created = 0;

	fq = &eth_info->fwd_tx_fqinfo[0];
	for (ii = 0; ii < DPAA_FWD_TX_QUEUES; ii++) {
		memset(fq, 0, sizeof(struct qman_fq));
		fq->cb.dqrr = fwd_tx_drain_dqrr;
		//FQ for egress
		if (qman_create_fq(0, 
					(QMAN_FQ_FLAG_DYNAMIC_FQID | QMAN_FQ_FLAG_TO_DCPORTAL),
					fq)) {
			DPA_ERROR("%s::unable to create fq at index %d\n",
					__func__, ii);
			goto err_ret;
		}
		memset(&opts, 0, sizeof(struct qm_mcc_initfq));
		opts.fqid = fq->fqid;
		opts.count = 1;
		opts.we_mask = (QM_INITFQ_WE_FQCTRL | QM_INITFQ_WE_DESTWQ |
				QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA);
		opts.fqd.fq_ctrl = QM_FQCTRL_PREFERINCACHE;
		opts.fqd.dest.channel = eth_info->tx_channel_id;
		opts.fqd.dest.wq = eth_info->tx_wq;
		//OVFQ=1 - override FQ in tree
		//A2V=1 - contextA A2 field is valid
		//A0V=1 - contextA A0 field is valid
		//B0V=0 - contextB field is not valid
		//OVOM=1 - use contextA2 bits instead of ICAD
		//EBD=1 - deallocate buffers inside FMan

		opts.fqd.context_a.hi = 0x9a000000; 
		opts.fqd.context_a.lo = 0xC0000000;
		if (qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts)) {
			DPA_ERROR("%s::qman_init_fq failed for fqid %d\n",
					__func__, fq->fqid);
			qman_destroy_fq(fq, 0);
			goto err_ret;
		}
		/* creating /proc/fqid_stats dir for listing fqids */
		cdx_create_type_fqid_info_in_procfs(fq, TX_DIR, iface_info->tx_proc_entry, NULL);
		created++;
		if (cdx_dpa_init_fault())
			goto err_ret;
#ifdef DEVMAN_DEBUG
		DPA_INFO("%s::created fq 0x%x chnl id 0x%x\n", 
				__func__, fq->fqid, eth_info->tx_channel_id);
#endif
		fq++;
	}
	return 0;

err_ret:
	while (created)
		cdx_destroy_fq(&eth_info->fwd_tx_fqinfo[--created]);
	return FAILURE;
}

static void cdx_drain_fq(struct qman_fq *fq);

static void destroy_fwd_tx_fqs(struct dpa_iface_info *iface_info)
{
	struct eth_iface_info *eth_info = &(iface_info->eth_info);
	struct qman_fq *fq;
	uint32_t ii;

	/* Keep the embedded FQs alive through asynchronous retirement and
	 * the final callbacks before the caller frees the interface. */
	for (ii = 0; ii < DPAA_FWD_TX_QUEUES; ii++)
		cdx_drain_fq(&eth_info->fwd_tx_fqinfo[ii]);
	synchronize_net();

	fq = &eth_info->fwd_tx_fqinfo[0];
	for (ii = 0; ii < DPAA_FWD_TX_QUEUES; ii++) {
		cdx_remove_fqid_info_in_procfs(fq->fqid);
		qman_destroy_fq(fq, 0);
#ifdef DEVMAN_DEBUG
		DPA_INFO("%s::created fq 0x%x chnl id 0x%x\n", 
				__func__, fq->fqid, eth_info->tx_channel_id);
#endif
		fq++;
	}
}

struct net_device *find_osdev_by_fman_params(uint32_t fm_idx, uint32_t port_idx,
		uint32_t speed)
{
	struct net_device *device;
	struct dpa_priv_s *priv;	
	struct mac_device *macdev;

	device = first_net_device(&init_net);
	while(1) {
		if (!device) 
			break;
		/* Every Ethernet-framed device, bridges and VLAN devices
		 * included, but only a DPAA port's private area is a
		 * dpa_priv_s with a MAC behind it. */
		if (device->type == ARPHRD_ETHER && dpa_netdev_is_dpaa(device)) {
			t_LnxWrpFmDev *p_LnxWrpFmDev;
			priv = netdev_priv(device);
			macdev = priv->mac_dev;
			if (macdev) {
				p_LnxWrpFmDev = (t_LnxWrpFmDev*)macdev->fm;
				if (speed == 10) {
					//10 gig interfaces upports only SUPPORTED_10000baseT_Full
					/*DGW board has 2 fixed-link interfaces 
						1 - (eth2)(xDSL)1G Fixed link interface linked to rgmii-txid
						2 - eth5(G.fast)- 1G Fixed link interface linked to sgmii and
						connected to 10G link of the board.
						sgmii - considered as 1000baseT_Full and this has cell_index = 0*/

					if ( (!macdev->fixed_link) && (macdev->if_support != SUPPORTED_10000baseT_Full) )
						goto next_device; 
				}
				if ((fm_idx == p_LnxWrpFmDev->id) && 
						(port_idx == macdev->cell_index))
					return device;
			}
		}
next_device:
		device = next_net_device(device);
	}
	return device;
}


//get interface information from OS device priv structure
static int get_eth_iface_info(struct dpa_iface_info *iface_info,
		char *name)
{
	struct net_device *device;
	struct eth_iface_info *eth_info;
	struct dpa_priv_s *priv;
	struct dpa_fq *dpa_fq;
	struct dpa_fq *tmp;
	struct dpa_bp *bp;
	int ii;

	device = dev_get_by_name(&init_net, name);	
	if (!device) {
		DPA_ERROR("%s::could not find device %s\n", __func__, name);
		return FAILURE;
	}
	/* Every later reading of this port's netdev_priv() -- queue
	 * resolution, statistics, teardown -- relies on this record naming a
	 * DPAA port, so a device of another driver by that name is refused
	 * here, once. */
	if (!dpa_netdev_is_dpaa(device)) {
		DPA_ERROR("%s::%s is not a DPAA Ethernet port\n", __func__, name);
		dev_put(device);
		return FAILURE;
	}
	priv = netdev_priv(device);
	//set as ethernet interface
	iface_info->if_flags = (IF_TYPE_ETHERNET | IF_TYPE_PHYSICAL);
	//copy name
	strncpy(iface_info->name, name, IF_NAME_SIZE);
	iface_info->name[IF_NAME_SIZE - 1] = '\0';
	//iface mtu
	iface_info->mtu = device->mtu;
	//os interface id
	iface_info->osid = device->ifindex;
	eth_info = &iface_info->eth_info;
	/* Save the netdev. It is the source of this port's hardware address
	 * too, read where the header is encoded rather than copied here: the
	 * only value that was ever available to copy is perm_addr, which by
	 * definition does not follow `ip link set ... address`, and nothing
	 * else ever refreshed it. The reference taken above is held for the
	 * life of this record, so the read is always safe. */
	eth_info->net_dev = device;
	//copy speed, mtu and others
	eth_info->speed = priv->mac_dev->max_speed;
	eth_info->rx_channel_id = priv->channel;
	//get fq info
	list_for_each_entry_safe(dpa_fq, tmp, &priv->dpa_fq_list, list) {
		{
#ifdef DEVMAN_DEBUG
			DPA_INFO("%s::iface %s, fqid %d, channel %d, wq %d, type %d\n",
					__func__, iface_info->name, 
					dpa_fq->fqid, dpa_fq->channel, dpa_fq->wq,
					dpa_fq->fq_type);
#endif
			switch(dpa_fq->fq_type) {
				case FQ_TYPE_RX_DEFAULT:
					eth_info->fqinfo[RX_DEFA_FQ].fq_base
						= dpa_fq->fqid;
					eth_info->fqinfo[RX_DEFA_FQ].num_fqs 
						= 1;
					eth_info->defa_rx_dpa_fq = dpa_fq;
					break;
				case FQ_TYPE_RX_ERROR:
					eth_info->fqinfo[RX_ERR_FQ].fq_base
						= dpa_fq->fqid;
					eth_info->fqinfo[RX_ERR_FQ].num_fqs 
						= 1;
					eth_info->err_rx_dpa_fq = dpa_fq;
					break;
				case FQ_TYPE_TX_CONFIRM:
					eth_info->fqinfo[TX_CFM_FQ].fq_base
						= dpa_fq->fqid;
					eth_info->fqinfo[TX_CFM_FQ].num_fqs 
						= 1;
					break;
				case FQ_TYPE_TX_ERROR:
					eth_info->fqinfo[TX_ERR_FQ].fq_base
						= dpa_fq->fqid;
					eth_info->fqinfo[TX_ERR_FQ].num_fqs 
						= 1;
					break;
				case FQ_TYPE_RX_PCD:
					if (!eth_info->rx_pcd_wq) {
						eth_info->rx_pcd_wq = dpa_fq->wq;
						eth_info->dqrr = dpa_fq->fq_base.cb.dqrr;
					}
					break;
				default:
					break;
			}
		}
	}
	//get buffer pool info
	//number of buffer pools in use by this port
	eth_info->num_pools = (int)priv->bp_count;
	if (eth_info->num_pools > MAX_PORT_BMAN_POOLS) {
		DPA_ERROR("%s::invalid num pools value\n", __func__);
		return FAILURE;
	}
	bp = priv->dpa_bp;
	for (ii = 0; ii < eth_info->num_pools; ii++) {
		eth_info->pool_info[ii].pool_id = bp->bpid ;
		eth_info->pool_info[ii].buf_size = bp->size; 
		eth_info->pool_info[ii].count = bp->config_count;
		eth_info->pool_info[ii].base_addr = bp->paddr;
		bp++;
	}
	//get egress FQ info
	for (ii = 0; ii < DPAA_ETH_TX_QUEUES; ii++) {
		eth_info->eth_tx_fqinfo[ii].fq_base = priv->egress_fqs[ii]->fqid;
		eth_info->eth_tx_fqinfo[ii].num_fqs = 1;
	}
	//get channel and workqueue to be use for transmit
	if (dpa_get_tx_chnl_info(eth_info->eth_tx_fqinfo[0].fq_base, 
				&eth_info->tx_channel_id, 
				&eth_info->tx_wq)) {
		DPA_ERROR("%s::dpa_get_tx_chnl_info failed\n", 
				__func__);
		return FAILURE;
	}
	return SUCCESS;
}


//add port info to linked list
int dpa_add_port_to_list(struct dpa_iface_info *iface_info)
{
	spin_lock(&dpa_devlist_lock);
	if (dpa_interface_info)
		iface_info->next = dpa_interface_info;
	dpa_interface_info = iface_info;
	spin_unlock(&dpa_devlist_lock);
	return SUCCESS;
}

/* Undo dpa_add_port_to_list(): unlink iface_info from the global
 * list. Safe to call if the entry isn't linked. */
static void dpa_remove_port_from_list(struct dpa_iface_info *iface_info)
{
	struct dpa_iface_info **slot;

	spin_lock(&dpa_devlist_lock);
	slot = &dpa_interface_info;
	while (*slot) {
		if (*slot == iface_info) {
			*slot = iface_info->next;
			iface_info->next = NULL;
			break;
		}
		slot = &(*slot)->next;
	}
	spin_unlock(&dpa_devlist_lock);
}


//get dpa_info by itf id
struct dpa_iface_info *dpa_get_ifinfo_by_itfid(uint32_t itf_id)
{
	struct dpa_iface_info *iface_info;

	iface_info = dpa_interface_info;
	while (iface_info) {
		//search list for matching id
		if (iface_info->itf_id == itf_id) 
			break;
		iface_info = iface_info->next;
	}
	return iface_info;
}

/* Whether `dev' is a port of the DPAA Ethernet driver, and so has a struct
 * dpa_priv_s as its private area. netdev_priv() of anything else is some other
 * driver's state -- a bridge's, a VLAN device's -- and reading it as a DPAA
 * port's follows garbage. The driver's ops are its own static table; the one
 * member of it the driver exports is dpa_ndo_init, and no other driver's ops
 * carry it. */
bool dpa_netdev_is_dpaa(const struct net_device *dev)
{
	return dev && dev->netdev_ops && dev->netdev_ops->ndo_init == dpa_ndo_init;
}

/* Physical identity survives an OS rename. The control transaction prevents
 * interface removal; all physical records exist before adapter claim. */
struct dpa_iface_info *dpa_get_ifinfo_by_netdev(const struct net_device *dev)
{
	struct dpa_iface_info *iface;

	lockdep_assert_held(&cdx_info->ctrl.mutex);
	/* Both arms that carry a device, because both can be named as a flow's
	 * egress. The union means the field has to be chosen by if_flags
	 * rather than read blindly. */
	for (iface = dpa_interface_info; iface; iface = iface->next) {
		if ((iface->if_flags & IF_TYPE_ETHERNET) &&
		    iface->eth_info.net_dev == dev)
			return iface;
		/* The WLAN record outlives its device by one workqueue hop
		 * (the retire path frees it from ft_wifi_work_fn), so a match
		 * by address alone could name a netdev that was freed and
		 * reallocated inside that hop. VWD clears its own binding
		 * synchronously, so ask it as well. */
		if ((iface->if_flags & IF_TYPE_WLAN) &&
		    iface->wlan_info.net_dev == dev &&
		    dpaa_vwd_vap_owns(iface->wlan_info.vap_id, dev))
			return iface;
	}
	return NULL;
}

/* Notifier-safe identity check: never retain storage after dropping the lock
 * or take the control mutex while the caller owns RTNL. */
bool dpa_netdev_is_physical(const struct net_device *dev)
{
	struct dpa_iface_info *iface;
	bool found = false;

	spin_lock(&dpa_devlist_lock);
	for (iface = dpa_interface_info; iface; iface = iface->next) {
		if ((iface->if_flags & (IF_TYPE_ETHERNET | IF_TYPE_PHYSICAL)) ==
		    (IF_TYPE_ETHERNET | IF_TYPE_PHYSICAL) &&
		    iface->eth_info.net_dev == dev) {
			found = true;
			break;
		}
	}
	spin_unlock(&dpa_devlist_lock);
	return found;
}

/* get dpa_info by portid */
struct dpa_iface_info *dpa_get_ohifinfo_by_portid(uint32_t portid)
{
	struct dpa_iface_info *iface_info;

	/* Called from vwd init, outside the ctrl mutex, as well as from
	 * the VAP command path, so walk under the list lock. The
	 * returned pointer stays valid without it: OFPORT entries are
	 * never released (dpa_release_interface skips them), so their
	 * lifetime is the module's. The type check matters — oh_info
	 * lives in the per-type union, so a non-OFPORT entry's bytes at
	 * that offset could false-match the portid. */
	spin_lock(&dpa_devlist_lock);
	iface_info = dpa_interface_info;
	while (iface_info) {
		if ((iface_info->if_flags & IF_TYPE_OFPORT) &&
				(iface_info->oh_info.portid == portid))
			break;
		iface_info = iface_info->next;
	}
	spin_unlock(&dpa_devlist_lock);
	return iface_info;
}

/*
 * Get the fqid from ethernet interface.
 */
static inline int dpa_get_fqid_from_eth(struct eth_iface_info *eth_info,
		uint32_t *tx_fqid,
		void  *info)
{
	uint32_t fqid;
	U32 mark = 0; /* Default queue */
	union ctentry_qosmark *qosmark = (union ctentry_qosmark *)&mark;
	if(info)
		qosmark = info;
	fqid = cdx_get_txfqid(eth_info, qosmark);

	if (!fqid) {
		DPA_ERROR("%s::unable to get ceetm fqid for chnl %d queue %d\n",
				__func__, qosmark->chnl_id, qosmark->queue);
		return FAILURE;
	}
	*tx_fqid = fqid;
	return SUCCESS;
}

/*
 * This function gets the tx fqid and portid of the interface.
 * Return value: In success case return SUCCESS and parameters gets updated.
 *               In failure case it returns FAILURE.
 *
 * It names no device. A WLAN interface's would be a Wi-Fi VAP, which has no
 * struct dpa_priv_s behind it, so a caller that needs a port to borrow one
 * from names that port itself, as an IPsec SA names the one it is bound to.
 */
static int dpa_get_tx_fqid_devinfo_by_iface(struct dpa_iface_info *iface_info,
		uint32_t *fqid, uint8_t *is_dscp_fq_map, uint32_t *portid, uint32_t hash)
{
	uint32_t ohport_handle;

	iface_info =  dpa_get_phys_iface(iface_info);
	if (!iface_info) {
		DPA_INFO("%s:: iface info null\n", __func__);
		return FAILURE;
	}

	if (!(iface_info->if_flags & IF_TYPE_ETHERNET) && !(iface_info->if_flags & IF_TYPE_WLAN))
		return FAILURE;

	if (iface_info->if_flags & IF_TYPE_WLAN)
	{
		if (portid)
		{
			dpaa_get_wifi_ohport_handle(&ohport_handle);
			get_ofport_portid(FMAN_IDX, ohport_handle, portid);
#ifdef DEVMAN_DEBUG
			DPA_INFO("%s:: wlan portid :%d: %x\n", __func__, *portid, *portid);
#endif
		}

		if(fqid)
		{
			if (dpaa_get_vap_fwd_fq(iface_info->wlan_info.vap_id, fqid, hash))
				return FAILURE;
#ifdef DEVMAN_DEBUG
			DPA_INFO("%s:: wlan tx fqid :%d: %x\n", __func__, *fqid, *fqid);
#endif
		}
	}
	else
	{
		struct eth_iface_info *eth_info;


		eth_info = &iface_info->eth_info;
		if( portid )
			*portid = eth_info->portid;

		if(fqid)
			if(dpa_get_fqid_from_eth(eth_info, fqid, NULL))
				return FAILURE;

		if (is_dscp_fq_map)
		{
			if (cdx_get_tx_dscp_fq_map(eth_info, is_dscp_fq_map, NULL) != 0)
			{
				DPA_ERROR("%s::unable to get ceetm dscp fq map\n", __func__);
				return FAILURE;
			}
		}
	}

	return SUCCESS;
}

int dpa_check_for_logical_iface_types(struct _itf *input_itf,
		struct dpa_l2hdr_info *l2_info)
{
	struct dpa_iface_info *iface_info;

	/* Only physical ports register: Ethernet ports and Wi-Fi VAPs. A VLAN,
	 * PPPoE or tunnel in front of one is described by the flow instead
	 * (apply_l2_encap()), so the interface itself is all there is to
	 * check. */
	iface_info = dpa_interface_info;
	while(iface_info) {
		if (iface_info->itf_id  == input_itf->index){
			if (iface_info->if_flags & IF_TYPE_ETHERNET)
			{
				if(iface_info->eth_info.vsp_h)
					l2_info->rspid = FM_VSP_GetRelativeProfileId(iface_info->eth_info.vsp_h);
				return SUCCESS;
			}
			if (iface_info->if_flags & IF_TYPE_WLAN)
				return SUCCESS;
			DPA_ERROR("%s::unsupported type 0x%x\n",
					__func__, iface_info->if_flags);
			break;
		}
		iface_info = iface_info->next;
	}
	return FAILURE;
}

int dpa_get_iface_info_by_ipaddress(int sa_family, uint32_t  *daddr, uint32_t * tx_fqid,
		uint32_t * itf_id, uint32_t * portid, uint32_t hash)
{
	struct dpa_iface_info *iface_info;
	struct net_device* device = NULL;
	int ret = FAILURE;

	spin_lock(&dpa_devlist_lock);
	iface_info = dpa_interface_info;
	while(iface_info) {
		if (iface_info->if_flags & (IF_TYPE_ETHERNET | IF_TYPE_WLAN)){

			device = dev_get_by_name(&init_net, iface_info->name);
			if (!device)
			{
				printk("%s:: Could not find device : %s\n",__func__, iface_info->name);
				goto next_iface;
			}

			if(sa_family == PROTO_IPV4 )
			{
				struct in_device  *in_dev;
				struct in_ifaddr *if_info;

				rcu_read_lock();
				in_dev = (struct in_device *)(device->ip_ptr);
				if(in_dev)
				{
					if_info = in_dev->ifa_list;
					for (;if_info;if_info= (struct in_ifaddr*)(if_info->ifa_next))
					{
						if (if_info->ifa_local == *daddr)
						{
							ret = dpa_get_tx_fqid_devinfo_by_iface(iface_info,
									tx_fqid, NULL, portid, hash);
							if (ret < 0)
							{
								printk("%s:: Could not get portid and tx_fqid for : %s \n",__func__, iface_info->name);
								dev_put(device);
								rcu_read_unlock();
								goto end;
							}
							if (itf_id)
								*itf_id = iface_info->itf_id;

							ret = SUCCESS;
							dev_put(device);
							rcu_read_unlock();
							goto end;
						}
					}
				}
				rcu_read_unlock();
			} else {
				struct inet6_dev * inet6_device;
				struct inet6_ifaddr *ifp;
				rcu_read_lock();
				inet6_device = (struct inet6_dev *) device->ip6_ptr;
				if(inet6_device)
				{
					read_lock_bh(&inet6_device->lock);
					list_for_each_entry(ifp, &inet6_device->addr_list, if_list) {
						if (!(memcmp(&ifp->addr, daddr, 16 )))
						{
							ret = dpa_get_tx_fqid_devinfo_by_iface(iface_info,
									tx_fqid, NULL, portid, hash);
							if (ret < 0)
							{
								printk("%s:: Could not get portid and tx_fqid for : %s \n",__func__, iface_info->name);
								dev_put(device);
								read_unlock_bh(&inet6_device->lock);
								rcu_read_unlock();
								goto end;
							}
							if (itf_id)
								*itf_id = iface_info->itf_id;

							ret = SUCCESS;
							dev_put(device);
							read_unlock_bh(&inet6_device->lock);
							rcu_read_unlock();
							goto end;
						}
					}
					read_unlock_bh(&inet6_device->lock);

				}
				rcu_read_unlock();
			}
			dev_put(device);
		}
next_iface:
		iface_info = iface_info->next;
	}
end:
	spin_unlock(&dpa_devlist_lock);
	return ret;
}
int dpa_get_l2l3_info_by_itf_id(uint32_t itf_id, struct dpa_l2hdr_info *l2_info,
		struct dpa_l3hdr_info *l3_info)
{

	struct dpa_iface_info *iface_info;
	int retval = FAILURE;
	memset(l2_info, 0, sizeof(struct dpa_l2hdr_info));
	memset(l3_info, 0, sizeof(struct dpa_l3hdr_info));

	spin_lock(&dpa_devlist_lock);
	iface_info = dpa_get_ifinfo_by_itfid(itf_id);
	if (!iface_info)
		goto out;

	//search list for matching id
	if (iface_info->if_flags & IF_TYPE_ETHERNET ) {
		l2_info->mtu = iface_info->mtu;
#ifdef INCLUDE_ETHER_IFSTATS
		l2_info->ether_stats_offset = iface_info->txstats_index;
#endif
		retval = SUCCESS;
	} else if (iface_info->if_flags &  IF_TYPE_WLAN) {
		l2_info->mtu = iface_info->mtu;
		l2_info->is_wlan_iface = 1;
		retval = SUCCESS;
	} else {
		DPA_INFO("%s::iface type %x not "
				"supported \n",
				__func__, iface_info->if_flags);
	}
out:
	spin_unlock(&dpa_devlist_lock);
	return retval;
}

int dpa_get_out_tx_info_by_itf_id(PRouteEntry rt_entry ,
		struct dpa_l2hdr_info *l2_info,
		struct dpa_l3hdr_info *l3_info, uint32_t hash)
{

	struct dpa_iface_info *iface_info;
	int retval = FAILURE;
	uint32_t itf_id;
	unsigned char* src_mac = NULL;

	memset(l2_info, 0, sizeof(struct dpa_l2hdr_info));
	memset(l3_info, 0, sizeof(struct dpa_l3hdr_info));

	if(!rt_entry)
	{
		DPA_ERROR("%s::NULL Route \n",
				__func__);
		return retval;
	}
	/* An SA holds its tunnel route across interface removal, which
	 * quarantines the route (itf cleared); refuse instead of following
	 * a cleared pointer. */
	if (!rt_entry->itf)
	{
		DPA_ERROR("%s::route has no egress interface\n",
				__func__);
		return retval;
	}
	itf_id = rt_entry->itf->index;
	l2_info->mtu = rt_entry->mtu;
	spin_lock(&dpa_devlist_lock);
	iface_info = dpa_get_ifinfo_by_itfid(itf_id);
	while (1) {
		if (!iface_info)
			break;

		if (iface_info->if_flags & IF_TYPE_WLAN) {

			struct wlan_iface_info* wlan_info = &iface_info->wlan_info;

			if(!(NULL_MAC_ADDR(l2_info->l2hdr)))
				memcpy(&l2_info->l2hdr[0], rt_entry->dstmac,
						ETHER_ADDR_LEN);
			if (!src_mac)
			{
				src_mac = wlan_info->mac_addr;
			}

			/* A VAP's forwarding queues are spread over the CPU
			 * portals, and the dequeue callback runs on the CPU
			 * whose portal the queue lands on. Spread by the
			 * caller's hash rather than pinning every SA to
			 * queue 0, which put all encrypted Wi-Fi egress on
			 * one core. */
			if (dpaa_get_vap_fwd_fq(iface_info->wlan_info.vap_id, &l2_info->fqid, hash))
				break;

			l2_info->is_wlan_iface = 1;
			retval = SUCCESS;
			break;
		}

		/* search list for matching id */
		if (iface_info->if_flags & IF_TYPE_ETHERNET) {
			struct eth_iface_info *eth_info;

			eth_info = &iface_info->eth_info;

			if(!(NULL_MAC_ADDR(l2_info->l2hdr)))
				memcpy(&l2_info->l2hdr[0], rt_entry->dstmac,
						ETHER_ADDR_LEN);
			if (!src_mac)
			{
				/* The port's own address is the netdev's,
				 * read now rather than from a copy taken at
				 * registration that never followed a
				 * change. */
				src_mac = (unsigned char *)eth_info->net_dev->dev_addr;
			}
			if(dpa_get_fqid_from_eth(eth_info, &l2_info->fqid, NULL))
				break;
			if (cdx_get_tx_dscp_fq_map(eth_info, &l2_info->is_dscp_fq_map, NULL) != 0)
			{
				DPA_ERROR("%s::unable to get ceetm dscp fq map\n", __func__);
				break;
			}
#ifdef INCLUDE_ETHER_IFSTATS
			l2_info->ether_stats_offset = iface_info->txstats_index;
#endif
			retval = SUCCESS;
			break;
		}
		DPA_INFO("%s::iface type %x not "
				"supported \n",
				__func__, iface_info->if_flags);
		break;
	}
	if (src_mac)
		memcpy(&l2_info->l2hdr[ETHER_ADDR_LEN], src_mac, ETHER_ADDR_LEN);

	spin_unlock(&dpa_devlist_lock);
	return retval;
}

int dpa_get_num_vlan_iface_stats_entries(uint32_t iif, uint32_t underlying_iif,
		uint32_t *num_entries)
{
	struct dpa_iface_info *iface_info;

	/* No VLAN interface registers -- a flow names its own tags -- so a
	 * registered port has none to count, and anything else is refused. */
	iface_info = dpa_interface_info;
	*num_entries = 0;
	while(iface_info) {
		if (iface_info->itf_id  == iif) {
			if (iface_info->if_flags & (IF_TYPE_ETHERNET | IF_TYPE_WLAN))
				return SUCCESS;
			DPA_ERROR("%s::unsupported type 0x%x\n",
					__func__, iface_info->if_flags);
			break;
		} 
		iface_info = iface_info->next;
	}
	return FAILURE;
}


int dpa_get_tx_info_by_itf(PRouteEntry rt_entry, struct dpa_l2hdr_info *l2_info,
		struct dpa_l3hdr_info *l3_info, void *qosinfo, uint32_t hash)
{

	uint32_t itf_id;
	struct dpa_iface_info *iface_info;
	int retval = FAILURE;
	unsigned char* src_mac = NULL;

	memset(l2_info, 0, sizeof(struct dpa_l2hdr_info));
	memset(l3_info, 0, sizeof(struct dpa_l3hdr_info));
	spin_lock(&dpa_devlist_lock);
	if(!rt_entry->underlying_input_itf)
	{
		DPA_ERROR("%s::NULL underlying input interface\n",
				__func__);
		goto err_ret;
	}

	/* An interface removal clears the itf of a route that is still
	 * referenced; such a route can no longer describe an egress path. */
	if (!rt_entry->itf)
	{
		DPA_ERROR("%s::route has no egress interface\n",
				__func__);
		goto err_ret;
	}

	/* input_itf may be NULL for a VLAN-on-bridge ingress that never
	 * registered as an onif; the physical port (underlying_input_itf) is
	 * the real classification key, so fall back to it. */
	if (dpa_check_for_logical_iface_types(
				rt_entry->input_itf ? rt_entry->input_itf : rt_entry->underlying_input_itf,
				l2_info)) {
		DPA_ERROR("%s::get_iface_type failed iface %d\n",
				__func__,
				rt_entry->input_itf ? rt_entry->input_itf->index :
						rt_entry->underlying_input_itf->index);
		goto err_ret;
	}

	itf_id = rt_entry->itf->index;
	iface_info = dpa_get_ifinfo_by_itfid(itf_id);
	l2_info->mtu = rt_entry->mtu;
	while (1) {
		if (!iface_info)
			break;

		if (iface_info->if_flags & IF_TYPE_WLAN) {

			struct wlan_iface_info* wlan_info = &iface_info->wlan_info;

			if(!(NULL_MAC_ADDR(l2_info->l2hdr)))
				memcpy(&l2_info->l2hdr[0], rt_entry->dstmac,
						ETHER_ADDR_LEN);
			if (!src_mac)
			{
				src_mac = wlan_info->mac_addr;
			}

			if (dpaa_get_vap_fwd_fq(iface_info->wlan_info.vap_id, &l2_info->fqid, hash))
				break;

			l2_info->is_wlan_iface = 1;
			retval = SUCCESS;
			break;
		}

		//search list for matching id
		if (iface_info->if_flags & IF_TYPE_ETHERNET) {
			struct eth_iface_info *eth_info;

			eth_info = &iface_info->eth_info;
#ifdef INCLUDE_ETHER_IFSTATS
			l2_info->ether_stats_offset = iface_info->txstats_index;
#endif


			if(!(NULL_MAC_ADDR(l2_info->l2hdr)))
				memcpy(&l2_info->l2hdr[0], rt_entry->dstmac,
						ETHER_ADDR_LEN);

			if (!src_mac)
			{
				/* As above: the netdev's current address, not
				 * a registration-time copy of perm_addr. */
				src_mac = (unsigned char *)eth_info->net_dev->dev_addr;
			}

			if(dpa_get_fqid_from_eth(eth_info, &l2_info->fqid, qosinfo))
				goto err_ret;
			if (cdx_get_tx_dscp_fq_map(eth_info, &l2_info->is_dscp_fq_map, qosinfo) != 0)
			{
				DPA_ERROR("%s::unable to get ceetm dscp fq map\n", __func__);
				goto err_ret;
			}
			retval = SUCCESS;
			break;
		}
		DPA_INFO("%s::iface type %x not "
				"supported \n",
				__func__, iface_info->if_flags);
		break;
	}
	if (src_mac)
		memcpy(&l2_info->l2hdr[ETHER_ADDR_LEN], src_mac, ETHER_ADDR_LEN);
err_ret:
	spin_unlock(&dpa_devlist_lock);
	return retval;
}


/* return interface information by name and type */
struct dpa_iface_info *dpa_get_iface_by_name(char *name)
{
	struct dpa_iface_info *iface_info;

	spin_lock(&dpa_devlist_lock);
	iface_info = dpa_interface_info;
	while (1) {
		if (!iface_info)
			break;
		if (strcmp(name, iface_info->name) == 0) {
			break;
		}
		iface_info = iface_info->next;
	}
	spin_unlock(&dpa_devlist_lock);
	return iface_info;
}

int dpa_get_iface_hwid_by_name_and_type(char *name, uint32_t type)
{
	struct dpa_iface_info *iface_info;

	iface_info = dpa_get_iface_by_name(name);
	if (iface_info) 
		return (iface_info->eth_info.hardwarePortId);
	else
		return -1;
}

struct dpa_iface_info *dpa_get_phys_iface(struct dpa_iface_info *iface_info)
{
	if (iface_info &&
	    (iface_info->if_flags & (IF_TYPE_ETHERNET | IF_TYPE_WLAN)))
		return iface_info;
	return NULL;
}

static void dpa_get_iface_stats(struct dpa_iface_info *iface_info,
		uint8_t *offset, uint32_t stats_type)
{
	if (stats_type == TX_IFSTATS)
		*offset = iface_info->txstats_index;
	else
		*offset = iface_info->rxstats_index;
}

/* The record a registered port counts in. Only Ethernet ports and Wi-Fi VAPs
 * register; a VLAN device, PPPoE session or tunnel has its record named by
 * the flow that crosses it, never looked up here. */
int dpa_get_iface_stats_entries(uint32_t iif_index,
		uint32_t underlying_iif_index, uint8_t *offset,
		uint32_t stats_type, uint32_t iface_type)
{
	struct dpa_iface_info *iface_info;

	/* lock-free lookups are safe here: this runs only from hw-entry
	 * creation under the ctrl mutex, and every unlink/free of a live
	 * node holds it too, so it serializes us against the frees
	 * (non-mutex adds only publish fresh nodes). */
	iface_info = dpa_get_ifinfo_by_itfid(iif_index);
	if (!iface_info) {
		DPA_ERROR("%s::iface is NULL\n", __func__);
		return FAILURE;
	}

	switch(iface_type)
	{
		case IF_TYPE_ETHERNET:
		case IF_TYPE_WLAN:
			if (!(iface_info->if_flags & (IF_TYPE_ETHERNET | IF_TYPE_WLAN)))
				return FAILURE;
			dpa_get_iface_stats(iface_info, offset, stats_type);
			return SUCCESS;
	}
	return FAILURE;
}

static void free_stats(struct dpa_iface_info *info);

/* Free the remaining interface records and their statistics pool after
 * onif teardown. Startup rollback also uses this sweep, after stopping
 * ports and draining queues. FMAN metadata must remain available until
 * the MURAM allocation has been returned. */
void dpa_release_iflist(void)
{
	struct dpa_iface_info *iface_info;

	spin_lock(&dpa_devlist_lock);
	while (dpa_interface_info) {
		iface_info = dpa_interface_info;
		dpa_interface_info = iface_info->next;
		spin_unlock(&dpa_devlist_lock);

		if ((iface_info->if_flags & IF_TYPE_ETHERNET) &&
				iface_info->eth_info.net_dev) {
			dpa_reset_eth_ifinfo(
				netdev_priv(iface_info->eth_info.net_dev));
			dev_put(iface_info->eth_info.net_dev);
		}
		free_stats(iface_info);
		/* the fqid proc tree is already gone at this point in the
		 * LIFO chain; these reclaim only the wrapper structs */
		cdx_remove_dir_in_procfs(&iface_info->tx_proc_entry);
		cdx_remove_dir_in_procfs(&iface_info->pcd_proc_entry);
		cdx_remove_dir_in_procfs(&iface_info->rx_proc_entry);
		kfree(iface_info);

		spin_lock(&dpa_devlist_lock);
	}
	iface_count = 0;
	spin_unlock(&dpa_devlist_lock);

	/* every stats slot is back on the freelist now; release the MURAM
	 * carve behind them */
	{
		uint64_t muram_base;
		uint32_t muram_size;

		cdx_deinit_iface_stats(dpa_get_fm_MURAM_handle(0, &muram_base,
				&muram_size));
	}
}


static void free_stats(struct dpa_iface_info *info)
{

	if(info->if_flags & IF_TYPE_ETHERNET) {
		free_iface_stats(IF_TYPE_ETHERNET, info);
		return;
	}
	return;
}

#ifdef DPA_IPSEC_OFFLOAD
static void dpa_bman_restore_discard_mask(struct dpa_iface_info *iface_info);
#endif

/* remove dpa interface */
void dpa_release_interface(uint32_t itf_id)
{
	struct dpa_iface_info *prev_info;
	struct dpa_iface_info *curr_info;

	prev_info = NULL;
	spin_lock(&dpa_devlist_lock);
	curr_info = dpa_interface_info;
	while (curr_info) {
		/* OFPORT fixtures are injection-created, carry no onif id
		 * (historically 0 from kzalloc, now the ~0U sentinel) and
		 * are never released; skip them so a legitimate itf_id
		 * can't alias one */
		if (!(curr_info->if_flags & IF_TYPE_OFPORT) &&
				(curr_info->itf_id == itf_id))
			break;
		prev_info = curr_info;
		curr_info = curr_info->next;
	}
	if (!curr_info) {
		spin_unlock(&dpa_devlist_lock);
		return;
	}

	if (prev_info)
		prev_info->next = curr_info->next;
	else
		dpa_interface_info = curr_info->next;

	iface_count--;
	spin_unlock(&dpa_devlist_lock);

	/* Unlinked: the dev_get_stats reader can no longer reach the
	 * node, and every other unlink/free holds the ctrl mutex we
	 * are called under — so the slow HW teardown (the
	 * FM_PCD HC path busy-waits up to ~10ms) and the frees run
	 * without holding the spinlock. */
#ifdef DEVMAN_DEBUG
	printk("%s::removed iface %s, type %d\n",
			__func__, curr_info->name,
			curr_info->if_flags);
#endif
	if((curr_info->if_flags	& IF_TYPE_ETHERNET) && (curr_info->eth_info.net_dev))
	{
		/* Reverse of dpa_add_eth_if() acquisition order:
		 * CEETM → discard mask → FF policer → virt storage profile → netdev ref. */
#ifdef ENABLE_EGRESS_QOS
		cdx_disable_ceetm_on_iface(curr_info);
#endif
#ifdef DPA_IPSEC_OFFLOAD
		dpa_bman_restore_discard_mask(curr_info);
#endif
		dpa_remove_ethport_ff_policier_profile(curr_info);
		dpa_remove_virt_storage_profile(&curr_info->eth_info);
		/* fwd tx FQs were created unconditionally in dpa_add_eth_if;
		 * retire/oos/destroy them (removes their fqid proc nodes
		 * first, while the per-iface tx dir still exists) */
		destroy_fwd_tx_fqs(curr_info);
		/* unpublish the stats slot from the driver before
		 * free_stats below returns it to the freelist */
		dpa_reset_eth_ifinfo(netdev_priv(curr_info->eth_info.net_dev));
		dev_put(curr_info->eth_info.net_dev);
	}
	/* free stats */
	free_stats(curr_info);
	/* per-iface proc dirs + their wrappers. The pcd dir may still hold
	 * nodes for dist FQs that outlive the iface registration; those
	 * pdes die with the dir here and their tracking nodes are
	 * reclaimed by cdx_deinit_fqid_procfs (which skips the stale
	 * proc_remove) */
	cdx_remove_dir_in_procfs(&curr_info->tx_proc_entry);
	cdx_remove_dir_in_procfs(&curr_info->pcd_proc_entry);
	cdx_remove_dir_in_procfs(&curr_info->rx_proc_entry);
	/* free iface structure */
	kfree(curr_info);
}


/* Get a port's hardware address by interface name.
 *
 * Reads the netdev rather than any stored copy, for the reason
 * get_eth_iface_info() gives: the only value ever stored was perm_addr, and
 * nothing refreshed it. The record holds a reference to the device for its
 * whole life, so the dereference is safe under the list lock.
 */
int dpa_get_mac_addr(char *name, char *mac_addr)
{
	struct dpa_iface_info *iface_info;
	int retval;

	retval = -1;
	spin_lock(&dpa_devlist_lock);
	iface_info = dpa_interface_info;
	while (iface_info) {
		//look for ethernet device
		if (iface_info->if_flags & IF_TYPE_ETHERNET) {
			//match name
			if (strcmp (name, iface_info->name) == 0) {
				memcpy(mac_addr,
				       iface_info->eth_info.net_dev->dev_addr,
				       ETH_ALEN);
				retval = 0;
				break;
			}
		}
		iface_info = iface_info->next;
	}
	spin_unlock(&dpa_devlist_lock);
	return retval;
}

#ifdef DPA_IPSEC_OFFLOAD
/*
* This function reconfiguring the discard mask by clearing the FM_FD_ERR_PRS_HDR_ERR
* and FM_FD_ERR_BLOCK_LIMIT_EXCEEDED error bit flags from FM_RFSDM_DEFAULT macro.
*/
static int dpa_bman_reconfigure_discard_mask(struct dpa_iface_info *iface_info)
{
	struct eth_iface_info *eth_info;
	struct dpa_priv_s *priv;
	struct mac_device *mac_dev;
	t_LnxWrpFmPortDev *port = NULL;
	fmPortFrameErrSelect_t ErrDiscard;

	eth_info = &iface_info->eth_info;
	priv = netdev_priv(eth_info->net_dev);
	mac_dev = priv->mac_dev;
	port = (t_LnxWrpFmPortDev *)mac_dev->port_dev[RX];

	if (!port->h_Dev)
	{
		DPA_ERROR("%s::no handle for eth dev %s\n",
				__func__, iface_info->name);
		return FAILURE;
	}

	/* Clearing FM_FD_ERR_PRS_HDR_ERR and FM_FD_ERR_BLOCK_LIMIT_EXCEEDED error bit flags from
	* FM_RFSDM_DEFAULT macro.
	*/
	ErrDiscard = FM_RFSDM_DEFAULT & (~(FM_FD_ERR_PRS_HDR_ERR | FM_FD_ERR_BLOCK_LIMIT_EXCEEDED));
	if (FM_PORT_SetDiscardMask(port->h_Dev, ErrDiscard) != 0)
	{
		DPA_ERROR("%s:: failed to set eth dev %s port ErrorsToDiscard configuration.\n",
				__func__, iface_info->name);
		return FAILURE;
	}
	return SUCCESS;
}

/*
 * Undo dpa_bman_reconfigure_discard_mask() — restore the port's
 * discard mask to FM_RFSDM_DEFAULT.
 *
 * There is no FM_PORT_GetDiscardMask in the FMan SDK, so we can't
 * capture and restore the exact prior value. Instead we write
 * back the architectural default, which is what the port held
 * before dpa_bman_reconfigure_discard_mask ran. Correct only as
 * long as dpa_bman_reconfigure_discard_mask remains the sole
 * writer of this port's discard mask from ASK; flag for SME
 * review if that assumption ever breaks.
 *
 * Used on the dpa_add_eth_if err-path unwind (err_ret6). Best-
 * effort: logs but ignores failure, because we're already in an
 * error-handling cascade.
 */
static void dpa_bman_restore_discard_mask(struct dpa_iface_info *iface_info)
{
	struct eth_iface_info *eth_info;
	struct dpa_priv_s *priv;
	struct mac_device *mac_dev;
	t_LnxWrpFmPortDev *port = NULL;

	eth_info = &iface_info->eth_info;
	priv = netdev_priv(eth_info->net_dev);
	mac_dev = priv->mac_dev;
	port = (t_LnxWrpFmPortDev *)mac_dev->port_dev[RX];

	if (!port || !port->h_Dev)
		return;

	if (FM_PORT_SetDiscardMask(port->h_Dev, FM_RFSDM_DEFAULT) != 0)
		DPA_ERROR("%s:: failed to restore discard mask on %s\n",
				__func__, iface_info->name);
}
#endif

int dpa_add_eth_if(char *name, struct _itf *itf, struct _itf *phys_itf) 
{
	struct dpa_iface_info *iface_info;
	struct dpa_priv_s *priv;
	struct mac_device *mac_dev;

	if(iface_count >= (MAX_LOGICAL_INTERFACES - MAX_PPPoE_INTERFACES))
	{
		DPA_ERROR("%s::Number of interfaces support in fast path is only %d\n",
				__func__,
				(MAX_LOGICAL_INTERFACES - MAX_PPPoE_INTERFACES));
		return FAILURE;
	}
	//ethernet/physical iface type
	iface_info = (struct dpa_iface_info *)
		kzalloc(sizeof(struct dpa_iface_info), GFP_KERNEL);  
	if (!iface_info) {
		DPA_ERROR("%s::no mem for eth dev info size %d\n", 
				__func__, 
				(uint32_t)sizeof(struct dpa_iface_info));
		return FAILURE;
	}
	iface_info->itf_id = itf->index;
	iface_info->if_flags = itf->type;
	//get iface from os device
	if (get_eth_iface_info(iface_info, name))
		goto err_ret;
	//get rest of info from config 
	if (get_dpa_eth_iface_info(&iface_info->eth_info, name)) {
		DPA_ERROR("%s::get_dpa_eth_iface_info failed %s\n", 
				__func__, name);
		goto err_ret;
	}

	if (cdx_create_dir_in_procfs(&iface_info->tx_proc_entry, name, TX_DIR)) {
		DPA_ERROR("%s:: create tx proc entry failed %s\n", 
				__func__, name);
		goto err_ret;
	}
	if (cdx_create_dir_in_procfs(&iface_info->pcd_proc_entry, name, PCD_DIR)) {
		DPA_ERROR("%s:: create pcd proc entry failed %s\n", 
				__func__, name);
		goto err_ret1;
	}

	priv = netdev_priv(iface_info->eth_info.net_dev);
	mac_dev = priv->mac_dev;
	iface_info->eth_info.hardwarePortId = fm_port_get_hwid(mac_dev->port_dev[RX]);
#ifdef CDX_DPA_DEBUG
	printk("%s::port %s hwid %d\n", __func__,
			iface_info->name, iface_info->eth_info.hardwarePortId);
#endif
#ifdef INCLUDE_ETHER_IFSTATS
	if (alloc_iface_stats(itf->type, iface_info) != SUCCESS) {
		DPA_ERROR("%s:: alloc_iface_stats failed\n", __func__);
		goto err_ret2;
	}
	dpa_set_eth_ifinfo(priv, iface_info->stats);
	dpa_update_eth_if(priv);
	iface_info->if_flags |= IF_STATS_ENABLED;
#endif
	//add to list
	if (dpa_add_port_to_list(iface_info)) {
		DPA_ERROR("%s::dpa_add_port_to_list failed\n",
				__func__);
		goto err_stats;
	}

	if(dpa_add_virt_storage_profile(iface_info->eth_info.net_dev ,&iface_info->eth_info)){
		DPA_ERROR("%s::dpa_add_virt_storage_porfile_config failed\n",
				__func__);
		goto err_ret3;
	}
	//add policer profile to port
	if (dpa_add_ethport_ff_policier_profile(iface_info)) {
		DPA_ERROR("%s::dpa_add_policier_profile failed\n",
				__func__);
		goto err_ret4;
	}

#ifdef DPA_IPSEC_OFFLOAD 
	/* Turn off PRS_HDR_ERR and BLOCK_LIMIT_EXCEEDED FD error bits. */
	/* fd.cmd/status word last byte dentores the NH type in the ESP trailer. */
	/* for IPv6 traffic NH type is 0x29(32+8+1), bit 32 and 8 are matching */
	/* with the above errors in bman driver, so turning off them. */
	if (dpa_bman_reconfigure_discard_mask(iface_info)) {
		DPA_ERROR("%s::dpa_add_policier_profile failed\n",
				__func__);
		goto err_ret5;
	}
#endif

#ifdef ENABLE_EGRESS_QOS
	/* enable CEETM on this interface */
	if (cdx_enable_ceetm_on_iface(iface_info)) {
		DPA_ERROR("%s::cdx_enable_ceetm_on_iface failed\n",
				__func__);
		goto err_ret6;
	}
#endif
	/* no CEETM, create fwd Fqs */
	if (create_fwd_tx_fqs(iface_info)) {
		DPA_ERROR("%s::create_fwd_tx_fqs failed\n", 
				__func__);
		goto err_ret7;
	}
	iface_count++;
	return SUCCESS;
err_ret7:
#ifdef ENABLE_EGRESS_QOS
	cdx_disable_ceetm_on_iface(iface_info);
err_ret6:
#endif
#ifdef DPA_IPSEC_OFFLOAD
	/* not nested under ENABLE_EGRESS_QOS: the discard mask was
	 * reconfigured regardless of CEETM, so later failures must
	 * restore it even in builds without egress QoS */
	dpa_bman_restore_discard_mask(iface_info);
err_ret5:
#endif
	dpa_remove_ethport_ff_policier_profile(iface_info);
err_ret4:
	dpa_remove_virt_storage_profile(&iface_info->eth_info);
err_ret3:
	dpa_remove_port_from_list(iface_info);
err_stats:
#ifdef INCLUDE_ETHER_IFSTATS
	if (iface_info->if_flags & IF_STATS_ENABLED) {
		/* unpublish before the slot goes back to the freelist —
		 * priv->ifinfo would otherwise keep pointing at recycled
		 * stats memory the datapath writes through */
		dpa_reset_eth_ifinfo(priv);
		free_iface_stats(itf->type, iface_info);
	}
#endif
err_ret2:
	cdx_remove_dir_in_procfs(&iface_info->pcd_proc_entry);
err_ret1:
	cdx_remove_dir_in_procfs(&iface_info->tx_proc_entry);
err_ret:
	/* get_eth_iface_info holds a dev_get_by_name ref once net_dev is
	 * set; released on no other error path (normal release is in
	 * dpa_release_interface) */
	if (iface_info->eth_info.net_dev)
		dev_put(iface_info->eth_info.net_dev);
	kfree(iface_info);
	return FAILURE;
}

//get interface information from OS device priv structure
static int get_wlan_iface_info(struct dpa_iface_info *iface_info)
{
	struct net_device *device;
	uint32_t ohport_handle;
	int ret = 0;

	device = dev_get_by_name(&init_net, iface_info->name);
	if (!device) {
		DPA_INFO("%s::could not find device %s\n", __func__, iface_info->name);
		return FAILURE;
	}
	iface_info->mtu = device->mtu;
	/* Borrowed, exactly as the ethernet arm borrows its own: compared to
	 * resolve a netdev back to this iface, never dereferenced, and gone
	 * when the VAP is retired. */
	iface_info->wlan_info.net_dev = device;
	dev_put(device);

	dpaa_get_wifi_ohport_handle(&ohport_handle);
	DPA_INFO("%s::OH port handle  %d\n", __func__, ohport_handle);

	ret = get_ofport_fman_and_portindex(FMAN_IDX, ohport_handle, &iface_info->wlan_info.fman_idx, 
			&iface_info->wlan_info.port_idx, &iface_info->wlan_info.portid);
	if (ret) {
		DPA_ERROR("%s::get_ofport_fman_and_portindex failed\n", __func__);
		return FAILURE;
	}

	DPA_INFO("%s::fman_idx: %d port_idx: %d\n", __func__, iface_info->wlan_info.fman_idx, iface_info->wlan_info.port_idx);
	return SUCCESS;
}

int dpa_add_wlan_if(char *name, struct _itf *itf, uint32_t vap_id, unsigned char* mac)
{
	struct dpa_iface_info *iface_info;

	if(iface_count >= (MAX_LOGICAL_INTERFACES - MAX_PPPoE_INTERFACES))
	{
		DPA_ERROR("%s::Number of interfaces support in fast path is only %d\n",
				__func__,
				(MAX_LOGICAL_INTERFACES - MAX_PPPoE_INTERFACES));
		return FAILURE;
	}
	//ethernet/physical iface type
	iface_info = (struct dpa_iface_info *)
		kzalloc(sizeof(struct dpa_iface_info), GFP_KERNEL);
	if (!iface_info) {
		DPA_ERROR("%s::no mem for eth dev info size %d\n",
				__func__,
				(uint32_t)sizeof(struct dpa_iface_info));
		return FAILURE;
	}
	memset(iface_info, 0, sizeof(struct dpa_iface_info));
	iface_info->itf_id = itf->index;
	iface_info->if_flags = itf->type;
	strncpy(&iface_info->name[0], name, IF_NAME_SIZE);
	iface_info->wlan_info.vap_id = vap_id;
	memcpy(&iface_info->wlan_info.mac_addr[0], mac, ETH_ALEN);
	if (get_wlan_iface_info(iface_info)) {
		DPA_ERROR("%s::get_wlan_iface_info failed\n", __func__);
		goto err_ret;
	}

	//add to list
	if (dpa_add_port_to_list(iface_info)) {
		DPA_ERROR("%s::dpa_add_port_to_list failed\n",
				__func__);
		goto err_ret;
	}
	/* dpa_release_interface decrements iface_count for WLAN entries;
	 * without this increment repeated vap add/remove cycles underflow
	 * the u8 counter and the cap checks then reject every add */
	iface_count++;

	return SUCCESS;
err_ret:
	kfree(iface_info);
	return FAILURE;
}

//get fm and port index from itf_index
int dpa_get_fm_port_index(uint32_t itf_index, uint32_t underlying_iif_index , 
		uint32_t *fm_index, uint32_t *port_index,
		uint32_t *portid)
{
	struct dpa_iface_info *iface_info;

	iface_info = dpa_interface_info;
	while (1) {
		if (!iface_info)
			break;
		/* match itf index */
		if (iface_info->itf_id == itf_index) {
			if (iface_info->if_flags & IF_TYPE_ETHERNET) {
				/* ensure it is ethernet and return params */
				*fm_index = iface_info->eth_info.fman_idx;
				*port_index = iface_info->eth_info.port_idx;
				if (portid)
					*portid = iface_info->eth_info.portid;
				return 0;
			}
			if (iface_info->if_flags & IF_TYPE_WLAN) {
				/* ensure it is wifi and return params */
				*fm_index = iface_info->wlan_info.fman_idx;
				*port_index = iface_info->wlan_info.port_idx;
				if (portid)
					*portid = iface_info->wlan_info.portid;
				return 0;
			}
			DPA_ERROR("%s::unsupported type 0x%x\n",
					__func__, iface_info->if_flags);
			break;
		}
		iface_info = iface_info->next;
	}
	return -1;
}

void dpa_update_timestamp(uint32_t ts)
{
	FM_PCD_UpdateExtTimeStamp(EXTERNAL_TIMESTAMP_TIMERID, cpu_to_be32(ts));
}

uint32_t dpa_get_timestamp_addr(uint32_t id)
{
	return(FM_PCD_GetExtTimeStampAddr(id));
}


int cdx_copy_eth_rx_channel_info(uint32_t fman_idx, struct dpa_fq *dpa_fq)
{
	struct dpa_iface_info *iface_info;

	/* reachable from vwd init and the injection path — outside the
	 * ctrl mutex — so walk and copy under the list lock; the caller
	 * keeps only the copied channel id */
	spin_lock(&dpa_devlist_lock);
	iface_info = dpa_interface_info;
	while(1) {
		if (!iface_info)
			break;
		if (iface_info->if_flags & IF_TYPE_ETHERNET) {
			if (iface_info->eth_info.fman_idx == fman_idx) {
				dpa_fq->channel = iface_info->eth_info.rx_channel_id;
				spin_unlock(&dpa_devlist_lock);
				return 0;
			}
		}
		iface_info = iface_info->next;
	}
	spin_unlock(&dpa_devlist_lock);
	return -1;
}

/* The producer must be stopped before draining a queue. */
static void cdx_drain_fq(struct qman_fq *fq)
{
	enum qman_fq_state state;
	u32 flags;
	int ret;

	/* Retirement may be asynchronous. Keep the FQ and its callback data
	 * alive until QMan has returned every frame and accepted OOS.
	 */
	for (;;) {
		qman_fq_state(fq, &state, &flags);
		if (state == qman_fq_state_oos)
			break;
		if (flags & (QMAN_FQ_STATE_CHANGING | QMAN_FQ_STATE_ORL))
			goto wait;
		if (state != qman_fq_state_retired) {
			ret = qman_retire_fq(fq, NULL);
			if (ret < 0)
				pr_warn_ratelimited("cdx: cannot retire FQ %u: %d\n",
						    fq->fqid, ret);
			goto wait;
		}
		if (flags & QMAN_FQ_STATE_NE) {
			ret = qman_volatile_dequeue(fq,
					QMAN_VOLATILE_FLAG_WAIT |
					QMAN_VOLATILE_FLAG_FINISH,
					QM_VDQCR_NUMFRAMES_TILLEMPTY);
			if (ret)
				goto wait;
		}
		ret = qman_oos_fq(fq);
		if (!ret)
			break;
		pr_warn_ratelimited("cdx: cannot take FQ %u out of service: %d\n",
				    fq->fqid, ret);
wait:
		usleep_range(1000, 2000);
	}
}

void cdx_destroy_fq(struct qman_fq *fq)
{
	cdx_drain_fq(fq);
	/* The portal updates its FQ state before returning from the callback. */
	synchronize_net();
	cdx_remove_fqid_info_in_procfs(fq->fqid);
	qman_destroy_fq(fq, 0);
}

void cdx_drain_fq_list(struct dpa_fq *head)
{
	struct dpa_fq *fq;

	if (!head)
		return;
	for (fq = head; fq; fq = (struct dpa_fq *)fq->list.next)
		cdx_drain_fq(&fq->fq_base);
	/* Finish callbacks while retaining queue storage for dependent teardown. */
	synchronize_net();
}

void cdx_destroy_fq_list(struct dpa_fq **head)
{
	struct dpa_fq *fq;

	cdx_drain_fq_list(*head);
	while (*head) {
		fq = *head;
		*head = (struct dpa_fq *)fq->list.next;
		cdx_remove_fqid_info_in_procfs(fq->fq_base.fqid);
		qman_destroy_fq(&fq->fq_base, 0);
		kfree(fq);
	}
}


//create pcd
int cdx_create_fq(struct dpa_fq *dpa_fq, uint32_t flags, void *pcd_proc_entry)
{
	struct qman_fq *fq;
	struct qm_mcc_initfq opts;

	fq = &dpa_fq->fq_base;
	if (qman_create_fq(dpa_fq->fqid, flags, fq)) {
		DPA_ERROR("%s::qman_create_fq failed for fqid %d\n",
				__func__, dpa_fq->fqid);
		return -1;
	}
	memset(&opts, 0, sizeof(struct qm_mcc_initfq));
	if (flags & QMAN_FQ_FLAG_DYNAMIC_FQID)
		dpa_fq->fqid = fq->fqid;
	opts.fqid = dpa_fq->fqid;
	opts.count = 1;
	opts.we_mask = (QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
			QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA);
	//opts.fqd.fq_ctrl = (QM_FQCTRL_PREFERINCACHE | QM_FQCTRL_HOLDACTIVE);
	opts.fqd.fq_ctrl = QM_FQCTRL_PREFERINCACHE;
	opts.fqd.dest.channel = dpa_fq->channel;
	opts.fqd.dest.wq = dpa_fq->wq;
	opts.fqd.context_a.stashing.exclusive =
		(QM_STASHING_EXCL_DATA | QM_STASHING_EXCL_ANNOTATION);
	opts.fqd.context_a.stashing.data_cl = NUM_PKT_DATA_LINES_IN_CACHE;
	opts.fqd.context_a.stashing.annotation_cl = NUM_ANN_LINES_IN_CACHE;
	if (qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts)) {
		DPA_ERROR("%s::qman_init_fq failed for fqid %d\n",
				__func__, dpa_fq->fqid);
		qman_destroy_fq(fq, 0);
		return -1;
	}

	cdx_create_type_fqid_info_in_procfs(fq, PCD_DIR, pcd_proc_entry, NULL);
#ifdef DEVMAN_DEBUG
	DPA_INFO("%s::created fq 0x%x channel 0x%x\n", __func__, 
			dpa_fq->fqid, dpa_fq->channel);
#endif
	return 0;
}


//routine to create all FQs required by distribution in xml file
static int cdxdrv_create_pcd_fqs(struct dpa_iface_info *iface_info)
{
	uint32_t ii;
	uint32_t jj;
	struct dpa_fq *dpa_fq;
	uint32_t fqid;	
	uint32_t max_dist;
	struct cdx_dist_info *dist_info;
	uint32_t portal_channel[NR_CPUS];
	uint32_t num_portals;
	uint32_t next_portal_ch_idx;
	const cpumask_t *affine_cpus;
	struct eth_iface_info *eth_iface_info = &(iface_info->eth_info);

	max_dist = eth_iface_info->max_dist;
	dist_info = eth_iface_info->dist_info;

	num_portals = 0;
	next_portal_ch_idx = 0;
	affine_cpus = qman_affine_cpus();
	/* get channel used by portals affined to each cpu */
	for_each_cpu(ii, affine_cpus) {
		portal_channel[num_portals] = qman_affine_channel(ii);
		num_portals++;
	}
	if (!num_portals) {
		DPA_ERROR("%s::unable to get affined portal info\n",
				__func__);
		return -1;
	}
#ifdef DEVMAN_DEBUG
	DPA_INFO("%s::num_portals %d ::", __func__, num_portals);
	for (ii = 0; ii < num_portals; ii++)
		DPA_INFO("%d ", portal_channel[ii]);
	DPA_INFO("\n");
#endif

#ifdef DEVMAN_DEBUG
	DPA_INFO("%s::max dist %d\n", __func__, max_dist);	
#endif
	for (ii = 0; ii < max_dist; ii++) {
		fqid = (dist_info->base_fqid + 
				(eth_iface_info->portid << PORTID_SHIFT_VAL));
#ifdef DEVMAN_DEBUG
		DPA_INFO("%s::dist %d, count %d, base %x(%d) fqid %x(%d)\n",
				__func__, ii, dist_info->count, 
				dist_info->base_fqid, dist_info->base_fqid,
				fqid, fqid);
#endif
		for (jj = 0; jj < dist_info->count; jj++) {
			if (find_pcd_fq_info(fqid)) {
				dpa_fq = kzalloc(sizeof(struct dpa_fq), GFP_KERNEL);
				if (!dpa_fq) {
					DPA_ERROR("%s::unable to alloc mem for fqid %d\n",
							__func__, fqid);
					return -1;
				}
				memset(dpa_fq, 0, sizeof(struct dpa_fq));
#ifdef DEVMAN_DEBUG
				DPA_INFO("%s::net dev %p\n", __func__,
						eth_iface_info->net_dev);
#endif
				dpa_fq->net_dev = eth_iface_info->net_dev;
				dpa_fq->fqid = fqid;
				dpa_fq->fq_type = FQ_TYPE_RX_PCD;
				//round robin channel ids
				dpa_fq->channel = portal_channel[next_portal_ch_idx];
				if (next_portal_ch_idx == (num_portals - 1))
					next_portal_ch_idx = 0;
				else
					next_portal_ch_idx++;
				//use same wq used by ethernet RX PCD FQs for port
				dpa_fq->wq = eth_iface_info->rx_pcd_wq;
				//use same callback used by ethernet driver 
				dpa_fq->fq_base.cb.dqrr = eth_iface_info->dqrr;
				//create PCD FQ
				if (cdx_create_fq(dpa_fq, 0, iface_info->pcd_proc_entry)) {
					DPA_ERROR("%s::cdx_create_fq failed for fqid %d\n",
							__func__, fqid);
					kfree(dpa_fq);
					return -1;
				}
				add_pcd_fq_info(dpa_fq);
				if (cdx_dpa_init_fault())
					return -EIO;
#ifdef DEVMAN_DEBUG
				DPA_INFO("%s::netdev %s fqid 0x%x created chnl 0x%x\n", 
						__func__, dpa_fq->net_dev->name, fqid, dpa_fq->channel);
#endif
			} 
#ifdef DEVMAN_DEBUG
			else {
				DPA_INFO("%s::fqid 0x%x already created\n", 
						__func__, fqid);
			}
#endif
			fqid++;
		}
		dist_info++;	
	}
	return 0;
}


int cdx_create_port_fqs(void)
{
	struct dpa_iface_info *iface_info;

	iface_info = dpa_interface_info;
	while(1) {
		if (!iface_info)
			break;
#ifdef DEVMAN_DEBUG
		printk("%s::%s type %x\n", __func__,
				iface_info->name, iface_info->if_flags);
#endif
		if (iface_info->if_flags & IF_TYPE_ETHERNET) {
			if (cdxdrv_create_pcd_fqs(iface_info)) {
				DPA_ERROR("%s::create pcd fq for %s failed\n",
						__func__, iface_info->name);
				return -1;
			}
		} else {
			if (iface_info->if_flags & IF_TYPE_OFPORT) {
				if (cdxdrv_create_of_fqs(iface_info)) {
					DPA_ERROR("%s::create of fq for %s failed\n",
							__func__, iface_info->name);
					return -1;
				}
			}
		}
		iface_info = iface_info->next;
	}
	return 0;
}

int get_phys_port_poolinfo_bysize(uint32_t size, struct port_bman_pool_info *pool_info)
{
	uint32_t ii;
	struct dpa_iface_info *iface_info;

	iface_info = dpa_interface_info;
	while(1) {
		if (!iface_info)
			break;
		if (iface_info->if_flags & IF_TYPE_ETHERNET) {
			for (ii = 0; ii < iface_info->eth_info.num_pools; ii++) {
				if (iface_info->eth_info.pool_info[ii].buf_size >= size) {
					memcpy(pool_info, &iface_info->eth_info.pool_info[ii],
							sizeof(struct port_bman_pool_info));
					return 0;
				}
			}
		}
		iface_info = iface_info->next;
	}
	printk("%s::failed\n", __func__);
	return -1;
}

/* The first physical Ethernet port on record, held. For consumers that need
 * a DPAA port's private data for what every port shares -- the buffer layout
 * and errata handling -- rather than for any one port in particular. Pairs
 * with dev_put() on the returned priv's net_dev. */
struct dpa_priv_s *dpa_first_eth_priv(void)
{
	struct dpa_iface_info *iface;
	struct net_device *device = NULL;

	spin_lock(&dpa_devlist_lock);
	for (iface = dpa_interface_info; iface; iface = iface->next) {
		if ((iface->if_flags & IF_TYPE_ETHERNET) && iface->eth_info.net_dev) {
			device = iface->eth_info.net_dev;
			dev_hold(device);
			break;
		}
	}
	spin_unlock(&dpa_devlist_lock);
	if (!device) {
		DPA_INFO("%s::no Ethernet port on record\n", __func__);
		return NULL;
	}
	return netdev_priv(device);
}


static void virt_iface_stats_callback(struct net_device *dev, struct rtnl_link_stats64 *storage)
{
	struct dpa_iface_info *iface_info;
	struct cdx_ft_stats rx, tx;

	spin_lock(&dpa_devlist_lock);
	iface_info = dpa_interface_info;
	while(1)
	{
		//more interfaces to scan?
		if (!iface_info)
			break;		
		//check if this the iface we want
		if ((iface_info->if_flags & IF_TYPE_ETHERNET) ?
		    iface_info->eth_info.net_dev != dev :
		    strcmp(dev->name, iface_info->name)) {
			iface_info = iface_info->next;
			continue;
		}
		//if stats is disabled on the iface do nothing
		if (!(iface_info->if_flags & IF_STATS_ENABLED))
			break;
		/* Every arm reads its record through cdx_ifstats_read(), which
		 * carries the firmware's 32-bit packet count past its wrap; the
		 * raw count would step the device's packets back by 2^32 there.
		 * That nests dpa_statslist_lock inside this lock. */
		if (iface_info->if_flags & IF_TYPE_ETHERNET) {
			/* The port's record: what UPDATE_ETH_RX_STATS counted on
			 * ingress and the enqueue counted on egress, both as
			 * whole frames. The driver's own rx_bytes excludes the
			 * Ethernet header, so the record is restated to match
			 * before the two are added; transmit already agrees. */
			cdx_ifstats_read(iface_info->stats, &rx, &tx);
			cdx_ifstats_fold(storage, rx.bytes, rx.packets,
					 tx.bytes, tx.packets,
					 CDX_IFSTATS_PORT_RX_OVERHEAD, 0);
			break;
		}
		printk("%s::unknown iface type,no stats available\n",
				__func__);
		iface_info = iface_info->next;
	}
	spin_unlock(&dpa_devlist_lock);
	/* The flowtable owner registers no logical interfaces, so its VLAN
	 * devices are not on the list above; their records are published to the
	 * device by index and folded here. Outside the device-list lock: the two
	 * are independent, and nothing needs them nested. */
	cdx_ft_ifstats_fold(dev, storage);
}

static void devman_deinit_linux_stats(void)
{
	dev_fp_stats_get_deregister();
	cdx_ifstats_stop();
	return;
}

int devman_init_linux_stats(void)
{
	dev_fp_stats_get_register(virt_iface_stats_callback);
	/* The records the hook folds count packets in 32 bits, which wrap in
	 * minutes at line rate; the sampler reads them often enough that no
	 * wrap goes unseen, for as long as the hook can be called. */
	cdx_ifstats_start();
	register_cdx_deinit_func(devman_deinit_linux_stats);
	return 0;
}
