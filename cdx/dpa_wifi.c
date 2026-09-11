/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <net/pkt_sched.h>
#include <linux/rcupdate.h>
#include <linux/netdevice.h>
#include <linux/if_vlan.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter_bridge.h>
#include <linux/irqnr.h>
#include <linux/ppp_defs.h>
#include <linux/highmem.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/workqueue.h>

#include <linux/fsl_bman.h>

#include "portdefs.h"
#include "misc.h"
#include "dpaa_eth.h"
#include "dpaa_eth_common.h"
#include "dpa_wifi.h"
#include "layer2.h"
#include "cdx.h"
#include "procfs.h"

//uncomment to allow debug prints
//#define DPA_WIFI_DEBUG  1

static unsigned int num_tx_sent = 0;
static DEFINE_PER_CPU(unsigned int, num_tx_done);
static atomic_t vwd_tx_pending = ATOMIC_INIT(0);
static struct delayed_work vwd_tx_work;
static bool vwd_stopping = true;
#define PORTID_SHIFT_VAL 	8
#define VAP_TX_CONF_BUF_COUNT	128
#define DPAWIFI_ERROR(fmt, ...)\
{\
        printk(KERN_CRIT fmt, ## __VA_ARGS__);\
}
#ifdef CDX_DPA_DEBUG
#define DPAWIFI_INFO(fmt, ...)\
{\
        printk(KERN_INFO fmt, ## __VA_ARGS__);\
}
#else
#define DPAWIFI_INFO(fmt, ...)
#endif

#define percpu_var_sum(var, total)\
{\
	unsigned int ii; \
	total = 0;\
	for_each_possible_cpu(ii)\
		total += per_cpu(var, ii);\
}

#define INCR_PER_CPU_STAT(ptr, stat)\
{\
        get_cpu_ptr((ptr))->stat++;\
        put_cpu_ptr((ptr));\
}

/*
 * Concurrency (VWD, virtual wifi driver):
 *   vwd.vaplock (spinlock_t in dpaa_vwd_priv_s)
 *      - Guards the VAP table (vwd.vap[] and dev_attr_vap[]) and
 *        the associated sysfs attribute bindings. Taken _bh on the
 *        ioctl paths and by the softirq classifiers/rx fastpath, so
 *        NOTHING may sleep under it. Sleeping VAP setup (vwd_vap_up:
 *        GFP_KERNEL allocs, qman FQ creation; device_create_file)
 *        runs outside the lock: the ioctl handler claims the slot
 *        with VAP_ST_CONFIGURING under the lock, drops it for the
 *        work, and re-takes it to publish VAP_ST_OPEN or roll back.
 *        Datapath consumers key on net_dev->wifi_offload_dev (the
 *        nf-hook classifiers and the lock-free ipsec xmit hook —
 *        release-published only after the FQs are live) or on
 *        VAP_ST_OPEN (the rx fastpath), so they never observe a
 *        half-built VAP.
 *   vwd.txlock (spinlock_t)
 *      - Guards the tx-path state used by dpaa_vwd_send_packet and
 *        the netfilter route/bridge hooks. Taken in softirq
 *        context (hook path), so spin_lock() without _bh is OK
 *        because callers are already under softirq or sufficiently
 *        serialized. Producers on the ioctl path disable BH as
 *        needed.
 *   vwd (file-scope struct)
 *      - Initialized once in dpaa_vwd_init(), torn down in
 *        dpaa_vwd_exit(). VWD holds the Ethernet netdev reference
 *        returned by get_eth_priv() until callbacks have drained,
 *        then releases it during initialization failure or exit.
 *
 * Contexts:
 *   dpaa_vwd_open/close/ioctl               - process.
 *   dpaa_vwd_nf_{route,bridge}_hook_fn      - softirq (netfilter).
 *   dpaa_vwd_send_packet                    - softirq.
 *   dpaa_vwd_{init,exit,up,down}           - module init/exit.
 */

struct dpaa_vwd_priv_s vwd;

extern struct dpa_bp *dpa_bpid2pool(int bpid);
extern struct dpa_priv_s* get_eth_priv(unsigned char* name);

static int dpaa_vwd_open(struct inode *inode, struct file *file);
static long dpaa_vwd_ioctl(struct file * file, unsigned int cmd, unsigned long arg);

// nf_hookfn modified in netfilter.h //const struct nf_hook_ops *ops,
static unsigned int dpaa_vwd_nf_route_hook_fn( void *ops,struct sk_buff *skb,const struct nf_hook_state *state);
static unsigned int dpaa_vwd_nf_bridge_hook_fn( void *ops,struct sk_buff *skb,const struct nf_hook_state *state);

static int dpaa_vwd_send_packet(struct dpaa_vwd_priv_s *priv, void *vap_handle, struct sk_buff *skb);
static ssize_t vwd_show_dump_stats(struct device *dev, struct device_attribute *attr, char *buf);
static ssize_t vwd_show_vap_stats(struct device *dev, struct device_attribute *attr, char *buf);
static ssize_t vwd_show_fast_path_enable(struct device *dev, struct device_attribute *attr, char *buf);
static ssize_t vwd_set_fast_path_enable(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);
static ssize_t vwd_show_oh_buff_limit(struct device *dev, struct device_attribute *attr, char *buf);
static ssize_t vwd_set_oh_buff_limit(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);
static DEVICE_ATTR(vwd_debug_stats, 0444, vwd_show_dump_stats, NULL);
static DEVICE_ATTR(vwd_fast_path_enable, 0644, vwd_show_fast_path_enable, vwd_set_fast_path_enable);
static struct device_attribute dev_attr_vap[MAX_WIFI_VAPS];
static DEVICE_ATTR(vwd_oh_buff_limit, 0644, vwd_show_oh_buff_limit, vwd_set_oh_buff_limit);
static int process_vap_rx_fwd_pkt(struct qman_portal *portal, struct qman_fq *fq, const struct qm_dqrr_entry *dq);
static void vwd_fq_destroy(struct qman_fq *fq);
static void vwd_release_pcd_fqs(struct dpaa_vwd_priv_s *priv);
void drain_bp_tx_done_bpool(struct dpa_bp *bp);

static int (*vwd_rx_hdlr)(struct sk_buff *);

static unsigned int oh_buff_limit = 1024;

static int wifi_rx_dummy_hdlr(struct sk_buff *skb)
{
	return -1;
}

static int wifi_rx_fastpath_register(int (*hdlr)(struct sk_buff *skb))
{
	pr_info("%s:%d VWD Tx function registered\n", __func__, __LINE__ );
	WRITE_ONCE(vwd_rx_hdlr, hdlr);

	return 0;
}

static void wifi_rx_fastpath_unregister(void)
{
	pr_info("%s:%d VWD Tx function unregistered\n", __func__, __LINE__ );
	WRITE_ONCE(vwd_rx_hdlr, wifi_rx_dummy_hdlr);

	return;
}

int cdx_wifi_rx_fastpath(struct sk_buff *skb)
{
	int (*handler)(struct sk_buff *);
	int ret = -1;

	rcu_read_lock();
	handler = READ_ONCE(vwd_rx_hdlr);
	if (handler)
		ret = handler(skb);
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL(cdx_wifi_rx_fastpath);

static const struct file_operations vwd_fops = {
	.owner                  = THIS_MODULE,
	.open                   = dpaa_vwd_open,
	.unlocked_ioctl         = dpaa_vwd_ioctl,
};

/* IPV4 route hook , recieve the packet and forward to VWD driver*/
static struct nf_hook_ops vwd_hook = {
	.hook = dpaa_vwd_nf_route_hook_fn,
	.pf = PF_INET,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_FIRST,
};

/* IPV6 route hook , recieve the packet and forward to VWD driver*/
static struct nf_hook_ops vwd_hook_ipv6 = {
	.hook = dpaa_vwd_nf_route_hook_fn,
	.pf = PF_INET6,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP6_PRI_FIRST,
};

/* Bridge hook , recieve the packet and forward to VWD driver*/
static struct nf_hook_ops vwd_hook_bridge = {
	.hook = dpaa_vwd_nf_bridge_hook_fn,
	.pf = PF_BRIDGE,
	.hooknum = NF_BR_PRE_ROUTING,
	.priority = NF_BR_PRI_FIRST,
};
/* In case VWD OFFLOAD , headers can be added in ucode, and the length of the 
	 original buffer can be increased. And this increased length is written from 
	 fixed offset (192) for packets coming from OH port causing headers to grow at tail.
	 So tailroom is introduced to allow the tail to grow upto 64 bytes */
#define SKB_ASK_TAILROOM 	64

bool a050385_check_skb(struct sk_buff *skb, struct dpa_priv_s *priv);
struct sk_buff *a050385_realign_skb(struct sk_buff *skb, struct dpa_priv_s *priv);

/* This function will return 1 if the device is cellular (i.e no_l2_itf) */
int vwd_is_no_l2_itf_device(struct net_device* dev)
{
	struct vap_desc_s *vap;
	if (dev->wifi_offload_dev)
	{
		vap = (struct vap_desc_s *)dev->wifi_offload_dev;
		if (vap->no_l2_itf)
			return 1;
	}
	return 0;
}

/* This function transmits local ESP packets to SEC for processing */
static int vwd_xmit_local_packet(struct sk_buff *skb)
{
	struct dpaa_vwd_priv_s *priv = &vwd;
	struct vap_desc_s *vap;
	unsigned char hdroom_realloced = 0;
	int ret;

	INCR_PER_CPU_STAT(priv->vwd_global_stats, pkts_total_local_tx);
	if (!skb->dev->wifi_offload_dev)
		goto send_pkt;

	vap = (struct vap_desc_s *)skb->dev->wifi_offload_dev;

	if (vap->no_l2_itf)
	{
		ret = dpa_add_dummy_eth_hdr(&skb, 0, &hdroom_realloced); 

		if (ret < 0)
			goto send_pkt;

		skb_push(skb, ETH_HLEN);

		if (hdroom_realloced) {
			INCR_PER_CPU_STAT(vap->vap_stats, pkts_tx_no_head);
		}
	}

	INCR_PER_CPU_STAT(vap->vap_stats, pkts_local_tx_dpaa);
	dpaa_submit_outb_pkt_to_SEC(skb, skb->dev, priv->txconf_bp);

	return 0;
send_pkt:
	return original_dev_queue_xmit(skb);
}

static ssize_t vwd_show_vap_stats(struct device *dev, struct device_attribute *attribute, char *buf)
{
	ssize_t len = 0;
	struct dpaa_vwd_priv_s *priv = &vwd;
	int ii = 0;

	struct vap_stats_s *per_cpu_stats;
	struct vap_stats_s total_stats;
	int i;

	for (ii = 0; ii < MAX_WIFI_VAPS; ii++) {
		if (!strcmp(attribute->attr.name, priv->vaps[ii].ifname)) {
			break;
		}
	}

	/* No vap entry */
	if (ii == MAX_WIFI_VAPS)
		return 0;

	memset(&total_stats, 0, sizeof(struct vap_stats_s));
	for_each_possible_cpu(i) {
		per_cpu_stats = per_cpu_ptr(priv->vaps[ii].vap_stats, i);
		total_stats.pkts_local_tx_dpaa += per_cpu_stats->pkts_local_tx_dpaa;
		total_stats.pkts_transmitted += per_cpu_stats->pkts_transmitted;
		total_stats.pkts_slow_forwarded += per_cpu_stats->pkts_slow_forwarded;
		total_stats.pkts_tx_dropped += per_cpu_stats->pkts_tx_dropped;
		total_stats.pkts_rx_fast_forwarded += per_cpu_stats->pkts_rx_fast_forwarded;
		total_stats.pkts_tx_cloned += per_cpu_stats->pkts_tx_cloned;
		total_stats.pkts_tx_no_head += per_cpu_stats->pkts_tx_no_head;
		total_stats.pkts_tx_non_linear += per_cpu_stats->pkts_tx_non_linear;
		total_stats.pkts_tx_realign += per_cpu_stats->pkts_tx_realign;
		total_stats.pkts_tx_sg += per_cpu_stats->pkts_tx_sg;
		total_stats.pkts_tx_copied += per_cpu_stats->pkts_tx_copied;
		total_stats.pkts_tx_route += per_cpu_stats->pkts_tx_route;
		total_stats.pkts_tx_bridge += per_cpu_stats->pkts_tx_bridge;
		total_stats.pkts_direct_rx += per_cpu_stats->pkts_direct_rx;
		total_stats.pkts_rx_ipsec += per_cpu_stats->pkts_rx_ipsec;
		total_stats.pkts_oh_buf_threshold_drop += per_cpu_stats->pkts_oh_buf_threshold_drop;
		total_stats.pkts_slow_path_drop += per_cpu_stats->pkts_slow_path_drop;
	}

	len += sprintf(buf, "VAP (id : %d  name : %s)\n",ii,priv->vaps[ii].ifname);
	len += sprintf(buf + len, "\nTo DPAA\n");
	len += sprintf(buf + len, "  WiFi Rx pkts from route hook : %u\n", total_stats.pkts_tx_route);
	len += sprintf(buf + len, "  WiFi Rx pkts from bridge hook : %u\n", total_stats.pkts_tx_bridge);
	len += sprintf(buf + len, "  WiFi Rx pkts from direct rx : %u\n", total_stats.pkts_direct_rx);
	len += sprintf(buf + len, "  WiFi Rx pkts submitted to DPAA : %u\n", total_stats.pkts_transmitted);
	len += sprintf(buf + len, "  WiFi local Tx pkts submitted to DPAA : %u\n", total_stats.pkts_local_tx_dpaa);
	len += sprintf(buf + len, "  Drops while sending it to DPAA : %u\n", total_stats.pkts_tx_dropped);
	len += sprintf(buf + len, "  WiFI OH buf threshold Drops : %u\n", total_stats.pkts_oh_buf_threshold_drop);
	len += sprintf(buf + len, "  No head room|non linear|cloned|realign - %x : %x : %x : %x\n", total_stats.pkts_tx_no_head, total_stats.pkts_tx_non_linear, total_stats.pkts_tx_cloned, total_stats.pkts_tx_realign);

	len += sprintf(buf + len, "  Paged SG submissions : %u\n", total_stats.pkts_tx_sg);
	len += sprintf(buf + len, "  Copies for private/unsupported layouts : %u\n", total_stats.pkts_tx_copied);

	len += sprintf(buf + len, "From DPAA\n");
	len += sprintf(buf + len, "  WiFi Rx pkts : %u \n", total_stats.pkts_slow_forwarded);
	len += sprintf(buf + len, "  WiFi Tx pkts : %u \n", total_stats.pkts_rx_fast_forwarded);
	len += sprintf(buf + len, "  WiFi Tx ipsec pkts : %u\n", total_stats.pkts_rx_ipsec);
	len += sprintf(buf + len, "  WiFI Rx slow path drops : %u\n", total_stats.pkts_slow_path_drop);

	return len;
}

/** vwd_show_dump_stats
 *
 */
static ssize_t vwd_show_dump_stats(struct device *dev, struct device_attribute *attr, char *buf)
{
	ssize_t len = 0;
	struct dpaa_vwd_priv_s *priv = &vwd;
	unsigned int total_num_tx_done;
	//int ii;
	struct vwd_global_stats_s *per_cpu_stats;
	struct vwd_global_stats_s total_stats;
	int i;

	memset(&total_stats, 0, sizeof(struct vwd_global_stats_s));
	for_each_possible_cpu(i) {
		per_cpu_stats = per_cpu_ptr(priv->vwd_global_stats, i);
		total_stats.pkts_total_local_tx += per_cpu_stats->pkts_total_local_tx;
		total_stats.pkts_slow_fail += per_cpu_stats->pkts_slow_fail;
		total_stats.pkts_dev_down_drop += per_cpu_stats->pkts_dev_down_drop;
		total_stats.pkts_tx_errors += per_cpu_stats->pkts_tx_errors;
	}

	len += sprintf(buf + len, "\nStatus\n");
	len += sprintf(buf + len, "  Fast path - %s\n", priv->fast_path_enable ? "Enable" : "Disable");
	percpu_var_sum(num_tx_done, total_num_tx_done);
	len += sprintf(buf + len, "  tx_sent:done  %u:%u\n", num_tx_sent, total_num_tx_done);
	len += sprintf(buf + len, "  Hardware-owned frames : %d\n",
			atomic_read(&vwd_tx_pending));

	len += sprintf(buf + len, "\nTo DPAA\n");
	len += sprintf(buf + len, "  WiFi local Tx pkts : %u\n", total_stats.pkts_total_local_tx);

	len += sprintf(buf + len, "From DPAA\n");
	len += sprintf(buf + len, "  Hardware/enqueue errors : %u\n", total_stats.pkts_tx_errors);
	len += sprintf(buf + len, "  WiFI Rx Fails : %u\n", total_stats.pkts_slow_fail);
	len += sprintf(buf + len, "  WiFI Device Down Drops : %u\n", total_stats.pkts_dev_down_drop);

	return len;
}


/** vwd_show_fast_path_enable
 *
 */
static ssize_t vwd_show_fast_path_enable(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct dpaa_vwd_priv_s *priv = &vwd;
	int idx;

	idx = sprintf(buf, "\n%d\n", priv->fast_path_enable);
	return idx;
}

/** vwd_set_fast_path_enable
 *
 */
static ssize_t vwd_set_fast_path_enable(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	struct dpaa_vwd_priv_s  *priv = &vwd;
	unsigned int fast_path = 0;

	sscanf(buf, "%d", &fast_path);
	if (fast_path && !priv->fast_path_enable)
	{
		DPAWIFI_INFO("%s: Wifi fast path enabled \n", __func__);
		priv->fast_path_enable = 1;
	}
	else if (!fast_path && priv->fast_path_enable)
	{
		DPAWIFI_INFO("%s: Wifi fast path disabled \n", __func__);
		priv->fast_path_enable = 0;
	}
	return count;
}

/** vwd_show_oh_buff_limit
 *
 */
static ssize_t vwd_show_oh_buff_limit(struct device *dev, struct device_attribute *attr, char *buf)
{
	int idx;

	idx = sprintf(buf, "\n%d\n", oh_buff_limit);
	return idx;
}

/** vwd_set_oh_buff_limit
 *
 */
static ssize_t vwd_set_oh_buff_limit(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	int buff_limit = 0;

	sscanf(buf, "%d", &buff_limit);
	if (buff_limit <= 0)
	{
		DPAWIFI_INFO("%s: Invalid buff limit value \n", __func__);
	}
	oh_buff_limit = buff_limit;
	return count;
}


/** dpaa_vwd_sysfs_init
 *
 */
static int dpaa_vwd_sysfs_init( struct dpaa_vwd_priv_s *priv )
{

	if (device_create_file(priv->vwd_device, &dev_attr_vwd_debug_stats))
		goto err_dbg_sts;

	if (device_create_file(priv->vwd_device, &dev_attr_vwd_fast_path_enable))
		goto err_fp_en;


	if (device_create_file(priv->vwd_device, &dev_attr_vwd_oh_buff_limit))
		goto err_oh_buff_limit;
	return 0;
err_oh_buff_limit:


	device_remove_file(priv->vwd_device, &dev_attr_vwd_fast_path_enable);
err_fp_en:
	device_remove_file(priv->vwd_device, &dev_attr_vwd_debug_stats);
err_dbg_sts:
	return -1;

}

/** dpaa_vwd_sysfs_exit
 *
 */
static void dpaa_vwd_sysfs_exit(void)
{
	struct dpaa_vwd_priv_s *priv = &vwd;


	device_remove_file(priv->vwd_device, &dev_attr_vwd_oh_buff_limit);
	device_remove_file(priv->vwd_device, &dev_attr_vwd_fast_path_enable);
	device_remove_file(priv->vwd_device, &dev_attr_vwd_debug_stats);
}

/* This function returns 1 if the packet is not supported
	 in fast path */
static int vwd_unsupported_eth_packet(struct sk_buff* skb)
{
	unsigned char* data_ptr;
	int length;
	/* Move to packet network header */
	data_ptr = skb_mac_header(skb);
	length = skb->len + (skb->data - data_ptr);
	/* Broadcasts and MC are handled by stack */
	if((eth_hdr(skb)->h_dest[0] & 0x1) || ( length <= ETH_HLEN ) )
	{
		return 1;
	}
	/* Jambo frames are not supported, will be handled by stack */
	if (length > ETH_FRAME_LEN || skb_is_gso(skb))
	{
		DPAWIFI_INFO(KERN_INFO "%s:%d frame len:%d is bigger. Disable LRO/GRO on %s\n", __func__, __LINE__, length, skb->dev->name);
		return 1;
	}

	return 0;
}

/* This function returns 1 if the routed packet is not offloaded and sent to stack
	 and 0 for all packets sent to fast past , only routed packets are handled here*/
static int vwd_classify_route_packet( struct dpaa_vwd_priv_s *priv,struct sk_buff **skb_in, int *vapid)
{
	int rc = 1;	
	struct sk_buff *skb = *skb_in;
	struct vap_desc_s *vap;
	unsigned char hdroom_realloced = 0;

	spin_lock_bh(&priv->vaplock);
	/* getting vap structure from netdev pointer */
	vap = (struct vap_desc_s*)skb->dev->wifi_offload_dev;

	/* when a packet is received on other than wifi fastpath devices,
	 * vap can be NULL
	 */
	/* All bridge packets are handled in bridge hook  and bridge 
		 device should not have wifi_offloade_dev set*/
	if (!vap) 
		goto done;

	if (vap->ifindex != skb->skb_iif)
		goto done;

	/* packets sent to DPAA and returned from DPAA with no entry 
		 should be given to host */
	if (skb->expt_pkt == 1)
	{
		skb->expt_pkt = 0;
		goto done;
	}
	*vapid = vap->vapid;

	/* handle packets with NO L2 header */
	if (vap->no_l2_itf)
	{
		spin_unlock_bh(&priv->vaplock);
		if (dpa_add_dummy_eth_hdr(skb_in, priv->eth_priv->tx_headroom, &hdroom_realloced)  < 0 )
			return 1;

		skb = *skb_in;

		if (hdroom_realloced) {
			INCR_PER_CPU_STAT(vap->vap_stats, pkts_tx_no_head);
		}
		return 0;
	}

	if (vwd_unsupported_eth_packet(skb))
		goto done;

	if (skb->protocol != ntohs(ETH_P_IP) && skb->protocol != ntohs(ETH_P_IPV6))
		goto done;

	rc = 0; /* Success */
done:
	spin_unlock_bh(&priv->vaplock);
	return rc;
}

/* This fucntion returns l3_protocol from ethennet packet */
static void vwd_get_l3_proto(struct sk_buff* skb, unsigned short* l3_proto)
{
	unsigned short type = 0;
	unsigned char* data_ptr;
	struct ethhdr* hdr;

	data_ptr = skb_mac_header(skb);

	hdr = (struct ethhdr *)data_ptr;

	type = htons(hdr->h_proto);
	data_ptr += ETH_HLEN;

	if( type == ETH_P_8021Q )
	{
		struct vlan_hdr *vhdr = (struct vlan_hdr *)data_ptr;
		data_ptr += VLAN_HLEN;
		type = htons(vhdr->h_vlan_encapsulated_proto);
	}
	if( type == ETH_P_PPP_SES )
	{
		struct pppoe_hdr *phdr = (struct pppoe_hdr *)data_ptr;
		if (htons(*(u16 *)(phdr+1)) == PPP_IP)
			type = ETH_P_IP;
		else if (htons(*(u16 *)(phdr+1)) == PPP_IPV6)
			type = ETH_P_IPV6;
	}

	*l3_proto = type;
}

/* This function processes all bridge packets , and send supported
	 bridge packets to DPAA for lookup and fast forwarding */
static int vwd_classify_bridge_packet( struct dpaa_vwd_priv_s *priv,struct sk_buff *skb, int *vapid)
{
	int rc = 1;
	struct vap_desc_s *vap;
	unsigned short l3_proto;
	spin_lock_bh(&priv->vaplock);
	vap = (struct vap_desc_s*)skb->dev->wifi_offload_dev;

	/* when a packet is received on other than wifi fastpath devices,
	 * vap can be NULL
	 */
	if (!vap)
		goto done;

	if (vap->ifindex != skb->skb_iif)
		goto done;

	*vapid = vap->vapid;
	/* packets sent to DPAA and returned from DPAA with no entry 
		 should be given to host */
	if (skb->expt_pkt == 1)
	{
		skb->expt_pkt = 0;
		goto done;
	}


	if (vwd_unsupported_eth_packet(skb))
		goto done;


	if (skb->pkt_type == PACKET_HOST)
	{
		vwd_get_l3_proto(skb, &l3_proto);
		if (l3_proto != ETH_P_IP && l3_proto != ETH_P_IPV6)
			goto done;
	}
	/*WiFi management packets received with dst address as bssid*/
	else if (!memcmp(vap->macaddr, eth_hdr(skb)->h_dest, ETH_ALEN))
	{
		goto done;
	}

	rc = 0;
done:
	spin_unlock_bh(&priv->vaplock);
	return rc;

}


static unsigned int dpaa_vwd_nf_bridge_hook_fn( void *ops, //const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	struct dpaa_vwd_priv_s *priv = &vwd;
	int vapid = -1;

	if (!priv->fast_path_enable)
		goto done;

	if( !vwd_classify_bridge_packet(priv,skb,&vapid) )
	{
#ifdef DPA_WIFI_DEBUG
		DPAWIFI_INFO("%s: Accepted devname : %s \n", __func__,skb->dev->name);
#endif
		INCR_PER_CPU_STAT(priv->vaps[vapid].vap_stats, pkts_tx_bridge);
		skb_push(skb, ETH_HLEN);
		spin_lock_bh(&priv->txlock);
		dpaa_vwd_send_packet( priv, &priv->vaps[vapid], skb);
		spin_unlock_bh(&priv->txlock);
		return NF_STOLEN;
	}
done:
	return NF_ACCEPT;
}

/** vwd_nf_route_hook_fn
 *
 */
static unsigned int dpaa_vwd_nf_route_hook_fn( void *ops, //const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	struct dpaa_vwd_priv_s *priv = &vwd;
	int vapid = -1;

	if (!priv->fast_path_enable)
		goto done;
	if( !vwd_classify_route_packet(priv, &skb, &vapid) )
	{
#ifdef DPA_WIFI_DEBUG
		DPAWIFI_INFO("%s: Accepted devname : %s \n", __func__,skb->dev->name);
#endif
		INCR_PER_CPU_STAT(priv->vaps[vapid].vap_stats, pkts_tx_route);
		skb_push(skb, ETH_HLEN);
		spin_lock_bh(&priv->txlock);
		dpaa_vwd_send_packet( priv, &priv->vaps[vapid], skb);
		spin_unlock_bh(&priv->txlock);
		return NF_STOLEN;
	}
done:
	return NF_ACCEPT;
}


struct vwd_dma_mapping {
	dma_addr_t addr;
	unsigned int size;
	unsigned int page_offset;
	struct page *page;
};

/* Completion in BMan returns only the buffer address, not the FD. Keep
 * ownership and the original mappings before the DMA area, on separate
 * cache lines. Never use hardware-writable SG entries to unmap a frame.
 */
struct vwd_tx_buffer {
	struct sk_buff *skb;
	struct net_device *dev;
	struct vap_desc_s *vap;
	u32 generation;
	unsigned int size;
	unsigned int num_maps;
	bool page_allocated;
	struct vwd_dma_mapping maps[DPA_SGT_MAX_ENTRIES];
	u8 buffer[] __aligned(SMP_CACHE_BYTES);
};

static void vwd_free_tx_buffer(struct vwd_tx_buffer *tx)
{
	dev_put(tx->dev);
	if (tx->page_allocated)
		free_page((unsigned long)tx);
	else
		kfree(tx);
}

static void vwd_complete_tx_buffer(struct vwd_tx_buffer *tx)
{
	vwd_free_tx_buffer(tx);
	get_cpu_var(num_tx_done)++;
	put_cpu_var(num_tx_done);
	atomic_dec(&vwd_tx_pending);
}

static void vwd_unmap_payload(struct dpa_bp *bp, struct vwd_tx_buffer *tx)
{
	unsigned int i;

	for (i = 0; i < tx->num_maps; i++) {
		struct vwd_dma_mapping *map = &tx->maps[i];

		if (map->page)
			dma_unmap_page(bp->dev, map->addr, map->size,
				       DMA_BIDIRECTIONAL);
		else
			dma_unmap_single(bp->dev, map->addr, map->size,
					 DMA_BIDIRECTIONAL);
	}
}

static struct vwd_tx_buffer *vwd_unmap_tx_buffer(struct dpa_bp *bp,
					       dma_addr_t addr)
{
	/* Like the surrounding DPAA SDK, this path uses direct DMA addresses. */
	struct vwd_tx_buffer *tx = (void *)((u8 *)phys_to_virt(addr) -
					offsetof(struct vwd_tx_buffer, buffer));

	dma_unmap_single(bp->dev, addr, tx->size, DMA_BIDIRECTIONAL);
	vwd_unmap_payload(bp, tx);
	return tx;
}

static int vwd_skb_to_sg_fd(struct dpaa_vwd_priv_s *priv, struct sk_buff *skb,
			  struct vap_desc_s *vap, u32 generation, struct qm_fd *fd)
{
	struct dpa_bp *bp = priv->txconf_bp;
	unsigned int offset = priv->eth_priv->tx_headroom;
	unsigned int size = ALIGN(offset + DPA_SGT_SIZE, SMP_CACHE_BYTES);
	unsigned int alloc_size = sizeof(struct vwd_tx_buffer) + size;
	struct vwd_tx_buffer *tx;
	struct qm_sg_entry *sgt;
	struct vwd_dma_mapping *map;
	dma_addr_t addr;
	unsigned int i;
	bool page_allocated = false;

	BUILD_BUG_ON(DPA_SGT_SIZE < DPA_SGT_MAX_ENTRIES * sizeof(*sgt));
	if (WARN_ON_ONCE(offset > DPA_MAX_FD_OFFSET ||
			 skb_shinfo(skb)->nr_frags >= DPA_SGT_MAX_ENTRIES))
		return -EINVAL;

#ifdef FM_ERRATUM_A050385
	page_allocated = fm_has_errata_a050385();
#endif
	if (page_allocated) {
		if (WARN_ON_ONCE(alloc_size > PAGE_SIZE))
			return -EINVAL;
		tx = (void *)get_zeroed_page(GFP_ATOMIC);
	} else {
		tx = kzalloc(alloc_size, GFP_ATOMIC);
	}
	if (!tx)
		return -ENOMEM;
	tx->skb = skb;
	tx->dev = skb->dev;
	dev_hold(tx->dev);
	tx->vap = vap;
	tx->generation = generation;
	tx->size = size;
	tx->page_allocated = page_allocated;
	sgt = (void *)(tx->buffer + offset);

	/* Map the whole writable head, but describe only its packet data.
	 * The SG address includes headroom; neither the 9-bit FD offset nor
	 * the 13-bit SG offset has to encode the skb's headroom.
	 */
	map = &tx->maps[0];
	map->size = skb_end_pointer(skb) - skb->head;
	map->addr = dma_map_single(bp->dev, skb->head, map->size,
				   DMA_BIDIRECTIONAL);
	if (dma_mapping_error(bp->dev, map->addr))
		goto unmap;
	tx->num_maps++;
	qm_sg_entry_set64(&sgt[0], map->addr + skb_headroom(skb));
	qm_sg_entry_set_len(&sgt[0], skb_headlen(skb));
	qm_sg_entry_set_bpid(&sgt[0], 0xff);

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		const skb_frag_t *frag = &skb_shinfo(skb)->frags[i];

		map = &tx->maps[i + 1];
		map->page = skb_frag_page(frag);
		map->page_offset = skb_frag_off(frag);
		map->size = skb_frag_size(frag);
		map->addr = skb_frag_dma_map(bp->dev, frag, 0, map->size,
					     DMA_BIDIRECTIONAL);
		if (dma_mapping_error(bp->dev, map->addr))
			goto unmap;
		tx->num_maps++;
		qm_sg_entry_set64(&sgt[i + 1], map->addr);
		qm_sg_entry_set_len(&sgt[i + 1], map->size);
		qm_sg_entry_set_bpid(&sgt[i + 1], 0xff);
	}
	qm_sg_entry_set_final(&sgt[tx->num_maps - 1], 1);

	/* FMan also writes parse results into this prefix. */
	addr = dma_map_single(bp->dev, tx->buffer, tx->size,
			      DMA_BIDIRECTIONAL);
	if (dma_mapping_error(bp->dev, addr))
		goto unmap;
	fd->format = qm_fd_sg;
	fd->bpid = bp->bpid;
	fd->offset = offset;
	fd->length20 = skb->len;
	qm_fd_addr_set64(fd, addr);
	return 0;

unmap:
	vwd_unmap_payload(bp, tx);
	vwd_free_tx_buffer(tx);
	return -ENOMEM;
}

/* Locate a returned segment in the original DMA mappings before reading it.
 * Hardware may adjust descriptors when it changes packet headers.
 */
static int vwd_sg_mapping(struct vwd_tx_buffer *tx, const struct qm_sg_entry *sg,
			 unsigned int *offset)
{
	dma_addr_t addr = qm_sg_addr(sg) + qm_sg_entry_get_offset(sg);
	unsigned int len = qm_sg_entry_get_len(sg);
	unsigned int i;

	if (qm_sg_entry_get_ext(sg) || !len)
		return -EINVAL;
	for (i = 0; i < tx->num_maps; i++) {
		struct vwd_dma_mapping *map = &tx->maps[i];

		if (addr >= map->addr && addr - map->addr <= map->size &&
		    len <= map->size - (addr - map->addr)) {
			*offset = addr - map->addr;
			return i;
		}
	}
	return -EINVAL;
}

static void vwd_copy_segment(struct vwd_tx_buffer *tx, unsigned int index,
			     unsigned int offset, u8 *dst, unsigned int len)
{
	struct vwd_dma_mapping *map = &tx->maps[index];

	if (!map->page) {
		memcpy(dst, tx->skb->head + offset, len);
		return;
	}
	offset += map->page_offset;
	while (len) {
		struct page *page = nth_page(map->page, offset >> PAGE_SHIFT);
		unsigned int off = offset_in_page(offset);
		unsigned int count = min(len, (unsigned int)PAGE_SIZE - off);
		void *src = kmap_local_page(page);

		memcpy(dst, src + off, count);
		kunmap_local(src);
		dst += count;
		offset += count;
		len -= count;
	}
}

static struct sk_buff *vwd_tx_fd_to_skb(const struct qm_fd *fd,
				      struct vwd_tx_buffer **owner)
{
	struct vwd_tx_buffer *tx = vwd_unmap_tx_buffer(vwd.txconf_bp,
						     qm_fd_addr(fd));
	struct sk_buff *skb = tx->skb, *nskb = NULL;
	unsigned int off = dpa_fd_offset(fd), total = 0, count = 0, i;
	struct qm_sg_entry *sgt;
	bool unchanged = true;

	/* The caller retains the device reference through delivery or drop. */
	*owner = tx;
	if (fd->format != qm_fd_sg || off > tx->size - DPA_SGT_SIZE)
		goto drop;
	sgt = (void *)(tx->buffer + off);
	for (i = 0; i < DPA_SGT_MAX_ENTRIES; i++) {
		unsigned int offset, len = qm_sg_entry_get_len(&sgt[i]);
		int index = vwd_sg_mapping(tx, &sgt[i], &offset);

		if (index < 0 || total > dpa_fd_length(fd) ||
		    len > dpa_fd_length(fd) - total)
			goto drop;
		if (index != i || offset != (i ? 0 : skb_headroom(skb)) ||
		    len != (i ? tx->maps[index].size : skb_headlen(skb)))
			unchanged = false;
		total += len;
		if (qm_sg_entry_get_final(&sgt[i])) {
			count = i + 1;
			break;
		}
	}
	if (!count || total != dpa_fd_length(fd) || total < ETH_HLEN ||
	    total > ETH_FRAME_LEN + SKB_ASK_TAILROOM)
		goto drop;
	if (unchanged && count == tx->num_maps && total == skb->len) {
		return skb;
	}

	/* Preserve a hardware-modified layout, including Wi-Fi-to-Wi-Fi
	 * forwarding. Ordinary exceptions retain their original nonlinear skb.
	 */
	nskb = alloc_skb(NET_SKB_PAD + NET_IP_ALIGN + total, GFP_ATOMIC);
	if (!nskb)
		goto drop;
	skb_reserve(nskb, NET_SKB_PAD + NET_IP_ALIGN);
	skb_copy_header(nskb, skb);
	skb_headers_offset_update(nskb, skb_headroom(nskb) - skb_headroom(skb));
	for (i = 0; i < count; i++) {
		unsigned int offset, len = qm_sg_entry_get_len(&sgt[i]);
		int index = vwd_sg_mapping(tx, &sgt[i], &offset);

		vwd_copy_segment(tx, index, offset, skb_put(nskb, len), len);
	}
	skb_reset_mac_header(nskb);
	skb_set_network_header(nskb, ETH_HLEN);
	skb_reset_transport_header(nskb);
	/* A changed layout invalidates receive checksum metadata. */
	nskb->ip_summed = CHECKSUM_NONE;
	nskb->csum = 0;
drop:
	dev_kfree_skb_any(skb);
	return nskb;
}

static void vwd_release_tx_frame(const struct qm_fd *fd)
{
	struct vwd_tx_buffer *tx = vwd_unmap_tx_buffer(vwd.txconf_bp,
						     qm_fd_addr(fd));

	dev_kfree_skb_any(tx->skb);
	vwd_complete_tx_buffer(tx);
}

static void vwd_ern(struct qman_portal *portal, struct qman_fq *fq,
		    const struct qm_mr_entry *msg)
{
	INCR_PER_CPU_STAT(vwd.vwd_global_stats, pkts_tx_errors);
	vwd_release_tx_frame(&msg->ern.fd);
}

/* This function converts the fd from ipsec  and frag bufferpool to skb */
static struct sk_buff* sec_frag_fd_to_vwd_skb(const struct qm_dqrr_entry *dq, struct dpa_bp* dpa_bp)
{
	uint8_t *ptr, *skb_ptr;
	uint32_t len;
	struct sk_buff *skb;
	struct bm_buffer bmb;

	len = dq->fd.length20;
	ptr = (uint8_t *)(phys_to_virt((uint64_t)dq->fd.addr) + dq->fd.offset);

	skb = dev_alloc_skb(len + dq->fd.offset + 32);
	if (!skb) {
		DPAWIFI_ERROR("%s::skb alloc failed\n", __func__);
		return NULL;
	}
	skb_reserve(skb, dq->fd.offset);
	skb_ptr = skb_put(skb, len);
	memcpy(skb_ptr, ptr, len);

	/* Release FD */
	bmb.bpid = dq->fd.bpid;
	bmb.addr = dq->fd.addr;
	while (bman_release(dpa_bp->pool, &bmb, 1, 0))
		cpu_relax();

	return skb;
}

static struct sk_buff *__hot contig_fd_to_vwd_skb(const struct dpa_priv_s *priv,
		const struct qm_fd *fd)
{
	struct dpa_bp *dpa_bp;
	dma_addr_t addr;
	void *vaddr;
	struct sk_buff *skb;
	struct sk_buff **skbh;
	ssize_t fd_off;

	dpa_bp = dpa_bpid2pool(fd->bpid);
	if (!dpa_bp) {
		DPAWIFI_ERROR("%s::invalid buffer pool id %d\n", __func__, fd->bpid);
		return NULL;
	}
	//get phys addressa and virt address
	addr = qm_fd_addr(fd);
	vaddr = phys_to_virt(addr);
	fd_off = dpa_fd_offset(fd);

	dma_unmap_single(dpa_bp->dev, addr, dpa_bp->size,
			 DMA_BIDIRECTIONAL);
	DPA_READ_SKB_PTR(skb, skbh, vaddr, -1);
	if (!skb)
		return NULL;

#ifdef DPA_WIFI_DEBUG
	if (fd_off > priv->rx_headroom) {
		DPAWIFI_ERROR("%s:: no headroom %d:%d\n", __func__, (int)fd_off, priv->rx_headroom);
		//return NULL;
	}	
#endif

	/* The Ethernet pool uses the SDK's truesize accounting. */
#ifdef FM_ERRATUM_A050385
	if (likely(!fm_has_errata_a050385())) {
#else
	if (likely(!dpaa_errata_a010022)) {
#endif
		skb->truesize = SKB_TRUESIZE(dpa_fd_length(fd));
	}
	skb->data = vaddr;
	skb->len = 0;
	skb_reset_tail_pointer(skb);
	skb_reserve(skb, fd_off);
	skb_put(skb, dpa_fd_length(fd));
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s::skb:%p head %p data %p headroom %d\n", 
			__func__, skb, skb->head, skb->data, skb_headroom(skb));
	DPAWIFI_INFO("%s::skb:len %d tail %d end %d\n", __func__, skb->len, skb->tail, skb->end);
#endif
	return skb;

}

static int dpaa_vwd_send_packet(struct dpaa_vwd_priv_s *priv, void *vap_handle,
				struct sk_buff *skb)
{
	struct vap_desc_s *vap = vap_handle;
	struct qm_fd fd;
	struct sk_buff *nskb;
	unsigned int total_num_tx_done;
	u32 generation;
	bool copy = skb_cloned(skb) || skb_shared(skb) || skb_zcopy(skb) ||
		    skb_has_shared_frag(skb) || skb_has_frag_list(skb) ||
		    skb_shinfo(skb)->nr_frags >= DPA_SGT_MAX_ENTRIES ||
		    skb_headlen(skb) < ETH_HLEN ||
		    skb->ip_summed == CHECKSUM_PARTIAL;
	int err, i;

	/* Classification and submission are separate critical sections. */
	spin_lock(&priv->vaplock);
	if (vwd_stopping || vap->state != VAP_ST_OPEN ||
	    (void *)READ_ONCE(skb->dev->wifi_offload_dev) != vap) {
		spin_unlock(&priv->vaplock);
		goto drop;
	}
	generation = vap->generation;
	spin_unlock(&priv->vaplock);

	percpu_var_sum(num_tx_done, total_num_tx_done);
	if (num_tx_sent - total_num_tx_done >= (VAP_TX_CONF_BUF_COUNT >> 4))
		drain_bp_tx_done_bpool(priv->txconf_bp);

	percpu_var_sum(num_tx_done, total_num_tx_done);
	if (num_tx_sent - total_num_tx_done > oh_buff_limit) {
		INCR_PER_CPU_STAT(vap->vap_stats, pkts_oh_buf_threshold_drop);
		goto free_skb;
	}

	if (skb->len < ETH_HLEN || skb->len > ETH_FRAME_LEN + SKB_ASK_TAILROOM)
		goto drop;
	if (skb_is_nonlinear(skb))
		INCR_PER_CPU_STAT(vap->vap_stats, pkts_tx_non_linear);
	if (skb_cloned(skb) || skb_shared(skb))
		INCR_PER_CPU_STAT(vap->vap_stats, pkts_tx_cloned);

	/* FMan can write packet headers. Keep private, representable page
	 * fragments in place; copy shared data and layouts beyond its table.
	 */
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		const skb_frag_t *frag = &skb_shinfo(skb)->frags[i];

		if (!skb_frag_size(frag) || page_count(skb_frag_page(frag)) != 1)
			copy = true;
	}
	if (copy) {
		nskb = skb_copy_expand(skb, priv->eth_priv->tx_headroom,
				       SKB_ASK_TAILROOM, GFP_ATOMIC);
		if (!nskb)
			goto drop;
		dev_kfree_skb(skb);
		skb = nskb;
		INCR_PER_CPU_STAT(vap->vap_stats, pkts_tx_copied);
	}

#ifdef FM_ERRATUM_A050385
	if (unlikely(fm_has_errata_a050385()) &&
	    a050385_check_skb(skb, priv->eth_priv)) {
		INCR_PER_CPU_STAT(vap->vap_stats, pkts_tx_realign);
		nskb = a050385_realign_skb(skb, priv->eth_priv);
		if (!nskb)
			goto drop;
		dev_kfree_skb(skb);
		skb = nskb;
	}
#endif

	if (skb->ip_summed == CHECKSUM_PARTIAL && skb_checksum_help(skb))
		goto drop;

	clear_fd(&fd);
	err = vwd_skb_to_sg_fd(priv, skb, vap, generation, &fd);
	if (err)
		goto drop;

	if (skb_is_nonlinear(skb))
		INCR_PER_CPU_STAT(vap->vap_stats, pkts_tx_sg);

	atomic_inc(&vwd_tx_pending);
	for (i = 0; i < 100000; i++) {
		err = qman_enqueue(&vap->wlan_fq_to_fman->fq_base, &fd, 0);
		if (err != -EBUSY)
			break;
	}
	if (err < 0) {
		struct vwd_tx_buffer *tx;

		tx = vwd_unmap_tx_buffer(priv->txconf_bp, qm_fd_addr(&fd));
		vwd_free_tx_buffer(tx);
		atomic_dec(&vwd_tx_pending);
		goto drop;
	}

	num_tx_sent++;
	INCR_PER_CPU_STAT(vap->vap_stats, pkts_transmitted);
	queue_delayed_work(system_wq, &vwd_tx_work, msecs_to_jiffies(10));
	return 0;

drop:
	INCR_PER_CPU_STAT(vap->vap_stats, pkts_tx_dropped);
free_skb:
	dev_kfree_skb(skb);
	return -1;
}

static int process_rx_exception_pkt(struct qman_portal *portal, struct qman_fq *fq,
		const struct qm_dqrr_entry *dq)
{
	struct dpaa_vwd_priv_s *priv = &vwd;
	struct sk_buff *skb;
	struct net_device *dev;
	struct vap_desc_s *vap;
	struct vwd_tx_buffer *tx;

#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s::exception packet\n", __func__);
	DPAWIFI_INFO("%s::fqid %x(%d), bpid %d, len %d, offset %d addr %llx status %08x\n", __func__,
			dq->fqid, dq->fqid, dq->fd.bpid, dq->fd.length20,
			dq->fd.offset,  (uint64_t)dq->fd.addr, dq->fd.status);
#endif

	skb = vwd_tx_fd_to_skb(&dq->fd, &tx);

	if (!skb) {
		INCR_PER_CPU_STAT(priv->vwd_global_stats, pkts_slow_fail);
		DPAWIFI_ERROR("%s::unable to get skb pointer for fd\n", __func__);
		goto rel_fd;
	}

	dev = tx->dev;
	vap = tx->vap;
	/* A completion may outlive removal and re-registration of its VAP. */
	if (READ_ONCE(vap->state) != VAP_ST_OPEN ||
	    READ_ONCE(vap->generation) != tx->generation ||
	    (void *)READ_ONCE(dev->wifi_offload_dev) != vap ||
	    READ_ONCE(dev->reg_state) != NETREG_REGISTERED) {
		INCR_PER_CPU_STAT(priv->vwd_global_stats, pkts_dev_down_drop);
		dev_kfree_skb(skb);
		goto rel_fd;
	}
	if (!vap->no_l2_itf)
	{
		skb->protocol = eth_type_trans(skb, dev);
		skb->expt_pkt = 1;
		if (netif_receive_skb(skb) == NET_RX_DROP) {
#ifdef DPA_WIFI_DEBUG
			DPAWIFI_ERROR("%s::netif_receive_skb:NET_RX_DROP\n", __func__);
#endif
			INCR_PER_CPU_STAT(vap->vap_stats, pkts_slow_path_drop);
		}
	}
	else
	{
		skb_pull(skb, ETH_HLEN);
		skb_reset_network_header(skb);
		skb->mac_len = 0;
		skb->expt_pkt = 1;
		if (netif_rx(skb) == NET_RX_DROP) {
#ifdef DPA_WIFI_DEBUG
			DPAWIFI_ERROR("%s::netif_receive_skb:NET_RX_DROP\n", __func__);
#endif
			INCR_PER_CPU_STAT(vap->vap_stats, pkts_slow_path_drop);
		}
	}
	INCR_PER_CPU_STAT(vap->vap_stats, pkts_slow_forwarded);
rel_fd:
	vwd_complete_tx_buffer(tx);
	return 0;
}

void drain_tx_bp_pool(struct dpa_bp *bp)
{
	int ret, num = 8;

	do {
		struct bm_buffer bmb[8];
		int i;

		ret = bman_acquire(bp->pool, bmb, num, 0);
		if (ret < 0) {
			if (num == 8) {
				/* we have less than 8 buffers left;
				 * drain them one by one
				 */
				num = 1;
				ret = 1;
				continue;
			} else {
				/* Pool is fully drained */
				break;
			}
		}

		for (i = 0; i < num; i++) {
			dma_addr_t addr = bm_buf_addr(&bmb[i]);

			dma_unmap_single(bp->dev, addr, bp->size,
					DMA_BIDIRECTIONAL);

			_dpa_bp_free_pf(phys_to_virt(addr));
		}
	} while (ret > 0);
}


static enum qman_cb_dqrr_result vwd_rx_exception_pkt(struct qman_portal *portal, struct qman_fq *fq,
		const struct qm_dqrr_entry *dq)
{

	struct dpa_priv_s               *priv = vwd.eth_priv;
	struct dpa_percpu_priv_s        *percpu_priv;

	if (!(dq->stat & QM_DQRR_STAT_FD_VALID))
		return qman_cb_dqrr_consume;

	DPA_BUG_ON(priv);
	/* IRQ handler, non-migratable; safe to use raw_cpu_ptr here */
	percpu_priv = raw_cpu_ptr(priv->percpu_priv);

#ifndef CONFIG_FSL_ASK_QMAN_PORTAL_NAPI
	if (unlikely(dpaa_eth_napi_schedule(percpu_priv, portal)))
		return qman_cb_dqrr_stop;
#endif

	process_rx_exception_pkt(portal, fq, dq);	
	return qman_cb_dqrr_consume;
}


static enum qman_cb_dqrr_result vwd_rx_error(struct qman_portal *portal,
		struct qman_fq *fq, const struct qm_dqrr_entry *dq)
{
#ifndef CONFIG_FSL_ASK_QMAN_PORTAL_NAPI
	struct dpa_percpu_priv_s *percpu_priv;
#endif

	if (!(dq->stat & QM_DQRR_STAT_FD_VALID))
		return qman_cb_dqrr_consume;

#ifndef CONFIG_FSL_ASK_QMAN_PORTAL_NAPI
	percpu_priv = raw_cpu_ptr(vwd.eth_priv->percpu_priv);
	if (unlikely(dpaa_eth_napi_schedule(percpu_priv, portal)))
		return qman_cb_dqrr_stop;
#endif
	INCR_PER_CPU_STAT(vwd.vwd_global_stats, pkts_tx_errors);
	vwd_release_tx_frame(&dq->fd);
	return qman_cb_dqrr_consume;
}


static void vwd_send_to_vap(struct sk_buff* skb)
{
	struct ethhdr *hdr;

	hdr = (struct ethhdr *)skb->data;
	skb->protocol = hdr->h_proto;

	skb_reset_mac_header(skb);
	skb_set_network_header(skb, sizeof(struct ethhdr));
	skb->priority = 0;
	original_dev_queue_xmit(skb);
	return;
}

static enum qman_cb_dqrr_result vap_rx_fwd_pkt(struct qman_portal *portal, struct qman_fq *fq,
		const struct qm_dqrr_entry *dq)
{

#ifndef CONFIG_FSL_ASK_QMAN_PORTAL_NAPI
	struct dpa_priv_s               *priv = vwd.eth_priv;
	struct dpa_percpu_priv_s        *percpu_priv;
#endif

	if (!(dq->stat & QM_DQRR_STAT_FD_VALID))
		return qman_cb_dqrr_consume;

#ifndef CONFIG_FSL_ASK_QMAN_PORTAL_NAPI
	DPA_BUG_ON(priv);
	/* IRQ handler, non-migratable; safe to use raw_cpu_ptr here */
	percpu_priv = raw_cpu_ptr(priv->percpu_priv);

	if (unlikely(dpaa_eth_napi_schedule(percpu_priv, portal)))
		return qman_cb_dqrr_stop;
#endif
	process_vap_rx_fwd_pkt(portal, fq, dq);
	return qman_cb_dqrr_consume;
}

static int process_vap_rx_fwd_pkt(struct qman_portal *portal, struct qman_fq *fq, const struct qm_dqrr_entry *dq )
{
	struct dpaa_vwd_priv_s *priv = &vwd;
	struct sk_buff *skb;
	struct net_device *net_dev;
	struct dpa_bp *dpa_bp, *ipsec_bp, *frag_bp;
	struct vap_desc_s *vap; 
	struct vwd_tx_buffer *tx = NULL;
	bool no_l2_itf;
	int *count_ptr;

	dpa_bp = dpa_bpid2pool(dq->fd.bpid);
	if (!dpa_bp) {
		INCR_PER_CPU_STAT(priv->vwd_global_stats, pkts_slow_fail);
		return 0;
	}
	/* The notifier clears these links under vaplock before the device
	 * can be freed. Keep our own reference through dev_queue_xmit().
	 */
	spin_lock_bh(&priv->vaplock);
	net_dev = ((struct dpa_fq *)fq)->net_dev;
	if (net_dev) {
		vap = (void *)READ_ONCE(net_dev->wifi_offload_dev);
		if (!vap || vap->state != VAP_ST_OPEN || !netif_running(net_dev))
			net_dev = NULL;
		else {
			dev_hold(net_dev);
			no_l2_itf = vap->no_l2_itf;
		}
	}
	spin_unlock_bh(&priv->vaplock);
	/*If vap interface is down then fq net_dev is NULL, in this case release the fd.*/
	if (!net_dev)
	{
		if (printk_ratelimit())
			DPAWIFI_ERROR("%s::vap interface is down, releasing the frame from fq %u.\n ", 
							__func__, fq->fqid);
		INCR_PER_CPU_STAT(priv->vwd_global_stats, pkts_dev_down_drop);
		goto rel_fd;
	}
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s::forwarding packet\n", __func__);
	DPAWIFI_INFO("%s::fqid %x(%d), bpid %d, len %d, offset %d netdev %p dev %s addr %llx\n", __func__,
			dq->fqid, dq->fqid, dq->fd.bpid, dq->fd.length20,
			dq->fd.offset, net_dev, net_dev->name, (uint64_t)dq->fd.addr);
#endif
	ipsec_bp = get_ipsec_bp();
	if (dpa_bp == priv->txconf_bp) {
		skb = vwd_tx_fd_to_skb(&dq->fd, &tx);
		goto process_skb;
	}
	/* Other pools retain their Ethernet/IPsec ownership rules. */
	if (dq->fd.format != qm_fd_contig) {
		DPAWIFI_ERROR("%s::TBD discarding SG frame :%d\n ", __func__,dq->fd.format);
		INCR_PER_CPU_STAT(priv->vwd_global_stats, pkts_slow_fail);
		goto rel_fd;
	}

	/* If the packet is recieved from ipsec, then the buffer used is not
	   from ethernet buffer pool or from kernel, so this buffer has to be
	   copied to skb and to be sent to wifi driver, and the buffer from ipsec bufferpool 
	   is released */ 
	/* If the packet is fragmented in fast path, then one of the packet will be received
	   from fragment buffer pool */
	frag_bp  = get_frag_bp();
	if ( (dpa_bp == ipsec_bp) || (dpa_bp == frag_bp) )
	{
		/* Process secure packet transmitted to wifi */
		skb = sec_frag_fd_to_vwd_skb(dq, dpa_bp);
		if (!skb)
			goto rel_fd;
		goto process_skb;
	}
	/* Check if buffer is from ethernet pool to refill buffer pool
	   for wifi packets, buffers are skb buffers and they will get freed to kernel */
	if (dpa_bp != priv->txconf_bp)
	{
		count_ptr = raw_cpu_ptr(vwd.eth_priv->percpu_count);
		if (unlikely(dpaa_eth_refill_bpools(dpa_bp, count_ptr,
				CONFIG_FSL_DPAA_ETH_REFILL_THRESHOLD))) {
			//if we cant refill give this up
			goto rel_fd;
		}
		*count_ptr -= 1;
	}

	skb = contig_fd_to_vwd_skb(priv->eth_priv, &dq->fd);

	if (!skb) {
		INCR_PER_CPU_STAT(priv->vwd_global_stats, pkts_slow_fail);
		DPAWIFI_ERROR("%s::contig_fd_to_vwd_skb failed\n", __func__);
		goto rel_fd;
	}

process_skb:
	if (!skb) {
		INCR_PER_CPU_STAT(priv->vwd_global_stats, pkts_slow_fail);
		goto done;
	}
	skb->dev = net_dev;

	INCR_PER_CPU_STAT(vap->vap_stats, pkts_rx_fast_forwarded);
	if (dpa_bp == ipsec_bp) {
		INCR_PER_CPU_STAT(vap->vap_stats, pkts_rx_ipsec);
	}

	/* check if vap is corresponding to no l2 hdr */
	if (!no_l2_itf)
		vwd_send_to_vap(skb);
	else
	{
		/* Set the protocol before giving it to stack */
		/* skip the ethernet header in skb, then transmit */
		struct ethhdr *hdr;

		hdr = (struct ethhdr *)skb->data;
		skb->protocol = hdr->h_proto;

		skb_pull(skb, ETH_HLEN);
		skb_reset_network_header(skb);
		skb->mac_len = 0;
		skb->priority = 0;
		original_dev_queue_xmit(skb);
	}
done:
	if (tx)
		vwd_complete_tx_buffer(tx);
	if (net_dev)
		dev_put(net_dev);
	return 0;

rel_fd:
	if (dpa_bp == priv->txconf_bp) {
		vwd_release_tx_frame(&dq->fd);
		goto done;
	}
	{
		struct bm_buffer bmb;

		memset(&bmb, 0, sizeof(struct bm_buffer));
		bmb.bpid = dq->fd.bpid;
		bmb.addr = dq->fd.addr;
		while (bman_release(dpa_bp->pool, &bmb, 1, 0))
			cpu_relax();	
	}
	goto done;
}


static int vwd_init_pcd_fqs(struct dpaa_vwd_priv_s *priv)
{
	uint32_t fqbase;
	uint32_t fqcount;
	uint32_t portid;
	uint32_t ii,jj;
	uint32_t portal_channel[NR_CPUS];
	uint32_t num_portals, max_dist;
	uint32_t next_portal_ch_idx = 0;
	const cpumask_t *affine_cpus;
	struct dpa_fq *dpa_fq;
	struct dpa_iface_info *oh_iface_info;
	struct qman_fq *fq;

	/*get cpu portal channel info */
	num_portals = 0;
	next_portal_ch_idx = 0;
	affine_cpus = qman_affine_cpus();
	/* get channel used by portals affined to each cpu */
	for_each_cpu(ii, affine_cpus) {
		portal_channel[num_portals] = qman_affine_channel(ii);
		num_portals++;
	}
	if (!num_portals) {
		DPAWIFI_ERROR("%s::unable to get affined portal info\n", __func__);
		return -1;
	}
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s::num_portals %d ::", __func__, num_portals);
	for (ii = 0; ii < num_portals; ii++)
		DPAWIFI_INFO("%d ", portal_channel[ii]);
	DPAWIFI_INFO("\n");
#endif

	if (get_ofport_max_dist(FMAN_IDX, priv->oh_port_handle, &max_dist) < 0)
	{
		DPAWIFI_ERROR("%s::unable to get distributions for oh port\n", __func__);
		return -1;
	}

	for(jj = 0;jj < max_dist; jj++)
	{

		if (get_oh_port_pcd_fqinfo(FMAN_IDX, priv->oh_port_handle, 
					jj, &fqbase, &fqcount)) {
			DPAWIFI_ERROR("%s::err getting pcd fq\n", __func__) ;
			return -1;
		}
		/*get port id required for FQ creation*/
		if (get_ofport_portid(FMAN_IDX, priv->oh_port_handle, &portid)) {
			DPAWIFI_ERROR("%s::err getting of port id\n", __func__) ;
			return -1;
		}
		DPAWIFI_INFO("%s::pcd FQ base for portid %d  dist %x(%d), count %d\n",
				__func__, portid, fqbase, fqbase, fqcount);

		if ((oh_iface_info = dpa_get_ohifinfo_by_portid(portid)) == NULL) {
			DPAWIFI_ERROR("%s::err getting oh iface info of port id %u\n", __func__, portid) ;
			return -1;
		}
		if (oh_iface_info->pcd_proc_entry == NULL)
		{
			DPAWIFI_ERROR("%s()::%d OH iface pcd proc entry is invalid:\n", __func__, __LINE__);
			return -1;
		}

		/*alloc for as many fqs as required */
		priv->wlan_exception_fq = kzalloc((sizeof(struct dpa_fq) * fqcount), GFP_KERNEL);
		if (!priv->wlan_exception_fq) {
			DPAWIFI_ERROR("%s::err allocating fq mem\n", __func__) ;
			return -1;
		}
		/*save dpa_fq base info */
		dpa_fq = priv->wlan_exception_fq;
		/*add port id into FQID */
		fqbase |= (portid << PORTID_SHIFT_VAL);
		/*create all FQs */
		priv->expt_fq_count = 0;
		for (ii = 0; ii < fqcount; ii++) {
			struct qm_mcc_initfq opts;

			memset(dpa_fq, 0, sizeof(struct dpa_fq));
			/*set FQ parameters 
			  dpa_fq->net_dev = vap->wifi_dev; */
			dpa_fq->fq_type = FQ_TYPE_RX_PCD;
			dpa_fq->fqid = fqbase;
			/*set call back function pointer*/
			fq = &dpa_fq->fq_base;
			fq->cb.dqrr = vwd_rx_exception_pkt;
			/*round robin channel like ethernet driver does */
			dpa_fq->channel = portal_channel[next_portal_ch_idx];
			if (next_portal_ch_idx == (num_portals - 1))
				next_portal_ch_idx = 0;
			else
				next_portal_ch_idx++;
			dpa_fq->wq = DEFA_WQ_ID;
			/*set options similar to ethernet driver */
			memset(&opts, 0, sizeof(struct qm_mcc_initfq));
			opts.fqd.fq_ctrl = (QM_FQCTRL_PREFERINCACHE | QM_FQCTRL_HOLDACTIVE);
			opts.fqd.context_a.stashing.exclusive =
				(QM_STASHING_EXCL_DATA | QM_STASHING_EXCL_ANNOTATION);
			opts.fqd.context_a.stashing.data_cl = NUM_PKT_DATA_LINES_IN_CACHE;
			opts.fqd.context_a.stashing.annotation_cl = NUM_ANN_LINES_IN_CACHE;
			/*create FQ */
			if (qman_create_fq(dpa_fq->fqid, 0, fq)) {
				DPAWIFI_ERROR("%s::qman_create_fq failed for fqid %d\n",
						__func__, dpa_fq->fqid);
				goto err_ret;
			}
			opts.fqid = dpa_fq->fqid;
			opts.count = 1;
			opts.fqd.dest.channel = dpa_fq->channel;
			opts.fqd.dest.wq = dpa_fq->wq;
			opts.we_mask = (QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
					QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA);

			/*init FQ */
			if (qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts)) {
				DPAWIFI_ERROR("%s::qman_init_fq failed for fqid %d\n",
						__func__, dpa_fq->fqid);
				qman_destroy_fq(fq, 0);
				goto err_ret;
			}

			cdx_create_type_fqid_info_in_procfs(fq, PCD_DIR, oh_iface_info->pcd_proc_entry, NULL);
#ifdef DPA_WIFI_DEBUG
			DPAWIFI_INFO("%s::created pcd fq %x(%d) for wlan packets "
					"channel 0x%x\n", __func__,
					dpa_fq->fqid, dpa_fq->fqid, dpa_fq->channel);
#endif
			/*next FQ */
			dpa_fq++;
			fqbase++;
			priv->expt_fq_count++;
		}
	}
	return 0;
err_ret:
	vwd_release_pcd_fqs(priv);
	return -1;
}

static int create_vap_fwd_from_fman_fqs(struct vap_desc_s *vap, void *proc_entry)
{
	uint32_t ii;
	struct dpa_fq *dpa_fq;
	struct qman_fq *fq;
	struct qm_mcc_initfq opts;
	uint32_t portal_channel[NR_CPUS];
	uint32_t num_portals;
	const cpumask_t *affine_cpus;

	/* get cpu portal channel info */
	num_portals = 0;
	affine_cpus = qman_affine_cpus();
	/* get channel used by portals affined to each cpu */
	for_each_cpu(ii, affine_cpus) {
		portal_channel[num_portals] = qman_affine_channel(ii);
		num_portals++;
	}

	if (!num_portals) {
		DPAWIFI_ERROR("%s::unable to get affined portal info\n",
				__func__);
		return -1;
	}

	for (ii = 0; ii < CDX_VWD_FWD_FQ_MAX; ii++) {
		uint32_t flags;

		/* create FQ for forward from DPAA to wireless interface */
		dpa_fq = kzalloc(sizeof(struct dpa_fq), GFP_KERNEL);

		if (!dpa_fq) {
			DPAWIFI_ERROR("%s::unable to alloc mem for dpa_fq\n", __func__) ;
			return -1;
		}
		memset(dpa_fq, 0, sizeof(struct dpa_fq));
		memset(&opts, 0, sizeof(struct qm_mcc_initfq));
		fq = &dpa_fq->fq_base;
		flags = 0;

		/* fwd fq */
		fq->cb.dqrr = vap_rx_fwd_pkt;
		if (cdx_copy_eth_rx_channel_info(FMAN_IDX, dpa_fq)) {
			DPAWIFI_ERROR("%s::unable to get cpu channel info\n", __func__) ;
			kfree(dpa_fq);
			return -1;
		}

		/* opts.fqd.fq_ctrl = (QM_FQCTRL_PREFERINCACHE | QM_FQCTRL_HOLDACTIVE); */
		opts.fqd.context_a.stashing.exclusive =
			(QM_STASHING_EXCL_DATA | QM_STASHING_EXCL_ANNOTATION);
		opts.fqd.context_a.stashing.data_cl = NUM_PKT_DATA_LINES_IN_CACHE;
		opts.fqd.context_a.stashing.annotation_cl = NUM_ANN_LINES_IN_CACHE;
		dpa_fq->fq_type = FQ_TYPE_RX_PCD;
		dpa_fq->wq = DEFA_VWD_WQ_ID;
		dpa_fq->net_dev = vap->wifi_dev;

		if (!dpa_fq->fqid)
			flags |= QMAN_FQ_FLAG_DYNAMIC_FQID;

		if (qman_create_fq(dpa_fq->fqid, flags, fq)) {
			DPAWIFI_ERROR("%s::qman_create_fq failed for fqid %d\n",
					__func__, dpa_fq->fqid);
			kfree(dpa_fq);
			return -1;
		}

		dpa_fq->channel = portal_channel[ii % num_portals];

		dpa_fq->fqid = fq->fqid;
		opts.fqid = dpa_fq->fqid;
		opts.count = 1;
		opts.fqd.dest.channel = dpa_fq->channel;
		opts.fqd.dest.wq = dpa_fq->wq;
		opts.we_mask = (QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
				QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA);
		if (qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts)) {
			DPAWIFI_ERROR("%s::qman_init_fq failed for fqid %d\n",
					__func__, dpa_fq->fqid);
			qman_destroy_fq(fq, 0);
			kfree(dpa_fq);
			return -1;
		}	

		/* TX OH2 */
		cdx_create_type_fqid_info_in_procfs(fq, TX_DIR, proc_entry, NULL);
		vap->wlan_fq_from_fman[ii] = dpa_fq;

#ifdef DPA_WIFI_DEBUG
		DPAWIFI_INFO("%s::created fq %x(%d) for wlan packets "
				"channel 0x%x\n", __func__,
				dpa_fq->fqid, dpa_fq->fqid, dpa_fq->channel);
#endif
	}

	return 0;
}

static int create_vap_fqs(struct vap_desc_s *vap)
{
	//uint32_t ii;
	struct dpa_fq *dpa_fq;
	struct qman_fq *fq;
	struct qm_mcc_initfq opts;
	struct dpa_fq **dpa_fq_ptr;
	struct dpa_iface_info *oh_iface_info;
	uint32_t flags;
	uint32_t portid;


	/*get port id required for FQ creation*/
	if (get_ofport_portid(FMAN_IDX, vap->vwd->oh_port_handle, &portid)) {
		DPAWIFI_ERROR("%s::err getting of port id\n", __func__) ;
		return -1;
	}
	DPAWIFI_INFO("%s:portid %d \n", __func__, portid);

	if ((oh_iface_info = dpa_get_ohifinfo_by_portid(portid)) == NULL) {
		DPAWIFI_ERROR("%s::err getting oh iface info of port id %u\n", __func__, portid) ;
		return -1;
	}
	if (oh_iface_info->tx_proc_entry == NULL)
	{
		DPAWIFI_ERROR("%s()::%d OH iface tx proc entry is invalid:\n", __func__, __LINE__);
		return -1;
	}

	if (create_vap_fwd_from_fman_fqs(vap, oh_iface_info->tx_proc_entry)) {
		DPAWIFI_ERROR("%s::unable to create fwd fqs\n", __func__) ;
		return -1;
	}

	if (oh_iface_info->rx_proc_entry == NULL)
	{
		DPAWIFI_ERROR("%s()::%d OH iface rx proc entry is invalid:\n", __func__, __LINE__);
		return -1;
	}


	/* create FQ for exception packets from wireless interface */
	dpa_fq = kzalloc(sizeof(struct dpa_fq), GFP_KERNEL);
	if (!dpa_fq) {
		DPAWIFI_ERROR("%s::unable to alloc mem for dpa_fq\n", __func__) ;
		return -1;
	}
	memset(dpa_fq, 0, sizeof(struct dpa_fq));
	memset(&opts, 0, sizeof(struct qm_mcc_initfq));
	fq = &dpa_fq->fq_base;
	fq->cb.ern = vwd_ern;
	/* Retirement can return frames that have not reached FMan. */
	fq->cb.dqrr = vwd_rx_error;
	dpa_fq_ptr = NULL;
	flags = 0;
	/* offline port fq */
	flags |= QMAN_FQ_FLAG_TO_DCPORTAL;
	opts.fqd.fq_ctrl = QM_FQCTRL_PREFERINCACHE;
	dpa_fq->channel = vap->channel;
	/* contexta, b  */
	opts.fqd.context_a.hi = 0; //0x12000000; //OVFQ, A2V, OVOM
	opts.fqd.context_a.lo = 0x00000000; //0;
	dpa_fq->fq_type = FQ_TYPE_RX_PCD;
	dpa_fq->wq = DEFA_VWD_WQ_ID;
	dpa_fq->net_dev = vap->wifi_dev;
	if (!dpa_fq->fqid)
		flags |= QMAN_FQ_FLAG_DYNAMIC_FQID;
	if (qman_create_fq(dpa_fq->fqid, flags, fq)) {
		DPAWIFI_ERROR("%s::qman_create_fq failed for fqid %d\n",
				__func__, dpa_fq->fqid);
		kfree(dpa_fq);
		return -1;
	}

	dpa_fq->fqid = fq->fqid;
	opts.fqid = dpa_fq->fqid;
	opts.count = 1;
	opts.fqd.dest.channel = dpa_fq->channel;
	opts.fqd.dest.wq = dpa_fq->wq;
	opts.we_mask = (QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
			QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA);
	if (qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts)) {
		DPAWIFI_ERROR("%s::qman_init_fq failed for fqid %d\n",
				__func__, dpa_fq->fqid);
		qman_destroy_fq(fq, 0);
		kfree(dpa_fq);
		return -1;
	}	

	/* RX OH2 */
	cdx_create_type_fqid_info_in_procfs(fq, RX_DIR, 
				oh_iface_info->rx_proc_entry, NULL);
	vap->wlan_fq_to_fman = dpa_fq;

#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s::created fq %x(%d) for wlan packets "
			"channel 0x%x\n", __func__,
			dpa_fq->fqid, dpa_fq->fqid, dpa_fq->channel);
#endif
	return 0;
}

/* Destroys Frame Queues */
static void vwd_fq_destroy(struct qman_fq *fq)
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
				pr_warn_ratelimited("vwd: cannot retire FQ %u: %d\n",
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
		pr_warn_ratelimited("vwd: cannot take FQ %u out of service: %d\n",
				    fq->fqid, ret);
wait:
		usleep_range(1000, 2000);
	}

	/* The portal updates its FQ state before returning from the callback. */
	synchronize_net();
	cdx_remove_fqid_info_in_procfs(fq->fqid);
	qman_destroy_fq(fq, 0);
}


static int release_vap_fqs(struct vap_desc_s *vap)
{
	int i;
	/* This WLAN exception FQ is used for all vwd interfaces */
	/* TODO - Need to modify to delete only for last interface, and add 
	   for 1st interface */	
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s:: vwd count :%d\n", __func__, vap->vwd->expt_fq_count);
#endif

	for (i = 0; i < CDX_VWD_FWD_FQ_MAX; i++) {
		if (vap->wlan_fq_from_fman[i])
		{
#ifdef DPA_WIFI_DEBUG
			DPAWIFI_INFO("%s:: releasing fq from fman :%d\n", __func__, vap->wlan_fq_from_fman[i]->fqid);
#endif
			vwd_fq_destroy(&vap->wlan_fq_from_fman[i]->fq_base);
			kfree(vap->wlan_fq_from_fman[i]);
			vap->wlan_fq_from_fman[i] = NULL;
		}
	}

	if (vap->wlan_fq_to_fman)
	{
#ifdef DPA_WIFI_DEBUG
		DPAWIFI_INFO("%s:: releasing fq to fman :%d\n", __func__, vap->wlan_fq_to_fman->fqid);
#endif
		vwd_fq_destroy(&vap->wlan_fq_to_fman->fq_base);
		kfree(vap->wlan_fq_to_fman);
		vap->wlan_fq_to_fman = NULL;
	}
	return 0;
}

int dpaa_get_vap_fwd_fq(uint16_t vap_id, uint32_t* fqid, uint32_t hash)
{
	*fqid = vwd.vaps[vap_id].wlan_fq_from_fman[hash & (CDX_VWD_FWD_FQ_MAX - 1)]->fqid;
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s:: fwd_fq :%x\n",__func__, *fqid);
#endif
	return 0;
}

/* This function returns net dev with VAP id */
int dpaa_get_wifi_dev(uint16_t vap_id, void** netdev)
{
	*netdev = (void*)vwd.vaps[vap_id].wifi_dev;
	return 0;
}

/* This function returns  WIFI related OH port handle */
int dpaa_get_wifi_ohport_handle( uint32_t* oh_handle)
{
	*oh_handle = vwd.oh_port_handle;
	return 0;
}

static int add_device_tx_done_bpool(struct dpaa_vwd_priv_s  *vwd)
{
	struct dpa_bp *bp;
	struct dpa_bp *bp_parent;

	if (get_phys_port_poolinfo_bysize(VAPDEV_BUFSIZE, &vwd->parent_pool_info)) {
		DPAWIFI_ERROR("%s::failed to locate eth bman pool for dev %s\n", __func__, vwd->name);
		return -1;
	}
	bp_parent = dpa_bpid2pool(vwd->parent_pool_info.pool_id);
	if (!bp_parent)
		return -ENODEV;

	bp = kzalloc(sizeof(struct dpa_bp), GFP_KERNEL);

	if (unlikely(bp == NULL)) {
		DPAWIFI_ERROR("%s::failed to allocate mem for bman pool for dev %s\n",
				__func__,vwd->name);
		return -1;
	}
	bp->size = VAPDEV_BUFSIZE;
	bp->config_count = VAP_TX_CONF_BUF_COUNT;
	bp->dev = bp_parent->dev;
	if (dpa_bp_alloc(bp, bp->dev)) {
		DPAWIFI_ERROR("%s::dpa_bp_alloc failed for dev %s\n", __func__, vwd->name);
		kfree(bp);
		return -1;
	}
	vwd->txconf_bp = bp;
	printk("%s::txconf bpid %d, for dev %s\n", __func__, bp->bpid, vwd->name);

	return 0;
}

void drain_bp_tx_done_bpool(struct dpa_bp *bp)
{
	int ret, num = 8;


	do {
		struct bm_buffer bmb[8];
		int i;

		ret = bman_acquire(bp->pool, bmb, num, 0);
		if (ret < 0) {
			if (num == 8) {
				/* we have less than 8 buffers left;
				 * drain them one by one
				 */
				num = 1;
				ret = 1;
				continue;
			} else {
				/* Pool is fully drained */
				break;
			}
		}

		for (i = 0; i < num; i++) {
			struct vwd_tx_buffer *tx;

			tx = vwd_unmap_tx_buffer(bp, bm_buf_addr(&bmb[i]));
			dev_kfree_skb_any(tx->skb);
			vwd_complete_tx_buffer(tx);
		}
	} while (ret > 0);

}

/* Hardware may return the last few frames after traffic has stopped.
 * Reclaim them without waiting for another transmit, including the netdev
 * references that otherwise prevent interface unregistration from finishing.
 */
static void vwd_tx_reclaim_work(struct work_struct *work)
{
	spin_lock_bh(&vwd.txlock);
	drain_bp_tx_done_bpool(vwd.txconf_bp);
	if (!vwd_stopping && atomic_read(&vwd_tx_pending))
		queue_delayed_work(system_wq, &vwd_tx_work, msecs_to_jiffies(10));
	spin_unlock_bh(&vwd.txlock);
}

static int release_device_tx_done_bpool(struct dpaa_vwd_priv_s  *vwd)
{
	if (!vwd->txconf_bp)
		return 0;
	drain_bp_tx_done_bpool(vwd->txconf_bp);
	_dpa_bp_free(vwd->txconf_bp);
	kfree(vwd->txconf_bp);
	vwd->txconf_bp = NULL;
	return 0;
}


static int set_vap_fqs_netdev(struct vap_desc_s *vap)
{
	int index = 0;
	for (index = 0; index < CDX_VWD_FWD_FQ_MAX; index++)
		vap->wlan_fq_from_fman[index]->net_dev = vap->wifi_dev;
	vap->wlan_fq_to_fman->net_dev = vap->wifi_dev;
	return 0;
}

/*
 * This function resets the vap fq net_dev to NULL.
 */
static int reset_vap_fqs_netdev(struct vap_desc_s *vap)
{
	int index = 0;
	for (index = 0; index < CDX_VWD_FWD_FQ_MAX; index++)
		vap->wlan_fq_from_fman[index]->net_dev = NULL;
	vap->wlan_fq_to_fman->net_dev = NULL;
	return 0;
}

static int vwd_vap_up(struct dpaa_vwd_priv_s *priv, struct vap_desc_s *vap, struct vap_cmd_s *cmd)
{
	struct net_device *wifi_dev;

	wifi_dev = dev_get_by_name(&init_net, cmd->ifname);
	if (!wifi_dev) {
		DPAWIFI_ERROR("%s::No WiFi device %s\n", 
				__func__, &cmd->ifname[0]);
		return -1;
	}
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s:: wifidev found.. %s\n", __func__, cmd->ifname);
#endif
	if (!(wifi_dev->flags & IFF_UP)) {
		DPAWIFI_ERROR("%s::WiFi device %s not UP\n",
				__func__, &cmd->ifname[0]);
		dev_put(wifi_dev);
		return -1;
	}
	if (get_ofport_info(FMAN_IDX, priv->oh_port_handle, &vap->channel,
				&vap->td[0]))
	{
		dev_put(wifi_dev);
		return -1;
	}

	vap->ifindex = cmd->ifindex;

	vap->no_l2_itf = cmd->no_l2_itf;
	vap->direct_rx_path = cmd->direct_rx_path;
	memcpy(vap->macaddr, cmd->macaddr, ETH_ALEN);
	vap->wifi_dev = wifi_dev;
	vap->vwd = priv;

	/* vap->wlan_fq_to_fman is NULL means so far this interface is not up. If it gets up first time
	   it creates all the frame queues. These frame queues can delete only cdx module gets unloaded.*/
	if (!vap->wlan_fq_to_fman)
	{
		/* create frame queues */
		if (create_vap_fqs(vap)) {
			DPAWIFI_ERROR("%s::unable to create vap fqs for device %s\n",
					__func__, &cmd->ifname[0]);
			release_vap_fqs(vap);
			vap->wifi_dev = NULL;
			dev_put(wifi_dev);
			return -1;
		}
	}
	else
	{
		set_vap_fqs_netdev(vap);
	}

	/* In struct net_device , wifi_offload_dev field is defined,
	 * using this field to store the vap_desc_t structure pointer.
	 * Published only now, after the FQs are live: the ipsec xmit
	 * hook consumes this pointer lock-free, so a release-publish
	 * after the FQ stores is what keeps it from seeing a half-built
	 * VAP. The caller flips vap->state to VAP_ST_OPEN under vaplock.
	 */
	vap->generation++;
	smp_store_release(&wifi_dev->wifi_offload_dev,
			(struct net_device *)vap);

	dev_put(wifi_dev);
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s: UP: name:%s, vapid:%d, direct_rx_path : %s, ifindex:%d, mac:%x:%x:%x:%x:%x:%x\n",
			__func__, vap->ifname, vap->vapid,
			vap->direct_rx_path ? "ON":"OFF", vap->ifindex,
			vap->macaddr[0], vap->macaddr[1],
			vap->macaddr[2], vap->macaddr[3],
			vap->macaddr[4], vap->macaddr[5] );

#endif
	return 0;
}

static int vwd_vap_down(struct dpaa_vwd_priv_s *priv , struct vap_desc_s *vap)
{
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s:%d\n", __func__, __LINE__);
	DPAWIFI_INFO("%s:DOWN: name:%s, vapid:%d, direct_rx_path : %s, ifindex:%d, mac:%x:%x:%x:%x:%x:%x\n",
			__func__, vap->ifname, vap->vapid,
			vap->direct_rx_path ? "ON":"OFF", vap->ifindex,
			vap->macaddr[0], vap->macaddr[1],
			vap->macaddr[2], vap->macaddr[3],
			vap->macaddr[4], vap->macaddr[5] );
#endif

	/* unpublish from the lock-free ipsec xmit hook first, then tear
	 * down the fq netdev links it would have used */
	if(vap->wifi_dev)
		WRITE_ONCE(vap->wifi_dev->wifi_offload_dev, NULL);

	reset_vap_fqs_netdev(vap);

	vap->state = VAP_ST_CONFIGURED;

	vap->wifi_dev = NULL;
	priv->vap_count--;

	return 0;
}

/** vwd_vap_configure
 *
 */
static int vwd_vap_configure(struct dpaa_vwd_priv_s *priv, struct vap_desc_s *vap, struct vap_cmd_s *cmd)
{
	vap->vapid = cmd->vapid;
	vap->ifindex = cmd->ifindex;
	vap->direct_rx_path = cmd->direct_rx_path;
	vap->no_l2_itf = cmd->no_l2_itf;
	memcpy(vap->ifname, cmd->ifname, 12);
	memcpy(vap->macaddr, cmd->macaddr, ETH_ALEN);
	vap->state = VAP_ST_CONFIGURED;

	/* Configure sysfs attributes */
	dev_attr_vap[vap->vapid].attr.name=vap->ifname;
	dev_attr_vap[vap->vapid].attr.mode=0444;
	dev_attr_vap[vap->vapid].show=vwd_show_vap_stats;
	dev_attr_vap[vap->vapid].store = NULL;

	return 0;
}

/* Clear every netdev's wifi_offload_dev alias pointing at this VAP —
 * the wifi netdev itself and any VLAN-on-vap device control_vlan
 * copied the pointer onto. Caller holds rtnl (the ioctl entry takes
 * it), which is what makes the netdev walk safe. */
static void vwd_unpublish_vap(struct vap_desc_s *vap)
{
	struct net_device *dev;

	ASSERT_RTNL();
	for_each_netdev(&init_net, dev) {
		if (READ_ONCE(dev->wifi_offload_dev) ==
				(struct net_device *)vap)
			WRITE_ONCE(dev->wifi_offload_dev, NULL);
	}
}

/* Republish the vap pointer onto VLAN devices riding on its wifi
 * netdev. FCI VLAN registration copies the parent's pointer when the
 * VLAN entry is added (control_vlan); a REMOVE/re-ADD cycle of the vap
 * would otherwise leave those aliases cleared until the VLAN entry is
 * re-registered, which no netlink event triggers. This publishes by
 * netdev relationship, so VLANs that were never FCI-registered get the
 * alias too — safe: their ESP traffic takes the SEC round-trip and
 * falls back to the exception/software path. Caller holds rtnl. */
static void vwd_publish_vlan_aliases(struct vap_desc_s *vap)
{
	struct net_device *dev;

	ASSERT_RTNL();
	if (!vap->wifi_dev)
		return;
	for_each_netdev(&init_net, dev) {
		if (is_vlan_dev(dev) &&
		    vlan_dev_real_dev(dev) == vap->wifi_dev)
			WRITE_ONCE(dev->wifi_offload_dev,
					(struct net_device *)vap);
	}
}

/** dpaa_vwd_handle_vap
 *
 */
static int dpaa_vwd_handle_vap( struct dpaa_vwd_priv_s *priv, struct vap_cmd_s *cmd )
{
	int rc = 0, ii;
	int create_sysfs = 0;
	struct vap_desc_s *vap;
	DECLARE_BITMAP(reset_mask, MAX_WIFI_VAPS);
	DECLARE_BITMAP(open_mask, MAX_WIFI_VAPS);

	bitmap_zero(reset_mask, MAX_WIFI_VAPS);
	bitmap_zero(open_mask, MAX_WIFI_VAPS);

#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO( "%s function called %d: %s\n", __func__, cmd->action, cmd->ifname);
#endif
	if (cmd->vapid < 0) {
		DPAWIFI_ERROR("%s : Invalid VAPID (%d)\n", __func__, cmd->vapid);
		return -1;
	}

	if (cmd->vapid >= MAX_WIFI_VAPS) {
		DPAWIFI_ERROR("%s : VAPID (%d)  >=  MAX_WIFI_VAPS(%d)\n", __func__, cmd->vapid, MAX_WIFI_VAPS);
		return -1;
	}

	spin_lock_bh(&priv->vaplock);
	vap = &priv->vaps[cmd->vapid];
	switch (cmd->action) {
		case CONFIGURE:
			DPAWIFI_INFO("%s: CONFIGURE ... %s\n", __func__, cmd->ifname);
			if (vap->state != VAP_ST_CLOSE) {
				DPAWIFI_ERROR("%s : VAP (id : %d  name : %s) is not in close state\n",
						__func__, cmd->vapid, cmd->ifname);
				rc = -1;
				break;
			}

			if (!(rc = vwd_vap_configure(priv, vap, cmd)))
			{
				DPAWIFI_INFO("%s: Configured VAP (id : %d  name : %s)\n", __func__, cmd->vapid, cmd->ifname);
				/* device_create_file sleeps; do it after the
				 * final unlock below */
				create_sysfs = 1;
			}
			else
			{
				DPAWIFI_ERROR("%s: Failed to configure VAP (id : %d  name : %s)\n",
						__func__, cmd->vapid, cmd->ifname);
			}
			break;


		case ADD:
			DPAWIFI_INFO("%s: ADD ... %s\n", __func__, cmd->ifname);
			if (vap->state != VAP_ST_CONFIGURED) {
				DPAWIFI_ERROR("%s : VAP (id : %d  name : %s) is not configured \n",
						__func__, cmd->vapid, cmd->ifname);
				rc = -1;
				break;
			}

			/* vwd_vap_up sleeps (GFP_KERNEL allocs, qman FQ
			 * setup) and must not run under the BH spinlock the
			 * softirq classifiers share. Claim the slot so
			 * concurrent ioctls see it mid-transition and bail;
			 * the classifiers and the ipsec xmit hook key on
			 * VAP_ST_OPEN / wifi_offload_dev and stay away. */
			vap->state = VAP_ST_CONFIGURING;
			spin_unlock_bh(&priv->vaplock);
			rc = vwd_vap_up(priv, vap, cmd);
			if (!rc)
				vwd_publish_vlan_aliases(vap);
			spin_lock_bh(&priv->vaplock);
			if (rc < 0)
			{
				DPAWIFI_ERROR("%s : VAP (id : %d  name : %s) is not UP \n",
						__func__, cmd->vapid, cmd->ifname);
				vap->state = VAP_ST_CONFIGURED;
				rc = -1;
			}
			else
			{
				vap->state = VAP_ST_OPEN;
				priv->vap_count++;
			}
			break;
		case REMOVE:
			DPAWIFI_INFO("%s: REMOVE ... %s\n", __func__, cmd->ifname);
			if (vap->state != VAP_ST_OPEN) {
				DPAWIFI_INFO("%s : VAP (id : %d  name : %s) is not opened \n",
						__func__, cmd->vapid, cmd->ifname);
				rc = -1;
				break;
			}
			/* Claim the slot (other ioctls are also rtnl-
			 * serialized; the claim additionally keeps the exit
			 * walk away), unpublish every wifi_offload_dev alias
			 * and wait out in-flight lock-free consumers before
			 * vwd_vap_down tears down the fq netdev links they
			 * use. synchronize_rcu sleeps, hence the unlock. */
			vap->state = VAP_ST_CONFIGURING;
			spin_unlock_bh(&priv->vaplock);
			vwd_unpublish_vap(vap);
			synchronize_rcu();
			spin_lock_bh(&priv->vaplock);
			vwd_vap_down(priv, vap);

			break;
		case UPDATE:
			DPAWIFI_INFO("%s: UPDATE ... %s\n", __func__, cmd->ifname);
			if (vap->state == VAP_ST_CONFIGURING) {
				/* an ADD is mid-flight outside the lock;
				 * updating its fields now would race it */
				rc = -1;
				break;
			}
			vap->ifindex = cmd->ifindex;
			vap->direct_rx_path = cmd->direct_rx_path;
			vap->no_l2_itf = cmd->no_l2_itf;
			memcpy(vap->macaddr, cmd->macaddr, ETH_ALEN);
			break;		
		case RESET:
			DPAWIFI_INFO("%s: RESET ...\n", __func__);
			/* pass 1 (locked): claim OPEN slots and mark
			 * everything that will drop to CLOSE */
			for (ii = 0; ii < MAX_WIFI_VAPS; ii++) {
				vap = &priv->vaps[ii];

				if (vap->state == VAP_ST_CLOSE ||
						vap->state == VAP_ST_CONFIGURING)
					continue;

				if (vap->state == VAP_ST_OPEN) {
					vap->state = VAP_ST_CONFIGURING;
					__set_bit(ii, open_mask);
				}
				__set_bit(ii, reset_mask);
			}
			if (!bitmap_empty(reset_mask, MAX_WIFI_VAPS)) {
				/* unpublish + grace period for the formerly
				 * OPEN slots, outside the BH spinlock */
				spin_unlock_bh(&priv->vaplock);
				for_each_set_bit(ii, open_mask, MAX_WIFI_VAPS)
					vwd_unpublish_vap(&priv->vaps[ii]);
				if (!bitmap_empty(open_mask, MAX_WIFI_VAPS))
					synchronize_rcu();
				spin_lock_bh(&priv->vaplock);
				for_each_set_bit(ii, open_mask, MAX_WIFI_VAPS)
					vwd_vap_down(priv, &priv->vaps[ii]);
				for_each_set_bit(ii, reset_mask, MAX_WIFI_VAPS)
					priv->vaps[ii].state = VAP_ST_CLOSE;
				/* per-vap sysfs attrs are removed after the
				 * final unlock below */
			}
			break;

		default:
			DPAWIFI_INFO("%s::unhandled cmd %d\n", __func__, cmd->action);	
			rc = -1;
			break;
	}

	spin_unlock_bh(&priv->vaplock);

	if (create_sysfs) {
		/* Create sysfs entry for vap interface */
		if (device_create_file(priv->vwd_device, &dev_attr_vap[cmd->vapid])) {
			DPAWIFI_ERROR("%s::unable to create sysfs entry for vap iface %s\n",
					__func__, cmd->ifname);
		}
	}
	/* RESET dropped these to CLOSE; drop their sysfs attrs too so a
	 * later re-CONFIGURE doesn't double-create (device_remove_file
	 * sleeps, so it runs here, after the unlock) */
	for_each_set_bit(ii, reset_mask, MAX_WIFI_VAPS)
		device_remove_file(priv->vwd_device, &dev_attr_vap[ii]);
	return rc;

}

/** vwd_open
 *
 */
static int dpaa_vwd_open(struct inode *inode, struct file *file)
{
	int result = 0;
	unsigned dev_minor = iminor(inode);

	if (READ_ONCE(vwd_stopping))
		return -ENODEV;
	DPAWIFI_INFO( "%s :  minor device -> %d\n", __func__, dev_minor);
	if (dev_minor != 0)
	{
		DPAWIFI_INFO(KERN_ERR ": trying to access unknown minor device -> %d\n", dev_minor);
		result = -ENODEV;
		goto out;
	}

	file->private_data = &vwd;

out:
	return result;
}

#define SIOCVAPUPDATE  ( 0x6401 )

/**dpaa_vwd_ioctl
 *
 */
long dpaa_vwd_ioctl(struct file * file, unsigned int cmd, unsigned long arg)
{
	struct vap_cmd_s vap_cmd;
	void __user *argp = (void __user *)arg;
	int rc = -EOPNOTSUPP;
	struct dpaa_vwd_priv_s *priv = (struct dpaa_vwd_priv_s *)file->private_data;

	rtnl_lock();
	if (READ_ONCE(vwd_stopping)) {
		rc = -ENODEV;
		goto done;
	}
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s vapcmd recvd:%x \n", __func__, cmd);
#endif
	switch(cmd) {
		case SIOCVAPUPDATE:
			if (copy_from_user(&vap_cmd, argp, sizeof(struct vap_cmd_s))) {
				rc = -EFAULT;
				goto done;
			}

			rc = dpaa_vwd_handle_vap(priv, &vap_cmd);
	}
done:
	rtnl_unlock();
	return rc;
}

static int vwd_init_ohport(struct dpaa_vwd_priv_s *priv)
{
	int handle;

	/* Get OH port for this driver */
	handle = alloc_offline_port(FMAN_IDX, PORT_TYPE_WIFI, vwd_rx_exception_pkt, vwd_rx_error);
	if (handle < 0)
	{
		DPAWIFI_ERROR("%s: Error in allocating OH port Channel\n", __func__);
		return -1;
	}
	priv->oh_port_handle = handle;
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s: allocated oh port %d\n", __func__, priv->oh_port_handle);
#endif


	/* Send exceptions to the parser, without the SEC error check. */
	handle = ohport_set_ofne(priv->oh_port_handle, 0x440000);
	if (handle < 0)
		release_offline_port(FMAN_IDX, priv->oh_port_handle);
	return handle;
}

static void vwd_release_pcd_fqs(struct dpaa_vwd_priv_s *priv)
{
	struct qman_fq* fq;
	struct dpa_fq* dpafq;
	int i;

	if (priv->wlan_exception_fq)
	{
#ifdef DPA_WIFI_DEBUG
		DPAWIFI_INFO("%s:: releasing expt fq :%d\n", __func__, priv->expt_fq_count);
#endif
		dpafq = priv->wlan_exception_fq;
		for (i = 0; i < priv->expt_fq_count; i++)
		{
			fq= &dpafq->fq_base;
			vwd_fq_destroy(fq);
			dpafq++;
		}
		kfree(priv->wlan_exception_fq);
		priv->wlan_exception_fq = NULL;
		priv->expt_fq_count = 0;
	}

	return;
}

static int vwd_init_stats(struct dpaa_vwd_priv_s *priv)
{
	int i = 0;

	/* Allocate per cpu structure for each vap */
	for (i = 0; i< MAX_WIFI_VAPS; i++) {
		priv->vaps[i].vap_stats = alloc_percpu(struct vap_stats_s);
		if (!priv->vaps[i].vap_stats)
			return -1;
	}

	/* Allocate per cpu structure for vwd global stats */
	priv->vwd_global_stats = alloc_percpu(struct vwd_global_stats_s);
	if (!priv->vwd_global_stats)
		return -1;
	return 0;
}

static void vwd_release_stats(struct dpaa_vwd_priv_s *priv)
{
	int i = 0;
	/* Free up the per cpu structure of each vap */
	for (i = 0; i< MAX_WIFI_VAPS; i++) {
		if (priv->vaps[i].vap_stats) {
			free_percpu(priv->vaps[i].vap_stats);
			priv->vaps[i].vap_stats = NULL;
		}
	}

	/* Free up the per cpu structure of vwd global stats */
	if (priv->vwd_global_stats) {
		free_percpu(priv->vwd_global_stats);
		priv->vwd_global_stats = NULL;
	}
}

static int vwd_free_ohport(struct dpaa_vwd_priv_s *priv)
{

	int rc;
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s: releasing oh port %d\n", __func__, priv->oh_port_handle);
#endif
	rc = release_offline_port(FMAN_IDX, priv->oh_port_handle);
	if (rc < 0)
	{
		DPAWIFI_ERROR("%s: Error in releasing OH port Channel\n", __func__);
		return -1;
	}

	return 0;
}

/*
 * vwd_wifi_if_send_pkt
 */
static int vwd_wifi_if_send_pkt(struct sk_buff *skb)
{
	struct dpaa_vwd_priv_s *priv = &vwd;
	struct vap_desc_s *vap;
	int rc = -1;

	if (!READ_ONCE(priv->fast_path_enable) || skb_is_gso(skb) ||
	    (eth_hdr(skb)->h_dest[0] & 0x1))
	{
		goto end;
	}

	spin_lock_bh(&priv->vaplock);
	vap = (struct vap_desc_s *)skb->dev->wifi_offload_dev;

	if (vap && (vap->ifindex == skb->dev->ifindex) && vap->direct_rx_path && (vap->state == VAP_ST_OPEN))
	{
		spin_unlock_bh(&priv->vaplock);
		INCR_PER_CPU_STAT(priv->vaps[vap->vapid].vap_stats, pkts_direct_rx);
		skb_push(skb, ETH_HLEN);
		spin_lock_bh(&priv->txlock);
		dpaa_vwd_send_packet( priv, &priv->vaps[vap->vapid], skb);
		spin_unlock_bh(&priv->txlock);
		rc = 0;
	}
	else
		spin_unlock_bh(&priv->vaplock);
end:
	return rc;
}

/* NETDEV_UNREGISTER teardown: cdx deliberately holds no ref on the
 * wifi netdev (vwd_vap_up dev_puts after publishing), so an unregister
 * while a VAP is OPEN would leave vap->wifi_dev and the fq net_dev
 * links dangling. Notifiers run in process context under rtnl, so the
 * unpublish + grace + down sequence the ioctl REMOVE arm uses works
 * here too. Upper devices (VLAN aliases) unregister before their real
 * device and each event clears its own dev's pointer. */
static int vwd_netdev_event(struct notifier_block *nb,
		unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct dpaa_vwd_priv_s *priv = &vwd;
	struct vap_desc_s *found = NULL;
	struct net_device *p;
	int ii;

	if (event != NETDEV_UNREGISTER)
		return NOTIFY_DONE;

	p = READ_ONCE(dev->wifi_offload_dev);
	if ((void *)p >= (void *)&priv->vaps[0] &&
	    (void *)p < (void *)&priv->vaps[MAX_WIFI_VAPS])
		WRITE_ONCE(dev->wifi_offload_dev, NULL);

	/* claim every OPEN vap riding on the dying dev (a pathological
	 * config can point several at one ifname) */
	spin_lock_bh(&priv->vaplock);
	for (ii = 0; ii < MAX_WIFI_VAPS; ii++) {
		struct vap_desc_s *vap = &priv->vaps[ii];

		if (vap->state == VAP_ST_OPEN && vap->wifi_dev == dev) {
			vap->state = VAP_ST_CONFIGURING;
			found = vap;
		}
	}
	spin_unlock_bh(&priv->vaplock);

	if (found) {
		/* clear the claimed vaps' remaining aliases ourselves
		 * rather than relying on upper devices (8021q) having
		 * unregistered first — rtnl is held here */
		for (ii = 0; ii < MAX_WIFI_VAPS; ii++) {
			struct vap_desc_s *vap = &priv->vaps[ii];

			if (vap->state == VAP_ST_CONFIGURING &&
					vap->wifi_dev == dev)
				vwd_unpublish_vap(vap);
		}
		/* wait out in-flight lock-free consumers before the fq
		 * net_dev links go; the netdev itself outlives the
		 * notifier chain, so vwd_vap_down's derefs are safe */
		synchronize_rcu();
		spin_lock_bh(&priv->vaplock);
		for (ii = 0; ii < MAX_WIFI_VAPS; ii++) {
			struct vap_desc_s *vap = &priv->vaps[ii];

			if (vap->state == VAP_ST_CONFIGURING &&
					vap->wifi_dev == dev)
				vwd_vap_down(priv, vap);
		}
		spin_unlock_bh(&priv->vaplock);
	}
	return NOTIFY_DONE;
}

static struct notifier_block vwd_netdev_notifier = {
	.notifier_call = vwd_netdev_event,
};

/** dpaa_vwd_up
 *
 */
static int dpaa_vwd_up(struct dpaa_vwd_priv_s *priv)
{
	int ret;

	ret = nf_register_net_hook(&init_net, &vwd_hook);
	if (ret)
		return ret;
	ret = nf_register_net_hook(&init_net, &vwd_hook_ipv6);
	if (ret)
		goto err_ipv6;
	ret = nf_register_net_hook(&init_net, &vwd_hook_bridge);
	if (ret)
		goto err_bridge;
	ret = register_netdevice_notifier(&vwd_netdev_notifier);
	if (ret)
		goto err_notifier;
	ret = dpaa_vwd_sysfs_init(priv);
	if (ret)
		goto err_sysfs;
	wifi_rx_fastpath_register(vwd_wifi_if_send_pkt);
	return 0;

err_sysfs:
	unregister_netdevice_notifier(&vwd_netdev_notifier);
err_notifier:
	nf_unregister_net_hook(&init_net, &vwd_hook_bridge);
err_bridge:
	nf_unregister_net_hook(&init_net, &vwd_hook_ipv6);
err_ipv6:
	nf_unregister_net_hook(&init_net, &vwd_hook);
	synchronize_net();
	return ret;
}

/** dpaa_vwd_down
 *
 */
static int dpaa_vwd_down( struct dpaa_vwd_priv_s *priv )
{
	int ii;

#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO( "%s: %s\n", priv->name, __func__);
#endif
	DECLARE_BITMAP(attr_mask, MAX_WIFI_VAPS);
	struct net_device *dev;

	bitmap_zero(attr_mask, MAX_WIFI_VAPS);

	/* unregister_netdevice_notifier replays a synthesized
	 * NETDEV_UNREGISTER for every live netdev to the departing
	 * notifier, so this line already runs the notifier's
	 * claim/grace/down sequence for each still-OPEN vap; the walk
	 * below then finds them CONFIGURED and still releases their FQs
	 * and attrs exactly once via the masks */
	unregister_netdevice_notifier(&vwd_netdev_notifier);
	wifi_rx_fastpath_unregister();
	nf_unregister_net_hook(&init_net, &vwd_hook);
	nf_unregister_net_hook(&init_net, &vwd_hook_ipv6);
	nf_unregister_net_hook(&init_net, &vwd_hook_bridge);
	/* nf_unregister_net_hook only call_rcu()s the old entries array —
	 * it does NOT wait — and the rx-fastpath unregister is a bare
	 * pointer swap. Wait out in-flight classifiers/rx handlers here so
	 * release_vap_fqs below can't free FQs under them. */
	synchronize_rcu();

	/* rtnl taken for the whole vap teardown: it drains any in-flight
	 * vap ioctl (they run entirely under rtnl), so no slot can be
	 * mid-ADD when the walk below runs, and it covers the netdev walk
	 * in the alias sweep. Ioctls arriving after we drop it find every
	 * slot CLOSE and bail on their state checks. */
	rtnl_lock();

	/* state transitions under the lock; sleeping teardown after */
	spin_lock_bh(&priv->vaplock);
	for (ii = 0; ii < MAX_WIFI_VAPS; ii++)
	{
		struct vap_desc_s *vap = &priv->vaps[ii];

		/* unreachable now that rtnl above drains in-flight ioctls
		 * before this walk; kept as a defensive skip */
		if (vap->state == VAP_ST_CONFIGURING)
			continue;

		if (vap->state == VAP_ST_OPEN)
			vwd_vap_down(priv, vap);
		if (vap->state == VAP_ST_CONFIGURED) {
			__set_bit(ii, attr_mask);
			vap->state = VAP_ST_CLOSE;
		}
	}
	priv->vap_count = 0;
	spin_unlock_bh(&priv->vaplock);

	/* clear every wifi_offload_dev still pointing into the vap table —
	 * covers the wifi netdevs and any VLAN-on-vap aliases; a stale
	 * pointer surviving module unload would hand a later cdx instance
	 * a dangling vap */
	for_each_netdev(&init_net, dev) {
		struct net_device *p = READ_ONCE(dev->wifi_offload_dev);

		if ((void *)p >= (void *)&priv->vaps[0] &&
		    (void *)p < (void *)&priv->vaps[MAX_WIFI_VAPS])
			WRITE_ONCE(dev->wifi_offload_dev, NULL);
	}
	rtnl_unlock();

	for (ii = 0; ii < MAX_WIFI_VAPS; ii++)
	{
		if (test_bit(ii, attr_mask))
			device_remove_file(priv->vwd_device, &dev_attr_vap[ii]);
	}
	dpaa_vwd_sysfs_exit();

	return 0;
}

/* Publish the interfaces only after their callback resources are ready. */
int dpaa_vwd_init(void)
{
	struct dpaa_vwd_priv_s *priv = &vwd;
	int rc;

	memset(priv, 0, sizeof(*priv));
	strscpy(priv->name, "vwd", sizeof(priv->name));
	spin_lock_init(&priv->vaplock);
	spin_lock_init(&priv->txlock);
	INIT_DELAYED_WORK(&vwd_tx_work, vwd_tx_reclaim_work);
	WRITE_ONCE(vwd_stopping, true);

	rc = vwd_init_stats(priv);
	if (rc)
		goto err_stats;
	priv->eth_priv = get_eth_priv("eth0");
	if (!priv->eth_priv) {
		rc = -ENODEV;
		goto err_stats;
	}
	rc = add_device_tx_done_bpool(priv);
	if (rc)
		goto err_eth;
	rc = vwd_init_ohport(priv);
	if (rc < 0)
		goto err_pool;
	rc = vwd_init_pcd_fqs(priv);
	if (rc)
		goto err_oh;

	priv->vwd_major = register_chrdev(0, "vwd", &vwd_fops);
	if (priv->vwd_major < 0) {
		rc = priv->vwd_major;
		goto err_fqs;
	}
	priv->vwd_class = class_create("vwd");
	if (IS_ERR(priv->vwd_class)) {
		rc = PTR_ERR(priv->vwd_class);
		goto err_chrdev;
	}
	priv->vwd_device = device_create(priv->vwd_class, NULL,
			MKDEV(priv->vwd_major, VWD_MINOR), NULL, "vwd0");
	if (IS_ERR(priv->vwd_device)) {
		rc = PTR_ERR(priv->vwd_device);
		goto err_class;
	}
	rc = dpaa_vwd_up(priv);
	if (rc)
		goto err_device;
	rc = dpa_register_wifi_xmit_local_hook(vwd_xmit_local_packet);
	if (rc < 0)
		goto err_hooks;

	WRITE_ONCE(vwd_stopping, false);
	WRITE_ONCE(priv->fast_path_enable, 1);
	register_cdx_deinit_func(dpaa_vwd_exit);
	return 0;

err_hooks:
	dpaa_vwd_down(priv);
err_device:
	device_destroy(priv->vwd_class, MKDEV(priv->vwd_major, VWD_MINOR));
err_class:
	class_destroy(priv->vwd_class);
err_chrdev:
	unregister_chrdev(priv->vwd_major, "vwd");
err_fqs:
	vwd_release_pcd_fqs(priv);
err_oh:
	vwd_free_ohport(priv);
	synchronize_net();
err_pool:
	release_device_tx_done_bpool(priv);
err_eth:
	dev_put(priv->eth_priv->net_dev);
	priv->eth_priv = NULL;
err_stats:
	vwd_release_stats(priv);
	return rc;
}

void dpaa_vwd_exit(void)
{
	struct dpaa_vwd_priv_s *priv = &vwd;
	unsigned long deadline = jiffies + 5 * HZ;
	int i;

	/* Block new submissions before unpublishing any callback resources. */
	spin_lock_bh(&priv->txlock);
	WRITE_ONCE(vwd_stopping, true);
	WRITE_ONCE(priv->fast_path_enable, 0);
	spin_unlock_bh(&priv->txlock);
	dpa_unregister_wifi_xmit_local_hook();
	dpaa_vwd_down(priv);
	cancel_delayed_work_sync(&vwd_tx_work);

	/* Keep completion callbacks and the pool alive until hardware gives
	 * back every descriptor. A timeout cannot make DMA memory safe to free.
	 */
	for (;;) {
		spin_lock_bh(&priv->txlock);
		drain_bp_tx_done_bpool(priv->txconf_bp);
		spin_unlock_bh(&priv->txlock);
		if (!atomic_read(&vwd_tx_pending))
			break;
		if (time_after(jiffies, deadline)) {
			pr_warn("vwd: waiting for %d hardware-owned frames\n",
				atomic_read(&vwd_tx_pending));
			deadline = jiffies + 5 * HZ;
		}
		usleep_range(1000, 2000);
	}
	for (i = 0; i < MAX_WIFI_VAPS; i++)
		release_vap_fqs(&priv->vaps[i]);
	vwd_release_pcd_fqs(priv);
	vwd_free_ohport(priv);
	synchronize_net();
	release_device_tx_done_bpool(priv);
	vwd_release_stats(priv);
	dev_put(priv->eth_priv->net_dev);
	priv->eth_priv = NULL;
	device_destroy(priv->vwd_class, MKDEV(priv->vwd_major, VWD_MINOR));
	unregister_chrdev(priv->vwd_major, "vwd");
	class_destroy(priv->vwd_class);
}
