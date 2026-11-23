/* Copyright 2008-2013 Freescale Semiconductor, Inc.
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

#ifndef __DPAA_ETH_COMMON_H
#define __DPAA_ETH_COMMON_H

#include <linux/etherdevice.h> /* struct net_device */
#include <linux/fsl_bman.h> /* struct bm_buffer */
#include <linux/of_platform.h> /* struct platform_device */
#include <linux/net_tstamp.h>	/* struct hwtstamp_config */

#include "dpaa_eth.h"
#include "lnxwrp_fsl_fman.h"

#define dpaa_eth_init_port(type, port, param, errq_id, defq_id, buf_layout,\
			   frag_enabled) \
{ \
	param.errq = errq_id; \
	param.defq = defq_id; \
	param.priv_data_size = buf_layout->priv_data_size; \
	param.parse_results = buf_layout->parse_results; \
	param.hash_results = buf_layout->hash_results; \
	param.frag_enable = frag_enabled; \
	param.time_stamp = buf_layout->time_stamp; \
	param.manip_extra_space = buf_layout->manip_extra_space; \
	param.data_align = buf_layout->data_align; \
	fm_set_##type##_port_params(port, &param); \
}

/* The SGT needs to be 256 bytes long. Even if the table has only one entry,
 * the FMan will read 256 bytes from its start.
 */
#define DPA_SGT_SIZE 256
#define DPA_SGT_MAX_ENTRIES 16 /* maximum number of entries in SG Table */

#define DPA_BUFF_RELEASE_MAX 8 /* maximum number of buffers released at once */

#define DPA_RX_PCD_HI_PRIO_FQ_INIT_FAIL(dpa_fq, _errno) \
	(((dpa_fq)->fq_type == FQ_TYPE_RX_PCD_HI_PRIO) && \
	  (_errno == -EIO))
/* return codes for the dpaa-eth hooks */
enum dpaa_eth_hook_result {
	/* fd/skb was retained by the hook.
	 *
	 * On the Rx path, this means the Ethernet driver will _not_
	 * deliver the skb to the stack. Instead, the hook implementation
	 * is expected to properly dispose of the skb.
	 *
	 * On the Tx path, the Ethernet driver's dpa_tx() function will
	 * immediately return NETDEV_TX_OK. The hook implementation is expected
	 * to free the skb. *DO*NOT* release it to BMan, or enqueue it to FMan,
	 * unless you know exactly what you're doing!
	 *
	 * On the confirmation/error paths, the Ethernet driver will _not_
	 * perform any fd cleanup, nor update the interface statistics.
	 */
	DPAA_ETH_STOLEN,
	/* fd/skb was returned to the Ethernet driver for regular processing.
	 * The hook is not allowed to, for instance, reallocate the skb (as if
	 * by linearizing, copying, cloning or reallocating the headroom).
	 */
	DPAA_ETH_CONTINUE
};

typedef enum dpaa_eth_hook_result (*dpaa_eth_ingress_hook_t)(
		struct sk_buff *skb, struct net_device *net_dev, u32 fqid);
typedef enum dpaa_eth_hook_result (*dpaa_eth_egress_hook_t)(
		struct sk_buff *skb, struct net_device *net_dev);
typedef enum dpaa_eth_hook_result (*dpaa_eth_confirm_hook_t)(
		struct net_device *net_dev, const struct qm_fd *fd, u32 fqid);

#if defined(CONFIG_INET_IPSEC_OFFLOAD) || defined(CONFIG_INET6_IPSEC_OFFLOAD)
typedef struct qman_fq *(*cdx_get_ipsec_fq_hook_t)(u32 handle);
int dpa_register_ipsec_fq_handler(cdx_get_ipsec_fq_hook_t hookfn);
void dpa_unregister_ipsec_fq_handler(void);
struct xfrm_state;
int dpaa_submit_inb_pkt_to_SEC(struct sk_buff *skb, const struct xfrm_state *x);

#endif

#ifdef CONFIG_CPE_FAST_PATH
typedef struct qman_fq *(*cdx_get_ceetm_egressfq)(void *, uint32_t chnl_id, uint32_t queue, uint32_t ff);
typedef struct qman_fq *(*cdx_get_ceetm_dscp_fq)(void *, uint8_t dscp);
int dpa_register_ceetm_get_egress_fq(cdx_get_ceetm_egressfq egress_fq_func, cdx_get_ceetm_dscp_fq dscp_fq_func);
void dpa_unregister_ceetm_get_egress_fq(void);

/* Handler for the netdev's ndo_setup_tc, registered by the offload module
 * because a built-in driver cannot link against one.
 *
 * Registering is not optional once the ndo exists. Netfilter picks its
 * flowtable binding route on whether the netdev has an ndo_setup_tc at all
 * (nf_flow_table_offload_setup), so from the moment this driver offers one,
 * every hardware flowtable bind arrives here instead of through the module's
 * indirect registration. With no handler those binds are refused, where before
 * they were served.
 *
 * The handler sleeps -- it takes the module's own locks and can wait on RTNL --
 * so calls are held in an SRCU read-side section, and the unregister returns
 * only once every call already inside the handler has left it: the module's
 * text, and anything of its own the handler touches, may go after that.
 */
typedef int (*dpa_setup_tc_handler)(struct net_device *dev,
				    enum tc_setup_type type, void *type_data);
int dpa_register_setup_tc(dpa_setup_tc_handler handler);
void dpa_unregister_setup_tc(void);

/* The data-path half of the hardware qdisc, which only the module that hands
 * out leaf classes can answer.
 *
 * select_queue turns a frame into the Tx queue of the leaf class it belongs
 * to, or DPA_SELECT_QUEUE_NONE when it belongs to none, which leaves the
 * stack's own choice in place -- folded below the leaf range by the caller,
 * because real_num_tx_queues covers those queues once a class is using one and
 * nothing but a named class may be sent there.
 *
 * txq_fq then names the CEETM frame queue a frame on that Tx queue leaves by.
 * For a leaf's queue that is the leaf's class queue: reading the class from
 * the queue index rather than resolving the mark a second time is what keeps
 * the software path on the same class the hardware path put the flow on. For
 * an ordinary queue it is where a frame that named no class goes on a port the
 * module's tree owns, which the module decides from the frame itself -- so it
 * is handed the skb. NULL means the module has no tree on the port, and only
 * then does the driver resolve the frame from its own mark: on a port with a
 * tree that reading would pick queues the tree never configured.
 *
 * class_stats fills the hardware counters for every leaf slot, in slot order,
 * DPA_CEETM_CLASS_STATS values each, and then for the DPA_CEETM_IMPLICIT_QUEUES
 * queues traffic that names no leaf takes: the one unclassified traffic goes
 * to, then the one control traffic goes to. It fills all of them whatever the
 * tree currently looks like, zeroing what nothing holds, because ethtool's
 * string set is fixed length: names and values arrive in separate ioctls, so a
 * count that moved with tc would leave userspace reading one against the other.
 *
 * None of the three may sleep. Each is called inside an rcu_read_lock() the
 * driver takes itself -- ndo_select_queue has callers that hold none, AF_PACKET's
 * qdisc bypass among them -- and the unregister waits for a grace period, so
 * the module may free its text and state once it returns. A frame queue txq_fq
 * answers with has to stay valid for the enqueue that follows, which the
 * transmit path keeps inside its own read-side section.
 */
#define DPA_SELECT_QUEUE_NONE	((u16)~0U)
/* dequeued frames, dequeued bytes, rejected frames */
#define DPA_CEETM_CLASS_STATS	3
/* the unclassified queue, then the control queue, after the leaf slots */
#define DPA_CEETM_IMPLICIT_QUEUES	2
struct dpa_qdisc_ops {
	u16 (*select_queue)(struct net_device *dev, struct sk_buff *skb);
	struct qman_fq *(*txq_fq)(void *qm_ctx, u16 txq, struct sk_buff *skb);
	void (*class_stats)(void *qm_ctx, u64 *data);
};
void dpa_qdisc_class_stats(void *qm_ctx, u64 *data);
int dpa_register_qdisc_ops(const struct dpa_qdisc_ops *ops);
void dpa_unregister_qdisc_ops(void);
struct qman_fq *dpa_qdisc_txq_fq(void *qm_ctx, u16 txq, struct sk_buff *skb);
#endif


/* used in napi related functions */
extern u16 qman_portal_max;

/* from dpa_ethtool.c */
extern const struct ethtool_ops dpa_ethtool_ops;


int dpa_netdev_init(struct net_device *net_dev,
		    const uint8_t *mac_addr,
		    uint16_t tx_timeout);
int __cold dpa_start(struct net_device *net_dev);
int __cold dpa_stop(struct net_device *net_dev);
void __cold dpa_timeout(struct net_device *net_dev, unsigned int txqueue);
void __cold
dpa_get_stats64(struct net_device *net_dev,
		struct rtnl_link_stats64 *stats);
int dpa_ndo_init(struct net_device *net_dev);
int dpa_set_features(struct net_device *dev, netdev_features_t features);
netdev_features_t dpa_fix_features(struct net_device *dev,
				   netdev_features_t features);
#ifdef CONFIG_FSL_DPAA_TS
u64 dpa_get_timestamp_ns(const struct dpa_priv_s *priv,
			enum port_type rx_tx, const void *data);
/* Updates the skb shared hw timestamp from the hardware timestamp */
int dpa_get_ts(const struct dpa_priv_s *priv, enum port_type rx_tx,
	struct skb_shared_hwtstamps *shhwtstamps, const void *data);
#endif /* CONFIG_FSL_DPAA_TS */
int dpa_ioctl(struct net_device *dev, struct ifreq *rq, int cmd);
void __cold dpa_remove(struct platform_device *of_dev);
struct mac_device * __cold __must_check
__attribute__((nonnull)) dpa_mac_probe(struct platform_device *_of_dev);
int dpa_set_mac_address(struct net_device *net_dev, void *addr);
void dpa_set_rx_mode(struct net_device *net_dev);
void dpa_set_buffers_layout(struct mac_device *mac_dev,
		struct dpa_buffer_layout_s *layout);
int __attribute__((nonnull))
dpa_bp_alloc(struct dpa_bp *dpa_bp, struct device *dev);
void __cold __attribute__((nonnull))
dpa_bp_free(struct dpa_priv_s *priv);
struct dpa_bp *dpa_bpid2pool(int bpid);
void dpa_bpid2pool_map(int bpid, struct dpa_bp *dpa_bp);
bool dpa_bpid2pool_use(int bpid);
void dpa_bp_drain(struct dpa_bp *bp);
void __cold __attribute__((nonnull))
_dpa_bp_free(struct dpa_bp *dpa_bp);
struct dpa_fq *dpa_fq_alloc(struct device *dev,
			    u32 fq_start,
			    u32 fq_count,
			    struct list_head *list,
			    enum dpa_fq_type fq_type);
int dpa_fq_probe_mac(struct device *dev, struct list_head *list,
		     struct fm_port_fqs *port_fqs,
		     bool tx_conf_fqs_per_core,
		     enum port_type ptype);
int dpa_get_channel(void);
void dpa_release_channel(void);
void dpaa_eth_add_channel(u16 channel);
int dpaa_eth_cgr_init(struct dpa_priv_s *priv);
void dpa_destroy_cgr(struct qman_cgr *cgr);
void dpa_fq_setup(struct dpa_priv_s *priv, const struct dpa_fq_cbs_t *fq_cbs,
		struct fm_port *tx_port);
int dpa_fq_init(struct dpa_fq *dpa_fq, bool td_enable);
int dpa_fqs_init(struct device *dev, struct list_head *list, bool td_enable);
int __cold __attribute__((nonnull))
dpa_fq_free(struct device *dev, struct list_head *list);
void dpaa_eth_init_ports(struct mac_device *mac_dev,
		struct dpa_bp *bp, size_t count,
		struct fm_port_fqs *port_fqs,
		struct dpa_buffer_layout_s *buf_layout,
		struct device *dev);
void dpa_release_sgt(struct qm_sg_entry *sgt);
void dpa_release_sgt_by_bpid(struct qm_sg_entry *sgt);
//void __attribute__((nonnull))
void
dpa_fd_release(const struct net_device *net_dev, const struct qm_fd *fd);
void count_ern(struct dpa_percpu_priv_s *percpu_priv,
		      const struct qm_mr_entry *msg);
int dpa_enable_tx_csum(struct dpa_priv_s *priv,
	struct sk_buff *skb, struct qm_fd *fd, char *parse_results);
#ifdef CONFIG_CPE_FAST_PATH
void dpa_enable_ceetm(struct net_device *dev);
void dpa_disable_ceetm(struct net_device *dev);
#endif
struct proxy_device {
		struct mac_device *mac_dev;
};

/* mac device control functions exposed by proxy interface*/
int dpa_proxy_start(struct net_device *net_dev);
int dpa_proxy_stop(struct proxy_device *proxy_dev, struct net_device *net_dev);
int dpa_proxy_set_mac_address(struct proxy_device *proxy_dev,
			  struct net_device *net_dev);
int dpa_proxy_set_rx_mode(struct proxy_device *proxy_dev,
		      struct net_device *net_dev);
void dpa_set_eth_ifinfo(struct dpa_priv_s *priv, void* ifinfo);
void dpa_reset_eth_ifinfo(struct dpa_priv_s *priv);
int dpa_update_eth_if(struct dpa_priv_s *priv);
struct sk_buff *__hot contig_fd_to_skb(const struct dpa_priv_s *priv,
				       const struct qm_fd *fd,
				       bool *use_gro, bool dcl4c_valid);
struct sk_buff *__hot sg_fd_to_skb(const struct dpa_priv_s *priv,
				   const struct qm_fd *fd, bool *use_gro,
				   int *count_ptr, bool dcl4c_valid);


#endif /* __DPAA_ETH_COMMON_H */
