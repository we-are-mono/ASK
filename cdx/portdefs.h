/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */
 
/**
 * @file                port_defs.h
 * @description         dpaa port/interface management module header file
 */ 

#ifndef PORT_DEFS_H
#define PORT_DEFS_H  1

#include "dpaa_eth.h"
#include "cdx_common.h"
#include "types.h"

#define ETH_ALEN		6	
#define MAX_PORT_BMAN_POOLS     8	//max bman pools per port

#ifndef ENABLE_EGRESS_QOS
#define DPAA_FWD_TX_QUEUES	8	/* max forwarding(PCD) queues per port */
#else
#define DPAA_FWD_TX_QUEUES	16	/* max forwarding(PCD) queues per port */
#endif

#define PORT_1G_SPEED		1000
#define PORT_10G_SPEED		10000

//fq infor associated with fman controlled ports
struct port_fq_info {
	uint32_t fq_base;		//base fq
	uint32_t num_fqs;		//num of fqs from base
};


//bman pool info
struct port_bman_pool_info
{
  uint32_t pool_id;		//pool id known to system
  uint32_t buf_size;		//size of buffers managed by pool
  uint32_t count;		//number of buffer filled into pool
  uint64_t base_addr;		//base address of buffers (phys)
};


//types of FQs 
typedef enum {	
	TX_ERR_FQ,		//transmit error FQ
	TX_CFM_FQ,		//transmit confirmation FQ
	RX_ERR_FQ,		//receive error FQ
	RX_DEFA_FQ,		//default receive FQ	
	MAX_FQ_TYPES
}fq_types;

/* A port's 32-bit BMI count, carried past its wrap into the total since CDX
 * first read it. */
struct port_bmi_count {
	bool ready;
	u32 last;
	u64 total;
};

/* A port's 64-bit MAC count, carried past the MAC's own resets into the total
 * since CDX first read it. */
struct port_mac_count {
	bool ready;
	u64 last;
	u64 total;
};

//ethernet device information
struct eth_iface_info {
	struct net_device *net_dev;	//os device ref
	uint32_t speed;			//port speed
	uint32_t fman_idx;		//fman index within SOC
	uint32_t port_idx;		//port index within fman
	uint32_t portid;		//identification provided in xml pcd file
	uint32_t hardwarePortId;	//hardware port id
	t_Handle *vsp_h;			//VSP info for given eth interface
	struct port_fq_info fqinfo[MAX_FQ_TYPES];	//fq info for defa types
	struct port_fq_info eth_tx_fqinfo[DPAA_ETH_TX_QUEUES];	//ethdrv TX FQs 
	struct qman_fq fwd_tx_fqinfo[DPAA_FWD_TX_QUEUES]; /* cctable TX FQs */
	/* Tail drop over fwd_tx_fqinfo[] by frames: as many of the largest the
	 * MTU admits as take fwd_queue_us at the link's speed, at most a share
	 * of the Ethernet pool (devman.c). fwd_cgr_speed is the Mbit/s the
	 * threshold was sized for; zero until the group is set up and again
	 * once it is torn down. */
	struct qman_cgr fwd_cgr;
	uint32_t fwd_cgr_speed;
	/* The same queues again for what the IPsec offline port sends out of
	 * this port, all of it in buffers of SEC's output pool, with a group
	 * of its own bounded by a share of that pool (devman.c). */
	struct qman_fq sec_tx_fqinfo[DPAA_FWD_TX_QUEUES];
	struct qman_cgr sec_cgr;
	/* The port MTU both groups' bounds were sized for: they count frames,
	 * so the largest frame decides how long they queue. */
	uint32_t fwd_cgr_mtu;
	/* What the port's counters report while CDX holds it (devman.c), under
	 * dpa_devlist_lock. Transmit is what its MAC sent: what the port
	 * reported as CDX took it -- or, if its transmit never stood still
	 * then, at the first reading that did, which a port a hardware qdisc
	 * owns by then never has -- less what was still queued
	 * for it then (base_*), then the MAC's advance since, which offloaded
	 * frames an egress group refused never join: the MAC's counts then less
	 * the base taken with them, never a sum of clamped steps, and never
	 * reported below what was reported before (packets, bytes).
	 * last_frames is the last reading's frames, which fewer than says the
	 * MAC's counts were reset. Receive adds what the port took in and FMan
	 * then dropped: frames its enqueues lost to a congestion group, as
	 * drops, and frames it found no buffer for, as missed -- each a 32-bit
	 * BMI count carried past its wrap -- and frames the MAC dropped itself,
	 * its FIFO full, as missed too. link_speed is the Mbit/s the link ran
	 * at as CDX took the port, or last reported since -- the MAC's fastest
	 * while it has reported none -- which a reading from the statistics
	 * hook is timed by; zero until the port's queues are all made, and no
	 * such reading is taken until then. */
	struct {
		bool ready;
		u64 base_packets, base_bytes;
		u64 mac_frames, mac_octets;
		u64 last_frames;
		u64 packets, bytes;
		uint32_t link_speed;
	} tx_wire;
	struct port_bmi_count rx_discarded, rx_no_buffer;
	struct port_mac_count rx_mac_dropped;
	uint32_t rx_channel_id;		//channel id rx
	uint32_t tx_channel_id;		//channel id tx
	uint32_t tx_wq;			//tx work queue
	uint32_t rx_pcd_wq;		//wq used by ethernet driver pcd queues
	qman_cb_dqrr dqrr;
	/* The driver's congestion group for the port's queues to the CPU
	 * (dpaa_eth_priv_ingress_cgr_init()), a share of the pool counted in
	 * frames, which the distribution queues cdx makes for the port join
	 * as well (A347). NULL where the driver keeps none. */
	const struct qman_cgr *rx_cgr;
	uint32_t num_pools;	//pools used by port
	struct port_bman_pool_info pool_info[MAX_PORT_BMAN_POOLS]; //pool info
	/* No mac_addr here: a physical port's own address is net_dev's, read
	 * where the Ethernet header is encoded, rather than a cached copy that
	 * goes stale the moment anyone changes it. */
	uint32_t max_dist;		//max PCD distributions
	struct cdx_dist_info *dist_info;//pointer to array of pcd dist
	struct dpa_fq *defa_rx_dpa_fq; //default rx fq pointer
	struct dpa_fq *err_rx_dpa_fq;  //rx err fq pointer
};

//offline port device information
struct oh_iface_info {
        uint32_t fman_idx;              //fman index within SOC
        uint32_t port_idx;              //port index within fman
        uint32_t portid;                //portid from xml file
        struct port_fq_info fqinfo[MAX_FQ_TYPES]; //fq info for defa types
        uint32_t channel_id;            //channel id
        uint32_t max_dist;              //max PCD distributions
        struct cdx_dist_info *dist_info;//pointer to array of pcd dist
};

struct wlan_iface_info {
	/* The device this VAP rides, so a netdev can be resolved back to its
	 * iface the way an ethernet port can. Borrowed, never dereferenced --
	 * only compared -- and cleared when the VAP is retired, which is what
	 * the ethernet arm's own net_dev does. */
	struct net_device *net_dev;
	uint16_t vap_id;
	uint8_t mac_addr[ETH_ALEN];	/* Wlan interface mac address */
	uint32_t fman_idx;
	uint32_t port_idx;
	uint32_t portid;
};

struct iface_stats {
	uint32_t tx_packets;
	uint32_t rx_packets;
	uint64_t tx_bytes;
	uint64_t rx_bytes;
};

//dpa interface structure
struct dpa_iface_info {
	struct dpa_iface_info *next; //single link to next iface
	uint32_t if_flags; 	//from itf structure
	uint32_t itf_id;	//from itf_structure
	uint32_t osid;		//linux interface id

	uint8_t name[IF_NAME_SIZE]; //name as seen by OS
	/* Only physical ports register: Ethernet ports, Wi-Fi VAPs and the
	 * offline ports. A VLAN, PPPoE session or tunnel in front of one is
	 * described by the flow that crosses it. */
	union {
		struct eth_iface_info eth_info; //info if iface type is eth
		struct wlan_iface_info wlan_info; //internal wlan  info
		struct oh_iface_info oh_info; //internal oh parsing port info

	};
	void *tx_proc_entry;
	void *rx_proc_entry;
	void *pcd_proc_entry;
	struct qman_fq *egress_fqs[DPAA_ETH_TX_QUEUES]; /* storage for ethernet FQs replaces by CEETM FQs */
#ifdef INCLUDE_IFSTATS_SUPPORT
	void *stats;
	struct iface_stats *last_stats;
	uint8_t rxstats_index;
	uint8_t txstats_index;
#endif
};


//flags field values in struct oh_port_fq_td_info
#define OF_FQID_VALID           (1 << 8)
#define IN_USE                  (1 << 9)
#define PORT_VALID              (1 << 16)
#define PORT_TYPE_WIFI          (1 << 12)
#define PORT_TYPE_IPSEC         (2 << 12)
#define PORT_TYPE_MASK          (3 << 12)

int find_pcd_fq_info(uint32_t fqid);
void add_pcd_fq_info(struct dpa_fq *fq_info);
void cdx_destroy_fq(struct qman_fq *fq);
/* A parked, tail-dropping queue an entry enqueues to in order to drop what it
 * matches; see devman.c. The id, created on first use, under the control lock;
 * torn down at unload after the ports stop. */
int cdx_discard_fqid(uint32_t *fqid);
void cdx_discard_exit(void);
void cdx_drain_fq_list(struct dpa_fq *head);
void cdx_destroy_fq_list(struct dpa_fq **head);
void cdx_reset_offline_ports(void);
int get_dpa_eth_iface_info(struct eth_iface_info *iface_info, char *name);
int cdxdrv_create_of_fqs(struct dpa_iface_info *iface_info);
int get_ofport_fman_and_portindex(uint32_t fm_index, uint32_t handle, uint32_t* fm_idx, uint32_t* port_idx,
		uint32_t *portid);
int alloc_iface_stats(uint32_t dev_type, struct dpa_iface_info *iface);
void cdx_deinit_iface_stats(void *muram_handle);
void free_iface_stats(uint32_t dev_type, struct dpa_iface_info *iface);
/* The periodic read that keeps every record's packet count exact past the
 * firmware's 32 bits. Paired with the dev_get_stats hook, from module init to
 * module exit; stop may sleep. */
void cdx_ifstats_start(void);
void cdx_ifstats_stop(void);
int get_ofport_portid(uint32_t fm_idx, uint32_t handle, uint32_t *portid);
int get_ofport_info(uint32_t fm_idx, uint32_t handle, uint32_t *channel, void **td);
int get_ofport_max_dist(uint32_t fm_idx, uint32_t handle, uint32_t* max_dist);
int get_phys_port_poolinfo_bysize(uint32_t size, struct port_bman_pool_info *pool_info);
int alloc_offline_port(uint32_t fm_idx, uint32_t type, qman_cb_dqrr defa_rx, qman_cb_dqrr err_rx);
int get_oh_port_pcd_fqinfo(uint32_t fm_idx, uint32_t handle, uint32_t index,
			uint32_t *pfqid, uint32_t *count);
int release_offline_port(uint32_t fm_idx, int handle);
int get_dpa_oh_iface_info(struct oh_iface_info *iface_info, char *name);
int  get_tableInfo_by_portid( int fm_index, int portid,  void **td,  int * flags);
int dpa_add_port_to_list(struct dpa_iface_info *iface_info);
struct dpa_iface_info *dpa_get_ifinfo_by_itfid(uint32_t itf_id);
struct dpa_iface_info *dpa_get_ifinfo_by_netdev(const struct net_device *dev);
bool dpa_netdev_is_physical(const struct net_device *dev);
void dpa_fwd_cgr_follow_link(struct net_device *dev);
void dpa_port_counters_sample(void);
bool dpa_netdev_is_dpaa(const struct net_device *dev);
extern spinlock_t dpa_devlist_lock;
struct dpa_iface_info *dpa_get_ohifinfo_by_portid(uint32_t portid);
int cdx_copy_eth_rx_channel_info(uint32_t fman_idx, struct dpa_fq *dpa_fq);
int cdx_create_fq(struct dpa_fq *dpa_fq, uint32_t flags, void *pcd_proc_entry,
		  const struct qman_cgr *cgr);
void dpa_release_iflist(void);
/* The classifier ports CDX configured, stopped and started again around a
 * repair of the tables they walk; see dpa_cfg.c. RTNL and the control mutex
 * held for each. Stop never detaches a port or drains a queue, so resume puts
 * every port back exactly as it was; quiesce does both, for unload, and leaves
 * the ports for good. Resume returns how many ports would not start, or a
 * negative errno. */
int dpa_cfg_stop(void);
int dpa_cfg_resume(void);
int dpa_cfg_quiesce(void);
bool dpa_cfg_covered(void);
int dpa_cfg_shared_icid(void);
int dpa_cfg_port_rejected(uint32_t portid, u32 *count);
void dpa_cfg_deinit(void);
/* An external hash table of the configuration, to issue a PCD barrier through
 * when the caller has none of its own; NULL before one is configured. Caller
 * holds the control mutex. */
void *dpa_get_ehash_td(void);
/* Caller holds the control mutex. */
uint32_t dpa_get_num_fmans(void);
/* Caller holds the control mutex and RTNL; RTNL is dropped during retry waits. */
void qm_quiesce(void);
uint32_t get_logical_ifstats_base(void);
void *dpa_get_fm_MURAM_handle(uint32_t fm_idx, uint64_t *phyBaseAddr,
					uint32_t *MuramSize);
int dpaa_vwd_init(void);
void dpaa_vwd_exit(void);
uint32_t cdx_get_txfqid(struct eth_iface_info *eth_info, void *markval,
			uint32_t hash);
uint32_t cdx_get_sec_txfqid(struct eth_iface_info *eth_info, void *markval,
			    uint32_t hash);
int cdx_get_tx_dscp_fq_map(struct eth_iface_info *eth_info, uint8_t *is_dscp_fq_map, void *markval);
int dpaa_is_oh_port(uint32_t portid);
#endif
