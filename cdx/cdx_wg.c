// SPDX-License-Identifier: GPL-2.0-or-later
/* WireGuard offload.
 *
 * A WireGuard device as an egress the classifier may finish frames for, and
 * the receive path for its tunnels. It owns everything it uses -- its devices'
 * slots and logical interfaces, the queues it seals on and the steer queues it
 * receives on, one congestion group -- and shares nothing with VWD, whose
 * Wi-Fi VAPs reach the CPU the same way.
 *
 * Upload: a flow the flowtable sends into a registered WireGuard device is
 * installed with that device's logical interface as its egress
 * (IF_TYPE_WG). The encoder writes a made-up Ethernet header
 * (cdx_ft_wg_mac()) and enqueues the frame to one of the device's seal queues,
 * one per CPU (cdx_wg_get_seal_fq()). Its dequeue seals the packet where it
 * lies (wg_fastpath_seal()) and sends it out of the DPAA port the outer route
 * names, from the same buffer; anything the seal declines is handed to the
 * device as an skb.
 *
 * Download: the outer tuple a seal wrote is steered back, exactly, to a queue
 * of this file's (the steer section below), and each datagram is opened where
 * it lies (wg_fastpath_open()) and forwarded out of a DPAA port when the
 * flowtable holds its flow.
 *
 * Every dequeue callback runs in softirq: the portal's own NAPI drains it
 * (CONFIG_FSL_ASK_QMAN_PORTAL_NAPI, which registration requires), a volatile
 * dequeue included.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/rcupdate.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/udp.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/fsl_bman.h>
#include <net/ip.h>
#include <net/wg_fastpath.h>
#include <net/netfilter/nf_flow_table.h>

#include "portdefs.h"
#include "misc.h"
#include "dpaa_eth.h"
#include "dpaa_eth_common.h"
#include "layer2.h"
#include "cdx.h"
#include "cdx_common.h"
#include "devman.h"
#include "cdx_flowtable_backend.h"
#include "cdx_wg.h"
#include "procfs.h"

/* Work queue of every queue here, as VWD's and the classifier's PCD queues
 * use: below the transmit confirmations and the host command's answers. */
#define CDX_WG_WQ		5

/* Frames every WireGuard queue -- seal and steer -- may hold together before
 * QMan refuses the classifier's enqueue and FMan drops the frame. They are
 * Ethernet-pool frames, so this is WireGuard's share of the common private
 * pool (12720 buffers), which no other consumer's group counts.
 * ponytail: one group for every WireGuard device; a device per group if one
 * tunnel's backlog should not hold another's. */
#define CDX_WG_QUEUE_FRAMES	2048

/* A registered device's seal queue: on one CPU's portal channel. */
struct cdx_wg_sealq {
	struct qman_fq fq;
	struct cdx_wg_dev *w;
	unsigned int cpu;
};

struct cdx_wg_dev_pc {
	/* Sealed and sent from the buffer; handed to the device as an skb;
	 * not sent (no room, no port); released as the device went. */
	unsigned long sealed, slow, tx_fail, down;
};

enum {
	CDX_WG_FREE,
	CDX_WG_OPEN,
	/* Unregistering: the datapath lets go (cdx_wg_netdev_event()); the
	 * flowtable's worker releases the rest (cdx_wg_dev_del()). */
	CDX_WG_GONE,
};

/* A registered WireGuard device.
 *
 * The slots are static, so a pointer to one is always valid; what it names is
 * `state` and `gen`. Every transition happens under RTNL (registration and
 * release under the flowtable transaction as well), and the datapath reads
 * them under RCU: `dev` is followed only while the slot is OPEN, which it
 * stops being inside the device's NETDEV_UNREGISTER notifier -- before the
 * core's synchronize_net() and so before the device can be freed. `gen` moves
 * with every registration, so a queue of an earlier one does not pass for the
 * current (cdx_wg_live()).
 *
 * The device is borrowed, never referenced: a reference would be one
 * unregister_netdevice() waits for, and the worker that would drop it runs
 * after unregistration.
 */
struct cdx_wg_dev {
	struct net_device *dev;
	unsigned int state;
	u32 gen;
	u16 id;
	/* The CPU its tunnel is received on (steer queue), which its flows are
	 * sealed away from; -1 when every CPU receives it (wg_rx_spread). */
	int rx_cpu;
	/* The logical interface the classifier names as the egress. */
	struct _itf itf;
	u8 mac[ETH_ALEN];
	char ifname[IFNAMSIZ];
	unsigned int nq;
	struct cdx_wg_sealq *sq;
	struct cdx_wg_dev_pc __percpu *pc;
};

#define CDX_WG_DEVS	8
static struct cdx_wg_dev cdx_wg_devs[CDX_WG_DEVS];
static struct qman_cgr cdx_wg_cgr;
static bool cdx_wg_ready;
/* Set first at exit: no frame notes a steer after it (every note is made in a
 * dequeue's RCU read section), and no work re-arms. */
static bool cdx_wg_stopping;

/* The device a queue of registration `gen` may use, or NULL. Under RCU. */
static struct net_device *cdx_wg_live(const struct cdx_wg_dev *w, u32 gen)
{
	struct net_device *dev;

	if (smp_load_acquire(&w->state) != CDX_WG_OPEN || READ_ONCE(w->gen) != gen)
		return NULL;
	dev = READ_ONCE(w->dev);
	return dev && netif_running(dev) ? dev : NULL;
}

/* The open registration of `dev` and its generation; RTNL or the flowtable
 * transaction held. */
static struct cdx_wg_dev *cdx_wg_find_open(const struct net_device *dev, u32 *gen)
{
	unsigned int i;

	for (i = 0; i < CDX_WG_DEVS; i++) {
		struct cdx_wg_dev *w = &cdx_wg_devs[i];

		if (READ_ONCE(w->state) == CDX_WG_OPEN && w->dev == dev) {
			*gen = w->gen;
			return w;
		}
	}
	return NULL;
}

/* What every queue here shares, on `channel`: WireGuard's work queue and
 * congestion group, and the stashing the classifier's own CPU queues use. */
static void cdx_wg_fq_opts(struct qm_mcc_initfq *opts, u32 fqid, u16 channel)
{
	memset(opts, 0, sizeof(*opts));
	opts->fqid = fqid;
	opts->count = 1;
	opts->we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
			QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA |
			QM_INITFQ_WE_CGID;
	opts->fqd.dest.channel = channel;
	opts->fqd.dest.wq = CDX_WG_WQ;
	opts->fqd.fq_ctrl = QM_FQCTRL_CGE;
	opts->fqd.cgid = (u8)cdx_wg_cgr.cgrid;
	opts->fqd.context_a.stashing.exclusive =
		QM_STASHING_EXCL_DATA | QM_STASHING_EXCL_ANNOTATION;
	opts->fqd.context_a.stashing.data_cl = NUM_PKT_DATA_LINES_IN_CACHE;
	opts->fqd.context_a.stashing.annotation_cl = NUM_ANN_LINES_IN_CACHE;
}

/* The DPAA ports a WireGuard device's sealed frames may leave by, with cdx's
 * forwarding queues to each: the queues the classifier itself sends on, which
 * return a buffer to its pool instead of confirming it to the driver (the
 * driver's own egress queues confirm every frame, and its confirmation path
 * would look for an skb). Ports are load-once, so the table is filled under
 * the control mutex and RTNL and read without a lock. */
#define CDX_WG_PORTS 16
static struct {
	struct net_device *dev;
	struct eth_iface_info *eth;
} cdx_wg_ports[CDX_WG_PORTS];
static unsigned int cdx_wg_nports;

static void cdx_wg_ports_update(void)
{
	struct dpa_iface_info *iface;
	struct net_device *dev;
	unsigned int n = 0;

	ASSERT_RTNL();
	for_each_netdev(&init_net, dev) {
		if (n == CDX_WG_PORTS)
			break;
		if (!dpa_netdev_is_dpaa(dev))
			continue;
		iface = dpa_get_ifinfo_by_netdev(dev);
		if (!iface || !(iface->if_flags & IF_TYPE_ETHERNET))
			continue;
		WRITE_ONCE(cdx_wg_ports[n].eth, &iface->eth_info);
		WRITE_ONCE(cdx_wg_ports[n].dev, dev);
		n++;
	}
	smp_store_release(&cdx_wg_nports, n);
}

static struct eth_iface_info *cdx_wg_port(const struct net_device *dev)
{
	unsigned int i, n = smp_load_acquire(&cdx_wg_nports);

	for (i = 0; i < n; i++)
		if (READ_ONCE(cdx_wg_ports[i].dev) == dev)
			return READ_ONCE(cdx_wg_ports[i].eth);
	return NULL;
}

static bool cdx_wg_can_tx(const struct net_device *dev)
{
	if (!cdx_wg_port(dev))
		return false;
#ifdef CONFIG_FSL_DPAA_CEETM
	/* ponytail: a port a hardware qdisc owns shapes through its class
	 * queues, which this does not pick; such a port keeps the slow path. */
	if (((struct dpa_priv_s *)netdev_priv(dev))->ceetm_en)
		return false;
#endif
	return true;
}

/* Receive steers for WireGuard peers.
 *
 * A peer's packets arrive on the port its sealed frames leave by, addressed to
 * the router, so they miss every classifier table and end in the port's
 * Ethernet distribution -- which hashes only the L2 pair, the same for every
 * tunnel behind one upstream gateway, so every tunnel lands on one queue and
 * one CPU, through the exception policer. The seal reports the outer tuple it
 * wrote; its reverse is the peer's, and a classifier entry for that exact
 * tuple (cdx_ehash_steer4_add()) enqueues it, unmodified, to a frame queue of
 * the slot's own on a CPU picked round robin (struct cdx_wg_rxq below), whose
 * dequeue hands the datagram straight to WireGuard, as its socket would --
 * without the IP input, routing, netfilter and socket lookup the stack spends
 * on every packet.
 *
 * Security: a steered tuple skips the exception policer
 * CDX_EXPT_ETH_RATELIMIT, and its datagrams skip the netfilter PREROUTING and
 * INPUT hooks (and conntrack, tc ingress and rp_filter with them). Only an
 * established peer's exact five-tuple is ever steered, the one the router
 * itself just sealed for, and WireGuard authenticates every datagram it takes.
 *
 * The fast path only notes a tuple: it claims an empty slot without a lock
 * (EMPTY -> CLAIMING by cmpxchg, the fields written, then PENDING with
 * release) and schedules the worker. Everything after that -- the install,
 * the delete, every transition out of PENDING, INSTALLED or FAILED, and the
 * slot's `ct` and `rxq` -- happens under the control mutex. The fast path reads the
 * fields of a slot it does not own racily: a torn read can only make it skip
 * one claim, which the next frame makes again.
 *
 * Neither netdev is referenced. `wg` is compared by the slot: the worker
 * installs only for a device registered here and open, and cdx_wg_dev_del()
 * drops every slot of the device before its registration goes. The queue's
 * dequeue does follow its device, and so may not rely on that drop -- which
 * can come after the device has unregistered -- but only on this file's own
 * unregister notifier: see cdx_wg_rxq_dev(). `port` is a DPAA port, which is
 * load-once (cdx_wg_ports above).
 *
 * ponytail: 16 slots, first come; a peer past them stays on the miss path.
 * ponytail: endpoint roaming is not followed. A roamed peer's new tuple takes a
 * new slot; the old entry stays until the device's registration goes.
 * ponytail: a FAILED slot is not retried while its device lives. */
enum {
	CDX_WG_STEER_EMPTY,
	CDX_WG_STEER_CLAIMING,
	CDX_WG_STEER_PENDING,
	CDX_WG_STEER_INSTALLED,
	CDX_WG_STEER_FAILED,
};

/* A steer queue's counters, per CPU, as an ordered queue is dequeued on every
 * CPU at once; read racily for statistics. */
struct cdx_wg_rxq_pc {
	unsigned long delivered, to_stack, dropped;
	/* Of delivered: opened where they lay and sent out of a port from the
	 * same buffer, or opened and handed to the device as an skb. */
	unsigned long forwarded, opened;
	/* Ordered queues: sequence numbers given up for a frame not sent on in
	 * order (cdx_wg_skip()), and those QMan never took. */
	unsigned long skipped, skip_fail;
};

/* An installed steer's frame queue, in WireGuard's congestion group.
 * Allocated per install rather than embedded in the slot, because a delete
 * that cannot prove the entry unlinked must leave the queue standing after the
 * slot is reused (cdx_wg_rxq_abandon()).
 *
 * Either on one CPU's portal channel, or `ordered`: on the port's pool
 * channel, which every CPU's portal dequeues, avoiding blocking, so one
 * tunnel's frames are opened on every CPU at once, and with an order
 * restoration point, so QMan puts the frames sent on back in the order they
 * arrived (cdx_wg_rxq_create()). An ordered queue's forwarded frames all
 * leave by egress queue `txq`: restored order across two queues would be lost
 * again at the port.
 *
 * `wg`, `w` and `gen` name the device the dequeue delivers to and the
 * registration it must still be in (cdx_wg_rxq_dev()); `wg` is cleared before
 * the queue is drained or abandoned, after which every frame goes to the
 * stack. */
struct cdx_wg_rxq {
	struct qman_fq fq;
	struct net_device *port;
	struct net_device *wg;
	struct cdx_wg_dev *w;
	u32 gen;
	unsigned int cpu;
	bool ordered;
	unsigned int txq;
	struct cdx_wg_rxq_pc __percpu *pc;
	/* delivered at the last cdx_wg_inline_update() tick. */
	unsigned long seen;
};

#define CDX_WG_STEERS 16
static struct cdx_wg_steer {
	unsigned int state;
	struct net_device *wg;
	struct net_device *port;
	/* As the peer sends them: peer -> router, network order. */
	__be32 saddr, daddr;
	__be16 sport, dport;
	struct hw_ct *ct;
	/* Set with the entry, cleared before the queue is freed; statistics
	 * read it under RCU, which the free waits out (cdx_destroy_fq()). */
	struct cdx_wg_rxq *rxq;
} cdx_wg_steers[CDX_WG_STEERS];
/* The next CPU, round robin over the affine ones; under the control mutex. */
static unsigned int cdx_wg_steer_cpu;

static void cdx_wg_steer_work_fn(struct work_struct *work);
static DECLARE_WORK(cdx_wg_steer_work, cdx_wg_steer_work_fn);

static bool cdx_wg_steer_same(const struct cdx_wg_steer *a, const struct cdx_wg_steer *b)
{
	return a->wg == b->wg && a->port == b->port &&
	       a->saddr == b->saddr && a->daddr == b->daddr &&
	       a->sport == b->sport && a->dport == b->dport;
}

/* The fast path's half: lock-free, never sleeps. */
static void cdx_wg_steer_note(struct net_device *wg, const struct wg_fastpath_tx *tx)
{
	struct cdx_wg_steer *s;
	int i, slot = -1;

	if (READ_ONCE(cdx_wg_stopping))
		return;
	for (i = 0; i < CDX_WG_STEERS; i++) {
		s = &cdx_wg_steers[i];
		switch (smp_load_acquire(&s->state)) {
		case CDX_WG_STEER_EMPTY:
			if (slot < 0)
				slot = i;
			break;
		case CDX_WG_STEER_CLAIMING:
			break;
		default:
			if (READ_ONCE(s->wg) == wg && READ_ONCE(s->port) == tx->dev &&
			    READ_ONCE(s->saddr) == tx->daddr &&
			    READ_ONCE(s->daddr) == tx->saddr &&
			    READ_ONCE(s->sport) == tx->dport &&
			    READ_ONCE(s->dport) == tx->sport)
				return;
		}
	}
	if (slot < 0)
		return;
	s = &cdx_wg_steers[slot];
	/* Lost to another CPU: the next frame looks again. */
	if (cmpxchg(&s->state, CDX_WG_STEER_EMPTY, CDX_WG_STEER_CLAIMING) !=
	    CDX_WG_STEER_EMPTY)
		return;
	WRITE_ONCE(s->wg, wg);
	WRITE_ONCE(s->port, tx->dev);
	WRITE_ONCE(s->saddr, tx->daddr);
	WRITE_ONCE(s->daddr, tx->saddr);
	WRITE_ONCE(s->sport, tx->dport);
	WRITE_ONCE(s->dport, tx->sport);
	smp_store_release(&s->state, CDX_WG_STEER_PENDING);
	schedule_work(&cdx_wg_steer_work);
}

#define cdx_wg_count(q, f)	this_cpu_inc((q)->pc->f)

static unsigned long cdx_wg_sum(const struct cdx_wg_rxq *q, size_t off)
{
	unsigned long sum = 0;
	int cpu;

	for_each_possible_cpu(cpu)
		sum += READ_ONCE(*(unsigned long *)((u8 *)per_cpu_ptr(q->pc, cpu) + off));
	return sum;
}
#define cdx_wg_total(q, f)	cdx_wg_sum(q, offsetof(struct cdx_wg_rxq_pc, f))

/* An ordered queue's frame owes the queue's order restoration point exactly
 * one enqueue under its sequence number: the frame itself, sent on in order,
 * or a hole, which lets the frames behind it go. */
struct cdx_wg_seq {
	u16 seq;
	bool owed;
};

/* How long an enqueue under an order restoration point waits for room in the
 * portal's ring. It must not be given up lightly: a sequence number never
 * enqueued holds every later frame until the window overflows, and at idle
 * for good. QMan leaves every portal's ring full at once for up to ~200 us
 * under load (measured), past a fixed retry count's reach.
 * ponytail: a ring full past this is not recovered; the queue's next open
 * (wg down/up) gives it a fresh restoration point. */
#define CDX_WG_ORP_WAIT_NS	(5 * NSEC_PER_MSEC)

static int cdx_wg_orp_enqueue(struct cdx_wg_rxq *q, struct qman_fq *fq,
			      const struct qm_fd *fd, u32 flags, u16 seq)
{
	u64 start = 0, now;
	int err;

	while ((err = qman_enqueue_orp(fq, fd, flags, &q->fq, seq)) == -EBUSY) {
		now = ktime_get_ns();
		if (!start)
			start = now;
		else if (now - start > CDX_WG_ORP_WAIT_NS)
			break;
		cpu_relax();
	}
	if (unlikely(err))
		pr_warn_ratelimited("cdx: WireGuard rx order: portal ring full for 5 ms, sequence %u of fqid 0x%x lost\n",
				    seq, q->fq.fqid);
	return err;
}

/* Give up the frame's place in the order, before anything slow is done with
 * it. A hole goes in under the steer queue's own object with an empty
 * descriptor, so a rejection has nothing to free (cdx_wg_hole_ern()). */
static void cdx_wg_skip(struct cdx_wg_rxq *q, struct cdx_wg_seq *s)
{
	static const struct qm_fd none;

	if (!s->owed)
		return;
	s->owed = false;
	if (unlikely(cdx_wg_orp_enqueue(q, &q->fq, &none, QMAN_ENQUEUE_FLAG_HOLE, s->seq)))
		cdx_wg_count(q, skip_fail);
	else
		cdx_wg_count(q, skipped);
}

/* The device a steered datagram may be handed to, or NULL for the stack.
 *
 * Under rcu_read_lock(). The device is not referenced, and the slot's delete
 * (cdx_wg_dev_del()) may come after the device has unregistered, so what
 * keeps it alive here is the registration's own state: cdx_wg_netdev_event()
 * takes it out of OPEN inside the device's NETDEV_UNREGISTER notifier, and the
 * core runs synchronize_net() after its notifiers and before the device can be
 * freed or WireGuard's destructor run (unregister_netdevice_many_notify(), then
 * netdev_run_todo()). A read section that saw the open therefore began before
 * that grace period and ends before either. The generation, bumped by every
 * registration before the state is published, keeps a later one of the slot
 * -- by another device at a reused address, say -- from passing for the one the
 * steer was installed under. netif_running() keeps a device being closed,
 * whose socket WireGuard has already let go of, on the stack's path. */
static struct net_device *cdx_wg_rxq_dev(const struct cdx_wg_rxq *q)
{
	struct net_device *wg = READ_ONCE(q->wg);

	return wg && cdx_wg_live(q->w, q->gen) == wg ? wg : NULL;
}

enum {
	CDX_WG_RX_DELIVER,
	CDX_WG_RX_STACK,
	CDX_WG_RX_DROP,
};

/* What becomes of a steered frame, the skb at its IPv4 header: delivered as
 * WireGuard's socket would take it, handed to the stack for anything that is
 * well formed but not a plain datagram, or dropped as malformed. On delivery
 * the transport header is set and the UDP checksum is validated --
 * CHECKSUM_UNNECESSARY when the parser vouched for it (contig_fd_to_skb() and
 * sg_fd_to_skb() trust FM_FD_STAT_L4CV only with the parse result's checksum
 * at its valid value, and only on a port with NETIF_F_RXCSUM), otherwise
 * checked here over the UDP length. WireGuard checks the UDP length framing
 * again itself (prepare_skb_header()). */
static int cdx_wg_rx_check(struct sk_buff *skb)
{
	const struct iphdr *iph;
	const struct udphdr *uh;
	unsigned int ihl, len, ulen;

	if (skb->protocol != htons(ETH_P_IP) || skb->pkt_type != PACKET_HOST)
		return CDX_WG_RX_STACK;
	if (!pskb_may_pull(skb, sizeof(*iph)))
		return CDX_WG_RX_DROP;
	iph = ip_hdr(skb);
	if (iph->version != 4 || iph->ihl < 5)
		return CDX_WG_RX_DROP;
	ihl = iph->ihl * 4;
	if (!pskb_may_pull(skb, ihl))
		return CDX_WG_RX_DROP;
	iph = ip_hdr(skb);
	if (ip_fast_csum((const u8 *)iph, iph->ihl))
		return CDX_WG_RX_DROP;
	len = ntohs(iph->tot_len);
	if (len < ihl || skb->len < len)
		return CDX_WG_RX_DROP;
	if (pskb_trim_rcsum(skb, len))
		return CDX_WG_RX_DROP;
	iph = ip_hdr(skb);
	/* Options are the stack's to act on and a fragment its to reassemble;
	 * neither is how a WireGuard peer sends. */
	if (ihl != sizeof(*iph) || ip_is_fragment(iph) ||
	    iph->protocol != IPPROTO_UDP)
		return CDX_WG_RX_STACK;
	skb_set_transport_header(skb, ihl);
	if (!pskb_may_pull(skb, ihl + sizeof(*uh)))
		return CDX_WG_RX_DROP;
	iph = ip_hdr(skb);
	uh = udp_hdr(skb);
	ulen = ntohs(uh->len);
	if (ulen < sizeof(*uh) || ulen > len - ihl)
		return CDX_WG_RX_DROP;
	/* A zero checksum is IPv4 UDP's "none", which the socket takes too. */
	if (uh->check && skb->ip_summed != CHECKSUM_UNNECESSARY &&
	    csum_tcpudp_magic(iph->saddr, iph->daddr, ulen, IPPROTO_UDP,
			      skb_checksum(skb, ihl, ulen, 0)))
		return CDX_WG_RX_DROP;
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	return CDX_WG_RX_DELIVER;
}


/* The download fast path (cdx_wg_rx_raw()): 0 off, 1 on, 2 while the steered
 * tunnels that delivered in the last second sit on two CPUs or more, or for
 * an ordered queue (wg_rx_spread) always. A tunnel on one receive CPU is
 * opened there in arrival order, which its decryption workers outrun; two or
 * more such tunnels, or one opened on every CPU, do not.
 * ponytail: a knob while the trade-off is measured. */
static unsigned int wg_rx_raw = 2;
module_param(wg_rx_raw, uint, 0644);
MODULE_PARM_DESC(wg_rx_raw, "WireGuard download fast path: 0 off, 1 on, 2 with two or more active tunnels");
static bool cdx_wg_raw_auto;

/* Steer queues ordered (struct cdx_wg_rxq): a tunnel opened on every CPU
 * rather than on one receive CPU of its own. Read as a steer is installed and
 * as a tunnel opens, so a change takes effect on the tunnel's next open.
 * ponytail: a knob while the trade-off is measured. */
static unsigned int wg_rx_spread = 1;
module_param(wg_rx_spread, uint, 0644);
MODULE_PARM_DESC(wg_rx_spread, "WireGuard receive: 1 opens each tunnel on every CPU, order restored by QMan; 0 on one CPU per tunnel");

/* The restoration window, as QMan encodes it (0: 32 frames, doubling, 7: 4096):
 * how far ahead of the oldest frame still owed a frame may be sent on before
 * QMan moves on without it -- which it then takes late, out of order (OA and
 * OLWS, cdx_wg_rxq_create()), rather than rejecting either. */
#define CDX_WG_ORP_WINDOW	5

/* The parser's checksum verdict, as _dpa_process_parse_results() reads it. */
#define CDX_WG_CSUM_VALID	0xFFFF

/* A packet the open path decrypted but cannot send out of a port itself,
 * handed to the WireGuard device as an skb over the same buffer, as its own
 * receive path hands one on (wg_packet_consume_data_done()). Built from the
 * frame as received, then cut to the plaintext. */
static void cdx_wg_rx_open_stack(struct cdx_wg_rxq *q, struct net_device *wg,
				 const struct qm_fd *fd, u8 *data, u8 *inner,
				 unsigned int ilen)
{
	struct dpa_priv_s *priv = netdev_priv(q->port);
	struct dpa_bp *dpa_bp = priv->dpa_bp;
	int *count_ptr = raw_cpu_ptr(priv->percpu_count);
	bool use_gro = false;
	struct sk_buff *skb;

	if (unlikely(dpaa_eth_refill_bpools(dpa_bp, count_ptr,
					    CONFIG_FSL_DPAA_ETH_REFILL_THRESHOLD))) {
		dpa_fd_release(q->port, fd);
		cdx_wg_count(q, dropped);
		return;
	}
	dma_unmap_single(dpa_bp->dev, qm_fd_addr(fd), dpa_bp->size,
			 DMA_BIDIRECTIONAL);
	skb = contig_fd_to_skb(priv, fd, &use_gro, false);
	(*count_ptr)--;
	__skb_pull(skb, inner - data);
	__skb_trim(skb, ilen);
	skb->dev = wg;
	skb->protocol = (inner[0] >> 4) == 4 ? htons(ETH_P_IP) : htons(ETH_P_IPV6);
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	skb->pkt_type = PACKET_HOST;
	/* Authenticated by its tag, so every checksum inside is as received. */
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb->csum_level = ~0;
	netif_receive_skb(skb);
	cdx_wg_count(q, opened);
}

/* A steered frame opened where it lies (wg_fastpath_open()) and, when the
 * flowtable already holds its flow -- one the forward chain admitted -- sent
 * out of a DPAA port from the same buffer: the buffer keeps its pool, so the
 * port returns it on transmission and the pool's count is left alone, as for
 * a frame the classifier forwards. Returns false, with the frame untouched,
 * for the skb path; true once the frame is forwarded, delivered or dropped.
 * An ordered queue's frame is sent on in order under `s`, or gives its place
 * up before the slow path. */
static bool cdx_wg_rx_raw(struct cdx_wg_rxq *q, const struct qm_fd *fd,
			  struct cdx_wg_seq *s)
{
	struct net_device *port = q->port, *wg;
	struct dpa_priv_s *priv = netdev_priv(port);
	struct dpa_percpu_priv_s *percpu_priv = raw_cpu_ptr(priv->percpu_priv);
	unsigned int len, tot, ulen, ilen;
	struct nf_flow_raw_xmit x;
	struct eth_iface_info *eth;
	struct nf_flowtable *ft;
	u8 *vaddr, *data, *inner;
	struct udphdr *uh;
	struct iphdr *iph;
	struct qm_fd tfd;
	int i, err;

	/* An ordered queue is opened on every CPU already, so auto is on. */
	if (fd->format != qm_fd_contig || !READ_ONCE(wg_rx_raw) ||
	    (READ_ONCE(wg_rx_raw) == 2 && !READ_ONCE(cdx_wg_raw_auto) && !q->ordered))
		return false;
	wg = cdx_wg_rxq_dev(q);
	if (!wg)
		return false;
	vaddr = phys_to_virt(qm_fd_addr(fd));
	data = vaddr + dpa_fd_offset(fd);
	len = dpa_fd_length(fd);
	if (len < ETH_HLEN + sizeof(*iph) + sizeof(*uh) ||
	    ((struct ethhdr *)data)->h_proto != htons(ETH_P_IP))
		return false;
	iph = (struct iphdr *)(data + ETH_HLEN);
	if (iph->version != 4 || iph->ihl != 5 || ip_fast_csum((u8 *)iph, 5) ||
	    ip_is_fragment(iph) || iph->protocol != IPPROTO_UDP)
		return false;
	tot = ntohs(iph->tot_len);
	if (tot < sizeof(*iph) + sizeof(*uh) || tot > len - ETH_HLEN)
		return false;
	uh = (struct udphdr *)(iph + 1);
	ulen = ntohs(uh->len);
	if (ulen < sizeof(*uh) || ulen > tot - sizeof(*iph))
		return false;
	/* The parser's verdict when the port asked for it, else checked here;
	 * a bad one is the skb path's to drop and count. */
	if (uh->check) {
		const fm_prs_result_t *pr =
			(const fm_prs_result_t *)(vaddr + DPA_RX_PRIV_DATA_SIZE);

		if (!((READ_ONCE(port->features) & NETIF_F_RXCSUM) &&
		      (fd->status & FM_FD_STAT_L4CV) && pr->cksum == CDX_WG_CSUM_VALID) &&
		    csum_tcpudp_magic(iph->saddr, iph->daddr, ulen, IPPROTO_UDP,
				      csum_partial(uh, ulen, 0)))
			return false;
	}

	switch (wg_fastpath_open(wg, iph, uh, port->ifindex, (u8 *)(uh + 1),
				 ulen - sizeof(*uh), &inner, &ilen)) {
	case WG_FP_PASS:
		return false;
	case WG_FP_CONSUMED:
		percpu_priv->stats.rx_packets++;
		percpu_priv->stats.rx_bytes += len;
		dpa_fd_release(port, fd);
		cdx_wg_count(q, dropped);
		return true;
	}
	percpu_priv->stats.rx_packets++;
	percpu_priv->stats.rx_bytes += len;
	cdx_wg_count(q, delivered);

	if ((inner[0] >> 4) != 4 || !(ft = nf_flow_table_ingress(wg)) ||
	    nf_flow_offload_ip_raw(ft, wg, (struct iphdr *)inner, ilen,
				   cdx_wg_can_tx, &x)) {
		cdx_wg_skip(q, s);
		cdx_wg_rx_open_stack(q, wg, fd, data, inner, ilen);
		return true;
	}
	/* cdx_wg_can_tx() passed it, so the port is in the table. */
	eth = cdx_wg_port(x.dev);
	data = inner - ETH_HLEN;
	ether_addr_copy(data, x.h_dest);
	ether_addr_copy(data + ETH_ALEN, x.h_source);
	((struct ethhdr *)data)->h_proto = htons(ETH_P_IP);
	tfd = *fd;
	tfd.offset = data - vaddr;
	tfd.length20 = ilen + ETH_HLEN;
	tfd.cmd = 0;
	err = -EBUSY;
	if (s->owed) {
		err = cdx_wg_orp_enqueue(q, &eth->fwd_tx_fqinfo[q->txq], &tfd, 0, s->seq);
		/* Still owed on failure: the caller gives the place up. */
		s->owed = !!err;
	} else {
		/* One CPU's queue: the frames are in order already. */
		for (i = 0; i < 1000 && err == -EBUSY; i++)
			err = qman_enqueue(&eth->fwd_tx_fqinfo[smp_processor_id() &
							       (DPAA_FWD_TX_QUEUES - 1)],
					   &tfd, 0);
	}
	if (unlikely(err)) {
		dpa_fd_release(port, &tfd);
		cdx_wg_count(q, dropped);
	} else {
		cdx_wg_count(q, forwarded);
	}
	return true;
}

/* One steered frame, under rcu_read_lock(). It was received by `port` and
 * enqueued as it arrived, so it is taken exactly as the port's own receive
 * would take it (priv_rx_default_dqrr(), _dpa_rx()): the port's pool refilled
 * against the port's per-CPU count, the skb built zero-copy over the buffer
 * (scatter/gather too, a jumbo frame's), the parse results read for the L4
 * checksum, and the port's receive counters advanced. */
static void cdx_wg_rxq_rx(struct cdx_wg_rxq *q, const struct qm_fd *fd,
			  struct cdx_wg_seq *s)
{
	struct net_device *port = q->port, *wg;
	struct dpa_priv_s *priv = netdev_priv(port);
	struct dpa_percpu_priv_s *percpu_priv = raw_cpu_ptr(priv->percpu_priv);
	struct dpa_bp *dpa_bp = priv->dpa_bp;
	bool use_gro = false, l4c;
	struct sk_buff *skb;
	int *count_ptr;

	if (unlikely(fd->status & FM_FD_STAT_RX_ERRORS)) {
		percpu_priv->stats.rx_errors++;
		goto release;
	}
	/* Only the port's own pool: anything else -- SEC's output pool or the
	 * fragment pool -- was not received by the port, and no steer enqueues
	 * it. */
	if (unlikely(dpa_bpid2pool(fd->bpid) != dpa_bp ||
		     (fd->format != qm_fd_contig && fd->format != qm_fd_sg)))
		goto release;
	if (cdx_wg_rx_raw(q, fd, s))
		return;
	cdx_wg_skip(q, s);
	count_ptr = raw_cpu_ptr(priv->percpu_count);
	if (unlikely(dpaa_eth_refill_bpools(dpa_bp, count_ptr,
					    CONFIG_FSL_DPAA_ETH_REFILL_THRESHOLD)))
		goto release;
	dma_unmap_single(dpa_bp->dev, qm_fd_addr(fd), dpa_bp->size,
			 DMA_BIDIRECTIONAL);
	l4c = !!(READ_ONCE(port->features) & NETIF_F_RXCSUM);
	if (likely(fd->format == qm_fd_contig)) {
		skb = contig_fd_to_skb(priv, fd, &use_gro, l4c);
	} else {
		skb = sg_fd_to_skb(priv, fd, &use_gro, count_ptr, l4c);
		percpu_priv->rx_sg++;
	}
	/* The contig buffer or the table, as _dpa_rx() accounts it. */
	(*count_ptr)--;
	if (unlikely(skb->len < ETH_HLEN)) {
		dev_core_stats_rx_dropped_inc(port);
		kfree_skb(skb);
		cdx_wg_count(q, dropped);
		return;
	}
	skb->protocol = eth_type_trans(skb, port);
	percpu_priv->stats.rx_packets++;
	percpu_priv->stats.rx_bytes += skb->len;
	skb_record_rx_queue(skb, raw_smp_processor_id());
	skb_reset_network_header(skb);
	skb->skb_iif = port->ifindex;

	switch (cdx_wg_rx_check(skb)) {
	case CDX_WG_RX_DROP:
		dev_core_stats_rx_dropped_inc(port);
		kfree_skb(skb);
		cdx_wg_count(q, dropped);
		return;
	case CDX_WG_RX_DELIVER:
		wg = cdx_wg_rxq_dev(q);
		if (likely(wg)) {
			wg_fastpath_receive(wg, skb);
			cdx_wg_count(q, delivered);
			return;
		}
		fallthrough;
	default:
		/* A well-formed frame with its network header set: the stack
		 * receives it as the port would have. */
		netif_receive_skb(skb);
		cdx_wg_count(q, to_stack);
		return;
	}

release:
	/* Every buffer of the frame, a scatter/gather frame's too. */
	dpa_fd_release(port, fd);
	cdx_wg_count(q, dropped);
}

static enum qman_cb_dqrr_result cdx_wg_rxq_dqrr(struct qman_portal *portal,
						struct qman_fq *fq,
						const struct qm_dqrr_entry *dq)
{
	struct cdx_wg_rxq *q = container_of(fq, struct cdx_wg_rxq, fq);
	struct cdx_wg_seq s;

	if (!(dq->stat & QM_DQRR_STAT_FD_VALID))
		return qman_cb_dqrr_consume;
	s.seq = dq->seqnum & QM_EQCR_SEQNUM_SEQMASK;
	s.owed = q->ordered;
	rcu_read_lock();
	cdx_wg_rxq_rx(q, &dq->fd, &s);
	/* Whatever path the frame took, its place is settled. */
	cdx_wg_skip(q, &s);
	rcu_read_unlock();
	return qman_cb_dqrr_consume;
}

/* Only a hole is enqueued under the steer queue's own object (the classifier
 * enqueues the frames, and takes its own rejections back), with an empty
 * descriptor: nothing to free, and the place it gave up is QMan's to skip on
 * its own (CDX_WG_ORP_WINDOW). */
static void cdx_wg_hole_ern(struct qman_portal *portal, struct qman_fq *fq,
			    const struct qm_mr_entry *msg)
{
	struct cdx_wg_rxq *q = container_of(fq, struct cdx_wg_rxq, fq);

	pr_warn_ratelimited("cdx: WireGuard rx order: hole %u of fqid 0x%x rejected (rc 0x%02x)\n",
			    msg->ern.seqnum, q->fq.fqid, msg->ern.rc);
	cdx_wg_count(q, skip_fail);
}

/* A steer's queue: WireGuard's work queue, stashing and congestion group. On
 * `cpu`'s portal channel, or `ordered` (struct cdx_wg_rxq): on the port's pool
 * channel with an order restoration point that, past its window, moves on
 * without a frame still owed (OA) and takes that frame late rather than
 * rejecting it (OLWS 3), so a CPU held up costs order, never a frame. Control
 * mutex held. */
static struct cdx_wg_rxq *cdx_wg_rxq_create(struct net_device *port,
					    struct net_device *wg,
					    struct cdx_wg_dev *w, u32 gen,
					    unsigned int cpu, bool ordered)
{
	struct qm_mcc_initfq opts;
	struct cdx_wg_rxq *q;

	q = kzalloc(sizeof(*q), GFP_KERNEL);
	if (!q)
		return ERR_PTR(-ENOMEM);
	q->pc = alloc_percpu(struct cdx_wg_rxq_pc);
	if (!q->pc) {
		kfree(q);
		return ERR_PTR(-ENOMEM);
	}
	q->port = port;
	q->wg = wg;
	q->w = w;
	q->gen = gen;
	q->cpu = cpu;
	q->ordered = ordered;
	q->txq = cpu & (DPAA_FWD_TX_QUEUES - 1);
	q->fq.cb.dqrr = cdx_wg_rxq_dqrr;
	q->fq.cb.ern = cdx_wg_hole_ern;
	if (qman_create_fq(0, QMAN_FQ_FLAG_DYNAMIC_FQID, &q->fq)) {
		free_percpu(q->pc);
		kfree(q);
		return ERR_PTR(-ENOMEM);
	}
	cdx_wg_fq_opts(&opts, q->fq.fqid, qman_affine_channel(cpu));
	if (ordered) {
		opts.fqd.dest.channel = ((struct dpa_priv_s *)netdev_priv(port))->channel;
		/* Default scheduling keeps an active queue on the one portal it
		 * was given, waiting on that portal's ring while the others idle;
		 * avoid-blocking hands each frame to any portal with room. */
		opts.fqd.fq_ctrl |= QM_FQCTRL_ORP | QM_FQCTRL_AVOIDBLOCK;
		opts.we_mask |= QM_INITFQ_WE_ORPC;
		opts.fqd.orprws = CDX_WG_ORP_WINDOW;
		opts.fqd.oa = 1;
		opts.fqd.olws = 3;
	}
	if (qman_init_fq(&q->fq, QMAN_INITFQ_FLAG_SCHED, &opts)) {
		/* Never initialised, so out of service already. */
		qman_destroy_fq(&q->fq, 0);
		free_percpu(q->pc);
		kfree(q);
		return ERR_PTR(-EIO);
	}
	cdx_create_type_fqid_info_in_procfs(&q->fq, UNSPECIFIED, NULL, NULL);
	return q;
}

/* Control mutex held, and nothing left to enqueue to the queue: its entry was
 * never linked, or is out of the table. Frames still queued go to the stack
 * (`wg` cleared first); cdx_destroy_fq() retires the queue, waits out its
 * asynchronous retirement, drains it through the callback and takes it out of
 * service, then runs synchronize_net()
 * before destroying it -- after which no callback and no statistics reader
 * still holds `q` (the slot's pointer was cleared before this). */
static void cdx_wg_rxq_destroy(struct cdx_wg_rxq *q)
{
	WRITE_ONCE(q->wg, NULL);
	cdx_destroy_fq(&q->fq);
	free_percpu(q->pc);
	kfree(q);
}

/* The entry may still be linked (cdx_ehash_steer_del() could not prove the
 * unlink), so frames may still arrive: a queue destroyed under them would
 * raise enqueue errors, and once its FQID went back to the allocator they
 * would land in whatever queue took it next. So the queue is left in service,
 * delivering to the stack from now on, and deliberately leaked -- one per
 * failed delete, which has latched the datapath restart that settles the key.
 * The module is pinned with it: the callback must not be unloaded from under a
 * queue still in service. */
static void cdx_wg_rxq_abandon(struct cdx_wg_rxq *q)
{
	WRITE_ONCE(q->wg, NULL);
	__module_get(THIS_MODULE);
	pr_warn("cdx: WireGuard rx steer queue 0x%x left in service: its entry may still be linked\n",
		q->fq.fqid);
}

/* Control mutex held, and the slot not CLAIMING. */
static void cdx_wg_steer_clear(struct cdx_wg_steer *s)
{
	struct cdx_wg_rxq *q = s->rxq;
	int rc;

	if (READ_ONCE(s->state) == CDX_WG_STEER_INSTALLED) {
		/* The entry first, as it is what enqueues to the queue. Owns
		 * the entry from here on, whichever way it goes. */
		rc = cdx_ehash_steer_del(s->ct);
		WRITE_ONCE(s->rxq, NULL);
		/* Unsynced is out of every chain, parked until the next sync
		 * proves the microcode has left it; it needs no queue, as the
		 * IPsec SA release frees the FQIDs such an entry named
		 * (cdx_ipsec_delete_fp_entry()). */
		if (!rc || rc == EN_EHASH_DELETE_UNSYNCED)
			cdx_wg_rxq_destroy(q);
		else
			cdx_wg_rxq_abandon(q);
	}
	s->ct = NULL;
	WRITE_ONCE(s->wg, NULL);
	WRITE_ONCE(s->port, NULL);
	smp_store_release(&s->state, CDX_WG_STEER_EMPTY);
}

/* Control mutex held. The queue first, then the entry that feeds it; on
 * success the slot's queue is published for statistics before the caller
 * publishes INSTALLED. */
static int cdx_wg_steer_install(struct cdx_wg_steer *s, struct cdx_wg_dev *w,
				u32 gen)
{
	const struct cpumask *cpus = qman_affine_cpus();
	bool ordered = READ_ONCE(wg_rx_spread);
	struct cdx_wg_rxq *q;
	unsigned int cpu, n;
	int rc;

	/* An unproven delete is latched and not yet settled: the key may be
	 * one still linked. */
	if (cdx_ft_failed())
		return -EIO;
	n = cpumask_weight(cpus);
	if (!n)
		return -ENODEV;
	/* An ordered queue's turn only picks its egress queue. */
	cpu = !ordered && w->rx_cpu >= 0 ? w->rx_cpu :
	      cpumask_nth(cdx_wg_steer_cpu++ % n, cpus);
	q = cdx_wg_rxq_create(s->port, s->wg, w, gen, cpu, ordered);
	if (IS_ERR(q))
		return PTR_ERR(q);
	rc = cdx_ehash_steer4_add(s->port, s->saddr, s->daddr, s->sport,
				  s->dport, q->fq.fqid, &s->ct);
	if (rc) {
		/* Nothing was linked (cdx_ehash_steer4_add()), so nothing ever
		 * enqueued to the queue. */
		cdx_wg_rxq_destroy(q);
		return rc;
	}
	WRITE_ONCE(s->rxq, q);
	pr_info("cdx: WireGuard rx steer %pI4:%u -> %pI4:%u on %s to fqid 0x%x (%s %u)\n",
		&s->saddr, ntohs(s->sport), &s->daddr, ntohs(s->dport),
		netdev_name(s->port), q->fq.fqid,
		ordered ? "every cpu, ordered, txq" : "cpu", ordered ? q->txq : cpu);
	return 0;
}

/* Once every CPU is receiving a steered tunnel of its own, WireGuard decrypts
 * where packets arrive instead of handing them to a worker on another, equally
 * busy CPU (wg_fastpath_rx_inline()). Only a tunnel that delivered since the
 * last tick counts, so an idle one leaves its CPU to the workers. Runs every
 * second while a steer is installed; reads the queues under RCU, as the
 * statistics do. ponytail: one-second hysteresis, no traffic weighting. */
static void cdx_wg_inline_fn(struct work_struct *work);
static DECLARE_DELAYED_WORK(cdx_wg_inline_work, cdx_wg_inline_fn);

static void cdx_wg_inline_fn(struct work_struct *work)
{
	struct cpumask cpus;
	unsigned int i, installed = 0;

	cpumask_clear(&cpus);
	rcu_read_lock();
	for (i = 0; i < CDX_WG_STEERS; i++) {
		struct cdx_wg_steer *s = &cdx_wg_steers[i];
		struct cdx_wg_rxq *q;
		unsigned long d;

		if (smp_load_acquire(&s->state) != CDX_WG_STEER_INSTALLED)
			continue;
		installed++;
		q = READ_ONCE(s->rxq);
		if (!q)
			continue;
		d = cdx_wg_total(q, delivered);
		if (d != q->seen) {
			if (q->ordered)
				cpumask_or(&cpus, &cpus, qman_affine_cpus());
			else
				cpumask_set_cpu(q->cpu, &cpus);
		}
		q->seen = d;
	}
	rcu_read_unlock();
	wg_fastpath_rx_inline(cpumask_weight(&cpus) >= num_online_cpus());
	WRITE_ONCE(cdx_wg_raw_auto, cpumask_weight(&cpus) >= 2);
	if (installed && !READ_ONCE(cdx_wg_stopping))
		schedule_delayed_work(&cdx_wg_inline_work, HZ);
}

static void cdx_wg_steer_work_fn(struct work_struct *work)
{
	unsigned int i, j;

	cdx_ft_begin();
	for (i = 0; i < CDX_WG_STEERS; i++) {
		struct cdx_wg_steer *s = &cdx_wg_steers[i];
		struct cdx_wg_dev *w;
		u32 gen;
		int rc;

		if (smp_load_acquire(&s->state) != CDX_WG_STEER_PENDING)
			continue;
		/* Noted by a frame in flight as the registration went: nothing
		 * to do. */
		w = cdx_wg_find_open(s->wg, &gen);
		if (READ_ONCE(cdx_wg_stopping) || !w) {
			cdx_wg_steer_clear(s);
			continue;
		}
		/* Two CPUs noted the same tuple at once. */
		for (j = 0; j < CDX_WG_STEERS; j++) {
			unsigned int st = smp_load_acquire(&cdx_wg_steers[j].state);

			if (j != i && st >= CDX_WG_STEER_PENDING &&
			    cdx_wg_steer_same(s, &cdx_wg_steers[j]))
				break;
		}
		if (j < CDX_WG_STEERS) {
			cdx_wg_steer_clear(s);
			continue;
		}
		rc = cdx_wg_steer_install(s, w, gen);
		if (rc) {
			pr_warn_ratelimited("cdx: WireGuard rx steer %pI4:%u -> %pI4:%u not installed (%d)\n",
					    &s->saddr, ntohs(s->sport), &s->daddr,
					    ntohs(s->dport), rc);
			smp_store_release(&s->state, CDX_WG_STEER_FAILED);
			continue;
		}
		smp_store_release(&s->state, CDX_WG_STEER_INSTALLED);
	}
	if (!READ_ONCE(cdx_wg_stopping))
		schedule_delayed_work(&cdx_wg_inline_work, HZ);
	cdx_ft_end();
}

/* Delete the steers of WireGuard device `wg`, or every one when NULL. Control
 * mutex held: so the worker, which takes it, is not waited for here -- a slot
 * it has yet to look at is either dropped here or dropped by it, since it
 * installs only for a device still registered and open. A slot still CLAIMING
 * becomes PENDING and goes the same way. */
static void cdx_wg_steers_drop(const struct net_device *wg)
{
	unsigned int i;

	cdx_ft_assert_held();
	for (i = 0; i < CDX_WG_STEERS; i++) {
		struct cdx_wg_steer *s = &cdx_wg_steers[i];
		unsigned int st = smp_load_acquire(&s->state);

		if (st == CDX_WG_STEER_EMPTY || st == CDX_WG_STEER_CLAIMING)
			continue;
		if (wg && s->wg != wg)
			continue;
		cdx_wg_steer_clear(s);
	}
}

/* Module exit: no frame notes a tuple once cdx_wg_stopping is seen (every note is
 * made inside the dequeue path's RCU read section), and then no work is left
 * to run, so every slot is either EMPTY or the control mutex's. */
static void cdx_wg_steers_exit(void)
{
	synchronize_net();
	cancel_work_sync(&cdx_wg_steer_work);
	/* After the steer worker, which arms it; it re-arms only while not
	 * stopping. */
	cancel_delayed_work_sync(&cdx_wg_inline_work);
	wg_fastpath_rx_inline(false);
	cdx_ft_begin();
	cdx_wg_steers_drop(NULL);
	cdx_ft_end();
}

/* A WireGuard device's receive steers, summed over its installed slots. */
struct cdx_wg_rx_stats {
	unsigned int steers;
	unsigned long delivered, to_stack, dropped, forwarded, opened;
	unsigned long skipped, skip_fail;
};

/* Racy reads for statistics. A slot's queue is freed only after its pointer is
 * cleared and a grace period has passed (cdx_wg_rxq_destroy()), so the RCU
 * read section keeps every queue it finds. */
static void cdx_wg_steers_stats(const struct net_device *wg,
				struct cdx_wg_rx_stats *st)
{
	unsigned int i;

	memset(st, 0, sizeof(*st));
	if (!wg)
		return;
	rcu_read_lock();
	for (i = 0; i < CDX_WG_STEERS; i++) {
		struct cdx_wg_steer *s = &cdx_wg_steers[i];
		const struct cdx_wg_rxq *q;

		if (smp_load_acquire(&s->state) != CDX_WG_STEER_INSTALLED ||
		    READ_ONCE(s->wg) != wg)
			continue;
		st->steers++;
		q = READ_ONCE(s->rxq);
		if (!q)
			continue;
		st->delivered += cdx_wg_total(q, delivered);
		st->to_stack += cdx_wg_total(q, to_stack);
		st->dropped += cdx_wg_total(q, dropped);
		st->forwarded += cdx_wg_total(q, forwarded);
		st->opened += cdx_wg_total(q, opened);
		st->skipped += cdx_wg_total(q, skipped);
		st->skip_fail += cdx_wg_total(q, skip_fail);
	}
	rcu_read_unlock();
}

/* Upload. */

/* A frame the classifier finished for one of `sq`'s device's flows, sealed
 * where it lies and sent from the same buffer. The FD keeps its pool, so the
 * egress port returns the buffer to it after transmission, as it does for a
 * frame the classifier forwards; the pool's per-CPU count is therefore left
 * alone. Returns false, with the frame untouched, for anything the seal
 * declines. */
static bool cdx_wg_seal(struct cdx_wg_sealq *sq, struct net_device *dev,
			struct dpa_bp *dpa_bp, const struct qm_fd *in)
{
	struct cdx_wg_dev *w = sq->w;
	struct eth_iface_info *eth;
	struct wg_fastpath_tx tx;
	struct qm_fd fd = *in;
	struct qman_fq *fq;
	int i, err;

	err = wg_fastpath_seal(dev, cdx_wg_can_tx, phys_to_virt(qm_fd_addr(in)),
			       dpa_fd_offset(in), dpa_fd_length(in), dpa_bp->size, &tx);
	if (err == -EXDEV && w->nq > 1) {
		/* This CPU receives the tunnel: hand the frame, untouched, to
		 * the device's seal queue on the next CPU. A flow's frames all
		 * take the same turn, so they stay in order. */
		fq = &w->sq[(sq - w->sq + 1) % w->nq].fq;
		err = -EBUSY;
		for (i = 0; i < 1000 && err == -EBUSY; i++)
			err = qman_enqueue(fq, &fd, 0);
		if (unlikely(err)) {
			this_cpu_inc(w->pc->tx_fail);
			dpa_fd_release(NULL, &fd);
		}
		return true;
	}
	if (err)
		return false;
	cdx_wg_steer_note(dev, &tx);
	fd.offset = tx.off;
	fd.length20 = tx.len;
	fd.cmd = 0;
	/* cdx_wg_can_tx() passed the port, so it is in the table. */
	eth = cdx_wg_port(tx.dev);
	err = -ENODEV;
	if (likely(eth)) {
		/* One flow's frames arrive on one seal queue, so on one CPU: a
		 * queue per CPU keeps them in order. */
		fq = &eth->fwd_tx_fqinfo[smp_processor_id() & (DPAA_FWD_TX_QUEUES - 1)];
		err = -EBUSY;
		for (i = 0; i < 1000 && err == -EBUSY; i++)
			err = qman_enqueue(fq, &fd, 0);
	}
	if (unlikely(err)) {
		this_cpu_inc(w->pc->tx_fail);
		dpa_fd_release(NULL, &fd);
	} else {
		this_cpu_inc(w->pc->sealed);
	}
	return true;
}

/* A frame the seal declined -- no current keypair yet, a handshake to make, a
 * port it may not send on -- handed to the device's own transmit, the
 * Ethernet header the classifier wrote dropped. Copied out: it is the rare
 * case, and a copy leaves the buffer's pool accounting alone whichever pool
 * it came from (an Ethernet port's, SEC's output, the fragment pool). */
static void cdx_wg_seal_slow(struct cdx_wg_dev *w, struct net_device *dev,
			     const struct qm_fd *fd)
{
	const u8 *data = (const u8 *)phys_to_virt(qm_fd_addr(fd)) + dpa_fd_offset(fd);
	unsigned int len = dpa_fd_length(fd);
	struct sk_buff *skb = NULL;

	if (fd->format == qm_fd_contig && len > ETH_HLEN)
		skb = netdev_alloc_skb(dev, len - ETH_HLEN);
	if (unlikely(!skb)) {
		this_cpu_inc(w->pc->tx_fail);
		dpa_fd_release(NULL, fd);
		return;
	}
	skb->protocol = ((const struct ethhdr *)data)->h_proto;
	skb_put_data(skb, data + ETH_HLEN, len - ETH_HLEN);
	dpa_fd_release(NULL, fd);
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	this_cpu_inc(w->pc->slow);
	dev_queue_xmit(skb);
}

static enum qman_cb_dqrr_result cdx_wg_seal_dqrr(struct qman_portal *portal,
						 struct qman_fq *fq,
						 const struct qm_dqrr_entry *dq)
{
	struct cdx_wg_sealq *sq = container_of(fq, struct cdx_wg_sealq, fq);
	struct cdx_wg_dev *w = sq->w;
	struct net_device *dev;
	struct dpa_bp *dpa_bp;

	if (!(dq->stat & QM_DQRR_STAT_FD_VALID))
		return qman_cb_dqrr_consume;
	dpa_bp = dpa_bpid2pool(dq->fd.bpid);
	if (unlikely(!dpa_bp)) {
		/* No pool to give it back to. */
		this_cpu_inc(w->pc->tx_fail);
		return qman_cb_dqrr_consume;
	}
	rcu_read_lock();
	/* A seal queue lives exactly as long as its registration, so the
	 * current generation is its own. */
	dev = cdx_wg_live(w, READ_ONCE(w->gen));
	if (unlikely(!dev)) {
		this_cpu_inc(w->pc->down);
		dpa_fd_release(NULL, &dq->fd);
	} else if (!cdx_wg_seal(sq, dev, dpa_bp, &dq->fd)) {
		cdx_wg_seal_slow(w, dev, &dq->fd);
	}
	rcu_read_unlock();
	return qman_cb_dqrr_consume;
}

/* Software enqueues to a seal queue only in cdx_wg_seal()'s turn to the next
 * CPU; a frame QMan refuses there goes back to its pool. The classifier takes
 * its own rejections back. */
static void cdx_wg_seal_ern(struct qman_portal *portal, struct qman_fq *fq,
			    const struct qm_mr_entry *msg)
{
	dpa_fd_release(NULL, &msg->ern.fd);
}

static void cdx_wg_sealqs_destroy(struct cdx_wg_dev *w, unsigned int n)
{
	while (n--)
		cdx_destroy_fq(&w->sq[n].fq);
	kfree(w->sq);
	w->sq = NULL;
	w->nq = 0;
}

/* One seal queue per affine CPU, queue i on the i-th one's portal channel:
 * a flow's sealing is a CPU's worth of work, and its queue is where it is
 * done. */
static int cdx_wg_sealqs_create(struct cdx_wg_dev *w)
{
	const struct cpumask *cpus = qman_affine_cpus();
	struct qm_mcc_initfq opts;
	unsigned int n = 0, cpu;

	w->sq = kcalloc(cpumask_weight(cpus), sizeof(*w->sq), GFP_KERNEL);
	if (!w->sq)
		return -ENOMEM;
	for_each_cpu(cpu, cpus) {
		struct cdx_wg_sealq *sq = &w->sq[n];

		sq->w = w;
		sq->cpu = cpu;
		sq->fq.cb.dqrr = cdx_wg_seal_dqrr;
		sq->fq.cb.ern = cdx_wg_seal_ern;
		if (qman_create_fq(0, QMAN_FQ_FLAG_DYNAMIC_FQID, &sq->fq))
			goto err;
		cdx_wg_fq_opts(&opts, sq->fq.fqid, qman_affine_channel(cpu));
		if (qman_init_fq(&sq->fq, QMAN_INITFQ_FLAG_SCHED, &opts)) {
			/* Never initialised, so out of service already. */
			qman_destroy_fq(&sq->fq, 0);
			goto err;
		}
		/* /proc/fqid_stats, as every cdx queue has; cdx_destroy_fq()
		 * removes it. */
		cdx_create_type_fqid_info_in_procfs(&sq->fq, UNSPECIFIED, NULL, NULL);
		n++;
	}
	w->nq = n;
	return 0;
err:
	cdx_wg_sealqs_destroy(w, n);
	return -EIO;
}

/* Registration, for the flowtable adapter (ask_flowtable_wg.c). */

bool cdx_wg_dev_supported(struct net_device *dev)
{
	/* The datapath runs every dequeue inline, which only portal NAPI
	 * makes softirq context (see the top of this file). */
	return IS_ENABLED(CONFIG_FSL_ASK_QMAN_PORTAL_NAPI) &&
	       READ_ONCE(cdx_wg_ready) && dev &&
	       net_eq(dev_net(dev), &init_net) && cdx_ft_wg_dev(dev);
}
EXPORT_SYMBOL_NS_GPL(cdx_wg_dev_supported, ASK_CDX_FLOWTABLE);

/* The order is the one the failure handling unwinds: the queues the encoder
 * will name, the logical interface and the devman record that name them, and
 * last the state, which is what the datapath and the encoder read first. */
int cdx_wg_dev_add(struct net_device *dev, struct cdx_wg_dev **result)
{
	static unsigned int rx_turn;
	const struct cpumask *cpus = qman_affine_cpus();
	struct cdx_wg_dev *w = NULL;
	unsigned int i;
	int rc;

	cdx_ft_assert_held();
	ASSERT_RTNL();
	*result = NULL;
	if (!cdx_wg_dev_supported(dev))
		return -EOPNOTSUPP;
	for (i = 0; i < CDX_WG_DEVS; i++) {
		if (cdx_wg_devs[i].state != CDX_WG_FREE && cdx_wg_devs[i].dev == dev)
			return -EEXIST;
		if (!w && cdx_wg_devs[i].state == CDX_WG_FREE)
			w = &cdx_wg_devs[i];
	}
	if (!w)
		return -ENOSPC;
	w->id = w - cdx_wg_devs;
	w->pc = alloc_percpu(struct cdx_wg_dev_pc);
	if (!w->pc)
		return -ENOMEM;
	rc = cdx_wg_sealqs_create(w);
	if (rc)
		goto err_pc;
	cdx_ft_wg_mac(dev, w->mac);
	strscpy(w->ifname, dev->name, sizeof(w->ifname));
	memset(&w->itf, 0, sizeof(w->itf));
	rc = -ENOSPC;
	if (!add_onif(dev->name, &w->itf, NULL, IF_TYPE_WG | IF_TYPE_PHYSICAL))
		goto err_q;
	rc = -EIO;
	if (dpa_add_wg_if(dev->name, &w->itf, w->id, w->mac, dev))
		goto err_onif;
	cdx_wg_ports_update();
	/* Its receive CPU, dealt in turn as it registers, so its steer and its
	 * flows' seal queues agree before the first entry exists. None when
	 * its steer is ordered: every CPU receives it. */
	w->rx_cpu = -1;
	if (!READ_ONCE(wg_rx_spread) && cpumask_weight(cpus))
		w->rx_cpu = cpumask_nth(rx_turn++ % cpumask_weight(cpus), cpus);
	WRITE_ONCE(w->dev, dev);
	WRITE_ONCE(w->gen, w->gen + 1);
	smp_store_release(&w->state, CDX_WG_OPEN);
	*result = w;
	return 0;

err_onif:
	/* Releases a devman record with it, had there been one. */
	remove_onif_by_index(w->itf.index);
err_q:
	cdx_wg_sealqs_destroy(w, w->nq);
err_pc:
	free_percpu(w->pc);
	w->pc = NULL;
	return rc;
}
EXPORT_SYMBOL_NS_GPL(cdx_wg_dev_add, ASK_CDX_FLOWTABLE);

/* Always consumes *wdev. The caller has retired every flow egressing through
 * the device, so nothing in the classifier enqueues to its seal queues; valid
 * after the device unregistered, reading only the slot. */
void cdx_wg_dev_del(struct cdx_wg_dev **wdev)
{
	struct cdx_wg_dev *w = *wdev;

	cdx_ft_assert_held();
	ASSERT_RTNL();
	if (!w)
		return;
	*wdev = NULL;
	/* Its receive steers first: they name the device, compared only. */
	cdx_wg_steers_drop(w->dev);
	/* Then nothing resolves to it any more and nothing dequeued uses it;
	 * its queues drain to their pools before the slot can be taken again
	 * (cdx_destroy_fq() waits out the callbacks). */
	smp_store_release(&w->state, CDX_WG_FREE);
	remove_onif_by_index(w->itf.index);
	cdx_wg_sealqs_destroy(w, w->nq);
	free_percpu(w->pc);
	w->pc = NULL;
	WRITE_ONCE(w->dev, NULL);
}
EXPORT_SYMBOL_NS_GPL(cdx_wg_dev_del, ASK_CDX_FLOWTABLE);

/* For cdx_ft_egress_supported(): the frame queues an entry would name exist.
 * Flowtable transaction held. */
bool cdx_wg_dev_is_open(const struct net_device *dev)
{
	u32 gen;

	return cdx_wg_find_open(dev, &gen);
}

/* For devman's netdev lookup: record `id` is `dev`'s current registration. */
bool cdx_wg_owns(u16 id, const struct net_device *dev)
{
	return id < CDX_WG_DEVS &&
	       smp_load_acquire(&cdx_wg_devs[id].state) == CDX_WG_OPEN &&
	       READ_ONCE(cdx_wg_devs[id].dev) == dev;
}

/* The seal queue a new flow through device `id` is installed with. Flows are
 * dealt in turn over every CPU but the one receiving the tunnel, which carries
 * all its ACKs and would only bounce them (cdx_wg_seal()). Called by the
 * encoder under the device list's spinlock: no sleeping. */
int cdx_wg_get_seal_fq(u16 id, u32 *fqid)
{
	static atomic_t turn;
	struct cdx_wg_dev *w;
	unsigned int i, n;

	if (id >= CDX_WG_DEVS)
		return -1;
	w = &cdx_wg_devs[id];
	if (smp_load_acquire(&w->state) != CDX_WG_OPEN || !w->nq)
		return -1;
	n = w->nq;
	do
		i = (unsigned int)atomic_inc_return(&turn) % n;
	while (n > 1 && (int)w->sq[i].cpu == w->rx_cpu);
	*fqid = w->sq[i].fq.fqid;
	return 0;
}

/* The datapath's hold on a device ends here, inside its unregistration and so
 * before the core's synchronize_net() lets it be freed (cdx_wg_live()); what is
 * left of the registration the flowtable's worker releases later. */
static int cdx_wg_netdev_event(struct notifier_block *nb, unsigned long event,
			       void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	unsigned int i;

	if (event != NETDEV_UNREGISTER)
		return NOTIFY_DONE;
	for (i = 0; i < CDX_WG_DEVS; i++) {
		struct cdx_wg_dev *w = &cdx_wg_devs[i];

		if (READ_ONCE(w->state) == CDX_WG_OPEN && READ_ONCE(w->dev) == dev)
			smp_store_release(&w->state, CDX_WG_GONE);
	}
	return NOTIFY_DONE;
}

static struct notifier_block cdx_wg_netdev_nb = {
	.notifier_call = cdx_wg_netdev_event,
};

/* /proc/cdx_wireguard: one line per registered device. Takes the flowtable
 * transaction, which keeps the slots' counters from being freed under it. */
static int cdx_wg_show(struct seq_file *m, void *v)
{
	unsigned int i;

	cdx_ft_begin();
	for (i = 0; i < CDX_WG_DEVS; i++) {
		struct cdx_wg_dev *w = &cdx_wg_devs[i];
		struct cdx_wg_dev_pc t = {};
		struct cdx_wg_rx_stats st;
		int cpu;

		if (w->state == CDX_WG_FREE)
			continue;
		for_each_possible_cpu(cpu) {
			const struct cdx_wg_dev_pc *p = per_cpu_ptr(w->pc, cpu);

			t.sealed += READ_ONCE(p->sealed);
			t.slow += READ_ONCE(p->slow);
			t.tx_fail += READ_ONCE(p->tx_fail);
			t.down += READ_ONCE(p->down);
		}
		cdx_wg_steers_stats(w->dev, &st);
		seq_printf(m, "%s id %u%s rx_cpu %d sealed %lu slow %lu tx_fail %lu down %lu steers %u delivered %lu to_stack %lu dropped %lu forwarded %lu opened %lu order_skipped %lu order_skip_fail %lu\n",
			   w->ifname, w->id, w->state == CDX_WG_GONE ? " gone" : "",
			   w->rx_cpu, t.sealed, t.slow, t.tx_fail, t.down,
			   st.steers, st.delivered, st.to_stack, st.dropped,
			   st.forwarded, st.opened, st.skipped, st.skip_fail);
	}
	cdx_ft_end();
	return 0;
}

static void cdx_wg_cgr_exit(void)
{
	struct qm_mcc_initcgr opts;

	memset(&opts, 0, sizeof(opts));
	qman_modify_cgr(&cdx_wg_cgr, QMAN_CGR_FLAG_USE_INIT, &opts);
	qman_release_cgrid(cdx_wg_cgr.cgrid);
}

static void cdx_wg_exit(void)
{
	unsigned int i;

	WRITE_ONCE(cdx_wg_ready, false);
	WRITE_ONCE(cdx_wg_stopping, true);
	cdx_wg_steers_exit();
	/* The flowtable adapter, which registers devices, unloads first and
	 * releases every one (ft_wg_exit()); one left over would leave queues
	 * and a logical interface behind the module. RTNL before the
	 * transaction, the order every other path takes them in. */
	rtnl_lock();
	cdx_ft_begin();
	for (i = 0; i < CDX_WG_DEVS; i++) {
		struct cdx_wg_dev *w = &cdx_wg_devs[i];

		if (WARN_ON(w->state != CDX_WG_FREE))
			cdx_wg_dev_del(&w);
	}
	cdx_ft_end();
	rtnl_unlock();
	remove_proc_entry("cdx_wireguard", NULL);
	unregister_netdevice_notifier(&cdx_wg_netdev_nb);
	cdx_wg_cgr_exit();
}

/* After the classifier is built (the ports' records exist). Not fatal to cdx:
 * without it no WireGuard device registers, and nothing else depends on it. */
int cdx_wg_init(void)
{
	struct qm_mcc_initcgr opts;
	int rc;

	if (qman_alloc_cgrid(&cdx_wg_cgr.cgrid) < 0)
		return -ENOSPC;
	memset(&opts, 0, sizeof(opts));
	/* No state-change notifications, so no portal owns the group; the
	 * egress groups set theirs up the same way (devman.c). */
	opts.we_mask = QM_CGR_WE_MODE | QM_CGR_WE_CS_THRES | QM_CGR_WE_CSTD_EN |
		       QM_CGR_WE_CSCN_EN;
	opts.cgr.mode = QMAN_CGR_MODE_FRAME;
	opts.cgr.cstd_en = QM_CGR_EN;
	qm_cgr_cs_thres_set64(&opts.cgr.cs_thres, CDX_WG_QUEUE_FRAMES, 1);
	if (qman_modify_cgr(&cdx_wg_cgr, QMAN_CGR_FLAG_USE_INIT, &opts)) {
		qman_release_cgrid(cdx_wg_cgr.cgrid);
		return -EIO;
	}
	rc = register_netdevice_notifier(&cdx_wg_netdev_nb);
	if (rc) {
		cdx_wg_cgr_exit();
		return rc;
	}
	if (!proc_create_single("cdx_wireguard", 0444, NULL, cdx_wg_show))
		pr_warn("cdx: /proc/cdx_wireguard not created\n");
	WRITE_ONCE(cdx_wg_ready, true);
	register_cdx_deinit_func(cdx_wg_exit);
	return 0;
}
