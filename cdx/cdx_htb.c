// SPDX-License-Identifier: GPL-2.0-or-later
/* A hardware qdisc for the DPAA netdev: HTB offload driving CEETM.
 *
 * The scheduler CMM used to build with twelve CMD_QM_* commands is the same
 * scheduler sch_htb asks for with tc_htb_qopt_offload, so this translates one
 * into the other. Nothing new is claimed here: ceetm_init_channels() already
 * built every channel, class queue and logical FQ at module load, and each
 * setter in cdx_ceetm_app.c is a thin function over a (channel, class queue)
 * pair. What this file owns is which pair a tc class means, and giving it
 * back.
 *
 * The tree maps onto the hardware's own three levels:
 *
 *   qdisc root         the port, that is its LNI
 *   class under root   a CEETM channel; its rate and ceil are the channel's
 *                      committed and excess shapers
 *   class under that   a class queue on that channel; prio picks one of the
 *                      eight strict-priority queues, quantum instead puts it
 *                      in the weighted group
 *
 * A class under the root that has no children yet is both: it holds a channel
 * and occupies one class queue on it, because sch_htb gives every leaf a netdev
 * Tx queue and expects frames to be able to reach it. Deeper than that is
 * refused -- there is no fourth level in CEETM to put it on.
 *
 * Classification is not here and must not come here. An offloaded flow produces
 * no skb, reaches no qdisc and touches no Tx queue, so a tc filter could only
 * ever steer the software half; the conntrack mark is the one key both halves
 * can read. HTB supplies the tree, the mark picks the leaf.
 *
 * Everything below runs under RTNL in process context, and sch_htb wraps every
 * leaf add, delete and graft in dev_deactivate()/dev_activate(), so the netdev
 * can be quiesced the moment a callback returns. The exceptions are two works,
 * which run without RTNL: the one that grows class queues once frames other
 * queues held have left (cdx_htb_regrow_work()), under this file's mutex
 * throughout, and the one that gives a torn-down tree's channels back once its
 * port's flowtable entries no longer send to them (cdx_htb_release_work()),
 * which drops the mutex while it waits for the flowtable and reads again what
 * it was releasing once it has it back. RTNL is
 * also what serialises the commands against each other; the hardware layer
 * still refuses what would clash -- ceetm_assign_chnl() will not hand out a
 * channel another port holds, and TC_HTB_CREATE below will not take a port
 * that is already configured.
 */
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/rcupdate.h>
#include <linux/rtnetlink.h>
#include <linux/slab.h>
#include <linux/srcu.h>
#include <net/pkt_cls.h>
#include <net/pkt_sched.h>
#include <net/dsfield.h>
#include <net/inet_ecn.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/ndisc.h>
#include <linux/atomic.h>
#include <linux/if_packet.h>
#include <linux/if_pppox.h>
#include <linux/icmpv6.h>
#include <linux/if_vlan.h>
#include <linux/math64.h>
#include <linux/percpu.h>
#include <linux/ppp_defs.h>
#include <linux/timekeeping.h>
#include <linux/udp.h>
#include <linux/workqueue.h>
#include <dpaa_eth.h>
#include <dpaa_eth_common.h>
#include "cdx.h"
#include "portdefs.h"
#include "module_qm.h"
#include "cdx_ceetm_app.h"
#include "cdx_flowtable.h"
#include "cdx_flowtable_backend.h"
#include "cdx_htb.h"
#include "cdx_police.h"
#include "cdx_dscp.h"
#include "dpa_ipsec.h"

/* Leaf classes are handed netdev Tx queue indices out of the headroom patch 150
 * reserved above the direct queues, and sch_htb turns the index this file
 * returns straight into netdev_get_tx_queue() with no bounds check.
 *
 * real_num_tx_queues grows to cover them as classes come into service, because
 * netdev_cap_txqueue() rewrites anything at or above it to queue zero. The
 * driver keeps ordinary traffic off the range by folding its own queue choice
 * back below the base, so what the count decides is only whether a leaf can be
 * named -- not whether unclassified frames can wander onto one.
 */
#define CDX_HTB_QID_BASE	DPAA_ETH_TX_QUEUES
#define CDX_HTB_MAX_LEAVES	DPAA_ETH_CEETM_LEAF_QUEUES

/* No such queue, no such class. Both maps below are byte arrays, so one
 * sentinel serves for a whole memset. */
#define CDX_HTB_NONE		0xffu

/* Every egress destination a decoded conntrack mark can name. */
#define CDX_HTB_CLASSES		256
static_assert(CDX_HTB_CLASSES > CDX_FT_QOS_EGRESS_MASK,
	      "class_txq[] must cover every egress class the adapter can decode");

/* Frames a leaf's class queue asks to hold before tail drop.
 *
 * The hardware layer's default is eight, which is what CMM configured and is
 * far too shallow for a queue that is deliberately being shaped: a class whose
 * arrival rate exceeds its share has nowhere to wait, so it loses frames rather
 * than queueing them. A hundred and twenty-eight is about a millisecond at a
 * gigabit. HTB carries no queue-depth field, so this is a default rather than
 * a setting: a RED qdisc on the leaf asks for its own limit instead, counted in
 * frames (cdx_htb_red_want()). Either is only asked for: what a queue gets is
 * its share of what the whole tree may hold (cdx_htb_cap()).
 */
#define CDX_HTB_CQ_DEPTH	128

/* What one tree's class queues may hold together, in frames.
 *
 * A frame on a class queue holds a buffer until the port sends it, however
 * short the frame: one of the pool every DPAA port receives into, or for an
 * IPsec flow one of SEC's output pool. Sixteen leaves at CDX_HTB_CQ_DEPTH
 * would hold 2,048 frames, more than SEC's pool kept for them, and a RED limit
 * of four megabytes counted in bytes held every buffer of the Ethernet pool
 * with 64-byte frames: the ports missed what they received, the gateway's own
 * frames included (A337). So every class queue counts frames, and a tree holds
 * no more than the port's share of the Ethernet pool -- half of what the port
 * seeds it with, the share its forwarding queues are held to
 * (fwd_pool_frames()) -- nor, all live trees together, more than the 1,024
 * frames of SEC's pool kept for them (IPSEC_QDISC_FRAMES): a class queue
 * carries SEC's frames among the rest and cannot tell them apart. Those are
 * divided evenly between the trees, which with four CPUs leaves the SEC
 * pool's share the tighter of the two.
 *
 * What is held to those is what the queues may hold, not only the depths they
 * are given. Lowering a depth evicts nothing: a queue holding more keeps it
 * until it sends it, which a paused port, or a queue starved behind a
 * strict-priority sibling, never does, and a queue a leaf gives back is reset
 * with its frames still on it. Counting depths alone, a RED leaf filled and
 * then shrunk while another grew and filled, a few times over, held more than
 * all of SEC's pool, and SEC refused every SA's jobs (A348). So each queue is
 * charged what it holds as well (cdx_htb_cap_charge()), and a queue grows only
 * into what is left; the rest of its share waits until those frames have gone
 * (cdx_htb_regrow_work()).
 *
 * That holds but for one frame per class queue a change has just configured
 * or given back, and never more than one: a queue configured while other
 * queues' frames fill the budget still starts at a frame (CDX_HTB_CQ_START),
 * until those frames leave; and a queue a class gave back, charged only what
 * it holds, is parked at a frame (CEETM_PARKED_CQ_DEPTH), which the classifier
 * entries that named it can still fill until they have been retired or
 * rebuilt after the change. A change touches at most the eighteen class
 * queues of its tree, against the 128 frames of SEC's pool left over for its
 * own jobs. On a tree taken down, that frame lands after the drain, on a
 * channel its port no longer serves, quarantined for the port until nothing in
 * the flowtable sends to it; it stays, charged, until the quarantine's release
 * pops it (cdx_htb_release_work()), or the port takes the channel back and
 * sends it.
 */
#define CDX_HTB_ETH_FRAMES	((u64)CONFIG_FSL_DPAA_ETH_MAX_BUF_COUNT * num_possible_cpus() / 2)
#define CDX_HTB_SEC_FRAMES	IPSEC_QDISC_FRAMES

/* The class queues one tree can use: a leaf's each, and the top channel's two
 * that unclassified and control traffic take while no leaf holds them. */
#define CDX_HTB_CAP_QUEUES	(CDX_HTB_MAX_LEAVES + 2)

/* What a class queue holds when it is configured, before the cap grows it to
 * its share once every other queue of the tree has made room: configured at
 * a full depth, a new queue would take the tree past its budget until the
 * others had shrunk. Never zero, which a congestion group takes as no tail
 * drop at all -- so a queue configured while frames other queues hold fill
 * the budget takes it a frame past, until they leave. A queue given back is
 * parked at no more (CEETM_PARKED_CQ_DEPTH), which is what holds the frames
 * that can still reach it to one as well (CDX_HTB_ETH_FRAMES). */
#define CDX_HTB_CQ_START	1
static_assert(CEETM_PARKED_CQ_DEPTH <= CDX_HTB_CQ_START,
	      "a queue given back may take no more than one starting out");

/* How soon the cap looks again at a tree whose queues it kept short of their
 * share because frames other queues still hold left no room
 * (cdx_htb_regrow_work()): soon after the change that left them short, then
 * half as often each time they still are, down to once a second. Those frames
 * leave at the rate their port sends them, which a paused port does not. */
#define CDX_HTB_REGROW_FIRST_MS	100
#define CDX_HTB_REGROW_LAST_MS	1000

/* How soon a release of a torn-down tree's channels that the flowtable could
 * not yet clear asks again (cdx_htb_release_work()): soon at first, since what
 * holds it up -- an invalidation, or an SA or multicast group whose rebuild
 * failed and went back to its worker -- is work already under way, then half
 * as often each time, down to once a second. */
#define CDX_HTB_RELEASE_FIRST_MS	100
#define CDX_HTB_RELEASE_LAST_MS		1000

/* A RED qdisc names its thresholds in bytes, and a class queue counts frames:
 * the bytes are divided by a standard frame as it leaves -- the MTU's, where
 * that is smaller -- with a VLAN tag, and the preamble, gap and FCS its time on
 * the wire includes.
 *
 * Not by the largest frame a jumbo port admits, which would leave a RED band
 * of a frame or two. The price is deliberate: on a jumbo port the curve and
 * the limit are counted in 1,542-byte frames while the frames queued may be
 * six times that, so a queue of jumbo frames holds about six times the bytes
 * its RED qdisc names, and its latency at the limit is six times longer. What
 * that leaves bounded is what matters to the buffer pools: every frame holds
 * one buffer whatever its size, and the cap bounds the frames. */
#define CDX_HTB_RED_OVERHEAD	(VLAN_ETH_HLEN + 24)

/* Where a frame goes that names no leaf, on a port whose tree is live.
 *
 * Unclassified traffic -- no class known for the frame's connection, or a
 * class no leaf holds -- takes the leaf `default' names, as software HTB sends
 * it there. With no default leaf it takes the top channel's class queue 0, the
 * lowest strict priority, below the weighted group: the queue the hardware has
 * always resolved a mark with no class to (cdx_get_txfqid() with zero
 * nibbles). That holds forwarded or not, tracked or not, so a flow's frames
 * land on the same queue before and after it is offloaded, and a frame whose
 * connection nothing classified is never anywhere better than that.
 *
 * Control traffic is the exception: what the gateway sends itself -- from its
 * sockets, and the link frames it originates, ARP, neighbour discovery, PPPoE
 * discovery and a session's LCP, IGMP, DHCP -- and link protocols the bridge
 * carries between ports (cdx_htb_parse(), cdx_htb_control()). None of it is
 * ever offloaded, and nothing a host sends through the gateway is control. It takes the top channel's class queue 7, the
 * highest strict priority, never the default leaf -- a default is commonly the
 * lowest class, and a saturated one above it would starve an LCP echo there
 * until the session dropped. Class queue 7 is bounded by a budget instead
 * (CDX_HTB_CONTROL_SHARE); what exceeds it is sent as unclassified traffic.
 *
 * Unlike software HTB's direct queue, neither is unshaped: both sit on the top
 * channel and so under its cap. That is deliberate. A link shaped to what the
 * upstream will carry has to hold everything it sends to that rate, or the
 * queue that builds is the upstream's, where no priority applies.
 *
 * Class queue 7 is not reserved: a prio 0 leaf on the top channel holds it,
 * and control traffic then shares that leaf's queue -- the highest priority
 * there is, which is what that traffic needs -- and appears in its counters.
 */
#define CDX_HTB_UNCLASSIFIED_CQ	0
#define CDX_HTB_CONTROL_CQ	(NUM_PQS - 1)

/* What control traffic may take of the top channel.
 *
 * Its queue is the highest priority there is and competes for committed
 * tokens, so nothing about the queue itself bounds it: unbounded, anything
 * that counts as control -- the gateway's own bulk transfer, a flood of ARP
 * requests it answers -- would starve every leaf on the channel. So a budget
 * stands in front of it: a sixteenth of the top channel's committed rate,
 * never less than 64 kbit/s unless the channel is slower than twice that, and
 * a burst of sixteen full-size frames -- of the largest frame the ports are
 * built for, so jumbo frames of the gateway's own sessions burst as far as
 * standard ones do. Enough for every link protocol and the gateway's own
 * sessions many times over; what a leaf can lose to it is bounded by it. A
 * control frame over budget is sent as unclassified traffic rather than
 * dropped. */
#define CDX_HTB_CONTROL_SHARE	16
#define CDX_HTB_CONTROL_FLOOR	8000		/* bytes per second */
#define CDX_HTB_CONTROL_BURST	(16U * dpa_get_max_frm())	/* bytes */

/* The WRED curve a RED qdisc on a leaf asked for, in its own bytes. Kept so
 * the cap can draw it again in frames whenever what it is drawn for moves --
 * the depth the queue is given, the port's MTU -- and after the class queue is
 * configured afresh: ceetm_set_class_queue() starts every queue on plain tail
 * drop. */
struct cdx_htb_red_curve {
	u32 min, max, probability, limit;
};

struct cdx_htb_class {
	struct list_head list;
	/* Minors only. sch_htb truncates classid to u16 in the offload
	 * structure, and every command that names a parent names its minor, so
	 * the major never reaches this file except once, from TC_HTB_CREATE. */
	u16 classid;
	u16 parent;		/* 0 when the parent is the qdisc root */
	u16 qid;		/* netdev Tx queue, leaves only */
	u32 quantum;		/* weighted-group weight, 0 for strict priority */
	u8 channel;		/* CEETM channel index, both kinds */
	u8 cq;			/* class-queue index, leaves only */
	bool inner;		/* a channel with children, so not a queue */
	/* The class queue is running `curve' for the RED qdisc `red_qdisc'
	 * grafted on this leaf. Only a curve the hardware took keeps it set --
	 * the cap clears it when the curve will not go on -- so it is also what
	 * that qdisc's statistics call reports as offloaded. The handle matters
	 * because a qdisc replacing another on the same class is created before
	 * the one it replaces is destroyed. */
	bool red;
	u32 red_qdisc;
	struct cdx_htb_red_curve curve;
	/* The curve that one displaced, kept until its qdisc is destroyed. A
	 * new qdisc that fails after its REPLACE programmed the queue is
	 * destroyed with the one it would have replaced still grafted, and
	 * that one gets its curve back. */
	bool red_displaced;
	u32 displaced_qdisc;
	struct cdx_htb_red_curve displaced;
};

struct cdx_htb_port {
	struct tQM_context_ctl *qm_ctx;
	struct list_head classes;
	u16 cq_used[CDX_CEETM_MAX_CHANNELS];
	u16 channels;		/* channels claimed for this port */
	u16 major;		/* the qdisc handle's major */
	u16 defcls;
	u16 leaves;		/* qids in use, dense from CDX_HTB_QID_BASE */
	bool live;
	/* Class queues this file made eligible for the unclassified and
	 * control traffic above while no leaf holds them, all on one channel
	 * (NONE when there are none). Undone when the channel stops being the
	 * top one, and forgotten as soon as anything else configures or resets
	 * the queue (cdx_htb_implicit_forget()). */
	u8 implicit_channel;
	u16 implicit;
	/* What the Tx path reads, and the only part of this structure it may.
	 * Plain byte arrays rather than a walk of the class list, because both
	 * are read from ndo_select_queue and cpe_fp_tx without RTNL while that
	 * list is being mutated under it. A reader racing a rebuild sees an old
	 * byte or a new one, never a freed node. The hardware path reads them
	 * too, from cdx_get_txfqid(), for the same answer. */
	u8 class_txq[CDX_HTB_CLASSES];		/* class -> leaf slot */
	u8 txq_channel[CDX_HTB_MAX_LEAVES];	/* leaf slot -> CEETM channel */
	u8 txq_cq[CDX_HTB_MAX_LEAVES];		/* leaf slot -> class queue */
	/* The top channel, or NONE while no tree is live: which is also the
	 * switch that tells both paths whether any of this applies. */
	u8 top;
	/* Where unclassified traffic goes, as channel << 8 | class queue: the
	 * default leaf's pair, or the top channel's class queue 0. One word, so
	 * a reader never pairs one channel with another's queue. */
	u16 unclassified;
	/* The committed rate each channel was shaped at, bytes per second. */
	u64 rate[CDX_CEETM_MAX_CHANNELS];
	/* The control budget (cdx_htb_control_admit()): bytes per second and
	 * the burst, in nanoseconds at that rate, published from the top
	 * channel's rate, and the time by which what it admitted would have
	 * left. */
	u64 control_rate;
	s64 control_tau;
	atomic64_t control_tat;
	/* What the log has been told, until it is put right: the class queues
	 * whose depth or curve the hardware refused, per channel; that the
	 * tree's queues were kept short for a refused shrink; and that they
	 * were for want of what the queues hold. The regrow work meets each
	 * again every second while it lasts (cdx_htb_cap_apply()). */
	u16 refused[CDX_CEETM_MAX_CHANNELS];
	bool told_stuck, told_unread;
};

/* The release of the channels a tree taken down left quarantined for its port
 * (ceetm_stop_qos()), one a port, under cdx_htb_mutex. Kept apart from the
 * port, which cdx_htb_port_gone() clears whole and a new tree starts afresh,
 * while this outlives both until the release is done or the port goes.
 *
 * `dev' is the port's netdev, held while a release is due. Every teardown on
 * the port moves `gen' on, and the HTB command that made it, having marked the
 * port's flowtable entries for re-installation, sets `marked' to it
 * (cdx_htb_release_arm()): a release waits for the marking that follows the
 * teardown, and one that saw `gen' move while it waited gives back nothing a
 * later teardown quarantined. `told' says the log was told the entries could
 * not yet be shown retired or rebuilt. */
struct cdx_htb_release {
	struct net_device *dev;
	unsigned long gen, marked;
	bool due, told;
};

/* Indexed the way gQMCtx is, so a netdev's stashed QoS context names its
 * entry. Ports without CEETM never reach here at all. */
static struct cdx_htb_port cdx_htb_ports[MAX_PHY_PORTS];

/* The class lists, which the Tx path never reads -- it reads the byte arrays
 * published from them. HTB commands and the DSCP filter callbacks that ask
 * which queue a classid means both arrive under RTNL today -- tc takes it
 * around the DSCP block's callback, which is not registered unlocked -- but
 * that is the callers' arrangement rather than a contract of this file, so one
 * mutex over the control side of every port serialises the two regardless.
 * The work that regrows a tree's class queues (cdx_htb_regrow_work()) holds
 * this alone, and no RTNL: everything the cap reads is kept under it but a
 * port's MTU, which it reads once. */
static DEFINE_MUTEX(cdx_htb_mutex);

/* Looks again at the trees whose class queues the cap kept short of their
 * share, until none is (cdx_htb_regrow_work()). Armed, and its pace kept,
 * under cdx_htb_mutex; cancelled without it, which the work takes. The flag
 * says the work itself is running the cap, which re-arms it at its own pace
 * rather than starting afresh. */
static void cdx_htb_regrow_work(struct work_struct *work);
static DECLARE_DELAYED_WORK(cdx_htb_regrow, cdx_htb_regrow_work);
static unsigned int cdx_htb_regrow_ms;
static bool cdx_htb_regrowing;

/* The class queues the tree of a port that went had in use, per channel
 * (cdx_htb_port_gone()). They are no live tree's any more, but until the port's
 * CEETM context is released and drained (cdx_htb_port_released()) they can
 * still hold frames up to their depth, and are charged so. Under
 * cdx_htb_mutex. */
static u16 cdx_htb_departing[CDX_CEETM_MAX_CHANNELS];

/* The releases of torn-down trees' channels, indexed as the ports are, and the
 * work that carries them out (cdx_htb_release_work()) at its pace. Under
 * cdx_htb_mutex, which the work takes only around what it reads and writes
 * here: it waits for the flowtable without it. */
static struct cdx_htb_release cdx_htb_releases[MAX_PHY_PORTS];
static void cdx_htb_release_work(struct work_struct *work);
static DECLARE_DELAYED_WORK(cdx_htb_release, cdx_htb_release_work);
static unsigned int cdx_htb_release_ms;

static struct cdx_htb_port *cdx_htb_entry(struct tQM_context_ctl *qm_ctx)
{
	if (!qm_ctx || qm_ctx < gQMCtx || qm_ctx >= gQMCtx + ARRAY_SIZE(gQMCtx))
		return NULL;
	return &cdx_htb_ports[qm_ctx - gQMCtx];
}

/* The entry, with the context it is for recorded in it. That is fixed by the
 * entry's index, so it is stored only where it is not there yet: before a
 * port's first command, and after cdx_htb_port_gone() cleared the entry. Never
 * over a live tree's, which the regrow work reads holding cdx_htb_mutex alone,
 * and this is called without it. */
static struct cdx_htb_port *cdx_htb_port_of(struct net_device *dev)
{
	struct dpa_priv_s *priv = netdev_priv(dev);
	struct cdx_htb_port *port = cdx_htb_entry(priv->qm_ctx);

	if (port && port->qm_ctx != priv->qm_ctx)
		port->qm_ctx = priv->qm_ctx;
	return port;
}

static const char *cdx_htb_port_name(struct cdx_htb_port *port)
{
	return port->qm_ctx && port->qm_ctx->net_dev ? port->qm_ctx->net_dev->name : "?";
}

static struct cdx_htb_class *cdx_htb_find(struct cdx_htb_port *port, u16 classid)
{
	struct cdx_htb_class *cl;

	list_for_each_entry(cl, &port->classes, list)
		if (cl->classid == classid)
			return cl;
	return NULL;
}

static struct cdx_htb_class *cdx_htb_find_qid(struct cdx_htb_port *port, u16 qid)
{
	struct cdx_htb_class *cl;

	list_for_each_entry(cl, &port->classes, list)
		if (!cl->inner && cl->qid == qid)
			return cl;
	return NULL;
}

static bool cdx_htb_channel_owned(struct cdx_htb_port *port, u8 channel)
{
	struct cdx_htb_class *cl;

	list_for_each_entry(cl, &port->classes, list)
		if (!cl->parent && cl->channel == channel)
			return true;
	return false;
}

/* ---- the tree's share of the buffer pools ------------------------------- */

/* Trees that are live, on every port: what SEC's share is divided between. */
static unsigned int cdx_htb_live_trees(void)
{
	unsigned int ii, trees = 0;

	for (ii = 0; ii < ARRAY_SIZE(cdx_htb_ports); ii++)
		trees += cdx_htb_ports[ii].live;
	return trees;
}

/* What one tree's class queues may hold together, in frames
 * (CDX_HTB_ETH_FRAMES). */
static u32 cdx_htb_budget(void)
{
	unsigned int trees = max(cdx_htb_live_trees(), 1u);

	return (u32)min_t(u64, CDX_HTB_ETH_FRAMES, CDX_HTB_SEC_FRAMES / trees);
}

/* The frame a RED qdisc's bytes are counted in on this port: its MTU, but no
 * more than 1,500 bytes on a jumbo port, and the overhead of a frame on the
 * wire (CDX_HTB_RED_OVERHEAD, which says what a jumbo port gives for it). */
static u32 cdx_htb_red_frame(struct cdx_htb_port *port)
{
	struct net_device *dev = port->qm_ctx ? port->qm_ctx->net_dev : NULL;
	unsigned int mtu = dev ? READ_ONCE(dev->mtu) : ETH_DATA_LEN;

	return min_t(unsigned int, mtu, ETH_DATA_LEN) + CDX_HTB_RED_OVERHEAD;
}

/* The depth a RED leaf asks for: its qdisc's limit, in frames. */
static u32 cdx_htb_red_want(struct cdx_htb_port *port,
			    const struct cdx_htb_red_curve *curve)
{
	return max_t(u32, curve->limit / cdx_htb_red_frame(port), 1);
}

/* A RED leaf's curve in frames, for a queue given `depth' of them.
 *
 * The qdisc's thresholds are divided into frames, and where the cap gave the
 * queue less than the limit asked for, scaled by what it got against what it
 * asked for, so the curve keeps its shape below a shallower tail drop. The
 * minimum stays below the tail drop, so the curve starts before the queue is
 * full; and the band is never narrower than the encoding draws with the
 * implied minimum where it was put (ceetm_wred_min_band()), which also keeps
 * a band that rounded to nothing from being refused as no band at all. */
static void cdx_htb_red_frames(struct cdx_htb_port *port,
			       const struct cdx_htb_red_curve *curve, u32 depth,
			       u32 *min, u32 *max)
{
	u32 frame = cdx_htb_red_frame(port), want = cdx_htb_red_want(port, curve);
	u64 lo = curve->min / frame, hi = curve->max / frame;

	if (depth < want) {
		lo = div_u64(lo * depth, want);
		hi = div_u64(hi * depth, want);
	}
	if (lo >= depth)
		lo = depth - 1;
	hi = max_t(u64, hi, lo + ceetm_wred_min_band(curve->probability));
	*min = (u32)lo;
	*max = (u32)hi;
}

/* One class queue of a tree, as the cap sizes it. */
struct cdx_htb_cap_queue {
	struct cdx_htb_class *cl;	/* NULL for one no leaf holds */
	u32 want;			/* frames it asks for */
	u32 depth;			/* frames it is given */
	u32 held;			/* frames it holds now */
	u8 channel, cq;
};

/* The class queues a tree uses: each leaf's, and the top channel's queues
 * unclassified and control traffic take while no leaf holds them
 * (cdx_htb_implicit_sync()). These are what the cap sizes. A queue the tree
 * gave back is not among them, though it may still hold what it had queued:
 * reset, it is eligible only for the excess tokens the tree's own queues leave
 * unused, and drains as they come -- behind a class that takes every token it
 * may, not until that class goes quiet, and not at all while the port is
 * paused. So it is still charged what it holds (cdx_htb_cap_charge()), and
 * its frames still count against what the tree's own queues may grow into. */
static unsigned int cdx_htb_cap_queues(struct cdx_htb_port *port,
				       struct cdx_htb_cap_queue *q)
{
	static const u8 implicit[] = { CDX_HTB_UNCLASSIFIED_CQ, CDX_HTB_CONTROL_CQ };
	struct cdx_htb_class *cl;
	bool fallback = true;
	unsigned int n = 0, ii;

	list_for_each_entry(cl, &port->classes, list) {
		if (cl->inner || WARN_ON_ONCE(n >= CDX_HTB_MAX_LEAVES))
			continue;
		if (port->defcls && cl->classid == port->defcls)
			fallback = false;
		q[n++] = (struct cdx_htb_cap_queue){
			.cl = cl, .channel = cl->channel, .cq = cl->cq,
			.want = cl->red ? cdx_htb_red_want(port, &cl->curve) :
					  CDX_HTB_CQ_DEPTH,
		};
	}
	if (port->top == CDX_HTB_NONE)
		return n;
	for (ii = 0; ii < ARRAY_SIZE(implicit); ii++) {
		if (port->cq_used[port->top] & BIT(implicit[ii]))
			continue;
		/* With a default leaf, unclassified traffic takes that leaf and
		 * nothing reaches queue 0: it takes no share, and keeps a frame
		 * for whatever was resolved to it before the leaf came. */
		q[n++] = (struct cdx_htb_cap_queue){
			.channel = port->top, .cq = implicit[ii],
			.want = implicit[ii] == CDX_HTB_UNCLASSIFIED_CQ && !fallback ?
				CDX_HTB_CQ_START : CDX_HTB_CQ_DEPTH,
		};
	}
	return n;
}

/* The same queues as cdx_htb_cap_queues() lists, those on one channel, as a
 * mask of class queues: the ones every tree's cap charges at their depth
 * (cdx_htb_cap_charge()), whichever port they are on. */
static u16 cdx_htb_tree_mask(struct cdx_htb_port *port, u8 channel)
{
	struct cdx_htb_class *cl;
	u16 mask = 0;

	list_for_each_entry(cl, &port->classes, list)
		if (!cl->inner && cl->channel == channel)
			mask |= BIT(cl->cq);
	if (channel == port->top)
		mask |= BIT(CDX_HTB_UNCLASSIFIED_CQ) | BIT(CDX_HTB_CONTROL_CQ);
	return mask;
}

/* The live tree whose port holds `channel', or NULL. ceetm_assign_chnl() gives
 * a channel to one port at a time. */
static struct cdx_htb_port *cdx_htb_channel_port(u8 channel)
{
	unsigned int ii;

	for (ii = 0; ii < ARRAY_SIZE(cdx_htb_ports); ii++)
		if (cdx_htb_ports[ii].live &&
		    (cdx_htb_ports[ii].channels & BIT(channel)))
			return &cdx_htb_ports[ii];
	return NULL;
}

/* Share `budget' frames between the queues, max-min fair: a queue asking for
 * no more than an even share of what is left gets what it asks for, and the
 * queues asking for more split the rest evenly. Never under a frame. */
static void cdx_htb_cap_share(struct cdx_htb_cap_queue *q, unsigned int n,
			      u32 budget)
{
	unsigned int left = n, ii;
	bool settled;
	u32 share;

	for (ii = 0; ii < n; ii++)
		q[ii].depth = 0;
	while (left) {
		share = budget / left;
		settled = false;
		for (ii = 0; ii < n; ii++) {
			if (q[ii].depth || q[ii].want > share)
				continue;
			q[ii].depth = q[ii].want;
			budget -= q[ii].want;
			left--;
			settled = true;
		}
		if (settled)
			continue;
		for (ii = 0; ii < n; ii++)
			if (!q[ii].depth)
				q[ii].depth = max_t(u32, share, 1);
		return;
	}
}

/* Program one queue at `depth' frames, from what it holds now. A RED leaf's
 * curve is drawn again every time, for that depth and the port's MTU, and
 * written where it differs from what the group holds. Any
 * other queue goes on plain tail drop, with a curve taken off if one is
 * running there -- a leaf whose RED qdisc went, or a parent that inherited its
 * last child's queue. */
static int cdx_htb_cap_write(struct cdx_htb_port *port,
			     const struct cdx_htb_cap_queue *q, u32 depth,
			     u32 now, bool curve)
{
	u32 min, max;

	if (q->cl && q->cl->red) {
		cdx_htb_red_frames(port, &q->cl->curve, depth, &min, &max);
		return ceetm_set_class_wred(q->channel, q->cq, min, max,
					    q->cl->curve.probability, depth);
	}
	if (curve)
		return ceetm_clear_class_wred(q->channel, q->cq, depth);
	if (now != depth)
		return ceetm_set_class_depth(q->channel, q->cq, depth);
	return 0;
}

/* What the class queues may hold from now on, in frames: `tree' for those of
 * this port's channels, `all' for those of every channel, which is what SEC's
 * share has to cover -- any of them can carry SEC's frames.
 *
 * A queue a tree uses is charged the larger of its depth and what it holds:
 * below its depth it may fill up to it, and above it, a depth lowered under
 * what was queued, the count only falls. Any other queue is charged what it
 * holds -- one a leaf gave back or the top channel stopped using, reset with
 * its frames still on it, and one of a channel no tree holds: given back with
 * its tree or its port, or whose drain at teardown failed. Every such queue is
 * parked at a frame (CEETM_PARKED_CQ_DEPTH), and nothing names it once the
 * classifier entries on its port have been retired or rebuilt after the
 * change; until then they can put that frame on it, beyond what it is charged.
 * On a channel no tree holds, that frame stays charged until the channel's
 * quarantine ends, it is claimed again or the module goes, each of which pops
 * it first (ceetm_pop_leftovers()). What each of
 * this tree's own queues holds goes into `q', where the growth that has to fit
 * into what is left starts from. The queues a departing port's tree used count
 * as a tree's until its context is released (cdx_htb_departing).
 *
 * The caller reads this after it has written every shrink, never before: a
 * count read under the old, higher depth could still have risen before the
 * new one took, and one read above the new depth can only fall. */
static int cdx_htb_cap_charge(struct cdx_htb_port *port,
			      struct cdx_htb_cap_queue *q, unsigned int n,
			      u32 *tree, u32 *all)
{
	struct cdx_htb_port *owner;
	unsigned int cq, ii;
	u32 held, depth;
	bool curve;
	u16 used;
	u8 ch;
	int rc;

	*tree = 0;
	*all = 0;
	for (ch = 0; ch < CDX_CEETM_MAX_CHANNELS; ch++) {
		owner = cdx_htb_channel_port(ch);
		used = owner ? cdx_htb_tree_mask(owner, ch) :
			       cdx_htb_departing[ch];
		for (cq = 0; cq < MAX_SCHEDULER_QUEUES; cq++) {
			rc = ceetm_class_queue_backlog(ch, cq, &held);
			/* A queue never built holds nothing. */
			if (rc == -ENODEV)
				held = 0;
			else if (rc)
				return rc;
			for (ii = 0; owner == port && ii < n; ii++)
				if (q[ii].channel == ch && q[ii].cq == cq)
					q[ii].held = held;
			if ((used & BIT(cq)) &&
			    !ceetm_class_queue_state(ch, cq, &depth, &curve))
				held = max(held, depth);
			*all += held;
			if (owner == port)
				*tree += held;
		}
	}
	return 0;
}

/* What the queues of this tree that grow may add between them, once its
 * shrinks are written: what is left of its budget and of SEC's share,
 * whichever is less, beside what every queue may hold (cdx_htb_cap_charge()).
 * Each may be spent already -- a queue shrunk under what it holds still holds
 * it -- and then nothing grows. Nothing either when what the queues hold
 * cannot be read: no bound would be left. */
static u32 cdx_htb_cap_room(struct cdx_htb_port *port,
			    struct cdx_htb_cap_queue *q, unsigned int n)
{
	const u32 budget = cdx_htb_budget(), sec = CDX_HTB_SEC_FRAMES;
	u32 tree, all;
	int rc;

	rc = cdx_htb_cap_charge(port, q, n, &tree, &all);
	if (rc) {
		if (!port->told_unread)
			pr_warn("cdx: %s keeps its class queues short of their share: what they hold cannot be read (%d)\n",
				cdx_htb_port_name(port), rc);
		port->told_unread = true;
		return 0;
	}
	port->told_unread = false;
	return min(tree < budget ? budget - tree : 0,
		   all < sec ? sec - all : 0);
}

/* Program what cdx_htb_cap_share() gave each queue: every queue that shrinks,
 * then the rest, so the depths the tree's queues are given never add up past
 * its budget; and while a queue will not shrink, none grows, though a curve
 * still goes on at the depth its queue has, and `withheld' says to try again.
 * A refusal the tries meet again is told once, until it is put right.
 *
 * The depths are not the whole of it, because lowering one evicts nothing: a
 * queue holding more refuses frames until it has sent down to it, at its own
 * rate -- not at all while its port is paused -- and a queue the tree gave
 * back keeps what it held. So once the shrinks are written, the queues that
 * grow, in the order they were listed, share the room what every queue may
 * hold leaves (cdx_htb_cap_room()); growing up to what a queue already holds
 * itself costs nothing. A queue that gets less than its share stays at what it
 * got, and `withheld' says so: the rest comes as those frames leave
 * (cdx_htb_regrow_work()). A RED leaf kept short has its curve drawn for the
 * depth it got, as for any share smaller than its limit.
 *
 * A RED leaf whose curve will not go on loses it, with a warning unless it is
 * `asking', whose caller says so itself. Returns whether one did: that leaf
 * now asks for a plain leaf's depth, and the shares are drawn again. */
static bool cdx_htb_cap_apply(struct cdx_htb_port *port,
			      struct cdx_htb_cap_queue *q, unsigned int n,
			      struct cdx_htb_class *asking, bool *withheld)
{
	bool stuck = false, lost = false, charged = false, curve, shrinks;
	u32 done = 0, now, depth, base, room = 0;
	unsigned int pass, ii;
	int rc;

	*withheld = false;
	for (pass = 0; pass < 2; pass++) {
		for (ii = 0; ii < n; ii++) {
			if ((done & BIT(ii)) ||
			    ceetm_class_queue_state(q[ii].channel, q[ii].cq, &now, &curve))
				continue;
			shrinks = q[ii].depth < now;
			if (shrinks != (pass == 0))
				continue;
			done |= BIT(ii);
			depth = q[ii].depth;
			if (stuck) {
				depth = min(depth, now);
			} else if (depth > now) {
				/* Read once, when the first queue grows: every
				 * shrink is written by then. */
				if (!charged) {
					room = cdx_htb_cap_room(port, q, n);
					charged = true;
				}
				base = max(now, q[ii].held);
				if (depth > base) {
					depth = min(depth, base + room);
					room -= depth - base;
					if (depth < q[ii].depth)
						*withheld = true;
				}
			}
			rc = cdx_htb_cap_write(port, &q[ii], depth, now, curve);
			if (!rc) {
				port->refused[q[ii].channel] &= (u16)~BIT(q[ii].cq);
				continue;
			}
			if (shrinks)
				stuck = true;
			if (q[ii].cl && q[ii].cl->red) {
				q[ii].cl->red = false;
				lost = true;
				if (q[ii].cl != asking)
					pr_warn("cdx: %s class %x lost its RED curve on class queue %u; the RED qdisc is no longer offloaded\n",
						cdx_htb_port_name(port), q[ii].cl->classid,
						q[ii].cq);
				continue;
			}
			/* Told once, until a write to the queue takes. */
			if (port->refused[q[ii].channel] & BIT(q[ii].cq))
				continue;
			port->refused[q[ii].channel] |= BIT(q[ii].cq);
			if (curve)
				pr_warn("cdx: CEETM channel %u queue %u kept a RED curve its class no longer has\n",
					q[ii].channel, q[ii].cq);
			else
				pr_warn("cdx: CEETM channel %u queue %u kept %u frames of tail drop rather than %u\n",
					q[ii].channel, q[ii].cq, now, depth);
		}
	}
	/* A shrink the hardware refused is tried again with the rest, by the
	 * regrow work rather than only at the next change to the tree: until it
	 * takes, the queues that were to grow stay short of their share. Told
	 * once, until a round has no shrink refused. */
	if (stuck) {
		*withheld = true;
		if (!port->told_stuck)
			pr_warn("cdx: %s left class queues short of their share: one would not give up frames to them\n",
				cdx_htb_port_name(port));
	}
	port->told_stuck = stuck;
	return lost;
}

/* Size every class queue of a port's tree to its share of what the tree may
 * hold (CDX_HTB_ETH_FRAMES), and program it. Redone whole whenever a share
 * can move: a change to the tree's queues (cdx_htb_publish()), to a RED
 * leaf's curve (cdx_htb_red()), to the port's MTU, which RED's frames are
 * counted in (cdx_htb_mtu_changed()), and to the number of trees SEC's share
 * is divided between (cdx_htb_cap_trees()) -- and, while frames other queues
 * hold keep some queue short of its share, until none is
 * (cdx_htb_regrow_work()). Every depth and every curve a class queue of a live
 * tree is given comes from here, but for the frame a queue starts with
 * (CDX_HTB_CQ_START). Ends, because each round but the last takes a RED leaf's
 * curve away. Returns whether a queue was kept short; the regrow work is
 * armed for it here, other than from the work itself, which keeps its own
 * pace. */
static bool cdx_htb_cap(struct cdx_htb_port *port, struct cdx_htb_class *asking)
{
	struct cdx_htb_cap_queue q[CDX_HTB_CAP_QUEUES];
	bool withheld;
	unsigned int n;

	if (!port->live)
		return false;
	do {
		n = cdx_htb_cap_queues(port, q);
		cdx_htb_cap_share(q, n, cdx_htb_budget());
	} while (cdx_htb_cap_apply(port, q, n, asking, &withheld));
	if (withheld && !cdx_htb_regrowing) {
		cdx_htb_regrow_ms = CDX_HTB_REGROW_FIRST_MS;
		mod_delayed_work(system_wq, &cdx_htb_regrow,
				 msecs_to_jiffies(cdx_htb_regrow_ms));
	}
	return withheld;
}

/* A tree came or went, and the share of SEC's pool every other tree may hold
 * moved with the number of them. */
static void cdx_htb_cap_trees(struct cdx_htb_port *port)
{
	unsigned int ii;

	for (ii = 0; ii < ARRAY_SIZE(cdx_htb_ports); ii++)
		if (&cdx_htb_ports[ii] != port)
			cdx_htb_cap(&cdx_htb_ports[ii], NULL);
}

/* Look again at every live tree, for the queues the cap kept short of their
 * share because frames other queues held left no room for them -- a queue
 * shrunk under what it held, one a leaf gave back, another tree's -- or
 * because the hardware refused a shrink, which is tried again. Those frames
 * leave as their ports send them, and nothing announces it, so this polls:
 * soon after the change that left a queue short (CDX_HTB_REGROW_FIRST_MS),
 * then half as often each time one still is, down to once a second
 * (CDX_HTB_REGROW_LAST_MS), and stops once every queue has its share. A port
 * paused for good keeps it polling at that slowest pace, each time reading the
 * count of every class queue once per live tree, and so do the frames a tree
 * taken down under traffic can leave on its channels, a frame a queue at most
 * (CEETM_PARKED_CQ_DEPTH), until their release pops them
 * (cdx_htb_release_work()), which redraws every tree's shares then.
 *
 * It holds cdx_htb_mutex and no RTNL, so it waits for no tc command, and the
 * only waits on it are the cancels, made without the mutex. What the cap reads
 * is all kept under that mutex: the class lists; every field of a port it
 * reads but the context, which is written only where it is not set yet
 * (cdx_htb_port_of()); and the hardware layer's record of each queue, which
 * after module load only this file changes -- but for the queues of a port
 * whose CEETM context is released, which ceetm_quiesce_port() parks under the
 * control mutex instead, a word at a time: a read of one there sees its old
 * depth or the parked one, and what it holds is read from the hardware
 * anyway. The port's MTU, which RTNL
 * guards, is read once (cdx_htb_red_frame()), and a change to it redraws the
 * curves under RTNL anyway. A port's netdev outlives its live tree: the tree
 * stops being live under this mutex, at TC_HTB_DESTROY or
 * cdx_htb_port_gone(), before the netdev is released. */
static void cdx_htb_regrow_work(struct work_struct *work)
{
	bool withheld = false;
	unsigned int ii;

	mutex_lock(&cdx_htb_mutex);
	cdx_htb_regrowing = true;
	for (ii = 0; ii < ARRAY_SIZE(cdx_htb_ports); ii++)
		withheld |= cdx_htb_cap(&cdx_htb_ports[ii], NULL);
	cdx_htb_regrowing = false;
	if (withheld) {
		cdx_htb_regrow_ms = clamp_t(unsigned int, 2 * cdx_htb_regrow_ms,
					    CDX_HTB_REGROW_FIRST_MS,
					    CDX_HTB_REGROW_LAST_MS);
		queue_delayed_work(system_wq, &cdx_htb_regrow,
				   msecs_to_jiffies(cdx_htb_regrow_ms));
	}
	mutex_unlock(&cdx_htb_mutex);
}

/* Republish what the Tx path reads. Called after every change to the tree,
 * under RTNL, and cheap enough to redo whole rather than patch in place.
 *
 * A class names its channel the way a conntrack mark does, where a channel
 * nibble of zero means "whichever channel this port owns" rather than channel
 * zero. The top channel is the answer both paths give: the highest channel a
 * class under the root holds, which is also where every frame that names no
 * leaf goes, so it has to be one that is shaped. A channel this port claimed
 * and no class holds -- its class was deleted, or its add failed after the
 * claim -- runs unshaped, and taking it as the top would move that traffic
 * out from under the port's cap. Only while no class holds any channel is the
 * highest claimed one taken instead, so frames still have somewhere to go;
 * nothing is shaped then anyway. The hardware follows through
 * cdx_htb_resolve_class(), which hands it an explicit channel. */
static void cdx_htb_implicit_sync(struct cdx_htb_port *port, u8 top);

/* Size the control budget from the top channel's committed rate. The two
 * words are read without a lock; a reader that pairs an old one with a new
 * one admits by a burst that was right a moment ago. */
static void cdx_htb_control_budget(struct cdx_htb_port *port, u8 top)
{
	u64 rate = top == CDX_HTB_NONE ? 0 : port->rate[top], budget = 0;

	if (top != CDX_HTB_NONE) {
		/* A channel with no rate is unshaped, and a floor is all there
		 * is to go by. */
		budget = max(rate / CDX_HTB_CONTROL_SHARE,
			     rate ? min_t(u64, CDX_HTB_CONTROL_FLOOR, rate / 2) :
				    CDX_HTB_CONTROL_FLOOR);
	}
	WRITE_ONCE(port->control_tau, budget ?
		   (s64)div64_u64((u64)CDX_HTB_CONTROL_BURST * NSEC_PER_SEC, budget) : 0);
	WRITE_ONCE(port->control_rate, budget);
}

static void cdx_htb_publish(struct cdx_htb_port *port)
{
	struct cdx_htb_class *cl;
	u8 top = CDX_HTB_NONE, claimed = CDX_HTB_NONE, default_slot = CDX_HTB_NONE;
	u16 unclassified;
	unsigned int ii;

	memset(port->class_txq, CDX_HTB_NONE, sizeof(port->class_txq));
	memset(port->txq_channel, CDX_HTB_NONE, sizeof(port->txq_channel));
	for (ii = 0; ii < CDX_CEETM_MAX_CHANNELS; ii++) {
		if (!(port->channels & BIT(ii)))
			continue;
		claimed = ii;
		if (cdx_htb_channel_owned(port, ii))
			top = ii;
	}
	if (top == CDX_HTB_NONE)
		top = claimed;
	if (!port->live)
		top = CDX_HTB_NONE;
	unclassified = top << 8 | CDX_HTB_UNCLASSIFIED_CQ;
	list_for_each_entry(cl, &port->classes, list) {
		u8 slot;

		if (cl->inner)
			continue;
		slot = (u8)(cl->qid - CDX_HTB_QID_BASE);
		if (WARN_ON_ONCE(slot >= CDX_HTB_MAX_LEAVES))
			continue;
		port->txq_cq[slot] = cl->cq;
		WRITE_ONCE(port->txq_channel[slot], cl->channel);
		WRITE_ONCE(port->class_txq[((cl->channel + 1) << 4) | cl->cq], slot);
		if (cl->channel == top)
			WRITE_ONCE(port->class_txq[cl->cq], slot);
		if (port->defcls && cl->classid == port->defcls) {
			default_slot = slot;
			unclassified = cl->channel << 8 | cl->cq;
		}
	}
	/* Class zero is the unclassified one, and the default leaf answers
	 * for it; without one it stays whichever leaf holds the top channel's
	 * class queue 0, which is where the hardware sends it too. */
	if (default_slot != CDX_HTB_NONE)
		WRITE_ONCE(port->class_txq[0], default_slot);
	WRITE_ONCE(port->unclassified, unclassified);
	cdx_htb_control_budget(port, top);
	WRITE_ONCE(port->top, top);
	cdx_htb_implicit_sync(port, top);
	/* Last, once the queues the tree uses are settled: whatever came,
	 * went or moved, each one's share of the tree's budget follows. */
	cdx_htb_cap(port, NULL);
}

/* Keep the class queues unclassified and control traffic take on the top
 * channel eligible for both of its token buckets while no leaf holds them.
 *
 * An unconfigured strict class queue is excess-eligible only, and a channel's
 * excess tokens come only from committed ones its classes leave unused: the
 * shaper is coupled, and a class with rate equal to ceil has no excess rate of
 * its own. So a leaf that keeps its queue backlogged takes every token, and a
 * queue left excess-only never transmits again -- the gateway's own ARP and
 * LCP frames starve behind a saturated class, and a PPPoE session drops. Every
 * queue a frame can be resolved to therefore competes for committed tokens
 * too, which leaves strict priority deciding between them, as it does between
 * leaves.
 *
 * Redone whole from cdx_htb_publish() after every change: the top channel
 * moves when a class under the root claims a higher one, and a leaf can take
 * either queue or give it back. A queue a leaf has taken was configured for
 * that leaf and is the leaf's; it leaves this set without being reset.
 */
static void cdx_htb_implicit_sync(struct cdx_htb_port *port, u8 top)
{
	const u16 needed = BIT(CDX_HTB_UNCLASSIFIED_CQ) | BIT(CDX_HTB_CONTROL_CQ);
	u8 channel = port->implicit_channel;
	u16 want = 0, drop;
	unsigned int cq;

	if (top != CDX_HTB_NONE)
		want = needed & ~port->cq_used[top];
	if (channel != CDX_HTB_NONE) {
		drop = channel == top ? port->implicit & ~want : port->implicit;
		for (cq = 0; cq < NUM_PQS; cq++) {
			if (!(drop & BIT(cq)))
				continue;
			port->implicit &= (u16)~BIT(cq);
			if (port->cq_used[channel] & BIT(cq))
				continue;
			if (ceetm_reset_class_queue(channel, cq))
				pr_warn("cdx: CEETM channel %u queue %u did not return to its defaults\n",
					channel, cq);
		}
	}
	port->implicit_channel = top;
	for (cq = 0; cq < NUM_PQS; cq++) {
		if (!(want & BIT(cq)) || (port->implicit & BIT(cq)))
			continue;
		/* Tried again at the next change if this fails: nothing about
		 * the command that got here depends on it. Its depth is the
		 * cap's, which follows. */
		if (ceetm_set_class_queue(top, cq, 0, CDX_HTB_CQ_START)) {
			pr_warn("cdx: %s cannot make CEETM channel %u queue %u eligible; frames that name no class can starve there\n",
				cdx_htb_port_name(port), top, cq);
			continue;
		}
		port->implicit |= BIT(cq);
		port->refused[top] &= (u16)~BIT(cq);
	}
}

/* Narrow or widen the usable Tx queues to cover the leaf classes in service.
 * Ordinary traffic is folded below this range by the driver, so what it really
 * decides is whether a leaf's queue can be named at all: sch_htb grafts a qdisc
 * on it either way, but netdev_cap_txqueue() rewrites anything at or above the
 * count to queue zero. */
static int cdx_htb_resize(struct cdx_htb_port *port, u16 leaves)
{
	if (!port->qm_ctx->net_dev)
		return 0;
	return netif_set_real_num_tx_queues(port->qm_ctx->net_dev,
					    CDX_HTB_QID_BASE + leaves);
}

/* A channel for a class directly under the qdisc root.
 *
 * Channels are returned to the global pool only when the qdisc goes away. One
 * this port has already claimed but no class holds any more is handed out
 * again instead of being detached and rebound: detaching a live channel means
 * draining it while frames are still being classified onto it, and a claim that
 * lasts as long as the qdisc costs nothing but a bit in chnl_map.
 */
static int cdx_htb_channel_get(struct cdx_htb_port *port, u8 *channel,
			       struct netlink_ext_ack *extack)
{
	uint32_t claimed;
	int rc;
	u8 ii;

	for (ii = 0; ii < CDX_CEETM_MAX_CHANNELS; ii++)
		if ((port->channels & BIT(ii)) && !cdx_htb_channel_owned(port, ii)) {
			*channel = ii;
			return 0;
		}
	rc = ceetm_claim_channel(port->qm_ctx, &claimed);
	/* Every channel left is held for another port until its flowtable
	 * entries are retired or rebuilt (cdx_htb_release_work()), normally a
	 * matter of moments: worth saying so, or the operator is told the SoC
	 * has none and stops trying. */
	if (rc == -EBUSY) {
		NL_SET_ERR_MSG_MOD(extack,
				   "a CEETM channel is held until another port's flowtable entries are retired or rebuilt; try again shortly");
		pr_warn_ratelimited("cdx: %s found the only CEETM channels left held until another port's flowtable entries are retired or rebuilt\n",
				    cdx_htb_port_name(port));
		return -EBUSY;
	}
	if (rc) {
		NL_SET_ERR_MSG_MOD(extack,
				   "no CEETM channel left; the SoC has eight and every port shares them");
		return -ENOSPC;
	}
	port->channels |= BIT(claimed);
	*channel = claimed;
	return 0;
}

/* Which class queue a leaf's scheduling parameters name.
 *
 * The eight strict-priority queues are one per priority, so prio names a queue
 * directly and two leaves cannot share one; asking for a priority that is taken
 * is an error rather than a silent demotion. A leaf that gives a quantum is
 * asking to share bandwidth rather than to pre-empt, which is the weighted
 * group, and there are eight of those because cdx claims group A only.
 *
 * GET_CEETM_PRIORITY() inverts the strict range: configuration index 0 is CEETM
 * queue 7, the lowest priority. Indexing from the top of the range is what
 * makes prio 0 the queue that actually wins.
 */
static int cdx_htb_cq_get(struct cdx_htb_port *port, u8 channel, u8 prio,
			  u32 quantum, u8 *cq, struct netlink_ext_ack *extack)
{
	u8 ii;

	if (quantum) {
		for (ii = NUM_PQS; ii < MAX_SCHEDULER_QUEUES; ii++)
			if (!(port->cq_used[channel] & BIT(ii))) {
				*cq = ii;
				return 0;
			}
		NL_SET_ERR_MSG_MOD(extack,
				   "no weighted class queue left on this channel; there are eight");
		return -ENOSPC;
	}
	if (prio >= NUM_PQS) {
		NL_SET_ERR_MSG_MOD(extack,
				   "prio must be 0 to 7, one per strict-priority class queue");
		return -EINVAL;
	}
	ii = NUM_PQS - 1 - prio;
	if (port->cq_used[channel] & BIT(ii)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "another class already holds this priority on this channel; give a quantum to share instead");
		return -EEXIST;
	}
	*cq = ii;
	return 0;
}

/* A class queue cdx_htb_implicit_sync() configured is being configured or
 * reset by something else, so the configuration it made no longer stands:
 * the queue is a leaf's now, or given back and parked, or in whatever state a
 * failed command left it. Forgetting it is what lets the next sync program it
 * again once no leaf holds it -- a queue still marked would be taken as
 * eligible when it is not, and nothing moves the mark until the top channel
 * does. */
static void cdx_htb_implicit_forget(struct cdx_htb_port *port, u8 channel, u8 cq)
{
	if (channel == port->implicit_channel)
		port->implicit &= (u16)~BIT(cq);
}

/* Program a leaf's class queue, and remember that it is taken. It starts on
 * plain tail drop at CDX_HTB_CQ_START; its depth, and a RED leaf's curve, are
 * the cap's, when the tree is published. */
static int cdx_htb_cq_configure(struct cdx_htb_port *port, u8 channel, u8 cq,
				u32 quantum, struct netlink_ext_ack *extack)
{
	int rc;

	cdx_htb_implicit_forget(port, channel, cq);
	rc = ceetm_set_class_queue(channel, cq, quantum, CDX_HTB_CQ_START);
	if (rc) {
		NL_SET_ERR_MSG_MOD(extack,
				   "CEETM rejected the class queue; a quantum is a weight of 1 to 255, not a byte count");
		return rc;
	}
	port->cq_used[channel] |= BIT(cq);
	/* A new class's queue: a refusal of it is news again. */
	port->refused[channel] &= (u16)~BIT(cq);
	return 0;
}

static void cdx_htb_cq_release(struct cdx_htb_port *port, u8 channel, u8 cq)
{
	if (!(port->cq_used[channel] & BIT(cq)))
		return;
	port->cq_used[channel] &= (u16)~BIT(cq);
	cdx_htb_implicit_forget(port, channel, cq);
	if (ceetm_reset_class_queue(channel, cq))
		pr_warn("cdx: CEETM channel %u queue %u did not return to its defaults\n",
			channel, cq);
}

/* Put a class queue back the way it was, after a change that could not be
 * completed; its depth, and a RED leaf's curve, come back with the publish
 * that follows. Nothing else can be done about a failure here: the caller is
 * already unwinding. */
static void cdx_htb_cq_restore(struct cdx_htb_port *port, struct cdx_htb_class *cl)
{
	if (!cdx_htb_cq_configure(port, cl->channel, cl->cq, cl->quantum, NULL))
		return;
	pr_warn("cdx: CEETM channel %u queue %u lost its configuration\n",
		cl->channel, cl->cq);
	/* Released on the way here, which took its curve with it. */
	cl->red = false;
}

/* tc rates are bytes per second; CEETM shapers are programmed in bits.
 *
 * A channel's two token buckets are additive, not nested: a class queue
 * eligible for both transmits against the committed rate and then again
 * against the excess one, so the channel's output approaches their sum. HTB
 * means ceil as a total ceiling, which makes the excess rate ceil *minus* the
 * committed rate rather than ceil itself. Measured on the rig: a class given
 * rate 200mbit ceil 200mbit ran at 376 Mbit/s when both buckets were
 * programmed at 200, which is 400 Mbit of frame rate less TCP's header share.
 *
 * ceil equal to rate therefore leaves nothing to borrow, which is what an HTB
 * class with no ceil of its own is asking for.
 */
static int cdx_htb_shape(struct cdx_htb_port *port, u8 channel, u64 rate,
			 u64 ceil, struct netlink_ext_ack *extack)
{
	u64 excess = ceil > rate ? ceil - rate : 0;

	if (ceetm_set_channel_rates(channel, rate * 8, excess * 8)) {
		NL_SET_ERR_MSG_MOD(extack, "CEETM cannot shape at the requested rate");
		return -EINVAL;
	}
	port->rate[channel] = rate;
	return 0;
}

/* Take a channel's rate away when the class that asked for it goes. Left
 * programmed, it would shape whatever class is given the channel next, before
 * that class has said anything. Nothing can be done about a failure here: the
 * caller is already giving the channel up. */
static void cdx_htb_unshape(struct cdx_htb_port *port, u8 channel)
{
	port->rate[channel] = 0;
	if (ceetm_set_channel_rates(channel, 0, 0))
		pr_warn("cdx: CEETM channel %u kept a rate it no longer has a class for\n",
			channel);
}

static void cdx_htb_class_free(struct cdx_htb_port *port, struct cdx_htb_class *cl)
{
	list_del(&cl->list);
	kfree(cl);
}

/* Keep the qid range dense by moving the last leaf into the hole, and report
 * which class moved so sch_htb can migrate that class's qdisc with it. Skipping
 * this fragments a budget of sixteen slots per port. Only the netdev queue
 * index moves: a leaf's channel and class queue are what its frames actually
 * reach, and neither changes. Returns the moved class's id, or zero. */
static u16 cdx_htb_qid_free(struct cdx_htb_port *port, u16 qid)
{
	struct cdx_htb_class *last;

	port->leaves--;
	if (qid == CDX_HTB_QID_BASE + port->leaves)
		return 0;
	last = cdx_htb_find_qid(port, CDX_HTB_QID_BASE + port->leaves);
	if (WARN_ON_ONCE(!last))
		return 0;
	last->qid = qid;
	return last->classid;
}

static int cdx_htb_create(struct cdx_htb_port *port, struct tc_htb_qopt_offload *opt)
{
	if (port->live) {
		NL_SET_ERR_MSG_MOD(opt->extack, "a hardware qdisc already owns this port");
		return -EBUSY;
	}
	/* A port whose LNI or channels are still configured is not this
	 * qdisc's to take over: only a hardware qdisc configures them, and one
	 * left configured belongs to a tree that was never taken down. */
	if (port->qm_ctx->qos_enabled || port->qm_ctx->chnl_map) {
		NL_SET_ERR_MSG_MOD(opt->extack,
				   "CEETM on this port is still configured by a tree that was never taken down");
		return -EBUSY;
	}
	INIT_LIST_HEAD(&port->classes);
	memset(port->cq_used, 0, sizeof(port->cq_used));
	memset(port->rate, 0, sizeof(port->rate));
	memset(port->refused, 0, sizeof(port->refused));
	port->told_stuck = false;
	port->told_unread = false;
	port->channels = 0;
	port->leaves = 0;
	port->implicit = 0;
	port->implicit_channel = CDX_HTB_NONE;
	port->major = opt->parent_classid;
	/* The class unclassified traffic takes in both paths, from the moment
	 * a leaf by that minor exists. Fixed for the qdisc's life: sch_htb
	 * has no change operation to alter it with. */
	port->defcls = opt->classid;
	port->live = true;
	cdx_htb_publish(port);
	/* One tree more divides SEC's share between more of them: the others
	 * shrink, before this one has a queue to grow. */
	cdx_htb_cap_trees(port);
	return 0;
}

/* A tree on `port' was taken down and its channels are quarantined for the
 * port (ceetm_stop_qos()): a release of them is due, holding the port's netdev
 * until it is done. Armed only once the command has marked the port's
 * flowtable entries (cdx_htb_release_arm()). */
static void cdx_htb_release_due(struct cdx_htb_port *port)
{
	struct cdx_htb_release *r = &cdx_htb_releases[port - cdx_htb_ports];
	struct net_device *dev = port->qm_ctx->net_dev;

	/* A tree has no channels on a port with no netdev; the context
	 * release ends the quarantine should there be one. */
	if (WARN_ON_ONCE(!dev))
		return;
	if (!r->due) {
		dev_hold(dev);
		r->dev = dev;
		r->due = true;
		r->told = false;
	}
	r->gen++;
}

/* Teardown, for a command whose return value sch_htb discards.
 *
 * Every claim has to come back whatever the hardware says, so this reports
 * trouble and keeps going rather than stopping at the first failure. A channel
 * whose drain failed stays marked as such inside the hardware layer, which is
 * what stops it being handed out again.
 *
 * The others do not go back to the global pool here but stay quarantined for
 * this port, which may take them back at once, while its flowtable entries can
 * still send to their class queues: they are released once nothing in the
 * flowtable does (cdx_htb_release_work(), which the command arms after this
 * returns). Egress resumes on the port's forwarding queues at once meanwhile.
 */
static void cdx_htb_destroy(struct cdx_htb_port *port)
{
	struct cdx_htb_class *cl, *next;
	bool claimed = port->channels;

	if (ceetm_stop_qos(port->qm_ctx))
		pr_warn("cdx: CEETM on %s did not stop cleanly\n",
			port->qm_ctx->iface_info ?
			(const char *)port->qm_ctx->iface_info->name : "?");
	list_for_each_entry_safe(cl, next, &port->classes, list)
		cdx_htb_class_free(port, cl);
	memset(port->cq_used, 0, sizeof(port->cq_used));
	memset(port->rate, 0, sizeof(port->rate));
	port->channels = 0;
	port->leaves = 0;
	port->live = false;
	/* Stopping reset every class queue of the port's channels and gave
	 * the channels back, the implicit ones with them. */
	port->implicit = 0;
	port->implicit_channel = CDX_HTB_NONE;
	/* Stop the Tx path naming a leaf before the queues stop existing. */
	cdx_htb_publish(port);
	if (cdx_htb_resize(port, 0))
		pr_warn("cdx: %s kept Tx queues no class is using\n",
			port->qm_ctx->net_dev ? port->qm_ctx->net_dev->name : "?");
	if (claimed)
		cdx_htb_release_due(port);
	/* And the trees left grow into the share of SEC's pool this one gave
	 * back. Its queues are drained and parked by now; what its entries
	 * put on them until the release is charged as what they hold. */
	cdx_htb_cap_trees(port);
}

static int cdx_htb_leaf_alloc(struct cdx_htb_port *port,
			      struct tc_htb_qopt_offload *opt)
{
	bool root = opt->parent_classid == TC_HTB_CLASSID_ROOT;
	struct cdx_htb_class *parent, *cl;
	u8 channel, cq;
	int rc;

	if (port->leaves == CDX_HTB_MAX_LEAVES) {
		NL_SET_ERR_MSG_MOD(opt->extack,
				   "no Tx queue left for another leaf class on this port");
		return -ENOSPC;
	}
	if (cdx_htb_find(port, opt->classid))
		return -EEXIST;
	if (root) {
		rc = cdx_htb_channel_get(port, &channel, opt->extack);
		if (rc)
			return rc;
	} else {
		parent = cdx_htb_find(port, (u16)opt->parent_classid);
		if (!parent || !parent->inner)
			return -ENOENT;
		channel = parent->channel;
	}
	rc = cdx_htb_cq_get(port, channel, opt->prio, opt->quantum, &cq, opt->extack);
	if (rc)
		return rc;
	cl = kzalloc(sizeof(*cl), GFP_KERNEL);
	if (!cl)
		return -ENOMEM;
	/* Shape before the port starts scheduling, so the first frame out of a
	 * new channel already meets the rate it was given. */
	if (root) {
		rc = cdx_htb_shape(port, channel, opt->rate, opt->ceil, opt->extack);
		if (rc)
			goto err_class;
	}
	rc = cdx_htb_cq_configure(port, channel, cq, opt->quantum, opt->extack);
	if (rc)
		goto err_class;
	/* The switch that makes any of this real: until CEETM is enabled the
	 * port still sends through its plain forwarding FQs and the whole tree
	 * is inert. It needs a channel bound first, which is why it happens
	 * here and not at TC_HTB_CREATE. Already-enabled is a no-op, so this
	 * also recovers a port whose first attempt failed. */
	if (ceetm_enable_or_disable_qos(port->qm_ctx, 1)) {
		NL_SET_ERR_MSG_MOD(opt->extack, "CEETM would not start on this port");
		rc = -EIO;
		goto err_cq;
	}
	/* Last thing that can fail: growing the usable range is what lets the
	 * stack put a frame on this leaf's queue at all. */
	rc = cdx_htb_resize(port, port->leaves + 1);
	if (rc) {
		NL_SET_ERR_MSG_MOD(opt->extack, "cannot put another Tx queue into service");
		goto err_cq;
	}
	cl->classid = opt->classid;
	cl->parent = root ? 0 : (u16)opt->parent_classid;
	cl->channel = channel;
	cl->cq = cq;
	cl->quantum = opt->quantum;
	cl->qid = CDX_HTB_QID_BASE + port->leaves++;
	list_add_tail(&cl->list, &port->classes);
	cdx_htb_publish(port);
	opt->qid = cl->qid;
	return 0;

err_cq:
	cdx_htb_cq_release(port, channel, cq);
err_class:
	kfree(cl);
	/* A channel claimed for a class that did not come into being stays
	 * bound to this port and unowned, so the next class reuses it. It gives
	 * back the rate it was shaped at, as a deleted class's channel does,
	 * and the top channel stays where a class holds one. The queue this
	 * class briefly took may have been one unclassified or control traffic
	 * was using, and the publish makes it eligible again. */
	if (root)
		cdx_htb_unshape(port, channel);
	cdx_htb_publish(port);
	return rc;
}

/* The parent was a leaf holding a class queue on its own channel; it becomes
 * that channel and the new child takes over both its Tx queue and its place on
 * the channel. Only a class directly under the qdisc root can do this: a class
 * queue has nothing below it to turn into. */
static int cdx_htb_leaf_to_inner(struct cdx_htb_port *port,
				 struct tc_htb_qopt_offload *opt)
{
	struct cdx_htb_class *parent, *cl;
	u8 cq;
	int rc;

	parent = cdx_htb_find(port, (u16)opt->parent_classid);
	if (!parent || parent->inner)
		return -ENOENT;
	if (parent->parent) {
		NL_SET_ERR_MSG_MOD(opt->extack,
				   "CEETM is two levels deep: classes under the qdisc are channels, their children are class queues");
		return -EOPNOTSUPP;
	}
	if (cdx_htb_find(port, opt->classid))
		return -EEXIST;
	cl = kzalloc(sizeof(*cl), GFP_KERNEL);
	if (!cl)
		return -ENOMEM;
	/* Free the parent's queue before choosing the child's, so a child that
	 * asks for the priority its parent held gets it. */
	cdx_htb_cq_release(port, parent->channel, parent->cq);
	rc = cdx_htb_cq_get(port, parent->channel, opt->prio, opt->quantum, &cq,
			    opt->extack);
	if (!rc)
		rc = cdx_htb_cq_configure(port, parent->channel, cq, opt->quantum,
					  opt->extack);
	if (rc) {
		cdx_htb_cq_restore(port, parent);
		kfree(cl);
		/* The queue the child was refused may have been one the tree
		 * keeps eligible for unclassified or control traffic. */
		cdx_htb_publish(port);
		return rc;
	}
	cl->classid = opt->classid;
	cl->parent = parent->classid;
	cl->channel = parent->channel;
	cl->cq = cq;
	cl->quantum = opt->quantum;
	cl->qid = parent->qid;
	list_add_tail(&cl->list, &port->classes);
	parent->inner = true;
	parent->qid = 0;
	parent->cq = 0;
	parent->quantum = 0;
	/* Its class queue was released above, curve and all, and a channel
	 * has no congestion group of its own to carry one. sch_htb destroys
	 * the parent's old qdisc next; that finds an inner class and does
	 * nothing. */
	parent->red = false;
	parent->red_displaced = false;
	cdx_htb_publish(port);
	return 0;
}

/* TC_HTB_LEAF_DEL, with siblings left behind. The class queue and the Tx queue
 * both come back; the channel does not, because the qdisc may still hand it to
 * the next class under the root. */
static int cdx_htb_leaf_del(struct cdx_htb_port *port,
			    struct tc_htb_qopt_offload *opt)
{
	struct cdx_htb_class *cl = cdx_htb_find(port, opt->classid);
	u16 moved;

	if (!cl || cl->inner)
		return -ENOENT;
	cdx_htb_cq_release(port, cl->channel, cl->cq);
	/* A class under the root takes its channel out of service with it. */
	if (!cl->parent)
		cdx_htb_unshape(port, cl->channel);
	moved = cdx_htb_qid_free(port, cl->qid);
	cdx_htb_class_free(port, cl);
	cdx_htb_publish(port);
	if (moved)
		opt->classid = moved;
	return 0;
}

/* TC_HTB_LEAF_DEL_LAST and its _FORCE twin, whose return value sch_htb
 * discards. The parent becomes a leaf again and inherits both the Tx queue and
 * the class queue the child was using, which is what "preserving qid" means for
 * hardware that has nowhere else to put the parent's frames. */
static int cdx_htb_leaf_del_last(struct cdx_htb_port *port,
				 struct tc_htb_qopt_offload *opt, bool force)
{
	struct cdx_htb_class *cl = cdx_htb_find(port, opt->classid);
	struct cdx_htb_class *parent;

	if (!cl || cl->inner)
		return force ? 0 : -ENOENT;
	parent = cdx_htb_find(port, cl->parent);
	if (!parent) {
		/* Nothing to hand the queues back to. Return them rather than
		 * leak them; a forced teardown still has to balance. */
		cdx_htb_cq_release(port, cl->channel, cl->cq);
		cdx_htb_qid_free(port, cl->qid);
		cdx_htb_class_free(port, cl);
		cdx_htb_publish(port);
		return force ? 0 : -ENOENT;
	}
	/* The child's RED qdisc goes with the child, but only after this
	 * command, and its destroy will then name a class that no longer
	 * exists. So the parent inherits the queue as a plain leaf, and the
	 * publish below takes the child's curve off it. */
	parent->inner = false;
	parent->qid = cl->qid;
	parent->cq = cl->cq;
	parent->quantum = cl->quantum;
	parent->red = false;
	parent->red_displaced = false;
	cdx_htb_class_free(port, cl);
	cdx_htb_publish(port);
	return 0;
}

static int cdx_htb_node_modify(struct cdx_htb_port *port,
			       struct tc_htb_qopt_offload *opt)
{
	struct cdx_htb_class *cl = cdx_htb_find(port, opt->classid);
	u8 cq;
	int rc;

	if (!cl)
		return -ENOENT;
	/* A class under the root is a channel, and a channel is the only thing
	 * here with a shaper. A class queue's rate and ceil have no hardware
	 * behind them, so what a leaf can change is where it sits among its
	 * siblings. */
	if (!cl->parent) {
		rc = cdx_htb_shape(port, cl->channel, opt->rate, opt->ceil, opt->extack);
		/* The control budget follows the top channel's rate. */
		cdx_htb_publish(port);
		return rc;
	}
	cdx_htb_cq_release(port, cl->channel, cl->cq);
	rc = cdx_htb_cq_get(port, cl->channel, opt->prio, opt->quantum, &cq, opt->extack);
	if (!rc)
		rc = cdx_htb_cq_configure(port, cl->channel, cq, opt->quantum, opt->extack);
	if (rc) {
		cdx_htb_cq_restore(port, cl);
		cdx_htb_publish(port);
		return rc;
	}
	cl->cq = cq;
	cl->quantum = opt->quantum;
	/* A RED qdisc on the leaf moves with it: the queue it now occupies was
	 * configured on tail drop, the one it left was reset, and the publish
	 * draws the curve on the new one. */
	cdx_htb_publish(port);
	return 0;
}

/* A RED qdisc on a leaf class is that class's WRED curve.
 *
 * sch_red offers the only vocabulary in tc for what the congestion group can
 * already do, and it arrives naming the class it was grafted under -- which is
 * the class queue whose congestion group this configures. A RED qdisc anywhere
 * else has no class queue behind it and is refused rather than silently kept in
 * software, because an offloaded flow would never reach it.
 *
 * ECN is refused for the same reason: this hardware drops, it does not mark, so
 * accepting `ecn` would answer a request to mark by dropping instead.
 *
 * RED names its thresholds in bytes and a class queue counts frames, which is
 * what bounds the buffers it holds. So the curve is kept as the qdisc gave it
 * and the cap programs it (cdx_htb_cap()): the limit, in frames, is what the
 * queue asks for of the tree's budget, and the curve is drawn in frames for
 * the depth the queue is given (cdx_htb_red_frames()).
 *
 * "Refused" has to mean the hardware is left without a curve, and the qdisc has
 * to say so, because sch_red discards what this returns and creates or changes
 * the software qdisc regardless. So a refused or failed REPLACE also takes away
 * a curve the class already had -- otherwise `tc qdisc change` to a setting
 * this refuses would leave the old curve running under a qdisc showing the
 * new one -- and the statistics call answers "offloaded" only for a class
 * whose curve the hardware took, which is what tc's `offloaded' reflects. The
 * reason goes to the kernel log, the one place sch_red leaves to say it.
 *
 * The curve belongs to one qdisc, not to the class. `tc qdisc replace' of a
 * RED qdisc by another creates the new one -- its REPLACE programs the class
 * queue -- and only then destroys the old one, whose DESTROY names the same
 * class; so everything but a successful REPLACE acts only on the qdisc whose
 * curve is running. The curve a replacement displaced is kept until its own
 * qdisc's destroy, and put back if the replacement is destroyed first, which
 * is how a replacement that fails after programming the queue goes.
 */
static int cdx_htb_red(struct net_device *dev, struct cdx_htb_port *port,
		       struct tc_red_qopt_offload *opt)
{
	struct cdx_htb_class *cl = NULL;
	const char *refused = NULL;
	bool running;
	int rc = -EOPNOTSUPP;

	/* A qdisc's parent is a whole handle. Only one grafted directly on a
	 * class of this qdisc names a class queue; one deeper in, under a
	 * leaf's own child qdisc, carries that qdisc's major and a minor this
	 * tree could mistake for one of its own classes. */
	if (opt->parent == TC_H_ROOT)
		refused = "the root qdisc is the port, which has no single class queue";
	else if (TC_H_MAJ(opt->parent) != (u32)port->major << 16)
		refused = "it is not grafted directly on a class of the hardware qdisc";
	else if (!(cl = cdx_htb_find(port, TC_H_MIN(opt->parent))))
		refused = "the hardware qdisc has no such class";
	else if (cl->inner) {
		refused = "its class is a channel, which has no congestion group";
		cl = NULL;
	}
	running = cl && cl->red && cl->red_qdisc == opt->handle;

	switch (opt->command) {
	case TC_RED_REPLACE:
		if (!refused && opt->set.is_ecn) {
			refused = "the hardware drops and cannot mark, so ECN cannot be offloaded";
		} else if (!refused &&
			   (!opt->set.max || opt->set.max <= opt->set.min || !opt->set.limit)) {
			refused = "the curve needs a band, min below max, and a limit";
			rc = -EINVAL;
		} else if (!refused) {
			bool had = cl->red;
			u32 had_qdisc = cl->red_qdisc;
			struct cdx_htb_red_curve had_curve = cl->curve;

			/* The cap programs it: the limit is what the queue asks
			 * for of the tree's budget, and the curve is drawn in
			 * frames for the depth the queue is given. */
			cl->red = true;
			cl->red_qdisc = opt->handle;
			cl->curve = (struct cdx_htb_red_curve){
				opt->set.min, opt->set.max,
				opt->set.probability, opt->set.limit };
			cdx_htb_cap(port, cl);
			if (cl->red) {
				if (had && !running) {
					cl->red_displaced = true;
					cl->displaced_qdisc = had_qdisc;
					cl->displaced = had_curve;
				}
				return 0;
			}
			refused = "CEETM rejected the curve";
			rc = -EIO;
			/* The cap left the queue on tail drop. A curve another
			 * qdisc had running there is that qdisc's until it goes,
			 * and goes back on; this qdisc's own is gone either way. */
			cl->red_qdisc = had_qdisc;
			cl->curve = had_curve;
			if (had && !running) {
				cl->red = true;
				cdx_htb_cap(port, NULL);
			}
			running = false;
		}
		/* A change to this qdisc: the old curve must not run under the
		 * settings the software qdisc now shows, and the cap puts the
		 * queue back on tail drop. Another qdisc's curve stays until that
		 * qdisc is destroyed, as it is next when this one was meant to
		 * replace it. */
		if (running) {
			cl->red = false;
			cdx_htb_cap(port, NULL);
		}
		if (cl && cl->red)
			netdev_warn(dev, "RED qdisc %x: not offloaded: %s; its class queue keeps RED qdisc %x's curve until that qdisc goes\n",
				    TC_H_MAJ(opt->handle) >> 16, refused,
				    TC_H_MAJ(cl->red_qdisc) >> 16);
		else
			netdev_warn(dev, "RED qdisc %x: not offloaded: %s%s\n",
				    TC_H_MAJ(opt->handle) >> 16, refused,
				    cl ? "; its class queue is on tail drop" : "");
		return rc;
	case TC_RED_DESTROY:
		if (!cl)
			return -EOPNOTSUPP;
		/* The qdisc a replacement displaced, going as the replacement
		 * completes: its successor's curve is the one running, and
		 * stays. */
		if (cl->red_displaced && cl->displaced_qdisc == opt->handle) {
			cl->red_displaced = false;
			return 0;
		}
		if (!running)
			return 0;
		/* The replacement itself, failing after its REPLACE: the qdisc
		 * it displaced is still grafted, and gets its curve back. One
		 * that will not go back leaves the queue on tail drop. */
		if (cl->red_displaced) {
			cl->red_displaced = false;
			cl->red_qdisc = cl->displaced_qdisc;
			cl->curve = cl->displaced;
			cdx_htb_cap(port, cl);
			if (!cl->red)
				netdev_warn(dev, "RED qdisc %x: its curve could not be put back; its class queue is on tail drop\n",
					    TC_H_MAJ(cl->displaced_qdisc) >> 16);
			return 0;
		}
		cl->red = false;
		cdx_htb_cap(port, NULL);
		return 0;
	case TC_RED_STATS:
		/* Answering is what marks the qdisc offloaded, so only a class
		 * running the curve answers. The counters stay software's: what
		 * the class queue dropped for an offloaded flow never reached
		 * this qdisc, and ethtool -S reports it per leaf, as rejected
		 * frames. */
		return running ? 0 : -EOPNOTSUPP;
	case TC_RED_XSTATS:
		/* Asked only of a qdisc already reported offloaded. RED's own
		 * early and forced drop counts have no hardware source. */
		return 0;
	default:
		/* TC_RED_GRAFT: a qdisc under RED would sit below the class
		 * queue, where nothing offloaded ever arrives. */
		return -EOPNOTSUPP;
	}
}

static int cdx_htb_query_queue(struct cdx_htb_port *port,
			       struct tc_htb_qopt_offload *opt)
{
	struct cdx_htb_class *cl = cdx_htb_find(port, opt->classid);

	if (!cl || cl->inner)
		return -ENOENT;
	opt->qid = cl->qid;
	return 0;
}

static int cdx_htb_setup_red(struct net_device *dev,
			     struct tc_red_qopt_offload *opt)
{
	struct cdx_htb_port *port = cdx_htb_port_of(dev);
	int rc;

	ASSERT_RTNL();
	if (!port || !port->live) {
		if (opt->command == TC_RED_REPLACE)
			netdev_warn(dev, "RED qdisc %x: not offloaded: no hardware qdisc on this port\n",
				    TC_H_MAJ(opt->handle) >> 16);
		return -EOPNOTSUPP;
	}
	mutex_lock(&cdx_htb_mutex);
	rc = cdx_htb_red(dev, port, opt);
	mutex_unlock(&cdx_htb_mutex);
	return rc;
}

static int cdx_htb_command(struct cdx_htb_port *port, struct tc_htb_qopt_offload *opt)
{
	switch (opt->command) {
	case TC_HTB_CREATE:
		return cdx_htb_create(port, opt);
	case TC_HTB_DESTROY:
		cdx_htb_destroy(port);
		return 0;
	case TC_HTB_LEAF_ALLOC_QUEUE:
		return cdx_htb_leaf_alloc(port, opt);
	case TC_HTB_LEAF_TO_INNER:
		return cdx_htb_leaf_to_inner(port, opt);
	case TC_HTB_LEAF_DEL:
		return cdx_htb_leaf_del(port, opt);
	case TC_HTB_LEAF_DEL_LAST:
		return cdx_htb_leaf_del_last(port, opt, false);
	case TC_HTB_LEAF_DEL_LAST_FORCE:
		return cdx_htb_leaf_del_last(port, opt, true);
	case TC_HTB_NODE_MODIFY:
		return cdx_htb_node_modify(port, opt);
	case TC_HTB_LEAF_QUERY_QUEUE:
		return cdx_htb_query_queue(port, opt);
	}
	return -EOPNOTSUPP;
}

/* ---- the flowtable's egress hook ----------------------------------------
 *
 * An HTB command and a DSCP filter reach it, both under RTNL today: the DSCP
 * block callback is not registered unlocked, so tc takes RTNL around it. The
 * adapter's registration is still kept alive by SRCU rather than by that --
 * the adapter's unload does not take RTNL to unregister, and a caller's locking
 * is not the hook's to depend on -- and SRCU rather than RCU because both ops
 * sleep. Unregistering waits out every call already inside the adapter's
 * text.
 */
DEFINE_STATIC_SRCU(cdx_ft_egress_srcu);
static const struct cdx_ft_egress_ops __rcu *cdx_ft_egress_ops;
/* Serialises registration against itself; callers never take it. */
static DEFINE_MUTEX(cdx_ft_egress_lock);

/* Mark every entry on `dev' for re-installation. May sleep, and a no-op with
 * no adapter registered: then there are no entries to mark. */
void cdx_ft_egress_changed(struct net_device *dev)
{
	const struct cdx_ft_egress_ops *ops;
	int idx;

	idx = srcu_read_lock(&cdx_ft_egress_srcu);
	ops = srcu_dereference(cdx_ft_egress_ops, &cdx_ft_egress_srcu);
	if (ops)
		ops->changed(dev);
	srcu_read_unlock(&cdx_ft_egress_srcu, idx);
}

/* Wait until what cdx_ft_egress_changed(dev) started has finished, or say it
 * cannot be told yet (-EAGAIN). With no adapter registered there is nobody to
 * ask, but an adapter that is unloading unregisters before it retires its
 * entries -- so the answer is then whether the backend holds any at all. */
int cdx_ft_egress_drain(struct net_device *dev)
{
	const struct cdx_ft_egress_ops *ops;
	int idx, rc;

	might_sleep();
	idx = srcu_read_lock(&cdx_ft_egress_srcu);
	ops = srcu_dereference(cdx_ft_egress_ops, &cdx_ft_egress_srcu);
	if (ops)
		rc = ops->drain(dev);
	else
		rc = cdx_ft_idle() ? 0 : -EAGAIN;
	srcu_read_unlock(&cdx_ft_egress_srcu, idx);
	return rc;
}

/* Tell the adapter the datapath restarted. A no-op with none registered: an
 * adapter loading later starts from the restarted state anyway. */
void cdx_ft_egress_restarted(void)
{
	const struct cdx_ft_egress_ops *ops;
	int idx;

	idx = srcu_read_lock(&cdx_ft_egress_srcu);
	ops = srcu_dereference(cdx_ft_egress_ops, &cdx_ft_egress_srcu);
	if (ops)
		ops->restarted();
	srcu_read_unlock(&cdx_ft_egress_srcu, idx);
}

/* ---- releasing a torn-down tree's channels ------------------------------
 *
 * A tree taken down stops its port's transmit path and drains its class queues
 * at once, but whatever the hardware still sends to them goes on putting a
 * parked frame on each until it is retired, or rebuilt against the port as it
 * now is. Every HTB command marks the port's flowtable entries for that
 * (cdx_ft_egress_changed()), and sch_htb takes each leaf away (LEAF_DEL)
 * before the tree, so a flow's retirement starts at the first of those, while
 * tc holds the RTNL its readmission needs, and has normally finished before
 * the channels go. What a teardown does not retire is rebuilt instead, since
 * nothing would offer it again: an SA, by its own work, and a multicast
 * group's listener entries, by workers that wait for the RTNL the command and
 * whatever follows it hold. Those, and a retirement a burst of churn has not
 * finished, are what outlive the teardown. The tree's channels therefore stay
 * quarantined for the port (ceetm_stop_qos()) rather than going straight back
 * to the pool: claimed by another port's tree meanwhile, a channel would carry
 * those frames out of the wrong port (A350). The port's own next tree may
 * take them back at once; frames on them then leave by the port they were
 * meant for.
 *
 * The release waits until the flowtable has nothing left that sends to them
 * (cdx_ft_egress_drain(), which rebuilds itself the multicast groups their
 * workers have not got to, and waits for the rest) -- nor anything a walk begun
 * before an unlink may still be inside, which only a completed barrier proves
 * (cdx_ft_proven()) -- and only then ends the quarantine, popping what the
 * entries left (ceetm_end_quarantine()). Until then what they left is charged
 * as what the queues hold, as the cap charges any queue no tree uses.
 *
 * Locks. The drain sleeps on the flowtable's own work, which takes the control
 * mutex, whose holder takes cdx_htb_mutex in cdx_htb_port_gone(): so the work
 * waits for it holding neither -- nor RTNL, which it never takes -- with its
 * own reference on the netdev, and re-reads what it was releasing under
 * cdx_htb_mutex afterwards. No holder of
 * the control mutex or of cdx_htb_mutex ever waits for the work; only
 * cdx_htb_exit() cancels it, holding nothing. A port that goes meanwhile
 * (cdx_htb_port_gone()) just forgets its release, whose quarantine ends with
 * the port's context, classification stopped by then. */

/* One port's release, if it is due and its port's entries have been marked
 * since its last teardown. Returns whether it has to be tried again. */
static bool cdx_htb_release_one(unsigned int ii)
{
	struct cdx_htb_release *r = &cdx_htb_releases[ii];
	struct net_device *dev, *put = NULL;
	bool again = false;
	unsigned long gen;
	int rc;

	mutex_lock(&cdx_htb_mutex);
	if (!r->due || r->marked != r->gen) {
		mutex_unlock(&cdx_htb_mutex);
		return false;
	}
	gen = r->gen;
	dev = r->dev;
	dev_hold(dev);
	mutex_unlock(&cdx_htb_mutex);

	rc = cdx_ft_egress_drain(dev);

	mutex_lock(&cdx_htb_mutex);
	/* Gone with its port, or taken down again while the drain ran: what
	 * was proven does not cover the later teardown, whose own marking
	 * arms this again. */
	if (!r->due || r->gen != gen) {
		mutex_unlock(&cdx_htb_mutex);
		dev_put(dev);
		return false;
	}
	if (rc) {
		if (!r->told)
			pr_warn("cdx: %s keeps the CEETM channels of its last tree out of service until its flowtable entries have been retired or rebuilt (%d)\n",
				netdev_name(dev), rc);
		r->told = true;
		again = true;
	} else {
		if (ceetm_end_quarantine(&gQMCtx[ii]))
			pr_warn("cdx: %s left frames on a CEETM channel of its last tree that could not be freed; the channel stays out of service\n",
				netdev_name(dev));
		put = r->dev;
		r->dev = NULL;
		r->due = false;
		/* What the entries left was charged, and is gone: a tree kept
		 * short for it can grow now. */
		cdx_htb_cap_trees(NULL);
	}
	mutex_unlock(&cdx_htb_mutex);
	dev_put(dev);
	if (put)
		dev_put(put);
	return again;
}

/* Release what is due, and look again later at what cannot be yet: soon, then
 * less often (CDX_HTB_RELEASE_FIRST_MS, CDX_HTB_RELEASE_LAST_MS). A channel
 * the flowtable can never show nothing sends to is never released. */
static void cdx_htb_release_work(struct work_struct *work)
{
	bool again = false;
	unsigned int ii;

	for (ii = 0; ii < ARRAY_SIZE(cdx_htb_releases); ii++)
		again |= cdx_htb_release_one(ii);
	if (!again)
		return;
	/* The first look is the one the command arms; the first retry follows
	 * it by CDX_HTB_RELEASE_FIRST_MS. */
	mutex_lock(&cdx_htb_mutex);
	queue_delayed_work(system_wq, &cdx_htb_release,
			   msecs_to_jiffies(cdx_htb_release_ms));
	cdx_htb_release_ms = clamp_t(unsigned int, 2 * cdx_htb_release_ms,
				     CDX_HTB_RELEASE_FIRST_MS,
				     CDX_HTB_RELEASE_LAST_MS);
	mutex_unlock(&cdx_htb_mutex);
}

/* `port''s entries have been marked for re-installation after a teardown that
 * made a release due: the release may go ahead, once they have been retired
 * or rebuilt. Called by the command, after cdx_ft_egress_changed(), with no
 * lock held. */
static void cdx_htb_release_arm(struct cdx_htb_port *port)
{
	struct cdx_htb_release *r = &cdx_htb_releases[port - cdx_htb_ports];

	mutex_lock(&cdx_htb_mutex);
	if (r->due) {
		r->marked = r->gen;
		cdx_htb_release_ms = CDX_HTB_RELEASE_FIRST_MS;
		mod_delayed_work(system_wq, &cdx_htb_release, 0);
	}
	mutex_unlock(&cdx_htb_mutex);
}

static int cdx_htb_setup_tc(struct net_device *dev, struct tc_htb_qopt_offload *opt)
{
	struct cdx_htb_port *port = cdx_htb_port_of(dev);
	int rc;

	ASSERT_RTNL();
	if (!port) {
		NL_SET_ERR_MSG_MOD(opt->extack, "CEETM is not configured on this interface");
		return -EOPNOTSUPP;
	}
	if (opt->command != TC_HTB_CREATE && !port->live)
		return -ENOENT;
	/* A tree going takes the regrow work's reason with it, if it was the
	 * tree kept short; one still short on another port arms it again when
	 * the destroy below redraws the others' shares. Cancelled without the
	 * mutex, which the work takes. */
	if (opt->command == TC_HTB_DESTROY)
		cancel_delayed_work_sync(&cdx_htb_regrow);

	mutex_lock(&cdx_htb_mutex);
	rc = cdx_htb_command(port, opt);
	mutex_unlock(&cdx_htb_mutex);
	/* Whatever the tree now is, a DSCP filter naming a class in it has to
	 * be told: a class that moved or went away leaves the map pointing at a
	 * queue the operator no longer means. Outside the lock, because the
	 * reprogramming comes back through the resolver below. */
	cdx_dscp_tree_changed(dev);
	/* And every entry transmitting on the port, for the same reason one
	 * level down: each names the queue it was installed with. Even after
	 * a failed command, which may have got as far as switching the mode;
	 * re-installing what did not need it only costs a readmission. */
	if (opt->command != TC_HTB_LEAF_QUERY_QUEUE)
		cdx_ft_egress_changed(dev);
	/* A tree taken down left its channels quarantined, and their release
	 * waits for the entries this and the leaf deletions before it marked to
	 * have been retired or rebuilt. Armed only now: a release that drained
	 * before the last marking proves nothing. */
	if (opt->command == TC_HTB_DESTROY)
		cdx_htb_release_arm(port);
	return rc;
}

int cdx_register_ft_egress(const struct cdx_ft_egress_ops *ops)
{
	int rc = 0;

	if (!ops || !ops->changed || !ops->drain || !ops->restarted)
		return -EINVAL;
	mutex_lock(&cdx_ft_egress_lock);
	if (rcu_access_pointer(cdx_ft_egress_ops))
		rc = -EBUSY;
	else
		rcu_assign_pointer(cdx_ft_egress_ops, ops);
	mutex_unlock(&cdx_ft_egress_lock);
	return rc;
}
EXPORT_SYMBOL_NS_GPL(cdx_register_ft_egress, ASK_CDX_FLOWTABLE);

/* Returns once no call is inside either op, so the registrant's text can go. */
void cdx_unregister_ft_egress(void)
{
	mutex_lock(&cdx_ft_egress_lock);
	RCU_INIT_POINTER(cdx_ft_egress_ops, NULL);
	mutex_unlock(&cdx_ft_egress_lock);
	synchronize_srcu(&cdx_ft_egress_srcu);
}
EXPORT_SYMBOL_NS_GPL(cdx_unregister_ft_egress, ASK_CDX_FLOWTABLE);

/* The CEETM channel and class queue a leaf class names, for a filter that
 * wants to send something to it.
 *
 * classid is a whole tc handle, the way `action skbedit priority 1:10' writes
 * it, because a filter names a class as the operator typed it. The tree itself
 * is keyed on minors -- sch_htb truncates them in the offload structure -- so
 * the major is checked against the qdisc's and then discarded.
 */
int cdx_htb_class_queue(struct net_device *dev, u32 classid, u8 *channel, u8 *cq,
			struct netlink_ext_ack *extack)
{
	struct cdx_htb_port *port = cdx_htb_port_of(dev);
	struct cdx_htb_class *cl;
	int rc = 0;

	if (!port)
		return -EOPNOTSUPP;
	mutex_lock(&cdx_htb_mutex);
	if (!port->live) {
		NL_SET_ERR_MSG_MOD(extack, "no hardware qdisc on this port to name a class in");
		rc = -ENOENT;
		goto out;
	}
	if (TC_H_MAJ(classid) >> 16 != port->major) {
		NL_SET_ERR_MSG_MOD(extack, "that class belongs to another qdisc");
		rc = -EINVAL;
		goto out;
	}
	cl = cdx_htb_find(port, TC_H_MIN(classid));
	if (!cl) {
		NL_SET_ERR_MSG_MOD(extack, "no such class on this port");
		rc = -ENOENT;
		goto out;
	}
	/* An inner class is a channel. Frames are enqueued to queues, and a
	 * channel has as many as sixteen of them. */
	if (cl->inner) {
		NL_SET_ERR_MSG_MOD(extack, "that class is a channel, not a leaf queue");
		rc = -EINVAL;
		goto out;
	}
	*channel = cl->channel;
	*cq = cl->cq;
out:
	mutex_unlock(&cdx_htb_mutex);
	return rc;
}

void cdx_htb_port_gone(struct tQM_context_ctl *qm_ctx)
{
	struct cdx_htb_port *port = cdx_htb_entry(qm_ctx);
	struct cdx_htb_release *r;
	struct cdx_htb_class *cl, *next;
	struct net_device *put = NULL;
	unsigned int ii;

	if (!port)
		return;
	/* A release due for an earlier tree is forgotten, not waited for: the
	 * caller holds the control mutex, which the release's wait on the
	 * flowtable needs. Releasing the context ends the quarantine, with
	 * classification stopped by then; a release running now finds the
	 * port's record gone when it looks again, and gives nothing back. */
	r = &cdx_htb_releases[port - cdx_htb_ports];
	mutex_lock(&cdx_htb_mutex);
	if (r->due) {
		put = r->dev;
		r->dev = NULL;
		r->due = false;
	}
	mutex_unlock(&cdx_htb_mutex);
	if (put)
		dev_put(put);
	/* The regrow work reads a live tree's netdev, which the caller releases
	 * after the context. What keeps the work off this one is the tree
	 * ceasing to be live below, under the mutex the work holds: a run that
	 * gets the mutex first is finished before this goes on, and one after
	 * passes the tree by. Cancelling as well leaves no run pending on this
	 * tree's account; one another tree still needs is armed again when the
	 * context is released (cdx_htb_port_released()). A change on another
	 * port can also arm it again before the mutex is taken here, which is
	 * harmless for the same reason. Cancelled without the mutex, which the
	 * work takes. */
	cancel_delayed_work_sync(&cdx_htb_regrow);
	mutex_lock(&cdx_htb_mutex);
	if (!port->live)
		goto out;
	/* Until the caller has released and drained the context, the queues
	 * this tree used can still hold frames up to their depth -- classifier
	 * entries still name them -- and every other tree's cap charges them
	 * so. */
	for (ii = 0; ii < CDX_CEETM_MAX_CHANNELS; ii++)
		if (port->channels & BIT(ii))
			cdx_htb_departing[ii] |= cdx_htb_tree_mask(port, ii);
	/* The caller is releasing the whole CEETM context, so the hardware is
	 * its problem; only the bookkeeping is ours. A qdisc still attached to
	 * a netdev being unregistered is destroyed by dev_shutdown() before the
	 * netdev goes, so this normally finds nothing. */
	list_for_each_entry_safe(cl, next, &port->classes, list)
		cdx_htb_class_free(port, cl);
	memset(port, 0, sizeof(*port));
	INIT_LIST_HEAD(&port->classes);
	/* Zero is a channel and a leaf slot, not "none": the maps the Tx path
	 * reads have to say none explicitly. */
	port->implicit_channel = CDX_HTB_NONE;
	cdx_htb_publish(port);
out:
	mutex_unlock(&cdx_htb_mutex);
}

/* A port's tree went (cdx_htb_port_gone()) and its CEETM context has been
 * released, its queues with it: only now do the trees left grow into the share
 * of SEC's pool it had, which until then its queues could still hold. The
 * release parked and drained them (ceetm_quiesce_port()) with the classifier
 * stopped, so they stop being charged at their depth; a queue whose drain
 * failed is still charged what it holds, as any queue of a channel no tree
 * holds is. */
void cdx_htb_port_released(void)
{
	mutex_lock(&cdx_htb_mutex);
	memset(cdx_htb_departing, 0, sizeof(cdx_htb_departing));
	cdx_htb_cap_trees(NULL);
	mutex_unlock(&cdx_htb_mutex);
}

/* The port's MTU changed. A RED leaf's thresholds are counted in frames of the
 * size the MTU admits (cdx_htb_red_frames()), so what it asks for and the
 * curve it runs move with it, and the tree's shares are drawn again. */
void cdx_htb_mtu_changed(struct net_device *dev)
{
	struct cdx_htb_port *port = cdx_htb_port_of(dev);

	ASSERT_RTNL();
	if (!port)
		return;
	mutex_lock(&cdx_htb_mutex);
	cdx_htb_cap(port, NULL);
	mutex_unlock(&cdx_htb_mutex);
}

/* The data path. Both callbacks run per frame, without RTNL, against the byte
 * maps cdx_htb_publish() keeps.
 *
 * The class comes from the adapter's own classifier, registered below, so the
 * frame lands on the class the hardware rule would have given the same flow.
 * With no classifier registered no class is decoded, but a port with a live
 * tree still answers for every frame through cdx_htb_txq_fq(): the driver's own
 * resolution from skb->mark reads a different field in a different encoding,
 * and on a port the tree owns it would pick queues the tree never configured.
 * A port without a tree answers nothing, and cpe_fp_tx() resolves the frame as
 * it did before any of this existed.
 *
 * Nothing here reads what the stack attached to the skb on the way, because
 * crossing a device boundary scrubs it: ppp_start_xmit() drops every frame's
 * conntrack and ingress index, and so do the IP tunnels, so a frame for a PPPoE
 * session or a 6in4 tunnel reaches the port looking like one nothing
 * forwarded. The headers survive every such boundary. So the decisions are
 * made from them: the connection is found again from the packet's tuple
 * (cdx_ft_qos_class_fn), and whether a frame is control traffic is a property
 * of its protocol and of whether the gateway sent it.
 */
static cdx_ft_qos_class_fn cdx_ft_qos_class_func;
/* Whether any class the classifier can decode carries a remark. A remark is
 * the one thing a class does on a port with no tree, so without one such a
 * port has nothing to ask the classifier. */
static bool cdx_ft_qos_remarks;

int cdx_register_ft_qos_class(cdx_ft_qos_class_fn fn, bool remarks)
{
	if (!fn)
		return -EINVAL;
	if (cmpxchg(&cdx_ft_qos_class_func, NULL, fn))
		return -EBUSY;
	WRITE_ONCE(cdx_ft_qos_remarks, remarks);
	return 0;
}
EXPORT_SYMBOL_NS_GPL(cdx_register_ft_qos_class, ASK_CDX_FLOWTABLE);

/* Finishes the readers that may be inside the classifier before its module
 * goes. Each takes its own rcu_read_lock() around the pointer and the call
 * (cdx_htb_select_queue()), so this holds whatever context the frame came
 * from -- AF_PACKET's qdisc bypass reaches ndo_select_queue holding none. */
void cdx_unregister_ft_qos_class(void)
{
	WRITE_ONCE(cdx_ft_qos_class_func, NULL);
	synchronize_net();
	WRITE_ONCE(cdx_ft_qos_remarks, false);
}
EXPORT_SYMBOL_NS_GPL(cdx_unregister_ft_qos_class, ASK_CDX_FLOWTABLE);

/* A datagram an IP fragment belongs to: the fields every fragment of it
 * repeats, which is how a later fragment is matched to the first. */
struct cdx_htb_datagram {
	__be32 saddr[4], daddr[4];
	__be32 id;
	u8 family, proto;
};

/* What the Tx path reads from a frame's headers. Offsets are from skb->data,
 * which is where the Ethernet header starts both in ndo_select_queue and in
 * ndo_start_xmit; a VLAN tag the stack still carries out of band is not in the
 * frame yet, and one already pushed in is walked past, as is a PPPoE session
 * header. */
struct cdx_htb_frame {
	/* The frame's own IP header, and AF_INET or AF_INET6; a family of zero
	 * for a frame that carries none. */
	unsigned int nh;
	u8 family;
	/* The IP header an IP-in-IP frame carries -- 6in4, 4in6, and their
	 * like -- likewise. */
	unsigned int inner;
	u8 inner_family;
	/* A link protocol (cdx_htb_parse()). */
	bool link;
	/* The frame's own IP header is addressed within the link: to a
	 * multicast group, the limited broadcast, or an IPv6 link-local
	 * address. Nothing so addressed is ever routed. */
	bool scoped;
	/* A fragment of a larger datagram; whether it is a later one, which
	 * carries no transport header to find a connection by; and whether it
	 * is the datagram's last. */
	bool fragment, later, last;
	struct cdx_htb_datagram datagram;
};

/* The transport protocol of the IP packet at `off', and where its header
 * starts. False for a packet whose transport header cannot be reached: a
 * fragment after the first, or a header this frame does not hold. A fragment
 * is recorded in `f' either way, first or later, with the datagram it is of.
 *
 * IPv6 extension headers are walked as ipv6_skip_exthdr() walks them, which
 * this does itself only because that one does not say where the fragment
 * header it passed was. */
static bool cdx_htb_l4(const struct sk_buff *skb, struct cdx_htb_frame *f,
		       unsigned int off, u8 family, u8 *proto, unsigned int *thoff)
{
	if (family == AF_INET) {
		struct iphdr _iph;
		const struct iphdr *iph;

		iph = skb_header_pointer(skb, off, sizeof(_iph), &_iph);
		if (!iph || iph->version != 4 || iph->ihl < 5)
			return false;
		if (off == f->nh)
			f->scoped = ipv4_is_multicast(iph->daddr) || ipv4_is_lbcast(iph->daddr);
		if (iph->frag_off & htons(IP_MF | IP_OFFSET)) {
			f->fragment = true;
			f->later = !!(iph->frag_off & htons(IP_OFFSET));
			f->last = f->later && !(iph->frag_off & htons(IP_MF));
			f->datagram.family = AF_INET;
			f->datagram.proto = iph->protocol;
			f->datagram.id = (__force __be32)iph->id;
			f->datagram.saddr[0] = iph->saddr;
			f->datagram.daddr[0] = iph->daddr;
			if (f->later)
				return false;
		}
		*proto = iph->protocol;
		*thoff = off + iph->ihl * 4;
		return true;
	} else {
		struct ipv6hdr _ip6h;
		const struct ipv6hdr *ip6h;
		unsigned int at = off + sizeof(_ip6h);
		u8 nexthdr;

		ip6h = skb_header_pointer(skb, off, sizeof(_ip6h), &_ip6h);
		if (!ip6h || ip6h->version != 6)
			return false;
		if (off == f->nh)
			f->scoped = ip6h->daddr.s6_addr[0] == 0xff ||
				    (ip6h->daddr.s6_addr[0] == 0xfe &&
				     (ip6h->daddr.s6_addr[1] & 0xc0) == 0x80);
		for (nexthdr = ip6h->nexthdr; ipv6_ext_hdr(nexthdr);) {
			struct ipv6_opt_hdr _hdr;
			const struct ipv6_opt_hdr *hp;
			unsigned int hdrlen;

			if (nexthdr == NEXTHDR_NONE)
				return false;
			hp = skb_header_pointer(skb, at, sizeof(_hdr), &_hdr);
			if (!hp)
				return false;
			if (nexthdr == NEXTHDR_FRAGMENT) {
				struct frag_hdr _fh;
				const struct frag_hdr *fh;

				fh = skb_header_pointer(skb, at, sizeof(_fh), &_fh);
				if (!fh)
					return false;
				f->fragment = true;
				f->later = !!(ntohs(fh->frag_off) & ~0x7);
				f->last = f->later && !(ntohs(fh->frag_off) & IP6_MF);
				f->datagram.family = AF_INET6;
				f->datagram.proto = fh->nexthdr;
				f->datagram.id = fh->identification;
				memcpy(f->datagram.saddr, &ip6h->saddr, sizeof(ip6h->saddr));
				memcpy(f->datagram.daddr, &ip6h->daddr, sizeof(ip6h->daddr));
				if (f->later)
					return false;
				hdrlen = sizeof(*fh);
			} else if (nexthdr == NEXTHDR_AUTH) {
				hdrlen = ipv6_authlen(hp);
			} else {
				hdrlen = ipv6_optlen(hp);
			}
			nexthdr = hp->nexthdr;
			at += hdrlen;
		}
		*proto = nexthdr;
		*thoff = at;
		return true;
	}
}

/* The IP version of the header at `off', or zero. */
static u8 cdx_htb_ip_family(const struct sk_buff *skb, unsigned int off)
{
	u8 _first, *first = skb_header_pointer(skb, off, sizeof(_first), &_first);

	if (!first)
		return 0;
	return *first >> 4 == 4 ? AF_INET : *first >> 4 == 6 ? AF_INET6 : 0;
}

#define CDX_HTB_MAX_TAGS	2

/* Read a frame's headers into `f'.
 *
 * A link protocol is one that keeps links, addresses and neighbours working
 * and never leaves the link it is on: every frame that is not IP -- ARP, PPPoE
 * discovery, a PPP session's own LCP, authentication and NCP frames, LLDP,
 * spanning tree -- and, in IP, IGMP, neighbour discovery and MLD, and DHCP in
 * either family. Whose it is decides whether it is control (cdx_htb_control()).
 * ICMP echoes and errors are not link protocols: the gateway's own are control
 * because the gateway sent them, and a forwarded one is traffic like any other.
 */
static void cdx_htb_parse(const struct sk_buff *skb, struct cdx_htb_frame *f)
{
	unsigned int off = ETH_HLEN, tags, thoff;
	__be16 _field, *field, type;
	struct udphdr _uh;
	const struct udphdr *uh;
	u8 proto, _icmp6, *icmp6;

	memset(f, 0, sizeof(*f));
	f->link = true;
	/* The EtherType, and past each tag the one it encapsulates. */
	field = skb_header_pointer(skb, ETH_HLEN - sizeof(_field), sizeof(_field), &_field);
	for (tags = 0; field && eth_type_vlan(*field) && tags < CDX_HTB_MAX_TAGS; tags++) {
		off += VLAN_HLEN;
		field = skb_header_pointer(skb, off - sizeof(_field), sizeof(_field), &_field);
	}
	if (!field)
		return;
	type = *field;
	/* A session's own PPP protocol, behind its six-byte header. */
	if (type == htons(ETH_P_PPP_SES)) {
		field = skb_header_pointer(skb, off + sizeof(struct pppoe_hdr),
					   sizeof(_field), &_field);
		if (!field)
			return;
		off += PPPOE_SES_HLEN;
		type = *field == htons(PPP_IP) ? htons(ETH_P_IP) :
		       *field == htons(PPP_IPV6) ? htons(ETH_P_IPV6) : 0;
	}
	if (type == htons(ETH_P_IP))
		f->family = AF_INET;
	else if (type == htons(ETH_P_IPV6))
		f->family = AF_INET6;
	else
		return;
	f->nh = off;
	f->link = false;
	if (!cdx_htb_l4(skb, f, off, f->family, &proto, &thoff))
		return;
	switch (proto) {
	case IPPROTO_IGMP:
		f->link = f->family == AF_INET;
		break;
	case IPPROTO_ICMPV6:
		icmp6 = skb_header_pointer(skb, thoff, sizeof(_icmp6), &_icmp6);
		if (!icmp6 || f->family != AF_INET6)
			break;
		switch (*icmp6) {
		case ICMPV6_MGM_QUERY:
		case ICMPV6_MGM_REPORT:
		case ICMPV6_MGM_REDUCTION:
		case ICMPV6_MLD2_REPORT:
		case NDISC_ROUTER_SOLICITATION:
		case NDISC_ROUTER_ADVERTISEMENT:
		case NDISC_NEIGHBOUR_SOLICITATION:
		case NDISC_NEIGHBOUR_ADVERTISEMENT:
		case NDISC_REDIRECT:
			f->link = true;
		}
		break;
	case IPPROTO_UDP:
		uh = skb_header_pointer(skb, thoff, sizeof(_uh), &_uh);
		if (!uh)
			break;
		if (f->family == AF_INET)
			f->link = uh->dest == htons(67) || uh->dest == htons(68);
		else
			f->link = uh->dest == htons(546) || uh->dest == htons(547);
		break;
	case IPPROTO_IPIP:
	case IPPROTO_IPV6:
		f->inner_family = cdx_htb_ip_family(skb, thoff);
		if (f->inner_family != (proto == IPPROTO_IPIP ? AF_INET : AF_INET6))
			f->inner_family = 0;
		else
			f->inner = thoff;
		break;
	}
}

/* Whether a frame is control traffic, and if so whether it is the gateway's
 * own link traffic, which *own_link says.
 *
 * Control is what the gateway sends itself, and link protocols the bridge
 * carries between its ports. None of it is ever offloaded. The gateway's own
 * are its sockets' frames -- how it is reached and managed, and how it
 * resolves names for the network behind it -- the socketless frames it
 * originates, ARP, LCP and IGMP among them, which never received an ingress
 * index, and whatever netpoll sends with interrupts off, which is how a
 * console reaches the network when everything else has failed.
 *
 * A link protocol the bridge forwards between ports is control too, but not
 * the gateway's own: it is a host on the other side being answered. And one
 * that routing forwarded -- a unicast DHCP renewal to a server upstream, say,
 * or anything a host shapes like a link protocol and addresses off the link --
 * is traffic like any other, taking its flow's queue, as the flow does in
 * hardware. Routing takes only a frame addressed to this host, which leaves
 * PACKET_HOST; a frame the bridge forwards is addressed to another. A routed
 * frame a scrub reached first has no ingress index either, so an IP link frame
 * without one is taken for the gateway's own only when its destination is on
 * the link, which every such frame the kernel originates without a socket --
 * IGMP, a kernel DHCP client -- has. A frame that is not IP cannot have been
 * routed at all.
 *
 * The distinction matters for the budget (cdx_htb_control_admit()): the
 * gateway's own link traffic may run past what its sessions and the hosts it
 * bridges for have spent, so neither a bulk transfer from the gateway nor a
 * host flooding broadcasts can push an LCP echo off the top of the tree. */
static bool cdx_htb_control(const struct sk_buff *skb, const struct cdx_htb_frame *f,
			    bool *own_link)
{
	*own_link = false;
	if (skb->sk || irqs_disabled()) {
		*own_link = f->link;
		return true;
	}
	if (!f->link)
		return false;
	if (!skb->skb_iif && (!f->family || f->scoped)) {
		*own_link = true;
		return true;
	}
	return skb->skb_iif && (!f->family || skb->pkt_type != PACKET_HOST);
}

/* Control frames sent as unclassified traffic because their port's budget was
 * spent. Reported in /proc/cdx_flowtable. */
static atomic64_t cdx_htb_control_overruns = ATOMIC64_INIT(0);

/* Take `len' bytes from the port's control budget, or refuse. Lock-free, and
 * callable from any context a frame is sent from.
 *
 * The budget is a rate and a burst (cdx_htb_control_budget()), kept as the
 * time by which everything admitted so far would have left at that rate. A
 * frame is admitted while that time is no more than the burst's worth ahead of
 * now -- twice that for the gateway's own link traffic, so neither its own
 * sessions nor the hosts it bridges for, spending the budget, can push an LCP
 * echo or an ARP reply off the top of the tree. */
static bool cdx_htb_control_admit(struct cdx_htb_port *port, unsigned int len,
				  bool link)
{
	u64 rate = READ_ONCE(port->control_rate);
	s64 tau = READ_ONCE(port->control_tau), now, tat, start, cost;

	if (!rate)
		return false;
	if (link)
		tau *= 2;
	cost = div64_u64((u64)len * NSEC_PER_SEC, rate);
	now = ktime_get_mono_fast_ns();
	tat = atomic64_read(&port->control_tat);
	do {
		start = tat > now ? tat : now;
		if (start - now > tau) {
			atomic64_inc(&cdx_htb_control_overruns);
			return false;
		}
	} while (!atomic64_try_cmpxchg(&port->control_tat, &tat, start + cost));
	return true;
}

u64 cdx_ft_qos_control_overruns(void)
{
	return atomic64_read(&cdx_htb_control_overruns);
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_qos_control_overruns, ASK_CDX_FLOWTABLE);

/* The class of the connection a frame belongs to: -1 with no classifier
 * registered, 0 when no connection is known, with *class zero, and 1 when one
 * was found, with *at and *family naming the IP header it was found for --
 * the one a remark rewrites.
 *
 * An IP-in-IP frame is classified by the connection it carries first. That is
 * the connection the hardware entry of an offloaded 6in4 or 4in6 flow was
 * built from and carries the class of, so its software frames take the same
 * one; the tunnel's own conntrack describes only the outer header, and counts
 * only when the carried connection is not known.
 *
 * The classifier is the adapter's text, so the pointer and the calls share a
 * read-side section taken here: the unregister's grace period waits for it
 * whatever context the frame arrived in. */
static int cdx_htb_frame_class(const struct sk_buff *skb,
			       const struct cdx_htb_frame *f, u32 *class,
			       unsigned int *at, u8 *family)
{
	cdx_ft_qos_class_fn classify;
	int found = -1;

	*class = 0;
	rcu_read_lock();
	classify = READ_ONCE(cdx_ft_qos_class_func);
	if (!classify)
		goto out;
	found = 1;
	if (f->inner_family && classify(skb, f->inner, f->inner_family, false, class)) {
		*at = f->inner;
		*family = f->inner_family;
		goto out;
	}
	if (classify(skb, f->nh, f->family, true, class)) {
		*at = f->nh;
		*family = f->family;
		goto out;
	}
	*class = 0;
	found = 0;
out:
	rcu_read_unlock();
	return found;
}

/* The class a datagram's first fragment was found, for its later fragments.
 *
 * A later fragment carries no transport header, so no connection can be found
 * for it by its tuple. Where the conntrack survived to the port every fragment
 * carries it -- ip_do_fragment() copies it to each -- but a scrub on the way,
 * PPPoE's among them, drops it from all of them, and the later fragments would
 * then take a different queue from the first: reordered, and starved whenever
 * that class is not. So the first fragment's answer is kept for the others.
 *
 * A datagram's fragments leave one after another from the CPU that made them
 * -- on the stock path a PPPoE session has no qdisc of its own, and ppp drains
 * its queue under its own lock -- so a handful of entries per CPU covers every
 * datagram in flight there. A qdisc on the ppp device can let another CPU send
 * the later fragments; they then find nothing here and go unclassified, which
 * is where they went before. An entry is one datagram: a first fragment
 * replaces whatever an earlier datagram with the same identity left, and the
 * last fragment retires it, so a reused IP ID cannot inherit a stale class. */
#define CDX_HTB_DATAGRAMS	4
struct cdx_htb_datagram_class {
	struct cdx_htb_datagram datagram;
	u32 class;
	/* The class was found for the fragment's own header, which each later
	 * fragment repeats and a remark rewrites; not for one the first
	 * fragment carried, which the later ones do not hold. */
	bool own;
	bool valid;
};
struct cdx_htb_datagrams {
	struct cdx_htb_datagram_class entry[CDX_HTB_DATAGRAMS];
	unsigned int next;
};
static DEFINE_PER_CPU(struct cdx_htb_datagrams, cdx_htb_datagrams);

static bool cdx_htb_same_datagram(const struct cdx_htb_datagram *a,
				  const struct cdx_htb_datagram *b)
{
	return a->family == b->family && a->proto == b->proto && a->id == b->id &&
	       !memcmp(a->saddr, b->saddr, sizeof(a->saddr)) &&
	       !memcmp(a->daddr, b->daddr, sizeof(a->daddr));
}

static int cdx_htb_fragment_class(const struct cdx_htb_frame *f, int found,
				  u32 *class, unsigned int *at, u8 *family)
{
	struct cdx_htb_datagram_class *entry = NULL;
	struct cdx_htb_datagrams *cache;
	unsigned long flags;
	unsigned int ii;

	if (!f->fragment || found < 0 || (f->later && found))
		return found;
	/* Interrupts off rather than only preemption: this runs with bottom
	 * halves enabled from AF_PACKET's qdisc bypass and with interrupts off
	 * from netpoll, and neither a softirq nor netpoll may meet an entry
	 * half written on this CPU. */
	local_irq_save(flags);
	cache = this_cpu_ptr(&cdx_htb_datagrams);
	for (ii = 0; ii < CDX_HTB_DATAGRAMS && !entry; ii++)
		if (cache->entry[ii].valid &&
		    cdx_htb_same_datagram(&cache->entry[ii].datagram, &f->datagram))
			entry = &cache->entry[ii];
	if (!f->later) {
		if (found) {
			if (!entry)
				entry = &cache->entry[cache->next++ % CDX_HTB_DATAGRAMS];
			entry->datagram = f->datagram;
			entry->class = *class;
			entry->own = *at == f->nh;
			entry->valid = true;
		} else if (entry) {
			entry->valid = false;
		}
	} else if (entry) {
		*class = entry->class;
		*at = f->nh;
		*family = entry->own ? f->family : 0;
		found = 1;
		if (f->last)
			entry->valid = false;
	}
	local_irq_restore(flags);
	return found;
}

/* The class queue a DSCP filter names for this frame, as a leaf slot.
 *
 * Only reached when the frame named no class of its own, which is the same
 * precedence the hardware applies: an entry whose mark carries a class does not
 * get the microcode's DSCP bit set either. The codepoint is read from the
 * innermost IP header -- behind any tag or session header, and inside an
 * IP-in-IP frame the carried packet's -- which is the one its sender set, and
 * the one the hardware parsed the flow by at its ingress. The answer comes from
 * the table the filter published, so software and hardware resolve one filter
 * rather than agreeing twice. */
static u8 cdx_htb_dscp_slot(struct cdx_htb_port *port, const struct sk_buff *skb,
			    const struct cdx_htb_frame *f)
{
	unsigned int at = f->inner_family ? f->inner : f->nh;
	u8 family = f->inner_family ?: f->family;
	union {
		struct iphdr v4;
		struct ipv6hdr v6;
	} _hdr;
	const void *hdr;
	u16 klass;
	u8 dscp;

	if (!family)
		return CDX_HTB_NONE;
	hdr = skb_header_pointer(skb, at, family == AF_INET ? sizeof(_hdr.v4) :
				 sizeof(_hdr.v6), &_hdr);
	if (!hdr)
		return CDX_HTB_NONE;
	dscp = (family == AF_INET ? ipv4_get_dsfield(hdr) : ipv6_get_dsfield(hdr)) >> 2;
	/* Already in this file's own class encoding, because the filter
	 * resolved its classid against this tree when it was programmed. So the
	 * published map answers it exactly as it answers a conntrack mark's --
	 * no second lookup, and no walk of a list being mutated under RTNL. */
	klass = cdx_dscp_class(port->qm_ctx, dscp);
	if (!klass || klass >= CDX_HTB_CLASSES)
		return CDX_HTB_NONE;
	return READ_ONCE(port->class_txq[klass]);
}

/* A frame the hardware would remark: one it forwards by routing. The gateway's
 * own carry their socket; a frame the bridge forwards arrived for another host,
 * and routing takes only a frame addressed to this one (ip_forward() and
 * ip6_forward() drop anything else), which it leaves as PACKET_HOST -- as the
 * scrubs on the way to a session or a tunnel also do. The hardware's remark
 * rides the opcode that decrements TTL, which a bridged flow's entry does not
 * carry. */
static bool cdx_htb_routed(const struct sk_buff *skb)
{
	return !skb->sk && skb->pkt_type == PACKET_HOST;
}

/* Frames the software path found a remark class for but could not rewrite --
 * the header could not be made writable -- and so sent as they arrived rather
 * than dropped for a marking. Reported in /proc/cdx_flowtable. */
static atomic64_t cdx_htb_remark_failures = ATOMIC64_INIT(0);

u64 cdx_ft_qos_remark_failures(void)
{
	return atomic64_read(&cdx_htb_remark_failures);
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_qos_remark_failures, ASK_CDX_FLOWTABLE);

/* Rewrite the DSCP of the IP header at `at' to the codepoint its class
 * carries, keeping the two ECN bits, as the hardware rule for the same flow
 * does.
 *
 * The hardware rewrites every routed flow it carries, in the opcode that
 * decrements TTL; nothing on the software path did, so a flow changed DSCP at
 * the moment it was offloaded, and one that never was left unmarked. This is
 * the software half, and the header is the one the class was found for: the
 * packet's own, behind any tag or session header, or the one an IP-in-IP frame
 * carries, which is the flow the hardware entry is for.
 *
 * Read first, and made writable only to change it: a clone shares its head
 * with a tap, and a frame already carrying the codepoint -- a sender that sets
 * it itself -- costs no copy. The IPv4 checksum is updated with it; neither
 * family's pseudo-header includes the field, so a checksum the stack left for
 * the hardware is unaffected. */
static void cdx_htb_remark(struct sk_buff *skb, unsigned int at, u8 family, u8 dscp)
{
	unsigned int len = family == AF_INET ? sizeof(struct iphdr) : sizeof(struct ipv6hdr);
	union {
		struct iphdr v4;
		struct ipv6hdr v6;
	} _hdr;
	const void *hdr;

	hdr = skb_header_pointer(skb, at, len, &_hdr);
	if (!hdr)
		goto failed;
	if ((family == AF_INET ? ipv4_get_dsfield(hdr) : ipv6_get_dsfield(hdr)) >> 2 == dscp)
		return;
	if (skb_ensure_writable(skb, at + len))
		goto failed;
	/* Looked up again: making the head writable may have moved it. */
	if (family == AF_INET)
		ipv4_change_dsfield((struct iphdr *)(skb->data + at), INET_ECN_MASK, dscp << 2);
	else
		ipv6_change_dsfield((struct ipv6hdr *)(skb->data + at), INET_ECN_MASK, dscp << 2);
	return;
failed:
	atomic64_inc(&cdx_htb_remark_failures);
}

static u16 cdx_htb_select_queue(struct net_device *dev, struct sk_buff *skb)
{
	struct dpa_priv_s *priv = netdev_priv(dev);
	struct cdx_htb_port *port;
	struct cdx_htb_frame f;
	unsigned int at = 0;
	u8 family = 0, slot;
	bool own_link;
	u32 class;
	u16 klass;
	int found;

	port = cdx_htb_entry(priv->qm_ctx);
	if (!port)
		return DPA_SELECT_QUEUE_NONE;
	/* With no tree there is no queue to choose, and a class can only
	 * remark: when no class can, a lookup here would buy nothing. */
	if (READ_ONCE(port->top) == CDX_HTB_NONE && !READ_ONCE(cdx_ft_qos_remarks))
		return DPA_SELECT_QUEUE_NONE;
	cdx_htb_parse(skb, &f);
	found = cdx_htb_frame_class(skb, &f, &class, &at, &family);
	found = cdx_htb_fragment_class(&f, found, &class, &at, &family);
	if (found < 0)
		return DPA_SELECT_QUEUE_NONE;
	/* Only the egress nibbles index the table. The class the adapter
	 * decodes is wider than an egress destination -- it also names an
	 * ingress policer profile and a remark, neither of which has any
	 * bearing on which queue a frame leaves by -- and this table is sized
	 * for the egress class alone. */
	klass = class & CDX_FT_QOS_EGRESS_MASK;
	/* The remark before the DSCP map, so the map reads the codepoint the
	 * frame leaves with. In hardware the rewrite is an opcode of the
	 * entry's header manipulation and the map is read by the enqueue that
	 * ends it; the order here follows that one, and has to change with it
	 * if the hardware turns out to read the field first. */
	if (found && (class & CDX_FT_QOS_REMARK_MASK) && family && cdx_htb_routed(skb))
		cdx_htb_remark(skb, at, family,
			       (class & CDX_FT_QOS_DSCP_MASK) >> CDX_FT_QOS_DSCP_SHIFT);
	/* No class named, so the DSCP map gets to choose, for every frame that
	 * carries a codepoint: nothing has named a class for it otherwise. */
	if (!klass) {
		slot = cdx_htb_dscp_slot(port, skb, &f);
		if (slot != CDX_HTB_NONE)
			return CDX_HTB_QID_BASE + slot;
	}
	slot = klass ? READ_ONCE(port->class_txq[klass]) : CDX_HTB_NONE;
	/* No class known: none named, or one no leaf holds, which the hardware
	 * resolves the same way (cdx_htb_resolve_class()). It takes class zero
	 * -- the default leaf, or whichever leaf holds the top channel's class
	 * queue 0, where the flow's rule will send it -- forwarded or not,
	 * tracked or not, so a flow is on one queue before and after it is
	 * offloaded. Control traffic is the exception, and is left to
	 * cdx_htb_txq_fq(), on a direct queue: it never goes to the default
	 * leaf, which is commonly the lowest-priority one and would starve it
	 * behind any saturated class. */
	if (slot == CDX_HTB_NONE && !cdx_htb_control(skb, &f, &own_link))
		slot = READ_ONCE(port->class_txq[0]);
	if (slot == CDX_HTB_NONE)
		return DPA_SELECT_QUEUE_NONE;
	return CDX_HTB_QID_BASE + slot;
}

/* The frame queue a frame on Tx queue `txq' leaves by, or NULL when no tree is
 * live on the port and the driver's own resolution applies.
 *
 * A leaf's queue names its class queue. Any other -- a direct queue, or a leaf
 * slot that went away after the frame was put on it -- carries a frame that
 * named no leaf. Control traffic takes the top channel's control queue while
 * the port's budget lasts, and past it goes where unclassified traffic goes:
 * the default leaf, or the top channel's class queue 0. Every one of those is
 * a queue this port owns and cdx_htb_implicit_sync() keeps eligible, so while
 * the tree is live no frame is left to the driver's mark-based resolution. */
static struct qman_fq *cdx_htb_txq_fq(void *qm_ctx, u16 txq, struct sk_buff *skb)
{
	struct cdx_htb_port *port = cdx_htb_entry(qm_ctx);
	struct cdx_htb_frame f;
	bool own_link;
	u8 top, channel;
	u16 slot, pair;

	if (!port)
		return NULL;
	top = READ_ONCE(port->top);
	if (top == CDX_HTB_NONE)
		return NULL;
	if (txq >= CDX_HTB_QID_BASE) {
		slot = txq - CDX_HTB_QID_BASE;
		if (slot < CDX_HTB_MAX_LEAVES) {
			channel = READ_ONCE(port->txq_channel[slot]);
			if (channel != CDX_HTB_NONE)
				return ceetm_class_fq(qm_ctx, channel,
						      READ_ONCE(port->txq_cq[slot]));
		}
	}
	cdx_htb_parse(skb, &f);
	if (cdx_htb_control(skb, &f, &own_link) &&
	    cdx_htb_control_admit(port, skb->len, own_link))
		return ceetm_class_fq(qm_ctx, top, CDX_HTB_CONTROL_CQ);
	pair = READ_ONCE(port->unclassified);
	return ceetm_class_fq(qm_ctx, pair >> 8, pair & 0xff);
}

/* The (channel, class queue) a hardware entry on this port enqueues to for an
 * egress class, when a live tree owns the port: the class's own leaf, or where
 * unclassified traffic goes for a class no leaf holds -- the same answer the
 * software path gives the same flow. False when no tree is live, which leaves
 * the class's own reading in charge. The channel is in the mark's numbering on
 * the way in and out: zero is the top channel, anything else one-based.
 *
 * Lock-free over the published maps, like the Tx path: a change to the tree
 * retires every entry on the port, so one resolved against a map that was
 * being rebuilt is replaced. */
bool cdx_htb_resolve_class(struct tQM_context_ctl *qm_ctx, u32 *channel, u32 *cq)
{
	struct cdx_htb_port *port = cdx_htb_entry(qm_ctx);
	u8 top, slot = CDX_HTB_NONE, leaf_channel;
	u16 pair;

	if (!port)
		return false;
	top = READ_ONCE(port->top);
	if (top == CDX_HTB_NONE)
		return false;
	if (*channel <= CDX_CEETM_MAX_CHANNELS && *cq < MAX_SCHEDULER_QUEUES &&
	    (*channel || *cq))
		slot = READ_ONCE(port->class_txq[*channel << 4 | *cq]);
	if (slot != CDX_HTB_NONE && slot < CDX_HTB_MAX_LEAVES) {
		leaf_channel = READ_ONCE(port->txq_channel[slot]);
		if (leaf_channel != CDX_HTB_NONE) {
			*channel = leaf_channel + 1;
			*cq = READ_ONCE(port->txq_cq[slot]);
			return true;
		}
	}
	pair = READ_ONCE(port->unclassified);
	*channel = (pair >> 8) + 1;
	*cq = pair & 0xff;
	return true;
}

/* The counters that describe accelerated traffic, in leaf-slot order, and
 * then those of the two queues traffic that names no leaf takes: the one
 * unclassified traffic goes to, and the top channel's control queue. Either
 * may be a leaf's too, and is then reported under that leaf as well; either
 * may be a queue no leaf holds, and is then visible nowhere else.
 *
 * A slot no class holds, a queue with no tree to put it on, and a queue the
 * hardware will not answer for are left at the zero the caller already wrote:
 * ethtool asks for a fixed number of values and has to get one for each. Runs
 * under RTNL from ethtool, which is also what publishes the map, so this reads
 * a settled one. */
static_assert(DPA_CEETM_IMPLICIT_QUEUES == 2,
	      "the unclassified queue, then the control queue, after the leaves");
static void cdx_htb_class_stats(void *qm_ctx, u64 *data)
{
	struct cdx_htb_port *port = cdx_htb_entry(qm_ctx);
	unsigned int slot;
	u16 unclassified;
	u8 top;

	if (!port)
		return;
	for (slot = 0; slot < CDX_HTB_MAX_LEAVES;
	     slot++, data += DPA_CEETM_CLASS_STATS) {
		u8 channel = READ_ONCE(port->txq_channel[slot]);

		if (channel == CDX_HTB_NONE)
			continue;
		ceetm_class_counters(channel, READ_ONCE(port->txq_cq[slot]),
				     &data[0], &data[1], &data[2]);
	}
	top = READ_ONCE(port->top);
	if (top == CDX_HTB_NONE)
		return;
	unclassified = READ_ONCE(port->unclassified);
	ceetm_class_counters(unclassified >> 8, unclassified & 0xff,
			     &data[0], &data[1], &data[2]);
	data += DPA_CEETM_CLASS_STATS;
	ceetm_class_counters(top, CDX_HTB_CONTROL_CQ, &data[0], &data[1], &data[2]);
}

static const struct dpa_qdisc_ops cdx_htb_qdisc_ops = {
	.select_queue = cdx_htb_select_queue,
	.txq_fq = cdx_htb_txq_fq,
	.class_stats = cdx_htb_class_stats,
};

/* The flowtable adapter's half of the ndo.
 *
 * Only one handler can be registered with the driver, and this one is it,
 * because cdx stays loaded while the adapter can come and go. TC_SETUP_FT
 * therefore arrives here and is passed on. Netfilter chooses between this route and the adapter's indirect
 * block registration purely on whether the netdev has an ndo_setup_tc at all,
 * so a bind that arrives with nothing registered has to be refused rather than
 * quietly served by neither.
 *
 * The call runs in the adapter's text and may sleep there, and nf_tables
 * makes it without RTNL, so neither the Tx hook's RCU nor the egress hook's
 * RTNL covers it: each call runs inside cdx_ft_handler_srcu, and
 * unregistering waits them out before the adapter's module can go.
 */
static cdx_ft_setup_tc_handler cdx_ft_handler;
DEFINE_STATIC_SRCU(cdx_ft_handler_srcu);

int cdx_register_ft_setup_tc(cdx_ft_setup_tc_handler handler)
{
	if (!handler)
		return -EINVAL;
	if (cmpxchg(&cdx_ft_handler, NULL, handler))
		return -EBUSY;
	return 0;
}
EXPORT_SYMBOL_NS_GPL(cdx_register_ft_setup_tc, ASK_CDX_FLOWTABLE);

/* Returns once no bind or unbind is inside the adapter's handler, so the
 * adapter's text may go after it. Not from inside the handler, nor holding
 * anything a bind waits for. */
void cdx_unregister_ft_setup_tc(void)
{
	WRITE_ONCE(cdx_ft_handler, NULL);
	/* A call that read the handler before the store may still be inside
	 * it; the caller's module text has to outlive that call. */
	synchronize_srcu(&cdx_ft_handler_srcu);
}
EXPORT_SYMBOL_NS_GPL(cdx_unregister_ft_setup_tc, ASK_CDX_FLOWTABLE);

static int cdx_setup_tc(struct net_device *dev, enum tc_setup_type type,
			void *type_data)
{
	/* Read the handler once, inside the SRCU section the unregister waits
	 * out: it can NULL the pointer concurrently, and a call it did not wait
	 * for would run in freed module text. */
	cdx_ft_setup_tc_handler handler;
	int idx, rc;

	switch (type) {
	case TC_SETUP_QDISC_HTB:
		return cdx_htb_setup_tc(dev, type_data);
	case TC_SETUP_QDISC_RED:
		return cdx_htb_setup_red(dev, type_data);
	case TC_SETUP_ROOT_QDISC:
		/* A notification that the netdev's root qdisc changed, not a
		 * request. This driver's scheduler state comes from the HTB
		 * commands themselves, so there is nothing to do -- but
		 * answering -EOPNOTSUPP makes qdisc_offload_graft_helper()
		 * report "Offloading graft operation failed" on every
		 * successful `tc qdisc add ... htb offload`, because by then
		 * the qdisc is already flagged as offloaded. */
		return 0;
	case TC_SETUP_BLOCK: {
		/* Filters, not qdiscs, and the two directions of a clsact
		 * qdisc are two different objects: an ingress block carries the
		 * police action that programs this port's rate limiter, an
		 * egress one the DSCP map that classifies what leaves by it.
		 * Each half refuses the other's binder type, so offering both
		 * is how a clsact gets served at all. */
		struct flow_block_offload *bo = type_data;

		if (bo->binder_type == FLOW_BLOCK_BINDER_TYPE_CLSACT_EGRESS)
			return cdx_dscp_setup_block(dev, type_data);
		return cdx_police_setup_block(dev, type_data);
	}
	case TC_SETUP_FT:
		idx = srcu_read_lock(&cdx_ft_handler_srcu);
		handler = READ_ONCE(cdx_ft_handler);
		rc = handler ? handler(dev, type, type_data) : -EOPNOTSUPP;
		srcu_read_unlock(&cdx_ft_handler_srcu, idx);
		return rc;
	default:
		return -EOPNOTSUPP;
	}
}

/* The two halves TC_SETUP_BLOCK serves above, as a multicast stream the
 * classifier replicates meets them. An egress DSCP filter does exactly what
 * it does in software: every listener entry on a port whose map is published
 * reads the map per frame (cdx_dscp_mirrored()). An ingress filter never
 * does. A matchall police is the port's rate limiter, but the soft parser
 * hands that profile only unicast TCP, UDP and ESP frames: it stops parsing a
 * multicast frame at the IP header and leaves it to the classifier unmetered,
 * where the software path would police it. And flower's per-flow profiles
 * are bound to flowtable entries, which a multicast entry is not. */
bool cdx_tc_filter_mirrored(struct net_device *dev, bool ingress,
			    unsigned long cookie)
{
	return !ingress && cdx_dscp_mirrored(dev, cookie);
}
EXPORT_SYMBOL_NS_GPL(cdx_tc_filter_mirrored, ASK_CDX_FLOWTABLE);

int cdx_htb_init(void)
{
	unsigned int ii;
	int rc;

	for (ii = 0; ii < ARRAY_SIZE(cdx_htb_ports); ii++) {
		INIT_LIST_HEAD(&cdx_htb_ports[ii].classes);
		cdx_htb_publish(&cdx_htb_ports[ii]);
	}
	rc = dpa_register_qdisc_ops(&cdx_htb_qdisc_ops);
	if (rc)
		return rc;
	rc = dpa_register_setup_tc(cdx_setup_tc);
	if (rc)
		dpa_unregister_qdisc_ops();
	return rc;
}

void cdx_htb_exit(void)
{
	unsigned int ii;

	/* Stop new commands before releasing anything: the driver holds a
	 * pointer into this module's text rather than a symbol reference, so a
	 * tc command can arrive until this returns. The data path is retired
	 * the same way, and waits out the frames already inside it. */
	dpa_unregister_setup_tc();
	dpa_unregister_qdisc_ops();
	for (ii = 0; ii < ARRAY_SIZE(cdx_htb_ports); ii++) {
		/* Filters before the tree they name classes in, and from out
		 * here rather than inside cdx_htb_port_gone(), because a filter
		 * add takes the DSCP lock and then this file's. */
		cdx_dscp_port_gone(&gQMCtx[ii]);
		cdx_htb_port_gone(&gQMCtx[ii]);
	}
	/* No tree is live now, and only a live tree arms the regrow work, so
	 * once this returns nothing runs in this module's text from it. No
	 * release is due either -- each port's going forgot its own, and only
	 * a tc command arms one -- and a release still running finds nothing
	 * to give back once it has the mutex again. Waited for holding
	 * nothing: its wait on the flowtable returns at once with no adapter
	 * left, which unloads before this module. The quarantines end with the
	 * ports' contexts (ceetm_exit()). */
	cancel_delayed_work_sync(&cdx_htb_regrow);
	cancel_delayed_work_sync(&cdx_htb_release);
}
