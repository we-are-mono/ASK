/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef CDX_FLOWTABLE_H
#define CDX_FLOWTABLE_H

#include <linux/if.h>
#include <linux/types.h>

/* The `transit` parameter; see cdx_flowtable_backend.c. */
extern bool cdx_ft_transit;

struct net_device;
enum tc_setup_type;

/* Implemented by the adapter module, for a driver whose netdev offers an
 * ndo_setup_tc. Netfilter then reaches the adapter through that ndo instead of
 * through its indirect block registration, so whoever holds that ndo must route
 * TC_SETUP_FT here or hardware acceleration stops with no error.
 *
 * CDX holds it, because the driver takes one handler and CDX stays loaded
 * while the adapter can come and go; the adapter registers with CDX instead,
 * and CDX dispatches. Registration is a one-shot claim: a second caller is refused
 * rather than being allowed to displace the first. */
int cdx_ft_setup_tc(struct net_device *dev, enum tc_setup_type type, void *type_data);

typedef int (*cdx_ft_setup_tc_handler)(struct net_device *dev,
				       enum tc_setup_type type, void *type_data);
int cdx_register_ft_setup_tc(cdx_ft_setup_tc_handler handler);
void cdx_unregister_ft_setup_tc(void);

/* The adapter's own classifier, for the software Tx path: the class of the
 * connection an IP packet belongs to.
 *
 * Registered so the software path resolves a frame's class with the very
 * decode that gave the hardware rule for the same flow its class, from the
 * same conntrack mark. Unregistered, the software path expresses no opinion
 * and behaves as it did before there was a qdisc.
 *
 * nhoff is the offset from skb->data of an IPv4 or IPv6 header, as family
 * says; a family of zero means the frame's network header was not found, and
 * only a conntrack the skb carries is consulted. own says the header is the
 * frame's own, so a conntrack the skb carries describes it; a header a 6in4 or
 * 4in6 frame carries is not, and only a lookup finds its connection. The
 * conntrack is looked for when a scrub took it -- ppp_start_xmit() and the IP
 * tunnels drop it, and the ingress index with it -- because cdx sees the frame
 * only at the port, after those.
 *
 * True with *class set when a connection was found, false otherwise with
 * *class untouched. Never sleeps: called inside rcu_read_lock() from whatever
 * context the frame is sent from, interrupts off included (netpoll). */
struct sk_buff;
typedef bool (*cdx_ft_qos_class_fn)(const struct sk_buff *skb, unsigned int nhoff,
				    u8 family, bool own, u32 *class);
/* `remarks' says whether any class the classifier can decode carries a
 * remark; without one, a port with no tree does not ask it about any frame. */
int cdx_register_ft_qos_class(cdx_ft_qos_class_fn fn, bool remarks);
void cdx_unregister_ft_qos_class(void);

/* Forwarded frames the software path could not remark as their class asks --
 * sent unchanged -- for the adapter's status to report. */
u64 cdx_ft_qos_remark_failures(void);

/* Control frames sent as unclassified traffic because their port's control
 * budget was spent, summed over every port, for the adapter's status. */
u64 cdx_ft_qos_control_overruns(void);

/* What the hardware qdisc has to give and what of it is held, for the
 * adapter's status.
 *
 * cdx_qos_budget() takes no sleeping lock: it reads a snapshot cdx keeps of
 * the channels and leaves as they change, retried should a write overlap it,
 * and the policer pool's counts under the pool's spinlock -- so the status
 * read, which the controller's health probe and drain wait read, never waits
 * for a tc command or a release. From process context, holding any lock or
 * none. Its answer is one moment's, but for the quarantine a port's context
 * being released ends: cdx follows that in the snapshot once the release is
 * done (cdx_htb_port_released()).
 *
 * cdx_qos_port_next() takes cdx_htb_mutex and, inside it, the policer pool's
 * spinlock and nothing else, so it sleeps, and may be made holding RTNL, the
 * control mutex -- the flowtable's transaction -- or neither: wherever one of
 * those and that mutex are both taken, that mutex is taken last, and nothing
 * holding it waits for either (cdx_htb.c). Never from atomic context. Each
 * answer is one moment's, with the same exception for a context's release,
 * which happens under the control mutex rather than cdx_htb_mutex: asked under
 * the transaction, there is none.
 *
 * The SoC's CEETM channels: how many the device tree gave (`channels'), how
 * many are mapped to a port for its tree (`channels_used'), and how many no
 * tree may claim yet (`channels_held'): quarantined for a port whose tree
 * went, until its flowtable entries are retired or rebuilt, or out of service
 * for good after a drain failed. The rest are free. The FMan's pool of
 * ingress policer profiles a flower filter on any port draws from
 * (`policers'), and how many of them are spoken for (`policers_used'): by a
 * filter, or held for the flows a departed filter's profile still meters. And
 * how many leaf classes a tree may have on a port (`leaves'). */
struct cdx_qos_budget {
	u32 channels, channels_used, channels_held;
	u32 policers, policers_used;
	u32 leaves;
};
void cdx_qos_budget(struct cdx_qos_budget *b);

/* One port's: its name and index (`name', `ifindex'), read where cdx knows
 * its netdev to be there; whether a tree is live on it (`tree'); the channels
 * its tree claimed, as a bitmap by channel number (`channels'), and how many
 * of those no class holds (`spare'), which its next class under the root
 * takes before it claims another; the channels quarantined for it after its
 * last tree went (`held', a bitmap); its leaf classes (`leaves'); and the
 * pool's profiles its flower filters hold (`policers'). */
struct cdx_qos_port {
	char name[IFNAMSIZ];
	int ifindex;
	u32 channels;
	u32 spare;
	u32 held;
	u32 leaves;
	u32 policers;
	bool tree;
};

/* One class of a port's tree, with the hardware it got: what a consumer
 * composes the mark that selects the class from, whose channel field is
 * `channel' + 1 and whose queue field is `queue' (cdx_flowtable_backend.h). A
 * class directly under the qdisc holds a channel; one with children is only
 * that (`inner'), with no class queue or leaf slot of its own. A leaf's slot
 * is its Tx queue's index above the direct queues, which its ethtool counters
 * are named by. A leaf's depth is the tail drop its class queue runs now, in
 * frames: what the cap gave it of its tree's budget, which may be less than
 * the class asked for -- zero for an inner class, and for a leaf whose class
 * queue the hardware layer cannot report. */
#define CDX_QOS_NONE	0xff
struct cdx_qos_class {
	u32 classid;	/* the tc handle, major:minor */
	u16 parent;	/* its parent's minor; zero under the qdisc */
	u8 channel;	/* the CEETM channel */
	u8 queue;	/* its class queue on that channel, or CDX_QOS_NONE */
	u8 slot;	/* its leaf slot, or CDX_QOS_NONE */
	bool inner;
	u32 depth;	/* its class queue's tail drop in frames, or zero */
};

/* Every port of cdx's in turn, for a reader that holds none of their netdevs
 * -- the adapter's procfs, which takes no RTNL to look one up. The first port
 * at or after `*index', which is set to it, and what it has in `p'. With
 * `classes' not NULL, every class of its tree too, in the order they were
 * made, written there: how many is returned, none for a port with no tree and
 * never more than `leaves' + `channels' of struct cdx_qos_budget, or -ENOSPC
 * when they do not fit in `max'. Zero without. -ENOENT when no port is left.
 * One call is one moment's; the walk is not, so a port made or gone between
 * two calls is listed or not. Walked as
 *
 *	for (ii = 0; (n = cdx_qos_port_next(&ii, &p, NULL, 0)) >= 0; ii++)
 */
int cdx_qos_port_next(unsigned int *index, struct cdx_qos_port *p,
		      struct cdx_qos_class *classes, unsigned int max);

/* A port's egress changed under the entries that transmit on it.
 *
 * Every hardware entry names the frame queue it enqueues to, chosen once, at
 * install, from the port's scheduling mode at that moment (cdx_get_txfqid()),
 * and whether the microcode's DSCP map picks the queue instead. An HTB tree
 * switches the port to CEETM at its first leaf and back when it goes, a class
 * change moves or removes the queue a class names, and a DSCP filter turns the
 * map on or off for the port. Nothing drains the queues of the mode the port
 * has left, so an entry installed before the change sends everything into a
 * queue nothing dequeues, and its classifier hits keep the flow alive while it
 * does. The adapter registers these to re-install everything on the port.
 *
 * changed() marks every flow entry, outbound SA and multicast group
 * replicating to the port for re-installation; the re-installation itself is
 * the adapter's queued work. It may sleep, and relies on no lock of the
 * caller's. Both callers hold RTNL today -- an HTB command always, and a DSCP
 * filter because its block callback is not registered unlocked, so tc takes
 * RTNL around it -- but neither op needs it.
 *
 * drain(dev) sleeps until everything changed(dev) started has finished, or
 * reports -EAGAIN when it cannot say so yet: before CDX hands the DSCP map to
 * another port, no entry installed while this one held it may still read it.
 * It takes the control mutex, so it is never called with it held. It never
 * waits for RTNL: a multicast group whose rebuild is still due is rebuilt by
 * drain() itself rather than waited for, since the learners' workers take
 * RTNL.
 *
 * restarted() says the datapath has restarted after a latch (cdx_ft_fatal()):
 * every port runs on the classifier again and admission is open. While the
 * classifier was out of the datapath, flows were declined, multicast groups and
 * SA rebuilds refused, and parked bindings held back; this asks for all of it
 * again. Called once per restart, with no lock of CDX's held. It may sleep.
 *
 * Registration is a one-shot claim, and unregistration waits out every call
 * already inside any op, so the module that registered can go once it
 * returns. */
struct cdx_ft_egress_ops {
	void (*changed)(struct net_device *dev);
	int (*drain)(struct net_device *dev);
	void (*restarted)(void);
};
int cdx_register_ft_egress(const struct cdx_ft_egress_ops *ops);
void cdx_unregister_ft_egress(void);

/* Whether the tc filter offloaded to `dev' under `cookie', on its ingress or
 * its egress, is one the hardware applies as it is to every frame of a
 * multicast stream the classifier replicates through the port, so that the
 * stream fares in hardware as it would through the software path that runs
 * the filter. For the routed multicast learner, which keeps a group in
 * software while any other filter runs there. Lock-free and never sleeps:
 * called from a classifier's walk, under RTNL. */
bool cdx_tc_filter_mirrored(struct net_device *dev, bool ingress,
			    unsigned long cookie);

int cdx_flowtable_guard_init(void);
void cdx_flowtable_guard_exit(void);
void cdx_flowtable_quiesced(void);
/* Cancel the work cdx_ft_fatal() schedules, which takes the classifier out of
 * the datapath and gives it back; unload only, unlocked. */
void cdx_ft_fatal_stop(void);
/* Datapath restarts so far, counted from one: a hold taken in one epoch on
 * behalf of a possibly linked classifier key is released by the restart that
 * ends it. Caller holds the control mutex. */
u32 cdx_ft_epoch(void);
/* Once claimed, adapter detach must never reopen configuration mutation. */

#endif
