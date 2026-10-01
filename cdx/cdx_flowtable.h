/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef CDX_FLOWTABLE_H
#define CDX_FLOWTABLE_H

#include <linux/types.h>

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
 * every port runs again and admission is open. While it was stopped, flows
 * were declined, multicast groups and SA rebuilds refused, and parked bindings
 * held back; this asks for all of it again. Called once per restart, with no
 * lock of CDX's held. It may sleep.
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
/* Cancel the work cdx_ft_fatal() schedules, which stops the ports and restarts
 * them; unload only, unlocked. */
void cdx_ft_fatal_stop(void);
/* Datapath restarts so far, counted from one: a hold taken in one epoch on
 * behalf of a possibly linked classifier key is released by the restart that
 * ends it. Caller holds the control mutex. */
u32 cdx_ft_epoch(void);
/* Once claimed, adapter detach must never reopen configuration mutation. */
bool cdx_flowtable_config_sealed(void);

#endif
