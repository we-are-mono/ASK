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

/* The adapter's own classifier: a conntrack mark in, an egress class out.
 *
 * Registered so the software Tx path resolves a frame's class with the very
 * function that decided the class of the hardware rule for the same flow.
 * Deriving it twice from the same mark would still be two decodes to keep in
 * step; this is one. Unregistered, the software path expresses no opinion and
 * behaves as it did before there was a qdisc. */
typedef u32 (*cdx_ft_qos_class_fn)(u32 mark);
int cdx_register_ft_qos_class(cdx_ft_qos_class_fn fn);
void cdx_unregister_ft_qos_class(void);

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
 * changed() marks every flow entry and outbound SA on the port for
 * re-installation and returns without sleeping; the re-installation itself is
 * the adapter's queued work. Multicast replicas are not covered.
 * It relies on no lock of the caller's. Both callers hold RTNL today -- an HTB
 * command always, and a DSCP filter because its block callback is not
 * registered unlocked, so tc takes RTNL around it -- but neither op needs it.
 *
 * drain(dev) sleeps until everything changed(dev) started has finished, or
 * reports -EAGAIN when it cannot say so yet: before CDX hands the DSCP map to
 * another port, no entry installed while this one held it may still read it.
 * It takes the control mutex, so it is never called with it held.
 *
 * Registration is a one-shot claim, and unregistration waits out every call
 * already inside either op, so the module that registered can go once it
 * returns. */
struct cdx_ft_egress_ops {
	void (*changed)(struct net_device *dev);
	int (*drain)(struct net_device *dev);
};
int cdx_register_ft_egress(const struct cdx_ft_egress_ops *ops);
void cdx_unregister_ft_egress(void);

int cdx_flowtable_guard_init(void);
void cdx_flowtable_guard_exit(void);
void cdx_flowtable_quiesced(void);
/* Once claimed, adapter detach must never reopen configuration mutation. */
bool cdx_flowtable_config_sealed(void);

#endif
