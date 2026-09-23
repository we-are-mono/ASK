/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef CDX_HTB_H
#define CDX_HTB_H

#include <linux/types.h>

struct tQM_context_ctl;
struct net_device;
struct netlink_ext_ack;

/* Claim the netdev's ndo_setup_tc and start serving TC_SETUP_QDISC_HTB.
 * cdx owns the registration because CEETM is cdx's, and because cdx stays
 * loaded while the flowtable adapter can come and go. */
int cdx_htb_init(void);
void cdx_htb_exit(void);

/* Drop a port's qdisc state without touching hardware, for a caller that is
 * already tearing the interface's CEETM context down. */
void cdx_htb_port_gone(struct tQM_context_ctl *qm_ctx);

/* The CEETM channel and class queue a leaf class names, for a filter that
 * wants to send something to it. `classid' is a whole tc handle, as an
 * operator writes it; an inner class or an unknown one is an error rather than
 * a queue. Takes this file's lock, so a caller holding its own must be
 * prepared for that order and not the reverse. */
int cdx_htb_class_queue(struct net_device *dev, u32 classid, u8 *channel, u8 *cq,
			struct netlink_ext_ack *extack);

/* What an egress class means on a port a hardware qdisc owns, for the
 * hardware path: the class's leaf, or where unclassified traffic goes for a
 * class no leaf holds, so that a flow's rule agrees with its software frames.
 * `channel' and `cq' are in a conntrack mark's numbering, in and out. Returns
 * false, leaving them alone, on a port with no live tree. Lock-free. */
bool cdx_htb_resolve_class(struct tQM_context_ctl *qm_ctx, u32 *channel, u32 *cq);

/* The flowtable adapter's egress hook, for CDX's own callers; see struct
 * cdx_ft_egress_ops. The first never sleeps and needs no lock; the second
 * sleeps, and must not be called holding a lock the adapter's retirement work
 * takes -- the control mutex above all. */
void cdx_ft_egress_changed(struct net_device *dev);
int cdx_ft_egress_drain(struct net_device *dev);

#endif /* CDX_HTB_H */
