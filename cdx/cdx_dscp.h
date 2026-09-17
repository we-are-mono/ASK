/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2026 Mono
 *
 * Egress classification by DSCP. The driver's single ndo_setup_tc dispatches a
 * clsact egress block here; see cdx_dscp.c for what the block accepts.
 */

#ifndef _CDX_DSCP_H_
#define _CDX_DSCP_H_

#include <linux/types.h>

struct net_device;
struct flow_block_offload;
struct tQM_context_ctl;

int cdx_dscp_setup_block(struct net_device *dev, struct flow_block_offload *f);

/* The hardware qdisc changed shape on this port, so every DSCP filter naming a
 * class in it has to be resolved again. Called from the HTB commands after the
 * tree has settled, and a no-op when the port holds no filters. */
void cdx_dscp_tree_changed(struct net_device *dev);

/* The class a DSCP names on this port, in the encoding the qdisc's own
 * published class map is indexed by -- (channel + 1) << 4 | class queue -- or
 * zero for none. For the software Tx path, which asks about a frame that named
 * no class of its own, so that both paths answer from the same filter.
 * Lock-free: reads a plain array republished under the lock after every
 * change. */
u16 cdx_dscp_class(struct tQM_context_ctl *qm_ctx, u8 dscp);

/* Forget a port's filters without touching hardware, for a caller already
 * tearing that interface's CEETM context down. Must be called before
 * cdx_htb_port_gone() rather than from inside it: a filter add takes this
 * file's lock and then the qdisc's, so the reverse order deadlocks. */
void cdx_dscp_port_gone(struct tQM_context_ctl *qm_ctx);

#endif /* _CDX_DSCP_H_ */
