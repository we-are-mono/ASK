/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef CDX_HTB_H
#define CDX_HTB_H

struct tQM_context_ctl;

/* Claim the netdev's ndo_setup_tc and start serving TC_SETUP_QDISC_HTB.
 * cdx owns the registration because CEETM is cdx's, and because cdx is loaded
 * in both ownership modes while the flowtable adapter is loaded in one. */
int cdx_htb_init(void);
void cdx_htb_exit(void);

/* Drop a port's qdisc state without touching hardware, for a caller that is
 * already tearing the interface's CEETM context down. */
void cdx_htb_port_gone(struct tQM_context_ctl *qm_ctx);

#endif /* CDX_HTB_H */
