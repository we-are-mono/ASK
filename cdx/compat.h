/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * What differs between the kernel lines ASK builds for (6.12 and 6.18), kept
 * here so the sources are written once, in the newest line's terms. Included
 * into every object by the Kbuild, ahead of the sources' own headers.
 *
 * Each difference is keyed on the release that made it upstream; the NXP SDK
 * is pinned per kernel line (lf-6.12.y with 6.12, lf-6.18.y with 6.18), so its
 * differences are keyed on the kernel line too.
 */
#ifndef CDX_COMPAT_H
#define CDX_COMPAT_H

#include <linux/version.h>
#include <linux/export.h>
#include <linux/module.h>

/* 6.13 made a symbol namespace a string literal; before it the macros
 * stringified a bare name. Written the newer way, taken the same way. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 13, 0)
#undef EXPORT_SYMBOL_NS_GPL
#define EXPORT_SYMBOL_NS_GPL(sym, ns)	__EXPORT_SYMBOL(sym, "GPL", ns)
#undef MODULE_IMPORT_NS
#define MODULE_IMPORT_NS(ns)		MODULE_INFO(import_ns, ns)
#endif

/* 6.16 handed xfrmdev_ops their device explicitly; before it the state's
 * xso.dev was the only way to it. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
#define CDX_XDO_DEV(dev)		struct net_device *dev,
#else
#define CDX_XDO_DEV(dev)
#endif

/* 6.17 renamed dev_get_port_parent_id(). */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 17, 0)
#define netif_get_port_parent_id	dev_get_port_parent_id
#endif

/* The lf-6.18 SDK tells a dequeue callback whether it may schedule its NAPI
 * and passes the portal's poll context; dpaa_eth_napi_schedule() takes the
 * former. A callback's parameter list ends in CDX_DQRR_POLL (no comma before
 * it), and schedules through cdx_napi_schedule(); under lf-6.12 `sched_napi` is
 * not a parameter, and the SDK decides from the calling context (not serving a
 * softirq) instead. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
struct qman_poll_ctx;
#define CDX_DQRR_POLL		, bool sched_napi, struct qman_poll_ctx *ctx
#define cdx_napi_schedule(percpu_priv, qm) \
	dpaa_eth_napi_schedule(percpu_priv, qm, sched_napi)
#else
#define CDX_DQRR_POLL
#define cdx_napi_schedule(percpu_priv, qm) \
	dpaa_eth_napi_schedule(percpu_priv, qm)
#endif

#endif /* CDX_COMPAT_H */
