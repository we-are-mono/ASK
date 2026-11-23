/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * What differs between the kernel lines ASK builds for (6.12 and 6.18), kept
 * here so the sources are written once, in the newest line's terms. Included
 * into every object by the Kbuild, ahead of the sources' own headers.
 *
 * Each difference is keyed on the release that made it upstream. The NXP SDK
 * is one copy for every line (sdk/linux), so its API does not differ between
 * them.
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

#endif /* CDX_COMPAT_H */
