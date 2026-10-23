/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef CDX_DETOUR_H
#define CDX_DETOUR_H

#include <linux/types.h>

/* The stage of a direction's detour through the offline port (A385): the
 * entry on the offline port that does the direction's work, and the one on its
 * receive port that hands its frames to it. */
#define CDX_DETOUR_NONE		0
#define CDX_DETOUR_OFFLINE	1
#define CDX_DETOUR_REDIRECT	2

struct cdx_ft_rule;
struct cdx_detour_flow;

/* For /proc/ask_flowtable: the directions recorded, and what the offline port
 * handed back -- given to Linux, with no direction to give it to, not copied,
 * or on the port's error queue. */
struct cdx_detour_counters {
	u64 flows;
	u64 delivered;
	u64 unknown;
	u64 failed;
	u64 errors;
};

int cdx_detour_init(void);
bool cdx_ft_detour_ready(void);
u32 cdx_detour_fqid(void);
u32 cdx_detour_portid(void);
int cdx_detour_flow_add(const struct cdx_ft_rule *rule, struct cdx_detour_flow **flow);
void cdx_detour_flow_del(struct cdx_detour_flow *flow);
void cdx_detour_counters(struct cdx_detour_counters *counters);
#ifdef CDX_DEBUG_FLOWTABLE
extern bool cdx_detour_strand;
int cdx_detour_exception_placement(u16 *channel, u8 *wq);
#endif

#endif
