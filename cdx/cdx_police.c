// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2026 Mono Technologies Inc.
 *
 * Ingress policing as a tc verb.
 *
 * The FMAN meters ingress traffic with RFC-2698 policer profiles, which only
 * CMM's control plane used to set. tc already has the vocabulary:
 *
 *	tc qdisc  add dev eth4 clsact
 *	tc filter add dev eth4 ingress matchall \
 *	    action police rate 500mbit burst 64k conform-exceed drop
 *
 * and the mapping is close to exact. flow_action_entry.police carries
 * rate_bytes_ps, peakrate_bytes_ps, burst and an exceed/notexceed pair; the
 * profile takes CIR, PIR, CBS and an action per colour. Only the unit differs:
 * the kernel counts bytes per second, the FMD's byte mode counts Kbit/s.
 *
 * Two halves. `matchall` is the port-wide one and needs no correlation with
 * anything: the filter's scope and the port profile's scope are the same set
 * of frames. `flower` matches a subset, so it reaches the seven per-flow
 * profiles instead and has to bind them to flows the flowtable admitted --
 * which is the whole of the second half below.
 *
 * Both report what they metered. The profile counts frames per colour and has
 * no byte counter, so tc is told frames and drops and nothing else.
 */

#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <net/flow_offload.h>
#include <net/pkt_cls.h>
#include <linux/jiffies.h>
#include <linux/spinlock.h>
#include "cdx.h"
#include "misc.h"
#include "cdx_ioctl.h"
#include "cdx_common.h"
#include "cdx_flowtable_backend.h"
#include "cdx_police.h"

/* Bytes per second as tc counts them, to the Kbit/s the profile is programmed
 * in. The FMD multiplies by 1000 on its way to bits, so this is the inverse of
 * what GetInfoRateReg() will do.
 *
 * Rounding down is deliberate: a policer that runs slightly under the rate the
 * operator asked for is honest, one that runs over is not.
 */
static u32 cdx_police_bytes_to_kbits(u64 bytes_ps)
{
	return (u32)div_u64(bytes_ps * 8, 1000);
}

/* A peak rate no port can approach, in Kbit/s: 100 Gbit/s, ten times the
 * fastest port. A bucket refilled at it is full again before the next frame
 * has finished arriving, so it holds back only a frame longer than itself.
 * Each profile meters one port's arrivals (a matchall is the port's own, a
 * flower profile is bound only to flows arriving on its filter's port), so no
 * second port can crowd it. The profile shares one fixed-point scale between
 * its two rates, sized to the larger; a committed rate of 1 Mbit/s still keeps
 * fifteen significant bits, which a faster peak would start to spend. */
#define CDX_POLICE_UNBOUNDED_KBITS	100000000U

/* Refuse anything the profile cannot express, rather than programming a meter
 * that differs from the one described. Everything here is a property of the
 * action, so it can be judged before any hardware is touched. */
static int cdx_police_check(const struct flow_action_entry *act,
			    struct netlink_ext_ack *extack)
{
	if (act->police.rate_bytes_ps && act->police.rate_pkt_ps) {
		NL_SET_ERR_MSG_MOD(extack, "police: byte and packet rates are exclusive");
		return -EOPNOTSUPP;
	}
	if (!act->police.rate_bytes_ps && !act->police.rate_pkt_ps) {
		NL_SET_ERR_MSG_MOD(extack, "police: a rate is required");
		return -EOPNOTSUPP;
	}
	/* Under tc the profile passes green on to the parser and drops yellow
	 * and red. It has no way to express any other pairing. */
	if (act->police.exceed.act_id != FLOW_ACTION_DROP) {
		NL_SET_ERR_MSG_MOD(extack, "police: exceed action must be drop");
		return -EOPNOTSUPP;
	}
	if (act->police.notexceed.act_id != FLOW_ACTION_ACCEPT &&
	    act->police.notexceed.act_id != FLOW_ACTION_PIPE) {
		NL_SET_ERR_MSG_MOD(extack, "police: conform action must be accept or pipe");
		return -EOPNOTSUPP;
	}
	/* avrate is a moving average the hardware does not keep, and silently
	 * ignoring it would police by a different rule than the one asked for. */
	if (act->police.avrate) {
		NL_SET_ERR_MSG_MOD(extack, "police: avrate is not supported");
		return -EOPNOTSUPP;
	}
	/* A packet-rate profile's buckets count frames, so neither can stand
	 * in for Linux's frame-length check; only the unlimited default, which
	 * tc gives a packet rate without an mtu, has nothing to check. */
	if (act->police.rate_pkt_ps && act->police.mtu != U32_MAX) {
		NL_SET_ERR_MSG_MOD(extack, "police: an mtu needs a byte rate");
		return -EOPNOTSUPP;
	}
	return 0;
}

/* The action's rates in the profile's own units. Byte mode is Kbit/s, packet
 * mode is packets per second; the two are never mixed, which cdx_police_check()
 * has already established. */
static int cdx_police_rates(const struct flow_action_entry *act,
			    struct netlink_ext_ack *extack, bool *byte_mode,
			    u32 *cir, u32 *pir, u32 *cbs, u32 *pbs)
{
	*byte_mode = act->police.rate_bytes_ps != 0;
	if (*byte_mode) {
		*cir = cdx_police_bytes_to_kbits(act->police.rate_bytes_ps);
		*cbs = act->police.burst;
		/* Linux passes a frame only when it fits both of its buckets --
		 * the rate's, `burst` deep, and the peak rate's, `mtu` deep --
		 * and treats a frame longer than `mtu` as exceeding whatever
		 * the buckets hold (tcf_police_act()). The profile drops yellow
		 * for tc (cdx_port_police_set()), so its green is that same
		 * rule: the committed bucket is the rate's, and the peak bucket
		 * at the peak rate does the length check as well, so it is as
		 * deep as the longest frame `mtu` lets through (below) -- 14
		 * bytes shallower than Linux's. With no peak rate it does the
		 * length check alone, refilled far faster than any port can
		 * drain it, so only a frame longer than it misses. */
		*pir = act->police.peakrate_bytes_ps ?
			cdx_police_bytes_to_kbits(act->police.peakrate_bytes_ps) :
			CDX_POLICE_UNBOUNDED_KBITS;
		/* A tc profile counts the frame from its IP header on
		 * (cdx_plcr_lengths()), what Linux charges the rate, while
		 * Linux's length check adds the 14-byte Ethernet header back:
		 * tc ingress has already moved a VLAN tag out of the frame. A
		 * second tag (QinQ) or a PPPoE session header stays in Linux's
		 * count and not in the profile's, which is that much more
		 * lenient. An mtu no frame fits keeps a bucket nothing fits. */
		*pbs = act->police.mtu > ETH_HLEN ? act->police.mtu - ETH_HLEN : 1;
	} else {
		*cir = (u32)act->police.rate_pkt_ps;
		*pir = *cir;
		*cbs = (u32)act->police.burst_pkt;
		*pbs = *cbs;
	}
	if (*pir < *cir) {
		NL_SET_ERR_MSG_MOD(extack, "police: peakrate must be at least rate");
		return -EOPNOTSUPP;
	}
	if (!*cir) {
		NL_SET_ERR_MSG_MOD(extack, "police: rate rounds to zero at this profile's resolution");
		return -EOPNOTSUPP;
	}
	return 0;
}

/* ---- what a filter can say about what it metered ------------------------
 *
 * The profile counts frames per colour and nothing else: there is no byte
 * counter anywhere in it. So tc is told how many frames the meter saw and how
 * many it dropped, and zero bytes. Deriving a byte count from an assumed frame
 * size would be an invention, and refusing statistics altogether would lose
 * the drop count -- which is the number an operator sizing a policer is
 * actually looking for, and one no software counter can supply for a flow that
 * never reaches the CPU.
 *
 * tc adds up what a driver reports and the hardware counters are free-running
 * totals, so every filter keeps the values it last read and reports the
 * difference.
 */

/* Guards both lists below. Taken from the flowtable's admission path through
 * cdx_police_lookup(), so it stays a spinlock; the counter reads are done
 * outside it, because they reach the FMD's host-command path and busy-wait
 * there. */
static DEFINE_SPINLOCK(cdx_police_lock);

/* A matchall filter is the port's own rate limiter rather than one of the
 * numbered per-flow profiles, so it is kept apart from them: none of it
 * reaches cdx_police_lookup(), and its counters come from a different handle.
 * The record exists to give the filter somewhere to keep its baseline. */
struct cdx_police_port {
	struct list_head		list;
	struct net_device		*dev;
	unsigned long			cookie;
	struct cdx_police_counters	base;
};

static LIST_HEAD(cdx_police_ports);

/* One counter's delta. A counter that has gone backwards was reset
 * underneath the filter rather than having wrapped, so the value it now holds
 * is the whole of the delta. Reading it as a 32-bit wrap
 * instead would credit a filter with most of four billion frames to cover a
 * sample nobody missed, which is a far worse answer than losing one wrap's
 * worth of counting. */
static u32 cdx_police_delta(u32 *last, u32 now)
{
	u32 delta = now >= *last ? now - *last : now;

	*last = now;
	return delta;
}

/* Green is enqueued, yellow and red are dropped, because a tc profile programs
 * e_FM_PCD_PLCR_DROP_FRAME on both. Every frame the meter saw is therefore the
 * sum of the three, and the dropped ones are the yellow and the red ones. */
static void cdx_police_report(struct flow_stats *stats,
			      struct cdx_police_counters *base,
			      const struct cdx_police_counters *now)
{
	u64 green = cdx_police_delta(&base->green, now->green);
	u64 drops = cdx_police_delta(&base->yellow, now->yellow) +
		    cdx_police_delta(&base->red, now->red);

	/* lastused is offered only when something moved. flow_stats_update()
	 * keeps the later of what it holds and what it is given, so a quiet
	 * filter has nothing to contribute and must not claim the present
	 * moment as a time it was used. */
	flow_stats_update(stats, 0, green + drops, drops,
			  green + drops ? jiffies : 0,
			  FLOW_ACTION_HW_STATS_IMMEDIATE);
}

/* Both finders run under cdx_police_lock. */
static struct cdx_police_port *cdx_police_port_find(struct net_device *dev,
						    unsigned long cookie)
{
	struct cdx_police_port *port;

	list_for_each_entry(port, &cdx_police_ports, list)
		if (port->dev == dev && port->cookie == cookie)
			return port;
	return NULL;
}

static int cdx_police_replace(struct net_device *dev,
			      struct tc_cls_matchall_offload *f)
{
	struct netlink_ext_ack *extack = f->common.extack;
	struct flow_action *action = &f->rule->action;
	const struct flow_action_entry *act;
	struct cdx_police_port *port;
	u32 cir, pir, cbs, pbs;
	unsigned long flags;
	bool byte_mode;
	int rc;

	if (!flow_offload_has_one_action(action)) {
		NL_SET_ERR_MSG_MOD(extack, "matchall: exactly one action is supported");
		return -EOPNOTSUPP;
	}
	act = &action->entries[0];
	if (act->id != FLOW_ACTION_POLICE) {
		NL_SET_ERR_MSG_MOD(extack, "matchall: only police is supported");
		return -EOPNOTSUPP;
	}
	rc = cdx_police_check(act, extack);
	if (rc)
		return rc;

	rc = cdx_police_rates(act, extack, &byte_mode, &cir, &pir, &cbs, &pbs);
	if (rc)
		return rc;

	/* A port has one rate limiter. A second matchall would program over the
	 * first's meter, and deleting either would return the port to its boot
	 * rate under the other, which tc would still show as in hardware. tc
	 * offers matchall filters under RTNL, so nothing lands in between. */
	spin_lock_irqsave(&cdx_police_lock, flags);
	list_for_each_entry(port, &cdx_police_ports, list) {
		if (port->dev == dev && port->cookie != f->cookie) {
			spin_unlock_irqrestore(&cdx_police_lock, flags);
			NL_SET_ERR_MSG_MOD(extack, "matchall: the port's rate limiter already has a police filter");
			return -EOPNOTSUPP;
		}
	}
	spin_unlock_irqrestore(&cdx_police_lock, flags);

	/* Allocated before the hardware is touched so a failure to program the
	 * port leaves nothing behind to unwind. */
	port = kzalloc(sizeof(*port), GFP_KERNEL);
	if (!port)
		return -ENOMEM;
	port->dev = dev;
	port->cookie = f->cookie;

	if (cdx_port_police_set(dev->name, byte_mode, cir, pir, cbs, pbs) != SUCCESS) {
		kfree(port);
		NL_SET_ERR_MSG_MOD(extack, "police: the port has no rate limiter");
		return -EINVAL;
	}

	/* The port's limiter has been counting since the port came up, so a new
	 * filter starts from where the hardware is now. Without this its first
	 * report would credit it with every frame the port ever metered. A read
	 * that fails leaves the baseline at zero, which is the same answer as
	 * one taken before any traffic. */
	cdx_port_police_counters(dev->name, &port->base);

	/* tc replays a filter onto a block callback that binds after it, so the
	 * same cookie can arrive twice. The second time reprograms the port and
	 * keeps the record already there: the hardware counters did not
	 * restart, so neither may the baseline. */
	spin_lock_irqsave(&cdx_police_lock, flags);
	if (cdx_police_port_find(dev, f->cookie)) {
		spin_unlock_irqrestore(&cdx_police_lock, flags);
		kfree(port);
		return 0;
	}
	list_add_tail(&port->list, &cdx_police_ports);
	spin_unlock_irqrestore(&cdx_police_lock, flags);
	return 0;
}

static int cdx_police_port_destroy(struct net_device *dev,
				   struct tc_cls_matchall_offload *f)
{
	struct cdx_police_port *port;
	unsigned long flags;

	spin_lock_irqsave(&cdx_police_lock, flags);
	port = cdx_police_port_find(dev, f->cookie);
	if (port)
		list_del(&port->list);
	spin_unlock_irqrestore(&cdx_police_lock, flags);
	kfree(port);
	cdx_port_police_clear(dev->name);
	return 0;
}

static int cdx_police_port_stats(struct net_device *dev,
				 struct tc_cls_matchall_offload *f)
{
	struct cdx_police_counters now;
	struct cdx_police_port *port;
	unsigned long flags;
	bool reported;

	if (cdx_port_police_counters(dev->name, &now) != SUCCESS)
		return -EINVAL;

	/* Looked up after the read rather than before it, because a filter can
	 * be destroyed while its counters are being fetched and the baseline
	 * belongs to whichever record is still there afterwards. */
	spin_lock_irqsave(&cdx_police_lock, flags);
	port = cdx_police_port_find(dev, f->cookie);
	reported = port != NULL;
	if (port)
		cdx_police_report(&f->stats, &port->base, &now);
	spin_unlock_irqrestore(&cdx_police_lock, flags);
	return reported ? 0 : -ENOENT;
}

static int cdx_police_matchall(struct net_device *dev,
			       struct tc_cls_matchall_offload *f)
{
	switch (f->command) {
	case TC_CLSMATCHALL_REPLACE:
		return cdx_police_replace(dev, f);
	case TC_CLSMATCHALL_DESTROY:
		return cdx_police_port_destroy(dev, f);
	case TC_CLSMATCHALL_STATS:
		return cdx_police_port_stats(dev, f);
	default:
		return -EOPNOTSUPP;
	}
}

/* ---- flower: a meter for a subset of the port's traffic ----------------
 *
 * matchall and the port profile describe the same frames, so one can simply be
 * the other. A flower filter does not: it names a 5-tuple, and the hardware
 * selects a per-flow profile through the `iqid` in a flowtable entry's own
 * action. The filter and the entry are created by different subsystems and
 * neither knows about the other, so the binding has to be made here --
 * remember what each filter matched, and consult that when a flow is admitted.
 *
 * The lookup runs once per admitted flow, not per frame.
 */
struct cdx_police_filter {
	struct list_head	list;
	struct net_device	*dev;
	unsigned long		cookie;
	u32			prio;		/* tc filter priority; lower wins */
	u8			profile;	/* 1..CDX_FT_QOS_MAX_POLICER */
	u8			family;		/* AF_INET or AF_INET6 */
	u8			proto;
	bool			proto_masked;
	bool			is_pipe;	/* conform continues (pipe) vs accept */
	union nf_inet_addr	src, src_mask, dst, dst_mask;
	__be16			sport, sport_mask, dport, dport_mask;
	struct cdx_police_counters base;
};

static LIST_HEAD(cdx_police_filters);
/* Profile 0 is the default every unclassified flow already meters against, so
 * the pool starts at 1. Bit n set means profile n is spoken for. */
static unsigned long cdx_police_profiles;
/* A profile a filter installed is named by every flow the flowtable admitted
 * under it, and those flows outlive the filter. Count them so a profile freed
 * by its filter's teardown is not handed to a new filter -- and reprogrammed --
 * while an old flow still meters against it. `pending` marks a profile whose
 * filter is gone but whose flows are not, held out of the pool until the last
 * unref. All under cdx_police_lock. */
static u32 cdx_police_profile_refs[CDX_FT_QOS_MAX_POLICER + 1];
static unsigned long cdx_police_profile_pending;

static int cdx_police_profile_get(void)
{
	unsigned int n;

	for (n = 1; n <= CDX_FT_QOS_MAX_POLICER; n++)
		if (!(cdx_police_profiles & BIT(n))) {
			cdx_police_profiles |= BIT(n);
			return n;
		}
	return -ENOSPC;
}

static void cdx_police_profile_put(unsigned int n)
{
	cdx_police_profiles &= ~BIT(n);
}

/* The flowtable backend refs a profile when it installs a flow that names it
 * and unrefs when it removes that flow. */
void cdx_police_profile_ref(u8 profile)
{
	unsigned long flags;

	if (!profile || profile > CDX_FT_QOS_MAX_POLICER)
		return;
	spin_lock_irqsave(&cdx_police_lock, flags);
	cdx_police_profile_refs[profile]++;
	spin_unlock_irqrestore(&cdx_police_lock, flags);
}
EXPORT_SYMBOL_NS_GPL(cdx_police_profile_ref, ASK_CDX_FLOWTABLE);

void cdx_police_profile_unref(u8 profile)
{
	unsigned long flags;

	if (!profile || profile > CDX_FT_QOS_MAX_POLICER)
		return;
	spin_lock_irqsave(&cdx_police_lock, flags);
	if (WARN_ON_ONCE(!cdx_police_profile_refs[profile])) {
		spin_unlock_irqrestore(&cdx_police_lock, flags);
		return;
	}
	/* The last flow of a profile whose filter is already gone: only now is it
	 * safe to return to the pool for another filter to reprogram. */
	if (--cdx_police_profile_refs[profile] == 0 &&
	    (cdx_police_profile_pending & BIT(profile))) {
		cdx_police_profile_pending &= ~BIT(profile);
		cdx_police_profile_put(profile);
	}
	spin_unlock_irqrestore(&cdx_police_lock, flags);
}
EXPORT_SYMBOL_NS_GPL(cdx_police_profile_unref, ASK_CDX_FLOWTABLE);

/* A field the filter did not constrain has a zero mask and matches anything,
 * which is what flower means by leaving it out. */
static bool cdx_police_addr_eq(const union nf_inet_addr *a,
			       const union nf_inet_addr *key,
			       const union nf_inet_addr *mask)
{
	int i;

	for (i = 0; i < 4; i++)
		if ((a->all[i] & mask->all[i]) != (key->all[i] & mask->all[i]))
			return false;
	return true;
}

static bool cdx_police_filter_matches(const struct cdx_police_filter *f,
				      const struct cdx_ft_rule *rule)
{
	/* The filter sits on one port's ingress, and a flowtable direction
	 * arrives on exactly one port. */
	if (f->dev != rule->in || f->family != rule->family)
		return false;
	if (f->proto_masked && f->proto != rule->proto)
		return false;
	if ((rule->sport & f->sport_mask) != (f->sport & f->sport_mask))
		return false;
	if ((rule->dport & f->dport_mask) != (f->dport & f->dport_mask))
		return false;
	return cdx_police_addr_eq(&rule->src, &f->src, &f->src_mask) &&
	       cdx_police_addr_eq(&rule->dst, &f->dst, &f->dst_mask);
}

/* Two filters overlap if some flow could match both: same port and family, and
 * for every field the two constraints agree wherever both mask it in. Lookup
 * picks a single profile, so two overlapping filters cannot both meter a flow
 * in hardware -- which is why a `pipe` conform, that in software would continue
 * from the first into the second, has no hardware form when they overlap. */
static bool cdx_police_overlap(const struct cdx_police_filter *a,
			       const struct cdx_police_filter *b)
{
	int i;

	if (a->dev != b->dev || a->family != b->family)
		return false;
	if (a->proto_masked && b->proto_masked && a->proto != b->proto)
		return false;
	if ((a->sport ^ b->sport) & a->sport_mask & b->sport_mask)
		return false;
	if ((a->dport ^ b->dport) & a->dport_mask & b->dport_mask)
		return false;
	for (i = 0; i < 4; i++) {
		if ((a->src.all[i] ^ b->src.all[i]) &
		    a->src_mask.all[i] & b->src_mask.all[i])
			return false;
		if ((a->dst.all[i] ^ b->dst.all[i]) &
		    a->dst_mask.all[i] & b->dst_mask.all[i])
			return false;
	}
	return true;
}

/* The profile an admitted flow should meter against, as a cdx_ft_rule.qos
 * policer nibble, or zero for the default. Among the filters that match, the
 * highest-priority (lowest tc prio) one wins, which is the one software TC
 * would have applied. The list is insertion-ordered -- fine on a block replay,
 * where tp hands filters over in priority order, but not when an operator
 * inserts a higher-priority filter after lower-priority ones already exist --
 * so the selection reads the priority rather than trusting list order.
 */
u8 cdx_police_lookup(const struct cdx_ft_rule *rule)
{
	const struct cdx_police_filter *f;
	unsigned long flags;
	u8 profile = 0;
	u32 best = 0;
	bool found = false;

	spin_lock_irqsave(&cdx_police_lock, flags);
	list_for_each_entry(f, &cdx_police_filters, list)
		if (cdx_police_filter_matches(f, rule) &&
		    (!found || f->prio < best)) {
			profile = f->profile;
			best = f->prio;
			found = true;
		}
	spin_unlock_irqrestore(&cdx_police_lock, flags);
	return profile;
}
EXPORT_SYMBOL_NS_GPL(cdx_police_lookup, ASK_CDX_FLOWTABLE);

/* The filter tc means by a cookie. Runs under cdx_police_lock. */
static struct cdx_police_filter *cdx_police_filter_find(struct net_device *dev,
							unsigned long cookie)
{
	struct cdx_police_filter *filter;

	list_for_each_entry(filter, &cdx_police_filters, list)
		if (filter->dev == dev && filter->cookie == cookie)
			return filter;
	return NULL;
}

/* Only the keys that make a 5-tuple. Anything else -- VLAN, MPLS, a TCP flag --
 * would select frames the hardware cannot distinguish at this point, and
 * accepting it would meter a wider set than the operator described. */
static int cdx_police_parse(struct flow_cls_offload *f,
			    struct cdx_police_filter *out)
{
	struct netlink_ext_ack *extack = f->common.extack;
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	struct flow_match_control control;
	struct flow_match_basic basic;
	unsigned long long used;
	const unsigned long long allowed =
		BIT_ULL(FLOW_DISSECTOR_KEY_CONTROL) | BIT_ULL(FLOW_DISSECTOR_KEY_BASIC) |
		BIT_ULL(FLOW_DISSECTOR_KEY_PORTS) |
		BIT_ULL(FLOW_DISSECTOR_KEY_IPV4_ADDRS) |
		BIT_ULL(FLOW_DISSECTOR_KEY_IPV6_ADDRS);

	used = rule->match.dissector->used_keys;
	if (used & ~allowed) {
		NL_SET_ERR_MSG_MOD(extack, "flower: only the 5-tuple keys are supported");
		return -EOPNOTSUPP;
	}
	if (!flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CONTROL)) {
		NL_SET_ERR_MSG_MOD(extack, "flower: a control key is required");
		return -EOPNOTSUPP;
	}
	flow_rule_match_control(rule, &control);
	if (control.mask->flags) {
		NL_SET_ERR_MSG_MOD(extack, "flower: fragment matching is not supported");
		return -EOPNOTSUPP;
	}
	if (control.key->addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS)
		out->family = AF_INET;
	else if (control.key->addr_type == FLOW_DISSECTOR_KEY_IPV6_ADDRS)
		out->family = AF_INET6;
	else {
		NL_SET_ERR_MSG_MOD(extack, "flower: an IPv4 or IPv6 address type is required");
		return -EOPNOTSUPP;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_BASIC)) {
		flow_rule_match_basic(rule, &basic);
		if (basic.mask->ip_proto) {
			if (basic.mask->ip_proto != 0xff) {
				NL_SET_ERR_MSG_MOD(extack, "flower: a partial protocol mask is not supported");
				return -EOPNOTSUPP;
			}
			out->proto = basic.key->ip_proto;
			out->proto_masked = true;
		}
	}
	if (out->family == AF_INET) {
		struct flow_match_ipv4_addrs ipv4;

		if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IPV4_ADDRS)) {
			flow_rule_match_ipv4_addrs(rule, &ipv4);
			out->src.ip = ipv4.key->src;
			out->src_mask.ip = ipv4.mask->src;
			out->dst.ip = ipv4.key->dst;
			out->dst_mask.ip = ipv4.mask->dst;
		}
	} else {
		struct flow_match_ipv6_addrs ipv6;

		if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IPV6_ADDRS)) {
			flow_rule_match_ipv6_addrs(rule, &ipv6);
			memcpy(&out->src.in6, &ipv6.key->src, sizeof(out->src.in6));
			memcpy(&out->src_mask.in6, &ipv6.mask->src, sizeof(out->src_mask.in6));
			memcpy(&out->dst.in6, &ipv6.key->dst, sizeof(out->dst.in6));
			memcpy(&out->dst_mask.in6, &ipv6.mask->dst, sizeof(out->dst_mask.in6));
		}
	}
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_PORTS)) {
		struct flow_match_ports ports;

		flow_rule_match_ports(rule, &ports);
		out->sport = ports.key->src;
		out->sport_mask = ports.mask->src;
		out->dport = ports.key->dst;
		out->dport_mask = ports.mask->dst;
	}
	return 0;
}

static int cdx_police_flower_replace(struct net_device *dev,
				     struct flow_cls_offload *f)
{
	struct netlink_ext_ack *extack = f->common.extack;
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	struct cdx_police_filter *filter;
	const struct flow_action_entry *act;
	u32 cir, pir, cbs, pbs;
	unsigned long flags;
	bool byte_mode;
	int profile, rc;

	/* A filter in a non-zero chain is only reached by a `goto chain` from
	 * chain 0. The offload binds by tuple lookup and cannot see that jump, so
	 * it would apply the meter to flows software never routes there. Decline
	 * it, as the flowtable admission path does. */
	if (f->common.chain_index) {
		NL_SET_ERR_MSG_MOD(extack, "flower: only chain 0 is supported");
		return -EOPNOTSUPP;
	}
	if (!flow_offload_has_one_action(&rule->action)) {
		NL_SET_ERR_MSG_MOD(extack, "flower: exactly one action is supported");
		return -EOPNOTSUPP;
	}
	act = &rule->action.entries[0];
	if (act->id != FLOW_ACTION_POLICE) {
		NL_SET_ERR_MSG_MOD(extack, "flower: only police is supported");
		return -EOPNOTSUPP;
	}
	rc = cdx_police_check(act, extack);
	if (rc)
		return rc;
	rc = cdx_police_rates(act, extack, &byte_mode, &cir, &pir, &cbs, &pbs);
	if (rc)
		return rc;
	/* The per-flow profiles are programmed in byte mode; a packet-rate
	 * meter would need the whole pool switched over, which is not a
	 * per-filter decision. */
	if (!byte_mode) {
		NL_SET_ERR_MSG_MOD(extack, "flower: a packet rate is only supported port-wide");
		return -EOPNOTSUPP;
	}

	filter = kzalloc(sizeof(*filter), GFP_KERNEL);
	if (!filter)
		return -ENOMEM;
	filter->dev = dev;
	filter->cookie = f->cookie;
	filter->prio = f->common.prio;
	filter->is_pipe = act->police.notexceed.act_id == FLOW_ACTION_PIPE;
	rc = cdx_police_parse(f, filter);
	if (rc)
		goto err_free;

	spin_lock_irqsave(&cdx_police_lock, flags);
	/* A pipe conform means "meter here and continue", which composes with any
	 * filter that overlaps it. Lookup applies one profile, so that composition
	 * cannot be represented: decline the offload and leave both to software TC,
	 * which evaluates the chain whole, rather than metering one and claiming
	 * the rest ran. A filter's own replacement (same cookie) is not a conflict. */
	{
		const struct cdx_police_filter *e;

		list_for_each_entry(e, &cdx_police_filters, list) {
			if (e->dev == dev && e->cookie == f->cookie)
				continue;
			if ((filter->is_pipe || e->is_pipe) &&
			    cdx_police_overlap(filter, e)) {
				spin_unlock_irqrestore(&cdx_police_lock, flags);
				NL_SET_ERR_MSG_MOD(extack,
					"flower: a pipe policer overlaps another filter and cannot compose in hardware");
				rc = -EOPNOTSUPP;
				goto err_free;
			}
		}
	}
	profile = cdx_police_profile_get();
	spin_unlock_irqrestore(&cdx_police_lock, flags);
	if (profile < 0) {
		/* Seven meters, and the eighth caller is told so rather than
		 * silently sharing one. tc then leaves the filter in software. */
		NL_SET_ERR_MSG_MOD(extack, "flower: no ingress policer profile is free");
		rc = -EOPNOTSUPP;
		goto err_free;
	}
	filter->profile = profile;

	if (cdx_ingress_enable_or_disable_qos(FMAN_INDEX, profile,
					      ENABLE_INGRESS_POLICER) != SUCCESS ||
	    cdx_ingress_policer_modify_config(FMAN_INDEX, profile,
					      cir, pir, cbs, pbs, true) != SUCCESS) {
		NL_SET_ERR_MSG_MOD(extack, "flower: the ingress policer profile could not be programmed");
		rc = -EINVAL;
		goto err_profile;
	}

	/* A profile given back by one filter and handed to the next still holds
	 * the frames the first one metered, so the baseline starts where the
	 * hardware is rather than at zero. */
	cdx_ingress_policer_counters(FMAN_INDEX, profile, &filter->base);

	spin_lock_irqsave(&cdx_police_lock, flags);
	list_add_tail(&filter->list, &cdx_police_filters);
	spin_unlock_irqrestore(&cdx_police_lock, flags);
	return 0;

err_profile:
	spin_lock_irqsave(&cdx_police_lock, flags);
	cdx_police_profile_put(profile);
	spin_unlock_irqrestore(&cdx_police_lock, flags);
err_free:
	kfree(filter);
	return rc;
}

static int cdx_police_flower_destroy(struct net_device *dev,
				     struct flow_cls_offload *f)
{
	struct cdx_police_filter *filter;
	unsigned long flags;
	u8 profile;

	spin_lock_irqsave(&cdx_police_lock, flags);
	filter = cdx_police_filter_find(dev, f->cookie);
	if (filter) {
		profile = filter->profile;
		/* Return the profile to the pool only if no admitted flow still
		 * names it; otherwise hold it out (pending) until the last such
		 * flow is unref'd, so it is never reprogrammed under a live flow. */
		if (cdx_police_profile_refs[profile])
			cdx_police_profile_pending |= BIT(profile);
		else
			cdx_police_profile_put(profile);
		list_del(&filter->list);
	}
	spin_unlock_irqrestore(&cdx_police_lock, flags);
	if (!filter)
		return -ENOENT;
	/* Turn the meter off before the profile can be handed to another
	 * filter, so a flow still naming it passes rather than meets somebody
	 * else's rate. Flows admitted under it keep naming it until they are
	 * reinstalled, which is the same contract the conntrack mark has. */
	cdx_ingress_enable_or_disable_qos(FMAN_INDEX, profile,
					  DISABLE_INGRESS_POLICER);
	kfree(filter);
	return 0;
}

static int cdx_police_flower_stats(struct net_device *dev,
				   struct flow_cls_offload *f)
{
	struct cdx_police_counters now;
	struct cdx_police_filter *filter;
	unsigned long flags;
	bool reported;
	u8 profile;

	/* Which profile to read is decided under the lock; reading it is not,
	 * because the counter fetch busy-waits on a host command. The filter
	 * is then found again, since it can be destroyed in between and its
	 * profile handed to somebody else. */
	spin_lock_irqsave(&cdx_police_lock, flags);
	filter = cdx_police_filter_find(dev, f->cookie);
	profile = filter ? filter->profile : 0;
	spin_unlock_irqrestore(&cdx_police_lock, flags);
	if (!profile)
		return -ENOENT;

	if (cdx_ingress_policer_counters(FMAN_INDEX, profile, &now) != SUCCESS)
		return -EINVAL;

	spin_lock_irqsave(&cdx_police_lock, flags);
	filter = cdx_police_filter_find(dev, f->cookie);
	reported = filter && filter->profile == profile;
	if (reported)
		cdx_police_report(&f->stats, &filter->base, &now);
	spin_unlock_irqrestore(&cdx_police_lock, flags);
	return reported ? 0 : -ENOENT;
}

static int cdx_police_flower(struct net_device *dev, struct flow_cls_offload *f)
{
	switch (f->command) {
	case FLOW_CLS_REPLACE:
		return cdx_police_flower_replace(dev, f);
	case FLOW_CLS_DESTROY:
		return cdx_police_flower_destroy(dev, f);
	case FLOW_CLS_STATS:
		return cdx_police_flower_stats(dev, f);
	default:
		return -EOPNOTSUPP;
	}
}

static int cdx_police_block_cb(enum tc_setup_type type, void *type_data,
			       void *cb_priv)
{
	struct net_device *dev = cb_priv;

	switch (type) {
	case TC_SETUP_CLSMATCHALL:
		return cdx_police_matchall(dev, type_data);
	case TC_SETUP_CLSFLOWER:
		return cdx_police_flower(dev, type_data);
	default:
		return -EOPNOTSUPP;
	}
}

static LIST_HEAD(cdx_police_block_list);

/* Ingress only. A clsact qdisc offers both directions and egress is the
 * scheduler's, reached through TC_SETUP_QDISC_HTB; a police action there would
 * describe a different object entirely. */
int cdx_police_setup_block(struct net_device *dev,
			   struct flow_block_offload *f)
{
	if (f->binder_type != FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS)
		return -EOPNOTSUPP;
	f->driver_block_list = &cdx_police_block_list;
	return flow_block_cb_setup_simple(f, &cdx_police_block_list,
					  cdx_police_block_cb, dev, dev, true);
}
