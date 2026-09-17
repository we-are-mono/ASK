// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2026 Mono
 *
 * Ingress policing as a tc verb.
 *
 * The FMAN meters ingress traffic with RFC-2698 policer profiles, and until now
 * the only way to set one was an FCI command -- a control plane that is sealed
 * in flowtable mode and whose only client does not run there. tc already has
 * the vocabulary:
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
 * This file is the port-wide half -- `matchall`, every frame arriving on the
 * port. It needs no correlation with anything: the filter's scope and the
 * profile's scope are the same set of frames. Matching a subset (`flower`) has
 * to reach the eight per-flow profiles instead, and bind them to flows the
 * flowtable admitted, which is a separate piece of work.
 */

#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <net/flow_offload.h>
#include <net/pkt_cls.h>
#include "cdx.h"
#include "misc.h"
#include "cdx_common.h"
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
	/* The profile drops red and passes green and yellow on to the parser.
	 * It has no way to express any other pairing. */
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
	return 0;
}

static int cdx_police_replace(struct net_device *dev,
			      struct tc_cls_matchall_offload *f)
{
	struct netlink_ext_ack *extack = f->common.extack;
	struct flow_action *action = &f->rule->action;
	const struct flow_action_entry *act;
	u32 cir, pir, cbs, pbs;
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

	byte_mode = act->police.rate_bytes_ps != 0;
	if (byte_mode) {
		cir = cdx_police_bytes_to_kbits(act->police.rate_bytes_ps);
		/* RFC-2698 requires the peak rate to be at least the committed
		 * one. tc lets an operator omit it, meaning "no second rate",
		 * which this profile spells as the two being equal. */
		pir = act->police.peakrate_bytes_ps ?
			cdx_police_bytes_to_kbits(act->police.peakrate_bytes_ps) : cir;
		cbs = act->police.burst;
		pbs = act->police.burst;
	} else {
		cir = (u32)act->police.rate_pkt_ps;
		pir = cir;
		cbs = (u32)act->police.burst_pkt;
		pbs = cbs;
	}
	if (pir < cir) {
		NL_SET_ERR_MSG_MOD(extack, "police: peakrate must be at least rate");
		return -EOPNOTSUPP;
	}
	if (!cir) {
		NL_SET_ERR_MSG_MOD(extack, "police: rate rounds to zero at this profile's resolution");
		return -EOPNOTSUPP;
	}

	if (cdx_port_police_set(dev->name, byte_mode, cir, pir, cbs, pbs) != SUCCESS) {
		NL_SET_ERR_MSG_MOD(extack, "police: the port has no rate limiter");
		return -EINVAL;
	}
	return 0;
}

static int cdx_police_matchall(struct net_device *dev,
			       struct tc_cls_matchall_offload *f)
{
	switch (f->command) {
	case TC_CLSMATCHALL_REPLACE:
		return cdx_police_replace(dev, f);
	case TC_CLSMATCHALL_DESTROY:
		cdx_port_police_clear(dev->name);
		return 0;
	default:
		/* TC_CLSMATCHALL_STATS wants per-colour counters. The profile
		 * keeps them and get_plcr_counter() reads them; wiring that to
		 * tc's accounting is separate work, and claiming support
		 * without it would report a filter as passing everything. */
		return -EOPNOTSUPP;
	}
}

static int cdx_police_block_cb(enum tc_setup_type type, void *type_data,
			       void *cb_priv)
{
	struct net_device *dev = cb_priv;

	if (type != TC_SETUP_CLSMATCHALL)
		return -EOPNOTSUPP;
	return cdx_police_matchall(dev, type_data);
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
