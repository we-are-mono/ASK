// SPDX-License-Identifier: GPL-2.0-or-later
/* CDX ownership and hardware services for the Linux flowtable adapter. */
#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#include <linux/module.h>
#include <linux/rtnetlink.h>
#include "portdefs.h"
#include "cdx.h"
#include "cdx_flowtable.h"
#include "cdx_flowtable_backend.h"
#include "cdx_flowtable_hw.h"
#include "devman.h"

static char *offload_owner = "cmm";
module_param(offload_owner, charp, 0444);
MODULE_PARM_DESC(offload_owner, "Hardware flow owner: cmm (default) or flowtable; boot selection only");

static bool ft_observe;
module_param_named(flowtable_observe, ft_observe, bool, 0444);
MODULE_PARM_DESC(flowtable_observe, "Validate requests but decline hardware installation");

/* These belong to CDX, not the adapter. Detach/reclaim must neither change the
 * selected owner nor forget an unproven hardware deletion. Configuration stays
 * sealed after the first claim, even if registration subsequently fails. */
static bool ft_claimed, ft_config_sealed, ft_failed;
static unsigned int ft_live;

bool cdx_flowtable_enabled(void)
{
	return !strcmp(offload_owner, "flowtable");
}

bool cdx_ft_observing(void)
{
	return ft_observe;
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_observing, ASK_CDX_FLOWTABLE);

bool cdx_flowtable_config_sealed(void)
{
	return READ_ONCE(ft_config_sealed);
}

int cdx_flowtable_mode_check(void)
{
	if (strcmp(offload_owner, "cmm") && strcmp(offload_owner, "flowtable"))
		return -EINVAL;
	if (ft_observe && !cdx_flowtable_enabled())
		return -EINVAL;
	return 0;
}

/* The SDK's normal ndo_open enables FMAN ports. A failed hardware unlink
 * belongs to the provider even after adapter detach, so guard that restart
 * here until provider teardown has detached PCD and released its ports. */
static int cdx_ft_netdev_event(struct notifier_block *nb, unsigned long event,
			     void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);

	if (event != NETDEV_PRE_UP || !READ_ONCE(ft_failed) ||
	    !dpa_netdev_is_physical(dev))
		return NOTIFY_DONE;
	netdev_err(dev, "CDX hardware retirement failed; unload CDX before restarting the port\n");
	return notifier_from_errno(-EIO);
}

static struct notifier_block ft_guard_nb = { .notifier_call = cdx_ft_netdev_event };
static bool ft_guard_registered;

int cdx_flowtable_guard_init(void)
{
	int rc;

	if (!cdx_flowtable_enabled())
		return 0;
	rc = register_netdevice_notifier(&ft_guard_nb);
	if (!rc)
		ft_guard_registered = true;
	return rc;
}

void cdx_flowtable_guard_exit(void)
{
	if (ft_guard_registered) {
		unregister_netdevice_notifier(&ft_guard_nb);
		ft_guard_registered = false;
	}
}

void cdx_ft_begin(void)
{
	mutex_lock(&cdx_info->ctrl.mutex);
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_begin, ASK_CDX_FLOWTABLE);

void cdx_ft_end(void)
{
	mutex_unlock(&cdx_info->ctrl.mutex);
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_end, ASK_CDX_FLOWTABLE);

void cdx_ft_assert_held(void)
{
	lockdep_assert_held(&cdx_info->ctrl.mutex);
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_assert_held, ASK_CDX_FLOWTABLE);

bool cdx_ft_failed(void)
{
	cdx_ft_assert_held();
	return ft_failed;
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_failed, ASK_CDX_FLOWTABLE);

unsigned int cdx_ft_pending(void)
{
	cdx_ft_assert_held();
	return cdx_ft_hw_pending() + cdx_ehash_quarantine_pending();
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_pending, ASK_CDX_FLOWTABLE);

int cdx_ft_claim(void)
{
	cdx_ft_assert_held();
	if (!cdx_flowtable_enabled() || ft_failed)
		return -EOPNOTSUPP;
	if (ft_claimed || ft_live || cdx_ft_pending())
		return -EBUSY;
	ft_claimed = true;
	WRITE_ONCE(ft_config_sealed, true);
	return 0;
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_claim, ASK_CDX_FLOWTABLE);

int cdx_ft_release(void)
{
	cdx_ft_assert_held();
	if (ft_live)
		return -EBUSY;
	ft_claimed = false;
	return 0;
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_release, ASK_CDX_FLOWTABLE);

int cdx_ft_admission_begin(void)
{
	cdx_ft_assert_held();
	/* RTNL holders can wait for callbacks needing this transaction. */
	return rtnl_trylock() ? 0 : -EAGAIN;
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_admission_begin, ASK_CDX_FLOWTABLE);

void cdx_ft_admission_end(void)
{
	cdx_ft_assert_held();
	rtnl_unlock();
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_admission_end, ASK_CDX_FLOWTABLE);

/* The devices cdx_ft_port_supported() can admit are exactly the physical
 * Ethernet onifs, and cdx_add_eth_onif() takes a phy_port slot for each one
 * it creates. One binding per device therefore cannot outrun that table. */
static_assert(CDX_FT_MAX_BINDINGS == MAX_PHY_PORTS);

/* A port belonging to a switch ASIC would let the bridge mark a VLAN as
 * already stripped by hardware, which describes a tag the adapter's own
 * encoder is then expected to reproduce with nothing in the rule naming it.
 * A DPAA MAC is never such a port; prove that rather than assume it. */
static bool cdx_ft_switch_port(struct net_device *dev)
{
	struct netdev_phys_item_id ppid;

	return dev_get_port_parent_id(dev, &ppid, false) != -EOPNOTSUPP;
}

bool cdx_ft_port_supported(struct net_device *dev)
{
	POnifDesc onif;
	struct dpa_iface_info *iface;

	cdx_ft_assert_held();
	/* A bridge port is admissible: the adapter's device walk recognizes the
	 * bridge hop above it and derives the tag stack the bridge produces, so
	 * an enslaved port is described rather than excluded. An L3 slave still
	 * is not -- a VRF moves the route lookup somewhere this contract does
	 * not follow. */
	if (!dev || !net_eq(dev_net(dev), &init_net) ||
	    dev->type != ARPHRD_ETHER || dev->addr_len != ETH_ALEN ||
	    dev->reg_state != NETREG_REGISTERED ||
	    netif_is_l3_slave(dev) || cdx_ft_switch_port(dev) ||
	    !netif_running(dev) || !netif_carrier_ok(dev))
		return false;
	iface = dpa_get_ifinfo_by_netdev(dev);
	if (!iface || iface->itf_id >= L2_MAX_ONIF)
		return false;
	onif = get_onif_by_index(iface->itf_id);
	if (!(onif->flags & ENTRY_VALID) || !onif->itf ||
	    onif->itf->index != iface->itf_id ||
	    onif->itf->type != (IF_TYPE_ETHERNET | IF_TYPE_PHYSICAL))
		return false;
	return true;
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_port_supported, ASK_CDX_FLOWTABLE);

int cdx_ft_add(const struct cdx_ft_rule *rule,
	       const struct cdx_ft_stats_binding *stats,
	       struct cdx_ft_hw **result)
{
	int rc;

	cdx_ft_assert_held();
	ASSERT_RTNL();
	*result = NULL;
	/* The adapter validates tuple/NAT eligibility, including same-port
	 * hairpin routing. The provider rechecks physical device state. */
	if (!ft_claimed || ft_failed || ft_observe || cdx_ft_pending() ||
	    !cdx_ft_port_supported(rule->in) || !cdx_ft_port_supported(rule->out) ||
	    !ether_addr_equal(rule->src_mac, rule->out->dev_addr))
		return -EOPNOTSUPP;
	rc = cdx_ft_hw_add(rule, stats, result);
	if (!rc)
		ft_live++;
	return rc;
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_add, ASK_CDX_FLOWTABLE);

/* Ownership, not encoding: a statistics slot is claimed and returned by the
 * adapter's own policy, so these are transaction-scoped like every other
 * backend operation but need no hardware state of their own. */
int cdx_ft_stats_alloc(enum cdx_ft_stats_kind kind, struct cdx_ft_stats_slot **slot)
{
	cdx_ft_assert_held();
	*slot = NULL;
	if (!ft_claimed || ft_failed)
		return -EOPNOTSUPP;
	return cdx_ft_ifstats_alloc(kind, slot);
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_stats_alloc, ASK_CDX_FLOWTABLE);

void cdx_ft_stats_free(struct cdx_ft_stats_slot **slot)
{
	cdx_ft_assert_held();
	cdx_ft_ifstats_free(slot);
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_stats_free, ASK_CDX_FLOWTABLE);

void cdx_ft_stats_read(const struct cdx_ft_stats_slot *slot,
		       struct cdx_ft_stats *rx, struct cdx_ft_stats *tx)
{
	cdx_ft_assert_held();
	cdx_ft_ifstats_read(slot, rx, tx);
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_stats_read, ASK_CDX_FLOWTABLE);

void cdx_ft_stats(struct cdx_ft_hw *hw, struct cdx_ft_counters *stats)
{
	cdx_ft_assert_held();
	cdx_ft_hw_stats(hw, stats);
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_stats, ASK_CDX_FLOWTABLE);

int cdx_ft_del(struct cdx_ft_hw **hw)
{
	int rc;

	cdx_ft_assert_held();
	if (!*hw)
		return 0;
	rc = cdx_ft_hw_del(hw);
	ft_live--;
	if (rc == -EIO)
		WRITE_ONCE(ft_failed, true);
	return rc;
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_del, ASK_CDX_FLOWTABLE);

int cdx_ft_recover(void)
{
	int rc;

	cdx_ft_assert_held();
	/* Never wait for RTNL while a callback transaction is held. CDX owns
	 * this terminal latch even after the adapter releases its claim. */
	if (ft_failed) {
		if (!rtnl_trylock())
			return -EAGAIN;
		rc = dpa_cfg_quiesce();
		rtnl_unlock();
		if (rc) {
			pr_err_ratelimited("cdx flowtable: waiting for hardware quiescence; reboot required\n");
			return -EAGAIN;
		}
		pr_err("cdx flowtable: hardware stopped after unproven deletion; reboot required\n");
		cdx_ft_hw_quiesced();
	}
	return cdx_ft_hw_retry();
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_recover, ASK_CDX_FLOWTABLE);

/* CDX's final shutdown has already stopped and detached every classifier port.
 * It can reclaim backend storage after the adapter and its work are gone. */
void cdx_flowtable_quiesced(void)
{
	cdx_ft_hw_quiesced();
}
