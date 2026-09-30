// SPDX-License-Identifier: GPL-2.0-or-later
/* CDX ownership and hardware services for the Linux flowtable adapter. */
#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#include <linux/module.h>
#include <linux/rtnetlink.h>
#include <linux/workqueue.h>
#include "portdefs.h"
#include "cdx.h"
#include "cdx_flowtable.h"
#include "cdx_flowtable_backend.h"
#include "cdx_flowtable_hw.h"
#include "cdx_ipsec_backend.h"
#include "cdx_mcast_backend.h"
#include "devman.h"
#include "dpa_wifi.h"

static bool ft_observe;
module_param_named(flowtable_observe, ft_observe, bool, 0444);
MODULE_PARM_DESC(flowtable_observe, "Validate requests but decline hardware installation");

/* ASK-DEBUG. Lives here rather than in the adapter because both modules make
 * admission decisions and one knob should govern both; the adapter reaches it
 * through the exported symbol. Writable at runtime (0644) on purpose -- the
 * question it answers usually arrives after the interesting boot. */
unsigned int cdx_ft_debug_mask;
EXPORT_SYMBOL_NS_GPL(cdx_ft_debug_mask, ASK_CDX_FLOWTABLE);
module_param_named(ask_debug, cdx_ft_debug_mask, uint, 0644);
MODULE_PARM_DESC(ask_debug, "ASK-DEBUG admission tracing: 1=refusals 2=accepts 4=devices");

/* These belong to CDX, not the adapter. Detach/reclaim must not forget an
 * unproven hardware deletion. Configuration stays sealed after the first
 * claim, even if registration subsequently fails. */
static bool ft_claimed, ft_config_sealed, ft_failed;
static unsigned int ft_live;

bool cdx_ft_observing(void)
{
	return ft_observe;
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_observing, ASK_CDX_FLOWTABLE);

bool cdx_flowtable_config_sealed(void)
{
	return READ_ONCE(ft_config_sealed);
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

static void ft_fatal_work_fn(struct work_struct *work);
static DECLARE_DELAYED_WORK(ft_fatal_work, ft_fatal_work_fn);

/* cdx_ft_fatal() latches from paths the adapter's invalidation pass never
 * visits -- a multicast root belongs to its learner, and that pass only runs
 * while a flowtable is bound -- so nothing else is guaranteed to drive
 * cdx_ft_recover() to the port quiescence the latch promises. Do it here, in a
 * context that holds neither lock, retrying each second while RTNL is
 * contended; recovery returns zero once the ports are stopped. */
static void ft_fatal_work_fn(struct work_struct *work)
{
	int rc;

	cdx_ft_begin();
	rc = cdx_ft_recover();
	cdx_ft_end();
	if (rc == -EAGAIN)
		schedule_delayed_work(&ft_fatal_work, HZ);
}

/* Latch terminal failure from outside the unicast delete path. A multicast or
 * IPsec classifier root that could not be provably unlinked may still resolve
 * in hardware -- replicating through a leaked listener chain, or enqueueing to
 * a deleted SA's queues -- which is exactly the state unicast's -EIO
 * latches. The same latch refuses new entries and
 * groups, blocks port restart and makes the drain demand a reset, and the work
 * above stops the ports, so a possibly-still-linked root fail-stops the
 * datapath rather than forwarding on unnoticed. One-way, so a lockless
 * WRITE_ONCE is enough; safe to call with the transaction held. */
void cdx_ft_fatal(void)
{
	WRITE_ONCE(ft_failed, true);
	schedule_delayed_work(&ft_fatal_work, 0);
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_fatal, ASK_CDX_FLOWTABLE);

/* Unload stops the ports itself; the work must not outlive the module or run
 * against a freed cdx_info. Disabled rather than cancelled: the deinit chain
 * after this still destroys multicast groups, and a failure there must latch
 * without queueing the work again, as must the work's own retry while this
 * waits for it. Called without the control lock, which the work takes. */
void cdx_ft_fatal_stop(void)
{
	disable_delayed_work_sync(&ft_fatal_work);
}

unsigned int cdx_ft_pending(void)
{
	cdx_ft_assert_held();
	return cdx_ft_hw_pending() + cdx_ehash_quarantine_pending();
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_pending, ASK_CDX_FLOWTABLE);

bool cdx_ft_idle(void)
{
	bool idle;

	cdx_ft_begin();
	/* SAs and multicast groups too: an adapter that has unregistered its
	 * egress hook retires them after it, on its way out. */
	idle = !ft_live && !cdx_ft_pending() && !cdx_ipsec_sa_count() &&
	       !cdx_mc_group_count();
	cdx_ft_end();
	return idle;
}

int cdx_ft_claim(void)
{
	cdx_ft_assert_held();
	if (ft_failed)
		return -EOPNOTSUPP;
	/* Parked ehash storage is released on any completed sync, as one
	 * barrier on the single FMan PCD proves every unlink before it
	 * (ft_hw_release_synced(), cdx_ehash.c). With two PCDs it would free
	 * entries the other's walkers may still hold, so refuse to own
	 * hardware there. LS1046A has one; sealing the config below keeps a
	 * second from arriving later. The count is the loader's, so this is
	 * a configuration to refuse, not a kernel bug to trace. */
	if (dpa_get_num_fmans() > 1) {
		pr_warn_once("cdx flowtable: the DPA configuration spans %u FMans; hardware offload supports one\n",
			     dpa_get_num_fmans());
		return -EOPNOTSUPP;
	}
	if (ft_claimed || ft_live)
		return -EBUSY;
	/* A deletion still waiting on its barrier -- this backend's, or one
	 * CDX parked for a path of its own -- is retried here rather than
	 * left to refuse the load until some unrelated delete syncs. */
	if (cdx_ft_pending())
		cdx_ft_hw_retry();
	if (cdx_ft_pending())
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
 * it creates. One binding per device per table therefore cannot outrun that. */
static_assert(CDX_FT_MAX_TABLE_DEVICES == MAX_PHY_PORTS);

/* A port belonging to a switch ASIC would let the bridge mark a VLAN as
 * already stripped by hardware, which describes a tag the adapter's own
 * encoder is then expected to reproduce with nothing in the rule naming it.
 * A DPAA MAC is never such a port; prove that rather than assume it. */
static bool cdx_ft_switch_port(struct net_device *dev)
{
	struct netdev_phys_item_id ppid;

	return dev_get_port_parent_id(dev, &ppid, false) != -EOPNOTSUPP;
}

/* Everything both predicates below require, which is every check that is
 * about the device rather than about what it is made of: the right namespace,
 * an Ethernet header, registered, running with carrier, not a VRF slave, not a
 * switch ASIC port, and a valid onif whose type the caller then judges.
 *
 * Returns the onif type on success and zero on any refusal. Zero is not a
 * legal type -- every onif carries at least one IF_TYPE bit -- so it is
 * unambiguous as a failure value.
 */
static U8 cdx_ft_onif_type(struct net_device *dev)
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
		return 0;
	iface = dpa_get_ifinfo_by_netdev(dev);
	if (!iface || iface->itf_id >= L2_MAX_ONIF)
		return 0;
	onif = get_onif_by_index(iface->itf_id);
	if (!(onif->flags & ENTRY_VALID) || !onif->itf ||
	    onif->itf->index != iface->itf_id)
		return 0;
	return onif->itf->type;
}

bool cdx_ft_port_supported(struct net_device *dev)
{
	return cdx_ft_onif_type(dev) == (IF_TYPE_ETHERNET | IF_TYPE_PHYSICAL);
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_port_supported, ASK_CDX_FLOWTABLE);

/* What a finished frame may be handed to, which is a strictly wider set than
 * what may originate one.
 *
 * A VAP is an egress and only an egress. The encoder already resolves one --
 * dpa_get_out_tx_info_by_itf_id() has a WLAN arm that turns the onif into the
 * VAP's forwarding frame queue -- so an entry leaving through a VAP is an
 * ordinary entry with its enqueue target pointed elsewhere, and needs nothing
 * else from this side.
 *
 * The reverse is not true and is not granted here. A VAP's own ingress is
 * never programmed: the adapter binds a non-DPAA device passively (every
 * request declined), so a flow arriving from Wi-Fi is refused here and stays
 * on the software fast path while the DPAA ports in the same table keep
 * theirs. Keeping the two predicates separate is what states that in code
 * rather than in a comment.
 *
 * Open, not merely configured: the frame queues an entry would name are built
 * during the transition to open.
 */
bool cdx_ft_egress_supported(struct net_device *dev)
{
	U8 type = cdx_ft_onif_type(dev);

	if (type == (IF_TYPE_ETHERNET | IF_TYPE_PHYSICAL))
		return true;
	ask_dbg(ASK_DBG_DEVICE, "egress %s onif_type=0x%x vap_open=%d\n",
		dev ? netdev_name(dev) : "(null)", type,
		dev ? dpaa_vwd_vap_is_open(dev) : -1);
	return type == (IF_TYPE_WLAN | IF_TYPE_PHYSICAL) &&
	       dpaa_vwd_vap_is_open(dev);
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_egress_supported, ASK_CDX_FLOWTABLE);

/* A deletion waiting on its barrier refuses every new entry in cdx_ft_add(),
 * and while no invalidation is in progress nothing else retries it: least of
 * all one CDX parked for a multicast or IPsec delete, which only another delete
 * of that kind would otherwise release. So admission retries it itself, at
 * most once a second: a sync under RTNL can busy-wait on the host-command
 * channel, and a wedged channel would otherwise be asked once per offered
 * flow. */
static unsigned long ft_retry_at;

static void cdx_ft_retry_pending(void)
{
	if (ft_retry_at && time_before(jiffies, ft_retry_at))
		return;
	ft_retry_at = jiffies + HZ;
	cdx_ft_hw_retry();
}

int cdx_ft_add(const struct cdx_ft_rule *rule,
	       const struct cdx_ft_stats_binding *stats,
	       struct cdx_ft_hw **result)
{
	int rc;

	cdx_ft_assert_held();
	ASSERT_RTNL();
	*result = NULL;
	if (!ft_failed && cdx_ft_pending())
		cdx_ft_retry_pending();
	/* The adapter validates tuple/NAT eligibility, including same-port
	 * hairpin routing. The provider rechecks physical device state. */
	if (!ft_claimed || ft_failed || ft_observe || cdx_ft_pending() ||
	    !cdx_ft_port_supported(rule->in) || !cdx_ft_egress_supported(rule->out) ||
	    !ether_addr_equal(rule->src_mac, rule->out->dev_addr)) {
		/* Eight clauses and one return: without the operands a refusal
		 * here says only that CDX declined, which is the least useful
		 * true thing it could say. */
		ask_dbg(ASK_DBG_DEVICE,
			"add claimed=%d failed=%d observe=%d pending=%u in=%s(%d) out=%s(%d) srcmac=%d\n",
			ft_claimed, ft_failed, ft_observe, cdx_ft_pending(),
			rule->in ? netdev_name(rule->in) : "(null)",
			cdx_ft_port_supported(rule->in),
			rule->out ? netdev_name(rule->out) : "(null)",
			cdx_ft_egress_supported(rule->out),
			rule->out ? ether_addr_equal(rule->src_mac, rule->out->dev_addr) : -1);
		return ask_refuse(-EOPNOTSUPP);
	}
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

void cdx_ft_stats_retention(unsigned int *retained, u64 *deferred)
{
	cdx_ft_assert_held();
	cdx_ft_ifstats_retention(retained, deferred);
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_stats_retention, ASK_CDX_FLOWTABLE);

void cdx_ft_stats_read(const struct cdx_ft_stats_slot *slot,
		       struct cdx_ft_stats *rx, struct cdx_ft_stats *tx)
{
	cdx_ft_assert_held();
	cdx_ft_ifstats_read(slot, rx, tx);
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_stats_read, ASK_CDX_FLOWTABLE);

void cdx_ft_stats_publish(struct cdx_ft_stats_slot *slot, int ifindex,
			  unsigned int rx_overhead, unsigned int tx_overhead)
{
	cdx_ft_assert_held();
	cdx_ft_ifstats_publish(slot, ifindex, rx_overhead, tx_overhead);
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_stats_publish, ASK_CDX_FLOWTABLE);

/* No transaction: the caller is a netdev notifier, and the slot's owner --
 * who alone can free it -- is serialized against that notifier by its own lock. */
void cdx_ft_stats_unpublish(struct cdx_ft_stats_slot *slot)
{
	cdx_ft_ifstats_unpublish(slot);
}
EXPORT_SYMBOL_NS_GPL(cdx_ft_stats_unpublish, ASK_CDX_FLOWTABLE);

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
