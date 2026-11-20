/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Test-only: a leak of the shared Ethernet receive pool, on demand.
 *
 * pool_leak takes buffers out of the pool every private DPAA port receives
 * into and frees them, unseen by the driver's per-CPU count of that pool, as
 * a buffer the hardware loses is (A453): the driver goes on believing the pool
 * holds them, and the CPU's receive, the only thing that refills it, never
 * finds its count low. Written "N", it takes N buffers, or as many as the
 * pool holds if fewer; written "all", every buffer the pool holds. Reading it
 * gives how many it has taken in all. What the pool does about it (A454) is
 * for a test to watch.
 *
 * Absent from a production build.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/rcupdate.h>
#include <linux/dma-mapping.h>
#include <linux/fsl_bman.h>
#include "dpaa_eth_common.h"
#include "dpaa_eth.h"
#include "portdefs.h"
#include "cdx.h"

#ifdef CDX_DEBUG_FLOWTABLE

/* Under pl_lock. Set by cdx_pool_faults_init(): a value given on the kernel
 * command line is set as the module loads, before CDX is up, and is refused. */
static DEFINE_MUTEX(pl_lock);
static bool pl_ready;
static u64 pl_taken;

/* The port whose probe made the pool every private port receives into
 * (dpa_priv_common_bpid), held: the pool's record is that port's device
 * memory, and the port's removal waits for the reference before it frees
 * the pool or the record. Found under RCU, not RTNL: a parameter's set runs
 * under the module's parameter lock, which a datapath restart takes under
 * the control mutex, itself taken under RTNL (cdx_flowtable_backend.c). */
static struct net_device *pl_pool_owner(netdevice_tracker *tracker)
{
	struct net_device *dev;

	rcu_read_lock();
	for_each_netdev_rcu(&init_net, dev) {
		struct dpa_priv_s *priv;

		if (!dpa_netdev_is_dpaa(dev))
			continue;
		priv = netdev_priv(dev);
		if (priv->mac_dev && priv->percpu_count && priv->dpa_bp &&
		    priv->dpa_bp->dev == dev->dev.parent) {
			netdev_hold(dev, tracker, GFP_ATOMIC);
			rcu_read_unlock();
			return dev;
		}
	}
	rcu_read_unlock();
	return NULL;
}

/* Eight at a time while eight are there, then one by one, as dpa_bp_drain()
 * empties a pool. Each buffer goes with the skb built on it
 * (_dpa_bp_add_8_bufs()), which owns its page: the pool's free_buf_cb puts
 * the page alone and would leave the skb behind. */
static u64 pl_take(struct dpa_bp *bp, u64 want)
{
	unsigned int num = 8;
	u64 taken = 0;

	while (taken < want) {
		struct bm_buffer bmb[8];
		int got, i;

		if (want - taken < num)
			num = want - taken;
		got = bman_acquire(bp->pool, bmb, num, 0);
		if (got <= 0) {
			if (num == 1)
				break;
			num = 1;
			continue;
		}
		for (i = 0; i < got; i++) {
			dma_addr_t addr = bm_buf_addr(&bmb[i]);
			struct sk_buff *skb, **skbh;

			dma_unmap_single(bp->dev, addr, bp->size, DMA_BIDIRECTIONAL);
			DPA_READ_SKB_PTR(skb, skbh, phys_to_virt(addr), -1);
			dev_kfree_skb_any(skb);
		}
		taken += got;
		cond_resched();
	}
	return taken;
}

static int pl_set(const char *val, const struct kernel_param *kp)
{
	netdevice_tracker tracker;
	struct net_device *owner;
	struct dpa_bp *bp;
	u64 want, taken;
	u8 bpid;
	int rc;

	if (sysfs_streq(val, "all")) {
		want = U64_MAX;
	} else {
		rc = kstrtou64(val, 0, &want);
		if (rc)
			return rc;
		if (!want)
			return -EINVAL;
	}
	mutex_lock(&pl_lock);
	if (!pl_ready) {
		mutex_unlock(&pl_lock);
		return -EAGAIN;
	}
	owner = pl_pool_owner(&tracker);
	if (!owner) {
		mutex_unlock(&pl_lock);
		return -ENODEV;
	}
	bp = ((struct dpa_priv_s *)netdev_priv(owner))->dpa_bp;
	bpid = bp->bpid;
	taken = pl_take(bp, want);
	netdev_put(owner, &tracker);
	pl_taken += taken;
	mutex_unlock(&pl_lock);
	pr_info("cdx: pool leak took %llu buffers from pool %u, %llu in all\n",
		taken, bpid, pl_taken);
	return 0;
}

static int pl_get(char *buf, const struct kernel_param *kp)
{
	u64 taken;

	mutex_lock(&pl_lock);
	taken = pl_taken;
	mutex_unlock(&pl_lock);
	return sysfs_emit(buf, "%llu\n", taken);
}

static const struct kernel_param_ops pl_ops = {
	.set = pl_set,
	.get = pl_get,
};
module_param_cb(pool_leak, &pl_ops, NULL, 0600);
MODULE_PARM_DESC(pool_leak, "\"N\" or \"all\": take N or every buffer from the private ports' shared receive pool and free it, unseen by the driver's count, as a lost buffer is (test)");

/* Nothing to undo at unload: the knob holds nothing, and what it touches is
 * the driver's. */
void cdx_pool_faults_init(void)
{
	mutex_lock(&pl_lock);
	pl_ready = true;
	mutex_unlock(&pl_lock);
}

#else

void cdx_pool_faults_init(void)
{
}

#endif
