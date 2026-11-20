// SPDX-License-Identifier: GPL-2.0
/*
 * The private ports' receive pool, watched.
 *
 * Every private port receives into one BMan pool (dpa_priv_common_bpid), and
 * only the CPU puts buffers into it: the receive path refills it
 * (dpaa_eth_refill_bpools()) once that CPU's count -- what it seeded, less
 * what it took out -- runs low. A buffer the hardware loses, one the
 * microcode never releases, leaves every count as it was. Such losses add up
 * unseen, and once the pool is empty every port discards every frame for want
 * of a buffer: none reaches a CPU, so nothing refills it, and nothing says
 * so. Only a reboot brought receive back.
 *
 * So the pool is read once a second, beside the ports' out-of-buffer discard
 * counts. Holding fewer buffers than one refill would add on each CPU, it is
 * dry. Dry at two readings in a row, with a frame discarded for want of a
 * buffer since the first, it is an episode: said once, counted for ethtool
 * -S, and the pool put back to what the per-CPU counts hold it to have, less
 * the frames waiting in the ports' queues to the CPU, whose buffers the
 * counts still include until the CPU takes them, and never past its
 * configured size. The buffers added raise no count: the counts already hold
 * them to be there. The episode ends once the pool holds half its size, and
 * until then each reading tops it up again, a reseed that fell short
 * included.
 *
 * An episode adds at most the pool's size. Buffers lost as fast as they go
 * back, or held somewhere that does not let them go, then cost one pool and
 * an episode that does not end, said once. A slower loss is put right each
 * time it empties the pool, as episodes that repeat, each one said: the
 * memory it takes is the loss's own, at its own pace, which only a fix of
 * the loss ends.
 *
 * Frames held on purpose -- in the queues to the CPU, the forwarding, SEC,
 * qdisc and WireGuard queues -- are each bounded in frames below the pool and
 * drain within milliseconds once nothing more comes in, so a pool dry for two
 * readings has lost its buffers, or a holder is stuck. Only every bound full
 * at once, under a sustained overload of every port, can keep it dry without
 * a loss: the episode is then a false one, and once the holders let go the
 * pool holds up to what they held more than the counts. That does not
 * compound: with that much more, the holders can no longer empty it.
 */
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/ratelimit.h>
#include <linux/workqueue.h>
#include <linux/netdevice.h>
#include <linux/fsl_bman.h>
#include <linux/fsl_qman.h>
#include <lnxwrp_fm.h>
#include "fm_port_ext.h"
#include "dpaa_eth.h"
#include "dpaa_eth_common.h"
#include "mac.h"

#define DPA_POOL_WATCH_MS	1000
/* Dry readings in a row that make an episode. */
#define DPA_POOL_DRY_READINGS	2
/* What dpaa_eth_reseed_bpool() adds at a time. */
#define DPA_POOL_BATCH		8

/* The watch's state, and the counts ethtool -S reports. */
struct dpa_pool_episode {
	/* Dry readings in a row, up to DPA_POOL_DRY_READINGS, and the frames
	 * the ports discarded for want of a buffer since the first. */
	unsigned int dry;
	u64 dry_discards;
	bool open;
	/* Its allowance spent, the pool still short, and said so. */
	bool spent;
	/* What the episode may still add, and what it added. */
	u32 allowance;
	u64 added;
	/* Since boot: the episodes, and the buffers they added. Written under
	 * dpa_pool_lock, read without it (dpa_pool_watch_stats()). */
	u64 episodes;
	u64 reseeded;
};

enum dpa_pool_verdict {
	DPA_POOL_QUIET,
	/* An episode begins; add what *want says. */
	DPA_POOL_OPEN,
	/* Still short of half; add what *want says, perhaps nothing. */
	DPA_POOL_TOPUP,
	/* Still short, and the episode's allowance is spent: say so, once. */
	DPA_POOL_SPENT,
	/* The pool holds half its size again: the episode is over. */
	DPA_POOL_CLOSE,
};

/* A reading's verdict, and how many buffers to add (*want). @free is BMan's
 * count; @discards, the ports' out-of-buffer discards since the last
 * reading; @seeded, the per-CPU counts summed; @queued, the frames waiting
 * in the ports' queues to the CPU; @size, the pool's configured size; @low,
 * one refill on each CPU, below which the pool is dry. @queued is read only
 * for a reading dpa_pool_wants_queued() names. */
static enum dpa_pool_verdict dpa_pool_step(struct dpa_pool_episode *e, u32 free,
					   u32 discards, s64 seeded, u64 queued,
					   u32 size, u32 low, u32 *want)
{
	s64 missing;

	*want = 0;
	if (free < low) {
		if (e->dry < DPA_POOL_DRY_READINGS)
			e->dry++;
		e->dry_discards += discards;
	} else {
		e->dry = 0;
		e->dry_discards = 0;
	}
	if (e->open && free >= size / 2) {
		e->open = false;
		return DPA_POOL_CLOSE;
	}
	if (!e->open && (e->dry < DPA_POOL_DRY_READINGS || !e->dry_discards))
		return DPA_POOL_QUIET;
	/* What the counts hold the pool to have and it does not, less what
	 * the CPU is still to take out, within the pool's size. */
	missing = seeded - free - (s64)min_t(u64, queued, S32_MAX);
	missing = clamp_t(s64, missing, 0, free < size ? size - free : 0);
	if (!e->open) {
		e->open = true;
		e->spent = false;
		e->allowance = size;
		e->added = 0;
		WRITE_ONCE(e->episodes, e->episodes + 1);
		*want = min_t(s64, missing, e->allowance);
		return DPA_POOL_OPEN;
	}
	if (e->allowance < DPA_POOL_BATCH) {
		if (e->spent)
			return DPA_POOL_QUIET;
		e->spent = true;
		return DPA_POOL_SPENT;
	}
	*want = min_t(s64, missing, e->allowance);
	return DPA_POOL_TOPUP;
}

/* Whether a reading with BMan's count at @free is one dpa_pool_step() uses
 * the waiting frames for: a dry pool, or one an episode still tops up. */
static bool dpa_pool_wants_queued(const struct dpa_pool_episode *e, u32 free,
				  u32 size, u32 low)
{
	return free < low || (e->open && free < size / 2);
}

/* What a reseed the verdict asked for put in. */
static void dpa_pool_added(struct dpa_pool_episode *e, u32 added)
{
	e->allowance -= min(added, e->allowance);
	e->added += added;
	WRITE_ONCE(e->reseeded, e->reseeded + added);
}

/* The private ports, each on the list from its probe to its removal; the
 * watch's state; when it last read the pool and when the episode opened; and
 * whether the episode was said, so that its end is said too. */
static LIST_HEAD(dpa_pool_ports);
static DEFINE_MUTEX(dpa_pool_lock);
static struct dpa_pool_episode dpa_pool_episode;
static unsigned long dpa_pool_read_at;
static unsigned long dpa_pool_open_at;
static bool dpa_pool_said;
/* A pool emptied and refilled over and over by an overload that is no loss
 * must not flood the log; the episodes are counted all the same. */
static DEFINE_RATELIMIT_STATE(dpa_pool_log, 10 * 60 * HZ, 10);

static void dpa_pool_watch_fn(struct work_struct *work);
static DECLARE_DELAYED_WORK(dpa_pool_watch_work, dpa_pool_watch_fn);

/* The port's out-of-buffer discard count: the BMI's, a register. */
static bool dpa_pool_port_discards(const struct dpa_priv_s *priv, u32 *count)
{
	t_LnxWrpFmPortDev *port = priv->mac_dev ?
		(t_LnxWrpFmPortDev *)priv->mac_dev->port_dev[RX] : NULL;

	if (!port || !port->h_Dev)
		return false;
	*count = FM_PORT_GetCounter(port->h_Dev,
				    e_FM_PORT_COUNTERS_RX_OUT_OF_BUFFERS_DISCARD);
	return true;
}

/* The frames in the ports' ingress congestion groups, which hold every queue
 * from a port to the CPU and count frames. */
static u64 dpa_pool_queued(void)
{
	struct qm_mcr_querycgr query;
	struct dpa_priv_s *priv;
	u64 queued = 0;

	list_for_each_entry(priv, &dpa_pool_ports, pool_watch) {
		if (!priv->use_ingress_cgr)
			continue;
		if (!qman_query_cgr(&priv->ingress_cgr, &query))
			queued += qm_mcr_querycgr_i_get64(&query);
		if (!qman_query_cgr(&priv->ingress_cgr_hi_prio, &query))
			queued += qm_mcr_querycgr_i_get64(&query);
	}
	return queued;
}

/* The per-CPU counts summed, and listed in @by_cpu. Each CPU changes its own
 * from softirq; a read of it from here is a snapshot. */
static s64 dpa_pool_seeded(int __percpu *counts, char *by_cpu, size_t len)
{
	size_t n = 0;
	s64 sum = 0;
	int cpu;

	by_cpu[0] = '\0';
	for_each_possible_cpu(cpu) {
		int count = READ_ONCE(*per_cpu_ptr(counts, cpu));

		sum += count;
		n += scnprintf(by_cpu + n, len - n, "%s%d", n ? " " : "", count);
	}
	return sum;
}

static void dpa_pool_watch_fn(struct work_struct *work)
{
	struct dpa_pool_episode *e = &dpa_pool_episode;
	char ports[128] = "", by_cpu[64] = "";
	u32 free, discards = 0, low, size, want, added = 0;
	unsigned long now = jiffies, since;
	enum dpa_pool_verdict verdict;
	struct dpa_priv_s *priv, *first;
	struct dpa_bp *bp;
	s64 seeded;
	u64 queued = 0;
	size_t n = 0;

	mutex_lock(&dpa_pool_lock);
	first = list_first_entry_or_null(&dpa_pool_ports, struct dpa_priv_s,
					 pool_watch);
	if (!first) {
		/* The last port is gone; the next probe starts the watch
		 * again. */
		mutex_unlock(&dpa_pool_lock);
		return;
	}
	bp = first->dpa_bp;
	/* The counts before BMan's: a refill between the two reads then
	 * shows in BMan's count and not yet in the counts, so it errs toward
	 * adding too little, which the episode's next reading makes up. */
	seeded = dpa_pool_seeded(first->percpu_count, by_cpu, sizeof(by_cpu));
	free = bman_query_free_buffers(bp->pool);
	list_for_each_entry(priv, &dpa_pool_ports, pool_watch) {
		u32 count;

		if (!dpa_pool_port_discards(priv, &count))
			continue;
		discards += count - priv->pool_discards;
		priv->pool_discards = count;
		n += scnprintf(ports + n, sizeof(ports) - n, "%s%s %u",
			       n ? ", " : "", netdev_name(priv->net_dev), count);
	}
	size = bp->config_count * num_possible_cpus();
	low = CONFIG_FSL_DPAA_ETH_REFILL_THRESHOLD * num_possible_cpus();
	since = now - dpa_pool_read_at;
	dpa_pool_read_at = now;
	if (dpa_pool_wants_queued(e, free, size, low))
		queued = dpa_pool_queued();
	verdict = dpa_pool_step(e, free, discards, seeded, queued, size, low,
				&want);

	switch (verdict) {
	case DPA_POOL_OPEN:
		dpa_pool_open_at = now;
		dpa_pool_said = __ratelimit(&dpa_pool_log);
		if (dpa_pool_said)
			pr_warn("fsl_dpa: receive pool %u ran dry: BMan holds %u of %u buffers, the driver counts %lld (%s by CPU), %llu frames wait for the CPU; out-of-buffer discards %s, %u in the last %u ms; adding %u, episode %llu\n",
				bp->bpid, free, size, seeded, by_cpu, queued,
				ports, discards, jiffies_to_msecs(since), want,
				e->episodes);
		break;
	case DPA_POOL_SPENT:
		pr_err("fsl_dpa: receive pool %u still short after episode %llu added %llu buffers, the pool's size: BMan holds %u, the driver counts %lld (%s by CPU), %llu frames wait for the CPU; out-of-buffer discards %s; adding no more until it holds half its size\n",
		       bp->bpid, e->episodes, e->added, free, seeded, by_cpu,
		       queued, ports);
		break;
	case DPA_POOL_CLOSE:
		if (dpa_pool_said)
			pr_info("fsl_dpa: receive pool %u is receiving again: episode %llu added %llu buffers over %u ms, BMan holds %u\n",
				bp->bpid, e->episodes, e->added,
				jiffies_to_msecs(now - dpa_pool_open_at), free);
		break;
	default:
		break;
	}
	if (want)
		added = dpaa_eth_reseed_bpool(bp, want);
	dpa_pool_added(e, added);
	mutex_unlock(&dpa_pool_lock);

	queue_delayed_work(system_long_wq, &dpa_pool_watch_work,
			   msecs_to_jiffies(DPA_POOL_WATCH_MS));
}

/* A private port joins the watch once probed, its discards counted from
 * here. The first starts it. */
void dpa_pool_watch_add(struct dpa_priv_s *priv)
{
	u32 count = 0;

	mutex_lock(&dpa_pool_lock);
	dpa_pool_port_discards(priv, &count);
	priv->pool_discards = count;
	list_add_tail(&priv->pool_watch, &dpa_pool_ports);
	mutex_unlock(&dpa_pool_lock);
	queue_delayed_work(system_long_wq, &dpa_pool_watch_work,
			   msecs_to_jiffies(DPA_POOL_WATCH_MS));
}

/* Before its removal takes down its congestion groups and its hold on the
 * pool: the watch reads both through the port. */
void dpa_pool_watch_del(struct dpa_priv_s *priv)
{
	mutex_lock(&dpa_pool_lock);
	list_del_init(&priv->pool_watch);
	mutex_unlock(&dpa_pool_lock);
}

/* At unload, every port gone: the work is the module's code. */
void dpa_pool_watch_stop(void)
{
	cancel_delayed_work_sync(&dpa_pool_watch_work);
}

/* Read without the lock, which a reseed holds for as long as it takes. */
void dpa_pool_watch_stats(u64 *episodes, u64 *reseeded)
{
	*episodes = READ_ONCE(dpa_pool_episode.episodes);
	*reseeded = READ_ONCE(dpa_pool_episode.reseeded);
}
