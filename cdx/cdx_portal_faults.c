/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Test-only loads on the QMan portal of the first CPU, the one the FMan
 * host-command confirmation is delivered on (lnxwrp_fm.c, hcCh).
 *
 * portal_backlog keeps a queue on that portal's channel from emptying for a
 * time, as an exception stream the CPU cannot keep up with would: by default
 * at the work queue of the detour's exception queue, the cdx queue pinned to
 * that CPU, or at the one given. QMan serves a channel's WQ0 and WQ1 ahead of
 * everything else on it, so a queue there that never empties holds every
 * queue below it on that CPU for as long as it does (A401).
 *
 * portal_stall holds the CPU itself with bottom halves off, so that nothing
 * services its portal for a time, however its queues are placed: a
 * confirmation queued meanwhile arrives when the stall ends, after its
 * waiter's deadline if the stall outlasts it.
 *
 * Each load also issues one host-command barrier, from another CPU, once the
 * load is in place, and says how it went: that a barrier meets the load is
 * what a test needs, and what it cannot arrange from outside, its own
 * commands being held up by the very load.
 *
 * Both are absent from a production build.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/ktime.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/nmi.h>
#include <linux/fsl_qman.h>
#include "dpaa_eth_common.h"
#include "dpaa_eth.h"
#include "portdefs.h"
#include "cdx.h"
#include "fm_ehash.h"
#include "cdx_flowtable_backend.h"
#include "cdx_detour.h"

#ifdef CDX_DEBUG_FLOWTABLE

/* Frames kept circulating; each dequeue puts its own back. */
#define PF_BACKLOG_FRAMES	64
#define PF_BACKLOG_MAX_MS	10000
/* Well short of the soft-lockup and RCU stall detectors' 20 s. */
#define PF_STALL_MAX_MS		3000

/* One backlog and one stall at a time. */
static DEFINE_MUTEX(pf_lock);
/* Set by cdx_portal_faults_init(), under pf_lock: a knob given on the kernel
 * command line is set before CDX has a control mutex for the barrier, or the
 * work items here are initialized, and is refused. */
static bool pf_ready;

/* A load's barrier: issued once the load is in place, from a CPU other than
 * the loaded one. */
struct pf_probe {
	struct work_struct work;
	const char *load;
	bool (*loaded)(void);
	unsigned int cpu;
	int rc;
	unsigned int ms;
	/* The load was still in place when the barrier returned. */
	bool overlapped;
	bool done;
};

static struct {
	struct qman_fq fq;
	struct delayed_work end;
	struct pf_probe probe;
	void *buf;
	/* Under pf_lock: a hold is set up or being taken down. */
	bool active;
	/* Read by the dequeue callback: frames go back while it is set. */
	bool holding;
	u16 channel;
	u8 wq;
	unsigned int holds;
	atomic_t circulating;
	atomic64_t dequeues;
	atomic_t lost;
} pf_backlog;

static struct {
	struct work_struct work;
	struct pf_probe probe;
	/* Under pf_lock: queued or running. */
	bool active;
	/* Bottom halves are off on the stalled CPU. */
	bool running;
	unsigned int ms, stalls;
} pf_stall;

static void pf_probe_fn(struct work_struct *work)
{
	struct pf_probe *probe = container_of(work, struct pf_probe, work);
	unsigned long deadline = jiffies + HZ;
	ktime_t start;
	void *td;

	while (!probe->loaded() && time_before(jiffies, deadline))
		usleep_range(500, 1000);
	cdx_ft_begin();
	td = dpa_get_ehash_td();
	start = ktime_get();
	probe->rc = td ? ExternalHashTableFmPcdHcSync(td) : -ENODEV;
	probe->ms = ktime_ms_delta(ktime_get(), start);
	probe->overlapped = probe->loaded();
	cdx_ft_end();
	WRITE_ONCE(probe->done, true);
	pr_info("cdx: barrier under the portal %s: %d after %u ms%s\n", probe->load,
		probe->rc, probe->ms, probe->overlapped ? "" : ", the load already over");
}

/* From any online CPU but the loaded one. */
static void pf_probe_start(struct pf_probe *probe, unsigned int loaded_cpu)
{
	probe->rc = 0;
	probe->ms = 0;
	probe->overlapped = probe->done = false;
	probe->cpu = cpumask_any_but(cpu_online_mask, loaded_cpu);
	if (probe->cpu >= nr_cpu_ids)
		probe->cpu = loaded_cpu;
	queue_work_on(probe->cpu, system_highpri_wq, &probe->work);
}

static int pf_probe_emit(char *buf, int at, const struct pf_probe *probe)
{
	return at + sysfs_emit_at(buf, at, " barrier_done %u barrier_rc %d barrier_ms %u barrier_overlapped %u barrier_cpu %u\n",
				  READ_ONCE(probe->done), probe->rc, probe->ms,
				  probe->overlapped, probe->cpu);
}

static enum qman_cb_dqrr_result pf_backlog_dqrr(struct qman_portal *portal,
						 struct qman_fq *fq,
						 const struct qm_dqrr_entry *dq)
{
	int tries;

	if (!(dq->stat & QM_DQRR_STAT_FD_VALID))
		return qman_cb_dqrr_consume;
	atomic64_inc(&pf_backlog.dequeues);
	/* The enqueue ring can be full for a moment under the portal's own
	 * traffic; a frame that cannot go back leaves the hold one short. */
	if (READ_ONCE(pf_backlog.holding)) {
		for (tries = 0; tries < 1000; tries++) {
			if (!qman_enqueue(fq, &dq->fd, 0))
				return qman_cb_dqrr_consume;
			cpu_relax();
		}
		atomic_inc(&pf_backlog.lost);
	}
	atomic_dec(&pf_backlog.circulating);
	return qman_cb_dqrr_consume;
}

/* Nothing bounds the queue, so QMan has no reason to reject a frame; one it
 * did would simply leave the hold short. */
static void pf_backlog_ern(struct qman_portal *portal, struct qman_fq *fq,
			   const struct qm_mr_entry *msg)
{
	atomic_inc(&pf_backlog.lost);
	atomic_dec(&pf_backlog.circulating);
}

/* In place once its frames are circulating: the portal has dequeued from it
 * since the hold began. */
static bool pf_backlog_loaded(void)
{
	return READ_ONCE(pf_backlog.holding) && atomic64_read(&pf_backlog.dequeues) > 0;
}

/* The frames reference a scratch buffer nothing reads: QMan carries the
 * descriptor, never the data, and no one releases it to a pool. */
static void pf_backlog_fd(struct qm_fd *fd, u32 tag)
{
	memset(fd, 0, sizeof(*fd));
	qm_fd_addr_set64(fd, virt_to_phys(pf_backlog.buf));
	fd->format = qm_fd_contig;
	fd->length20 = 64;
	fd->cmd = tag;
}

/* Under pf_lock. Every frame is let go before the queue is drained, so the
 * drain finds no producer. */
static void pf_backlog_teardown(bool made)
{
	int i;

	WRITE_ONCE(pf_backlog.holding, false);
	for (i = 0; i < 500 && atomic_read(&pf_backlog.circulating) > 0; i++)
		msleep(10);
	if (made)
		cdx_destroy_fq(&pf_backlog.fq);
	kfree(pf_backlog.buf);
	pf_backlog.buf = NULL;
	pf_backlog.active = false;
}

static void pf_backlog_end(struct work_struct *work)
{
	/* The barrier is the hold's: it finishes first, whatever it waits on. */
	flush_work(&pf_backlog.probe.work);
	mutex_lock(&pf_lock);
	if (pf_backlog.active) {
		pf_backlog_teardown(true);
		pr_info("cdx: portal backlog on channel 0x%x wq%u ended: %lld dequeues, %d frames lost\n",
			pf_backlog.channel, pf_backlog.wq,
			(long long)atomic64_read(&pf_backlog.dequeues),
			atomic_read(&pf_backlog.lost));
	}
	mutex_unlock(&pf_lock);
}

static int pf_backlog_start(unsigned int ms, int wq)
{
	struct qm_mcc_initfq opts = {};
	struct qman_fq *fq = &pf_backlog.fq;
	struct qm_fd fd;
	u16 channel;
	u8 detour_wq;
	int i, rc;

	if (!ms || ms > PF_BACKLOG_MAX_MS || wq > 7)
		return -EINVAL;
	rc = cdx_detour_exception_placement(&channel, &detour_wq);
	if (rc)
		return rc;
	mutex_lock(&pf_lock);
	if (!pf_ready || pf_backlog.active) {
		mutex_unlock(&pf_lock);
		return pf_ready ? -EBUSY : -EAGAIN;
	}
	pf_backlog.active = true;
	pf_backlog.channel = channel;
	pf_backlog.wq = wq < 0 ? detour_wq : wq;
	atomic_set(&pf_backlog.circulating, 0);
	atomic64_set(&pf_backlog.dequeues, 0);
	atomic_set(&pf_backlog.lost, 0);
	rc = -ENOMEM;
	pf_backlog.buf = kzalloc(64, GFP_KERNEL | GFP_DMA);
	if (!pf_backlog.buf)
		goto fail;
	memset(fq, 0, sizeof(*fq));
	fq->cb.dqrr = pf_backlog_dqrr;
	fq->cb.ern = pf_backlog_ern;
	rc = qman_create_fq(0, QMAN_FQ_FLAG_DYNAMIC_FQID, fq);
	if (rc)
		goto fail;
	/* Placed and held as the exception queues are. */
	opts.fqid = fq->fqid;
	opts.count = 1;
	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL;
	opts.fqd.dest.channel = channel;
	opts.fqd.dest.wq = pf_backlog.wq;
	opts.fqd.fq_ctrl = QM_FQCTRL_PREFERINCACHE | QM_FQCTRL_HOLDACTIVE;
	rc = qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts);
	if (rc) {
		qman_destroy_fq(fq, 0);
		goto fail;
	}
	WRITE_ONCE(pf_backlog.holding, true);
	for (i = 0; i < PF_BACKLOG_FRAMES; i++) {
		int tries;

		pf_backlog_fd(&fd, i);
		atomic_inc(&pf_backlog.circulating);
		for (tries = 0; tries < 100000; tries++) {
			rc = qman_enqueue(fq, &fd, 0);
			if (!rc)
				break;
			cpu_relax();
		}
		if (rc) {
			atomic_dec(&pf_backlog.circulating);
			pf_backlog_teardown(true);
			mutex_unlock(&pf_lock);
			return rc;
		}
	}
	pf_backlog.holds++;
	pf_probe_start(&pf_backlog.probe, cpumask_first(qman_affine_cpus()));
	schedule_delayed_work(&pf_backlog.end, msecs_to_jiffies(ms));
	pr_info("cdx: portal backlog on channel 0x%x wq%u for %u ms\n",
		channel, pf_backlog.wq, ms);
	mutex_unlock(&pf_lock);
	return 0;
fail:
	pf_backlog_teardown(false);
	mutex_unlock(&pf_lock);
	return rc;
}

/* "MS" or "MS WQ": a hold of MS milliseconds, at the detour exception
 * queue's work queue or at WQ. Returns at once; the hold ends by itself. */
static int pf_backlog_set(const char *val, const struct kernel_param *kp)
{
	unsigned int ms;
	int wq = -1, n;

	n = sscanf(val, "%u %d", &ms, &wq);
	if (n < 1)
		return -EINVAL;
	return pf_backlog_start(ms, n == 2 ? wq : -1);
}

static int pf_backlog_get(char *buf, const struct kernel_param *kp)
{
	int n = sysfs_emit(buf, "holds %u active %u channel 0x%x wq %u dequeues %lld lost %d",
			   pf_backlog.holds, READ_ONCE(pf_backlog.active), pf_backlog.channel,
			   pf_backlog.wq, (long long)atomic64_read(&pf_backlog.dequeues),
			   atomic_read(&pf_backlog.lost));

	return pf_probe_emit(buf, n, &pf_backlog.probe);
}

static const struct kernel_param_ops pf_backlog_ops = {
	.set = pf_backlog_set,
	.get = pf_backlog_get,
};
module_param_cb(portal_backlog, &pf_backlog_ops, NULL, 0600);
MODULE_PARM_DESC(portal_backlog, "\"MS [WQ]\": keep a queue on the first CPU's portal channel busy for MS ms, at the detour exception queue's work queue or WQ, and issue a barrier under it (test)");

static bool pf_stall_loaded(void)
{
	return READ_ONCE(pf_stall.running);
}

/* Run on the CPU itself, which runs nothing else meanwhile; the soft-lockup
 * watchdog is told so. */
static void pf_stall_fn(struct work_struct *work)
{
	unsigned long end = jiffies + msecs_to_jiffies(pf_stall.ms);

	local_bh_disable();
	WRITE_ONCE(pf_stall.running, true);
	while (time_before(jiffies, end)) {
		mdelay(10);
		touch_softlockup_watchdog();
	}
	WRITE_ONCE(pf_stall.running, false);
	local_bh_enable();
	pr_info("cdx: portal stall on CPU %d ended after %u ms\n",
		raw_smp_processor_id(), pf_stall.ms);
	/* The barrier is the stall's: the stall is over once it has finished. */
	flush_work(&pf_stall.probe.work);
	mutex_lock(&pf_lock);
	pf_stall.active = false;
	mutex_unlock(&pf_lock);
}

static int pf_stall_set(const char *val, const struct kernel_param *kp)
{
	unsigned int ms, cpu;
	int rc;

	rc = kstrtouint(val, 0, &ms);
	if (rc)
		return rc;
	if (!ms || ms > PF_STALL_MAX_MS || cpumask_empty(qman_affine_cpus()))
		return -EINVAL;
	cpu = cpumask_first(qman_affine_cpus());
	mutex_lock(&pf_lock);
	if (!pf_ready || pf_stall.active) {
		mutex_unlock(&pf_lock);
		return pf_ready ? -EBUSY : -EAGAIN;
	}
	pf_stall.ms = ms;
	pf_stall.active = true;
	pf_stall.stalls++;
	queue_work_on(cpu, system_highpri_wq, &pf_stall.work);
	pf_probe_start(&pf_stall.probe, cpu);
	mutex_unlock(&pf_lock);
	pr_info("cdx: portal stall on CPU %u for %u ms\n", cpu, ms);
	return 0;
}

static int pf_stall_get(char *buf, const struct kernel_param *kp)
{
	int n = sysfs_emit(buf, "stalls %u active %u", pf_stall.stalls,
			   READ_ONCE(pf_stall.active));

	return pf_probe_emit(buf, n, &pf_stall.probe);
}

static const struct kernel_param_ops pf_stall_ops = {
	.set = pf_stall_set,
	.get = pf_stall_get,
};
module_param_cb(portal_stall, &pf_stall_ops, NULL, 0600);
MODULE_PARM_DESC(portal_stall, "\"MS\": hold the first CPU with bottom halves off for MS ms, so nothing services its portal, and issue a barrier meanwhile (test)");

/* Unload ends a hold early and waits out a stall, whose work is the module's
 * code. */
static void cdx_portal_faults_exit(void)
{
	mutex_lock(&pf_lock);
	pf_ready = false;
	mutex_unlock(&pf_lock);
	cancel_delayed_work_sync(&pf_backlog.end);
	flush_work(&pf_backlog.probe.work);
	mutex_lock(&pf_lock);
	if (pf_backlog.active)
		pf_backlog_teardown(true);
	mutex_unlock(&pf_lock);
	flush_work(&pf_stall.work);
	flush_work(&pf_stall.probe.work);
}

void cdx_portal_faults_init(void)
{
	INIT_DELAYED_WORK(&pf_backlog.end, pf_backlog_end);
	INIT_WORK(&pf_backlog.probe.work, pf_probe_fn);
	pf_backlog.probe.load = "backlog";
	pf_backlog.probe.loaded = pf_backlog_loaded;
	INIT_WORK(&pf_stall.work, pf_stall_fn);
	INIT_WORK(&pf_stall.probe.work, pf_probe_fn);
	pf_stall.probe.load = "stall";
	pf_stall.probe.loaded = pf_stall_loaded;
	register_cdx_deinit_func(cdx_portal_faults_exit);
	mutex_lock(&pf_lock);
	pf_ready = true;
	mutex_unlock(&pf_lock);
}

#else

void cdx_portal_faults_init(void)
{
}

#endif
