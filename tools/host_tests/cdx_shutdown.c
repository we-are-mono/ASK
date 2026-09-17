/* Exercise the production terminal retry loops with recoverable hardware faults. */
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>

#define ENABLE_EGRESS_QOS
#define pr_warn_ratelimited(...) ((void)0)
#define ASSERT_RTNL() assert(rtnl)

struct _cdx_ctrl { bool mutex; void *timer_thread; };
static struct { struct _cdx_ctrl ctrl; } instance, *cdx_info = &instance;
static bool rtnl, ports_safe, queues_safe, callbacks_released, freed;
static bool timer_running;
static unsigned lock_contention, lock_waits, timer_stops;
static bool fman_info = true;
static unsigned port_failures, queue_failures, port_attempts, queue_attempts;
static unsigned sleeps, netlink_operations;
static unsigned init_level = 1;
void cdx_ctrl_timer_stop(void);

static void mutex_lock(bool *lock) { assert(!*lock && !rtnl); *lock = true; lock_waits++; }
static void mutex_unlock(bool *lock) { assert(*lock); *lock = false; }
static int mutex_trylock(bool *lock)
{
    assert(!*lock && rtnl);
    if (lock_contention) { lock_contention--; return 0; }
    *lock = true;
    return 1;
}
static void rtnl_lock(void) { assert(!rtnl && !cdx_info->ctrl.mutex); rtnl = true; }
static void rtnl_unlock(void) { assert(rtnl); rtnl = false; }
static void kthread_stop(void *thread)
{
    assert(thread == &timer_running && timer_running);
    assert(!rtnl && !cdx_info->ctrl.mutex && !callbacks_released);
    timer_running = false; timer_stops++;
}
/* The netdev's ndo_setup_tc has to be given up before anything a tc command
 * would reach is torn down, and before the timer stops taking the same locks a
 * qdisc command would find held. */
static bool ndo_released;
static void cdx_htb_exit(void)
{
    assert(!rtnl && !cdx_info->ctrl.mutex);
    assert(!ports_safe && !queues_safe && !callbacks_released && !freed);
    assert(timer_running);
    ndo_released = true;
}
static int dpa_cfg_quiesce(void)
{
    assert(ndo_released);
    assert(rtnl && cdx_info->ctrl.mutex && !callbacks_released && !freed && !timer_running);
    if (++port_attempts <= port_failures) return -1;
    ports_safe = true;
    return 0;
}
static void cdx_flowtable_quiesced(void)
{
    assert(rtnl && cdx_info->ctrl.mutex && ports_safe && !callbacks_released);
}
static int ceetm_exit(void)
{
    assert(rtnl && cdx_info->ctrl.mutex && ports_safe);
    assert(!callbacks_released && !freed);
    if (++queue_attempts <= queue_failures) return -1;
    queues_safe = true;
    return 0;
}
static void msleep(unsigned ms)
{
    assert(ms == 1000 && !rtnl && !cdx_info->ctrl.mutex && !timer_running);
    assert(!callbacks_released && !freed);
    /* Hardware remains faulty while an unrelated netlink operation runs. */
    rtnl_lock(); netlink_operations++; rtnl_unlock();
    lock_contention = 1;  /* Contention again when the retry reacquires. */
    sleeps++;
}
static void release_callbacks(void)
{
    assert(!rtnl && !cdx_info->ctrl.mutex && ports_safe && queues_safe);
    assert(!freed);
    cdx_ctrl_timer_stop();  /* Normal exit callback is idempotent. */
    callbacks_released = true;
}
static void (*deinit_fn[])(void) = {release_callbacks};
static void kfree(void *p)
{
    assert(p == cdx_info && callbacks_released && !rtnl && !cdx_info->ctrl.mutex);
    freed = true;
}
#include "cdx_shutdown.inc"

int main(void)
{
    for (port_failures = 0; port_failures <= 3; port_failures++) {
        for (queue_failures = 0; queue_failures <= 3; queue_failures++) {
            ports_safe = queues_safe = callbacks_released = freed = false;
            ndo_released = false;
            sleeps = netlink_operations = port_attempts = queue_attempts = 0;
            lock_contention = 2; lock_waits = timer_stops = 0;
            timer_running = true; cdx_info->ctrl.timer_thread = &timer_running;
            cdx_module_deinit();
            assert(freed && !rtnl && !cdx_info->ctrl.mutex);
            assert(ndo_released);
            assert(timer_stops == 1 && !cdx_info->ctrl.timer_thread);
            assert(lock_waits == 2 + sleeps && !lock_contention);
            assert(port_attempts == port_failures + 1);
            assert(queue_attempts == queue_failures + 1);
            assert(sleeps == port_failures + queue_failures);
            assert(netlink_operations == sleeps);
        }
    }
    puts("CDX shutdown: timer stopped, both locks available during retries; resources retained until recovery");
    return 0;
}
