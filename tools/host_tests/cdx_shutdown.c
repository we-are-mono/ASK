/* Exercise the production terminal retry loops with recoverable hardware faults. */
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>

#define ENABLE_EGRESS_QOS
#define pr_warn_ratelimited(...) ((void)0)
#define ASSERT_RTNL() assert(rtnl)

static struct { struct { bool mutex; } ctrl; } instance, *cdx_info = &instance;
static bool rtnl, ports_safe, queues_safe, callbacks_released, freed;
static bool fman_info = true;
static unsigned port_failures, queue_failures, port_attempts, queue_attempts;
static unsigned sleeps, netlink_operations;
static unsigned init_level = 1;

static void mutex_lock(bool *lock) { assert(!*lock); *lock = true; }
static void mutex_unlock(bool *lock) { assert(*lock); *lock = false; }
static void rtnl_lock(void) { assert(!rtnl); rtnl = true; }
static void rtnl_unlock(void) { assert(rtnl); rtnl = false; }
static int dpa_cfg_quiesce(void)
{
    assert(rtnl && cdx_info->ctrl.mutex && !callbacks_released && !freed);
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
    assert(ms == 1000 && !rtnl && cdx_info->ctrl.mutex);
    assert(!callbacks_released && !freed);
    /* Hardware remains faulty while an unrelated netlink operation runs. */
    rtnl_lock(); netlink_operations++; rtnl_unlock();
    sleeps++;
}
static void release_callbacks(void)
{
    assert(!rtnl && !cdx_info->ctrl.mutex && ports_safe && queues_safe);
    assert(!freed);
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
            sleeps = netlink_operations = port_attempts = queue_attempts = 0;
            cdx_module_deinit();
            assert(freed && !rtnl && !cdx_info->ctrl.mutex);
            assert(port_attempts == port_failures + 1);
            assert(queue_attempts == queue_failures + 1);
            assert(sleeps == port_failures + queue_failures);
            assert(netlink_operations == sleeps);
        }
    }
    puts("CDX shutdown: RTNL available during retries; resources retained until recovery");
    return 0;
}
