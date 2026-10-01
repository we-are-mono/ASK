#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>

#define ENABLE_EGRESS_QOS
#define CDX_DEBUG_DPA_INIT
#define SEC_PROFILE_SUPPORT
#include "cdx_ioctl.h"
#define __must_hold(x)
#define GFP_KERNEL 0
#define CDX_MAX_FMANS 16
#define MAX_PHY_PORTS 8
#define MAX_PHYS_PORTS 64
#define FM_MAX_NUM_OF_1G_RX_PORTS 2
#define FM_MAX_NUM_OF_10G_RX_PORTS 2
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
/* Errors, counted: a port a resume could not start is reported by name. */
static unsigned dpa_errors;
static char dpa_error_line[128];
#define DPA_ERROR(...) do { dpa_errors++; snprintf(dpa_error_line, sizeof(dpa_error_line), __VA_ARGS__); } while (0)
#define pr_err(...) do { } while (0)
#define pr_err_ratelimited(...) do { } while (0)
/* The coverage warning at setup, counted. */
static unsigned coverage_warnings;
#define pr_warn(...) (coverage_warnings++)
#define display_dpa_cfg() do { } while (0)
typedef void *t_Handle;
typedef int t_Error;

#define FMAN_INDEX 0
/* A port as the SDK keeps it: enabled, detached from its PCD, fenced against
 * enables, still finishing frames for so many more looks, given a PCD of its
 * own (for a port CDX did not configure), and whether the netdev owning an Rx
 * port is up. */
struct port { bool enabled, detached, fenced, pcd, netdev_down, fail_enable; unsigned busy; };
struct device { unsigned id; };
typedef struct { bool active; t_Handle h_Dev; char name[20]; } t_LnxWrpFmPortDev;
#define IFNAMSIZ 16
typedef struct {
    unsigned id;
    t_LnxWrpFmPortDev opPorts[2], rxPorts[4];
    struct device *dev;
} t_LnxWrpFmDev;
struct list_head { struct list_head *next; };
struct qman_fq { unsigned id; };
struct dpa_fq { struct qman_fq fq_base; struct list_head list; };
struct { unsigned flags, id; struct { unsigned index; } itf; } phy_port[MAX_PHY_PORTS];
struct port_ff_rate_lim_info { void *handle, *h_FmPcd, *port_handle; };
static struct port_ff_rate_lim_info port_rate_lim_mode[MAX_PHYS_PORTS];
static unsigned num_fmans;
static struct cdx_fman_info *fman_info;
static struct dpa_fq *dpa_pcd_fq;
static int dpa_cfg_lock, rtnl;
static bool config_sealed, seal_on_lock;
static unsigned lock_contention, lock_waits, rtnl_locks;
static bool cdx_flowtable_config_sealed(void) { return config_sealed; }
static unsigned port_up_mask = 15;
static struct { struct { int mutex; } ctrl; } cdx_instance, *cdx_info = &cdx_instance;
static void rtnl_lock(void) { assert(!rtnl && !cdx_info->ctrl.mutex); rtnl = 1; rtnl_locks++; }
static void rtnl_unlock(void) { assert(rtnl); rtnl = 0; }
static struct cdx_fman_info input[2];
static struct cdx_ctrl_set_dpa_params request = { input, 2 };
static t_LnxWrpFmDev wrappers[2];
static struct port ports[4];
static unsigned alloc_step, fail_alloc, live_allocs, step, fail_step, copy_step, fail_copy;
static void *stats, *oh[2], *eth[MAX_PHY_PORTS];
static unsigned slots, queues;
static bool restoring, unsafe_enable, fail_delete;

static void mutex_lock(int *lock)
{
    if (lock == &cdx_info->ctrl.mutex) { assert(!rtnl); lock_waits++; }
    assert(!*lock); *lock = 1;
    if (lock == &cdx_info->ctrl.mutex && seal_on_lock) config_sealed = true;
}
static int mutex_trylock(int *lock)
{
    assert(lock == &cdx_info->ctrl.mutex && rtnl && !*lock);
    if (lock_contention) { lock_contention--; return 0; }
    *lock = 1;
    if (seal_on_lock) config_sealed = true;
    return 1;
}
static void mutex_unlock(int *lock) { assert(*lock); *lock = 0; }
static void *kcalloc(size_t n, size_t size, int flags)
{
    (void)flags;
    if (++alloc_step == fail_alloc) return NULL;
    void *p = calloc(n ? n : 1, size);
    assert(p);
    live_allocs++;
    return p;
}
static void kfree(void *p) { if (p) { assert(live_allocs); live_allocs--; free(p); } }
static void *acquire(void) { return kcalloc(1, 8, 0); }
static int copy_from_user(void *dst, const void *src, size_t size)
{
    if (++copy_step == fail_copy) { memcpy(dst, src, size / 2); return 1; }
    memcpy(dst, src, size); return 0;
}
bool cdx_dpa_init_fault_at(const char *site) { (void)site; return ++step == fail_step; }
static bool stopped(void)
{
    for (unsigned i = 0; i < 4; i++) if (ports[i].enabled) return false;
    return true;
}
static int FM_PORT_GetEnabled(void *p, bool *enabled)
{ assert(rtnl); *enabled = ((struct port *)p)->enabled; return 0; }
static int FM_PORT_DetachPCD(void *p)
{ assert(!((struct port *)p)->enabled); ((struct port *)p)->detached = true; return 0; }
static int FM_PORT_Disable(void *p) { ((struct port *)p)->enabled = false; return 0; }
static unsigned refused_enables;
static int FM_PORT_Enable(void *p)
{
    if (((struct port *)p)->fenced) { refused_enables++; return -EBUSY; }
    if (((struct port *)p)->fail_enable) return -EIO;
    if (!((struct port *)p)->detached && (!stats || queues != 4)) unsafe_enable = true;
    ((struct port *)p)->enabled = true; return 0;
}
static int FM_PORT_SetFenced(void *p, bool fenced) { ((struct port *)p)->fenced = fenced; return 0; }
static unsigned stopped_looks;
static int FM_PORT_GetStopped(void *p, bool *stopped)
{
    struct port *port = p;

    stopped_looks++;
    *stopped = !port->enabled && !port->busy;
    if (port->busy) port->busy--;
    return 0;
}
static int FM_PORT_IsPcdAttached(void *p, bool *attached) { *attached = ((struct port *)p)->pcd; return 0; }
static unsigned waits;
static void usleep_range(unsigned min, unsigned max) { assert(min && max >= min); waits++; }
#define ASSERT_RTNL() assert(rtnl)
static bool dpa_rx_port_wanted(t_Handle handle, char name[IFNAMSIZ])
{
    assert(rtnl);
    snprintf(name, IFNAMSIZ, "eth%u", (unsigned)((struct port *)handle - ports));
    return !((struct port *)handle)->netdev_down;
}
static int cdxdrv_get_fman_handles(struct cdx_fman_info *f, t_LnxWrpFmDev **wrapper)
{
    unsigned n = f - fman_info;
    if (f->pcd_handle != (void *)(uintptr_t)(n + 1)) return -EIO;
    f->pcd_handle = &wrappers[n]; f->fm_handle = &wrappers[n]; f->muram_handle = &wrappers[n];
    *wrapper = &wrappers[n]; return 0;
}
static int get_port_info(struct cdx_fman_info *f, void *user, unsigned n)
{
    (void)user;
    f->portinfo = kcalloc(2, sizeof(*f->portinfo), 0);
    if (!f->portinfo) return -ENOMEM;
    for (unsigned i = 0; i < 2; i++) {
        struct cdx_port_info *p = &f->portinfo[i];
        p->index = i ? 0 : 1; p->type = i ? 10 : 0; p->fm_index = n;
        snprintf(p->name, sizeof(p->name), "%u", n);
        p->max_dist = 1;
        p->dist_info = kcalloc(1, sizeof(*p->dist_info), 0);
        if (!p->dist_info) return -ENOMEM;
    }
    return 0;
}
static int get_cctbl_info(struct cdx_fman_info *f, void *user, unsigned n)
{
    (void)user; (void)n;
    f->tbl_info = kcalloc(1, sizeof(*f->tbl_info), 0);
    return f->tbl_info ? 0 : -ENOMEM;
}
int cdxdrv_init_stats(void *muram) { assert(muram && stopped()); stats = acquire(); return stats ? 0 : -ENOMEM; }
static int cdx_add_oh_iface(char *name)
{
    unsigned n = atoi(name); oh[n] = acquire(); return oh[n] ? 0 : -ENOMEM;
}
static int cdx_add_eth_onif(char *name)
{
    unsigned n = atoi(name);
    port_rate_lim_mode[n].port_handle = &ports[2 * n + 1]; slots++;
    if (cdx_dpa_init_fault()) return -EIO;
    eth[n] = acquire(); if (!eth[n]) return -ENOMEM;
    phy_port[n].flags = 1; phy_port[n].itf.index = n;
    return 0;
}
static void remove_onif_by_index(unsigned n)
{
    assert(stopped() && !queues && fman_info && stats && eth[n]);
    kfree(eth[n]); eth[n] = NULL;
}
static void dpa_release_iflist(void)
{
    assert(stopped() && !slots && !queues && fman_info && fman_info->muram_handle);
    for (unsigned i = 0; i < 2; i++) { assert(!eth[i]); kfree(oh[i]); oh[i] = NULL; }
    kfree(stats); stats = NULL;
}
static void cdx_destroy_fq(struct qman_fq *fq) { (void)fq; assert(stopped() && queues); queues--; }
static void cdx_drain_fq_list(struct dpa_fq *head)
{
    assert(stopped());
    for (struct dpa_fq *fq = head; fq; fq = (struct dpa_fq *)fq->list.next)
        fq->fq_base.id = 1;
}
static void cdx_destroy_fq_list(struct dpa_fq **head)
{
    while (*head) {
        struct dpa_fq *fq = *head;
        cdx_destroy_fq(&fq->fq_base);
        *head = (struct dpa_fq *)fq->list.next;
        kfree(fq);
    }
}
static void cdx_reset_offline_ports(void) { assert(!queues); }
static int cdx_create_port_fqs(void)
{
    for (unsigned i = 0; i < 4; i++) {
        struct dpa_fq *fq = kcalloc(1, sizeof(*fq), 0);
        if (!fq) return -ENOMEM;
        fq->list.next = (struct list_head *)dpa_pcd_fq; dpa_pcd_fq = fq; queues++;
        if (cdx_dpa_init_fault()) return -EIO;
    }
    return 0;
}
int cdxdrv_create_missaction_policer_profiles(struct cdx_fman_info *f)
{
    for (unsigned i = 0; i < CDX_EXPT_MAX_EXPT_LIMIT_TYPES; i++) {
        f->expt_rate_limit_info[i].handle = acquire();
        if (!f->expt_rate_limit_info[i].handle || cdx_dpa_init_fault()) return -ENOMEM;
    }
    return 0;
}
int cdxdrv_create_ingress_qos_policer_profiles(struct cdx_fman_info *f)
{
    for (unsigned i = 0; i < INGRESS_ALL_POLICER_QUEUES; i++) {
        f->ingress_policer_info[i].handle = acquire();
        if (!f->ingress_policer_info[i].handle || cdx_dpa_init_fault()) return -ENOMEM;
    }
    return 0;
}
/* The devlink instance reports both device-wide meters and programs them, so it
 * may exist only while their profiles do: registered once both are created,
 * unregistered before either is released. A registration that fails costs the
 * verb, not the configuration. */
static struct device fman_devices[2];
static bool devlink_live;
static unsigned devlink_attaches;
static int devlink_attach_rc;
static int cdx_devlink_attach(struct device *dev)
{
    assert(rtnl && cdx_info->ctrl.mutex && dpa_cfg_lock);
    assert(dev == &fman_devices[FMAN_INDEX] && !devlink_live);
    for (unsigned i = 0; i < CDX_EXPT_MAX_EXPT_LIMIT_TYPES; i++)
        assert(fman_info[FMAN_INDEX].expt_rate_limit_info[i].handle);
    for (unsigned i = 0; i < INGRESS_ALL_POLICER_QUEUES; i++)
        assert(fman_info[FMAN_INDEX].ingress_policer_info[i].handle);
    devlink_attaches++;
    devlink_live = !devlink_attach_rc;
    return devlink_attach_rc;
}
static void cdx_devlink_detach(void) { devlink_live = false; }
static int FM_PCD_PlcrProfileDelete(void *p)
{
    assert(stopped() && !devlink_live);
    kfree(p); int ret = fail_delete ? -EIO : 0; fail_delete = false; return ret;
}
static int FM_PORT_PcdPlcrFreeProfiles(void *p) { assert(!((struct port *)p)->enabled && slots); slots--; return 0; }
static int cdxdrv_set_miss_action(unsigned n) { (void)n; assert(stats && queues == 4); return 0; }
#include "cdx_policers.inc"
#include "cdx_startup.inc"

static void setup(void)
{
    assert(!fman_info && !live_allocs && !slots && !queues);
    alloc_step = step = copy_step = 0; unsafe_enable = false; restoring = false;
    memset(input, 0xa5, sizeof(input));
    for (unsigned i = 0; i < 2; i++) {
        input[i].pcd_handle = (void *)(uintptr_t)(i + 1);
        input[i].max_ports = 2; input[i].num_tables = 1; input[i].index = i;
        wrappers[i].id = i;
        wrappers[i].dev = &fman_devices[i];
        wrappers[i].opPorts[0] = (t_LnxWrpFmPortDev){ true, &ports[2 * i] };
        wrappers[i].rxPorts[2] = (t_LnxWrpFmPortDev){ true, &ports[2 * i + 1] };
        snprintf(wrappers[i].opPorts[0].name, sizeof(wrappers[i].opPorts[0].name), "fm%u-port-oh1", i);
        snprintf(wrappers[i].rxPorts[2].name, sizeof(wrappers[i].rxPorts[2].name), "fm%u-port-rx2", i);
        ports[2 * i] = (struct port){.enabled = !!(port_up_mask & (1U << (2 * i)))};
        ports[2 * i + 1] = (struct port){.enabled = !!(port_up_mask & (1U << (2 * i + 1)))};
    }
}
static void clean_success(void)
{
    /* The module/control exit hooks quiesce before the final config hook. */
    cdx_ctrl_lock_with_rtnl();
    assert(!dpa_cfg_quiesce() && stopped() && queues == 4);
    for (struct dpa_fq *fq = dpa_pcd_fq; fq; fq = (struct dpa_fq *)fq->list.next)
        assert(fq->fq_base.id == 1);
    assert(!dpa_cfg_quiesce());
    cdx_ctrl_unlock_with_rtnl();
    dpa_cfg_deinit();
    assert(!fman_info && !rtnl && !dpa_cfg_lock && !cdx_info->ctrl.mutex);
    assert(!devlink_live);
    for (unsigned i = 0; i < 4; i++)
        assert(ports[i].enabled == !!(port_up_mask & (1U << i)));
    assert(!live_allocs && !slots && !queues);
}
static void retry(void)
{
    assert(!fman_info && !live_allocs && !slots && !queues);
    assert(!cdx_info->ctrl.mutex && !dpa_cfg_lock && !rtnl && !devlink_live);
    assert(!unsafe_enable);
    for (unsigned i = 0; i < 4; i++)
        assert(ports[i].enabled == !!(port_up_mask & (1U << i)));
    fail_alloc = fail_step = fail_copy = 0;
    setup(); assert(!cdx_ioc_set_dpa_params((unsigned long)&request));
    assert(!unsafe_enable);
    assert(cdx_ioc_set_dpa_params((unsigned long)&request) == -EBUSY);
    clean_success();
}
/* The restartable stop, from a configured datapath. ports[0]/[2] are offline
 * ports, ports[1]/[3] Rx ports (setup()), all enabled by default. */
static int locked_stop(void)
{
    cdx_ctrl_lock_with_rtnl();
    int rc = dpa_cfg_stop();
    cdx_ctrl_unlock_with_rtnl();
    return rc;
}
static int locked_resume(void)
{
    cdx_ctrl_lock_with_rtnl();
    int rc = dpa_cfg_resume();
    cdx_ctrl_unlock_with_rtnl();
    return rc;
}
static void check_stop_resume(void)
{
    static struct port foreign;

    port_up_mask = 15;
    setup(); assert(!cdx_ioc_set_dpa_params((unsigned long)&request));
    /* A stop disables and fences every port and waits until none has a
     * frame in hand; nothing is detached or drained. An enable from anyone
     * else is refused while it holds. Stopping again changes nothing. */
    ports[2].busy = 3;
    assert(!locked_stop() && stopped() && dpa_active_ports.state == DPA_PORTS_STOPPED);
    for (unsigned i = 0; i < 4; i++)
        assert(ports[i].fenced && !ports[i].detached);
    assert(waits == 3 && !ports[2].busy);
    for (struct dpa_fq *fq = dpa_pcd_fq; fq; fq = (struct dpa_fq *)fq->list.next)
        assert(fq->fq_base.id != 1);
    unsigned refused = refused_enables;
    assert(FM_PORT_Enable(&ports[1]) == -EBUSY && !ports[1].enabled && refused_enables == refused + 1);
    assert(!locked_stop() && stopped());
    /* A port still finishing a frame after the bounded wait is reported
     * busy: disabled and fenced all the same, asked again later. */
    ports[0].busy = 1000; waits = 0;
    assert(locked_stop() == -EBUSY && stopped() && ports[0].fenced);
    assert(waits == DPA_STOP_WAIT_US / DPA_STOP_POLL_US && dpa_active_ports.state == DPA_PORTS_STOPPED);
    ports[0].busy = 0;
    assert(!locked_stop());
    /* A resume starts what the first stop found enabled: an Rx port only if
     * its netdev is still up. Every fence comes off. */
    ports[3].netdev_down = true;
    assert(!locked_resume() && dpa_active_ports.state == DPA_PORTS_RUNNING);
    assert(ports[0].enabled && ports[1].enabled && ports[2].enabled && !ports[3].enabled);
    for (unsigned i = 0; i < 4; i++)
        assert(!ports[i].fenced && !ports[i].detached);
    assert(!locked_resume() && !ports[3].enabled);
    /* What a stop records is what was enabled when the datapath first
     * stopped, however many stops follow it. */
    ports[3].netdev_down = false;
    assert(!locked_stop() && !locked_stop() && !locked_resume());
    assert(ports[0].enabled && ports[1].enabled && ports[2].enabled && !ports[3].enabled);
    /* A port that will not start is named -- its own name and, for a receive
     * port, its netdev's -- and counted; the others start all the same, its
     * fence comes off with theirs, and the ports count as running. Its netdev
     * restarts it. */
    ports[1].fail_enable = true;
    unsigned errors = dpa_errors;
    assert(!locked_stop() && locked_resume() == 1 && dpa_active_ports.state == DPA_PORTS_RUNNING);
    assert(dpa_errors == errors + 1 && strstr(dpa_error_line, "fm0-port-rx2 of eth1"));
    assert(ports[0].enabled && !ports[1].enabled && ports[2].enabled && !ports[1].fenced);
    ports[1].fail_enable = false;
    assert(!FM_PORT_Enable(&ports[1]) && ports[1].enabled);
    /* A port CDX did not configure that reaches a classifier: the stop
     * stops CDX's own ports but cannot vouch for the tables, and says so
     * apart from ports that only cannot be resumed. */
    foreign = (struct port){ .enabled = true, .pcd = true };
    wrappers[1].opPorts[1] = (t_LnxWrpFmPortDev){ true, &foreign };
    assert(locked_stop() == -EXDEV && stopped() && foreign.enabled && !dpa_cfg_covered());
    foreign.pcd = false;
    assert(!locked_stop() && dpa_cfg_covered() && !locked_resume());
    wrappers[1].opPorts[1] = (t_LnxWrpFmPortDev){ 0 };
    /* Quiesce after a stop detaches and drains, keeping what the stop
     * recorded; nothing resumes from there and no stop vouches for it. */
    ports[3].enabled = true;
    assert(!locked_stop());
    cdx_ctrl_lock_with_rtnl();
    assert(!dpa_cfg_quiesce() && dpa_active_ports.state == DPA_PORTS_QUIESCED);
    for (unsigned i = 0; i < 4; i++)
        assert(ports[i].detached && !ports[i].enabled);
    for (struct dpa_fq *fq = dpa_pcd_fq; fq; fq = (struct dpa_fq *)fq->list.next)
        assert(fq->fq_base.id == 1);
    assert(dpa_cfg_resume() == -ENOTRECOVERABLE && dpa_cfg_stop() == -ENOTRECOVERABLE);
    for (unsigned i = 0; i < 4; i++)
        assert(!ports[i].enabled);
    /* A foreign port reaching a classifier still says so once detached:
     * an unload settles nothing it could walk to. */
    foreign = (struct port){ .enabled = true, .pcd = true };
    wrappers[0].opPorts[1] = (t_LnxWrpFmPortDev){ true, &foreign };
    assert(dpa_cfg_stop() == -EXDEV && !ports[0].enabled);
    cdx_ctrl_unlock_with_rtnl();
    assert(!dpa_cfg_covered());
    wrappers[0].opPorts[1] = (t_LnxWrpFmPortDev){ 0 };
    /* Unload takes the fences off and gives the stack its ports back, but
     * not an Rx port whose netdev went down while they were stopped. */
    ports[1].netdev_down = true;
    dpa_cfg_deinit();
    for (unsigned i = 0; i < 4; i++)
        assert(ports[i].enabled == (i != 1) && !ports[i].fenced);
    assert(!fman_info && !live_allocs && !slots && !queues);
    /* Ports a failed setup could not detach (cdx_ioc_set_dpa_params()'s
     * -EUCLEAN arm) are never resumed either. */
    setup(); assert(!cdx_ioc_set_dpa_params((unsigned long)&request));
    dpa_active_ports.state = DPA_PORTS_DETACHING;
    assert(locked_stop() == -ENOTRECOVERABLE && stopped() && locked_resume() == -ENOTRECOVERABLE);
    clean_success();
    /* A setup that finds a foreign port with a classifier says so once. */
    foreign = (struct port){ .enabled = true, .pcd = true };
    wrappers[0].rxPorts[0] = (t_LnxWrpFmPortDev){ true, &foreign };
    unsigned warned = coverage_warnings;
    setup(); assert(!cdx_ioc_set_dpa_params((unsigned long)&request));
    assert(coverage_warnings == warned + 1);
    wrappers[0].rxPorts[0] = (t_LnxWrpFmPortDev){ 0 };
    clean_success();
}

int main(void)
{
    /* The FMAN count is bounded before any lock, allocation or hardware
     * work: zero leaves fman_info unset for code that dereferences it, and
     * a count past CDX_MAX_FMANS overruns the per-FMAN wrapper array. */
    static const unsigned bad_counts[] = { 0, CDX_MAX_FMANS + 1, 10000, 0xffffffffu };
    for (unsigned i = 0; i < ARRAY_SIZE(bad_counts); i++) {
        setup(); request.num_fmans = bad_counts[i]; rtnl_locks = 0;
        assert(cdx_ioc_set_dpa_params((unsigned long)&request) == -EINVAL);
        assert(copy_step == 1 && !alloc_step && !step && !rtnl_locks);
        assert(!fman_info && !live_allocs && !cdx_info->ctrl.mutex && !rtnl);
    }
    request.num_fmans = 2;

    /* Claim can seal configuration while an already validated ioctl waits
     * for the control transaction. Drop RTNL to let that claimant run, then
     * recheck ownership before any allocation or hardware work. */
    setup(); seal_on_lock = true; lock_contention = 3;
    assert(cdx_ioc_set_dpa_params((unsigned long)&request) == -EOPNOTSUPP);
    assert(!cdx_info->ctrl.mutex && !rtnl && !live_allocs && !fman_info);
    assert(!step && !alloc_step);
    assert(lock_waits == 3 && !lock_contention);
    seal_on_lock = config_sealed = false;
    setup(); lock_contention = 2;
    assert(!cdx_ioc_set_dpa_params((unsigned long)&request));
    assert(lock_waits == 5 && !lock_contention);
    unsigned allocations = alloc_step, steps = step;
    assert(!unsafe_enable && devlink_live && devlink_attaches == 1); clean_success();
    /* A registration that fails is reported, and the ports are configured
     * all the same; the unwind then has nothing registered to take down. */
    setup(); devlink_attach_rc = -ENOMEM;
    assert(!cdx_ioc_set_dpa_params((unsigned long)&request) && !devlink_live);
    devlink_attach_rc = 0; clean_success();
    for (unsigned n = 1; n <= allocations; n++) {
        setup(); fail_alloc = n;
        assert(cdx_ioc_set_dpa_params((unsigned long)&request));
        retry();
    }
    for (unsigned n = 1; n <= steps; n++) {
        setup(); fail_step = n;
        assert(cdx_ioc_set_dpa_params((unsigned long)&request));
        retry();
    }
    for (unsigned n = 1; n <= 2; n++) {
        setup(); fail_copy = n;
        assert(cdx_ioc_set_dpa_params((unsigned long)&request));
        retry();
    }
    setup(); input[1].pcd_handle = (void *)0xdead;
    assert(cdx_ioc_set_dpa_params((unsigned long)&request)); retry();
    setup(); fail_step = steps; fail_delete = true;
    assert(cdx_ioc_set_dpa_params((unsigned long)&request) == -EUCLEAN);
    retry();
    for (port_up_mask = 0; port_up_mask < 16; port_up_mask++) {
        setup(); assert(!cdx_ioc_set_dpa_params((unsigned long)&request));
        for (unsigned i = 0; i < 4; i++)
            assert(ports[i].enabled == !!(port_up_mask & (1U << i)));
        /* Stack changes after SET_PARAMS are the state unload must restore. */
        port_up_mask ^= 15;
        for (unsigned i = 0; i < 4; i++)
            ports[i].enabled = !!(port_up_mask & (1U << i));
        clean_success();
        port_up_mask ^= 15;
        setup(); fail_step = steps;
        assert(cdx_ioc_set_dpa_params((unsigned long)&request));
        retry();
    }
    check_stop_resume();
    printf("CDX startup fault points passed: %u allocations, %u stages, partial copies and retry; "
           "restartable stop and resume\n", allocations, steps);
    return 0;
}
