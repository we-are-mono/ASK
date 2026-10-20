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
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, value) ((x) = (value))
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
typedef uint32_t u32;

#define FMAN_INDEX 0
/* A port as the SDK keeps it: enabled, detached from its PCD, fenced against
 * enables, still finishing frames for so many more looks, given a PCD of its
 * own (for a port CDX did not configure), and whether the netdev owning an Rx
 * port is up. And a datapath restart's software mode: frames sent past the PCD
 * it keeps, and a bypass that fails, that takes only the entry register, or a
 * PCD that will not come back. */
struct port { bool enabled, detached, fenced, pcd, netdev_down, fail_enable;
              bool bypassed, fail_bypass, half_bypass, fail_attach; unsigned busy; };
struct device { unsigned id; };
typedef struct { bool active; t_Handle h_Dev; char name[20]; int icid; } t_LnxWrpFmPortDev;
/* The ICID each port's FMBM_SPLIODN holds, and each CPU's portal FICID. */
struct fm_port;
static int fm_port_get_icid(struct fm_port *port) { return ((t_LnxWrpFmPortDev *)port)->icid; }
#define FIXTURE_ICID 63
#define FIXTURE_CPUS 4
static int portal_ficid[FIXTURE_CPUS];
static const void *qman_affine_cpus(void) { return portal_ficid; }
#define for_each_cpu(cpu, mask) for ((void)(mask), (cpu) = 0; (cpu) < FIXTURE_CPUS; (cpu)++)
static uint16_t qman_affine_channel(unsigned cpu) { return 0x400 + cpu; }
static int qman_portal_ficid(uint16_t channel) { return portal_ficid[channel - 0x400]; }
#define IFNAMSIZ 16
typedef struct {
    unsigned id;
    t_LnxWrpFmPortDev opPorts[3], rxPorts[4];
    void *h_Dev, *h_PcdDev, *h_MuramDev;
    uint64_t fmMuramPhysBaseAddr; unsigned fmMuramMemSize;
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
static unsigned lock_contention, lock_waits, rtnl_locks;
static unsigned port_up_mask = 15;
static struct { struct { int mutex; } ctrl; } cdx_instance, *cdx_info = &cdx_instance;
static void rtnl_lock(void) { assert(!rtnl && !cdx_info->ctrl.mutex); rtnl = 1; rtnl_locks++; }
static void rtnl_unlock(void) { assert(rtnl); rtnl = 0; }
#define FIXTURE_PORTS 4
#define CDX_PCD_NUM_GROUPS 21
#define CDX_PCD_SHARED_GROUPS 14
#define CDX_PCD_SEC_GROUPS 7
#define CDX_PCD_TUPLE_COUNT 4
#define CDX_PCD_TUPLE_FIRST 8
#define CDX_PCD_NUM_SCHEMES 25
#define CDX_PCD_MAX_PORTS 16
#define CDX_PCD_MAX_NUM_OF_KEYS 512
struct cdx_pcd_group {
    const char *table_name;
    unsigned short key_size, hash_res_mask;
    unsigned char table_type;
    unsigned char tunnel_family;
    const char *scheme_name;
    unsigned base_fqid;
    unsigned short num_fqids;
    unsigned char dist_type;
};
/* Only the fields dpa_cfg_publish() reads; the real table lives in
 * cdx_pcd_desc.c and is covered by test_cdx_pcd_build. */
static const struct cdx_pcd_group cdx_pcd_groups[CDX_PCD_NUM_GROUPS] = {
    [0 ... CDX_PCD_NUM_GROUPS - 1] = { .table_name = "t", .key_size = 14,
        .hash_res_mask = 0x7fff, .scheme_name = "s", .base_fqid = 0x1000, .num_fqids = 1 },
    [8 ... 11] = { .table_name = "t", .key_size = 56, .hash_res_mask = 0x7fff,
        .scheme_name = "s", .base_fqid = 0x1000, .num_fqids = 1, .tunnel_family = 4 },
};
struct cdx_pcd_port_state { void *h_port, *tables[CDX_PCD_NUM_GROUPS];
                            unsigned num_tables, first_group; void *cctree;
                            bool was_enabled, pcd_set; };
struct cdx_pcd_port { unsigned type, fm_index, number, portid, speed;
                      char name[CDX_CTRL_PORT_NAME_LEN]; };
struct cdx_pcd_state {
    unsigned char fm_index;
    void *fm_dev, *h_fm, *h_pcd, *net_env, *schemes[CDX_PCD_NUM_SCHEMES];
    unsigned num_schemes, num_ports;
    struct cdx_pcd_port ports[CDX_PCD_MAX_PORTS];
    struct cdx_pcd_port_state port_state[CDX_PCD_MAX_PORTS];
};
static t_LnxWrpFmDev wrappers[2];
static struct port ports[4];
static unsigned alloc_step, fail_alloc, live_allocs, step, fail_step;
static void *stats, *oh[2], *eth[MAX_PHY_PORTS];
static unsigned slots, queues;
static bool restoring, unsafe_enable, fail_delete;
/* Whether a policer profile exists for the reconcile work to rewrite, and how
 * often that work was stopped. */
static bool plcr_retry_live;
static unsigned plcr_retry_stops;

static void mutex_lock(int *lock)
{
    if (lock == &cdx_info->ctrl.mutex) { assert(!rtnl); lock_waits++; }
    assert(!*lock); *lock = 1;
}
static int mutex_trylock(int *lock)
{
    assert(lock == &cdx_info->ctrl.mutex && rtnl && !*lock);
    if (lock_contention) { lock_contention--; return 0; }
    *lock = 1;
    return 1;
}
static void mutex_unlock(int *lock) { assert(*lock); *lock = 0; }
/* The flowtable's transaction is the control mutex. */
static void cdx_ft_begin(void) { mutex_lock(&cdx_info->ctrl.mutex); }
static void cdx_ft_end(void) { mutex_unlock(&cdx_info->ctrl.mutex); }
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
bool cdx_dpa_init_fault_at(const char *site) { (void)site; return ++step == fail_step; }
static bool stopped(void)
{
    for (unsigned i = 0; i < 4; i++) if (ports[i].enabled) return false;
    return true;
}
static int FM_PORT_GetEnabled(void *p, bool *enabled)
{ assert(rtnl); *enabled = ((struct port *)p)->enabled; return 0; }
/* A detach ends a bypass too: there is no PCD left to go past. */
static int FM_PORT_DetachPCD(void *p)
{
    assert(!((struct port *)p)->enabled);
    ((struct port *)p)->detached = true;
    ((struct port *)p)->bypassed = false;
    return 0;
}
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
/* A port of CDX's own has its PCD until it is detached, or while it is
 * bypassed; one CDX did not configure has whatever a case gives it. */
static bool own_port(const void *p) { return p >= (void *)ports && p < (void *)(ports + 4); }
static int FM_PORT_IsPcdAttached(void *p, bool *attached)
{
    struct port *port = p;

    *attached = own_port(p) ? !port->detached && !port->bypassed : port->pcd;
    return 0;
}
/* The SDK switches a port past its PCD and back only while it takes no frame:
 * disabled, and for taking the PCD back seen idle too. A bypass of a port still
 * finishing one is the caller's risk, which it has to prove settled later. */
static unsigned bypass_calls;
static int FM_PORT_BypassPCD(void *p, bool bypass)
{
    struct port *port = p;

    assert(own_port(p) && !port->enabled && !port->detached && (bypass || !port->busy));
    bypass_calls++;
    if (bypass ? port->fail_bypass : port->fail_attach)
        return -EIO;
    port->bypassed = bypass;
    return bypass && port->half_bypass ? -EIO : 0;
}
/* A port's BMI discard count: which port was read, under the lock that keeps
 * the port list. */
enum { e_FM_PORT_COUNTERS_WRED_DISCARD = 9 };
static uint32_t FM_PORT_GetCounter(void *p, int counter)
{
    assert(counter == e_FM_PORT_COUNTERS_WRED_DISCARD && dpa_cfg_lock);
    return 0x1000 + (uint32_t)((struct port *)p - ports);
}
static unsigned waits;
static void usleep_range(unsigned min, unsigned max) { assert(min && max >= min); waits++; }
#define ASSERT_RTNL() assert(rtnl)
static bool dpa_rx_port_wanted(t_Handle handle, char name[IFNAMSIZ])
{
    assert(rtnl);
    snprintf(name, IFNAMSIZ, "eth%u", (unsigned)((struct port *)handle - ports));
    return !((struct port *)handle)->netdev_down;
}
/* A netdev, and the Rx port it receives on: none for a device not DPAA's. */
struct net_device { struct port *rx; };
static t_Handle dpa_netdev_rx_port(const struct net_device *dev)
{
    assert(rtnl);
    return dev->rx;
}
static bool pcd_built;
static int cdx_pcd_build(uint8_t fm_index, struct cdx_pcd_state *state)
{
    state->fm_index = fm_index;
    state->fm_dev = &wrappers[0];
    state->h_fm = state->h_pcd = &wrappers[0];
    state->num_ports = FIXTURE_PORTS;
    for (unsigned i = 0; i < FIXTURE_PORTS; i++) {
        state->ports[i].fm_index = fm_index;
        state->ports[i].number = i % 2 ? i / 2 : i / 2 + 1;
        state->ports[i].portid = i;
        state->ports[i].speed = i % 2 ? 10 : 0;
        snprintf(state->ports[i].name, sizeof(state->ports[i].name), "%u", i / 2);
        state->port_state[i].h_port = &ports[i];
        state->port_state[i].num_tables = i ? CDX_PCD_SHARED_GROUPS : CDX_PCD_SEC_GROUPS;
        state->port_state[i].first_group = i ? 0 : CDX_PCD_SHARED_GROUPS;
        for (unsigned g = 0; g < state->port_state[i].num_tables; g++)
            state->port_state[i].tables[g] = &ports[i];
    }
    for (unsigned i = 0; i < CDX_PCD_NUM_SCHEMES; i++) state->schemes[i] = state;
    pcd_built = true;
    return 0;
}
static void cdx_pcd_teardown(struct cdx_pcd_state *state)
{
    (void)state;
    for (unsigned i = 0; i < FIXTURE_PORTS; i++) ports[i].detached = true;
    pcd_built = false;
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
    plcr_retry_live = true;
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
        plcr_retry_live = true;
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
/* The work that rewrites a profile whose write did not land runs while any
 * profile exists, so it is stopped before one is released, whichever way the
 * configuration goes; nothing restarts it. */
static void cdx_plcr_reconcile_stop(void) { plcr_retry_live = false; plcr_retry_stops++; }
static int FM_PCD_PlcrProfileDelete(void *p)
{
    assert(stopped() && !devlink_live && !plcr_retry_live);
    kfree(p); int ret = fail_delete ? -EIO : 0; fail_delete = false; return ret;
}
static int FM_PORT_PcdPlcrFreeProfiles(void *p)
{
    assert(!((struct port *)p)->enabled && slots && !plcr_retry_live);
    slots--;
    return 0;
}
static int cdxdrv_set_miss_action(unsigned n) { (void)n; assert(stats && queues == 4); return 0; }
#define CDX_DPA_TBL_EXTERNAL_HASH 1
#define CDX_EXPT_ETH_DEFA_LIMIT 195312
#define CDX_EXPT_RATELIM_MODE EXPT_PKT_LIM_PLCR_MODE_PKT
#define CDX_EXPT_BURST_SIZE 64
static void *kzalloc(size_t size, int flags) { return kcalloc(1, size, flags); }
static void strscpy(char *dst, const char *src, size_t size) { snprintf(dst, size, "%s", src); }
#include "cdx_policers.inc"
/* /proc/cdx_pcd_schemes, a diagnostic the harness has no reader for. */
struct proc_dir_entry;
static struct proc_dir_entry *dpa_cfg_schemes_proc;
#define proc_create_single(name, mode, parent, show) ((struct proc_dir_entry *)NULL)
static void proc_remove(struct proc_dir_entry *e) { (void)e; }
#include "cdx_startup.inc"

static void setup(void)
{
    assert(!fman_info && !live_allocs && !slots && !queues);
    alloc_step = step = 0; unsafe_enable = false; restoring = false; pcd_built = false;
    wrappers[0].id = 0;
    wrappers[0].dev = &fman_devices[0];
    wrappers[0].h_Dev = wrappers[0].h_PcdDev = wrappers[0].h_MuramDev = &wrappers[0];
    for (unsigned i = 0; i < 2; i++) {
        wrappers[0].opPorts[i] = (t_LnxWrpFmPortDev){ true, &ports[2 * i] };
        wrappers[0].rxPorts[2 + i] = (t_LnxWrpFmPortDev){ true, &ports[2 * i + 1] };
        snprintf(wrappers[0].opPorts[i].name, sizeof(wrappers[0].opPorts[i].name), "fm0-port-oh%u", i + 1);
        snprintf(wrappers[0].rxPorts[2 + i].name, sizeof(wrappers[0].rxPorts[2 + i].name), "fm0-port-rx%u", 2 + i);
        wrappers[0].opPorts[i].icid = wrappers[0].rxPorts[2 + i].icid = FIXTURE_ICID;
        ports[2 * i] = (struct port){.enabled = !!(port_up_mask & (1U << (2 * i)))};
        ports[2 * i + 1] = (struct port){.enabled = !!(port_up_mask & (1U << (2 * i + 1)))};
    }
    for (unsigned i = 0; i < FIXTURE_CPUS; i++)
        portal_ficid[i] = FIXTURE_ICID;
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
    unsigned stops = plcr_retry_stops;
    dpa_cfg_deinit();
    assert(!fman_info && !rtnl && !dpa_cfg_lock && !cdx_info->ctrl.mutex);
    assert(!devlink_live && !plcr_retry_live && plcr_retry_stops > stops);
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
    fail_alloc = fail_step = 0;
    setup(); assert(!dpa_cfg_install());
    assert(!unsafe_enable);
    assert(dpa_cfg_install() == -EBUSY);
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
    setup(); assert(!dpa_cfg_install());
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
    wrappers[0].opPorts[2] = (t_LnxWrpFmPortDev){ true, &foreign };
    assert(locked_stop() == -EXDEV && stopped() && foreign.enabled && !dpa_cfg_covered());
    foreign.pcd = false;
    assert(!locked_stop() && dpa_cfg_covered() && !locked_resume());
    wrappers[0].opPorts[2] = (t_LnxWrpFmPortDev){ 0 };
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
    wrappers[0].opPorts[2] = (t_LnxWrpFmPortDev){ true, &foreign };
    assert(dpa_cfg_stop() == -EXDEV && !ports[0].enabled);
    cdx_ctrl_unlock_with_rtnl();
    assert(!dpa_cfg_covered());
    wrappers[0].opPorts[2] = (t_LnxWrpFmPortDev){ 0 };
    /* Unload takes the fences off and gives the stack its ports back, but
     * not an Rx port whose netdev went down while they were stopped. */
    ports[1].netdev_down = true;
    dpa_cfg_deinit();
    for (unsigned i = 0; i < 4; i++)
        assert(ports[i].enabled == (i != 1) && !ports[i].fenced);
    assert(!fman_info && !live_allocs && !slots && !queues);
    /* Ports a failed setup could not detach (dpa_cfg_install()'s
     * -EUCLEAN arm) are never resumed either. */
    setup(); assert(!dpa_cfg_install());
    dpa_active_ports.state = DPA_PORTS_DETACHING;
    assert(locked_stop() == -ENOTRECOVERABLE && stopped() && locked_resume() == -ENOTRECOVERABLE);
    clean_success();
    /* A setup that finds a foreign port with a classifier says so once. */
    foreign = (struct port){ .enabled = true, .pcd = true };
    wrappers[0].rxPorts[0] = (t_LnxWrpFmPortDev){ true, &foreign };
    unsigned warned = coverage_warnings;
    setup(); assert(!dpa_cfg_install());
    assert(coverage_warnings == warned + 1);
    wrappers[0].rxPorts[0] = (t_LnxWrpFmPortDev){ 0 };
    clean_success();
}

static int locked_bypass(unsigned *held)
{
    cdx_ctrl_lock_with_rtnl();
    int rc = dpa_cfg_bypass(held);
    cdx_ctrl_unlock_with_rtnl();
    return rc;
}
static int locked_unbypass(void)
{
    cdx_ctrl_lock_with_rtnl();
    int rc = dpa_cfg_unbypass();
    cdx_ctrl_unlock_with_rtnl();
    return rc;
}
static bool all(bool (*test)(const struct port *))
{
    for (unsigned i = 0; i < 4; i++)
        if (!test(&ports[i]))
            return false;
    return true;
}
/* Whether the netdev guard is told to refuse the open of a netdev on this
 * port, or on no DPAA port at all (NULL). */
static bool port_held(struct port *rx)
{
    struct net_device dev = { .rx = rx };

    rtnl_lock();
    bool held = dpa_cfg_port_held(&dev);
    rtnl_unlock();
    return held;
}
/* Forwarding in software: past the PCD, running, open to its netdev. */
static bool soft(const struct port *p) { return p->bypassed && p->enabled && !p->fenced && !p->detached; }
/* Stopped with its PCD, for a resume. */
static bool held_back(const struct port *p) { return !p->bypassed && !p->enabled && p->fenced && !p->detached; }
/* Running with its PCD, as before any of it. */
static bool classifying(const struct port *p) { return !p->bypassed && p->enabled && !p->fenced && !p->detached; }

/* A datapath restart's software mode, between its stop and its resume: every
 * port past its PCD, which it keeps, and forwarding to Linux. ports[0]/[2] are
 * offline ports, ports[1]/[3] Rx ports (setup()). */
static void check_bypass(void)
{
    unsigned held = 99, errors, looks;

    port_up_mask = 15;
    setup(); assert(!dpa_cfg_install());
    /* Only from a stop: a running port is never switched under its frames. */
    assert(locked_bypass(&held) == -EINVAL && !dpa_cfg_bypassed() && all(classifying));
    /* After one, every port goes past its PCD and starts again as a resume
     * would start it -- an Rx port whose netdev went down stays down -- with
     * the fence off, so its netdev's own open works as it would without CDX.
     * Nothing is detached or drained. */
    assert(!locked_stop());
    ports[3].netdev_down = true;
    assert(locked_bypass(&held) == 0 && !held && dpa_cfg_bypassed());
    assert(dpa_active_ports.state == DPA_PORTS_BYPASSED);
    assert(soft(&ports[0]) && soft(&ports[1]) && soft(&ports[2]));
    assert(ports[3].bypassed && !ports[3].enabled && !ports[3].fenced);
    for (struct dpa_fq *fq = dpa_pcd_fq; fq; fq = (struct dpa_fq *)fq->list.next)
        assert(fq->fq_base.id != 1);
    ports[3].netdev_down = false;
    assert(!FM_PORT_Enable(&ports[3]) && all(soft));
    /* Neither a stop nor a resume applies: only the unbypass gives the
     * classifier back. A bypass again changes nothing. */
    assert(locked_stop() == -EINVAL && locked_resume() == -EINVAL && all(soft));
    unsigned calls = bypass_calls;
    assert(locked_bypass(&held) == 0 && !held && all(soft) && bypass_calls == calls);
    /* Giving it back stops every port as a stop does, waiting out a frame in
     * hand, and then each takes its PCD back; a resume then starts what ran
     * meanwhile, the port its netdev opened included. */
    ports[1].busy = 2; waits = 0;
    assert(!locked_unbypass() && dpa_active_ports.state == DPA_PORTS_STOPPED);
    assert(!dpa_cfg_bypassed() && waits == 2 && all(held_back));
    assert(!locked_resume() && dpa_active_ports.state == DPA_PORTS_RUNNING && all(classifying));
    /* A netdev taken down while they were bypassed keeps its port down: the
     * unbypass records what ran then. */
    assert(!locked_stop() && locked_bypass(&held) == 0 && all(soft));
    assert(!FM_PORT_Disable(&ports[1]));
    assert(!locked_unbypass() && !locked_resume());
    assert(!ports[1].enabled && classifying(&ports[0]) && classifying(&ports[2]) && classifying(&ports[3]));
    assert(!FM_PORT_Enable(&ports[1]) && all(classifying));
    /* A port still finishing a frame when the unbypass waits for it, or one
     * that will not take its PCD back: every port goes back past its PCD and
     * starts again, and the caller asks later. */
    assert(!locked_stop() && locked_bypass(&held) == 0);
    ports[2].busy = 1000;
    assert(locked_unbypass() == -EBUSY && dpa_cfg_bypassed() && all(soft));
    ports[2].busy = 0;
    ports[1].fail_attach = true;
    assert(locked_unbypass() == -EIO && dpa_cfg_bypassed() && all(soft));
    ports[1].fail_attach = false;
    assert(!locked_unbypass() && !locked_resume() && all(classifying));
    /* A port still busy when the stop gave up on it is bypassed all the same,
     * and so is every other, so the datapath forwards in software; the count
     * of ports not yet seen idle says the tables may still be walked. A later
     * bypass stops that port alone again, briefly, to look, and starts it
     * again; once seen idle nothing stops it to look any more. */
    ports[1].busy = 1000;
    assert(locked_stop() == -EBUSY);
    assert(locked_bypass(&held) == 1 && !held && dpa_cfg_bypassed() && all(soft));
    waits = 0;
    assert(locked_bypass(&held) == 1 && waits == DPA_STOP_WAIT_US / DPA_STOP_POLL_US && all(soft));
    ports[1].busy = 0;
    assert(locked_bypass(&held) == 0 && all(soft));
    looks = stopped_looks;
    assert(locked_bypass(&held) == 0 && stopped_looks == looks && all(soft));
    assert(!locked_unbypass() && !locked_resume() && all(classifying));
    /* A port whose bypass fails stays stopped, fenced against its netdev's
     * open, named once however often it is tried again; the others proceed.
     * The netdev guard is told which port that is, to refuse the open itself
     * and say why. A bypass that took the port's entry though the rest failed
     * counts as done: its frames go past the PCD. The unbypass leaves the held
     * port as the stop did, for the resume to start with the others. */
    errors = dpa_errors;
    assert(!locked_stop());
    assert(!port_held(&ports[3]));
    ports[3].fail_bypass = ports[1].half_bypass = true;
    assert(locked_bypass(&held) == 0 && held == 1);
    assert(held_back(&ports[3]) && soft(&ports[0]) && soft(&ports[1]) && soft(&ports[2]));
    assert(dpa_errors == errors + 1 && strstr(dpa_error_line, "fm0-port-rx3"));
    assert(port_held(&ports[3]) && !port_held(&ports[1]) && !port_held(NULL));
    assert(locked_bypass(&held) == 0 && held == 1 && dpa_errors == errors + 1);
    assert(!locked_unbypass() && all(held_back) && !locked_resume() && all(classifying));
    assert(!port_held(&ports[3]));
    /* Tried again, and taken: it runs in software with the rest. */
    assert(!locked_stop() && locked_bypass(&held) == 0 && held == 1 && held_back(&ports[3]));
    ports[3].fail_bypass = ports[1].half_bypass = false;
    assert(locked_bypass(&held) == 0 && !held && all(soft) && !port_held(&ports[3]));
    /* Unload from a bypassed datapath detaches as from any other, and
     * nothing bypasses or unbypasses after. One that finds a port still
     * busy leaves them all forwarding in software for its next try, which
     * records what runs then rather than what it stopped. */
    cdx_ctrl_lock_with_rtnl();
    ports[0].busy = 1000;
    assert(dpa_cfg_quiesce() == -EBUSY && dpa_cfg_bypassed() && all(soft));
    ports[0].busy = 0;
    assert(!dpa_cfg_quiesce() && dpa_active_ports.state == DPA_PORTS_QUIESCED && !dpa_cfg_bypassed());
    for (unsigned i = 0; i < 4; i++)
        assert(ports[i].detached && !ports[i].enabled && !ports[i].bypassed);
    assert(dpa_cfg_bypass(&held) == -ENOTRECOVERABLE && dpa_cfg_unbypass() == -ENOTRECOVERABLE);
    cdx_ctrl_unlock_with_rtnl();
    dpa_cfg_deinit();
    for (unsigned i = 0; i < 4; i++)
        assert(ports[i].enabled && !ports[i].fenced);
    assert(!fman_info && !live_allocs && !slots && !queues);
}

/* IPsec offload needs every classifier port and every CPU's portal to enqueue
 * with one ICID. Ports CDX did not configure do not count; one CDX configured
 * that differs, or whose ICID cannot be read, or one portal that differs, is a
 * refusal. */
static void check_shared_icid(void)
{
    static struct port spare;

    port_up_mask = 15;
    setup(); assert(!dpa_cfg_install());
    assert(dpa_cfg_shared_icid() == FIXTURE_ICID);
    portal_ficid[FIXTURE_CPUS - 1] = 0;
    assert(dpa_cfg_shared_icid() == -EINVAL);
    clean_success();
    setup(); wrappers[0].rxPorts[0] = (t_LnxWrpFmPortDev){ true, &spare, "fm0-port-rx0", 0 };
    assert(!dpa_cfg_install() && dpa_cfg_shared_icid() == FIXTURE_ICID);
    wrappers[0].rxPorts[0] = (t_LnxWrpFmPortDev){ 0 };
    clean_success();
    setup(); wrappers[0].rxPorts[3].icid = 0;
    assert(!dpa_cfg_install() && dpa_cfg_shared_icid() == -EINVAL);
    clean_success();
    setup(); wrappers[0].opPorts[0].icid = -EIO;
    assert(!dpa_cfg_install() && dpa_cfg_shared_icid() == -EIO);
    clean_success();
    assert(!dpa_cfg_lock);
}

/* A described port's discard count comes from the port the install resolved
 * for it: the list and the description are walked in step. */
static void check_port_rejected(void)
{
    uint32_t count = 0;

    assert(dpa_cfg_port_rejected(0, &count) == -ENODEV && !count);
    setup(); assert(!dpa_cfg_install());
    for (unsigned id = 0; id < FIXTURE_PORTS; id++) {
        assert(!dpa_cfg_port_rejected(id, &count));
        assert(count == 0x1000 + id);
    }
    count = 0;
    assert(dpa_cfg_port_rejected(FIXTURE_PORTS, &count) == -ENODEV && !count);
    assert(!dpa_cfg_lock);
    clean_success();
    assert(dpa_cfg_port_rejected(0, &count) == -ENODEV);
}

int main(void)
{
    setup(); lock_contention = 2;
    assert(!dpa_cfg_install());
    assert(lock_waits == 2 && !lock_contention);
    unsigned allocations = alloc_step, steps = step;
    assert(!unsafe_enable && devlink_live && devlink_attaches == 1); clean_success();
    /* A registration that fails is reported, and the ports are configured
     * all the same; the unwind then has nothing registered to take down. */
    setup(); devlink_attach_rc = -ENOMEM;
    assert(!dpa_cfg_install() && !devlink_live);
    devlink_attach_rc = 0; clean_success();
    for (unsigned n = 1; n <= allocations; n++) {
        setup(); fail_alloc = n;
        assert(dpa_cfg_install());
        retry();
    }
    for (unsigned n = 1; n <= steps; n++) {
        setup(); fail_step = n;
        assert(dpa_cfg_install());
        retry();
    }
    setup(); fail_step = steps; fail_delete = true;
    assert(dpa_cfg_install() == -EUCLEAN);
    retry();
    for (port_up_mask = 0; port_up_mask < 16; port_up_mask++) {
        setup(); assert(!dpa_cfg_install());
        for (unsigned i = 0; i < 4; i++)
            assert(ports[i].enabled == !!(port_up_mask & (1U << i)));
        /* Stack changes after startup are the state unload must restore. */
        port_up_mask ^= 15;
        for (unsigned i = 0; i < 4; i++)
            ports[i].enabled = !!(port_up_mask & (1U << i));
        clean_success();
        port_up_mask ^= 15;
        setup(); fail_step = steps;
        assert(dpa_cfg_install());
        retry();
    }
    check_stop_resume();
    check_bypass();
    check_shared_icid();
    check_port_rejected();
    printf("CDX startup fault points passed: %u allocations, %u stages and retry; "
           "restartable stop, bypass and resume\n", allocations, steps);
    return 0;
}
