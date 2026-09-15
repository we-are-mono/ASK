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
#define DPA_ERROR(...) do { } while (0)
#define pr_err(...) do { } while (0)
#define display_dpa_cfg() do { } while (0)
typedef void *t_Handle;
typedef int t_Error;

struct port { bool enabled, detached; };
typedef struct { bool active; t_Handle h_Dev; } t_LnxWrpFmPortDev;
typedef unsigned char u8;
typedef struct {
    unsigned id;
    void *h_Dev, *h_PcdDev, *h_MuramDev;
    unsigned long long fmMuramPhysBaseAddr;
    unsigned fmMuramMemSize;
    t_LnxWrpFmPortDev opPorts[2], rxPorts[4];
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
static unsigned port_up_mask = 15;
static struct { struct { int mutex; } ctrl; } cdx_instance, *cdx_info = &cdx_instance;
static void rtnl_lock(void) { assert(!rtnl && cdx_info->ctrl.mutex); rtnl = 1; }
static void rtnl_unlock(void) { assert(rtnl); rtnl = 0; }
/* One FMan with an offline and an ethernet port: dpa_cfg_install() builds a
 * single engine, so the two-engine request the ioctl used to carry is gone. */
#define FIXTURE_PORTS 2
#define CDX_PCD_NUM_GROUPS 12
#define CDX_PCD_MAX_PORTS 16
#define CDX_PCD_MAX_NUM_OF_KEYS 512
struct cdx_pcd_group {
    const char *table_name;
    unsigned short key_size, hash_res_mask;
    unsigned char table_type;
    const char *scheme_name;
    unsigned base_fqid;
    unsigned short num_fqids;
    unsigned char dist_type;
};
/* Only the fields dpa_cfg_publish() reads; the real table lives in
 * cdx_pcd_desc.c and is covered by test_cdx_pcd_build. */
static const struct cdx_pcd_group cdx_pcd_groups[CDX_PCD_NUM_GROUPS] = {
    [0 ... CDX_PCD_NUM_GROUPS - 1] = { "t", 14, 0x7fff, 0, "s", 0x1000, 1, 0 },
};
struct cdx_pcd_port_state { void *h_port, *tables[CDX_PCD_NUM_GROUPS];
                            unsigned num_tables; void *cctree;
                            bool was_enabled, pcd_set; };
struct cdx_pcd_port { unsigned type, fm_index, number, portid, speed;
                      char name[CDX_CTRL_PORT_NAME_LEN]; };
struct cdx_pcd_state {
    unsigned char fm_index;
    void *fm_dev, *h_fm, *h_pcd, *net_env, *schemes[CDX_PCD_NUM_GROUPS];
    unsigned num_schemes, num_ports;
    struct cdx_pcd_port ports[CDX_PCD_MAX_PORTS];
    struct cdx_pcd_port_state port_state[CDX_PCD_MAX_PORTS];
};
static t_LnxWrpFmDev wrapper;
static struct port ports[FIXTURE_PORTS];
static unsigned alloc_step, fail_alloc, live_allocs, step, fail_step;
static void *stats, *oh[2], *eth[MAX_PHY_PORTS], *ceetm;
static unsigned slots, queues;
static bool restoring, unsafe_enable, fail_delete;

static void mutex_lock(int *lock) { assert(!*lock); *lock = 1; }
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
bool cdx_dpa_init_fault_at(const char *site) { (void)site; return ++step == fail_step; }
static bool stopped(void)
{
    for (unsigned i = 0; i < FIXTURE_PORTS; i++) if (ports[i].enabled) return false;
    return true;
}
static int FM_PORT_GetEnabled(void *p, bool *enabled)
{ assert(rtnl); *enabled = ((struct port *)p)->enabled; return 0; }
static int FM_PORT_DetachPCD(void *p)
{ assert(!((struct port *)p)->enabled); ((struct port *)p)->detached = true; return 0; }
static int FM_PORT_Disable(void *p) { ((struct port *)p)->enabled = false; return 0; }
static int FM_PORT_Enable(void *p)
{
    if (!((struct port *)p)->detached && (!stats || !ceetm || queues != FIXTURE_PORTS)) unsafe_enable = true;
    ((struct port *)p)->enabled = true; return 0;
}
/* The classifier builder is stubbed: it talks to real FMan hardware. What the
 * fixture supplies is its result -- the port set and handles -- so the real
 * dpa_cfg_publish() runs against it and its allocations stay under the
 * allocation-failure sweep below. */
static bool pcd_built;
static int cdx_pcd_build(u8 fm_index, struct cdx_pcd_state *state)
{
    memset(state, 0, sizeof(*state));
    state->fm_index = fm_index;
    state->fm_dev = &wrapper;
    state->h_fm = &wrapper;
    state->h_pcd = &wrapper;
    state->num_ports = FIXTURE_PORTS;
    for (unsigned i = 0; i < FIXTURE_PORTS; i++) {
        /* Port 0 is offline, port 1 ethernet -- both interface paths. */
        state->ports[i].fm_index = fm_index;
        state->ports[i].number = i ? 0 : 1;
        state->ports[i].portid = i;
        state->ports[i].speed = i ? 10 : 0;
        snprintf(state->ports[i].name, sizeof(state->ports[i].name), "%u", fm_index);
        state->port_state[i].h_port = &ports[i];
        for (unsigned g = 0; g < CDX_PCD_NUM_GROUPS; g++)
            state->port_state[i].tables[g] = (void *)(uintptr_t)(1 + g);
        state->port_state[i].num_tables = CDX_PCD_NUM_GROUPS;
    }
    for (unsigned g = 0; g < CDX_PCD_NUM_GROUPS; g++)
        state->schemes[g] = (void *)(uintptr_t)(1 + g);
    state->num_schemes = CDX_PCD_NUM_GROUPS;
    pcd_built = true;
    return 0;
}
static void cdx_pcd_teardown(struct cdx_pcd_state *state)
{
    if (!state->h_pcd) return;
    state->h_pcd = NULL;
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
    for (unsigned i = 0; i < FIXTURE_PORTS; i++) {
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
static int FM_PCD_PlcrProfileDelete(void *p)
{ assert(stopped()); kfree(p); int ret = fail_delete ? -EIO : 0; fail_delete = false; return ret; }
static int FM_PORT_PcdPlcrFreeProfiles(void *p) { assert(!((struct port *)p)->enabled && slots); slots--; return 0; }
static int ceetm_init_cq_plcr(void) { ceetm = acquire(); return ceetm ? 0 : -ENOMEM; }
static int ceetm_exit_cq_plcr(void) { assert(stopped()); kfree(ceetm); ceetm = NULL; return 0; }
static int cdxdrv_set_miss_action(unsigned n) { (void)n; assert(stats && queues == FIXTURE_PORTS && ceetm); return 0; }
/* dpa_cfg.c reaches for these outside the extracted function bodies. */
#define CDX_DPA_TBL_EXTERNAL_HASH 1
#define CDX_EXPT_ETH_DEFA_LIMIT 195312
#define CDX_EXPT_RATELIM_MODE EXPT_PKT_LIM_PLCR_MODE_PKT
#define CDX_EXPT_BURST_SIZE 64
static void *kzalloc(size_t size, int flags) { return kcalloc(1, size, flags); }
static void strscpy(char *dst, const char *src, size_t size)
{ snprintf(dst, size, "%s", src); }
#include "cdx_policers.inc"
#include "cdx_startup.inc"

static void setup(void)
{
    assert(!fman_info && !live_allocs && !slots && !queues);
    alloc_step = step = 0; unsafe_enable = false; restoring = false;
    pcd_built = false;
    wrapper.id = 0;
    wrapper.h_Dev = wrapper.h_PcdDev = wrapper.h_MuramDev = &wrapper;
    wrapper.opPorts[0] = (t_LnxWrpFmPortDev){ true, &ports[0] };
    wrapper.rxPorts[2] = (t_LnxWrpFmPortDev){ true, &ports[1] };
    for (unsigned i = 0; i < FIXTURE_PORTS; i++)
        ports[i] = (struct port){.enabled = !!(port_up_mask & (1U << i))};
}
static void clean_success(void)
{
    /* The module/control exit hooks quiesce before the final config hook. */
    mutex_lock(&cdx_info->ctrl.mutex); rtnl_lock();
    assert(!dpa_cfg_quiesce() && stopped() && queues == FIXTURE_PORTS);
    for (struct dpa_fq *fq = dpa_pcd_fq; fq; fq = (struct dpa_fq *)fq->list.next)
        assert(fq->fq_base.id == 1);
    assert(!dpa_cfg_quiesce());
    rtnl_unlock(); mutex_unlock(&cdx_info->ctrl.mutex);
    dpa_cfg_deinit();
    assert(!fman_info && !rtnl && !dpa_cfg_lock && !cdx_info->ctrl.mutex);
    for (unsigned i = 0; i < FIXTURE_PORTS; i++)
        assert(ports[i].enabled == !!(port_up_mask & (1U << i)));
    assert(!live_allocs && !slots && !queues);
}
static void retry(void)
{
    assert(!fman_info && !live_allocs && !slots && !queues);
    assert(!cdx_info->ctrl.mutex && !dpa_cfg_lock && !rtnl);
    assert(!unsafe_enable);
    for (unsigned i = 0; i < FIXTURE_PORTS; i++)
        assert(ports[i].enabled == !!(port_up_mask & (1U << i)));
    fail_alloc = fail_step = 0;
    setup(); assert(!dpa_cfg_install());
    assert(!unsafe_enable);
    /* A second install is refused without disturbing the first. */
    assert(dpa_cfg_install() == -EBUSY);
    clean_success();
}
int main(void)
{
    setup(); assert(!dpa_cfg_install());
    unsigned allocations = alloc_step, steps = step;
    assert(!unsafe_enable); clean_success();
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
    for (port_up_mask = 0; port_up_mask < (1U << FIXTURE_PORTS); port_up_mask++) {
        setup(); assert(!dpa_cfg_install());
        for (unsigned i = 0; i < FIXTURE_PORTS; i++)
            assert(ports[i].enabled == !!(port_up_mask & (1U << i)));
        /* Stack changes after startup are the state unload must restore. */
        port_up_mask ^= (1U << FIXTURE_PORTS) - 1;
        for (unsigned i = 0; i < FIXTURE_PORTS; i++)
            ports[i].enabled = !!(port_up_mask & (1U << i));
        clean_success();
        port_up_mask ^= (1U << FIXTURE_PORTS) - 1;
        setup(); fail_step = steps;
        assert(dpa_cfg_install());
        retry();
    }
    printf("CDX startup fault points passed: %u allocations, %u stages and retry\n",
           allocations, steps);
    return 0;
}
