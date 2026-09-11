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

struct port { bool enabled; };
typedef struct { bool active; t_Handle h_Dev; } t_LnxWrpFmPortDev;
typedef struct {
    unsigned id;
    t_LnxWrpFmPortDev opPorts[2], rxPorts[4];
} t_LnxWrpFmDev;
struct list_head { struct list_head *next; };
struct qman_fq { unsigned id; };
struct dpa_fq { struct qman_fq fq_base; struct list_head list; };
struct dpa_init_ports { t_Handle *handles; uint32_t count; };
struct { unsigned flags, id; struct { unsigned index; } itf; } phy_port[MAX_PHY_PORTS];
struct port_ff_rate_lim_info { void *handle, *h_FmPcd, *port_handle; };
static struct port_ff_rate_lim_info port_rate_lim_mode[MAX_PHYS_PORTS];
static unsigned num_fmans;
static struct cdx_fman_info *fman_info;
static struct dpa_fq *dpa_pcd_fq;
static int dpa_cfg_lock;
static struct { struct { int mutex; } ctrl; } cdx_instance, *cdx_info = &cdx_instance;
static struct cdx_fman_info input[2];
static struct cdx_ctrl_set_dpa_params request = { input, 2 };
static t_LnxWrpFmDev wrappers[2];
static struct port ports[4];
static unsigned alloc_step, fail_alloc, live_allocs, step, fail_step, copy_step, fail_copy;
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
static int FM_PORT_Disable(void *p) { ((struct port *)p)->enabled = false; return 0; }
static int FM_PORT_Enable(void *p)
{
    if (!restoring && (!stats || !ceetm || queues != 4)) unsafe_enable = true;
    ((struct port *)p)->enabled = true; return 0;
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
static int FM_PCD_PlcrProfileDelete(void *p)
{ assert(stopped()); kfree(p); int ret = fail_delete ? -EIO : 0; fail_delete = false; return ret; }
static int FM_PORT_PcdPlcrFreeProfiles(void *p) { assert(!((struct port *)p)->enabled && slots); slots--; return 0; }
static int ceetm_init_cq_plcr(void) { ceetm = acquire(); return ceetm ? 0 : -ENOMEM; }
static int ceetm_exit_cq_plcr(void) { assert(stopped()); kfree(ceetm); ceetm = NULL; return 0; }
static int cdxdrv_set_miss_action(unsigned n) { (void)n; assert(stats && queues == 4 && ceetm); return 0; }
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
        wrappers[i].opPorts[0] = (t_LnxWrpFmPortDev){ true, &ports[2 * i] };
        wrappers[i].rxPorts[2] = (t_LnxWrpFmPortDev){ true, &ports[2 * i + 1] };
        ports[2 * i].enabled = ports[2 * i + 1].enabled = true;
    }
}
static void clean_success(void)
{
    struct dpa_init_ports p = { 0 };
    t_LnxWrpFmDev *w[] = { &wrappers[0], &wrappers[1] };
    assert(!dpa_prepare_ports(w, &p));
    assert(!dpa_set_ports_enabled(&p, false));
    dpa_rollback_resources(); kfree(p.handles); release_cfg_info();
    assert(!live_allocs && !slots && !queues);
}
static void retry(void)
{
    assert(!fman_info && !live_allocs && !slots && !queues);
    assert(!cdx_info->ctrl.mutex && !dpa_cfg_lock);
    fail_alloc = fail_step = fail_copy = 0;
    setup(); assert(!cdx_ioc_set_dpa_params((unsigned long)&request));
    assert(!unsafe_enable);
    assert(cdx_ioc_set_dpa_params((unsigned long)&request) == -EBUSY);
    clean_success();
}
int main(void)
{
    setup(); assert(!cdx_ioc_set_dpa_params((unsigned long)&request));
    unsigned allocations = alloc_step, steps = step;
    assert(!unsafe_enable); clean_success();
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
    printf("CDX startup fault points passed: %u allocations, %u stages, partial copies and retry\n", allocations, steps);
    return 0;
}
