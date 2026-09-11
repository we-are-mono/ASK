/* Production DPA/FMC/FMLIB with only allocation and device boundaries replaced. */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include "fmc.h"
#include "fm_ioctls.h"
#include "fm_pcd_ioctls.h"
#include "fm_port_ioctls.h"
#include "../../dpa_app/dpa.c"

static unsigned step, fail_at, cleanup_step, cleanup_fail_at;
static unsigned allocated, open_fds, objects, next_cookie, next_fd;
static unsigned hardware_calls, compile_calls, set_calls;
static bool cleaning, configured, reject_set, reject_compile;
static unsigned engines = 2;
static void *allocations[4096];
enum kind { FM, PCD, PORT, CONTROL, ENV, SCHEME, TABLE, TREE, MANIP, POLICER, REPLIC };
const char *TMPFILENAME = "saved-fmc.bin";
struct device { char name[48]; enum kind kind; bool open, attached, disabled, hc_denied; unsigned env; };
static struct device devices[256];
struct object { enum kind kind; bool live; unsigned refs, env, owner; };
static struct object object[256];

void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void __real_free(void *);
static bool fault(void)
{
    if (cleaning)
        return ++cleanup_step == cleanup_fail_at;
    if (++step != fail_at)
        return false;
    cleaning = true;
    return true;
}
static void track(void *p)
{
    assert(p && allocated < 4096);
    allocations[allocated++] = p;
}
void *__wrap_malloc(size_t size)
{
    if (fault()) return NULL;
    void *p = __real_malloc(size); track(p); return p;
}
void *__wrap_calloc(size_t count, size_t size)
{
    if (fault()) return NULL;
    void *p = __real_calloc(count, size); track(p); return p;
}
void __wrap_free(void *p)
{
    if (!p) return;
    unsigned i;
    for (i = 0; i < allocated && allocations[i] != p; i++);
    assert(i < allocated);
    allocations[i] = allocations[--allocated];
    __real_free(p);
}
int __wrap_open(const char *name, int flags, ...)
{
    if (fault()) { errno = ENOMEM; return -1; }
    unsigned fd = ++next_fd;
    assert(fd < 256);
    for (unsigned i = 1; i < fd; i++) {
        if (!devices[i].open && strcmp(devices[i].name, name) == 0) {
            devices[fd] = devices[i];
            devices[i].name[0] = 0;
            devices[i].attached = devices[i].disabled = devices[i].hc_denied = false;
        }
    }
    snprintf(devices[fd].name, sizeof(devices[fd].name), "%s", name);
    devices[fd].open = true;
    devices[fd].kind = strstr(name, "cdx_ctrl") ? CONTROL :
        strstr(name, "-pcd") ? PCD : strstr(name, "-port-") ? PORT : FM;
    open_fds++;
    return fd;
}
int __wrap_close(int fd)
{
    assert(fd > 0 && devices[fd].open);
    assert(!devices[fd].disabled);
    assert(!devices[fd].hc_denied);
    devices[fd].open = false;
    open_fds--;
    return 0;
}
static unsigned cookie(void *id) { return (unsigned)(uintptr_t)id; }
static unsigned new_object(enum kind kind, unsigned owner, unsigned env)
{
    unsigned id = ++next_cookie;
    assert(id < 256);
    object[id] = (struct object){.kind = kind, .live = true, .owner = owner, .env = env};
    objects++;
    if (env) { assert(object[env].live); object[env].refs++; }
    return id;
}
static void delete_object(unsigned id)
{
    assert(id && object[id].live && object[id].refs == 0);
    if (object[id].env) {
        assert(object[object[id].env].live && object[object[id].env].refs);
        object[object[id].env].refs--;
    }
    object[id].live = false;
    objects--;
}
int __wrap_ioctl(int fd, unsigned long cmd, ...)
{
    void *arg = NULL;
    assert(devices[fd].open);
    if (cmd == CDX_CTRL_DPA_INIT_CHECK) {
        if (configured) { errno = EBUSY; return -1; }
        if (fault()) { errno = EIO; return -1; }
        return 0;
    }
    va_list ap;
    va_start(ap, cmd);
    if (cmd != FM_PCD_IOC_ENABLE && cmd != FM_PCD_IOC_DISABLE &&
        cmd != FM_PCD_IOC_SET_ADVANCED_OFFLOAD_SUPPORT &&
        cmd != FM_PORT_IOC_ENABLE && cmd != FM_PORT_IOC_DISABLE &&
        cmd != FM_PORT_IOC_DELETE_PCD)
        arg = va_arg(ap, void *);
    va_end(ap);
    if (cmd == FM_IOC_GET_API_VERSION) {
        ioc_fm_api_version_t *v = arg;
        v->version.major = 21; v->version.minor = 1; v->version.respin = 0;
        return 0;
    }
    if (fault()) { errno = EIO; return -1; }
    if (cmd == CDX_CTRL_DPA_SET_PARAMS) {
        struct cdx_ctrl_set_dpa_params *p = arg;
        set_calls++;
        assert(p->num_fmans == engines);
        for (unsigned i = 0; i < engines; i++) {
            struct cdx_fman_info *f = &p->fman_info[i];
            assert(f->num_tables == 2 && f->max_ports == 2);
            assert(devices[(uintptr_t)f->pcd_handle].open);
            for (unsigned j = 0; j < f->num_tables; j++)
                assert(object[cookie(f->tbl_info[j].id)].live);
        }
        if (reject_set) { cleaning = true; errno = EIO; return -1; }
        configured = true;
        return 0;
    }
    hardware_calls++;
    switch (cmd) {
    case FM_PCD_IOC_ENABLE:
    case FM_PCD_IOC_DISABLE:
    case FM_PCD_IOC_SET_ADVANCED_OFFLOAD_SUPPORT:
    case FM_PCD_IOC_PRS_LOAD_SW:
    case FM_PCD_IOC_KG_SET_ADDITIONAL_DATA_AFTER_PARSING:
        assert(devices[fd].kind == PCD); return 0;
    case FM_PCD_IOC_ALLOW_HC_USAGE:
        devices[fd].hc_denied = !*(uint8_t *)arg; return 0;
    case FM_PORT_IOC_DISABLE: devices[fd].disabled = true; return 0;
    case FM_PORT_IOC_ENABLE: devices[fd].disabled = false; return 0;
    case FM_PORT_IOC_VSP_ALLOC: return 0;
    case FM_PORT_IOC_SET_PCD: {
        ioc_fm_port_pcd_params_t *p = arg;
        unsigned env = cookie(p->net_env_id);
        assert(!devices[fd].attached && devices[fd].disabled && object[env].live);
        devices[fd].attached = true; devices[fd].env = env;
        object[env].refs++;
        return 0;
    }
    case FM_PORT_IOC_DELETE_PCD:
        assert(devices[fd].attached && devices[fd].disabled);
        devices[fd].attached = false;
        assert(object[devices[fd].env].refs);
        object[devices[fd].env].refs--;
        return 0;
#define CREATE_CASE(command, type, cls, environment) \
    case command: { type *p = arg; p->id = (void *)(uintptr_t)new_object(cls, fd, environment); return 0; }
    CREATE_CASE(FM_PCD_IOC_NET_ENV_CHARACTERISTICS_SET, ioc_fm_pcd_net_env_params_t, ENV, 0)
    CREATE_CASE(FM_PCD_IOC_CC_ROOT_BUILD, ioc_fm_pcd_cc_tree_params_t, TREE, cookie(p->net_env_id))
    CREATE_CASE(FM_PCD_IOC_MATCH_TABLE_SET, ioc_fm_pcd_cc_node_params_t, TABLE, 0)
    CREATE_CASE(FM_PCD_IOC_HASH_TABLE_SET, ioc_fm_pcd_hash_table_params_t, TABLE, 0)
    CREATE_CASE(FM_PCD_IOC_MANIP_NODE_SET, ioc_fm_pcd_manip_params_t, MANIP, 0)
    CREATE_CASE(FM_PCD_IOC_PLCR_PROFILE_SET, ioc_fm_pcd_plcr_profile_params_t, POLICER, 0)
    CREATE_CASE(FM_PCD_IOC_FRM_REPLIC_GROUP_SET, ioc_fm_pcd_frm_replic_group_params_t, REPLIC, 0)
#undef CREATE_CASE
    case FM_PCD_IOC_KG_SCHEME_SET: {
        ioc_fm_pcd_kg_scheme_params_t *p = arg;
        if (p->modify) { assert(object[cookie(p->scm_id.scheme_id)].live); p->id = p->scm_id.scheme_id; }
        else p->id = (void *)(uintptr_t)new_object(SCHEME, fd, cookie(p->net_env_params.net_env_id));
        return 0;
    }
    case FM_PCD_IOC_NET_ENV_CHARACTERISTICS_DELETE:
    case FM_PCD_IOC_KG_SCHEME_DELETE:
    case FM_PCD_IOC_MATCH_TABLE_DELETE:
    case FM_PCD_IOC_HASH_TABLE_DELETE:
    case FM_PCD_IOC_CC_ROOT_DELETE:
    case FM_PCD_IOC_MANIP_NODE_DELETE:
    case FM_PCD_IOC_PLCR_PROFILE_DELETE:
    case FM_PCD_IOC_FRM_REPLIC_GROUP_DELETE:
        delete_object(cookie(((ioc_fm_obj_t *)arg)->obj)); return 0;
    default:
        fprintf(stderr, "unhandled ioctl %#lx\n", cmd); abort();
    }
}

static void apply(fmc_model *m, fmc_apply_order_e type, unsigned index)
{
    m->apply_order[m->apply_order_count++] = (fmc_apply_order){type, index};
}
int fmc_compile(fmc_model *m, const char *a, const char *b, const char *c,
                const char *d, unsigned e, unsigned f, const char **g)
{
    compile_calls++;
    if (fault() || reject_compile) return 1;
    memset(m, 0, sizeof(*m));
    m->format_version = FMC_OUTPUT_FORMAT_VER;
    m->fman_count = engines;
    m->port_count = engines * 2;
    m->scheme_count = m->htnode_count = m->ccnode_count = engines;
    m->policer_count = m->replicator_count = engines;
    m->sp_enable = 1;
    for (unsigned i = 0; i < engines; i++) {
        m->fman[i].number = i;
        m->fman[i].port_count = 2;
        m->fman[i].ports[0] = i * 2; m->fman[i].ports[1] = i * 2 + 1;
        m->fman[i].offload_support = 1;
        m->fman[i].kg_payload_offset = 1;
        m->fman[i].frag_count = m->fman[i].reasm_count = 1;
        m->fman[i].hdr_count = 1;
        snprintf(m->htnode_name[i], FMC_NAME_LEN, "fm%u/port/1G/1/ccnode/cdx_udp4", i);
        snprintf(m->ccnode_name[i], FMC_NAME_LEN, "fm%u/port/1G/1/ccnode/cdx_tcp4", i);
        snprintf(m->scheme_name[i], FMC_NAME_LEN, "fm%u/port/1G/1/dist/cdx_udp4_dist", i);
        m->htnode[i].maxNumOfKeys = 16; m->htnode[i].hashResMask = 3;
        m->scheme[i].alwaysDirect = TRUE;
        m->scheme[i].nextEngine = e_FM_PCD_CC;
        m->replicator[i].numOfEntries = 2;
        m->policer[i].id.newParams.profileType = e_FM_PCD_PLCR_SHARED;
        apply(m, FMCEngineStart, i);
        apply(m, FMCManipulation, 0);
        apply(m, FMCPolicer, i);
        apply(m, FMCReplicator, i);
        for (unsigned j = 0; j < 2; j++) {
            unsigned n = i * 2 + j;
            fmc_port *p = &m->port[n];
            p->number = j + 1; p->portid = n + 1; p->type = e_FM_PORT_TYPE_RX;
            snprintf(p->name, FMC_NAME_LEN, "fm%u/port/1G/%u", i, j + 1);
            p->schemes_count = p->ccnodes_count = p->htnodes_count = 1;
            p->schemes[0] = p->ccnodes[0] = p->htnodes[0] = i;
            p->vspParam.numOfProfiles = 1;
            apply(m, FMCPortStart, n);
            if (!j) { apply(m, FMCHTNode, i); apply(m, FMCCCNode, i); }
            apply(m, FMCCCTree, n);
            if (!j) apply(m, FMCScheme, i);
            apply(m, FMCPortEnd, n);
        }
        apply(m, FMCEngineEnd, i);
    }
    return 0;
}
const char *fmc_get_error(void) { return "injected compilation failure"; }
void fmc_log_write(int32_t level, const char *format, ...) { }

static void reset(void)
{
    assert(!allocated && !open_fds && !objects);
    memset(devices, 0, sizeof(devices)); memset(object, 0, sizeof(object));
    memset(&cmodel, 0, sizeof(cmodel));
    step = fail_at = cleanup_step = cleanup_fail_at = 0;
    hardware_calls = compile_calls = set_calls = next_cookie = next_fd = 0;
    cleaning = configured = reject_set = reject_compile = false;
}
static void empty(void)
{
    assert(allocated == 0 && open_fds == 0 && objects == 0);
    for (unsigned i = 0; i < 256; i++)
        assert(!devices[i].attached && !devices[i].disabled && !devices[i].hc_denied);
}
int main(void)
{
    reset();
    assert(dpa_init() == 0 && objects && open_fds && !cleaning);
    unsigned startup_steps = step;
    unsigned calls = hardware_calls;
    unsigned compiles = compile_calls;
    assert(dpa_init() != 0 && hardware_calls == calls && compile_calls == compiles);
    cleaning = true;
    assert(fmc_clean(&cmodel) == 0);
    unsigned cleanup_steps = cleanup_step;
    empty();
    assert(fmc_clean(&cmodel) == 0); empty();

    for (unsigned n = 1; n <= startup_steps; n++) {
        reset(); fail_at = n;
        assert(dpa_init() != 0);
        empty();
        fail_at = 0; cleaning = false;
        assert(dpa_init() == 0);
        cleaning = true; assert(fmc_clean(&cmodel) == 0); empty();
    }
    for (unsigned n = 1; n <= cleanup_steps; n++) {
        reset(); reject_set = true; cleanup_fail_at = n;
        assert(dpa_init() != 0);
        for (unsigned fd = 1; fd <= next_fd; fd++) assert(!devices[fd].hc_denied);
        cleanup_fail_at = 0;
        assert(fmc_clean(&cmodel) == 0); empty();
    }
    reset();
    assert(dpa_init() == 0);
    FILE *saved = fopen(TMPFILENAME, "wb");
    assert(saved && fwrite(&cmodel, sizeof(cmodel), 1, saved) == 1);
    fclose(saved);
    fmc_release(&cmodel);
    assert(!allocated && !open_fds && objects);
    assert(fmc_load(&cmodel));
    cleaning = true; assert(fmc_clean(&cmodel) == 0); empty();
    fmc_release(&cmodel); empty();

    reset();
    cmodel.format_version = FMC_OUTPUT_FORMAT_VER - 1;
    saved = fopen(TMPFILENAME, "wb");
    assert(saved && fwrite(&cmodel, sizeof(cmodel), 1, saved) == 1);
    fclose(saved);
    assert(!fmc_load(&cmodel) && next_fd == 0); empty();
    saved = fopen(TMPFILENAME, "wb");
    assert(saved && fwrite("short", 5, 1, saved) == 1);
    fclose(saved);
    assert(!fmc_load(&cmodel) && next_fd == 0); empty();
    remove(TMPFILENAME);

    reset(); engines = 1;
    assert(dpa_init() == 0);
    cleaning = true; assert(fmc_clean(&cmodel) == 0); empty();
    printf("DPA lifecycle fault points passed: %u startup, %u cleanup; retry, shared objects, one/two FMANs\n",
           startup_steps, cleanup_steps);
    return 0;
}
