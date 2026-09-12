/* Actual Linux ioctl dispatch, with hardware dispatch boundaries counted. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <sys/ioctl.h>
#define __CORE_EXT_H
#define __ERR_MODULE__ MODULE_FM_PORT
#include "fm_port.h"
#ifndef TEST_NO_COMPAT
#define CONFIG_COMPAT
#define FM_COMPAT
#endif
#undef DBG
#undef REPORT_ERROR
#define DBG(level, args) ((void)0)
#define REPORT_ERROR(level, err, msg) ((void)0)
#include "fm_port_ioctls.h"
#ifdef CONFIG_COMPAT
#include "lnxwrp_ioctls_fm_compat.h"
#endif
#include "fm_eh_types.h"
#define __user
static const void *user_buffer;
static size_t user_size;
static int read_user(void *dest, const void *src, size_t size)
{
    uintptr_t address = (uintptr_t)src, start = (uintptr_t)user_buffer;
    if (address < start || size > user_size || address - start > user_size - size)
        return -EFAULT;
    memcpy(dest, src, size);
    return 0;
}
#define get_user(value, ptr) read_user(&(value), (ptr), sizeof(*(ptr)))
typedef struct { unsigned unused; } t_LnxWrpFmDev, t_LnxWrpFmPortDev;
struct file { void *private_data; };
static unsigned port_calls, fm_calls;
static t_Error dispatch_error;
static t_Error LnxwrpFmPortIOCTL(t_LnxWrpFmPortDev *dev, unsigned cmd, unsigned long arg, bool compat)
{ port_calls++; return dispatch_error; }
static t_Error LnxwrpFmIOCTL(t_LnxWrpFmDev *dev, unsigned cmd, unsigned long arg, bool compat)
{ fm_calls++; return dispatch_error; }
#include "port_ioctl_production.inc"

int main(void)
{
    struct file file = {.private_data = (void *)1};
    /* Native arm64 layouts used by the unused-scheme teardown test. */
    assert(FM_PCD_IOC_KG_SCHEME_SET == 0xc558e12c && FM_PCD_IOC_KG_SCHEME_DELETE == 0x4008e12d);
    assert(sizeof(ioc_fm_pcd_kg_scheme_params_t) == 1368);
    assert(offsetof(ioc_fm_pcd_kg_scheme_params_t, scm_id) == 8);
    assert(offsetof(ioc_fm_pcd_kg_scheme_params_t, always_direct) == 16);
    assert(offsetof(ioc_fm_pcd_kg_scheme_params_t, net_env_params.net_env_id) == 24);
    assert(offsetof(ioc_fm_pcd_kg_scheme_params_t, net_env_params.num_of_distinction_units) == 32);
    assert(offsetof(ioc_fm_pcd_kg_scheme_params_t, net_env_params.unit_ids) == 33);
    assert(offsetof(ioc_fm_pcd_kg_scheme_params_t, base_fqid) == 1080);
    assert(offsetof(ioc_fm_pcd_kg_scheme_params_t, next_engine) == 1320);
    assert(offsetof(ioc_fm_pcd_kg_scheme_params_t, kg_next_engine_params.done_action) == 1328);
    assert(offsetof(ioc_fm_pcd_kg_scheme_params_t, id) == 1360);
    assert(FM_PCD_IOC_NET_ENV_CHARACTERISTICS_SET == 0xc3d0e128);
    assert(FM_PCD_IOC_NET_ENV_CHARACTERISTICS_DELETE == 0x4008e129);
    assert(sizeof(ioc_fm_pcd_net_env_params_t) == 976);
    assert(offsetof(ioc_fm_pcd_net_env_params_t, units) == 4);
    assert(offsetof(ioc_fm_pcd_net_env_params_t, id) == 968);
    assert(e_IOC_FM_PCD_DONE == 1 && e_IOC_FM_PCD_DROP_FRAME == 1 && e_IOC_NET_HEADER_TYPE_ETH == 2);
    /* These native layouts also drive the UART hardware rejection test. */
    assert(FM_PCD_IOC_MANIP_NODE_SET == 0xc1d0e13f && sizeof(ioc_fm_pcd_manip_params_t) == 464);
    assert(e_IOC_FM_PCD_MANIP_REASSEM == 1);
    assert(FM_PCD_IOC_HASH_TABLE_SET == 0xc078e139 && sizeof(ioc_fm_pcd_hash_table_params_t) == 120);
    assert(offsetof(ioc_fm_pcd_hash_table_params_t, table_type) == 68);
    assert(IPV4_REASSM_TABLE == 14 && IPV6_REASSM_TABLE == 15);
    assert(FM_PORT_IOC_SET_PCD == 0x4040e15a && sizeof(ioc_fm_port_pcd_params_t) == 64);
    assert(offsetof(ioc_fm_port_pcd_params_t, p_ip_reassembly_manip) == 48);
    assert(offsetof(ioc_fm_port_pcd_params_t, p_capwap_reassembly_manip) == 56);

    unsigned cmds[] = {FM_PORT_IOC_PCD_CC_MODIFY_TREE, FM_PORT_IOC_PCD_CC_MODIFY_TREE_COMPAT};
    assert(cmds[0] == 0x4008e162 && cmds[1] == 0x4004e162);
    unsigned minors[] = {DEV_FM_OH_PORTS_MINOR_BASE, DEV_FM_RX_PORTS_MINOR_BASE, DEV_FM_TX_PORTS_MINOR_BASE};
    for (unsigned m = 0; m < 3; m++) {
        for (unsigned compat = 0; compat < 2; compat++) {
            for (unsigned c = 0; c < 2; c++) {
                /* Unreadable arguments still return unsupported, without
                 * looking at the device or entering the SDK dispatcher. */
                assert(fm_ioctls(minors[m], &file, cmds[c], 0, compat) == -EOPNOTSUPP);
                assert(fm_ioctls(minors[m], &file, cmds[c], 1, compat) == -EOPNOTSUPP);
                assert(!port_calls && !fm_calls);
            }
        }
    }
    for (unsigned compat = 0; compat < 2; compat++) {
#ifndef CONFIG_COMPAT
        if (compat) continue;
#endif
        static ioc_fm_pcd_manip_params_t manip;
        static ioc_fm_pcd_hash_table_params_t hash;
        static ioc_fm_port_pcd_params_t port;
        unsigned manip_cmd = FM_PCD_IOC_MANIP_NODE_SET, hash_cmd = FM_PCD_IOC_HASH_TABLE_SET;
        unsigned port_cmd = FM_PORT_IOC_SET_PCD;
        void *manip_arg = &manip, *hash_arg = &hash, *port_arg = &port;
        uint32_t *table_type = &hash.table_type;
        size_t port_size = sizeof(port);
#ifdef CONFIG_COMPAT
        static ioc_compat_fm_pcd_manip_params_t compat_manip;
        static ioc_compat_fm_pcd_hash_table_params_t compat_hash;
        static ioc_compat_fm_port_pcd_params_t compat_port;
        if (compat) {
            manip_cmd = FM_PCD_IOC_MANIP_NODE_SET_COMPAT;
            hash_cmd = FM_PCD_IOC_HASH_TABLE_SET_COMPAT;
            port_cmd = FM_PORT_IOC_SET_PCD_COMPAT;
            manip_arg = &compat_manip; hash_arg = &compat_hash; port_arg = &compat_port;
            port_size = sizeof(compat_port);
        }
#endif
        user_buffer = manip_arg; user_size = sizeof(uint32_t);
        *(uint32_t *)manip_arg = e_IOC_FM_PCD_MANIP_REASSEM;
        assert(fm_ioctls(DEV_FM_PCD_MINOR_BASE, &file, manip_cmd, (uintptr_t)manip_arg, compat) == -EOPNOTSUPP);
        assert(!port_calls && !fm_calls);
        *(uint32_t *)manip_arg = e_IOC_FM_PCD_MANIP_FRAG;
        assert(fm_ioctls(DEV_FM_PCD_MINOR_BASE, &file, manip_cmd, (uintptr_t)manip_arg, compat) == 0);
        assert(fm_calls == 1); fm_calls = 0;
        user_size = 0;
        assert(fm_ioctls(DEV_FM_PCD_MINOR_BASE, &file, manip_cmd, (uintptr_t)manip_arg, compat) == -EFAULT);
        if (!compat) {
            user_buffer = table_type; user_size = sizeof(*table_type);
            for (unsigned type = IPV4_REASSM_TABLE; type <= IPV6_REASSM_TABLE; type++) {
                *table_type = type | 0x80000000;
                assert(fm_ioctls(DEV_FM_PCD_MINOR_BASE, &file, hash_cmd, (uintptr_t)hash_arg, compat) == -EOPNOTSUPP);
                assert(!port_calls && !fm_calls);
            }
            *table_type = IPV4_UDP_TABLE;
            assert(fm_ioctls(DEV_FM_PCD_MINOR_BASE, &file, hash_cmd, (uintptr_t)hash_arg, compat) == 0);
            assert(fm_calls == 1); fm_calls = 0;
        }
        user_buffer = port_arg; user_size = port_size;
        for (unsigned type = 0; type < 4; type++) {
            /* All unrelated/nested pointers are deliberately invalid. */
            memset(port_arg, 0xff, port_size);
#ifdef CONFIG_COMPAT
            if (compat) {
                compat_port.p_ip_reassembly_manip = type & 1;
                compat_port.p_capwap_reassembly_manip = type & 2;
            } else
#endif
            {
                port.p_ip_reassembly_manip = (void *)(uintptr_t)(type & 1);
                port.p_capwap_reassembly_manip = (void *)(uintptr_t)(type & 2);
            }
            assert(fm_ioctls(minors[0], &file, port_cmd, (uintptr_t)port_arg, compat) == (type ? -EOPNOTSUPP : 0));
            assert(port_calls == !type && !fm_calls); port_calls = 0;
        }
        user_size = 0;
        assert(fm_ioctls(minors[0], &file, port_cmd, (uintptr_t)port_arg, compat) == -EFAULT);
    }
    /* Existing error mapping for other commands and device classes remains. */
    assert(fm_ioctls(minors[0], &file, 0, 0, false) == 0 && port_calls == 1);
    dispatch_error = E_NOT_SUPPORTED;
    assert(fm_ioctls(minors[0], &file, 0, 0, false) == -EFAULT && port_calls == 2);
    assert(fm_ioctls(DEV_FM_PCD_MINOR_BASE, &file, cmds[0], 0, false) == -EFAULT && fm_calls == 1);
    file.private_data = NULL;
    assert(fm_ioctls(minors[0], &file, cmds[0], 0, false) == -ENODEV && port_calls == 2);
    puts("SDK ioctl: reassembly and replacement rejected before object or nested argument access");
    return 0;
}
