/* Actual Linux ioctl dispatch, with hardware dispatch boundaries counted. */
#include <assert.h>
#include <stdio.h>
#include <sys/ioctl.h>
#define __CORE_EXT_H
#define __ERR_MODULE__ MODULE_FM_PORT
#include "fm_port.h"
#ifndef TEST_NO_COMPAT
#define CONFIG_COMPAT
#endif
#undef DBG
#undef REPORT_ERROR
#define DBG(level, args) ((void)0)
#define REPORT_ERROR(level, err, msg) ((void)0)
typedef struct { void *obj; } ioc_fm_obj_t;
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
    /* Existing error mapping for other commands and device classes remains. */
    assert(fm_ioctls(minors[0], &file, 0, 0, false) == 0 && port_calls == 1);
    dispatch_error = E_NOT_SUPPORTED;
    assert(fm_ioctls(minors[0], &file, 0, 0, false) == -EFAULT && port_calls == 2);
    assert(fm_ioctls(DEV_FM_PCD_MINOR_BASE, &file, cmds[0], 0, false) == -EFAULT && fm_calls == 1);
    file.private_data = NULL;
    assert(fm_ioctls(minors[0], &file, cmds[0], 0, false) == -ENODEV && port_calls == 2);
    puts("SDK ioctl: native/compat replacement rejected before argument or device access");
    return 0;
}
