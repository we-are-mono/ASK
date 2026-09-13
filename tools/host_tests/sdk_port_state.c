#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <stdarg.h>
#define __CORE_EXT_H
#define __ERR_MODULE__ MODULE_FM_PORT
#include "fm_port.h"
#include "fm_port_ioctls.h"
#ifdef CONFIG_COMPAT
#include <linux/compat.h>
#endif
#undef SANITY_CHECK_RETURN_ERROR
#undef RETURN_ERROR
#define SANITY_CHECK_RETURN_ERROR(p, err) do { if (!(p)) return ERROR_CODE(err); } while (0)
#define RETURN_ERROR(level, err, msg) return ERROR_CODE(err)
#define __user

typedef struct { void *h_Dev; } t_LnxWrpFmPortDev;
static bool fail_copy, fail_change;
static int copy_to_user(void *to, const void *from, size_t size)
{ assert(size == 1); if (fail_copy) return 1; memcpy(to, from, size); return 0; }
t_Error FM_PORT_Enable(t_Handle handle)
{ if (fail_change) return ERROR_CODE(E_INVALID_STATE); ((t_FmPort *)handle)->enabled = true; return E_OK; }
t_Error FM_PORT_Disable(t_Handle handle)
{ if (fail_change) return ERROR_CODE(E_INVALID_STATE); ((t_FmPort *)handle)->enabled = false; return E_OK; }
#include "port_state.inc"
static t_FmPort port;
static t_LnxWrpFmPortDev wrapper = {&port};
typedef struct { int fd; } t_Device;
int ioctl(int fd, unsigned long cmd, ...)
{
    va_list ap; va_start(ap, cmd); void *arg = va_arg(ap, void *); va_end(ap);
    assert(fd == 10 && cmd == FM_PORT_IOC_GET_ENABLED);
    return port_ioctl(&wrapper, cmd, (unsigned long)arg, false) == E_OK ? 0 : -1;
}
#include "port_state_fmlib.inc"
int main(void)
{
    assert(FM_PORT_IOC_GET_ENABLED == 0x8001e172);
    static struct { uint8_t before, value, after; } result;
    t_Device dev = {.fd = 10};
    for (unsigned state = 0; state < 2; state++) {
        port.enabled = state;
        for (unsigned compat = 0; compat < 2; compat++) {
            result.before = result.value = result.after = 0xa5;
            assert(port_ioctl(&wrapper, FM_PORT_IOC_GET_ENABLED, (unsigned long)&result.value, compat) == E_OK);
            assert(result.value == state && result.before == 0xa5 && result.after == 0xa5);
            bool enabled = !state;
            assert(LibraryGetEnabled(&dev, &enabled) == E_OK && enabled == state);
            fail_copy = true; result.value = 0xa5;
            assert(port_ioctl(&wrapper, FM_PORT_IOC_GET_ENABLED, (unsigned long)&result.value, compat) != E_OK);
            assert(result.value == 0xa5);
            enabled = !state;
            assert(LibraryGetEnabled(&dev, &enabled) != E_OK && enabled == !state);
            fail_copy = false;
        }
        fail_change = true;
        assert(port_ioctl(&wrapper, FM_PORT_IOC_ENABLE, 0, false) != E_OK);
        assert(port_ioctl(&wrapper, FM_PORT_IOC_DISABLE, 0, false) != E_OK);
        assert(port.enabled == state);
        fail_change = false;
    }
    bool enabled = true;
    assert(FM_PORT_GetEnabled(NULL, &enabled) != E_OK && enabled);
    assert(FM_PORT_GetEnabled(&port, NULL) != E_OK);
    port.p_FmPortDriverParam = (void *)1;
    assert(FM_PORT_GetEnabled(&port, &enabled) != E_OK && enabled);
    puts("Port state: SDK, native/compat ioctl, fmlib, copy faults and enable errors passed");
}
