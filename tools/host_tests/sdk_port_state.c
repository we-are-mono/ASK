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
/* The port's lock, which the fence is set under and an enable both reads the
 * fence and writes the port's registers under; the registers, host-endian
 * here, are written only by an enable. */
static int port_lock;
static bool port_locked;
static unsigned fence_locks;
uint32_t XX_LockIntrSpinlock(t_Handle lock)
{ assert(lock == &port_lock && !port_locked); port_locked = true; fence_locks++; return 7; }
void XX_UnlockIntrSpinlock(t_Handle lock, uint32_t flags)
{ assert(lock == &port_lock && port_locked && flags == 7); port_locked = false; }
static uint32_t ioread32be(const volatile uint32_t *reg) { return *reg; }
static void iowrite32be(uint32_t value, volatile uint32_t *reg) { assert(port_locked); *reg = value; }
t_Error FmPortImEnable(t_FmPort *p_FmPort) { (void)p_FmPort; assert(!"an independent-mode port"); return E_OK; }
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
    port.p_FmPortDriverParam = NULL;

    /* Stopped is what the registers say, not what software last asked for:
     * a port is stopped once disabled with its BMI no longer busy and, for a
     * port QMI dequeues for, QMI disabled and handling no frame. */
    static union fman_port_bmi_regs bmi;
    static struct fman_port_qmi_regs qmi;
    port.port.bmi_regs = &bmi; port.port.qmi_regs = &qmi;
    port.h_Spinlock = &port_lock;
    bool stopped = false;
    for (unsigned rx = 0; rx < 2; rx++) {
        port.portType = rx ? e_FM_PORT_TYPE_RX : e_FM_PORT_TYPE_OH_OFFLINE_PARSING;
        port.port.type = rx ? E_FMAN_PORT_TYPE_RX : E_FMAN_PORT_TYPE_OP;
        volatile uint32_t *cfg = rx ? &bmi.rx.fmbm_rcfg : &bmi.oh.fmbm_ocfg;
        volatile uint32_t *status = rx ? &bmi.rx.fmbm_rst : &bmi.oh.fmbm_ost;
        memset(&bmi, 0, sizeof(bmi)); memset(&qmi, 0, sizeof(qmi));
        port.enabled = false;
        assert(FM_PORT_GetStopped(&port, &stopped) == E_OK && stopped);
        port.enabled = true;
        assert(FM_PORT_GetStopped(&port, &stopped) == E_OK && !stopped);
        port.enabled = false;
        *cfg = BMI_PORT_CFG_EN;
        assert(FM_PORT_GetStopped(&port, &stopped) == E_OK && !stopped);
        *cfg = 0; *status = BMI_PORT_STATUS_BSY;
        assert(FM_PORT_GetStopped(&port, &stopped) == E_OK && !stopped);
        *status = 0; qmi.fmqm_pns = QMI_PORT_STATUS_DEQ_FD_BSY;
        assert(FM_PORT_GetStopped(&port, &stopped) == E_OK && stopped == rx);
        qmi.fmqm_pns = 0; qmi.fmqm_pnc = QMI_PORT_CFG_EN;
        assert(FM_PORT_GetStopped(&port, &stopped) == E_OK && stopped == rx);
        qmi.fmqm_pnc = 0;
        assert(FM_PORT_GetStopped(&port, &stopped) == E_OK && stopped);
        /* A port hands its frames to a PCD unless its next engine is the
         * BMI's own enqueue, whatever its frame-descriptor bits say. */
        volatile uint32_t *nia = rx ? &bmi.rx.fmbm_rfne : &bmi.oh.fmbm_ofne;
        bool attached = false;
        *nia = GET_NO_PCD_NIA_BMI_AC_ENQ_FRAME() | 0x5a000000;
        assert(FM_PORT_IsPcdAttached(&port, &attached) == E_OK && !attached);
        *nia = NIA_ENG_KG;
        assert(FM_PORT_IsPcdAttached(&port, &attached) == E_OK && attached);
        /* Fenced, it is refused every enable and left as it was; unfenced,
         * it enables as ever. Disabling it is never refused. The fence is
         * set, and read with the enable's register writes, under the port's
         * lock, each released again. */
        fence_locks = 0;
        assert(FM_PORT_SetFenced(&port, true) == E_OK && port.fenced);
        assert(sdk_port_enable(&port) != E_OK && !port.enabled && !*cfg && !qmi.fmqm_pnc);
        assert(FM_PORT_SetFenced(&port, false) == E_OK && !port.fenced);
        assert(sdk_port_enable(&port) == E_OK && port.enabled && *cfg == BMI_PORT_CFG_EN);
        assert(!!qmi.fmqm_pnc == !rx);
        assert(fence_locks == 4 && !port_locked);
        assert(FM_PORT_GetStopped(&port, &stopped) == E_OK && !stopped);
    }
    /* No other kind of port can have a PCD. */
    port.portType = e_FM_PORT_TYPE_TX;
    bool attached = true;
    assert(FM_PORT_IsPcdAttached(&port, &attached) == E_OK && !attached);
    /* And none of it answers for a port that cannot. */
    assert(FM_PORT_GetStopped(NULL, &stopped) != E_OK && FM_PORT_GetStopped(&port, NULL) != E_OK);
    assert(FM_PORT_IsPcdAttached(NULL, &attached) != E_OK && FM_PORT_SetFenced(NULL, true) != E_OK);
    port.p_FmPortDriverParam = (void *)1;
    assert(FM_PORT_GetStopped(&port, &stopped) != E_OK && FM_PORT_SetFenced(&port, true) != E_OK);
    assert(FM_PORT_IsPcdAttached(&port, &attached) != E_OK && !port.fenced);
    puts("Port state: SDK, native/compat ioctl, fmlib, copy faults and enable errors, "
         "stopped, PCD attachment and fence passed");
}
