#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;
#define __maybe_unused
#define QM_EQCR_SIZE 8
#define EQCR_PTR2IDX(p) (((uintptr_t)(p) >> 6) & 7)
#define qm_in(reg) (portal->hardware_ci)
struct qm_eqcr { u8 ci, available; void *cursor; };
struct qm_portal { struct qm_eqcr eqcr; u8 hardware_ci, cached_ci; };
struct qman_portal { struct qm_portal p; };
static struct qman_portal portal;
static unsigned pins, locked;
static struct qman_portal *get_affine_portal(void) { pins++; return &portal; }
static void put_affine_portal(void) { assert(pins); pins--; }
#define PORTAL_IRQ_LOCK(p, flags) do { assert(!locked); locked = 1; } while (0)
#define PORTAL_IRQ_UNLOCK(p, flags) do { assert(locked); locked = 0; } while (0)
static u8 qm_cyc_diff(u8 size, u8 first, u8 last) { return (last - first) & (size - 1); }
static void update_eqcr_ci(struct qman_portal *p, u8 avail)
{
    (void)avail; assert(locked);
    struct qm_eqcr *eq = &p->p.eqcr;
    eq->available += qm_cyc_diff(QM_EQCR_SIZE, eq->ci, p->p.cached_ci);
    eq->ci = p->p.cached_ci;
}
#include "cdx_eqcr.inc"
int main(void)
{
    for (u8 producer = 0; producer < 8; producer++) {
        for (u8 pending = 0; pending < 8; pending++) {
            for (u8 lag = 0; lag <= 2 && pending + lag <= 7; lag++) {
                u8 consumer = (producer - pending) & 7;
                u8 cached = (consumer - lag) & 7;
                memset(&portal, 0, sizeof(portal));
                portal.p.hardware_ci = consumer;
                portal.p.cached_ci = cached;
                portal.p.eqcr.ci = cached;
                portal.p.eqcr.available = 7 - pending - lag;
                portal.p.eqcr.cursor = (void *)(uintptr_t)(0x1000 + 64 * producer);
                assert(qman_eqcr_is_empty() == (pending == 0));
                assert(portal.p.eqcr.ci == cached);
                assert(portal.p.eqcr.available == 7 - pending - lag);
                assert(!pins && !locked);
            }
        }
    }
    puts("EQCR: 168 ring positions, pending entries and stale cached indices passed");
    return 0;
}
