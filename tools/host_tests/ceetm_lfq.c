/* Exercise the SDK claim/release functions, including both FMan pools. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint32_t u32;
typedef uint16_t u16;
#define GFP_KERNEL 0
#define cpu_to_be16(x) (x)
#define cpu_to_be24(x) (x)
#define pr_err(...) ((void)0)
#define CEETM_LFQMT_LFQID_MSB 0xF00000
#define CEETM_LFQMT_LFQID_LSB 0x000FFF
#define qm_dc_portal_fman0 0
#define qm_dc_portal_fman1 1
struct list_head { struct list_head *next, *prev; };
static void list_add_tail(struct list_head *n, struct list_head *h)
{ n->next = h; n->prev = h->prev; h->prev->next = n; h->prev = n; }
static void list_del(struct list_head *n)
{ n->prev->next = n->next; n->next->prev = n->prev; }
struct qm_ceetm_channel { unsigned dcp_idx, idx; };
struct qm_ceetm_cq {
    unsigned idx;
    struct qm_ceetm_channel *parent;
    struct list_head bound_lfqids;
};
struct qm_ceetm_lfq {
    unsigned idx, dctidx;
    struct qm_ceetm_channel *parent;
    struct list_head node;
};
struct qm_mcc_ceetm_lfqmt_config { unsigned lfqid, cqid, dctidx; };
static unsigned stage, fail_at, ids[2], objects;
static bool fails(void) { return ++stage == fail_at; }
static int alloc_id(unsigned fm, u32 *id)
{ if (fails()) return -ENOSPC; assert(!ids[fm]); ids[fm]++; *id = 0xF00001 + (fm << 16); return 0; }
static int qman_alloc_ceetm0_lfqid(u32 *id) { return alloc_id(0, id); }
static int qman_alloc_ceetm1_lfqid(u32 *id) { return alloc_id(1, id); }
static void release_id(unsigned fm, u32 id)
{ assert(ids[fm] == 1 && id == 0xF00001 + (fm << 16)); ids[fm]--; }
static void qman_release_ceetm0_lfqid(u32 id) { release_id(0, id); }
static void qman_release_ceetm1_lfqid(u32 id) { release_id(1, id); }
static void *kmalloc(size_t size, int flags)
{ if (fails()) return NULL; void *p = malloc(size); assert(p); objects++; return p; }
static void kfree(void *p) { assert(objects); objects--; free(p); }
static int qman_ceetm_configure_lfqmt(struct qm_mcc_ceetm_lfqmt_config *cfg)
{ return fails() ? -EIO : 0; }
#define CONFIG_FSL_DPA_PORTAL_SHARE
#define QM_PIRQ_MRI 1
struct qman_portal { void *sharing_redirect; int p; };
static struct qman_portal portal;
static unsigned pending_erns, pins, polls, irq_status;
static bool irq_enabled = true;
static struct qman_portal *get_raw_affine_portal(void) { pins++; return &portal; }
static void put_affine_portal(void) { assert(pins); pins--; }
#define local_irq_save(flags) do { (flags) = irq_enabled; irq_enabled = false; } while (0)
#define local_irq_restore(flags) do { irq_enabled = (flags); } while (0)
static unsigned __poll_portal_slow(struct qman_portal *p, unsigned sources)
{
    assert(!irq_enabled && p == &portal && sources == QM_PIRQ_MRI);
    polls++; pending_erns = 0; return QM_PIRQ_MRI;
}
static void qm_isr_status_clear(int *p, unsigned sources)
{ assert(!irq_enabled && p == &portal.p); irq_status &= ~sources; }
#include "lfq_production.inc"
int main(void)
{
    for (unsigned fm = 0; fm < 2; fm++) {
        struct qm_ceetm_channel channel = {.dcp_idx = fm, .idx = 37};
        struct qm_ceetm_cq cq = {.parent = &channel, .idx = 7};
        cq.bound_lfqids.next = cq.bound_lfqids.prev = &cq.bound_lfqids;
        for (unsigned failure = 0; failure <= 3; failure++) {
            struct qm_ceetm_lfq *lfq = NULL;
            fail_at = failure; stage = 0;
            int ret = qman_ceetm_lfq_claim(&lfq, &cq);
            assert(failure ? ret < 0 : ret == 0);
            if (failure) assert(!lfq);
            else assert(qman_ceetm_lfq_release(lfq) == 0);
            assert(!objects && !ids[0] && !ids[1]);
            assert(cq.bound_lfqids.next == &cq.bound_lfqids);
            assert(cq.bound_lfqids.prev == &cq.bound_lfqids);
        }
    }
    puts("both FMan pools: ID, allocation and mapping failures passed");
    pending_erns = 3;
    irq_status = 0;
    qman_drain_ern();
    assert(!pending_erns && !pins && irq_enabled && polls == 1);
    qman_drain_ern();
    assert(!pins && irq_enabled && polls == 2);
    portal.sharing_redirect = &portal;
    qman_drain_ern();
    assert(!pins && irq_enabled && polls == 2);
    puts("pending ERNs drain even without an IRQ status bit; shared portal ownership preserved");
    return 0;
}
