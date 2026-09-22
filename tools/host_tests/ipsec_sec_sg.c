#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define __hot
#define unlikely(x) (x)
#define EXPORT_SYMBOL(x)
#define ALIGN(n,a) (((n) + (a) - 1) & ~((a) - 1))
#define SMP_CACHE_BYTES 64
#define DPA_SGT_MAX_ENTRIES 16
#define smp_load_acquire(p) (*(p))
#define phys_to_virt(a) ((void *)(uintptr_t)(a))
#define net_ratelimit() false
#define netdev_err(...) ((void)0)
#define cpu_relax() ((void)0)
typedef uintptr_t dma_addr_t;
typedef uint32_t u32;
enum dma_data_direction { DMA_TO_DEVICE, DMA_BIDIRECTIONAL };
struct device { int refs, id; };
struct net_device { int unused; };
struct qm_sg_entry { uintptr_t addr; unsigned len; unsigned flags; };
_Static_assert(sizeof(struct qm_sg_entry) == 16, "hardware SG entry size");
struct qm_fd { dma_addr_t addr; unsigned format, bpid, cmd, length20, offset; };
enum { qm_fd_sg = 1 };
struct bm_buffer { union { uintptr_t opaque, addr; }; };
struct bman_pool { unsigned ids[128], count; };
struct dpa_bp { struct device *dev; struct bman_pool *pool; unsigned bpid; size_t size; };
typedef struct { void *data; unsigned size; } skb_frag_t;
struct sk_buff;
struct skb_shared_info { struct sk_buff *frag_list; unsigned nr_frags; skb_frag_t frags[17]; };
struct sk_buff { void *data; unsigned len, headlen; struct sk_buff *next; struct skb_shared_info sh; };
#define skb_shinfo(s) (&(s)->sh)
#define skb_walk_frags(s,f) for ((f) = (s)->sh.frag_list; (f); (f) = (f)->next)
static unsigned skb_headlen(struct sk_buff *s) { return s->headlen; }
static unsigned skb_frag_size(skb_frag_t *f) { return f->size; }
static struct device pool_dev = {1, 1}, payload_dev = {1, 2};
static struct bman_pool clean_pool, done_pool;
static struct dpa_bp clean = {&pool_dev, &clean_pool, 31, 1024};
static struct dpa_bp done = {&pool_dev, &done_pool, 32, 1024};
static struct dpa_bp *sg_bpool_g = &clean, *skb_2bfreed_bpool_g = &done;
static unsigned char storage[80][1024] __attribute__((aligned(64)));
static bool cpu_owned[80], linearize_fail;
static unsigned frees, maps, unmaps, fail_at, attempts, release_busy;
struct mapping { struct device *dev; void *ptr; unsigned len; bool page, active; };
static struct mapping mappings[4096];
static unsigned slot(dma_addr_t a)
{
    assert(a >= (uintptr_t)storage && a < (uintptr_t)(storage + 80));
    assert(!((a - (uintptr_t)storage) % 1024));
    return (a - (uintptr_t)storage) / 1024;
}
static int bman_acquire(struct bman_pool *p, struct bm_buffer *b, int count, int flags)
{
    assert(count == 1);
    if (!p->count) return 0;
    unsigned id = p->ids[--p->count];
    assert(!cpu_owned[id]);
    b->addr = (uintptr_t)storage[id];
    return 1;
}
static int bman_release(struct bman_pool *p, const struct bm_buffer *b, int count, int flags)
{
    assert(count == 1 && p->count < 128);
    if (release_busy) { release_busy--; return -EBUSY; }
    unsigned id = slot(b->addr);
    assert(!cpu_owned[id]);
    for (unsigned i = 0; i < p->count; i++) assert(p->ids[i] != id);
    p->ids[p->count++] = id;
    return 0;
}
static void bm_buffer_set64(struct bm_buffer *b, dma_addr_t a) { b->addr = a; }
static dma_addr_t qm_fd_addr(const struct qm_fd *f) { return f->addr; }
static void qm_fd_addr_set64(struct qm_fd *f, dma_addr_t a) { f->addr = a; }
static dma_addr_t qm_sg_addr(struct qm_sg_entry *s) { return s->addr; }
static unsigned qm_sg_entry_get_len(struct qm_sg_entry *s) { return s->len; }
static void qm_sg_entry_set_ext(struct qm_sg_entry *s, int v) { assert(!v); }
static void qm_sg_entry_set_final(struct qm_sg_entry *s, int v) { s->flags = v; }
static void qm_sg_entry_set_bpid(struct qm_sg_entry *s, int v) { assert(v == 255); }
static void qm_sg_entry_set_offset(struct qm_sg_entry *s, int v) { assert(!v); }
static void qm_sg_entry_set_len(struct qm_sg_entry *s, int v) { s->len = v; }
static void qm_sg_entry_set64(struct qm_sg_entry *s, dma_addr_t a) { s->addr = a; }
static struct device *get_device(struct device *d) { assert(d); d->refs++; return d; }
static void put_device(struct device *d) { assert(d->refs > 1); d->refs--; }
static void dma_sync_single_for_cpu(struct device *d, dma_addr_t a, size_t len, enum dma_data_direction dir)
{
    unsigned id = slot(a);
    assert(d == &pool_dev && len == 1024 && dir == DMA_BIDIRECTIONAL && !cpu_owned[id]);
    cpu_owned[id] = true;
}
static void dma_sync_single_for_device(struct device *d, dma_addr_t a, size_t len, enum dma_data_direction dir)
{
    unsigned id = slot(a);
    assert(d == &pool_dev && len == 1024 && dir == DMA_BIDIRECTIONAL && cpu_owned[id]);
    cpu_owned[id] = false;
}
static dma_addr_t map(struct device *d, void *ptr, unsigned len, bool page, enum dma_data_direction dir)
{
    assert(d == &payload_dev && dir == DMA_TO_DEVICE && d->refs > 1);
    assert(ptr && len && ++attempts < 4096);
    if (attempts == fail_at) return 0;
    maps++;
    mappings[attempts] = (struct mapping){d, ptr, len, page, true};
    return attempts;
}
static dma_addr_t dma_map_single(struct device *d, void *ptr, unsigned len, enum dma_data_direction dir)
{ return map(d, ptr, len, false, dir); }
static dma_addr_t skb_frag_dma_map(struct device *d, skb_frag_t *f, int off, unsigned len, enum dma_data_direction dir)
{ assert(!off); return map(d, f->data, len, true, dir); }
static bool dma_mapping_error(struct device *d, dma_addr_t a) { return !a; }
static void unmap(struct device *d, dma_addr_t a, unsigned len, bool page, enum dma_data_direction dir)
{
    assert(a > 0 && a < 4096 && dir == DMA_TO_DEVICE);
    struct mapping *m = &mappings[a];
    assert(m->active && m->dev == d && m->len == len && m->page == page);
    m->active = false;
    unmaps++;
}
static void dma_unmap_single(struct device *d, dma_addr_t a, unsigned len, enum dma_data_direction dir)
{ unmap(d, a, len, false, dir); }
static void dma_unmap_page(struct device *d, dma_addr_t a, unsigned len, enum dma_data_direction dir)
{ unmap(d, a, len, true, dir); }
static void free_data(void *ptr)
{
    for (unsigned i = 1; i <= attempts; i++)
        assert(!mappings[i].active || mappings[i].ptr != ptr);
    free(ptr);
}
static void free_skb(struct sk_buff *s)
{
    struct sk_buff *f = s->sh.frag_list;
    while (f) { struct sk_buff *next = f->next; free_skb(f); f = next; }
    for (unsigned i = 0; i < s->sh.nr_frags; i++) free_data(s->sh.frags[i].data);
    free_data(s->data);
    free(s);
}
static void dev_kfree_skb_any(struct sk_buff *s) { frees++; free_skb(s); }
static int skb_linearize(struct sk_buff *s)
{
    if (linearize_fail) return -ENOMEM;
    assert(!s->sh.frag_list);
    for (unsigned i = 0; i < s->sh.nr_frags; i++) free_data(s->sh.frags[i].data);
    s->sh.nr_frags = 0;
    return 0;
}
#include "ipsec_sec_sg.inc"

static struct sk_buff *packet(unsigned frags)
{
    struct sk_buff *s = calloc(1, sizeof(*s));
    assert(s && frags <= 17);
    s->data = calloc(1, 64); s->headlen = 64; s->sh.nr_frags = frags;
    for (unsigned i = 0; i < frags; i++) s->sh.frags[i] = (skb_frag_t){calloc(1, 32), 32};
    s->len = 64 + 32 * frags;
    return s;
}
static void reset(unsigned count)
{
    assert(maps == unmaps && payload_dev.refs == 1 && pool_dev.refs == 1);
    memset(&clean_pool, 0, sizeof(clean_pool)); memset(&done_pool, 0, sizeof(done_pool));
    memset(mappings, 0, sizeof(mappings)); memset(cpu_owned, 0, sizeof(cpu_owned));
    for (unsigned i = 0; i < count; i++) clean_pool.ids[clean_pool.count++] = i;
    memset(storage, 0xa5, sizeof(storage));
    frees = maps = unmaps = attempts = fail_at = release_busy = 0;
    linearize_fail = false;
}
static struct qm_fd submit(struct sk_buff *s)
{
    struct qm_fd fd = {0};
    assert(!skb_fraglist_to_sg_fd(&payload_dev, NULL, s, &fd, 0x42));
    assert(fd.format == qm_fd_sg && fd.bpid == done.bpid && fd.cmd == 0x42 && fd.length20 == s->len);
    return fd;
}
static void completed(struct qm_fd *fd)
{
    struct bm_buffer b = {.addr = fd->addr};
    assert(!bman_release(&done_pool, &b, 1, 0));
}
int main(void)
{
    /* Every partial mapping prefix across heads, page frags and frag_list. */
    for (unsigned failure = 1; failure <= 6; failure++) {
        reset(1);
        struct sk_buff *s = packet(2);
        s->sh.frag_list = packet(1); s->sh.frag_list->next = packet(0);
        fail_at = failure;
        struct qm_fd fd;
        assert(skb_fraglist_to_sg_fd(&payload_dev, NULL, s, &fd, 0) == -ENOMEM);
        assert(maps == failure - 1 && unmaps == maps && clean_pool.count == 1 && !frees);
        assert(payload_dev.refs == 1);
        free_skb(s);
    }
    reset(1);
    struct sk_buff *s = packet(2);
    s->sh.frag_list = packet(1); s->sh.frag_list->next = packet(0);
    struct qm_fd fd = submit(s);
    assert(!dpaa_sec_sg_reap(64) && !frees && !unmaps); /* still in hardware */
    completed(&fd);
    release_busy = 3;
    assert(dpaa_sec_sg_reap(64) == 1 && frees == 1 && maps == 6 && unmaps == 6);
    assert(clean_pool.count == 1 && payload_dev.refs == 1);
    /* Reuse and an idle reaper compete through BMan ownership, never both free. */
    fd = submit(packet(15)); completed(&fd);
    unsigned old_frees = frees;
    fd = submit(packet(0));
    assert(frees == old_frees + 1 && !dpaa_sec_sg_reap(64));
    dpaa_sec_sg_release(&fd, true); /* asynchronous rejection */
    assert(frees == old_frees + 2 && maps == unmaps);
    s = packet(3); fd = submit(s);
    dpaa_sec_sg_release(&fd, false); /* inbound synchronous giveback */
    assert(frees == old_frees + 2 && maps == unmaps && payload_dev.refs == 1);
    free_skb(s);
    reset(0); s = packet(0);
    assert(skb_fraglist_to_sg_fd(&payload_dev, NULL, s, &fd, 0) == -ENOBUFS);
    assert(!maps && !frees); free_skb(s);
    reset(1); s = packet(17); linearize_fail = true;
    assert(skb_fraglist_to_sg_fd(&payload_dev, NULL, s, &fd, 0) == -ENOMEM);
    assert(clean_pool.count == 1 && !maps);
    linearize_fail = false; fd = submit(s); completed(&fd);
    assert(dpaa_sec_sg_reap(64) == 1 && maps == 1 && unmaps == 1);
    reset(80);
    for (unsigned i = 0; i < 80; i++) { fd = submit(packet(0)); completed(&fd); }
    /* Builder reuse above is intentional; hold submissions in hardware first. */
    assert(dpaa_sec_sg_reap(64) == 1 && frees == 80);
    struct qm_fd fds[80];
    for (unsigned i = 0; i < 80; i++) fds[i] = submit(packet(1));
    for (unsigned i = 0; i < 80; i++) completed(&fds[i]);
    assert(dpaa_sec_sg_reap(64) == 64 && done_pool.count == 16);
    assert(dpaa_sec_sg_reap(64) == 16 && clean_pool.count == 80 && frees == 160);
    assert(maps == unmaps && payload_dev.refs == 1);
    skb_2bfreed_bpool_g = NULL;
    assert(!dpaa_sec_sg_reap(64));
    sg_bpool_g = NULL;
    assert(!dpaa_sec_sg_reap(64));
    return 0;
}
