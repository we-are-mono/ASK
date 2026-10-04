#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#undef errno

#define CS_TAIL_DROP
#define MAX_MATCH_TABLES 4
#define IPSEC_FMAN_IDX 0
#define PORT_TYPE_IPSEC 1
#define IPSEC_BUFSIZE 2048
#define IPSEC_BUFCOUNT 512
#define PORTID_SHIFT_VAL 8
#define NR_CPUS 4
#define FQ_TYPE_RX_PCD 1
#define DEFA_WQ_ID 1
#define NUM_PKT_DATA_LINES_IN_CACHE 2
#define NUM_ANN_LINES_IN_CACHE 1
#define PCD_DIR 1
#define SA_DIR 2
#define IPSEC_WQ_ID 2
#define NUM_FQS_PER_SA 3
#define FQ_FROM_SEC 0
#define FQ_TO_SEC 1
#define FQ_TO_CP 2
#define PRE_HDR_ALIGN 64
#define THIS_MODULE NULL
#define virt_to_phys(p) ((uintptr_t)(p))
#define CDX_FQD_CTX_A_OVERRIDE_FQ 1
#define CDX_FQD_CTX_A_A1_FIELD_VALID 2
#define CDX_FQD_CTX_A_SHIFT_BITS 24
#define CDX_FQD_CTX_A_A1_VAL_TO_CHECK_SECERR 2
#define QMAN_FQ_FLAG_TO_DCPORTAL 1
#define QM_FQCTRL_CPCSTASH 4
#define QM_FQCTRL_CGE 8
#define QM_INITFQ_WE_CGID 16
#define SUCCESS 0
#define FAILURE 1
#define GFP_KERNEL 0
#define GFP_DMA 0
#define GFP_ATOMIC 0
#define __GFP_COMP 1
#define PAGE_SIZE 4096
#define DMA_BIDIRECTIONAL 0
#define DMA_TO_DEVICE 1
#define SMP_CACHE_BYTES 64
#define ALIGN(n, a) (((n) + (a) - 1) & ~((a) - 1))
#define DPAA_EXTRA_BUF_SIZE_4_SKB 128
#define DPA_MAX_FD_OFFSET 64
#define DPA_SKB_SIZE(x) (x)
#define PTR_ALIGN(p, a) ((void *)(((uintptr_t)(p) + (a) - 1) & ~((uintptr_t)(a) - 1)))
#define unlikely(x) (x)
#define KERN_INFO ""
#define printk(...) do { } while (0)
#define pr_err(...) do { } while (0)
#define pr_err_ratelimited(...) do { } while (0)
#define dev_err(...) do { } while (0)
#define pr_debug(...) do { } while (0)
/* Counted: an SA release says out loud what it waits on. */
static unsigned warnings, warn_ons;
#define pr_warn_ratelimited(fmt, ...) ((void)sizeof(printf(fmt, ##__VA_ARGS__)), warnings++)
#define pr_info(...) do { } while (0)
#define WARN_ON_ONCE(c) ({ bool c_ = (c); if (c_) warn_ons++; c_; })
#define DPAIPSEC_INFO(...) do { } while (0)
#define DPAIPSEC_ERROR(...) do { } while (0)
#define EXPORT_SYMBOL(x)
#define smp_load_acquire(p) (*(p))
#define smp_store_release(p, v) (*(p) = (v))
#define WRITE_ONCE(p, v) ((p) = (v))
/* The published SEC pool BPID, module_param_cb in production. */
static int ipsec_bpid = -1;
#define DPA_WRITE_SKB_PTR(skb, skbh, addr, off) do { skbh = (void *)(addr); skbh[off] = skb; } while (0)
#define DPA_READ_SKB_PTR(skb, skbh, addr, off) do { skbh = (void *)(addr); skb = skbh[off]; } while (0)
#define cpu_to_be16(v) (v)
#define phys_to_virt(v) ((void *)(uintptr_t)(v))
#define QMAN_INITFQ_FLAG_SCHED 1
#define QM_INITFQ_WE_DESTWQ 1
#define QM_INITFQ_WE_FQCTRL 2
#define QM_INITFQ_WE_CONTEXTB 4
#define QM_INITFQ_WE_CONTEXTA 8
#define QM_FQCTRL_PREFERINCACHE 1
#define QM_FQCTRL_HOLDACTIVE 2
#define QM_STASHING_EXCL_DATA 1
#define QM_STASHING_EXCL_ANNOTATION 2
#define QMAN_FQ_STATE_CHANGING 1
#define QMAN_FQ_STATE_ORL 2
#define QMAN_FQ_STATE_NE 4
#define QMAN_FQ_STATE_VDQCR 8
#define QMAN_VOLATILE_FLAG_WAIT 1
#define QMAN_VOLATILE_FLAG_FINISH 2
#define QM_VDQCR_NUMFRAMES_TILLEMPTY 1
#define QM_DQRR_STAT_FQ_EMPTY 0x80
#define QM_DQRR_STAT_DQCR_EXPIRED 0x01
#define QM_DQRR_STAT_FD_VALID 0x10
#define QM_CGR_WE_CSCN_EN 1
#define QM_CGR_WE_CS_THRES 2
#define QM_CGR_WE_MODE 4
#define QM_CGR_WE_CSTD_EN 8
#define QM_CGR_EN 1
#define QMAN_CGR_FLAG_USE_INIT 1

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
typedef uint64_t U64;
typedef uint32_t U32;
typedef uint16_t U16;
typedef uint8_t U8;
typedef uintptr_t dma_addr_t;
typedef int cpumask_t;
#define for_each_cpu(i, mask) for ((i) = 0; (i) < *(mask); (i)++)
#define READ_ONCE(x) (x)
#define BIT(n) (1u << (n))
/* Jiffies, which the harness moves a timer period per tick. */
#define HZ 100
static unsigned long jiffies = 1000;
#define time_before(a, b) ((long)((a) - (b)) < 0)
#define time_after_eq(a, b) ((long)((a) - (b)) >= 0)
#define jiffies_to_msecs(j) ((unsigned)(j) * 1000 / HZ)
#define rmb() do { } while (0)
struct device { struct device *parent; void *drvdata; };
static void *dev_get_drvdata(struct device *dev) { return dev->drvdata; }
/* The frame descriptors an SA queue holds or QMan hands back. */
enum qm_fd_format { qm_fd_contig, qm_fd_sg };
struct qm_fd { enum qm_fd_format format; unsigned bpid; dma_addr_t addr; };
#define qm_fd_addr(fd) ((fd)->addr)
#define qm_fd_addr_get64(fd) ((fd)->addr)
struct qm_dqrr_entry { unsigned stat, fqid; struct qm_fd fd; };
struct qm_mr_entry { struct { unsigned rc; struct qm_fd fd; } ern; };
enum qman_cb_dqrr_result { qman_cb_dqrr_consume, qman_cb_dqrr_stop };
struct qman_portal { int unused; };
typedef struct { int counter; } atomic_t;
#define ATOMIC_INIT(n) { (n) }
static int atomic_inc_return(atomic_t *v) { return ++v->counter; }
struct sec_descriptor { char data[128]; };
typedef struct { void *proc_dir; } cdx_proc_dir_entry_t;
struct sk_buff { void *head; bool head_frag; };
struct page { void *addr; unsigned refs, size; struct page *next; };
struct bm_buffer { union { dma_addr_t addr; uint64_t opaque; }; unsigned bpid; };
struct bman_pool { unsigned count; struct bm_buffer buffers[IPSEC_BUFCOUNT]; };
struct dpa_bp {
    struct device *dev; size_t size; unsigned config_count, bpid;
    struct bman_pool *pool; int refs; void (*free_buf_cb)(void *);
};
struct port_bman_pool_info { unsigned pool_id; };
/* Singly linked where CDX threads its queue lists by hand; the kernel's own
 * list where it keeps held FQID ranges. */
struct list_head { struct list_head *next, *prev; };
#define LIST_HEAD(n) struct list_head n = { &n, &n }
#define list_entry(p, t, m) ((t *)((char *)(p) - __builtin_offsetof(t, m)))
#define list_for_each_entry_safe(p, n, h, m) \
    for (p = list_entry((h)->next, __typeof__(*p), m), n = list_entry(p->m.next, __typeof__(*p), m); \
         &p->m != (h); p = n, n = list_entry(n->m.next, __typeof__(*n), m))
static void list_add_tail(struct list_head *e, struct list_head *h)
{ e->next = h; e->prev = h->prev; h->prev->next = e; h->prev = e; }
static void list_del(struct list_head *e) { e->prev->next = e->next; e->next->prev = e->prev; }
/* The datapath epoch, which a restart moves on, read under the control
 * mutex. */
static struct { struct { bool mutex; } ctrl; } cdx_instance = { { true } }, *cdx_info = &cdx_instance;
#define lockdep_assert_held(m) assert(*(m))
static unsigned datapath_epoch = 1;
static unsigned cdx_ft_epoch(void) { assert(cdx_info->ctrl.mutex); return datapath_epoch; }
enum qman_fq_state { qman_fq_state_oos, qman_fq_state_sched, qman_fq_state_retired };
/* A queue with the frames it holds, which retirement leaves on it and a
 * volatile dequeue delivers through its callback. */
struct qman_fq {
    unsigned fqid, flags, pending, held; bool acquired, proc;
    struct qm_fd frames[4];
    enum qman_fq_state state;
    struct {
        enum qman_cb_dqrr_result (*dqrr)(struct qman_portal *, struct qman_fq *,
                                         const struct qm_dqrr_entry *);
        void (*ern)(struct qman_portal *, struct qman_fq *, const struct qm_mr_entry *);
    } cb;
};
struct dpa_fq {
    struct qman_fq fq_base; struct list_head list;
    unsigned fq_type, fqid, channel, wq;
};
struct qm_mcc_initfq {
    unsigned fqid, count, we_mask;
    struct { unsigned fq_ctrl, context_b, cgid; struct { unsigned channel, wq; } dest;
             struct { unsigned hi, lo; struct { unsigned exclusive, data_cl, annotation_cl; } stashing; } context_a; } fqd;
};
struct dpa_iface_info { void *pcd_proc_entry; };
struct qman_cgr { unsigned cgrid; void (*cb)(void); };
struct threshold { unsigned TA, Tn; };
struct qm_mcc_initcgr {
    unsigned we_mask;
    struct { unsigned cscn_en, mode, cstd_en; struct threshold cs_thres; } cgr;
};
/* A bounded allocator and checked refs model the kernel APIs, including
 * exhaustion and reuse. The lifecycle and tag-sharing code is compiled. */
#define VLAN_N_VID 4096
#define VLAN_VID_MASK 4095
#define DEFINE_IDA(n) struct { bool used[VLAN_N_VID]; } n
static unsigned tags;
static bool fault(void);
static int tag_alloc(bool *used, unsigned lo, unsigned hi)
{
    if (fault()) return -ENOMEM;
    for (unsigned i = lo; i <= hi; i++)
        if (!used[i]) { used[i] = true; tags++; return i; }
    return -ENOSPC;
}
#define ida_alloc_range(p, lo, hi, flags) tag_alloc((p)->used, lo, hi)
#define ida_free(p, i) do { assert((p)->used[i] && tags); (p)->used[i] = false; tags--; } while (0)
#define ida_destroy(p) do { assert(!tags); } while (0)
typedef unsigned refcount_t;
static void refcount_set(refcount_t *r, unsigned n) { assert(!*r); *r = n; }
static void refcount_inc(refcount_t *r) { assert(*r); ++*r; }
static bool refcount_dec_and_test(refcount_t *r) { assert(*r); return !--*r; }
#include "ipsec_types.inc"
static bool dpa_ipsec_ready;
static unsigned sec_congestion, qm_channel_caam;
static struct device device;
static struct dpa_bp parent = { .dev = &device };
static struct dpa_bp *dpa_bp_array[64];
static struct dpa_bp *sg_bpool_g, *skb_2bfreed_bpool_g;
static struct dpa_iface_info iface = { .pcd_proc_entry = &iface };
static cpumask_t cpus = 2;
static unsigned steps, fail_step, allocs, mappings, queues, proc_entries, callbacks;
static unsigned retires_failed, oos_failed, cgr_deletes_failed, pauses;
static unsigned seed_step, seed_fail, port_releases, registrations;
static int current_cpu;
static const char *seed_failure;
static bool port, cgr, cgrid;
static unsigned preempt_count;
static unsigned module_refs;
static bool module_going, sa_range;
static void (*exit_callback)(void);
static struct qman_fq *fq_registry[1024];
static struct page *pages;
static bool refill_running;
static void ipsec_pool_refill_start(void) { assert(!refill_running); refill_running = true; }
static void ipsec_pool_refill_stop(void) { refill_running = false; }
static unsigned dpaa_sec_sg_reap(unsigned budget)
{ assert(!refill_running && budget == 512); return 0; }

static bool fault(void) { return ++steps == fail_step; }
static bool seed_fault(const char *kind)
{
    return seed_failure && !strcmp(seed_failure, kind) && ++seed_step == seed_fail;
}
static void *kmalloc(size_t size, int flags)
{
    if (seed_fault("head")) return NULL;
    void *p = aligned_alloc(SMP_CACHE_BYTES, ALIGN(size, SMP_CACHE_BYTES)); assert(p); allocs++; return p;
}
static void *kzalloc(size_t size, int flags)
{
    if (fault()) return NULL;
    void *p = calloc(1, size); assert(p); allocs++; return p;
}
static void kfree(void *p) { if (p) { assert(allocs); allocs--; free(p); } }
static unsigned get_order(unsigned size)
{ unsigned order = 0; while ((PAGE_SIZE << order) < size) order++; return order; }
static struct page *alloc_pages(int flags, unsigned order)
{
    assert(flags & __GFP_COMP);
    if (seed_fault("head")) return NULL;
    struct page *p = calloc(1, sizeof(*p)); assert(p);
    p->size = PAGE_SIZE << order;
    p->addr = aligned_alloc(PAGE_SIZE, p->size); assert(p->addr);
    p->refs = 1; p->next = pages; pages = p; allocs += 2;
    return p;
}
static void *page_address(struct page *p) { assert(p->refs); return p->addr; }
static struct page *virt_to_head_page(void *addr)
{
    for (struct page *p = pages; p; p = p->next)
        if (addr >= p->addr && (char *)addr < (char *)p->addr + p->size) return p;
    assert(!"slab allocation cannot be retained as an skb page fragment");
    return NULL;
}
static void get_page(struct page *p) { assert(p->refs); p->refs++; }
static void put_page(struct page *p)
{
    assert(p->refs);
    if (--p->refs) return;
    struct page **link = &pages;
    while (*link != p) link = &(*link)->next;
    *link = p->next;
    kfree(p->addr); kfree(p);
}
static struct sk_buff *build_skb(void *head, unsigned size)
{
    if (seed_fault("skb")) return NULL;
    struct sk_buff *skb = malloc(sizeof(*skb)); assert(skb); allocs++;
    assert(virt_to_head_page(head)->size == size);
    skb->head = head; skb->head_frag = true; return skb;
}
static void skb_reserve(struct sk_buff *skb, unsigned bytes) { assert(bytes >= sizeof(void *)); }
static void kfree_skb(struct sk_buff *skb)
{ assert(skb->head_frag); put_page(virt_to_head_page(skb->head)); kfree(skb); }
#define dev_kfree_skb_any kfree_skb
static dma_addr_t dma_map_single(struct device *dev, void *p, size_t size, int direction)
{
    if (seed_fault("dma")) return 0;
    mappings++; return (uintptr_t)p;
}
static bool dma_mapping_error(struct device *dev, dma_addr_t addr) { return !addr; }
static void dma_unmap_single(struct device *dev, dma_addr_t addr, size_t size, int dir)
{ assert(addr && mappings); mappings--; }
static void bm_buffer_set64(struct bm_buffer *b, dma_addr_t addr) { b->addr = addr; }
static dma_addr_t bm_buf_addr(const struct bm_buffer *b) { return b->addr; }
static void cpu_relax(void) { }
static int bman_release(struct bman_pool *pool, struct bm_buffer *b, unsigned count, int flags)
{
    assert(pool && pool->count + count <= IPSEC_BUFCOUNT);
    memcpy(pool->buffers + pool->count, b, count * sizeof(*b)); pool->count += count;
    return 0;
}
static int bman_acquire(struct bman_pool *pool, struct bm_buffer *b, unsigned count, int flags)
{
    assert(pool && count);
    if (pool->count < count) return -ENOMEM;
    pool->count -= count;
    memcpy(b, pool->buffers + pool->count, count * sizeof(*b)); return count;
}
static void bman_free_pool(struct bman_pool *pool)
{
    assert(!pool->count && !queues && !callbacks);
    free(pool);
}
static struct dpa_bp *dpa_bpid2pool(unsigned bpid)
{ return bpid == 1 ? &parent : dpa_bp_array[bpid]; }
static bool atomic_dec_and_test(int *value) { assert(*value > 0); return !--*value; }
static int dpa_bp_alloc(struct dpa_bp *bp, struct device *dev)
{
    if (fault()) return -ENOMEM;
    unsigned id = 2;
    while (dpa_bp_array[id]) id++;
    assert(id < 64); bp->bpid = id; bp->refs = 1;
    bp->pool = calloc(1, sizeof(*bp->pool)); assert(bp->pool);
    dpa_bp_array[id] = bp; return 0;
}
static int get_phys_port_poolinfo_bysize(unsigned size, struct port_bman_pool_info *p)
{ if (fault()) return -ENOENT; p->pool_id = 1; return 0; }
static int alloc_offline_port(unsigned fm, unsigned type, void *rx, void *err)
{ if (fault()) return -ENOENT; assert(!port); port = true; return 0; }
static int release_offline_port(unsigned fm, int handle)
{ assert(port && handle == 0 && !queues && !callbacks); port = false; port_releases++; return 0; }
static int get_ofport_info(unsigned fm, int handle, unsigned *channel, void **td)
{ if (fault()) return -EIO; assert(port); *channel = 1; td[0] = &iface; return 0; }
static int get_ofport_portid(unsigned fm, int handle, unsigned *id)
{ if (fault()) return -EIO; assert(port); *id = 1; return 0; }
static const cpumask_t *qman_affine_cpus(void) { return &cpus; }
static unsigned qman_affine_channel(unsigned cpu) { return cpu; }
static int get_ofport_max_dist(unsigned fm, int handle, unsigned *count)
{ if (fault()) return -EIO; *count = 3; return 0; }
static struct dpa_iface_info *dpa_get_ohifinfo_by_portid(unsigned id)
{ return fault() ? NULL : &iface; }
static int get_oh_port_pcd_fqinfo(unsigned fm, int handle, unsigned dist, unsigned *base, unsigned *count)
{ if (fault()) return -EIO; *base = dist * 4; *count = 4; return 0; }
/* What a frame an SA queue gave back was dropped as: a software SEC input
 * through the SEC SG release, anything else through the common release. */
static unsigned sg_releases, fd_releases, cp_drops;
static void dpaa_sec_sg_release(const struct qm_fd *fd, bool free_skb)
{
    assert(free_skb && fd->format == qm_fd_sg && fd->bpid == skb_2bfreed_bpool_g->bpid);
    assert(fd->addr && sg_bpool_g);
    sg_releases++;
}
struct net_device;
static void dpa_fd_release(const struct net_device *dev, const struct qm_fd *fd)
{ assert(!dev && fd->addr); fd_releases++; }
/* The SA whose release is under way, which the CPU receive callback cannot
 * resolve any more: it marked itself SA_DELETE first. */
static U16 *releasing_flags;
static enum qman_cb_dqrr_result ipsec_exception_pkt_handler(struct qman_portal *qm,
        struct qman_fq *fq, const struct qm_dqrr_entry *dq)
{
    if (dq->stat & QM_DQRR_STAT_FD_VALID) {
        assert(releasing_flags && (*releasing_flags & SA_DELETE));
        cp_drops++;
    }
    return qman_cb_dqrr_consume;
}
static bool try_module_get(void *module)
{ if (module_going) return false; module_refs++; return true; }
static void __module_get(void *module) { assert(module_refs); module_refs++; }
static void module_put(void *module)
{
    assert(module_refs && !callbacks);
    for (unsigned i = 512; i < 515; i++) assert(!fq_registry[i]);
    module_refs--;
}
static int qman_alloc_fqid_range(unsigned *base, unsigned count, int align, int partial)
{
    if (fault()) return -ENOMEM;
    assert(!sa_range && module_refs); sa_range = true; *base = 512; return count;
}
static void qman_release_fqid_range(unsigned base, unsigned count)
{ assert(base == 512 && count == NUM_FQS_PER_SA && sa_range); sa_range = false; }
static int cdx_create_dir_in_procfs(void **entry, void *name, unsigned parent_id)
{
    cdx_proc_dir_entry_t *p = kzalloc(sizeof(*p), 0);
    if (!p) return -ENOMEM;
    p->proc_dir = p; *entry = p; return 0;
}
static void proc_remove(void *p) { assert(p); }
static int qman_create_fq(unsigned id, unsigned flags, struct qman_fq *fq)
{
    if (fault()) return -ENOMEM;
    assert(port && !fq_registry[id]); fq->fqid = id; fq->acquired = true;
    fq_registry[id] = fq; queues++; return 0;
}
static int qman_init_fq(struct qman_fq *fq, unsigned flags, void *opts)
{ if (fault()) return -EIO; fq->state = qman_fq_state_sched; return 0; }
static void cdx_create_type_fqid_info_in_procfs(struct qman_fq *fq, int dir, void *entry, void *arg)
{ assert(fq->acquired); fq->proc = true; proc_entries++; }
static void cdx_remove_fqid_info_in_procfs(unsigned id)
{ assert(fq_registry[id]->proc && proc_entries); fq_registry[id]->proc = false; proc_entries--; }
static void qman_destroy_fq(struct qman_fq *fq, unsigned flags)
{
    assert(fq->acquired && !fq->proc && fq->state == qman_fq_state_oos);
    assert(!callbacks && queues && fq_registry[fq->fqid] == fq);
    fq_registry[fq->fqid] = NULL; fq->acquired = false; queues--;
}
/* Retirement completes immediately, or after this many looks at the queue;
 * a PCD queue always retires holding a frame. */
static bool retire_at_once;
static unsigned retire_looks = 2, vdq_busy;
static void retired(struct qman_fq *fq)
{
    fq->flags &= ~QMAN_FQ_STATE_CHANGING; fq->state = qman_fq_state_retired;
    if (fq->fqid < 512 || fq->held) fq->flags |= QMAN_FQ_STATE_NE;
}
static void qman_fq_state(struct qman_fq *fq, enum qman_fq_state *state, u32 *flags)
{
    assert(fq->acquired && ipsecinfo.ipsec_bp);
    assert(fq->fqid >= 512 ? module_refs > 0 : !dpa_ipsec_ready);
    if (fq->flags & QMAN_FQ_STATE_CHANGING) {
        if (!fq->pending--) retired(fq);
    }
    if (state) *state = fq->state;
    if (flags) *flags = fq->flags;
}
static int qman_retire_fq(struct qman_fq *fq, void *flags)
{
    /* Only a scheduled queue, and never one already retiring. */
    assert(fq->state == qman_fq_state_sched && !(fq->flags & QMAN_FQ_STATE_CHANGING));
    if (retires_failed) { retires_failed--; return -EIO; }
    if (retire_at_once) { retired(fq); return 0; }
    fq->flags = QMAN_FQ_STATE_CHANGING;
    fq->pending = retire_looks; return 1;
}
/* The portal delivering a volatile dequeue: every frame left, then the entry
 * that finds the queue empty and ends the command. */
static void vdq_deliver(struct qman_fq *fq)
{
    struct qm_dqrr_entry dq = { .fqid = fq->fqid };
    assert(fq->flags & QMAN_FQ_STATE_VDQCR);
    for (unsigned i = 0; i < fq->held; i++) {
        dq.stat = QM_DQRR_STAT_FD_VALID; dq.fd = fq->frames[i];
        assert(fq->cb.dqrr(NULL, fq, &dq) == qman_cb_dqrr_consume);
    }
    fq->held = 0;
    dq.stat = QM_DQRR_STAT_FQ_EMPTY | QM_DQRR_STAT_DQCR_EXPIRED;
    memset(&dq.fd, 0, sizeof(dq.fd));
    assert(fq->cb.dqrr(NULL, fq, &dq) == qman_cb_dqrr_consume);
    fq->flags &= ~(QMAN_FQ_STATE_NE | QMAN_FQ_STATE_VDQCR);
    callbacks++;
}
static int qman_volatile_dequeue(struct qman_fq *fq, unsigned flags, unsigned count)
{
    assert(ipsecinfo.ipsec_bp && dpa_bp_array[2] == ipsecinfo.ipsec_bp);
    assert(fq->cb.dqrr && fq->state == qman_fq_state_retired);
    assert(count == QM_VDQCR_NUMFRAMES_TILLEMPTY && !(fq->flags & QMAN_FQ_STATE_VDQCR));
    if (vdq_busy && !(flags & QMAN_VOLATILE_FLAG_WAIT)) { vdq_busy--; return -EBUSY; }
    fq->flags |= QMAN_FQ_STATE_VDQCR;
    /* Waiting for the finish: the frames are delivered before it returns.
     * Otherwise later, when the portal is next polled. */
    if (flags & QMAN_VOLATILE_FLAG_FINISH) vdq_deliver(fq);
    return 0;
}
static void portal_poll(void)
{
    for (unsigned i = 0; i < 1024; i++)
        if (fq_registry[i] && (fq_registry[i]->flags & QMAN_FQ_STATE_VDQCR))
            vdq_deliver(fq_registry[i]);
}
static int qman_oos_fq(struct qman_fq *fq)
{
    if (oos_failed) { oos_failed--; return -EBUSY; }
    assert(fq->state == qman_fq_state_retired && !fq->flags);
    /* A frame QMan holds that the queue's state did not show: refused. */
    if (fq->held) return -EBUSY;
    if (fq->fqid >= 512) callbacks++;
    fq->state = qman_fq_state_oos; return 0;
}
static void synchronize_net(void)
{ assert(!dpa_ipsec_ready || module_refs); callbacks = 0; }
static void usleep_range(unsigned lo, unsigned hi)
{ assert(!dpa_ipsec_ready || module_refs); pauses++; assert(pauses < 1000); }
static void preempt_disable(void) { preempt_count++; }
static void preempt_enable(void) { assert(preempt_count); preempt_count--; }
static int smp_processor_id(void) { assert(preempt_count); return current_cpu; }
static int qman_alloc_cgrid(unsigned *id)
{ if (fault()) return -ENOMEM; assert(!cgrid); cgrid = true; *id = 0; return 0; }
static void cgr_cb(void) { }
static void qm_cgr_cs_thres_set64(struct threshold *threshold, unsigned value, int mode) { }
static int qman_create_cgr(struct qman_cgr *p, unsigned flags, struct qm_mcc_initcgr *opts)
{
    assert(preempt_count && ipsecinfo.cgr.cpu == current_cpu && cgrid);
    if (fault()) return -EIO;
    assert(!cgr); cgr = true; return 0;
}
static int smp_call_function_single(int cpu, void (*fn)(void *), void *arg, int wait)
{
    int previous = current_cpu;
    assert(wait); current_cpu = cpu; fn(arg); current_cpu = previous;
    return 0;
}
static int qman_delete_cgr(void *p)
{
    assert(cgr && !queues && ipsecinfo.ipsec_bp && current_cpu == ipsecinfo.cgr.cpu);
    if (cgr_deletes_failed) { cgr_deletes_failed--; return -EBUSY; }
    cgr = false; return 0;
}
static void qman_release_cgrid(unsigned id) { assert(cgrid && !cgr); cgrid = false; }
static bool cdx_dpa_init_fault(void) { return fault(); }
/* Producers that disagree on the ICID are one more refusal to unwind. */
static int dpa_cfg_shared_icid(void) { return fault() ? -EINVAL : 63; }
static void register_cdx_deinit_func(void (*cb)(void))
{ registrations++; exit_callback = cb; }
static bool barrier_fail, fatal;
static unsigned barriers;
static void *dpa_get_ehash_td(void) { return &iface; }
static int ExternalHashTableFmPcdHcSync(void *td)
{
    assert(td == &iface && !callbacks);
    for (unsigned i = 512; i < 515; i++) assert(!fq_registry[i]);
    barriers++;
    return barrier_fail ? -EIO : 0;
}
static void cdx_ft_fatal(void) { fatal = true; }
static bool cdx_ft_failed(void) { return fatal; }
void cdx_dpa_ipsec_exit(void);

/* SEC as its controller registers show it: CSTA[IDLE], the performance
 * counters and MCFGR, reached from the job ring's parent device. The
 * dequeued-request counter also moves for job-ring work, which proves nothing
 * of the queue interface. Every look reads CSTA once. */
struct caam_ctrl {
    u32 mcr;
    struct { u64 req_dequeued, ob_enc_req, ib_dec_req; u32 status; } perfmon;
};
struct caam_drv_private { struct caam_ctrl *ctrl; };
static struct caam_ctrl caam;
static struct caam_drv_private caam_priv = { &caam };
static struct device caam_dev = { .drvdata = &caam_priv }, job_ring = { .parent = &caam_dev };
static struct device *jrdev_g = &job_ring;
static unsigned sec_looks;
static u32 rd_reg32(const u32 *reg)
{
    if (reg == &caam.perfmon.status) sec_looks++;
    return *reg;
}
#define rd_reg64(p) (*(p))
/* SEC finishing IPsec protocol requests, outbound and inbound. */
static void sec_protocol(void) { caam.perfmon.ob_enc_req += 2; caam.perfmon.ib_dec_req++; }
/* SEC RM: CSTA[IDLE] is bit 1; the others here are status SEC also reports. */
static void sec_set(bool idle, bool watchdog)
{
    caam.perfmon.status = BIT(10) | BIT(8) | (idle ? BIT(1) : 0);
    caam.mcr = 0x3000 | (watchdog ? MCFGR_WDENABLE : 0);
}

/* The deletion timer: one armed entry, run a period at a time. */
typedef struct timer_entry_t { int (*handler)(struct timer_entry_t *); } TIMER_ENTRY;
static TIMER_ENTRY *armed;
static void cdx_timer_init(TIMER_ENTRY *t, int (*handler)(TIMER_ENTRY *))
{ assert(!armed); t->handler = handler; }
static void cdx_timer_add(TIMER_ENTRY *t, unsigned long period)
{ assert(!armed && t->handler && period == SA_CTX_RELEASE_TIMER_VAL); armed = t; }

/* The SA entry, with what its release reads and writes. */
typedef struct {
    TIMER_ENTRY deletion_timer;
    U8 release_state, release_flags;
    unsigned long release_step, release_t0;
    U64 release_protocol;
    U16 flags, handle;
    PDpaSecSAContext pSec_sa_context;
    bool linked;
} SAEntry, *PSAEntry;
#define container_of(p, t, m) ((t *)((char *)(p) - __builtin_offsetof(t, m)))
static unsigned fp_deletes, entries;
static int cdx_ipsec_delete_fp_entry(PSAEntry sa) { assert(sa->flags & SA_DELETE); fp_deletes++; return 0; }
static void sa_remove_from_list_fqid(PSAEntry sa) { assert(sa->linked && sa->pSec_sa_context); sa->linked = false; }
static void sa_free(PSAEntry sa)
{ assert(!sa->linked && !sa->pSec_sa_context && entries); entries--; releasing_flags = NULL; free(sa); }
#define MAX_CIPHER_KEY_LEN 100
#define MAX_AUTH_KEY_LEN 256
#define Heap_Alloc(size) kzalloc(size, 0)
#define log_err(...) do { } while (0)
#define kfree_sensitive kfree
static void cdx_ipsec_capture_post_free(void *p, size_t n) { }
#include "ipsec_lifecycle.inc"

static void clean(void)
{
    assert(!allocs && !mappings && !queues && !proc_entries && !callbacks);
    assert(!pages && !refill_running && !sg_bpool_g && !skb_2bfreed_bpool_g);
    for (unsigned id = 2; id < 64; id++) assert(!dpa_bp_array[id]);
    assert(!port && !cgr && !cgrid && !preempt_count && !dpa_bp_array[2] && !cdx_dpa_ipsec_ready());
    assert(!ipsecinfo.ipsec_bp && !ipsecinfo.ipsec_pcd_fqs && ipsec_bpid == -1);
    assert(!module_refs && !sa_range && !tags && !ipsecinfo.ipsec_exception_fq);
    assert(!ipsecinfo.expt_fq_count && ipsecinfo.ofport_handle < 0);
    for (unsigned i = 0; i < MAX_MATCH_TABLES; i++) assert(!ipsecinfo.ofport_td[i]);
}
static void reset(void)
{
    clean(); steps = fail_step = seed_step = seed_fail = pauses = registrations = 0;
    retires_failed = oos_failed = cgr_deletes_failed = 0;
    warnings = warn_ons = 0;
    seed_failure = NULL; exit_callback = NULL;
    module_going = false;
}
static unsigned normal(void)
{
    assert(cdx_dpa_ipsec_init() == SUCCESS);
    unsigned count = steps;
    assert(cdx_dpa_ipsec_ready() && registrations == 1 && queues == 12);
    assert(ipsecinfo.ipsec_bp->pool->count == IPSEC_BUFCOUNT);
    assert(ipsec_bpid == ipsecinfo.ipsec_bp->bpid);
    assert(mappings == IPSEC_BUFCOUNT + CDX_MAX_SG_BUFF_COUNT);
    assert(sg_bpool_g->pool->count == CDX_MAX_SG_BUFF_COUNT);
    assert(!skb_2bfreed_bpool_g->pool->count);
    /* Embedded SA queues have a distinct owner and lookup list. */
    struct dpa_fq sa[3] = {0};
    for (unsigned i = 0; i < 3; i++) {
        sa[i].fqid = 900 + i;
        ipsec_addfq_to_exceptionfq_list(&sa[i], &ipsecinfo);
        assert(cdx_find_ipsec_pcd_fqinfo(sa[i].fqid, &ipsecinfo) == -1);
    }
    for (unsigned i = 0; i < 3; i++)
        ipsec_delfq_from_exceptionfq_list(sa[i].fqid, &ipsecinfo);
    assert(!ipsecinfo.ipsec_exception_fq && ipsecinfo.expt_fq_count == 12);
    retires_failed = oos_failed = cgr_deletes_failed = 2;
    current_cpu = (current_cpu + 1) % 4;
    exit_callback(); clean();
    cdx_dpa_ipsec_exit(); clean();
    return count;
}

/* Every queue of an SA out of service the way its release takes them: a
 * step at a time, never waiting, with the portal polled between steps. */
static void sa_stopped(struct dpa_ipsec_sainfo *sa)
{
    for (unsigned i = 0; i < NUM_FQS_PER_SA; i++) {
        unsigned tries = 0;
        while (cdx_dpa_ipsec_fq_stop(sa, i)) { portal_poll(); assert(++tries < 8); }
        assert(sa->sec_fq[i].fq_base.state == qman_fq_state_oos);
    }
}

static unsigned sa_lifecycle(void)
{
    reset();
    assert(cdx_dpa_ipsec_init() == SUCCESS);
    unsigned baseline = allocs;
    steps = 0;
    struct dpa_ipsec_sainfo *sa = cdx_dpa_ipsecsa_alloc(&ipsecinfo, 42);
    assert(sa && module_refs == 1 && queues == 15);
    unsigned count = steps;
    /* Reached with a queue still in service, the release frees nothing:
     * QMan's callbacks and SEC may still use all of it. */
    assert(cdx_dpa_ipsecsa_release(sa) == FAILURE && warn_ons == 1);
    assert(module_refs == 1 && sa_range && tags == 1 && queues == 15);
    assert(ipsecinfo.ipsec_exception_fq);
    warn_ons = 0;
    /* A refused retirement or out-of-service step is asked for again. */
    retires_failed = 1; oos_failed = 1;
    sa_stopped(sa);
    assert(!retires_failed && !oos_failed && warnings == 2);
    warnings = 0;
    assert(cdx_dpa_ipsecsa_release(sa) == SUCCESS);
    assert(!module_refs && !sa_range && !tags && !ipsecinfo.ipsec_exception_fq);
    assert(allocs == baseline && queues == 12);

    /* An SA whose classifier entry could not be proven gone holds its FQIDs
     * past its release, until the datapath restart that settles the entry:
     * that restart gives them back when the SA went first, and an SA that
     * goes after it gives them back at once. */
    sa = cdx_dpa_ipsecsa_alloc(&ipsecinfo, 42);
    assert(sa);
    cdx_dpa_ipsecsa_keep_fqids(sa);
    sa_stopped(sa);
    assert(cdx_dpa_ipsecsa_release(sa) == SUCCESS);
    assert(module_refs == 1 && tags == 1 && sa_range && allocs == baseline + 1);
    assert(cdx_dpa_ipsec_release_held_fqids() == 1 && !sa_range && allocs == baseline);
    assert(!cdx_dpa_ipsec_release_held_fqids());
    sa = cdx_dpa_ipsecsa_alloc(&ipsecinfo, 42);
    assert(sa);
    cdx_dpa_ipsecsa_keep_fqids(sa);
    datapath_epoch++;
    sa_stopped(sa);
    assert(cdx_dpa_ipsecsa_release(sa) == SUCCESS && !sa_range && allocs == baseline);
    /* Held with nothing to record them in, they are lost with the SA rather
     * than handed to the next one. Only a reset gets them back. */
    sa = cdx_dpa_ipsecsa_alloc(&ipsecinfo, 42);
    assert(sa);
    cdx_dpa_ipsecsa_keep_fqids(sa);
    sa_stopped(sa);
    seed_failure = "head"; seed_step = 0; seed_fail = 1;
    assert(cdx_dpa_ipsecsa_release(sa) == SUCCESS && sa_range && allocs == baseline);
    seed_failure = NULL; seed_step = seed_fail = 0;
    assert(!cdx_dpa_ipsec_release_held_fqids() && sa_range);
    assert(module_refs == 1 && tags == 1);
    /* Simulate the reboot required after an unrecordable hold. */
    module_refs = 0; sa_range = false;
    for (unsigned i = 1; i < VLAN_VID_MASK; i++)
        if (ipsec_key_tags.used[i]) ipsec_put_key_tag(i);

    /* An empty FROM_SEC queue is insufficient: a failed PCD barrier pins
     * the tag, FQIDs and module until restart. It cannot be reused. */
    sa = cdx_dpa_ipsecsa_alloc(&ipsecinfo, 42);
    assert(sa);
    u16 held_tag = sa->key_tag;
    sa_stopped(sa); barrier_fail = true;
    unsigned previous_barriers = barriers;
    assert(cdx_dpa_ipsecsa_release(sa) == SUCCESS);
    assert(fatal && barriers == previous_barriers + 1 && module_refs == 1);
    assert(sa_range && tags == 1 && ipsec_key_tags.used[held_tag]);
    int another = ida_alloc_range(&ipsec_key_tags, 1, VLAN_VID_MASK - 1, 0);
    assert(another > 0 && another != held_tag);
    ida_free(&ipsec_key_tags, another);
    barrier_fail = fatal = false;
    assert(cdx_dpa_ipsec_release_held_fqids() == 1);
    assert(!module_refs && !tags && !sa_range);
    another = ida_alloc_range(&ipsec_key_tags, 1, VLAN_VID_MASK - 1, 0);
    assert(another == held_tag);
    ida_free(&ipsec_key_tags, another);

    /* An uncertain dependent-flow delete also pins the identity, even
     * when the SA root and its final barrier both succeed. */
    sa = cdx_dpa_ipsecsa_alloc(&ipsecinfo, 42);
    assert(sa); sa_stopped(sa); fatal = true;
    assert(cdx_dpa_ipsecsa_release(sa) == SUCCESS);
    assert(module_refs == 1 && tags == 1 && sa_range);
    fatal = false;
    assert(cdx_dpa_ipsec_release_held_fqids() == 1 && !module_refs && !tags);

    for (unsigned fail = 1; fail <= count; fail++) {
        steps = 0; fail_step = fail; pauses = 0;
        retires_failed = oos_failed = 2;
        assert(!cdx_dpa_ipsecsa_alloc(&ipsecinfo, 42));
        assert(!module_refs && !sa_range && !tags && !ipsecinfo.ipsec_exception_fq);
        assert(allocs == baseline && queues == 12 && !callbacks);
    }
    fail_step = retires_failed = oos_failed = 0;
    /* An unload that has settled every key that may have named them gives
     * what is held back. */
    sa = cdx_dpa_ipsecsa_alloc(&ipsecinfo, 42);
    assert(sa);
    cdx_dpa_ipsecsa_keep_fqids(sa);
    sa_stopped(sa);
    assert(cdx_dpa_ipsecsa_release(sa) == SUCCESS && sa_range && allocs == baseline + 1);
    cdx_dpa_ipsec_held_fqids_exit(true);
    assert(!sa_range && allocs == baseline);
    /* A held tag pins the module: restart must settle it before unload. */
    sa = cdx_dpa_ipsecsa_alloc(&ipsecinfo, 42);
    assert(sa);
    cdx_dpa_ipsecsa_keep_fqids(sa);
    sa_stopped(sa);
    assert(cdx_dpa_ipsecsa_release(sa) == SUCCESS && module_refs == 1);
    assert(cdx_dpa_ipsec_release_held_fqids() == 1 && !module_refs);
    module_going = true;
    assert(!cdx_dpa_ipsecsa_alloc(&ipsecinfo, 42));
    exit_callback();
    cdx_dpa_ipsec_held_fqids_exit(true);
    clean();
    return count + 3;
}

/* An SA's release as its deletion timer drives it (A308): a step per timer
 * period, waiting as long as a queue or SEC needs, never giving up and never
 * freeing anything before the last step. */
static PSAEntry machine_sa(void)
{
    PSAEntry sa = calloc(1, sizeof(*sa));
    assert(sa); entries++;
    sa->handle = 7;
    sa->pSec_sa_context = cdx_ipsec_sec_sa_context_alloc(7);
    PDpaSecSAContext ctx = sa->pSec_sa_context;
    assert(ctx && module_refs == 1 && tags == 1 && queues == 15);
    assert(ctx->to_sec_fqid == 513 && ctx->to_cp_fqid == 514 && ctx->sec_desc);
    /* The key mappings the descriptor names for the SA's life. */
    ctx->cipher_data.cipher_key_len = 16;
    ctx->crypto_key_dma = dma_map_single(&device, ctx->cipher_data.cipher_key, 16, 0);
    ctx->auth_data.split_key_len = 40;
    ctx->auth_data.split_key_pad_len = 48;
    ctx->auth_key_dma = dma_map_single(&device, ctx->auth_data.split_key, 48, 0);
    sa->linked = true;
    releasing_flags = &sa->flags;
    return sa;
}
static struct dpa_ipsec_sainfo *sainfo_of(PSAEntry sa)
{ return sa->pSec_sa_context->dpa_ipsecsa_handle; }
static enum qman_fq_state qstate(struct dpa_ipsec_sainfo *s, int q)
{ return s->sec_fq[q].fq_base.state; }
/* A frame left on one of the SA's queues. */
static void hold(struct dpa_ipsec_sainfo *s, int q, enum qm_fd_format format, unsigned bpid)
{
    struct qman_fq *fq = &s->sec_fq[q].fq_base;
    unsigned i = fq->held;
    assert(i < 4 && fq->state == qman_fq_state_sched);
    fq->frames[i] = (struct qm_fd){ format, bpid, 0x1000 + 0x100 * q + i };
    fq->held = i + 1;
}
/* One timer period: the portal delivers what was asked of it, time moves on,
 * and the release takes its step, looking at SEC at most once. Nonzero while
 * it asks to run again. */
static int tick(void)
{
    portal_poll();
    jiffies += SA_CTX_RELEASE_TIMER_VAL;
    TIMER_ENTRY *t = armed;
    assert(t);
    armed = NULL;
    unsigned looks = sec_looks;
    int again = t->handler(t);
    assert(sec_looks - looks <= 1);
    if (again) armed = t;
    return again;
}
/* Nothing an SA owns goes while its release waits. */
static void held_whole(unsigned allocs_held, unsigned mappings_held, u16 tag)
{
    assert(armed && entries == 1 && module_refs == 1 && tags == 1 && sa_range);
    assert(ipsec_key_tags.used[tag] && queues == 15);
    assert(allocs == allocs_held && mappings == mappings_held);
}
/* And everything goes once it is done: the tag exactly once (ida_free
 * refuses a second), the module reference, every allocation and mapping. */
static void released_whole(unsigned baseline, unsigned base_mappings, u16 tag)
{
    assert(!armed && !entries && !module_refs && !tags && !sa_range);
    assert(!ipsec_key_tags.used[tag] && queues == 12 && !ipsecinfo.ipsec_exception_fq);
    assert(allocs == baseline && mappings == base_mappings);
    assert(!sa_release_held && !warn_ons);
}

static unsigned release_machine(void)
{
    unsigned cases = 0;

    reset();
    fp_deletes = sg_releases = fd_releases = cp_drops = sec_looks = 0;
    assert(cdx_dpa_ipsec_init() == SUCCESS);
    unsigned baseline = allocs, base_mappings = mappings;
    unsigned sg_bpid = skb_2bfreed_bpool_g->bpid, out_bpid = ipsecinfo.ipsec_bp->bpid;

    /* A rejected enqueue and a drained frame are dropped alike: a software
     * SEC input through the SEC SG release, anything else back to its pool. */
    PSAEntry sa = machine_sa();
    struct dpa_ipsec_sainfo *s = sainfo_of(sa);
    struct qman_fq *to_sec = &s->sec_fq[FQ_TO_SEC].fq_base;
    struct qm_mr_entry ern = { .ern = { .rc = 0x24, .fd = { qm_fd_sg, sg_bpid, 0x5000 } } };
    assert(to_sec->cb.ern && to_sec->cb.dqrr && s->sec_fq[FQ_FROM_SEC].fq_base.cb.dqrr);
    to_sec->cb.ern(NULL, to_sec, &ern);
    assert(sg_releases == 1 && !fd_releases);
    ern.ern.fd = (struct qm_fd){ qm_fd_sg, 1, 0x5100 };
    to_sec->cb.ern(NULL, to_sec, &ern);
    ern.ern.fd = (struct qm_fd){ qm_fd_contig, sg_bpid, 0x5200 };
    to_sec->cb.ern(NULL, to_sec, &ern);
    assert(sg_releases == 1 && fd_releases == 2 && warnings == 3);
    sg_releases = fd_releases = warnings = 0;

    /* Retirement completing a period late, a portal whose volatile dequeue
     * is taken the first time, frames left on every queue, and SEC busy
     * with no progress until it is seen idle. */
    u16 tag = s->key_tag;
    hold(s, FQ_TO_SEC, qm_fd_contig, 1);
    hold(s, FQ_TO_SEC, qm_fd_sg, sg_bpid);
    hold(s, FQ_TO_SEC, qm_fd_sg, 1);
    hold(s, FQ_FROM_SEC, qm_fd_contig, out_bpid);
    hold(s, FQ_TO_CP, qm_fd_contig, out_bpid);
    retire_looks = 1; vdq_busy = 1; sec_set(false, true);
    unsigned allocs_held = allocs, mappings_held = mappings;
    cdx_ipsec_release_sa_resources(sa);
    /* Only the queue into SEC stops at once. */
    assert((sa->flags & SA_DELETE) && fp_deletes == 1 && armed == &sa->deletion_timer);
    assert((to_sec->flags & QMAN_FQ_STATE_CHANGING) && sa->release_state == SA_RELEASE_TO_SEC);
    assert(qstate(s, FQ_FROM_SEC) == qman_fq_state_sched && qstate(s, FQ_TO_CP) == qman_fq_state_sched);
    assert(tick() && sa->release_state == SA_RELEASE_TO_SEC && !sec_looks);
    /* Retired: T0, SEC's first look; its volatile dequeue refused. */
    assert(tick() && sa->release_state == SA_RELEASE_TO_SEC && sec_looks == 1);
    assert((sa->release_flags & SA_REL_T0) && sa->release_t0 == jiffies);
    assert(to_sec->held == 3 && !(to_sec->flags & QMAN_FQ_STATE_VDQCR));
    assert(tick() && (to_sec->flags & QMAN_FQ_STATE_VDQCR));
    /* The portal drops the three frames; then the queue goes out of
     * service, and SEC, busy, is looked at again. */
    assert(tick() && qstate(s, FQ_TO_SEC) == qman_fq_state_oos);
    assert(sg_releases == 1 && fd_releases == 2 && sa->release_state == SA_RELEASE_SEC_DONE);
    /* SEC's output queue stays in service until SEC is done: an output for
     * a job SEC took before T0 still reaches the offline port. */
    for (unsigned i = 0; i < 5; i++) {
        assert(tick() && sa->release_state == SA_RELEASE_SEC_DONE);
        assert(qstate(s, FQ_FROM_SEC) == qman_fq_state_sched);
        held_whole(allocs_held, mappings_held, tag);
    }
    hold(s, FQ_FROM_SEC, qm_fd_sg, out_bpid);
    sec_set(true, true);
    assert(tick() && sa->release_state == SA_RELEASE_FROM_SEC);
    sec_set(false, true);
    /* The exception queue outlasts the output queue by at least a period,
     * for frames the offline port took from it: its retirement is asked for
     * in a later period than the one the output queue went out of service. */
    unsigned periods = 0, from_sec_oos = 0, to_cp_retiring = 0;
    while (tick()) {
        assert(sa->release_state >= SA_RELEASE_FROM_SEC && ++periods < 16);
        if (!from_sec_oos && qstate(s, FQ_FROM_SEC) == qman_fq_state_oos)
            from_sec_oos = periods;
        if (!to_cp_retiring && (qstate(s, FQ_TO_CP) != qman_fq_state_sched ||
                                (s->sec_fq[FQ_TO_CP].fq_base.flags & QMAN_FQ_STATE_CHANGING)))
            to_cp_retiring = periods;
        if (qstate(s, FQ_FROM_SEC) != qman_fq_state_oos)
            assert(qstate(s, FQ_TO_CP) == qman_fq_state_sched);
        held_whole(allocs_held, mappings_held, tag);
    }
    assert(from_sec_oos && to_cp_retiring > from_sec_oos);
    assert(fd_releases == 4 && sg_releases == 1 && cp_drops == 1 && !warnings);
    released_whole(baseline, base_mappings, tag);
    cases++;

    /* SEC idle at T0, while the queue into SEC still empties, is proof enough
     * however busy SEC is afterwards; immediate retirement throughout. */
    retire_at_once = true;
    sa = machine_sa(); s = sainfo_of(sa); tag = s->key_tag;
    hold(s, FQ_TO_SEC, qm_fd_contig, 1);
    cdx_ipsec_release_sa_resources(sa);
    assert(qstate(s, FQ_TO_SEC) == qman_fq_state_retired);
    sec_set(true, true);
    assert(tick() && (sa->release_flags & SA_REL_SEC_DONE));
    sec_set(false, false);
    unsigned looks = sec_looks;
    /* Both later queues retire at once; the exception queue a period after
     * the output queue is out of service. */
    assert(tick() && sec_looks == looks && sa->release_state == SA_RELEASE_TO_CP);
    assert(qstate(s, FQ_FROM_SEC) == qman_fq_state_oos);
    assert(qstate(s, FQ_TO_CP) == qman_fq_state_sched);
    assert(!tick() && sec_looks == looks);
    released_whole(baseline, base_mappings, tag);
    cases++;

    /* An out-of-service step that QMan refuses because the queue holds a
     * frame its state did not show dequeues it again, and the next period's
     * attempt completes. */
    sa = machine_sa(); s = sainfo_of(sa); tag = s->key_tag;
    to_sec = &s->sec_fq[FQ_TO_SEC].fq_base;
    cdx_ipsec_release_sa_resources(sa);
    assert(qstate(s, FQ_TO_SEC) == qman_fq_state_retired && !to_sec->flags);
    to_sec->frames[0] = (struct qm_fd){ qm_fd_contig, 1, 0x7000 };
    to_sec->held = 1;
    unsigned dropped = fd_releases;
    assert(tick() && sa->release_state == SA_RELEASE_TO_SEC && warnings == 1);
    assert((to_sec->flags & QMAN_FQ_STATE_VDQCR) && !(to_sec->flags & QMAN_FQ_STATE_NE));
    sec_set(true, true);
    assert(tick() && fd_releases == dropped + 1 && qstate(s, FQ_TO_SEC) == qman_fq_state_oos);
    while (tick()) assert(armed);
    released_whole(baseline, base_mappings, tag);
    warnings = 0; cases++;

    /* Busy SEC that keeps finishing IPsec protocol requests with its DECO
     * watchdog on: proof SA_SEC_DONE_BOUND after T0, and not a period sooner,
     * in a period it finished more of them since the last look. */
    sa = machine_sa(); s = sainfo_of(sa); tag = s->key_tag;
    allocs_held = allocs; mappings_held = mappings;
    sec_set(false, true);
    cdx_ipsec_release_sa_resources(sa);
    assert(tick() && sa->release_state == SA_RELEASE_SEC_DONE);
    unsigned long t0 = sa->release_t0;
    while (jiffies + SA_CTX_RELEASE_TIMER_VAL < t0 + SA_SEC_DONE_BOUND) {
        sec_protocol();
        assert(tick() && sa->release_state == SA_RELEASE_SEC_DONE);
        assert(qstate(s, FQ_FROM_SEC) == qman_fq_state_sched);
        held_whole(allocs_held, mappings_held, tag);
    }
    sec_protocol();
    assert(tick() && jiffies == t0 + SA_SEC_DONE_BOUND && !warnings);
    assert(sa->release_state == SA_RELEASE_TO_CP);
    assert(!tick());
    released_whole(baseline, base_mappings, tag);
    cases++;

    /* SEC making no progress; progressing with its watchdog off; no SEC to
     * look at; progressing only early after T0, and not since; moving only
     * its dequeued-request count, which job-ring work moves too: each held
     * as long as it lasts, counted once, said once, nothing freed; done as
     * soon as SEC shows it. */
    for (unsigned kind = 0; kind < 5; kind++) {
        sa = machine_sa(); s = sainfo_of(sa); tag = s->key_tag;
        allocs_held = allocs; mappings_held = mappings;
        sec_set(false, kind != 1);
        if (kind == 2) jrdev_g = NULL;
        cdx_ipsec_release_sa_resources(sa);
        for (unsigned i = 0; i < 4 * SA_SEC_DONE_BOUND / SA_CTX_RELEASE_TIMER_VAL; i++) {
            if (kind == 1 || (kind == 3 && i < 5)) sec_protocol();
            if (kind == 4) caam.perfmon.req_dequeued += 7;
            assert(tick() && sa->release_state <= SA_RELEASE_SEC_DONE);
            assert(qstate(s, FQ_FROM_SEC) == qman_fq_state_sched);
            assert(qstate(s, FQ_TO_CP) == qman_fq_state_sched);
            held_whole(allocs_held, mappings_held, tag);
            assert(sa_release_held == (i >= SA_SEC_DONE_BOUND / SA_CTX_RELEASE_TIMER_VAL));
        }
        assert(warnings == 1);
        jrdev_g = &job_ring;
        if (kind == 1 || kind == 2) {
            sec_set(true, false);
        } else {
            sec_protocol();
        }
        assert(tick() && sa->release_state == SA_RELEASE_TO_CP);
        assert(!tick());
        released_whole(baseline, base_mappings, tag);
        warnings = 0; cases++;
    }

    /* A queue that will not retire is asked again every period, said out
     * loud every period, and counted as held once; nothing goes until it
     * does. The same for one that will not go out of service. */
    for (unsigned kind = 0; kind < 2; kind++) {
        sa = machine_sa(); s = sainfo_of(sa); tag = s->key_tag;
        allocs_held = allocs; mappings_held = mappings;
        sec_set(true, true);
        cdx_ipsec_release_sa_resources(sa);
        if (kind) oos_failed = 1000; else retires_failed = 1000;
        unsigned rounds = 2 * SA_SEC_DONE_BOUND / SA_CTX_RELEASE_TIMER_VAL;
        for (unsigned i = 0; i < rounds; i++) {
            assert(tick());
            held_whole(allocs_held, mappings_held, tag);
        }
        assert(sa_release_held == 1 && warnings > rounds);
        assert(sa->release_state == (kind ? SA_RELEASE_TO_SEC : SA_RELEASE_FROM_SEC));
        oos_failed = retires_failed = 0;
        while (tick()) assert(armed);
        released_whole(baseline, base_mappings, tag);
        warnings = 0; cases++;
    }
    retire_at_once = false; retire_looks = 2;
    sg_releases = fd_releases = cp_drops = 0;

    exit_callback();
    cdx_dpa_ipsec_held_fqids_exit(true);
    clean();
    return cases;
}

static void tag_lifecycle(void)
{
    reset();
    struct dpa_ipsec_sainfo owner = {0}, peer = {0};
    owner.key_tag = ida_alloc_range(&ipsec_key_tags, 1, VLAN_VID_MASK - 1, 0);
    peer.key_tag = ida_alloc_range(&ipsec_key_tags, 1, VLAN_VID_MASK - 1, 0);
    refcount_set(&ipsec_key_tag_refs[owner.key_tag], 1);
    refcount_set(&ipsec_key_tag_refs[peer.key_tag], 1);
    ipsec_share_key_tag(&peer, &owner);
    assert(tags == 1 && ipsec_get_key_tag(&peer) == owner.key_tag);
    ipsec_share_key_tag(&peer, &owner); /* idempotent before descriptor build */
    ipsec_put_key_tag(owner.key_tag);
    assert(tags == 1 && ipsec_key_tags.used[peer.key_tag]);
    ipsec_put_key_tag(peer.key_tag);
    assert(!tags);
    /* Exhaustion rejects admission, including full SA construction, rather
     * than wrapping to an active tag or using reserved VLAN IDs 0/4095. */
    for (unsigned i = 1; i < VLAN_VID_MASK; i++)
        assert(ida_alloc_range(&ipsec_key_tags, 1, VLAN_VID_MASK - 1, 0) == (int)i);
    assert(!cdx_dpa_ipsecsa_alloc(&ipsecinfo, 42) && !module_refs && !sa_range);
    for (unsigned i = 1; i < VLAN_VID_MASK; i++) ida_free(&ipsec_key_tags, i);
    clean();
}

int main(void)
{
    tag_lifecycle();
    /* An SG receiver frees the secondary skb shell after taking a page
     * reference. Exercise that lifetime with an actually seeded buffer. */
    reset();
    assert(cdx_dpa_ipsec_init() == SUCCESS);
    struct dpa_bp *bp = ipsecinfo.ipsec_bp;
    struct bm_buffer buffer;
    assert(bman_acquire(bp->pool, &buffer, 1, 0) == 1);
    void *data = phys_to_virt(buffer.addr);
    struct sk_buff *skb = ((struct sk_buff **)data)[-1];
    struct page *page = virt_to_head_page(data);
    assert(skb->head_frag && page->refs == 1);
    memset(data, 0x5a, bp->size);
    dma_unmap_single(bp->dev, buffer.addr, bp->size, DMA_BIDIRECTIONAL);
    get_page(page);
    kfree_skb(skb);
    assert(page->refs == 1);
    for (unsigned i = 0; i < bp->size; i++) assert(((unsigned char *)data)[i] == 0x5a);
    put_page(page);
    /* A failed remap must free the SGT and leave a replacement owed. */
    assert(bman_acquire(bp->pool, &buffer, 1, 0) == 1);
    data = phys_to_virt(buffer.addr);
    dma_unmap_single(bp->dev, buffer.addr, bp->size, DMA_BIDIRECTIONAL);
    seed_failure = "dma"; seed_step = 0; seed_fail = 1;
    int balance = 0;
    dpa_bp_recycle_frag(bp, (unsigned long)data, &balance);
    assert(balance == 0 && mappings == IPSEC_BUFCOUNT + CDX_MAX_SG_BUFF_COUNT - 2);
    seed_failure = NULL;
    cdx_dpa_ipsec_exit(); clean();
    unsigned cases = 0;
    for (sec_congestion = 0; sec_congestion <= 1; sec_congestion++) {
        reset(); unsigned count = normal(); cases++;
        for (unsigned fail = 1; fail <= count; fail++) {
            reset(); fail_step = fail; retires_failed = oos_failed = 2;
            assert(cdx_dpa_ipsec_init() != SUCCESS);
            assert(!registrations); clean();
            cdx_dpa_ipsec_exit(); clean(); cases++;
            reset(); normal(); /* Same tracked state can be acquired again. */
        }
        const char *kinds[] = { "head", "skb", "dma" };
        const unsigned positions[] = {1, 2, 8, 9, 10, 511, 512};
        for (unsigned k = 0; k < 3; k++) for (unsigned p = 0; p < 7; p++) {
            reset(); seed_failure = kinds[k]; seed_fail = positions[p];
            assert(cdx_dpa_ipsec_init() != SUCCESS);
            assert(seed_step == seed_fail && !registrations);
            clean(); cases++;
        }
        /* Fail each boundary of raw SG seeding, after the output pool. */
        const unsigned sg_positions[] = {513, 514, 520, 521, 1023, 1024};
        for (unsigned k = 0; k < 3; k += 2) for (unsigned p = 0; p < 6; p++) {
            reset(); seed_failure = kinds[k]; seed_fail = sg_positions[p];
            assert(cdx_dpa_ipsec_init() != SUCCESS);
            assert(seed_step == seed_fail && !registrations);
            clean(); cases++;
        }
        cases += sa_lifecycle();
        cases += release_machine();
    }
    printf("IPsec lifecycle: %u acquisition/seed cases, repeat cleanup and retry passed\n", cases);
    return 0;
}
