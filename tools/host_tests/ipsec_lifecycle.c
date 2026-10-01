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
#define pr_warn_ratelimited(...) do { } while (0)
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
#define QMAN_VOLATILE_FLAG_WAIT 1
#define QMAN_VOLATILE_FLAG_FINISH 2
#define QM_VDQCR_NUMFRAMES_TILLEMPTY 1
#define QM_CGR_WE_CSCN_EN 1
#define QM_CGR_WE_CS_THRES 2
#define QM_CGR_WE_MODE 4
#define QM_CGR_WE_CSTD_EN 8
#define QM_CGR_EN 1
#define QMAN_CGR_FLAG_USE_INIT 1

typedef uint32_t u32;
typedef uint8_t u8;
typedef uintptr_t dma_addr_t;
typedef int cpumask_t;
#define for_each_cpu(i, mask) for ((i) = 0; (i) < *(mask); (i)++)
struct device { int unused; };
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
struct qman_fq {
    unsigned fqid, flags, pending; bool acquired, proc;
    enum qman_fq_state state;
    struct { void (*dqrr)(void); void (*ern)(void); } cb;
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
static void ipsec_exception_pkt_handler(void) { }
static void dpa_ipsec_ern_cb(void) { }
static bool try_module_get(void *module)
{ if (module_going) return false; module_refs++; return true; }
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
static void qman_fq_state(struct qman_fq *fq, enum qman_fq_state *state, u32 *flags)
{
    assert(fq->acquired && ipsecinfo.ipsec_bp);
    assert(fq->fqid >= 512 ? module_refs > 0 : !dpa_ipsec_ready);
    if (fq->flags & QMAN_FQ_STATE_CHANGING) {
        if (!fq->pending--) { fq->flags &= ~QMAN_FQ_STATE_CHANGING; fq->state = qman_fq_state_retired; }
    }
    *state = fq->state; *flags = fq->flags;
}
static int qman_retire_fq(struct qman_fq *fq, void *flags)
{
    if (retires_failed) { retires_failed--; return -EIO; }
    fq->flags = QMAN_FQ_STATE_CHANGING;
    if (fq->fqid < 512) fq->flags |= QMAN_FQ_STATE_NE;
    fq->pending = 2; return 1;
}
static int qman_volatile_dequeue(struct qman_fq *fq, unsigned flags, unsigned count)
{
    assert(ipsecinfo.ipsec_bp && dpa_bp_array[2] == ipsecinfo.ipsec_bp);
    assert(fq->cb.dqrr && fq->state == qman_fq_state_retired);
    fq->flags &= ~QMAN_FQ_STATE_NE;
    callbacks++; return 0;
}
static int qman_oos_fq(struct qman_fq *fq)
{
    if (oos_failed) { oos_failed--; return -EBUSY; }
    assert(fq->state == qman_fq_state_retired && !fq->flags);
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
static void register_cdx_deinit_func(void (*cb)(void))
{ registrations++; exit_callback = cb; }
void cdx_dpa_ipsec_exit(void);
#include "ipsec_lifecycle.inc"

static void clean(void)
{
    assert(!allocs && !mappings && !queues && !proc_entries && !callbacks);
    assert(!pages && !refill_running && !sg_bpool_g && !skb_2bfreed_bpool_g);
    for (unsigned id = 2; id < 64; id++) assert(!dpa_bp_array[id]);
    assert(!port && !cgr && !cgrid && !preempt_count && !dpa_bp_array[2] && !cdx_dpa_ipsec_ready());
    assert(!ipsecinfo.ipsec_bp && !ipsecinfo.ipsec_pcd_fqs && ipsec_bpid == -1);
    assert(!module_refs && !sa_range && !ipsecinfo.ipsec_exception_fq);
    assert(!ipsecinfo.expt_fq_count && ipsecinfo.ofport_handle < 0);
    for (unsigned i = 0; i < MAX_MATCH_TABLES; i++) assert(!ipsecinfo.ofport_td[i]);
}
static void reset(void)
{
    clean(); steps = fail_step = seed_step = seed_fail = pauses = registrations = 0;
    retires_failed = oos_failed = cgr_deletes_failed = 0;
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

static void sa_retired(struct dpa_ipsec_sainfo *sa)
{
    for (unsigned i = 0; i < NUM_FQS_PER_SA; i++) {
        sa->sec_fq[i].fq_base.state = qman_fq_state_retired;
        sa->sec_fq[i].fq_base.flags = 0;
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
    sa_retired(sa);
    oos_failed = 1;
    assert(cdx_dpa_ipsecsa_release(sa) == FAILURE);
    assert(module_refs == 1 && sa_range && ipsecinfo.ipsec_exception_fq);
    assert(cdx_dpa_ipsecsa_release(sa) == SUCCESS);
    assert(!module_refs && !sa_range && !ipsecinfo.ipsec_exception_fq);
    assert(allocs == baseline && queues == 12);

    /* An SA whose classifier entry could not be proven gone holds its FQIDs
     * past its release, until the datapath restart that settles the entry:
     * that restart gives them back when the SA went first, and an SA that
     * goes after it gives them back at once. */
    sa = cdx_dpa_ipsecsa_alloc(&ipsecinfo, 42);
    assert(sa);
    cdx_dpa_ipsecsa_keep_fqids(sa);
    sa_retired(sa);
    assert(cdx_dpa_ipsecsa_release(sa) == SUCCESS);
    assert(!module_refs && sa_range && allocs == baseline + 1);
    assert(cdx_dpa_ipsec_release_held_fqids() == 1 && !sa_range && allocs == baseline);
    assert(!cdx_dpa_ipsec_release_held_fqids());
    sa = cdx_dpa_ipsecsa_alloc(&ipsecinfo, 42);
    assert(sa);
    cdx_dpa_ipsecsa_keep_fqids(sa);
    datapath_epoch++;
    sa_retired(sa);
    assert(cdx_dpa_ipsecsa_release(sa) == SUCCESS && !sa_range && allocs == baseline);
    /* Held with nothing to record them in, they are lost with the SA rather
     * than handed to the next one. Only a reset gets them back. */
    sa = cdx_dpa_ipsecsa_alloc(&ipsecinfo, 42);
    assert(sa);
    cdx_dpa_ipsecsa_keep_fqids(sa);
    sa_retired(sa);
    seed_failure = "head"; seed_step = 0; seed_fail = 1;
    assert(cdx_dpa_ipsecsa_release(sa) == SUCCESS && sa_range && allocs == baseline);
    seed_failure = NULL; seed_step = seed_fail = 0;
    assert(!cdx_dpa_ipsec_release_held_fqids() && sa_range);
    sa_range = false;

    for (unsigned fail = 1; fail <= count; fail++) {
        steps = 0; fail_step = fail; pauses = 0;
        retires_failed = oos_failed = 2;
        assert(!cdx_dpa_ipsecsa_alloc(&ipsecinfo, 42));
        assert(!module_refs && !sa_range && !ipsecinfo.ipsec_exception_fq);
        assert(allocs == baseline && queues == 12 && !callbacks);
    }
    fail_step = retires_failed = oos_failed = 0;
    /* An unload that has settled every key that may have named them gives
     * what is held back. */
    sa = cdx_dpa_ipsecsa_alloc(&ipsecinfo, 42);
    assert(sa);
    cdx_dpa_ipsecsa_keep_fqids(sa);
    sa_retired(sa);
    assert(cdx_dpa_ipsecsa_release(sa) == SUCCESS && sa_range && allocs == baseline + 1);
    cdx_dpa_ipsec_held_fqids_exit(true);
    assert(!sa_range && allocs == baseline);
    /* One that has not keeps it allocated, giving back only the record of
     * it -- and the IPsec exit, which runs before that is known, keeps both
     * for it to decide. */
    sa = cdx_dpa_ipsecsa_alloc(&ipsecinfo, 42);
    assert(sa);
    cdx_dpa_ipsecsa_keep_fqids(sa);
    sa_retired(sa);
    assert(cdx_dpa_ipsecsa_release(sa) == SUCCESS && sa_range && allocs == baseline + 1);
    module_going = true;
    assert(!cdx_dpa_ipsecsa_alloc(&ipsecinfo, 42));
    assert(!module_refs && allocs == baseline + 1);
    exit_callback();
    unsigned exited = allocs;
    assert(sa_range && exited);
    cdx_dpa_ipsec_held_fqids_exit(false);
    assert(sa_range && allocs == exited - 1);
    sa_range = false;
    clean();
    return count + 3;
}

int main(void)
{
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
    }
    printf("IPsec lifecycle: %u acquisition/seed cases, repeat cleanup and retry passed\n", cases);
    return 0;
}
