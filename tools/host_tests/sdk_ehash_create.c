/* Create an external hash table through the SDK's own creation path, with
 * every allocation counted and each failed in turn. A table comes into being
 * with the spare cumulative node a classifier delete falls back on when the
 * allocator fails it, zeroed like any new node, or not at all -- and then with
 * everything it had allocated given back. What creating and deleting one
 * costs does not grow with its bucket count. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define __CORE_EXT_H
#define __ERR_MODULE__ MODULE_FM_PCD
#include "fm_pcd.h"
/* A bucket lock, marked once initialised. */
typedef struct { unsigned magic; } spinlock_t;
#define SPINLOCK_READY 0x5a5au
#define spin_lock_init(lock) ((lock)->magic = SPINLOCK_READY)
#include "ehash_layout.h"
static unsigned allocations, calls, fail_call, frees, reported, sleeps;
#undef REPORT_ERROR
#define REPORT_ERROR(level, err, msg) (reported = GET_ERROR_TYPE(err))
/* The allocations numbered from one, so a case can fail any of them. What an
 * allocation hands out is poisoned: the creation zeroes what it relies on. */
static void *allocate(size_t size, size_t align)
{
    void *p;

    if (++calls == fail_call)
        return NULL;
    p = aligned_alloc(align, (size + align - 1) / align * align);
    assert(p);
    memset(p, 0xa5, size);
    allocations++;
    return p;
}
static void release(void *p) { assert(p && allocations); allocations--; frees++; free(p); }
#define GFP_KERNEL 0u
#define __GFP_ZERO 1u
#define PAGE_SIZE 4096u
#define BUILD_BUG_ON(cond) _Static_assert(!(cond), #cond)
/* Both entry points run where they may sleep, and say so. */
#define might_sleep() ((void)sleeps++)
#define kzalloc(size, flags) ({ void *p_ = allocate((size), 8); if (p_) memset(p_, 0, (size)); p_; })
#define kfree release
static void *kvcalloc(size_t n, size_t size, unsigned flags)
{
    void *p = allocate(n * size, 8);

    (void)flags;
    if (p)
        memset(p, 0, n * size);
    return p;
}
static void kvfree(void *p) { if (p) release(p); }
/* The buckets: whole pages, zeroed only when asked, and given back by the
 * size they were taken with. */
static size_t page_bytes;
static void *alloc_pages_exact(size_t size, unsigned flags)
{
    void *p = allocate(size, PAGE_SIZE);

    if (p && (flags & __GFP_ZERO))
        memset(p, 0, size);
    if (p)
        page_bytes = size;
    return p;
}
static void free_pages_exact(void *p, size_t size) { assert(size == page_bytes); release(p); }
void *XX_MallocSmart(uint32_t size, int mem, uint32_t align) { (void)mem; return allocate(size, align); }
void XX_FreeSmart(void *p) { release(p); }
physAddress_t XX_VirtToPhys(void *addr) { return (uintptr_t)addr; }
uint8_t FmPcdKgGetSchemeId(t_Handle scheme) { (void)scheme; return 0; }
/* An SDK assertion that fails ends the run. */
void XX_Print(char *str, ...) { fputs(str, stderr); }
void XX_Exit(int status) { (void)status; abort(); }
#define ehash_hcsync_fault_proc_init() ((void)0)
#define READ_ONCE(x) (*(volatile __typeof__(x) *)&(x))
/* Nothing is ever parked here; ehash_cumulative.c covers what is. */
static void ehash_unpark_table(struct en_exthash_info *info) { assert(info); }
static en_exthash_global_mem *en_global_muram_mem;
#include "ehash_create_production.inc"

/* A table of mask + 1 buckets, or, with a mask that is not one less than a
 * power of two, a request the creation refuses only after allocating
 * everything. */
static struct en_exthash_info *create(uint16_t mask)
{
    static uint8_t muram[EN_INTERNAL_BUFF_POOL_SIZE + sizeof(en_exthash_global_mem)];
    static t_FmPcd pcd;
    t_FmPcdHashTableParams params = {.table_type = IPV4_TCP_TABLE, .hashResMask = mask,
                                     .matchKeySize = 16};

    pcd.h_FmMuram = &pcd;
    pcd.pIntMuramPtr = muram;
    params.ccNextEngineParamsForMiss.nextEngine = e_FM_PCD_DONE;
    calls = 0;
    reported = 0;
    sleeps = 0;
    return ExternalHashTableSet(&pcd, &params);
}

/* Every bucket lock initialised and every bucket empty. */
static void check_ready(const struct en_exthash_info *info)
{
    for (uint32_t i = 0; i <= info->hashmask; i++)
        assert(info->bucket_lock[i].magic == SPINLOCK_READY);
    for (uint32_t i = 0; i < info->tablesize; i++)
        assert(!((const uint8_t *)info->table_base)[i]);
}

int main(void)
{
    struct en_exthash_info *info;
    unsigned needed;

    /* The table, one array of bucket locks, its buckets and its spare: a
     * zeroed node, as ExternalHashTableAllocCumulativeEntry() hands out. */
    info = create(1);
    assert(info && !reported && info->hashmask == 1 && info->tablesize == 2 * sizeof(struct en_exthash_bucket));
    assert(info->spare && sleeps == 1);
    for (size_t i = 0; i < sizeof(*info->spare); i++)
        assert(!((uint8_t *)info->spare)[i]);
    check_ready(info);
    needed = calls;
    assert(allocations == needed && needed == 4);
    FreeEnEhashInfo(info);
    assert(!allocations);

    /* The largest table costs what the smallest does: the allocations made
     * to create one, and the frees made to delete it, do not grow with its
     * bucket count. */
    info = create(0x7fff);
    assert(info && !reported && info->hashmask == 0x7fff);
    assert(info->tablesize == 0x8000 * sizeof(struct en_exthash_bucket));
    assert(calls == needed && allocations == needed);
    check_ready(info);
    frees = 0;
    sleeps = 0;
    assert(FM_PCD_HashTableDelete(info) == E_OK);
    assert(!allocations && frees == needed && sleeps == 1);

    /* Any one allocation failing, the spare's last among them, leaves no
     * table and nothing allocated. */
    for (fail_call = 1; fail_call <= needed; fail_call++) {
        info = create(1);
        assert(!info && reported == E_NO_MEMORY && !allocations);
    }
    fail_call = 0;

    /* A request refused after the spare was allocated gives it back too. */
    info = create(2);
    assert(!info && reported == E_INVALID_VALUE && calls == needed && !allocations);
    puts("EHASH creation: every table has its zeroed spare node, costs the same at any bucket count, and a failed creation keeps nothing");
}
