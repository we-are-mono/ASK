/* Create an external hash table through the SDK's own creation path, with
 * every allocation counted and each failed in turn. A table comes into being
 * with the spare cumulative node a classifier delete falls back on when the
 * allocator fails it, zeroed like any new node, or not at all -- and then with
 * everything it had allocated given back. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define __CORE_EXT_H
#define __ERR_MODULE__ MODULE_FM_PCD
#include "fm_pcd.h"
#include "ehash_layout.h"
static unsigned allocations, calls, fail_call, reported;
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
static void release(void *p) { assert(p && allocations); allocations--; free(p); }
#define kzalloc(size, flags) ({ void *p_ = allocate((size), 8); if (p_) memset(p_, 0, (size)); p_; })
#define kfree release
void *XX_MallocSmart(uint32_t size, int mem, uint32_t align) { (void)mem; return allocate(size, align); }
void XX_FreeSmart(void *p) { release(p); }
t_Handle XX_InitSpinlock(void) { return allocate(1, 8); }
void XX_FreeSpinlock(t_Handle lock) { release(lock); }
physAddress_t XX_VirtToPhys(void *addr) { return (uintptr_t)addr; }
uint8_t FmPcdKgGetSchemeId(t_Handle scheme) { (void)scheme; return 0; }
/* An SDK assertion that fails ends the run. */
void XX_Print(char *str, ...) { fputs(str, stderr); }
void XX_Exit(int status) { (void)status; abort(); }
#define ehash_hcsync_fault_proc_init() ((void)0)
static en_exthash_global_mem *en_global_muram_mem;
#include "ehash_create_production.inc"

/* A table of two buckets, or, with a mask that is not one less than a power
 * of two, a request the creation refuses only after allocating everything. */
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
    return ExternalHashTableSet(&pcd, &params);
}

int main(void)
{
    struct en_exthash_info *info;
    unsigned needed;

    /* The table, its bucket locks, its buckets and its spare: a zeroed node,
     * as ExternalHashTableAllocCumulativeEntry() hands out. */
    info = create(1);
    assert(info && !reported && info->hashmask == 1 && info->tablesize == 2 * sizeof(struct en_exthash_bucket));
    assert(info->spare);
    for (size_t i = 0; i < sizeof(*info->spare); i++)
        assert(!((uint8_t *)info->spare)[i]);
    needed = calls;
    assert(allocations == needed && needed == 6);
    FreeEnEhashInfo(info);
    assert(!allocations);

    /* Any one allocation failing, the spare's last among them, leaves no
     * table and nothing allocated. */
    for (fail_call = 1; fail_call <= needed; fail_call++) {
        info = create(1);
        assert(!info && reported == E_NO_MEMORY && !allocations);
    }
    fail_call = 0;

    /* A request refused after the spare was allocated gives it back too. */
    info = create(2);
    assert(!info && reported == E_INVALID_VALUE && calls == 7 && !allocations);
    puts("EHASH creation: every table has its zeroed spare node, and a failed creation keeps nothing");
}
