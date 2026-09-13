/* Exercise actual SDK table/root teardown and shared-cookie ownership. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void *t_Handle;
typedef int t_Error;
#define FALSE false
#define E_OK 0
#define E_BUSY 1
#define E_INVALID_HANDLE 2
#define E_INVALID_STATE 3
#define E_INVALID_SELECTION 4
#define E_NOT_SUPPORTED 5
#define SANITY_CHECK_RETURN_ERROR(p, e) do { if (!(p)) return (e); } while (0)
#define RETURN_ERROR(level, e, msg) return (e)
#define ASSERT_COND(p) assert(p)
#define GET_UINT32(x) (x)
#define READ_ONCE(x) (x)
#define WRITE_UINT32(x, y) ((x) = (y))
#define PTR_MOVE(p, n) ((void *)((char *)(p) + (n)))
#define UINT_TO_PTR(p) ((void *)(uintptr_t)(p))
#define XX_VirtToPhys(p) ((uintptr_t)(p))
#define FM_PCD_CC_AD_ENTRY_SIZE 16
#define EXPORT_SYMBOL(x)
#define pr_err(...) ((void)0)
#define DEFINE_SPINLOCK(name) int name
#define spin_lock_irqsave(lock, flags) ((void)(lock), (flags) = 0)
#define spin_unlock_irqrestore(lock, flags) ((void)(lock), (void)(flags))
typedef unsigned refcount_t;
static void refcount_set(refcount_t *r, unsigned n) { *r = n; }
static void refcount_inc(refcount_t *r) { assert(*r); ++*r; }
static bool refcount_dec_not_one(refcount_t *r) { assert(*r); if (*r == 1) return false; --*r; return true; }
enum fm_pcd_cookie_type { FM_PCD_COOKIE_NONE, FM_PCD_COOKIE_HASH_TABLE };
struct en_exthash_node {
    union { uint32_t word_0; struct { uint32_t ipv4_ad_offset:8, remaining:24; }; };
    uint32_t word_1, word_2, table_base_lo;
};
struct en_exthash_bucket { uint64_t h, pad; };
struct en_exthash_info {
    void *table_base, **pSpinlock, *h_Ad, *pcd;
    unsigned tree_owners, hashmask, num_keys;
    struct en_exthash_node node;
};
typedef struct { uintptr_t physicalMuramBase; unsigned env_owners; } t_FmPcd;
enum { e_FM_PCD_CC, e_FM_PCD_FR, e_FM_PCD_DONE };
struct next_engine {
    int nextEngine;
    void *h_Manip;
    union { struct { void *h_CcNode; } ccParams;
            struct { void *h_FrmReplic; } frParams; } params;
};
typedef struct {
    void *h_FmPcd, *p_Lock;
    unsigned owners, netEnvId, numOfEntries;
    uintptr_t ccTreeBaseAddr;
    struct { struct next_engine nextEngineParams; } keyAndNextEngineParams[2];
} t_FmPcdCcTree;
typedef struct next_engine t_FmPcdCcNextEngineParams;
static unsigned allocations;
static void *allocate(size_t size) { void *p = calloc(1, size); assert(p); allocations++; return p; }
static void release(void *p) { assert(p && allocations); allocations--; free(p); }
#define XX_FreeSpinlock release
#define XX_FreeSmart release
#define kfree release
static void *FmPcdGetMuramHandle(void *pcd) { assert(pcd); return pcd; }
static void FM_MURAM_FreeMem(void *muram, void *p) { assert(muram); release(p); }
static void FmPcdDecNetEnvOwners(t_FmPcd *pcd, unsigned id) { assert(pcd->env_owners); pcd->env_owners--; }
static void FmPcdManipUpdateOwner(void *p, bool add) { assert(!p); }
static void FrmReplicGroupUpdateOwner(void *p, bool add) { assert(!p); }
static void FmPcdReleaseLock(void *p, void *lock) { assert(!lock); }
static void DeleteTree(t_FmPcdCcTree *tree, t_FmPcd *pcd) { release((void *)tree->ccTreeBaseAddr); release(tree); }
#include "ehash_production.inc"

static struct en_exthash_info *table(t_FmPcd *pcd)
{
    struct en_exthash_info *t = allocate(sizeof(*t));
    t->pcd = pcd; t->hashmask = 1;
    t->table_base = allocate(2 * sizeof(struct en_exthash_bucket));
    t->pSpinlock = allocate(2 * sizeof(void *));
    for (unsigned i = 0; i < 2; i++) t->pSpinlock[i] = allocate(1);
    return t;
}
static t_FmPcdCcTree *root(t_FmPcd *pcd, struct en_exthash_info *t)
{
    t_FmPcdCcTree *r = allocate(sizeof(*r));
    r->h_FmPcd = pcd; r->numOfEntries = 1; pcd->env_owners++;
    r->ccTreeBaseAddr = (uintptr_t)allocate(FM_PCD_CC_AD_ENTRY_SIZE);
    r->keyAndNextEngineParams[0].nextEngineParams.nextEngine = e_FM_PCD_CC;
    r->keyAndNextEngineParams[0].nextEngineParams.params.ccParams.h_CcNode = t;
    copy_td_to_ccbase(t, (void *)r->ccTreeBaseAddr);
    struct en_exthash_node *ad = (void *)r->ccTreeBaseAddr;
    assert(ad->ipv4_ad_offset == 0xff && (ad->word_2 >> 24) == 0xff);
    return r;
}
/* The registry and ioctl arms are production code. User copies and the
 * legacy compat pointer/id map are fault-injected boundaries. */
#define CONFIG_COMPAT
#define COMPAT_US_TO_K 0
#define COMPAT_K_TO_US 1
#define FM_MAP_TYPE_PCD_NODE 1
#define __user
#define compat_ptr(arg) ((void *)(uintptr_t)(arg))
#define E_NO_MEMORY 6
#define E_READ_FAILED 7
#define E_WRITE_FAILED 8
#define E_INVALID_VALUE 9
#define XX_Free release
#define FM_PCD_IOC_HASH_TABLE_SET 10
#define FM_PCD_IOC_HASH_TABLE_SET_COMPAT 11
#define FM_PCD_IOC_HASH_TABLE_DELETE 12
#define FM_PCD_IOC_HASH_TABLE_DELETE_COMPAT 13
typedef struct { void *h_PcdDev; } t_LnxWrpFmDev;
typedef struct { void *id; struct next_engine cc_next_engine_params_for_miss; } ioc_fm_pcd_hash_table_params_t;
typedef ioc_fm_pcd_hash_table_params_t t_FmPcdHashTableParams;
typedef struct { uint32_t id; } ioc_compat_fm_pcd_hash_table_params_t;
typedef struct { void *obj; } ioc_fm_obj_t;
typedef struct { uint32_t obj; } ioc_compat_fm_obj_t;
static void *mapping;
static struct en_exthash_info *requested_table;
static unsigned malloc_calls, malloc_fail;
static bool copy_out_fail, map_fail;
static void *XX_Malloc(size_t size)
{ return ++malloc_calls == malloc_fail ? NULL : allocate(size); }
static int copy_from_user(void *to, const void *from, size_t size)
{ memcpy(to, from, size); return 0; }
static int copy_to_user(void *to, const void *from, size_t size)
{ if (copy_out_fail) return 1; memcpy(to, from, size); return 0; }
static void *compat_pcd_id2ptr(uint32_t id) { return id == 1 ? mapping : NULL; }
static void compat_del_ptr2id(void *ptr, unsigned type)
{ assert(type == FM_MAP_TYPE_PCD_NODE); if (mapping == ptr) mapping = NULL; }
static void compat_obj_delete(ioc_compat_fm_obj_t *from, ioc_fm_obj_t *to)
{ to->obj = compat_pcd_id2ptr(from->obj); compat_del_ptr2id(to->obj, FM_MAP_TYPE_PCD_NODE); }
static void compat_copy_fm_pcd_hash_table(ioc_compat_fm_pcd_hash_table_params_t *comp,
                                       ioc_fm_pcd_hash_table_params_t *param, unsigned direction)
{
    if (direction == COMPAT_US_TO_K) param->id = compat_pcd_id2ptr(comp->id);
    else if (map_fail) comp->id = 0;
    else { assert(!mapping || mapping == param->id); mapping = param->id; comp->id = 1; }
}
static t_Error fm_pcd_cookie_next_engine(struct next_engine *engine) { return E_OK; }
static void *FM_PCD_HashTableSet(void *pcd, t_FmPcdHashTableParams *params)
{ assert(pcd); if (!requested_table) requested_table = table(pcd); return requested_table; }
#include "hash_ioctl.inc"

int main(void)
{
    t_FmPcd pcd = {0};
    for (unsigned cycle = 0; cycle < 128; cycle++) {
        struct en_exthash_info *t = table(&pcd);
        uint64_t cookie = fm_pcd_cookie_create(t, FM_PCD_COOKIE_HASH_TABLE);
        t_FmPcdCcTree *a = root(&pcd, t), *b = root(&pcd, t);
        assert(t->tree_owners == 2);
        assert(fm_pcd_cookie_hash_put(cookie) == E_BUSY);
        assert(fm_pcd_cookie_lookup(cookie, FM_PCD_COOKIE_HASH_TABLE) == t);
        a->owners = 1;
        assert(FM_PCD_CcRootDelete(a) == E_INVALID_SELECTION);
        assert(pcd.env_owners == 2 && t->tree_owners == 2);
        a->owners = 0;
        assert(FM_PCD_CcRootDelete(a) == E_OK);
        assert(t->tree_owners == 1 && t->h_Ad == (void *)b->ccTreeBaseAddr);
        assert(fm_pcd_cookie_hash_put(cookie) == E_BUSY);
        assert(FM_PCD_CcRootDelete(b) == E_OK);
        assert(!t->tree_owners && !t->h_Ad && !pcd.env_owners);
        t->num_keys = 1;
        assert(fm_pcd_cookie_hash_put(cookie) == E_BUSY);
        t->num_keys = 0;
        ((struct en_exthash_bucket *)t->table_base)[1].h = 123;
        assert(fm_pcd_cookie_hash_put(cookie) == E_BUSY);
        ((struct en_exthash_bucket *)t->table_base)[1].h = 0;
        assert(fm_pcd_cookie_hash_put(cookie) == E_OK);
        assert(!fm_pcd_cookie_lookup(cookie, FM_PCD_COOKIE_HASH_TABLE));
        assert(fm_pcd_cookie_hash_put(cookie) == E_INVALID_SELECTION);
        assert(!allocations);
    }
    struct en_exthash_info *shared = table(&pcd);
    uint64_t cookie = fm_pcd_cookie_create(shared, FM_PCD_COOKIE_HASH_TABLE);
    assert(fm_pcd_cookie_create(shared, FM_PCD_COOKIE_HASH_TABLE) == cookie);
    assert(fm_pcd_cookie_hash_put(cookie) == E_OK);
    assert(fm_pcd_cookie_lookup(cookie, FM_PCD_COOKIE_HASH_TABLE) == shared);
    assert(fm_pcd_cookie_hash_put(cookie) == E_OK);
    assert(!fm_pcd_cookie_lookup(cookie, FM_PCD_COOKIE_HASH_TABLE) && !allocations);
    /* Failed creation must release the same partially allocated resources. */
    for (unsigned n = 0; n < 3; n++) {
        struct en_exthash_info *t = allocate(sizeof(*t));
        t->pcd = &pcd; t->hashmask = 1;
        t->pSpinlock = allocate(2 * sizeof(void *));
        for (unsigned i = 0; i < n; i++) t->pSpinlock[i] = allocate(1);
        FreeEnEhashInfo(t);
        assert(!allocations);
    }
    FreeEnEhashInfo(table(&pcd));
    assert(!allocations);
    t_LnxWrpFmDev wrapper = {.h_PcdDev = &pcd};
    for (unsigned mode = 0; mode < 3; mode++) {
        ioc_compat_fm_pcd_hash_table_params_t param = {0};
        requested_table = NULL; malloc_calls = 0;
        copy_out_fail = mode == 0; malloc_fail = mode == 1 ? 3 : 0;
        map_fail = mode == 2;
        assert(hash_ioctl(&wrapper, FM_PCD_IOC_HASH_TABLE_SET_COMPAT,
                          (unsigned long)&param, true) != E_OK);
        assert(!allocations && !mapping);
    }
    copy_out_fail = map_fail = false; malloc_fail = 0;
    requested_table = NULL;
    ioc_compat_fm_pcd_hash_table_params_t param = {0}, second = {0};
    assert(hash_ioctl(&wrapper, FM_PCD_IOC_HASH_TABLE_SET_COMPAT, (unsigned long)&param, true) == E_OK);
    assert(param.id && mapping);
    requested_table->tree_owners = 1;
    ioc_compat_fm_obj_t id = {.obj = param.id};
    assert(hash_ioctl(&wrapper, FM_PCD_IOC_HASH_TABLE_DELETE_COMPAT, (unsigned long)&id, true) == E_BUSY);
    assert(mapping && fm_pcd_cookie_lookup((uintptr_t)mapping, FM_PCD_COOKIE_HASH_TABLE) == requested_table);
    requested_table->tree_owners = 0;
    assert(hash_ioctl(&wrapper, FM_PCD_IOC_HASH_TABLE_SET_COMPAT, (unsigned long)&second, true) == E_OK);
    assert(second.id == param.id);
    assert(hash_ioctl(&wrapper, FM_PCD_IOC_HASH_TABLE_DELETE_COMPAT, (unsigned long)&id, true) == E_OK);
    assert(mapping && allocations); /* The second shared reference still owns the mapping. */
    assert(hash_ioctl(&wrapper, FM_PCD_IOC_HASH_TABLE_DELETE_COMPAT, (unsigned long)&id, true) == E_OK);
    assert(!mapping && !allocations);
    assert(FM_PCD_CcRootModifyNextEngine((void *)1, 0, 0, (void *)1) == E_NOT_SUPPORTED);
    assert(FmPcdCcModifyNextEngineParamTree((void *)1, (void *)1, 0, 0, (void *)1) == E_NOT_SUPPORTED);
    puts("EHASH teardown, unsupported retargeting and native/compat cookie ownership checks passed");
}
