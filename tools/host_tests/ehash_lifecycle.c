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
struct en_exthash_node { uint32_t word_0, word_1, word_2, table_base_lo; };
struct en_exthash_bucket { uint64_t h, pad; };
struct ip_reassembly_params { uint32_t timer_tnum, curr_sessions, type; };
struct en_exthash_info {
    void *table_base, **pSpinlock, *h_Ad, *pcd;
    unsigned tree_owners, hashmask, num_keys;
    struct en_exthash_node node;
    struct ip_reassembly_params *ip_reassem_info;
};
struct en_exthash_info *ipv4_reassly_tbl_info, *ipv6_reassly_tbl_info;
void *IprContextMem;
typedef struct { uintptr_t physicalMuramBase; unsigned env_owners; } t_FmPcd;
enum { e_FM_PCD_CC, e_FM_PCD_FR, e_FM_PCD_DONE };
struct next_engine {
    int nextEngine;
    void *h_Manip;
    union { struct { void *h_CcNode; } ccParams;
            struct { void *h_FrmReplic; } frParams; } params;
};
typedef struct {
    void *h_FmPcd, *h_IpReassemblyManip, *h_CapwapReassemblyManip, *p_Lock;
    unsigned owners, netEnvId, numOfEntries;
    uintptr_t ccTreeBaseAddr;
    struct { struct next_engine nextEngineParams; } keyAndNextEngineParams[2];
} t_FmPcdCcTree;
static unsigned allocations;
static void *allocate(size_t size) { void *p = calloc(1, size); assert(p); allocations++; return p; }
static void release(void *p) { assert(p && allocations); allocations--; free(p); }
#define XX_FreeSpinlock release
#define XX_FreeSmart release
#define kfree release
static void *FmPcdGetMuramHandle(void *pcd) { assert(pcd); return pcd; }
static void FM_MURAM_FreeMem(void *muram, void *p) { assert(muram); release(p); }
static void FmPcdDecNetEnvOwners(t_FmPcd *pcd, unsigned id) { assert(pcd->env_owners); pcd->env_owners--; }
static void FmPcdManipDeleteIpReassmSchemes(void *p) { assert(!p); }
static void FmPcdManipDeleteCapwapReassmSchemes(void *p) { assert(!p); }
static void FmPcdManipUpdateOwner(void *p, bool add) { assert(!p); }
static void FrmReplicGroupUpdateOwner(void *p, bool add) { assert(!p); }
static void FmPcdReleaseLock(void *p, void *lock) { assert(!lock); }
static void DeleteTree(t_FmPcdCcTree *tree, t_FmPcd *pcd) { release((void *)tree->ccTreeBaseAddr); release(tree); }
#include "ehash_production.inc"

static struct en_exthash_info *table(t_FmPcd *pcd, bool reassembly)
{
    struct en_exthash_info *t = allocate(sizeof(*t));
    t->pcd = pcd; t->hashmask = 1;
    t->table_base = allocate(2 * sizeof(struct en_exthash_bucket));
    if (reassembly) {
        t->ip_reassem_info = allocate(sizeof(*t->ip_reassem_info));
        t->ip_reassem_info->timer_tnum = 0xffffffff;
        if (!IprContextMem) IprContextMem = allocate(128);
    } else {
        t->pSpinlock = allocate(2 * sizeof(void *));
        for (unsigned i = 0; i < 2; i++) t->pSpinlock[i] = allocate(1);
    }
    return t;
}
static t_FmPcdCcTree *root(t_FmPcd *pcd, struct en_exthash_info *t)
{
    t_FmPcdCcTree *r = allocate(sizeof(*r));
    uint32_t offset;
    r->h_FmPcd = pcd; r->numOfEntries = 1; pcd->env_owners++;
    r->ccTreeBaseAddr = (uintptr_t)allocate(FM_PCD_CC_AD_ENTRY_SIZE);
    r->keyAndNextEngineParams[0].nextEngineParams.nextEngine = e_FM_PCD_CC;
    r->keyAndNextEngineParams[0].nextEngineParams.params.ccParams.h_CcNode = t;
    copy_td_to_ccbase(t, (void *)r->ccTreeBaseAddr, &offset);
    return r;
}
int main(void)
{
    t_FmPcd pcd = {0};
    for (unsigned cycle = 0; cycle < 128; cycle++) {
        struct en_exthash_info *t = table(&pcd, false);
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
    ipv4_reassly_tbl_info = table(&pcd, true);
    ipv6_reassly_tbl_info = table(&pcd, true);
    uint64_t v4 = fm_pcd_cookie_create(ipv4_reassly_tbl_info, FM_PCD_COOKIE_HASH_TABLE);
    uint64_t v6 = fm_pcd_cookie_create(ipv6_reassly_tbl_info, FM_PCD_COOKIE_HASH_TABLE);
    assert(fm_pcd_cookie_create(ipv4_reassly_tbl_info, FM_PCD_COOKIE_HASH_TABLE) == v4);
    assert(fm_pcd_cookie_hash_put(v4) == E_OK);
    assert(fm_pcd_cookie_lookup(v4, FM_PCD_COOKIE_HASH_TABLE) == ipv4_reassly_tbl_info);
    ipv4_reassly_tbl_info->ip_reassem_info->timer_tnum = 7;
    assert(fm_pcd_cookie_hash_put(v4) == E_BUSY);
    ipv4_reassly_tbl_info->ip_reassem_info->timer_tnum = 0xffffffff;
    ipv4_reassly_tbl_info->ip_reassem_info->curr_sessions = 1;
    assert(fm_pcd_cookie_hash_put(v4) == E_BUSY);
    ipv4_reassly_tbl_info->ip_reassem_info->curr_sessions = 0;
    assert(fm_pcd_cookie_hash_put(v4) == E_OK);
    assert(!ipv4_reassly_tbl_info && IprContextMem);
    assert(fm_pcd_cookie_hash_put(v6) == E_OK);
    assert(!ipv6_reassly_tbl_info && !IprContextMem && !allocations);
    /* Failed creation must release the same partially allocated resources. */
    for (unsigned n = 0; n < 3; n++) {
        struct en_exthash_info *t = allocate(sizeof(*t));
        t->pcd = &pcd; t->hashmask = 1;
        t->pSpinlock = allocate(2 * sizeof(void *));
        for (unsigned i = 0; i < n; i++) t->pSpinlock[i] = allocate(1);
        FreeEnEhashInfo(t);
        assert(!allocations);
    }
    FreeEnEhashInfo(table(&pcd, true));
    assert(!IprContextMem && !allocations);
    puts("EHASH teardown ownership and shared-cookie checks passed");
}
