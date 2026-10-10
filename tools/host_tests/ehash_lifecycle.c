/* Exercise actual SDK table/root teardown and CDX's quarantine over it. */
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
struct en_exthash_node {
    union { uint32_t word_0; struct { uint32_t ipv4_ad_offset:8, remaining:24; }; };
    uint32_t word_1, word_2, table_base_lo;
};
struct en_exthash_bucket { uint64_t h, pad; };
struct en_cumulative_tbl_entry;
struct en_exthash_info {
    void *table_base, **pSpinlock, *h_Ad, *pcd;
    unsigned tree_owners, hashmask, num_keys;
    struct en_exthash_node node;
    struct en_cumulative_tbl_entry *spare;
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
static void ExternalHashTableCumulativeEntryFree(void *node) { release(node); }
static void *FmPcdGetMuramHandle(void *pcd) { assert(pcd); return pcd; }
static void FM_MURAM_FreeMem(void *muram, void *p) { assert(muram); release(p); }
static void FmPcdDecNetEnvOwners(t_FmPcd *pcd, unsigned id) { assert(pcd->env_owners); pcd->env_owners--; }
static void FmPcdManipUpdateOwner(void *p, bool add) { assert(!p); }
static void FrmReplicGroupUpdateOwner(void *p, bool add) { assert(!p); }
static void FmPcdReleaseLock(void *p, void *lock) { assert(!lock); }
static void DeleteTree(t_FmPcdCcTree *tree, t_FmPcd *pcd) { release((void *)tree->ccTreeBaseAddr); release(tree); }
/* The parked nodes a table's deletion detaches from it, so a barrier proving
 * them later does not refill a spare that is gone; what it does to them is
 * ehash_cumulative.c's. Here: that teardown asks, once, while the table is
 * still whole. */
static struct en_exthash_info *unparked;
static unsigned unparks;
static void ehash_unpark_table(struct en_exthash_info *info)
{
    assert(info && info->table_base && info->spare);
    unparked = info;
    unparks++;
}
#include "ehash_production.inc"

/* A table as its creation leaves it, down to the spare cumulative node a
 * delete falls back on; teardown has to give every piece back. */
static struct en_exthash_info *table(t_FmPcd *pcd)
{
    struct en_exthash_info *t = allocate(sizeof(*t));
    t->pcd = pcd; t->hashmask = 1;
    t->table_base = allocate(2 * sizeof(struct en_exthash_bucket));
    t->pSpinlock = allocate(2 * sizeof(void *));
    for (unsigned i = 0; i < 2; i++) t->pSpinlock[i] = allocate(1);
    t->spare = allocate(1);
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
/* CDX's quarantine over this table API, compiled from cdx_ehash.c: what a
 * failed barrier leaves parked, and what releases it. The table API is the
 * boundary here, so its three calls are the ones simulated. */
#include <errno.h>
#include <stddef.h>
struct list_head { struct list_head *next, *prev; };
#define LIST_HEAD(n) struct list_head n = { &n, &n }
#define list_entry(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define list_for_each_entry(p, h, m) \
    for (p = list_entry((h)->next, typeof(*p), m); &p->m != (h); p = list_entry(p->m.next, typeof(*p), m))
#define list_for_each_entry_safe(p, n, h, m) \
    for (p = list_entry((h)->next, typeof(*p), m), n = list_entry(p->m.next, typeof(*p), m); \
         &p->m != (h); p = n, n = list_entry(n->m.next, typeof(*n), m))
static void list_add_tail(struct list_head *e, struct list_head *h)
{ e->next = h; e->prev = h->prev; h->prev->next = e; h->prev = e; }
static void list_del(struct list_head *e) { e->prev->next = e->next; e->next->prev = e->prev; }
static bool list_empty(const struct list_head *h) { return h->next == h; }
#define WRITE_ONCE(x, v) ((x) = (v))
#define GFP_KERNEL 0
/* Bookkeeping allocations, which a case can fail. */
static bool kmalloc_fails;
static void *kmalloc_stub(size_t size) { return kmalloc_fails ? NULL : allocate(size); }
#define kmalloc(size, flags) kmalloc_stub(size)
#define DPA_ERROR(...) ((void)0)
/* The control mutex every quarantine mutator requires, and lockdep's check
 * of it, counted rather than fatal so a case can prove the check is made. */
static struct { struct { bool mutex; } ctrl; } cdx_instance, *cdx_info = &cdx_instance;
static unsigned unlocked;
#define lockdep_assert_held(lock) do { if (!*(lock)) unlocked++; } while (0)
#define SUCCESS 0
#define FAILURE (-1)
#define EN_EHASH_DELETE_UNSYNCED (-2)
static unsigned hc_syncs;
static void *synced_table;
static bool hc_fail;
static int delete_rc;
static int ExternalHashTableFmPcdHcSync(void *td)
{ assert(td); hc_syncs++; synced_table = td; return hc_fail ? -1 : 0; }
static void ExternalHashTableEntryFree(void *entry) { release(entry); }
/* Which bucket a delete was told the key is in, and how many it was asked. */
static unsigned deletes, deleted_from;
static int ExternalHashTableDeleteKey(void *td, uint16_t index, void *entry)
{ assert(td && entry); deletes++; deleted_from = index; return delete_rc; }
/* Where the table says an entry is linked: in the bucket a case names, in
 * none (-ENOENT), or nowhere it can tell for a malformed chain (-EUCLEAN). */
static int find_rc;
static uint16_t found_in;
static unsigned finds;
static int ExternalHashTableFindEntry(void *td, void *entry, uint16_t *index)
{
    assert(td && entry && index);
    finds++;
    if (!find_rc) *index = found_in;
    return find_rc;
}
/* The table the DPA configuration gives the PCD, if any. */
static void *pcd_table;
static void *dpa_get_ehash_td(void) { assert(cdx_info->ctrl.mutex); return pcd_table; }
/* Declared by cdx_common.h in the module; one calls another defined below it. */
int cdx_ehash_quarantine_retry(void);
#include "quarantine_production.inc"

static void check_quarantine(void)
{
    t_FmPcd pcd = {0};
    struct en_exthash_info *first = table(&pcd), *second = table(&pcd);
    unsigned held = allocations;
    void *entry;

    /* Every mutator asserts the control mutex: one called without it is
     * caught, whatever else it does. */
    assert(cdx_ehash_quarantine_retry() == 0 && unlocked == 1);
    cdx_ehash_quarantine_free_all();
    cdx_ehash_quarantine_drain(first);
    cdx_ehash_quarantine_entry(first, NULL);
    cdx_ehash_quarantine_abandon();
    assert(unlocked == 5 && !hc_syncs);
    unlocked = 0;
    cdx_info->ctrl.mutex = true;

    /* Nothing parked: nothing to sync. */
    assert(cdx_ehash_quarantine_retry() == 0 && !hc_syncs);
    /* A delete whose barrier failed parks its entry against the table it
     * left, and a hand splice parks against the one it names. */
    delete_rc = EN_EHASH_DELETE_UNSYNCED;
    assert(cdx_ehash_delete_entry(first, 3, allocate(8)) == EN_EHASH_DELETE_UNSYNCED);
    cdx_ehash_quarantine_entry(second, allocate(8));
    assert(cdx_ehash_quarantine_pending() == 2 && allocations == held + 4);
    /* One sync through the first entry's table; a failed one keeps both. */
    hc_fail = true;
    assert(cdx_ehash_quarantine_retry() == -EAGAIN && hc_syncs == 1 && synced_table == first);
    assert(cdx_ehash_quarantine_pending() == 2 && allocations == held + 4);
    hc_fail = false;
    assert(cdx_ehash_quarantine_retry() == 0 && hc_syncs == 2 && synced_table == first);
    assert(!cdx_ehash_quarantine_pending() && allocations == held);
    /* An entry parked naming no table is synced through the PCD's own: any
     * table on it is barrier enough, and nothing else need come along to
     * issue one. With none configured it waits for a caller that has one;
     * one behind it that names a table is barrier enough for both. */
    cdx_ehash_quarantine_entry(NULL, allocate(8));
    assert(cdx_ehash_quarantine_retry() == -EAGAIN && hc_syncs == 2);
    pcd_table = first;
    assert(cdx_ehash_quarantine_retry() == 0 && hc_syncs == 3 && synced_table == first);
    assert(!cdx_ehash_quarantine_pending() && allocations == held);
    cdx_ehash_quarantine_entry(NULL, allocate(8));
    cdx_ehash_quarantine_entry(second, allocate(8));
    assert(cdx_ehash_quarantine_retry() == 0 && hc_syncs == 4 && synced_table == second);
    assert(!cdx_ehash_quarantine_pending() && allocations == held);
    /* A delete that syncs is the same barrier: its entry and the backlog go. */
    assert(cdx_ehash_delete_entry(first, 1, allocate(8)) == EN_EHASH_DELETE_UNSYNCED);
    delete_rc = SUCCESS;
    assert(cdx_ehash_delete_entry(first, 2, allocate(8)) == SUCCESS);
    assert(!cdx_ehash_quarantine_pending() && allocations == held && hc_syncs == 4);
    /* A key that may still be linked is never parked: no barrier makes it
     * free. It is recorded for the restart that settles it (exercised in
     * check_abandoned()); here unload, with the ports never stopped, leaks
     * it and gives back only the record. */
    delete_rc = -1;
    entry = allocate(8);
    assert(cdx_ehash_delete_entry(first, 4, entry) == -1 && !cdx_ehash_quarantine_pending());
    assert(allocations == held + 2);
    unsigned asked = deletes;
    assert(!cdx_ehash_abandoned_exit(false));
    assert(allocations == held + 1 && !finds && deletes == asked);
    release(entry); /* Only a hardware reset reclaims it. */
    /* Module exit tries one last barrier of its own, which releases the
     * backlog when it completes... */
    cdx_ehash_quarantine_entry(first, allocate(8));
    cdx_ehash_quarantine_abandon();
    assert(!cdx_ehash_quarantine_pending() && allocations == held && hc_syncs == 5);
    /* ...and with nothing proven even then gives back only the bookkeeping. */
    entry = allocate(8);
    cdx_ehash_quarantine_entry(first, entry);
    hc_fail = true;
    cdx_ehash_quarantine_abandon();
    hc_fail = false;
    assert(!cdx_ehash_quarantine_pending() && allocations == held + 1 && hc_syncs == 6);
    release(entry);
    assert(!unlocked);
    cdx_info->ctrl.mutex = false;
    FreeEnEhashInfo(first);
    FreeEnEhashInfo(second);
}

/* CDX's record of keys a delete could not prove gone, and the resolver the
 * datapath restart runs over it with every port stopped. Each entry is freed
 * once -- ASan's double-free and leak checks are the other half of the
 * oracle -- and never while a key it names may still be linked. */
static void check_abandoned(void)
{
    t_FmPcd pcd = {0};
    struct en_exthash_info *table_ = table(&pcd);
    unsigned held = allocations, resolved;
    void *root, *other, *member[2];

    cdx_info->ctrl.mutex = true;
    /* A delete refused before the unlink records its key as a root, with
     * the table and bucket it was added to, and parks nothing. */
    delete_rc = FAILURE;
    root = allocate(8);
    assert(cdx_ehash_delete_entry(table_, 5, root) == FAILURE);
    assert(!cdx_ehash_quarantine_pending() && allocations == held + 2 && !cdx_ehash_abandoned_lost());
    /* Behind it, the listeners only it reaches. */
    member[0] = allocate(8); member[1] = allocate(8);
    cdx_ehash_abandon_dependent(member[0]);
    cdx_ehash_abandon_dependent(member[1]);
    cdx_ehash_abandon_dependent(NULL);
    assert(allocations == held + 6);
    /* Still linked where it was added, and still refused, most likely for a
     * cumulative node: the restart waits, keeping everything. */
    find_rc = 0; found_in = 5;
    unsigned asked = deletes;
    assert(cdx_ehash_resolve_abandoned(&resolved) == -EAGAIN && !resolved);
    assert(deletes == asked + 1 && deleted_from == 5 && allocations == held + 6);
    /* Linked from another bucket than it was added to: deleted there. Its
     * dependents go only now, with every root settled. */
    delete_rc = SUCCESS; found_in = 9;
    assert(cdx_ehash_resolve_abandoned(&resolved) == 0 && resolved == 1);
    assert(deletes == asked + 2 && deleted_from == 9 && allocations == held);
    /* An unlink whose barrier failed is final too, with nothing walking. */
    delete_rc = FAILURE;
    root = allocate(8);
    assert(cdx_ehash_delete_entry(table_, 2, root) == FAILURE);
    delete_rc = EN_EHASH_DELETE_UNSYNCED; found_in = 2;
    assert(cdx_ehash_resolve_abandoned(&resolved) == 0 && resolved == 1 && allocations == held);
    /* Linked from no bucket at all: freed without a delete. */
    delete_rc = FAILURE;
    root = allocate(8);
    assert(cdx_ehash_delete_entry(table_, 3, root) == FAILURE);
    find_rc = -ENOENT; asked = deletes;
    assert(cdx_ehash_resolve_abandoned(&resolved) == 0 && resolved == 1);
    assert(deletes == asked && allocations == held);
    /* Nothing recorded: nothing to do. */
    assert(cdx_ehash_resolve_abandoned(&resolved) == 0 && !resolved);
    /* A root still linked after every try the restart gives it, or a table
     * the search finds malformed, is beyond a restart: nothing is freed,
     * dependents included. Two roots: the first settled one goes at once,
     * whatever the other does. */
    root = allocate(8); other = allocate(8);
    assert(cdx_ehash_delete_entry(table_, 1, root) == FAILURE);
    assert(cdx_ehash_delete_entry(table_, 1, other) == FAILURE);
    member[0] = allocate(8);
    cdx_ehash_abandon_dependent(member[0]);
    find_rc = 0; found_in = 1;
    unsigned tries = 0;
    int rc;
    while ((rc = cdx_ehash_resolve_abandoned(&resolved)) == -EAGAIN)
        tries++;
    assert(rc == -ENOTRECOVERABLE && tries == CDX_EHASH_RESOLVE_ATTEMPTS - 1);
    assert(allocations == held + 6);
    find_rc = -EUCLEAN;
    assert(cdx_ehash_resolve_abandoned(&resolved) == -ENOTRECOVERABLE && allocations == held + 6);
    /* Unload with the ports stopped settles what will go and leaks the
     * rest, giving back only the records -- which here is everything, the
     * table being malformed. */
    assert(!cdx_ehash_abandoned_exit(true));
    assert(allocations == held + 3);
    release(root); release(other); release(member[0]);
    /* And with a table that answers, unload frees them all. */
    root = allocate(8);
    assert(cdx_ehash_delete_entry(table_, 1, root) == FAILURE);
    member[0] = allocate(8);
    cdx_ehash_abandon_dependent(member[0]);
    find_rc = 0; delete_rc = SUCCESS;
    assert(cdx_ehash_abandoned_exit(true));
    assert(allocations == held);
    /* A record that cannot be made loses track of a key that may still be
     * linked, which no restart can then be proven safe without, and unload
     * frees no dependent while that is so. A dependent's own record failing
     * costs only that entry. */
    delete_rc = FAILURE;
    root = allocate(8);
    kmalloc_fails = true;
    assert(cdx_ehash_delete_entry(table_, 1, root) == FAILURE && cdx_ehash_abandoned_lost());
    member[1] = allocate(8);
    cdx_ehash_abandon_dependent(member[1]);
    kmalloc_fails = false;
    member[0] = allocate(8);
    cdx_ehash_abandon_dependent(member[0]);
    assert(allocations == held + 4);
    asked = deletes;
    assert(!cdx_ehash_abandoned_exit(true));
    assert(allocations == held + 3 && deletes == asked);
    release(root); release(member[0]); release(member[1]);
    assert(allocations == held);
    cdx_info->ctrl.mutex = false;
    FreeEnEhashInfo(table_);
}

int main(void)
{
    t_FmPcd pcd = {0};
    for (unsigned cycle = 0; cycle < 128; cycle++) {
        struct en_exthash_info *t = table(&pcd);
        t_FmPcdCcTree *a = root(&pcd, t), *b = root(&pcd, t);
        assert(t->tree_owners == 2);
        assert(FM_PCD_HashTableDelete(t) == E_BUSY);
        a->owners = 1;
        assert(FM_PCD_CcRootDelete(a) == E_INVALID_SELECTION);
        assert(pcd.env_owners == 2 && t->tree_owners == 2);
        a->owners = 0;
        assert(FM_PCD_CcRootDelete(a) == E_OK);
        assert(t->tree_owners == 1 && t->h_Ad == (void *)b->ccTreeBaseAddr);
        assert(FM_PCD_HashTableDelete(t) == E_BUSY);
        assert(FM_PCD_CcRootDelete(b) == E_OK);
        assert(!t->tree_owners && !t->h_Ad && !pcd.env_owners);
        t->num_keys = 1;
        assert(FM_PCD_HashTableDelete(t) == E_BUSY);
        t->num_keys = 0;
        ((struct en_exthash_bucket *)t->table_base)[1].h = 123;
        assert(FM_PCD_HashTableDelete(t) == E_BUSY);
        ((struct en_exthash_bucket *)t->table_base)[1].h = 0;
        /* Every refusal above left its parked nodes alone. */
        assert(unparks == cycle);
        assert(FM_PCD_HashTableDelete(t) == E_OK);
        assert(unparks == cycle + 1 && unparked == t);
        assert(!allocations);
    }
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
    assert(FM_PCD_CcRootModifyNextEngine((void *)1, 0, 0, (void *)1) == E_NOT_SUPPORTED);
    assert(FmPcdCcModifyNextEngineParamTree((void *)1, (void *)1, 0, 0, (void *)1) == E_NOT_SUPPORTED);
    check_quarantine();
    check_abandoned();
    assert(!allocations);
    puts("EHASH teardown, unsupported retargeting and quarantine checks passed");
}
