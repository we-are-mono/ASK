/* The ehash add and delete, compiled from the shipped patch against one bucket
 * every key collides in, so each of the delete's arms runs on a chain of
 * cumulative nodes. What is checked is what a sync that fails leaves behind:
 * the delete hands the caller its table entry to park, and any cumulative node
 * the unlink displaced is parked inside -- never freed before a later sync on
 * the PCD completes, and never lost either. LeakSanitizer is the second half of
 * that oracle: a displaced node nobody parked is a leak at exit. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void *t_Handle;
typedef int t_Error;
#define FM_EHASH_PRINT(...) ((void)0)
#define REPORT_ERROR(level, err, msg) ((void)0)
#define SANITY_CHECK_RETURN_ERROR(p, e) do { if (!(p)) return -1; } while (0)
#define printk(...) ((void)0)
#define printk_ratelimited(...) ((void)0)
#define XX_VirtToPhys(p) ((uint64_t)(uintptr_t)(p))
#define XX_PhysToVirt(a) ((void *)(uintptr_t)(a))
#define SwapUint64(v) __builtin_bswap64(v)
#define DEFINE_SPINLOCK(name) bool name
static unsigned warnings;
#define WARN_ONCE(cond, ...) ({ bool warned_ = (cond); if (warned_) warnings++; warned_; })

#include "ehash_types.inc"

/* The bucket and parked-list locks: held around exactly the code they cover,
 * never across a sync. */
static bool bucket_locked;
static uint32_t XX_LockIntrSpinlock(t_Handle lock) { assert(lock && !bucket_locked); bucket_locked = true; return 7; }
static void XX_UnlockIntrSpinlock(t_Handle lock, uint32_t flags)
{ assert(lock && bucket_locked && flags == 7); bucket_locked = false; }
#define spin_lock_irqsave(lock, flags) do { assert(!*(lock)); *(lock) = true; (flags) = 0; } while (0)
#define spin_unlock_irqrestore(lock, flags) do { assert(*(lock)); *(lock) = false; (void)(flags); } while (0)

/* Table entries and cumulative nodes come from the same allocator; the
 * sizes tell them apart, which is how a case counts the nodes. */
static unsigned live_entries, live_nodes;
static void *XX_MallocSmart(uint32_t size, int mem, uint32_t align)
{
    (void)mem;
    void *p = aligned_alloc(align, (size + align - 1) / align * align);
    assert(p);
    if (size == sizeof(struct en_cumulative_tbl_entry)) live_nodes++; else live_entries++;
    return p;
}
static void XX_FreeSmart(void *p)
{
    /* A cumulative node is the only thing freed through here by the code
     * under test; the cases free their own table entries directly. */
    assert(p && live_nodes);
    live_nodes--;
    free(p);
}
static void get_indexed_hash_bucket(uint8_t size, uint8_t *key, uint8_t shift, uint16_t mask,
                                    uint16_t *index)
{ (void)size; (void)key; (void)shift; (void)mask; *index = 0; }

/* The PCD's host-command sync. A delete's goes through the DeleteKey fault
 * knob first, as in the test image. */
static int pcd, other_pcd;
static unsigned syncs;
static int fail_syncs, fail_delete_syncs;
static void (*during_sync)(void);
static t_Error FmPcdHcSync(t_Handle h)
{
    assert(h == &pcd || h == &other_pcd);
    assert(!bucket_locked);
    syncs++;
    if (during_sync) { void (*hook)(void) = during_sync; during_sync = NULL; hook(); }
    if (fail_syncs) { fail_syncs--; return -1; }
    return 0;
}
static int ehash_delete_hcsync(struct en_exthash_info *info)
{
    if (fail_delete_syncs) { fail_delete_syncs--; syncs++; return -1; }
    return FmPcdHcSync(info->pcd);
}

#include "ehash_production.inc"

#define KEY 16
static struct en_exthash_bucket bucket;
static void *bucket_lock = (void *)1;
static struct en_exthash_info info = { .table_base = &bucket, .pSpinlock = &bucket_lock, .pcd = &pcd };

static struct en_exthash_tbl_entry *entry(unsigned n)
{
    struct en_exthash_tbl_entry *e = XX_MallocSmart(sizeof(*e), 0, 256);
    memset(e, 0, sizeof(*e));
    memset(e->hashentry.key, 0xa0, KEY);
    e->hashentry.key[0] = (uint8_t)n;
    e->hashentry.key[1] = (uint8_t)(n >> 8);
    return e;
}
static void release_entry(struct en_exthash_tbl_entry *e) { assert(live_entries); live_entries--; free(e); }
static void add(struct en_exthash_tbl_entry *e) { assert(ExternalHashTableAddKey(&info, KEY, e) == 0); }
static struct en_exthash_tbl_entry *head(void)
{ return bucket.h ? XX_PhysToVirt(SwapUint64(bucket.h)) : NULL; }
static bool found(struct en_exthash_tbl_entry *e)
{ return head() && find_entry_in_bucket(head(), e->hashentry.key, KEY); }
static bool direct(struct en_exthash_tbl_entry *e) { return bucket.h == SwapUint64(XX_VirtToPhys(e)); }
static unsigned parked(void)
{
    unsigned n = 0;
    for (struct en_cumulative_tbl_entry *node = ehash_parked; node; node = node->next_entry)
        n++;
    return n;
}
/* The number of cumulative nodes on the bucket's chain, following the
 * software links the delete maintains. */
static unsigned chained(void)
{
    struct en_cumulative_tbl_entry *node = (void *)head();
    unsigned n = 0;

    if (!node || !(node->cumulative_entry.flags & EN_CUMULATIVE_NODE))
        return 0;
    for (; node; node = node->next_entry)
        n++;
    return n;
}
/* A delete that succeeds; the caller may then free its entry. */
static void removed(struct en_exthash_tbl_entry *e)
{
    assert(ExternalHashTableDeleteKey(&info, 0, e) == 0 && !found(e));
    release_entry(e);
}
/* A delete whose barrier fails: the entry is out of the chain but not yet
 * the caller's to free. */
static void unsynced(struct en_exthash_tbl_entry *e)
{
    fail_delete_syncs = 1;
    assert(ExternalHashTableDeleteKey(&info, 0, e) == EN_EHASH_DELETE_UNSYNCED);
    assert(!fail_delete_syncs && !found(e));
}
static struct en_cumulative_tbl_entry *late;
static void park_late(void)
{
    late = ExternalHashTableAllocCumulativeEntry(&info);
    ehash_park_node(&info, late);
}

int main(void)
{
    struct en_exthash_tbl_entry *e[24];
    unsigned before;

    /* Three keys in one cumulative node; the third add replaced the node the
     * second made, behind a sync. */
    for (unsigned i = 0; i < 3; i++) { e[i] = entry(i); add(e[i]); }
    assert(chained() == 1 && live_nodes == 1 && found(e[0]) && found(e[1]) && found(e[2]));

    /* A delete that rebuilds the node without the key: the node it replaced
     * is parked, the caller's entry comes back unsynced. */
    unsynced(e[2]);
    assert(parked() == 1 && live_nodes == 2 && chained() == 1 && found(e[0]) && found(e[1]));
    /* A barrier that fails keeps it; one that completes frees it, and the
     * caller may then free its own entry. */
    fail_syncs = 1;
    assert(ExternalHashTableFmPcdHcSync(&info) == -1 && parked() == 1 && live_nodes == 2);
    assert(ExternalHashTableFmPcdHcSync(&info) == 0 && !parked() && live_nodes == 1);
    release_entry(e[2]);

    /* Two keys and no neighbour: the bucket takes the last entry directly and
     * the node is parked. A node parked while a later sync is in flight was
     * unlinked too late for it, and waits for the next. */
    unsynced(e[1]);
    assert(direct(e[0]) && parked() == 1 && live_nodes == 1);
    during_sync = park_late;
    removed(e[0]);
    assert(!bucket.h && parked() == 1 && ehash_parked == late && live_nodes == 1);
    release_entry(e[1]);
    assert(ExternalHashTableFmPcdHcSync(&info) == 0 && !parked() && !live_nodes);

    /* A chain: ten keys fill a node, the eleventh starts one in front. The
     * front node going, with the one behind still holding ten, moves the
     * bucket to the one behind and parks the front. */
    for (unsigned i = 0; i < 11; i++) { e[i] = entry(100 + i); add(e[i]); }
    assert(chained() == 2 && live_nodes == 2);
    unsynced(e[10]);
    assert(chained() == 1 && parked() == 1 && live_nodes == 2);
    /* A delete that syncs is the same barrier: it frees what it replaced and
     * what was parked before it. */
    before = syncs;
    removed(e[0]);
    assert(syncs == before + 1 && !parked() && live_nodes == 1 && chained() == 1);
    release_entry(e[10]);

    /* Not the front node, and down to its last key: the node before it is
     * unhooked from it and it is parked. */
    e[10] = entry(110); add(e[10]);       /* fills the node to ten again */
    e[11] = entry(111); add(e[11]);       /* a new front node */
    e[12] = entry(112); add(e[12]);       /* the front node rebuilt with two */
    assert(chained() == 2);
    for (unsigned i = 1; i < 10; i++) removed(e[i]);
    assert(chained() == 2 && !parked() && found(e[10]) && found(e[11]) && found(e[12]));
    unsynced(e[10]);
    assert(chained() == 1 && parked() == 1 && found(e[11]) && found(e[12]));
    removed(e[11]);
    assert(!parked());
    release_entry(e[10]);
    removed(e[12]);
    assert(!bucket.h && !live_nodes);

    /* Two single-key nodes in a chain. Either one going leaves the bucket
     * holding the other's entry directly, and both nodes are parked. */
    for (unsigned front = 0; front < 2; front++) {
        for (unsigned i = 0; i < 11; i++) { e[i] = entry(200 + i); add(e[i]); }
        for (unsigned i = 1; i < 10; i++) removed(e[i]);
        assert(chained() == 2 && live_nodes == 2);
        struct en_exthash_tbl_entry *gone = front ? e[10] : e[0], *kept = front ? e[0] : e[10];
        unsynced(gone);
        assert(direct(kept) && parked() == 2 && live_nodes == 2);
        removed(kept);
        assert(!bucket.h && !parked() && !live_nodes);
        release_entry(gone);
    }

    /* An add that rebuilds a node and whose sync fails stands, and the node
     * it replaced is parked rather than leaked. */
    for (unsigned i = 0; i < 2; i++) { e[i] = entry(300 + i); add(e[i]); }
    e[2] = entry(302);
    fail_syncs = 1;
    add(e[2]);
    assert(found(e[2]) && parked() == 1 && live_nodes == 2);
    assert(ExternalHashTableFmPcdHcSync(&info) == 0 && !parked() && live_nodes == 1);

    /* One sync proves nothing about a second PCD's walkers, so a node from
     * one is refused a place beside this PCD's and left alone. */
    unsynced(e[2]);
    assert(parked() == 1);
    struct en_exthash_info other = info;
    other.pcd = &other_pcd;
    struct en_cumulative_tbl_entry *stray = ExternalHashTableAllocCumulativeEntry(&other);
    ehash_park_node(&other, stray);
    assert(warnings == 1 && parked() == 1);
    /* Nor does a sync on the second PCD free this one's. */
    assert(ExternalHashTableFmPcdHcSync(&other) == 0 && parked() == 1);
    XX_FreeSmart(stray);
    removed(e[1]);
    assert(!parked());
    release_entry(e[2]);
    removed(e[0]);
    assert(!bucket.h && !live_nodes && !live_entries && !bucket_locked);
    puts("EHASH cumulative delete: every displaced node parked until a completed barrier, none leaked");
    return 0;
}
