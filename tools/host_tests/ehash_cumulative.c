/* The ehash add and delete, compiled from the shipped patch against one bucket
 * every key collides in, so each of the delete's arms runs on a chain of
 * cumulative nodes. What is checked is what a sync that fails leaves behind:
 * the delete hands the caller its table entry to park, and any cumulative node
 * the unlink displaced is parked inside -- never freed before a later sync on
 * the PCD completes, and never lost either. LeakSanitizer is the second half of
 * that oracle: a displaced node nobody parked is a leak at exit.
 *
 * The other thing checked is what a failed allocation leaves: a delete that
 * rebuilds a node takes the replacement outside the bucket lock and falls back
 * on the table's spare, so it unlinks the key however the allocator does, and
 * fails only when the spare is gone too -- then with the bucket untouched. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void *t_Handle;
typedef int t_Error;
#define FM_EHASH_PRINT(...) ((void)0)
static unsigned reports;
#define REPORT_ERROR(level, err, msg) (reports++)
#define SANITY_CHECK_RETURN_ERROR(p, e) do { if (!(p)) return -1; } while (0)
#define printk(...) ((void)0)
/* The barrier's own lines, counted: a run of failed barriers reports its
 * first, and the barrier that ends it one line more. */
static unsigned sync_failed_lines, sync_recovered_lines;
#define pr_err(...) (sync_failed_lines++)
#define pr_info(...) (sync_recovered_lines++)
#define XX_VirtToPhys(p) ((uint64_t)(uintptr_t)(p))
#define XX_PhysToVirt(a) ((void *)(uintptr_t)(a))
#define SwapUint64(v) __builtin_bswap64(v)
#define DEFINE_SPINLOCK(name) bool name
/* The spare's atomics, with the kernel's results: xchg() the old value,
 * cmpxchg() the old value whether or not it stored the new one. */
#define xchg(p, v) __atomic_exchange_n((p), (v), __ATOMIC_SEQ_CST)
#define cmpxchg(p, o, n) ({ __typeof__(*(p)) old_ = (o); \
    __atomic_compare_exchange_n((p), &old_, (n), false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); \
    old_; })
#define READ_ONCE(x) (*(volatile __typeof__(x) *)&(x))
/* The barrier that makes what a store links visible to the FMan before the
 * store itself, counted: a case checks which operations issue one. */
static unsigned link_barriers;
#define dma_wmb() ((void)link_barriers++)
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
 * sizes tell them apart, which is how a case counts the nodes. A case can
 * fail the next node allocations, as an atomic allocation fails under memory
 * pressure, and run a hook at the next one; the allocations made under a
 * bucket lock are counted, since a delete must make none. */
static unsigned live_entries, live_nodes, fail_node_allocs, locked_node_allocs;
static void (*during_node_alloc)(void);
static void *XX_MallocSmart(uint32_t size, int mem, uint32_t align)
{
    (void)mem;
    if (size == sizeof(struct en_cumulative_tbl_entry)) {
        if (during_node_alloc) { void (*hook)(void) = during_node_alloc; during_node_alloc = NULL; hook(); }
        locked_node_allocs += bucket_locked;
        if (fail_node_allocs) { fail_node_allocs--; return NULL; }
    }
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
/* Every key hashes to the bucket a case names: the first, unless it says. */
static uint16_t add_bucket;
static void get_indexed_hash_bucket(uint8_t size, uint8_t *key, uint8_t shift, uint16_t mask,
                                    uint16_t *index)
{ (void)size; (void)key; (void)shift; assert(add_bucket <= mask); *index = add_bucket; }
/* The PCD's host-command channel, as far as whether it has failed for good. */
static bool hc_failed;
static t_Handle FmPcdGetHcHandle(t_Handle pcd) { return pcd; }
static bool FmHcIsFailed(t_Handle hc) { assert(hc); return hc_failed; }

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
/* The cumulative nodes the table holds on its chain or parked: every one
 * allocated, less the table's spare. */
static unsigned nodes(void) { return live_nodes - (info.spare != NULL); }
/* A delete that succeeds; the caller may then free its entry. Whatever it
 * allocated, it allocated outside the bucket lock, and a completed barrier
 * always leaves the spare full: a delete that took it relinks the node it
 * replaced, or gives back the one it did not link. */
static void removed(struct en_exthash_tbl_entry *e)
{
    unsigned locked = locked_node_allocs;

    assert(ExternalHashTableDeleteKey(&info, 0, e) == 0 && !found(e));
    assert(locked_node_allocs == locked && info.spare);
    release_entry(e);
}
/* A delete whose barrier fails: the entry is out of the chain but not yet
 * the caller's to free. */
static void unsynced(struct en_exthash_tbl_entry *e)
{
    unsigned locked = locked_node_allocs;

    fail_delete_syncs = 1;
    assert(ExternalHashTableDeleteKey(&info, 0, e) == EN_EHASH_DELETE_UNSYNCED);
    assert(!fail_delete_syncs && !found(e) && locked_node_allocs == locked);
}
/* Other deletes on the same bucket while one has dropped its lock to take a
 * node, with the allocator working for them. */
static struct en_exthash_tbl_entry *meanwhile[2];
static void delete_meanwhile(void)
{
    unsigned failing = fail_node_allocs;

    fail_node_allocs = 0;
    for (unsigned i = 0; i < 2; i++) { removed(meanwhile[i]); meanwhile[i] = NULL; }
    fail_node_allocs = failing;
}
static struct en_cumulative_tbl_entry *late;
static void park_late(void)
{
    late = ExternalHashTableAllocCumulativeEntry(&info);
    ehash_park_node(&info, late);
}

/* Where an entry is linked, for an owner whose delete could not prove it
 * gone: looked for first where it was added, then everywhere, and answered
 * from the chains as the delete and the microcode both walk them -- or refused
 * when the two disagree, or a chain does not end. */
static uint16_t where(struct en_exthash_info *table, struct en_exthash_tbl_entry *e,
                      uint16_t hint, int expect)
{
    uint16_t index = hint;

    assert(ExternalHashTableFindEntry(table, e, &index) == expect && !bucket_locked);
    if (expect)
        assert(index == hint);
    return index;
}
static void check_find(void)
{
    struct en_exthash_tbl_entry *e[12], *stranger = entry(999);
    struct en_exthash_bucket buckets[4] = { 0 };
    void *locks[4] = { (void *)1, (void *)2, (void *)3, (void *)4 };
    struct en_exthash_info wide = { .table_base = buckets, .pSpinlock = locks, .pcd = &pcd,
                                    .hashmask = 3 };
    unsigned before;

    /* An empty table links nothing; nor does a malformed request. */
    assert(!bucket.h);
    where(&info, stranger, 0, -ENOENT);
    uint16_t index = 0;
    assert(ExternalHashTableFindEntry(NULL, stranger, &index) == -EINVAL);
    assert(ExternalHashTableFindEntry(&info, NULL, &index) == -EINVAL);
    assert(ExternalHashTableFindEntry(&info, stranger, NULL) == -EINVAL);
    /* A delete of a key no bucket links finds no node in an empty bucket,
     * rather than reading one at address zero; it changes nothing. */
    before = reports;
    assert(ExternalHashTableDeleteKey(&info, 0, stranger) == -1 && reports == before + 1);
    assert(!bucket.h && !bucket_locked);
    /* The bucket's head, a cumulative node's slot, and a node further down a
     * chain: each found where it was added. One never added is in none. */
    e[0] = entry(800); add(e[0]);
    assert(direct(e[0]) && !where(&info, e[0], 0, 0));
    where(&info, stranger, 0, -ENOENT);
    for (unsigned i = 1; i < 11; i++) { e[i] = entry(800 + i); add(e[i]); }
    assert(chained() == 2);
    for (unsigned i = 0; i < 11; i++) assert(!where(&info, e[i], 0, 0));
    where(&info, stranger, 0, -ENOENT);
    /* A hint past the table is no reason not to look. */
    assert(!where(&info, e[5], 7, 0) && !bucket_locked);
    /* A chain whose software link and the microcode's disagree, a flag that
     * promises a node the software does not have, and a chain that never
     * ends are all malformed: no answer would hold for both walkers. */
    struct en_cumulative_tbl_entry *front = (void *)head();
    uint64_t addr = front->cumulative_entry.next_entry_addr;
    front->cumulative_entry.next_entry_addr = 0;
    where(&info, e[1], 0, -EUCLEAN);
    front->cumulative_entry.next_entry_addr = addr;
    struct en_cumulative_tbl_entry *back = front->next_entry;
    back->cumulative_entry.flags |= EN_NEXT_CUMULATIVE_NODE;
    where(&info, stranger, 0, -EUCLEAN);
    back->next_entry = back;
    back->cumulative_entry.next_entry_addr = SwapUint64(XX_VirtToPhys(back));
    where(&info, stranger, 0, -EUCLEAN);
    back->next_entry = NULL;
    back->cumulative_entry.next_entry_addr = 0;
    back->cumulative_entry.flags &= ~EN_NEXT_CUMULATIVE_NODE;
    assert(!where(&info, e[10], 0, 0));
    /* So is a node no add or delete leaves: one holding no key, or a lone
     * node holding a single key, whose delete is refused however often it
     * is asked. A chain's head holding a single key is neither. */
    uint8_t keys = back->cumulative_entry.num_key_entries;
    back->cumulative_entry.num_key_entries = 0;
    where(&info, stranger, 0, -EUCLEAN);
    back->cumulative_entry.num_key_entries = keys;
    assert(front->cumulative_entry.num_key_entries == 1 &&
           ehash_node_entry(&front->cumulative_entry, 0) == e[10]);
    front->next_entry = NULL;
    front->cumulative_entry.next_entry_addr = 0;
    front->cumulative_entry.flags &= ~EN_NEXT_CUMULATIVE_NODE;
    where(&info, e[10], 0, -EUCLEAN);
    for (unsigned i = 0; i < 2; i++) {
        before = reports;
        assert(ExternalHashTableDeleteKey(&info, 0, e[10]) == -1 && reports == before + 1);
        assert(head() == (void *)front && !bucket_locked &&
               !(front->cumulative_entry.flags & EN_INVALID_CUMULATIVE_NODE));
    }
    front->next_entry = back;
    front->cumulative_entry.next_entry_addr = addr;
    front->cumulative_entry.flags |= EN_NEXT_CUMULATIVE_NODE;
    assert(!where(&info, e[10], 0, 0));
    for (unsigned i = 0; i < 11; i++) removed(e[i]);
    assert(!bucket.h);
    /* An entry linked from another bucket than the one it was named with is
     * found there, and a delete given that bucket unlinks it. */
    add_bucket = 2;
    e[0] = entry(900); e[1] = entry(901);
    assert(ExternalHashTableAddKey(&wide, KEY, e[0]) == 2);
    assert(ExternalHashTableAddKey(&wide, KEY, e[1]) == 2);
    add_bucket = 0;
    assert(where(&wide, e[1], 0, 0) == 2 && !buckets[0].h && buckets[2].h);
    where(&wide, stranger, 0, -ENOENT);
    assert(ExternalHashTableDeleteKey(&wide, 2, e[1]) == 0);
    where(&wide, e[1], 0, -ENOENT);
    release_entry(e[1]);
    assert(where(&wide, e[0], 3, 0) == 2);
    assert(ExternalHashTableDeleteKey(&wide, 2, e[0]) == 0 && !buckets[2].h);
    release_entry(e[0]);
    /* Whether the channel the barriers go through has failed for good. */
    assert(!ExternalHashTableHcFailed(&info) && !ExternalHashTableHcFailed(NULL));
    hc_failed = true;
    assert(ExternalHashTableHcFailed(&info));
    hc_failed = false;
    release_entry(stranger);
    if (wide.spare) ExternalHashTableCumulativeEntryFree(wide.spare);
}

/* A bucket holds at most EHASH_BUCKET_KEYS_MAX keys. The hash is an unkeyed
 * CRC the hardware computes, so colliding keys can be chosen; past the bound
 * an add is refused with the table untouched and the entry still the
 * caller's, and a delete makes room again. */
static void check_bucket_cap(void)
{
    struct en_exthash_tbl_entry *e[EHASH_BUCKET_KEYS_MAX + 1];
    unsigned i, before;

    assert(!bucket.h);
    for (i = 0; i < EHASH_BUCKET_KEYS_MAX; i++)
        add(e[i] = entry(0x1000 + i));
    before = syncs;
    e[i] = entry(0x1000 + i);
    assert(ExternalHashTableAddKey(&info, KEY, e[i]) == EHASH_ADD_BUCKET_FULL);
    assert(!found(e[i]) && syncs == before);
    for (i = 0; i < EHASH_BUCKET_KEYS_MAX; i++)
        assert(found(e[i]));
    removed(e[0]);
    add(e[EHASH_BUCKET_KEYS_MAX]);
    for (i = 1; i <= EHASH_BUCKET_KEYS_MAX; i++)
        removed(e[i]);
    assert(!bucket.h);
}

/* Deletes that defer their barrier, for a caller retiring many keys behind one:
 * each unlinks as a delete whose barrier failed would, issuing none, and one
 * barrier then proves them all -- through the DeleteKey fault knob, as a
 * delete's own is. Each displaced node goes back to the spare of the table it
 * came from, whichever table that barrier is issued through. */
static void check_deferred(void)
{
    struct en_exthash_tbl_entry *e[3];
    struct en_exthash_bucket second_bucket = { 0 };
    void *second_lock = (void *)2;
    struct en_exthash_info second = { .table_base = &second_bucket, .pSpinlock = &second_lock,
                                      .pcd = &pcd };
    struct en_cumulative_tbl_entry *own, *spare;
    unsigned before;

    for (unsigned i = 0; i < 3; i++) { e[i] = entry(900 + i); add(e[i]); }
    assert(chained() == 1 && !parked());
    before = syncs;
    own = (void *)head();
    spare = xchg(&info.spare, NULL);
    /* A rebuild, then the bucket taking the last key directly: both nodes
     * parked, no barrier issued, and never 0. */
    assert(ExternalHashTableUnlinkKey(&info, 0, e[2]) == EN_EHASH_DELETE_UNSYNCED);
    assert(syncs == before && !found(e[2]) && parked() == 1 && ehash_parked == own);
    assert(ExternalHashTableUnlinkKey(&info, 0, e[1]) == EN_EHASH_DELETE_UNSYNCED);
    assert(syncs == before && direct(e[0]) && parked() == 2 && !bucket_locked);
    /* The knob fails the barrier that covers them: both stay parked. */
    fail_delete_syncs = 1;
    assert(ExternalHashTableDeleteSync(&second) == -1 && !fail_delete_syncs && parked() == 2);
    /* One that completes, issued through another table on the PCD, refills
     * this table's empty spare and frees the other node, and leaves the other
     * table's spare as it was. */
    assert(ExternalHashTableDeleteSync(&second) == 0 && !parked() && syncs == before + 2);
    assert(info.spare && info.spare != spare && !second.spare);
    release_entry(e[2]);
    release_entry(e[1]);
    ExternalHashTableCumulativeEntryFree(spare);
    removed(e[0]);
    assert(!bucket.h && !nodes() && !live_entries && !bucket_locked);

    /* A node parked from a table that is then deleted names no table: the
     * barrier that proves it frees it rather than refilling a freed spare. */
    struct en_cumulative_tbl_entry *orphan = ExternalHashTableAllocCumulativeEntry(&second);
    unsigned allocated = live_nodes;
    ehash_park_node(&second, orphan);
    ehash_unpark_table(&second);
    assert(parked() == 1 && !orphan->parked_on);
    assert(ExternalHashTableDeleteSync(&info) == 0 && !parked() && !second.spare);
    assert(live_nodes == allocated - 1);
}

/* A table deleted while a barrier issued through another table is in its
 * sync: the node parked from the dying table is in the barrier's batch, and
 * the release must free it rather than refill the freed table's spare. A
 * second node parked from the dying table during the sync waits on the parked
 * list, detached too. A nested barrier inside the sync links a second batch. */
static struct en_exthash_info *dying;
static struct en_cumulative_tbl_entry *dying_late;

static void delete_dying(void)
{
    dying_late = ExternalHashTableAllocCumulativeEntry(dying);
    ehash_park_node(dying, dying_late);
    ehash_unpark_table(dying);
    assert(!dying_late->parked_on);
    free(dying);    /* FreeEnEhashInfo(): ASan reports any later touch */
    dying = NULL;
}

static void nested_barrier(void)
{
    during_sync = delete_dying;
    assert(ExternalHashTableFmPcdHcSync(&info) == 0);
}

static void check_delete_during_sync(void)
{
    for (unsigned nested = 0; nested < 2; nested++) {
        struct en_cumulative_tbl_entry *node;
        unsigned allocated;

        dying = calloc(1, sizeof(*dying));
        dying->pcd = &pcd;
        node = ExternalHashTableAllocCumulativeEntry(dying);
        ehash_park_node(dying, node);
        allocated = live_nodes;
        during_sync = nested ? nested_barrier : delete_dying;
        assert(ExternalHashTableDeleteSync(&info) == 0 && !during_sync && !dying);
        /* The in-flight node freed, the late one still parked, unowned. */
        assert(live_nodes == allocated && parked() == 1 && ehash_parked == dying_late);
        assert(!ehash_inflight);
        assert(ExternalHashTableFmPcdHcSync(&info) == 0 && !parked());
        assert(live_nodes == allocated - 1);
    }
}

/* A second PCD's node parked while this PCD's nodes are in a barrier's sync. */
static struct en_exthash_info *foreign_table;
static struct en_cumulative_tbl_entry *foreign_node;

static void park_foreign(void)
{
    assert(!ehash_parked);
    ehash_park_node(foreign_table, foreign_node);
    assert(!ehash_parked);
}

int main(void)
{
    struct en_exthash_tbl_entry *e[24];
    unsigned before;

    /* The table's spare, which its creation fills. */
    info.spare = ExternalHashTableAllocCumulativeEntry(&info);
    assert(info.spare && live_nodes == 1 && !nodes());

    /* Three keys in one cumulative node; the third add replaced the node the
     * second made, behind a sync. */
    for (unsigned i = 0; i < 3; i++) { e[i] = entry(i); add(e[i]); }
    assert(chained() == 1 && nodes() == 1 && found(e[0]) && found(e[1]) && found(e[2]));

    /* A delete that rebuilds the node without the key: the node it replaced
     * is parked, the caller's entry comes back unsynced. */
    unsynced(e[2]);
    assert(parked() == 1 && nodes() == 2 && chained() == 1 && found(e[0]) && found(e[1]));
    assert(sync_failed_lines == 1 && !sync_recovered_lines);
    /* A barrier that fails keeps it; one that completes frees it, and the
     * caller may then free its own entry. The failure continues the delete's
     * run, so it adds no line; the completion ends it with one. */
    fail_syncs = 1;
    assert(ExternalHashTableFmPcdHcSync(&info) == -1 && parked() == 1 && nodes() == 2);
    assert(sync_failed_lines == 1 && !sync_recovered_lines);
    assert(ExternalHashTableFmPcdHcSync(&info) == 0 && !parked() && nodes() == 1);
    assert(sync_failed_lines == 1 && sync_recovered_lines == 1);
    release_entry(e[2]);

    /* Two keys and no neighbour: the bucket takes the last entry directly and
     * the node is parked. A node parked while a later sync is in flight was
     * unlinked too late for it, and waits for the next. */
    unsynced(e[1]);
    assert(direct(e[0]) && parked() == 1 && nodes() == 1);
    during_sync = park_late;
    removed(e[0]);
    assert(!bucket.h && parked() == 1 && ehash_parked == late && nodes() == 1);
    release_entry(e[1]);
    assert(ExternalHashTableFmPcdHcSync(&info) == 0 && !parked() && !nodes());

    /* A chain: ten keys fill a node, the eleventh starts one in front. The
     * front node going, with the one behind still holding ten, moves the
     * bucket to the one behind and parks the front. */
    for (unsigned i = 0; i < 11; i++) { e[i] = entry(100 + i); add(e[i]); }
    assert(chained() == 2 && nodes() == 2);
    unsynced(e[10]);
    assert(chained() == 1 && parked() == 1 && nodes() == 2);
    /* A delete that syncs is the same barrier: it frees what it replaced and
     * what was parked before it. */
    before = syncs;
    removed(e[0]);
    assert(syncs == before + 1 && !parked() && nodes() == 1 && chained() == 1);
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
    assert(!bucket.h && !nodes());

    /* Two single-key nodes in a chain. Either one going leaves the bucket
     * holding the other's entry directly, and both nodes are parked. */
    for (unsigned front = 0; front < 2; front++) {
        for (unsigned i = 0; i < 11; i++) { e[i] = entry(200 + i); add(e[i]); }
        for (unsigned i = 1; i < 10; i++) removed(e[i]);
        assert(chained() == 2 && nodes() == 2);
        struct en_exthash_tbl_entry *gone = front ? e[10] : e[0], *kept = front ? e[0] : e[10];
        unsynced(gone);
        assert(direct(kept) && parked() == 2 && nodes() == 2);
        removed(kept);
        assert(!bucket.h && !parked() && !nodes());
        release_entry(gone);
    }

    /* An add that rebuilds a node and whose sync fails stands, and the node
     * it replaced is parked rather than leaked. */
    for (unsigned i = 0; i < 2; i++) { e[i] = entry(300 + i); add(e[i]); }
    e[2] = entry(302);
    fail_syncs = 1;
    add(e[2]);
    assert(found(e[2]) && parked() == 1 && nodes() == 2);
    assert(ExternalHashTableFmPcdHcSync(&info) == 0 && !parked() && nodes() == 1);

    /* One sync proves nothing about a second PCD's walkers, so a node from
     * one is refused a place beside this PCD's and left alone. */
    unsynced(e[2]);
    assert(parked() == 1);
    struct en_exthash_info other = info;
    other.pcd = &other_pcd;
    other.spare = NULL;
    struct en_cumulative_tbl_entry *stray = ExternalHashTableAllocCumulativeEntry(&other);
    ehash_park_node(&other, stray);
    assert(warnings == 1 && parked() == 1);
    /* Nor does a sync on the second PCD free this one's. */
    assert(ExternalHashTableFmPcdHcSync(&other) == 0 && parked() == 1 && !other.spare);
    /* A failed sync on the second PCD neither retags this PCD's list nor
     * makes this PCD's next park look foreign. */
    fail_syncs = 1;
    assert(ExternalHashTableFmPcdHcSync(&other) == -1 && parked() == 1);
    assert(ehash_parked_pcd == &pcd);
    struct en_cumulative_tbl_entry *mine = ExternalHashTableAllocCumulativeEntry(&info);
    ehash_park_node(&info, mine);
    assert(warnings == 1 && parked() == 2);
    assert(ExternalHashTableFmPcdHcSync(&other) == 0);   /* ends the failure run */
    /* While this PCD's nodes are in flight, the second PCD's node is refused. */
    foreign_table = &other;
    foreign_node = stray;
    during_sync = park_foreign;
    fail_syncs = 1;
    assert(ExternalHashTableFmPcdHcSync(&info) == -1 && warnings == 2 && parked() == 2);
    assert(ehash_parked_pcd == &pcd);
    assert(ExternalHashTableFmPcdHcSync(&info) == 0 && !parked());
    XX_FreeSmart(stray);
    removed(e[1]);
    assert(!parked());
    release_entry(e[2]);
    removed(e[0]);
    assert(!bucket.h && !nodes() && !live_entries && !bucket_locked);

    /* The allocator failing a delete that rebuilds a node: the delete looks
     * under the lock, finds it needs one, drops the lock without touching
     * the bucket and takes the table's spare instead. The key is unlinked,
     * nothing is reported, and the node it replaced, once the barrier
     * proves it unreachable, is the new spare. */
    struct en_cumulative_tbl_entry *spare, *replaced;
    for (unsigned i = 0; i < 5; i++) { e[i] = entry(400 + i); add(e[i]); }
    assert(chained() == 1 && nodes() == 1);
    spare = info.spare;
    replaced = (void *)head();
    before = reports;
    fail_node_allocs = 1;
    removed(e[4]);
    assert(!fail_node_allocs && reports == before);
    assert((void *)head() == spare && info.spare == replaced && nodes() == 1 && !parked());
    for (unsigned i = 0; i < 4; i++) assert(found(e[i]));

    /* The same with the barrier failing too: the key is unlinked all the
     * same and the delete unsynced, with the node it replaced parked, so the
     * spare stays empty until a node is next released on the table. */
    spare = info.spare;
    replaced = (void *)head();
    fail_node_allocs = 1;
    unsynced(e[3]);
    assert(!fail_node_allocs && reports == before);
    assert((void *)head() == spare && !info.spare && ehash_parked == replaced && parked() == 1);
    for (unsigned i = 0; i < 3; i++) assert(found(e[i]));

    /* Inside that window, a second rebuild while the allocator still fails
     * issues one barrier of its own, which would release the parked node
     * into the spare. When that barrier fails too, this is the one delete
     * that still fails for memory -- reported, the bucket untouched, the key
     * still resolving, no invalid flag left on the node that holds it, and
     * the parked node still parked. */
    struct en_cumulative_tbl_entry *holder = (void *)head();
    uint64_t chain = bucket.h;
    unsigned reported = reports;
    before = syncs;
    fail_node_allocs = 1;
    fail_syncs = 1;
    assert(ExternalHashTableDeleteKey(&info, 0, e[2]) == -1);
    assert(!fail_node_allocs && !fail_syncs && syncs == before + 1);
    assert(reports == reported + 1 && !bucket_locked);
    assert(bucket.h == chain && (void *)head() == holder && found(e[2]) && chained() == 1);
    assert(holder->cumulative_entry.num_key_entries == 3);
    assert(!(holder->cumulative_entry.flags & EN_INVALID_CUMULATIVE_NODE));
    assert(!info.spare && ehash_parked == replaced && parked() == 1);

    /* The same delete when that barrier completes: the parked node is the
     * spare again, the delete takes it and succeeds, and its own barrier
     * releases the node it replaced into the spare in turn. The entry the
     * unsynced delete handed back is proven gone with it. */
    before = syncs;
    fail_node_allocs = 1;
    removed(e[2]);
    assert(!fail_node_allocs && reports == reported + 1 && syncs == before + 2);
    assert((void *)head() == replaced && info.spare == holder && !parked());
    assert(chained() == 1 && nodes() == 1 && found(e[0]) && found(e[1]));
    release_entry(e[3]);

    /* An add that rebuilds a node refills an empty spare the same way, with
     * the node it replaced once its barrier completes. */
    spare = xchg(&info.spare, NULL);
    replaced = (void *)head();
    e[5] = entry(405);
    add(e[5]);
    assert(info.spare == replaced && (void *)head() != replaced && !parked());
    assert(chained() == 1 && nodes() == 2 && found(e[5]));      /* and the one set aside */

    /* With nothing parked, no barrier could refill the spare, so none is
     * issued and the delete fails at once: how the spare is left while
     * another delete on the table holds it. */
    struct en_cumulative_tbl_entry *aside = xchg(&info.spare, NULL);
    holder = (void *)head();
    chain = bucket.h;
    reported = reports;
    before = syncs;
    fail_node_allocs = 1;
    assert(ExternalHashTableDeleteKey(&info, 0, e[5]) == -1);
    assert(!fail_node_allocs && syncs == before && reports == reported + 1);
    assert(bucket.h == chain && found(e[5]) && chained() == 1);
    assert(!(holder->cumulative_entry.flags & EN_INVALID_CUMULATIVE_NODE));
    info.spare = aside;
    ExternalHashTableCumulativeEntryFree(spare);
    removed(e[5]);
    assert(found(e[0]) && found(e[1]) && chained() == 1 && nodes() == 1);

    /* A delete that does not rebuild a node allocates nothing, so neither a
     * failing allocator nor an empty spare can stop it: two keys and no
     * neighbour, then the last key alone. The node the first one drops is
     * the next released on the table, and fills the empty spare. */
    holder = (void *)head();
    spare = xchg(&info.spare, NULL);
    fail_node_allocs = 1;
    unsigned allocated = live_nodes;
    assert(ExternalHashTableDeleteKey(&info, 0, e[1]) == 0 && !found(e[1]) && direct(e[0]));
    release_entry(e[1]);
    assert(info.spare == holder);
    assert(ExternalHashTableDeleteKey(&info, 0, e[0]) == 0 && !bucket.h);
    release_entry(e[0]);
    assert(fail_node_allocs == 1 && live_nodes == allocated && info.spare == holder);
    fail_node_allocs = 0;
    ExternalHashTableCumulativeEntryFree(spare);
    assert(!nodes() && !live_entries);

    /* A node the delete took but no longer needs, the bucket having changed
     * while the lock was dropped: here other deletes take the rest of the
     * node's keys meanwhile, so the first finds its key alone in the bucket.
     * The node goes back to the spare it came from. */
    for (unsigned i = 0; i < 3; i++) { e[i] = entry(500 + i); add(e[i]); }
    spare = info.spare;
    fail_node_allocs = 1;
    during_node_alloc = delete_meanwhile;
    meanwhile[0] = e[1];
    meanwhile[1] = e[0];
    removed(e[2]);
    assert(!during_node_alloc && !fail_node_allocs && !meanwhile[0] && !meanwhile[1]);
    assert(info.spare == spare && !bucket.h && !parked() && !nodes());
    assert(!live_entries && !bucket_locked);

    /* A node released into the spare still holds the links its chain and the
     * parked list last wrote, so taking it has to zero it: a rebuild through
     * it links only what its neighbours need. Here the node behind a front
     * node is rebuilt twice with both barriers failing, so the second node
     * parked carries a parked link to the first and its table where its link
     * to the front node was; a barrier then releases it into the empty spare
     * and frees the first. */
    for (unsigned i = 0; i < 11; i++) { e[i] = entry(600 + i); add(e[i]); }
    assert(chained() == 2);
    struct en_cumulative_tbl_entry *front = (void *)head(), *first, *stale;
    spare = xchg(&info.spare, NULL);
    unsynced(e[9]);
    first = ehash_parked;
    unsynced(e[8]);
    stale = ehash_parked;
    assert(parked() == 2 && stale->next_entry == first && stale->parked_on == &info);
    assert(ExternalHashTableFmPcdHcSync(&info) == 0 && !parked() && info.spare == stale);
    assert(stale->next_entry && stale->parked_on == &info);
    release_entry(e[9]);
    release_entry(e[8]);
    /* The node behind, with eight keys and the front node before it, rebuilt
     * through that spare while the allocator fails: the new node has the
     * front node before it and nothing after it. A link left from the parked
     * list would lead the chain into the node the barrier freed. */
    fail_node_allocs = 1;
    removed(e[7]);
    assert(!fail_node_allocs && front->next_entry == stale && chained() == 2);
    assert(stale->prev_entry == front && !stale->next_entry);
    assert(!stale->cumulative_entry.next_entry_addr);
    assert(!(stale->cumulative_entry.flags & EN_NEXT_CUMULATIVE_NODE));
    ExternalHashTableCumulativeEntryFree(spare);
    for (unsigned i = 0; i < 7; i++) removed(e[i]);
    removed(e[10]);
    assert(!bucket.h && !parked() && !nodes() && !live_entries);

    /* Each add or delete that links memory it has just written issues the
     * barrier before the linking store; one that only unlinks issues none,
     * except the unlink that clears a node's next-node flag and then its
     * address, which orders the two with it. */
    before = link_barriers;
    e[0] = entry(700); add(e[0]);               /* an empty bucket takes the entry */
    assert(link_barriers == before + 1);
    e[1] = entry(701); add(e[1]);               /* a new node for the two keys */
    assert(link_barriers == before + 2);
    e[2] = entry(702); add(e[2]);               /* the node rebuilt with three */
    assert(link_barriers == before + 3);
    removed(e[2]);                              /* and rebuilt with two */
    assert(link_barriers == before + 4);
    removed(e[1]);                              /* the bucket takes the last entry */
    removed(e[0]);                              /* and then nothing */
    assert(link_barriers == before + 4);
    for (unsigned i = 0; i < 11; i++) { e[i] = entry(710 + i); add(e[i]); }
    assert(chained() == 2 && link_barriers == before + 4 + 11);  /* the last a front node */
    e[11] = entry(721); add(e[11]);             /* the front node rebuilt with two */
    for (unsigned i = 0; i < 8; i++) removed(e[i]);
    before = link_barriers;
    removed(e[8]);                              /* the node behind rebuilt with one */
    assert(link_barriers == before + 1);
    removed(e[9]);                              /* and unhooked from the front node */
    assert(link_barriers == before + 2 && chained() == 1);
    struct en_cumulative_tbl_entry *last = (void *)head();
    assert(!(last->cumulative_entry.flags & EN_NEXT_CUMULATIVE_NODE));
    assert(!last->cumulative_entry.next_entry_addr && !last->next_entry);
    removed(e[10]);
    removed(e[11]);
    assert(link_barriers == before + 2 && !bucket.h && !nodes() && !live_entries);

    /* A barrier retried once a second while the channel stays down reports
     * the first failure of the run only, however long it lasts; the barrier
     * that ends it says so once, and the next run reports again. */
    unsigned failed = sync_failed_lines, recovered = sync_recovered_lines;
    fail_syncs = 10;
    for (unsigned i = 0; i < 10; i++)
        assert(ExternalHashTableFmPcdHcSync(&info) == -1);
    assert(sync_failed_lines == failed + 1 && sync_recovered_lines == recovered);
    assert(ExternalHashTableFmPcdHcSync(&info) == 0 && sync_recovered_lines == recovered + 1);
    assert(ExternalHashTableFmPcdHcSync(&info) == 0 && sync_recovered_lines == recovered + 1);
    fail_syncs = 1;
    assert(ExternalHashTableFmPcdHcSync(&info) == -1 && sync_failed_lines == failed + 2);
    assert(ExternalHashTableFmPcdHcSync(&info) == 0 && sync_recovered_lines == recovered + 2);

    check_deferred();
    check_delete_during_sync();
    check_find();
    check_bucket_cap();

    /* The table's destruction frees its spare, and with it the last node. */
    ExternalHashTableCumulativeEntryFree(xchg(&info.spare, NULL));
    assert(!live_nodes && !live_entries);
    puts("EHASH cumulative delete: every displaced node parked until a completed barrier, none leaked; "
         "a failed allocation falls back on the spare, and fails a delete only with the bucket untouched; "
         "a possibly linked entry is found wherever a bucket links it");
    return 0;
}
