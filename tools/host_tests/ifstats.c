/* The interface-statistics allocator, compiled from CDX against the shipped
 * SDK header and a simulated MURAM carve.
 *
 * What it pins down is the arithmetic nothing on hardware can show cheaply: a
 * record's index is what the firmware is handed, and an index naming the wrong
 * record is a counter update landing in somebody else's memory -- silent, and
 * visible only as another interface's numbers moving. So every index the
 * allocator produces is checked against the address of the record it came
 * from, and every record handed out is checked against every other.
 *
 * The two pools are one carve: four timestamped records for PPPoE followed by
 * the plain ones everything else uses, with two different strides indexing
 * from the same base. That is the whole hazard, and it is why the pools are
 * checked for overlap in the units the firmware indexes with rather than in
 * pointers.
 */
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SUCCESS 0
#define FAILURE -1
#define GFP_KERNEL 0
#define U8_MAX 255
#define __iomem
#define memset_io(dst, value, size) memset((void *)(dst), (value), (size))
/* layer2.h. Only "is it PPPoE" changes the arm taken. */
#define IF_TYPE_ETHERNET (1 << 0)
#define IF_TYPE_VLAN     (1 << 1)
#define IF_TYPE_PPPOE    (1 << 2)

typedef uint8_t u8;
typedef uint64_t u64;

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define cpu_to_be64(x) __builtin_bswap64((uint64_t)(x))
#define cpu_to_be32(x) __builtin_bswap32((uint32_t)(x))
#else
#define cpu_to_be64(x) ((uint64_t)(x))
#define cpu_to_be32(x) ((uint32_t)(x))
#endif
#define be64_to_cpu(x) cpu_to_be64(x)
#define be32_to_cpu(x) cpu_to_be32(x)

/* Not recursive, and nothing sleeps while it is held: the production comment
 * states that every taker is process context and that plain spin_lock() is
 * therefore sufficient, so an edit that allocates or reads under it has to
 * fail here rather than deadlock on a board. */
static int locked;
typedef struct { int held; } spinlock_t;
#define DEFINE_SPINLOCK(name) spinlock_t name = { 0 }
static void spin_lock(spinlock_t *lock)
{
    assert(!lock->held && !locked);
    lock->held = locked = 1;
}
static void spin_unlock(spinlock_t *lock)
{
    assert(lock->held && locked);
    lock->held = locked = 0;
}

static unsigned kzalloc_fail;
static unsigned kzalloc_calls, kfree_calls;
static void *kzalloc(size_t size, int flags)
{
    (void)flags;
    assert(!locked);    /* GFP_KERNEL may sleep */
    if (kzalloc_fail) {
        kzalloc_fail--;
        return NULL;
    }
    kzalloc_calls++;
    return calloc(1, size);
}
static void kfree(const void *ptr)
{
    if (ptr)
        kfree_calls++;
    free((void *)(uintptr_t)ptr);
}

static unsigned dpa_errors;
__attribute__((format(printf, 1, 2)))
static void log_sink(const char *fmt, ...)
{
    va_list ap;
    char discarded[256];

    va_start(ap, fmt);
    vsnprintf(discarded, sizeof(discarded), fmt, ap);
    va_end(ap);
}
#define DPA_ERROR(...) (dpa_errors++, log_sink(__VA_ARGS__))
#define printk(...) log_sink(__VA_ARGS__)

/* The MURAM carve, as a real allocation so a record touched after the carve is
 * returned is a use-after-free the sanitizer reports rather than a read of
 * whatever a static array still held. The carve deliberately does not start at
 * the MURAM base: what the firmware is given is an offset from
 * FmMurambaseAddr, and a carve at zero would make every wrong subtraction look
 * right. */
#define MURAM_HANDLE ((void *)(uintptr_t)0x4d55524du)
#define MURAM_CARVE_OFFSET 0x1000u
void *FmMurambaseAddr;
static uint8_t *muram_region;
static uint8_t *carve;
static size_t carve_size;
static unsigned muram_allocs, muram_frees;
static int muram_fail;

static void *FM_MURAM_AllocMem(void *handle, uint32_t size, uint32_t align)
{
    assert(handle == MURAM_HANDLE);
    assert(align == sizeof(uint64_t));
    assert(!muram_region);
    if (muram_fail)
        return NULL;
    muram_region = malloc(MURAM_CARVE_OFFSET + size);
    assert(muram_region);
    /* A fresh carve is not zero -- MURAM holds whatever the last owner left --
     * so a record handed out without being cleared shows up as poison. */
    memset(muram_region, 0xa5, MURAM_CARVE_OFFSET + size);
    FmMurambaseAddr = muram_region;
    carve = muram_region + MURAM_CARVE_OFFSET;
    carve_size = size;
    muram_allocs++;
    return carve;
}

static int FM_MURAM_FreeMem(void *handle, void *ptr)
{
    assert(handle == MURAM_HANDLE);
    assert(muram_region && ptr == carve);
    free(muram_region);
    muram_region = NULL;
    FmMurambaseAddr = NULL;
    carve = NULL;
    muram_frees++;
    return 0;
}

#include "ifstats_types.inc"
#include "ifstats.inc"

/* Geometry, restated from the record shapes rather than from the numbers this
 * file expects: a change to either record has to move the expected indices
 * with it instead of failing as an unexplained mismatch. */
#define TS_RECORDS    MAX_PPPoE_INTERFACES
#define PLAIN_RECORDS (MAX_LOGICAL_INTERFACES - MAX_PPPoE_INTERFACES)
#define TS_STRIDE     (sizeof(struct en_ehash_stats_with_ts))
#define PLAIN_STRIDE  (sizeof(struct en_ehash_stats))
#define TS_SIZE       (sizeof(struct cdx_pppoe_iface_ifinfo))
#define PLAIN_SIZE    (sizeof(struct cdx_iface_ifinfo))
/* Where the plain pool starts, in its own units. Every plain index is at least
 * this, which is what the claim "zero is never a valid index" rests on for a
 * pool whose records carry no flag of their own. */
#define PLAIN_BASE_UNITS ((unsigned)((TS_RECORDS * TS_SIZE) / PLAIN_STRIDE))
/* Both fields that eventually carry an index are eight bits wide, so a plain
 * record far enough into the carve cannot be named at all. */
#define PLAIN_NAMEABLE (((U8_MAX - PLAIN_BASE_UNITS) / 2) + 1)

static unsigned ts_free_count(void)
{
    struct cdx_pppoe_iface_ifinfo *record;
    unsigned n = 0;

    for (record = pppoe_ifstats_freelist; record; record = record->next) {
        n++;
        /* A record returned to a list twice makes a cycle, and a cycle is how
         * two owners end up counting into one record. Bounding the walk is
         * what turns that into a failure rather than a hang. */
        assert(n <= TS_RECORDS);
    }
    return n;
}

static unsigned plain_free_count(void)
{
    struct cdx_iface_ifinfo *record;
    unsigned n = 0;

    for (record = ifstats_freelist; record; record = record->next) {
        n++;
        assert(n <= PLAIN_RECORDS);
    }
    return n;
}

static int all_zero(const void *start, size_t size)
{
    const uint8_t *bytes = start;

    for (size_t i = 0; i < size; i++)
        if (bytes[i])
            return 0;
    return 1;
}

/* Every record handed out, as the byte range its *index* names -- not as the
 * pointer the allocator happens to hold. The two agreeing is the property;
 * checking the pointers against each other would pass even if every index were
 * wrong in the same way. */
struct claim {
    size_t start, end;
    const void *record;
    const char *pool;
};
static struct claim claims[TS_RECORDS + PLAIN_RECORDS];
static unsigned claim_count;

static void claim(const struct cdx_ft_stats_slot *slot, const char *pool)
{
    int timestamped = slot->kind == CDX_FT_STATS_TIMESTAMPED;
    size_t stride = timestamped ? TS_STRIDE : PLAIN_STRIDE;
    size_t size = timestamped ? TS_SIZE : PLAIN_SIZE;
    unsigned rx = slot->rx_index, tx = slot->tx_index;
    size_t start;

    if (timestamped) {
        /* A timestamped index always carries the flag, so the flag is not
         * part of the number. */
        assert((rx & STATS_WITH_TS) && (tx & STATS_WITH_TS));
        rx &= (unsigned)~STATS_WITH_TS;
        tx &= (unsigned)~STATS_WITH_TS;
    }
    /* The transmit half is the receive half plus one stride, which is what
     * makes a single slot describe both directions of one interface. */
    assert(tx == rx + 1);
    start = rx * stride;
    /* The index names the record the allocator is holding, and not another. */
    assert((const uint8_t *)slot->record - carve == (ptrdiff_t)start);
    assert(start + size <= carve_size);
    for (unsigned i = 0; i < claim_count; i++) {
        if (claims[i].start == start) {
            /* The same record handed out again after it was returned. A
             * record cannot change pools, so its range and its stride are
             * the ones it had before. */
            assert(claims[i].record == slot->record);
            assert(claims[i].end == start + size);
            assert(!strcmp(claims[i].pool, pool));
            return;
        }
        assert(start >= claims[i].end || start + size <= claims[i].start);
    }
    assert(claim_count < sizeof(claims) / sizeof(claims[0]));
    claims[claim_count++] = (struct claim){ start, start + size, slot->record, pool };
}

static void reset_claims(void) { claim_count = 0; }

/* One slot, taken and immediately checked for the properties every slot has:
 * a cleared record, an index that names it, and a range no other record's
 * index names. */
static struct cdx_ft_stats_slot *take(enum cdx_ft_stats_kind kind, const char *pool)
{
    struct cdx_ft_stats_slot *slot = (struct cdx_ft_stats_slot *)(uintptr_t)0xdeadbeef;

    assert(cdx_ft_ifstats_alloc(kind, &slot) == 0);
    assert(slot && slot->kind == kind);
    assert(all_zero(slot->record,
                    kind == CDX_FT_STATS_TIMESTAMPED ? TS_SIZE : PLAIN_SIZE));
    claim(slot, pool);
    return slot;
}

static void init_pools(void)
{
    assert(cdxdrv_init_stats(MURAM_HANDLE) == 0);
    /* What the firmware is handed is the carve's offset from the MURAM base,
     * not a pointer. */
    assert(get_logical_ifstats_base() == MURAM_CARVE_OFFSET);
    assert(ts_free_count() == TS_RECORDS);
    assert(plain_free_count() == PLAIN_RECORDS);
    reset_claims();
}

static void drop_pools(void)
{
    cdx_deinit_iface_stats(MURAM_HANDLE);
    assert(!ts_free_count() && !plain_free_count());
    assert(!get_logical_ifstats_base());
    reset_claims();
}

int main(void)
{
    struct cdx_ft_stats_slot *ts[TS_RECORDS];
    struct cdx_ft_stats_slot *plain[PLAIN_RECORDS];
    struct cdx_ft_stats_slot *slot;
    struct cdx_ft_stats rx, tx;
    struct dpa_iface_info iface;

    /* The shapes the index arithmetic divides by. If either changes, every
     * expected index below changes with it. */
    assert(TS_STRIDE == 24 && PLAIN_STRIDE == 16);
    assert(TS_SIZE == 2 * TS_STRIDE && PLAIN_SIZE == 2 * PLAIN_STRIDE);
    assert(TS_RECORDS == 4 && PLAIN_RECORDS == 124);
    assert(STATS_WITH_TS == 0x80);

    /* A carve that cannot be made is reported rather than indexed. */
    muram_fail = 1;
    assert(cdxdrv_init_stats(MURAM_HANDLE) != 0);
    assert(!ts_free_count() && !plain_free_count());
    muram_fail = 0;

    init_pools();

    /* ---- the timestamped pool -------------------------------------------
     *
     * Four records, handed out in the order the carve lays them down, each
     * naming its own two halves. The flag is set on both, which is what lets
     * an index of zero mean "no record" for a session: a real one always has
     * bit seven. */
    for (unsigned i = 0; i < TS_RECORDS; i++) {
        ts[i] = take(CDX_FT_STATS_TIMESTAMPED, "timestamped");
        assert(ts[i]->rx_index == (u8)((i * 2) | STATS_WITH_TS));
        assert(ts[i]->tx_index == (u8)((i * 2 + 1) | STATS_WITH_TS));
        assert(ts[i]->rx_index && ts[i]->tx_index);
        assert(ts_free_count() == TS_RECORDS - 1 - i);
    }

    /* Exhaustion. The pool is four deep and shared, so a fifth caller is an
     * expected outcome rather than a fault -- and it must come away with
     * nothing at all, because an index it kept would name a record another
     * owner is counting into. */
    slot = (struct cdx_ft_stats_slot *)(uintptr_t)0xdeadbeef;
    assert(cdx_ft_ifstats_alloc(CDX_FT_STATS_TIMESTAMPED, &slot) == -ENOSPC);
    assert(!slot);
    assert(!ts_free_count());
    /* And the plain pool is untouched by it: the two are separate lists, so
     * running out of one is not running out of the other. */
    assert(plain_free_count() == PLAIN_RECORDS);

    /* A returned record goes back to the head of its own list, so the next
     * caller reuses it -- with the same indices, because an index is a
     * property of the record and not of whoever holds it. */
    {
        u8 rx_index = ts[1]->rx_index, tx_index = ts[1]->tx_index;
        const void *record = ts[1]->record;

        cdx_ft_ifstats_free(&ts[1]);
        assert(!ts[1]);
        assert(ts_free_count() == 1);
        /* Idempotent: the free nulls the caller's pointer, so calling it
         * again returns nothing to the list a second time. A record on one
         * list twice is two owners counting into one record. */
        cdx_ft_ifstats_free(&ts[1]);
        assert(ts_free_count() == 1);

        ts[1] = take(CDX_FT_STATS_TIMESTAMPED, "timestamped");
        assert(ts[1]->record == record);
        assert(ts[1]->rx_index == rx_index && ts[1]->tx_index == tx_index);
        assert(!ts_free_count());
    }

    /* ---- the plain pool -------------------------------------------------
     *
     * The same carve, a different stride, and indices that start past the
     * timestamped records rather than at zero. Checked rather than assumed: a
     * plain pool that began at zero would collide with the "no record"
     * convention on its very first record. */
    assert(PLAIN_BASE_UNITS == 12);
    for (unsigned j = 0; j < PLAIN_NAMEABLE; j++) {
        plain[j] = take(CDX_FT_STATS_PLAIN, "plain");
        assert(plain[j]->rx_index == (u8)(PLAIN_BASE_UNITS + j * 2));
        assert(plain[j]->tx_index == (u8)(PLAIN_BASE_UNITS + j * 2 + 1));
        assert(plain[j]->rx_index && plain[j]->tx_index);
    }

    /* Bit seven is the top bit of an index that runs to 255, not a property of
     * the pool. Below this record a plain index cannot be mistaken for a
     * timestamped one; from it on the two are indistinguishable by the flag
     * alone, and only the pool the caller asked for says which stride applies.
     * Pinned rather than asserted away, so a reader that reaches for the flag
     * to tell a plain record from a timestamped one fails here. */
    {
        unsigned first_aliasing = (STATS_WITH_TS - PLAIN_BASE_UNITS + 1) / 2;

        assert(first_aliasing == 58 && first_aliasing < PLAIN_NAMEABLE);
        assert(!(plain[first_aliasing - 1]->rx_index & STATS_WITH_TS));
        assert(!(plain[first_aliasing - 1]->tx_index & STATS_WITH_TS));
        assert(plain[first_aliasing]->rx_index & STATS_WITH_TS);
    }

    /* The carve holds more plain records than eight bits can name. The
     * allocator refuses those rather than truncating -- a truncated index
     * names a record at the other end of the area, and for the first values it
     * wraps to that is the timestamped pool. */
    assert(PLAIN_NAMEABLE == 122 && PLAIN_RECORDS - PLAIN_NAMEABLE == 2);
    assert(plain_free_count() == PLAIN_RECORDS - PLAIN_NAMEABLE);
    slot = (struct cdx_ft_stats_slot *)(uintptr_t)0xdeadbeef;
    assert(cdx_ft_ifstats_alloc(CDX_FT_STATS_PLAIN, &slot) == -ENOSPC);
    assert(!slot);
    /* Refused, not consumed: the unnameable record is still on the list, so
     * asking has not lost it out of the pool. */
    assert(plain_free_count() == PLAIN_RECORDS - PLAIN_NAMEABLE);

    /* Returning a nameable one makes the pool usable again at once, which is
     * what says the refusal above is about that record rather than a latch on
     * the whole list. */
    {
        const void *record = plain[7]->record;
        u8 rx_index = plain[7]->rx_index;

        cdx_ft_ifstats_free(&plain[7]);
        assert(plain_free_count() == PLAIN_RECORDS - PLAIN_NAMEABLE + 1);
        plain[7] = take(CDX_FT_STATS_PLAIN, "plain");
        assert(plain[7]->record == record && plain[7]->rx_index == rx_index);
    }

    /* Every record handed out of both pools, checked against every other:
     * claim() did the pairwise work as each was taken, and this is the count
     * it did it over. */
    assert(claim_count == TS_RECORDS + PLAIN_NAMEABLE);

    /* ---- what the firmware wrote ----------------------------------------
     *
     * Big-endian in the record, host order out, and each half read from its
     * own address: a read that took the transmit numbers from the receive half
     * would look healthy on a symmetric flow and wrong on everything else. */
    {
        struct en_ehash_ifstats_with_ts *record = ts[0]->record;

        record->rxstats.bytes = cpu_to_be64(0x1122334455667788ULL);
        record->rxstats.pkts = cpu_to_be32(0xdeadbeefu);
        record->txstats.bytes = cpu_to_be64(0x99aabbccddeeff00ULL);
        record->txstats.pkts = cpu_to_be32(0x0badc0deu);
        cdx_ft_ifstats_read(ts[0], &rx, &tx);
        assert(rx.bytes == 0x1122334455667788ULL && rx.packets == 0xdeadbeefu);
        assert(tx.bytes == 0x99aabbccddeeff00ULL && tx.packets == 0x0badc0deu);
        /* Packets are 32 bits in the record and 64 in the report, so the
         * widening must not carry the top bit into the upper half. */
        assert(rx.packets < 0x100000000ULL && tx.packets < 0x100000000ULL);

        /* Either half may be skipped, and the other still lands. */
        rx = (struct cdx_ft_stats){ .bytes = 1, .packets = 1 };
        cdx_ft_ifstats_read(ts[0], NULL, &tx);
        assert(rx.bytes == 1 && tx.bytes == 0x99aabbccddeeff00ULL);
        cdx_ft_ifstats_read(ts[0], &rx, NULL);
        assert(rx.bytes == 0x1122334455667788ULL);
    }
    {
        struct en_ehash_ifstats *record = plain[0]->record;

        record->rxstats.bytes = cpu_to_be64(4096);
        record->rxstats.pkts = cpu_to_be32(32);
        record->txstats.bytes = cpu_to_be64(8192);
        record->txstats.pkts = cpu_to_be32(64);
        cdx_ft_ifstats_read(plain[0], &rx, &tx);
        assert(rx.bytes == 4096 && rx.packets == 32);
        assert(tx.bytes == 8192 && tx.packets == 64);
    }
    /* No slot reads as zeroes rather than as an error: a caller the pool had
     * nothing for still has to be able to show a number. */
    rx = (struct cdx_ft_stats){ .bytes = 1, .packets = 1 };
    tx = rx;
    cdx_ft_ifstats_read(NULL, &rx, &tx);
    assert(!rx.bytes && !rx.packets && !tx.bytes && !tx.packets);
    cdx_ft_ifstats_read(NULL, NULL, NULL);

    /* An allocation that cannot get its own bookkeeping reports that rather
     * than an empty pool, and takes no record with it. */
    {
        unsigned before = ts_free_count();

        cdx_ft_ifstats_free(&plain[6]);
        kzalloc_fail = 1;
        slot = (struct cdx_ft_stats_slot *)(uintptr_t)0xdeadbeef;
        assert(cdx_ft_ifstats_alloc(CDX_FT_STATS_PLAIN, &slot) == -ENOMEM);
        assert(!slot && !kzalloc_fail);
        assert(plain_free_count() == PLAIN_RECORDS - PLAIN_NAMEABLE + 1);
        assert(ts_free_count() == before);
        plain[6] = take(CDX_FT_STATS_PLAIN, "plain");
    }

    for (unsigned i = 0; i < TS_RECORDS; i++)
        cdx_ft_ifstats_free(&ts[i]);
    for (unsigned j = 0; j < PLAIN_NAMEABLE; j++)
        cdx_ft_ifstats_free(&plain[j]);
    assert(ts_free_count() == TS_RECORDS && plain_free_count() == PLAIN_RECORDS);
    /* A fresh carve, so both lists are back in the order the carve lays them
     * down. Returned records go to the head, so after the returns above the
     * head of each list is its last record rather than its first, and the
     * exact indices below would be naming whichever record that was. */
    drop_pools();
    init_pools();

    /* ---- the legacy owner, on the same two lists ------------------------
     *
     * A registered interface draws from the same pool, which is why the
     * flowtable allocator has to treat exhaustion as an ordinary outcome: the
     * four timestamped records are not its own. The two index computations
     * have to agree as well, because both end up in the same opcode field. */
    memset(&iface, 0, sizeof(iface));
    assert(alloc_iface_stats(IF_TYPE_PPPOE, &iface) == SUCCESS);
    assert(iface.stats && iface.last_stats);
    assert(ts_free_count() == TS_RECORDS - 1);
    {
        const void *record = iface.stats;
        u8 rx_index = iface.rxstats_index, tx_index = iface.txstats_index;

        assert(record == carve);
        assert(rx_index == (u8)STATS_WITH_TS);
        assert(tx_index == (u8)(STATS_WITH_TS | 1));
        free_iface_stats(IF_TYPE_PPPOE, &iface);
        assert(!iface.stats && !iface.last_stats);
        assert(ts_free_count() == TS_RECORDS);
        /* Idempotent, which is what the production comment claims: a caller
         * holding an interface whose record was already returned may call
         * again, and the record must not reach the list a second time. */
        free_iface_stats(IF_TYPE_PPPOE, &iface);
        assert(ts_free_count() == TS_RECORDS);
        free_iface_stats(IF_TYPE_VLAN, &iface);
        assert(plain_free_count() == PLAIN_RECORDS);

        slot = take(CDX_FT_STATS_TIMESTAMPED, "timestamped");
        assert(slot->record == record);
        assert(slot->rx_index == rx_index && slot->tx_index == tx_index);
        cdx_ft_ifstats_free(&slot);
    }

    /* The plain halves agree too, and the legacy path ORs no flag in for this
     * pool -- so for a record low enough in the carve the index is a number
     * bit seven is not part of. The pool has records that number reaches, and
     * they are the ones the plain walk above pinned. */
    memset(&iface, 0, sizeof(iface));
    assert(alloc_iface_stats(IF_TYPE_VLAN, &iface) == SUCCESS);
    assert((const uint8_t *)iface.stats - carve == (ptrdiff_t)(TS_RECORDS * TS_SIZE));
    assert(iface.rxstats_index == (u8)PLAIN_BASE_UNITS);
    assert(iface.txstats_index == (u8)(PLAIN_BASE_UNITS + 1));
    assert(!(iface.rxstats_index & STATS_WITH_TS));
    free_iface_stats(IF_TYPE_VLAN, &iface);
    assert(plain_free_count() == PLAIN_RECORDS);

    /* Its own bookkeeping failing refuses the interface without taking a
     * record, which is the difference between an interface that cannot be
     * registered and one registered against a record nothing names. */
    memset(&iface, 0, sizeof(iface));
    kzalloc_fail = 1;
    assert(alloc_iface_stats(IF_TYPE_PPPOE, &iface) == FAILURE);
    assert(!iface.stats && !iface.last_stats && !kzalloc_fail);
    assert(ts_free_count() == TS_RECORDS);

    /* Contention, both ways round. Four records between the two owners, and
     * whoever asks fifth is refused whichever owner that is. */
    {
        struct dpa_iface_info legacy[2];

        memset(legacy, 0, sizeof(legacy));
        assert(alloc_iface_stats(IF_TYPE_PPPOE, &legacy[0]) == SUCCESS);
        assert(alloc_iface_stats(IF_TYPE_PPPOE, &legacy[1]) == SUCCESS);
        ts[0] = take(CDX_FT_STATS_TIMESTAMPED, "timestamped");
        ts[1] = take(CDX_FT_STATS_TIMESTAMPED, "timestamped");
        assert(!ts_free_count());
        slot = (struct cdx_ft_stats_slot *)(uintptr_t)0xdeadbeef;
        assert(cdx_ft_ifstats_alloc(CDX_FT_STATS_TIMESTAMPED, &slot) == -ENOSPC);
        assert(!slot);
        /* The legacy owner is refused by the same emptiness, and refusing is
         * where it has to return the bookkeeping it already allocated -- the
         * sanitizer is what proves that path leaks nothing. */
        memset(&iface, 0, sizeof(iface));
        assert(alloc_iface_stats(IF_TYPE_PPPOE, &iface) == FAILURE);
        assert(!iface.stats && !iface.last_stats);

        cdx_ft_ifstats_free(&ts[0]);
        cdx_ft_ifstats_free(&ts[1]);
        free_iface_stats(IF_TYPE_PPPOE, &legacy[0]);
        free_iface_stats(IF_TYPE_PPPOE, &legacy[1]);
        assert(ts_free_count() == TS_RECORDS);
    }

    /* ---- what alloc_iface_stats leaves to its callers -------------------
     *
     * The bookkeeping allocation is unconditional and overwrites whatever the
     * interface already named. No caller can reach that: all four allocate the
     * dpa_iface_info fresh and call this once on it, so it is an invariant the
     * callers keep rather than one the function enforces. This is what it
     * costs if one ever stops keeping it -- both the previous allocation and
     * the previous record become unreachable, because returning either needs
     * the pointer that was overwritten. */
    {
        struct iface_stats *first;
        struct cdx_pppoe_iface_ifinfo *stranded;

        memset(&iface, 0, sizeof(iface));
        assert(alloc_iface_stats(IF_TYPE_PPPOE, &iface) == SUCCESS);
        first = iface.last_stats;
        stranded = iface.stats;
        assert(alloc_iface_stats(IF_TYPE_PPPOE, &iface) == SUCCESS);
        assert(iface.last_stats != first);
        assert(iface.stats != stranded);
        assert(ts_free_count() == TS_RECORDS - 2);
        free_iface_stats(IF_TYPE_PPPOE, &iface);
        assert(ts_free_count() == TS_RECORDS - 1);
        /* Standing in for the caller that does not exist, so the sanitizer
         * does not report as a leak what production cannot reach. */
        kfree(first);
        stranded->next = pppoe_ifstats_freelist;
        pppoe_ifstats_freelist = stranded;
        assert(ts_free_count() == TS_RECORDS);
    }

    /* ---- deinit ---------------------------------------------------------
     *
     * The carve goes back and both lists go with it. Anything asking after
     * that is refused rather than handed an index into memory the driver no
     * longer owns. */
    unsigned carves = muram_allocs, returns = muram_frees;

    slot = take(CDX_FT_STATS_TIMESTAMPED, "timestamped");
    drop_pools();
    assert(muram_frees == returns + 1);
    {
        struct cdx_ft_stats_slot *after = (struct cdx_ft_stats_slot *)(uintptr_t)0xdeadbeef;

        assert(cdx_ft_ifstats_alloc(CDX_FT_STATS_TIMESTAMPED, &after) == -ENOSPC);
        assert(!after);
        assert(cdx_ft_ifstats_alloc(CDX_FT_STATS_PLAIN, &after) == -ENOSPC);
        assert(!after);
    }
    /* A slot outliving the carve is returned without its record being touched:
     * there is no list to return it to, and the memory it names is gone.
     * Reaching for it here would be a use-after-free the sanitizer reports. */
    cdx_ft_ifstats_free(&slot);
    assert(!slot);
    cdx_ft_ifstats_free(&slot);
    /* And deinit itself, called twice, returns the carve once. */
    cdx_deinit_iface_stats(MURAM_HANDLE);
    assert(muram_frees == returns + 1);

    /* The driver comes back up on a fresh carve with full pools. */
    init_pools();
    assert(muram_allocs == carves + 1);
    slot = take(CDX_FT_STATS_TIMESTAMPED, "timestamped");
    assert(slot->rx_index == (u8)STATS_WITH_TS);
    cdx_ft_ifstats_free(&slot);
    drop_pools();

    assert(!locked);
    assert(kzalloc_calls == kfree_calls);
    assert(dpa_errors);
    printf("ifstats pool geometry, indices, exhaustion and lifetime checks passed"
           " (%u records named, %u allocations)\n",
           (unsigned)(TS_RECORDS + PLAIN_NAMEABLE), kzalloc_calls);
    return 0;
}
