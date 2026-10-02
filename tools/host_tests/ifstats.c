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
 *
 * The firmware keeps 32 bits of packets per record half, so the other thing
 * pinned here is the software count carried past them: exact across a wrap,
 * whichever of a read and the periodic sampler sees the record first, and
 * starting over whenever a record is handed out again.
 */
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
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
typedef uint32_t u32;
typedef uint64_t u64;
/* A warning the kernel would print is a failure here. */
#define WARN_ON_ONCE(condition) ({ assert(!(condition)); 0; })
#define min(a, b) ((a) < (b) ? (a) : (b))
#define min_t(type, a, b) ((type)(a) < (type)(b) ? (type)(a) : (type)(b))
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))

/* Enough of the kernel's list to hold the published slots, and enough of a net
 * device and its counters for dev_get_stats()'s fold: the index the fold keys
 * on, the namespace it refuses, and the four counters it adds to. */
struct list_head { struct list_head *next, *prev; };
#define LIST_HEAD(n) struct list_head n = { &n, &n }
#define list_entry(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define list_for_each_entry(p, h, m) \
    for (p = list_entry((h)->next, typeof(*p), m); &p->m != (h); p = list_entry(p->m.next, typeof(*p), m))
static void list_init(struct list_head *h) { h->next = h->prev = h; }
#define INIT_LIST_HEAD(h) list_init(h)
static void list_add_tail(struct list_head *e, struct list_head *h)
{ e->next = h; e->prev = h->prev; h->prev->next = e; h->prev = e; }
static void list_del(struct list_head *e) { e->prev->next = e->next; e->next->prev = e->prev; }
static void list_del_init(struct list_head *e) { list_del(e); list_init(e); }
static void list_move_tail(struct list_head *e, struct list_head *h) { list_del(e); list_add_tail(e, h); }
static int list_empty(const struct list_head *h) { return h->next == h; }
struct net { int unused; };
static struct net init_net, other_net;
struct net_device { int ifindex; struct net *net; };
#define dev_net(d) ((d)->net ? (d)->net : &init_net)
#define net_eq(a, b) ((a) == (b))
struct rtnl_link_stats64 { u64 rx_packets, tx_packets, rx_bytes, tx_bytes, rx_errors; };
#define ETH_HLEN 14

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
/* The CDX control mutex, under which every flowtable caller counts the holds.
 * This harness is one thread standing in for those callers, so it is always
 * inside it. */
static struct { struct { int mutex; } ctrl; } cdx_instance = { { 1 } }, *cdx_info = &cdx_instance;
#define lockdep_assert_held(lock) assert(*(lock))

/* One delayed work item as the system workqueue holds it: queued or not, and
 * for how long. Running it is the test's call, which is what lets the order of
 * a sample against a read be chosen. A synchronous cancel waits for a running
 * item and so may sleep, which makes it wrong under the statistics lock. */
#define HZ 250
struct work_struct { int unused; };
struct delayed_work {
    struct work_struct work;
    void (*func)(struct work_struct *work);
    int queued;
    unsigned long delay;
};
#define DECLARE_DELAYED_WORK(n, f) struct delayed_work n = { .func = (f) }
#define to_delayed_work(w) container_of(w, struct delayed_work, work)
static int schedule_delayed_work(struct delayed_work *dwork, unsigned long delay)
{
    if (dwork->queued)
        return 0;
    dwork->queued = 1;
    dwork->delay = delay;
    return 1;
}
static int cancel_delayed_work_sync(struct delayed_work *dwork)
{
    int queued = dwork->queued;

    assert(!locked);
    dwork->queued = 0;
    return queued;
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

/* What the firmware leaves in one record half after `frames` frames of `size`
 * bytes each: a byte count wide enough never to wrap, and a packet count that
 * is the low 32 bits of the frames and nothing more. Either record shape. */
#define FIRMWARE_COUNTED(half, frames, size)                          \
    ((half).bytes = cpu_to_be64((u64)(frames) * (size)),              \
     (half).pkts = cpu_to_be32((uint32_t)(frames)))

/* The workqueue's turn. The sampler runs because it was queued and for no
 * other reason, and it queues itself again for the same period. */
static void sampler_period(void)
{
    assert(ifstats_sampler.queued);
    ifstats_sampler.queued = 0;
    ifstats_sampler.func(&ifstats_sampler.work);
    assert(!locked);
    assert(ifstats_sampler.queued && ifstats_sampler.delay == IFSTATS_SAMPLE_PERIOD);
}

/* How many records the sampler would read: one per record handed out, by
 * either owner, and none once it is returned. */
static unsigned live_records(void)
{
    unsigned n = 0;

    for (unsigned i = 0; i < MAX_LOGICAL_INTERFACES; i++)
        n += ifstats_wide[i].live;
    return n;
}

static const struct ifstats_wide *wide_of(const void *record)
{
    unsigned index = ifstats_record_index(record);

    assert(index < MAX_LOGICAL_INTERFACES);
    return &ifstats_wide[index];
}

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
    /* And its widened counts start from the zero the record was cleared to,
     * whatever an earlier holder of the record left in them. */
    assert(wide_of(slot->record)->live);
    assert(all_zero(&wide_of(slot->record)->rx, sizeof(struct ifstats_wide_half)));
    assert(all_zero(&wide_of(slot->record)->tx, sizeof(struct ifstats_wide_half)));
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
    /* One widening entry per record the carve holds, both pools. */
    assert(sizeof(ifstats_wide) / sizeof(ifstats_wide[0]) == TS_RECORDS + PLAIN_RECORDS);

    /* The sampler starts with the module, before any carve exists, and its
     * period is well inside the fastest wrap: 2^32 minimum-size frames take
     * 289 s at 10G (14,880,952 frames a second), and the period leaves room for
     * a record counting nine times that fast. */
    assert(!ifstats_sampler.queued);
    cdx_ifstats_start();
    assert(ifstats_sampler.queued && ifstats_sampler.delay == IFSTATS_SAMPLE_PERIOD);
    assert(IFSTATS_SAMPLE_PERIOD <= 60 * HZ);
    assert(9ULL * 14880952 * IFSTATS_SAMPLE_PERIOD / HZ < (1ULL << 32));
    /* A period with no carve reads nothing and still comes round again: the
     * carve follows the configuration, the sampler the module. */
    sampler_period();
    assert(!live_records());

    /* A carve that cannot be made is reported rather than indexed. */
    muram_fail = 1;
    assert(cdxdrv_init_stats(MURAM_HANDLE) != 0);
    assert(!ts_free_count() && !plain_free_count());
    muram_fail = 0;
    sampler_period();

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
    assert(!live_records());
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
        ifstats_wide_claim(stranded, false);
        stranded->next = pppoe_ifstats_freelist;
        pppoe_ifstats_freelist = stranded;
        assert(ts_free_count() == TS_RECORDS);
        assert(!live_records());
    }

    /* ---- publication: what dev_get_stats() sees -------------------------
     *
     * A slot published to a device is folded into that device's counters and
     * no other's, restated per packet by the overhead it was published with,
     * and is gone from the fold the moment it is freed. The values are the
     * ones the bench measured: 64 tagged frames of 302 bytes arrive as 19,328
     * bytes in the record; a VLAN device counts them as 284 each. */
    {
        struct net_device tagged = { .ifindex = 7 }, other = { .ifindex = 8 };
        struct net_device elsewhere = { .ifindex = 7, .net = &other_net };
        struct rtnl_link_stats64 storage;
        struct en_ehash_ifstats *record;

        slot = take(CDX_FT_STATS_PLAIN, "plain");
        assert(list_empty(&slot->published) && list_empty(&published_slots));
        record = slot->record;
        record->rxstats.bytes = cpu_to_be64(19328);
        record->rxstats.pkts = cpu_to_be32(64);
        record->txstats.bytes = cpu_to_be64(19072);
        record->txstats.pkts = cpu_to_be32(64);

        /* Unpublished, a record reaches no device at all. */
        memset(&storage, 0, sizeof(storage));
        cdx_ft_ifstats_fold(&tagged, &storage);
        assert(!storage.rx_packets && !storage.rx_bytes && !storage.tx_packets && !storage.tx_bytes);

        cdx_ft_ifstats_publish(slot, tagged.ifindex, ETH_HLEN + 4, 0);
        assert(!list_empty(&slot->published) && published_slots.next == &slot->published);
        /* Added to whatever the device's own counters already held, which is
         * what the driver's software path put there. */
        storage = (struct rtnl_link_stats64){ .rx_packets = 10, .rx_bytes = 1000,
                                              .tx_packets = 20, .tx_bytes = 2000,
                                              .rx_errors = 3 };
        cdx_ft_ifstats_fold(&tagged, &storage);
        assert(storage.rx_packets == 74 && storage.rx_bytes == 1000 + 64 * 284);
        assert(storage.tx_packets == 84 && storage.tx_bytes == 2000 + 19072);
        assert(storage.rx_errors == 3);
        /* Another index, or the same index in another namespace, is another
         * device. */
        memset(&storage, 0, sizeof(storage));
        cdx_ft_ifstats_fold(&other, &storage);
        cdx_ft_ifstats_fold(&elsewhere, &storage);
        assert(!storage.rx_packets && !storage.rx_bytes && !storage.tx_packets && !storage.tx_bytes);

        /* Republishing moves the slot rather than listing it twice: the old
         * device stops seeing it and the new one sees it exactly once. */
        cdx_ft_ifstats_publish(slot, other.ifindex, ETH_HLEN, ETH_HLEN);
        assert(published_slots.next == &slot->published &&
               published_slots.prev == &slot->published);
        memset(&storage, 0, sizeof(storage));
        cdx_ft_ifstats_fold(&tagged, &storage);
        assert(!storage.rx_packets && !storage.rx_bytes);
        cdx_ft_ifstats_fold(&other, &storage);
        assert(storage.rx_packets == 64 && storage.rx_bytes == 19328 - 64 * ETH_HLEN);
        assert(storage.tx_packets == 64 && storage.tx_bytes == 19072 - 64 * ETH_HLEN);

        /* Saturation. Minimum-size frames carry padding the firmware counts
         * and the overhead cannot know about, so bytes can fall short of
         * packets times overhead; the answer is then zero, not a wrapped
         * count in the exabytes. On a record handed out afresh: a firmware
         * count only ever grows, and this one rewound would read as a
         * count gone all the way round. */
        cdx_ft_ifstats_free(&slot);
        slot = take(CDX_FT_STATS_PLAIN, "plain");
        record = slot->record;
        record->rxstats.bytes = cpu_to_be64(60 * 3);
        record->rxstats.pkts = cpu_to_be32(3);
        cdx_ft_ifstats_publish(slot, other.ifindex, 100, 0);
        memset(&storage, 0, sizeof(storage));
        cdx_ft_ifstats_fold(&other, &storage);
        assert(storage.rx_packets == 3 && storage.rx_bytes == 0);
        /* The port's own arm in devman.c uses the same helper directly, with
         * the Ethernet header as the receive overhead and none on transmit. */
        memset(&storage, 0, sizeof(storage));
        cdx_ifstats_fold(&storage, 19328, 64, 19072, 64, ETH_HLEN, 0);
        assert(storage.rx_bytes == 18432 && storage.tx_bytes == 19072);
        assert(storage.rx_packets == 64 && storage.tx_packets == 64);

        /* Two slots on one device add up; freeing one withdraws only it. */
        {
            struct cdx_ft_stats_slot *second = take(CDX_FT_STATS_PLAIN, "plain");
            struct en_ehash_ifstats *more = second->record;

            more->rxstats.bytes = cpu_to_be64(1000);
            more->rxstats.pkts = cpu_to_be32(10);
            cdx_ft_ifstats_publish(second, other.ifindex, 0, 0);
            memset(&storage, 0, sizeof(storage));
            cdx_ft_ifstats_fold(&other, &storage);
            assert(storage.rx_packets == 13 && storage.rx_bytes == 1000);
            cdx_ft_ifstats_free(&second);
            memset(&storage, 0, sizeof(storage));
            cdx_ft_ifstats_fold(&other, &storage);
            assert(storage.rx_packets == 3 && storage.rx_bytes == 0);
        }

        /* Withdrawing ahead of the free leaves the record readable but folded
         * nowhere; publishing again brings it back; a NULL slot is nothing to
         * withdraw. */
        cdx_ft_ifstats_unpublish(slot);
        assert(list_empty(&slot->published) && list_empty(&published_slots));
        memset(&storage, 0, sizeof(storage));
        cdx_ft_ifstats_fold(&other, &storage);
        assert(!storage.rx_packets && !storage.rx_bytes);
        cdx_ft_ifstats_read(slot, &rx, &tx);
        assert(rx.packets == 3);
        cdx_ft_ifstats_unpublish(slot);
        cdx_ft_ifstats_unpublish(NULL);
        cdx_ft_ifstats_publish(NULL, other.ifindex, 0, 0);
        cdx_ft_ifstats_publish(slot, other.ifindex, 100, 0);
        memset(&storage, 0, sizeof(storage));
        cdx_ft_ifstats_fold(&other, &storage);
        assert(storage.rx_packets == 3 && storage.rx_bytes == 0);

        /* Freeing withdraws the publication under the same lock the fold
         * reads under, so a fold afterwards finds nothing -- and the slot's
         * memory is gone, which is what the sanitizer would report if the
         * list still pointed at it. */
        cdx_ft_ifstats_free(&slot);
        assert(list_empty(&published_slots));
        memset(&storage, 0, sizeof(storage));
        cdx_ft_ifstats_fold(&other, &storage);
        assert(!storage.rx_packets && !storage.rx_bytes);

        /* A published slot that outlives the carve reads nothing rather than
         * the memory the carve used to be: the fold is what guards that, not
         * the owner returning the slot first. */
        slot = take(CDX_FT_STATS_PLAIN, "plain");
        cdx_ft_ifstats_publish(slot, other.ifindex, 0, 0);
        drop_pools();
        memset(&storage, 0, sizeof(storage));
        cdx_ft_ifstats_fold(&other, &storage);
        assert(!storage.rx_packets && !storage.rx_bytes);
        cdx_ft_ifstats_free(&slot);
        assert(list_empty(&published_slots));
        init_pools();
    }

    /* ---- a record a hardware entry still names --------------------------
     *
     * The flowtable owner frees a device's slot when the device goes, and an
     * entry whose delete could not be proven may still be walked by the
     * microcode, which writes the record on every hit. Freeing withdraws the
     * publication at once -- the device's index may already be someone
     * else's -- but the record goes back to its pool only with the last hold:
     * back on the list early, its first word would be the list's link for the
     * microcode to overwrite, and the next device would be handed a record the
     * old entry still counts into. */
    {
        struct net_device gone = { .ifindex = 11 };
        struct rtnl_link_stats64 storage;
        struct cdx_ft_stats_slot *adapter, *other;
        unsigned free_before, retained;
        u64 deferred, deferred_before;
        const void *record;

        cdx_ft_ifstats_retention(&retained, &deferred_before);
        assert(!retained);
        slot = take(CDX_FT_STATS_PLAIN, "plain");
        record = slot->record;
        free_before = plain_free_count();
        cdx_ft_ifstats_publish(slot, gone.ifindex, 0, 0);
        /* Both directions of one connection name the record. */
        cdx_ft_ifstats_hold(slot);
        cdx_ft_ifstats_hold(slot);
        adapter = slot;
        cdx_ft_ifstats_free(&adapter);
        assert(!adapter && list_empty(&published_slots));
        cdx_ft_ifstats_retention(&retained, &deferred);
        assert(retained == 1 && deferred == deferred_before + 1);
        assert(plain_free_count() == free_before);
        /* A late write lands in the record itself, which is folded into no
         * device, and the next device is handed another record. */
        ((struct en_ehash_ifstats *)slot->record)->rxstats.pkts = cpu_to_be32(5);
        memset(&storage, 0, sizeof(storage));
        cdx_ft_ifstats_fold(&gone, &storage);
        assert(!storage.rx_packets);
        other = take(CDX_FT_STATS_PLAIN, "plain");
        assert(other->record != record);
        cdx_ft_ifstats_free(&other);
        /* One direction proven: still held. The other: back at the head of
         * its list, and cleared when it is handed out again. */
        cdx_ft_ifstats_put(slot);
        cdx_ft_ifstats_retention(&retained, &deferred);
        assert(retained == 1 && plain_free_count() == free_before);
        cdx_ft_ifstats_put(slot);
        cdx_ft_ifstats_retention(&retained, &deferred);
        assert(!retained && deferred == deferred_before + 1);
        assert(plain_free_count() == free_before + 1);
        slot = take(CDX_FT_STATS_PLAIN, "plain");
        assert(slot->record == record);
        /* A free no entry waits on returns the record at once and defers
         * nothing. */
        cdx_ft_ifstats_free(&slot);
        cdx_ft_ifstats_retention(&retained, &deferred);
        assert(!retained && deferred == deferred_before + 1);
        assert(plain_free_count() == free_before + 1);
        /* A hold that outlives the carve: the last put finds no list to
         * return the record to, and frees the slot alone. */
        slot = take(CDX_FT_STATS_PLAIN, "plain");
        cdx_ft_ifstats_hold(slot);
        adapter = slot;
        cdx_ft_ifstats_free(&adapter);
        drop_pools();
        cdx_ft_ifstats_put(slot);
        cdx_ft_ifstats_retention(&retained, &deferred);
        assert(!retained && deferred == deferred_before + 2);
        assert(!plain_free_count());
        init_pools();
    }

    /* ---- packet counts past 32 bits -------------------------------------
     *
     * The firmware keeps 32 bits of packets and carries nothing out of them,
     * so its count comes round after 2^32 frames: under five minutes of
     * minimum-size frames at 10G. A device's counters only ever grow, and the
     * bytes are restated per packet, so a fold that added the raw count would
     * step the packets back by 2^32 at the wrap and the bytes forward by 2^32
     * Ethernet headers. */
    {
        struct net_device port = { .ifindex = 9 };
        struct rtnl_link_stats64 before, after;
        struct en_ehash_ifstats *record;

        slot = take(CDX_FT_STATS_PLAIN, "plain");
        record = slot->record;
        cdx_ft_ifstats_publish(slot, port.ifindex, ETH_HLEN, 0);
        FIRMWARE_COUNTED(record->rxstats, 0xfffffff0u, 64);
        FIRMWARE_COUNTED(record->txstats, 0xffffffffu, 64);
        memset(&before, 0, sizeof(before));
        cdx_ft_ifstats_fold(&port, &before);
        assert(before.rx_packets == 0xfffffff0u && before.tx_packets == 0xffffffffu);
        assert(before.rx_bytes == 0xfffffff0ULL * (64 - ETH_HLEN));

        /* Thirty-two frames later on receive and one on transmit, both
         * across the wrap: the raw counts now read 0x10 and 0. */
        FIRMWARE_COUNTED(record->rxstats, 0x100000010ULL, 64);
        FIRMWARE_COUNTED(record->txstats, 0x100000000ULL, 64);
        memset(&after, 0, sizeof(after));
        cdx_ft_ifstats_fold(&port, &after);
        assert(after.rx_packets >= before.rx_packets && after.tx_packets >= before.tx_packets);
        assert(after.rx_bytes >= before.rx_bytes && after.tx_bytes >= before.tx_bytes);
        assert(after.rx_packets - before.rx_packets == 32);
        assert(after.tx_packets - before.tx_packets == 1);
        assert(after.rx_bytes - before.rx_bytes == 32 * (64 - ETH_HLEN));
        assert(after.tx_bytes - before.tx_bytes == 64);
        assert(after.rx_packets == 0x100000010ULL);

        /* The /proc rows read the same total, not the raw word. */
        cdx_ft_ifstats_read(slot, &rx, &tx);
        assert(rx.packets == 0x100000010ULL && tx.packets == 0x100000000ULL);
        cdx_ft_ifstats_free(&slot);
        assert(!live_records());
    }

    /* The sampler and a read advance one total between them, whichever sees
     * the record first. Read just short of the wrap, sampled just past it,
     * read again: the sample takes the wrap and the read after it adds only
     * what came since, so nothing is counted twice or lost. */
    {
        struct net_device port = { .ifindex = 9 };
        struct rtnl_link_stats64 first, second;
        struct en_ehash_ifstats *record;

        slot = take(CDX_FT_STATS_PLAIN, "plain");
        record = slot->record;
        cdx_ft_ifstats_publish(slot, port.ifindex, ETH_HLEN, 0);
        FIRMWARE_COUNTED(record->rxstats, 0xfffffff0u, 64);
        memset(&first, 0, sizeof(first));
        cdx_ft_ifstats_fold(&port, &first);
        assert(first.rx_packets == 0xfffffff0u);

        FIRMWARE_COUNTED(record->rxstats, 0x100000010ULL, 64);
        sampler_period();
        assert(wide_of(record)->rx.packets == 0x100000010ULL);
        assert(wide_of(record)->rx.raw == 0x10);
        /* A read straight after the sample adds nothing to it. */
        cdx_ft_ifstats_read(slot, &rx, &tx);
        assert(rx.packets == 0x100000010ULL);

        FIRMWARE_COUNTED(record->rxstats, 0x100000020ULL, 64);
        memset(&second, 0, sizeof(second));
        cdx_ft_ifstats_fold(&port, &second);
        assert(second.rx_packets - first.rx_packets == 48);
        assert(second.rx_bytes - first.rx_bytes == 48 * (64 - ETH_HLEN));

        /* Nothing reads the record while the count comes round four
         * times, three quarters of 2^32 a period: the sampler alone sees
         * it move. The raw word at the end is 0x20 + 5, which is all a read
         * without the sampler would have had to go on. */
        {
            u64 frames = 0x100000020ULL;

            for (unsigned i = 0; i < 4; i++) {
                frames += 0xc0000000ULL;
                FIRMWARE_COUNTED(record->rxstats, frames, 64);
                sampler_period();
            }
            FIRMWARE_COUNTED(record->rxstats, frames + 5, 64);
            assert((uint32_t)(frames + 5) == 0x25);
            cdx_ft_ifstats_read(slot, &rx, &tx);
            assert(rx.packets == frames + 5 && rx.bytes == (frames + 5) * 64);
            assert(rx.packets == 0x400000025ULL);
            /* Transmit counted nothing, and reads so. */
            assert(!tx.packets && !tx.bytes);
        }

        /* Handed out again, the record starts over. Its widened count must
         * not survive the free: the cleared record reads zero, and a raw
         * word left at 0x25 would make that zero a wrap worth 2^32 - 0x25
         * frames. */
        {
            const void *reused = slot->record;

            cdx_ft_ifstats_free(&slot);
            assert(!wide_of(reused)->live);
            /* Returned, it is on a free list whose link overlays the count;
             * the sampler leaves it alone. */
            sampler_period();
            assert(all_zero(&wide_of(reused)->rx, sizeof(struct ifstats_wide_half)));
            slot = take(CDX_FT_STATS_PLAIN, "plain");
            assert(slot->record == reused);
            record = slot->record;
            cdx_ft_ifstats_read(slot, &rx, &tx);
            assert(!rx.packets && !rx.bytes && !tx.packets && !tx.bytes);
            FIRMWARE_COUNTED(record->rxstats, 7, 64);
            cdx_ft_ifstats_read(slot, &rx, &tx);
            assert(rx.packets == 7 && rx.bytes == 7 * 64);
        }
        cdx_ft_ifstats_free(&slot);
    }

    /* The timestamped pool wraps the same way, and its timestamp is no part
     * of the count. */
    {
        struct en_ehash_ifstats_with_ts *record;

        slot = take(CDX_FT_STATS_TIMESTAMPED, "timestamped");
        record = slot->record;
        FIRMWARE_COUNTED(record->txstats, 0xffffffffu, 90);
        record->txstats.timestamp = cpu_to_be64(0x0123456789abcdefULL);
        cdx_ft_ifstats_read(slot, NULL, &tx);
        assert(tx.packets == 0xffffffffu);
        FIRMWARE_COUNTED(record->txstats, 0x100000002ULL, 90);
        sampler_period();
        FIRMWARE_COUNTED(record->txstats, 0x100000003ULL, 90);
        cdx_ft_ifstats_read(slot, NULL, &tx);
        assert(tx.packets == 0x100000003ULL && tx.bytes == 0x100000003ULL * 90);
        cdx_ft_ifstats_free(&slot);
    }

    /* The registered-interface owner's records, read through the call its
     * fold in devman.c makes: sampled like the flowtable's, restated from the
     * widened count, and started over when the interface's record is handed
     * out again. */
    {
        struct rtnl_link_stats64 storage;
        struct cdx_iface_ifinfo *record;
        struct cdx_pppoe_iface_ifinfo *session;
        struct dpa_iface_info ppp;

        memset(&iface, 0, sizeof(iface));
        assert(alloc_iface_stats(IF_TYPE_ETHERNET, &iface) == SUCCESS);
        record = iface.stats;
        assert(wide_of(record)->live && live_records() == 1);
        FIRMWARE_COUNTED(record->stats.rxstats, 0xfffffffeu, 1514);
        FIRMWARE_COUNTED(record->stats.txstats, 0xfffffffeu, 60);
        cdx_ifstats_read(iface.stats, &rx, &tx);
        assert(rx.packets == 0xfffffffeu && tx.packets == 0xfffffffeu);
        FIRMWARE_COUNTED(record->stats.rxstats, 0x100000001ULL, 1514);
        FIRMWARE_COUNTED(record->stats.txstats, 0x100000001ULL, 60);
        sampler_period();
        FIRMWARE_COUNTED(record->stats.rxstats, 0x100000004ULL, 1514);
        cdx_ifstats_read(iface.stats, &rx, &tx);
        assert(rx.packets == 0x100000004ULL && tx.packets == 0x100000001ULL);
        memset(&storage, 0, sizeof(storage));
        cdx_ifstats_fold(&storage, rx.bytes, rx.packets, tx.bytes, tx.packets, ETH_HLEN, 0);
        assert(storage.rx_bytes == 0x100000004ULL * (1514 - ETH_HLEN));
        assert(storage.tx_bytes == 0x100000001ULL * 60);

        /* A PPPoE interface's record is a timestamped one, found by where it
         * sits in the carve rather than by anything the caller says. */
        memset(&ppp, 0, sizeof(ppp));
        assert(alloc_iface_stats(IF_TYPE_PPPOE, &ppp) == SUCCESS);
        session = ppp.stats;
        assert((const uint8_t *)session < carve + TS_RECORDS * TS_SIZE);
        FIRMWARE_COUNTED(session->stats.rxstats, 0x100000000ULL, 100);
        cdx_ifstats_read(ppp.stats, &rx, &tx);
        /* First read of a raw zero: nothing is known to have come round,
         * which is why a record has to be read once per wrap from the
         * moment it is handed out -- and the sampler does. */
        assert(rx.packets == 0 && rx.bytes == 0x100000000ULL * 100);
        FIRMWARE_COUNTED(session->stats.rxstats, 0x1c0000000ULL, 100);
        sampler_period();
        FIRMWARE_COUNTED(session->stats.rxstats, 0x200000001ULL, 100);
        cdx_ifstats_read(ppp.stats, &rx, &tx);
        assert(rx.packets == 0x100000001ULL);
        free_iface_stats(IF_TYPE_PPPOE, &ppp);

        free_iface_stats(IF_TYPE_ETHERNET, &iface);
        assert(!live_records());
        memset(&iface, 0, sizeof(iface));
        assert(alloc_iface_stats(IF_TYPE_ETHERNET, &iface) == SUCCESS);
        assert((void *)iface.stats == (void *)record);
        cdx_ifstats_read(iface.stats, &rx, &tx);
        assert(!rx.packets && !rx.bytes && !tx.packets && !tx.bytes);
        free_iface_stats(IF_TYPE_ETHERNET, &iface);

        /* No record reads as zeroes rather than as a fault. */
        rx = (struct cdx_ft_stats){ .bytes = 1, .packets = 1 };
        cdx_ifstats_read(NULL, &rx, &tx);
        assert(!rx.bytes && !rx.packets && !tx.bytes && !tx.packets);
    }

    /* The carve going away takes every widened count with it; a record in a
     * new carve starts from nothing, and a period without one reads nothing. */
    slot = take(CDX_FT_STATS_PLAIN, "plain");
    FIRMWARE_COUNTED(((struct en_ehash_ifstats *)slot->record)->rxstats, 42, 64);
    sampler_period();
    assert(live_records() == 1);
    drop_pools();
    assert(!live_records());
    sampler_period();
    cdx_ft_ifstats_read(slot, &rx, &tx);
    assert(!rx.packets && !rx.bytes);
    cdx_ft_ifstats_free(&slot);
    init_pools();
    assert(!live_records());

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

    /* Unloading stops the sampler for good: nothing is left queued to run
     * after the module's text is gone, and a second stop is harmless. A
     * module loaded again starts it again. */
    cdx_ifstats_stop();
    assert(!ifstats_sampler.queued);
    cdx_ifstats_stop();
    assert(!ifstats_sampler.queued);
    cdx_ifstats_start();
    assert(ifstats_sampler.queued);
    cdx_ifstats_stop();
    assert(!ifstats_sampler.queued);

    assert(!locked);
    assert(kzalloc_calls == kfree_calls);
    assert(dpa_errors);
    printf("ifstats pool geometry, indices, exhaustion, lifetime, publication and packet-wrap checks passed"
           " (%u records named, %u allocations)\n",
           (unsigned)(TS_RECORDS + PLAIN_NAMEABLE), kzalloc_calls);
    return 0;
}
