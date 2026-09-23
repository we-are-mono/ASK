/* The IPsec backend's view of what SEC counted, compiled from
 * cdx/cdx_ipsec_backend.c and cdx/cdx_dpa_ipsec.c.
 *
 * SEC keeps an SA's counters in its shared descriptor and rewrites them by DMA
 * after every frame. Two things about that are worth proving off the
 * hardware, because a rig run reaches neither in any reasonable time: the
 * packet count is 32 bits wide and wraps after 2^32 frames, which the backend
 * turns into a 64-bit total; and a read racing one of those rewrites can tear
 * the 64-bit byte count, which the backend refuses to report. The descriptor
 * read itself is scripted here, so a case can hand it the torn values a race
 * produces. The sequence number is read by the real function, from a PDB laid
 * out and byte-ordered the way SEC keeps it.
 */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

/* SEC on this SoC is big-endian, and the PDB builder writes it through
 * cpu_to_caam32(); the reader undoes that with caam32_to_cpu(). */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define cpu_to_caam32(x) __builtin_bswap32(x)
#define caam32_to_cpu(x) __builtin_bswap32(x)
#else
#define cpu_to_caam32(x) (x)
#define caam32_to_cpu(x) (x)
#endif

/* Each marked load of a descriptor word can be preceded by a store of SEC's,
 * so a case can land one between the two words of a reading. */
static void (*before_load)(void);
#define READ_ONCE(x) (before_load ? before_load() : (void)0, (x))
#define min(a, b) ((a) < (b) ? (a) : (b))

#include "ipsec_backend_types.inc"

/* The PDB's sequence words, where the encapsulation PDB keeps them. */
struct sec_descriptor {
	struct {
		u32 seq_num_ext_hi;
		u32 seq_num;
	} pdb_en;
};
typedef struct {
	struct sec_descriptor *sec_desc;
} DpaSecSAContext, *PDpaSecSAContext;
typedef struct {
	u8 direction;
	u16 flags;
	u16 stats_offset;
	PDpaSecSAContext pSec_sa_context;
} SAEntry, *PSAEntry;
typedef struct { int unused; } RouteEntry;
struct net_device;

static bool transaction = true;
static void cdx_ft_assert_held(void) { assert(transaction); }

/* What the descriptor holds, and what a racing read sees instead. A scripted
 * reading is consumed once; with none left the descriptor reads as it is. */
static struct { u32 packets; u64 bytes; } descriptor, script[16];
static unsigned scripted, script_next, descriptor_reads;
static void get_stats_from_sa(PSAEntry sa, u32 *pkts, u64 *bytes, u8 *overflow)
{
	/* A descriptor that keeps no counters is never read for them: offset
	 * zero is the PDB's options word. */
	assert(sa->stats_offset);
	assert(!overflow);	/* the legacy report is not this reader's */
	descriptor_reads++;
	if (script_next < scripted) {
		*pkts = script[script_next].packets;
		*bytes = script[script_next].bytes;
		script_next++;
		return;
	}
	*pkts = descriptor.packets;
	*bytes = descriptor.bytes;
}
static void read_as(u32 packets, u64 bytes)
{
	assert(scripted < sizeof(script) / sizeof(script[0]));
	script[scripted].packets = packets;
	script[scripted].bytes = bytes;
	scripted++;
}
static void script_reset(void) { scripted = script_next = descriptor_reads = 0; }

#include "ipsec_backend_production.inc"

static struct sec_descriptor pdb;
static DpaSecSAContext context = { .sec_desc = &pdb };
static SAEntry entry = { .pSec_sa_context = &context, .stats_offset = 40 };

static void pdb_next(u32 hi, u32 lo)
{
	pdb.pdb_en.seq_num_ext_hi = cpu_to_caam32(hi);
	pdb.pdb_en.seq_num = cpu_to_caam32(lo);
}

/* SEC's store of the carry from (1, FFFFFFFF) to (2, 0), one word at a time,
 * landing between the loads of the first reading. */
static unsigned loads;
static bool carry_high_first;
static void sec_carries(void)
{
	loads++;
	if (carry_high_first) {
		if (loads == 1)
			pdb.pdb_en.seq_num_ext_hi = cpu_to_caam32(2);
		if (loads == 3)
			pdb.pdb_en.seq_num = cpu_to_caam32(0);
	} else {
		if (loads == 2)
			pdb.pdb_en.seq_num = cpu_to_caam32(0);
		if (loads == 3)
			pdb.pdb_en.seq_num_ext_hi = cpu_to_caam32(2);
	}
}

/* SEC sends a frame before every load. */
static void sec_sends(void)
{
	pdb.pdb_en.seq_num = cpu_to_caam32(caam32_to_cpu(pdb.pdb_en.seq_num) + 1);
}

static void test_packet_total(void)
{
	struct cdx_ipsec_sa sa = { .entry = &entry };
	struct cdx_ipsec_counters c;

	entry.direction = CDX_DPA_IPSEC_INBOUND;
	entry.flags = 0;
	script_reset();

	/* Nothing carried yet. */
	descriptor.packets = 0;
	descriptor.bytes = 0;
	cdx_ipsec_sa_stats(&sa, &c);
	assert(!c.packets && !c.bytes && !c.oseq);

	/* Up to the edge of SEC's 32 bits, reported as they stand. */
	descriptor.packets = 0xfffffff0;
	descriptor.bytes = 0xfffff000ULL;
	cdx_ipsec_sa_stats(&sa, &c);
	assert(c.packets == 0xfffffff0 && c.bytes == 0xfffff000ULL);

	/* And across it. SEC's count wrapped to 0x10; the total did not. The
	 * byte count, which SEC keeps in 64 bits, crosses 2^32 as it is. */
	descriptor.packets = 0x10;
	descriptor.bytes = 0x100000400ULL;
	cdx_ipsec_sa_stats(&sa, &c);
	assert(c.packets == 0x100000010ULL);
	assert(c.bytes == 0x100000400ULL);

	/* A second wrap keeps adding: the total is built from differences,
	 * never read. */
	descriptor.packets = 0x20;
	cdx_ipsec_sa_stats(&sa, &c);
	descriptor.packets = 0x0f;
	cdx_ipsec_sa_stats(&sa, &c);
	assert(c.packets == 0x20000000fULL);

	/* An unchanged reading adds nothing. */
	cdx_ipsec_sa_stats(&sa, &c);
	assert(c.packets == 0x20000000fULL);
}

static void test_torn_reading(void)
{
	struct cdx_ipsec_sa sa = { .entry = &entry };
	struct cdx_ipsec_counters c;

	entry.direction = CDX_DPA_IPSEC_INBOUND;
	entry.flags = 0;
	descriptor.packets = 100;
	descriptor.bytes = 0xfffffff0ULL;
	script_reset();
	cdx_ipsec_sa_stats(&sa, &c);
	assert(c.packets == 100 && c.bytes == 0xfffffff0ULL);

	/* SEC rewrites the counters across the 4 GB boundary while they are
	 * read: the first reading takes the new high word and the old low one.
	 * It does not agree with the next, so it is never reported. */
	script_reset();
	read_as(101, 0x1fffffff0ULL);
	descriptor.packets = 101;
	descriptor.bytes = 0x100000590ULL;
	cdx_ipsec_sa_stats(&sa, &c);
	assert(c.packets == 101 && c.bytes == 0x100000590ULL);
	assert(descriptor_reads == 3);

	/* An SA busy enough that no two readings ever agree keeps the totals
	 * of its last clean one rather than reporting any of these. */
	script_reset();
	for (unsigned i = 0; i < 1 + CDX_IPSEC_SAMPLE_TRIES; i++)
		read_as(200 + i, (0x3ULL << 32) + i);
	cdx_ipsec_sa_stats(&sa, &c);
	assert(c.packets == 101 && c.bytes == 0x100000590ULL);
	assert(descriptor_reads == 1 + CDX_IPSEC_SAMPLE_TRIES);

	/* And the reading after it still counts every packet in between: the
	 * skipped one moved nothing it should not have. */
	script_reset();
	descriptor.packets = 300;
	descriptor.bytes = 0x100009000ULL;
	cdx_ipsec_sa_stats(&sa, &c);
	assert(c.packets == 300 && c.bytes == 0x100009000ULL);
}

/* Readings that agree and still cannot be right. */
static void test_implausible_bytes(void)
{
	struct cdx_ipsec_sa sa = { .entry = &entry };
	struct cdx_ipsec_counters c;

	entry.direction = CDX_DPA_IPSEC_INBOUND;
	entry.flags = 0;
	script_reset();
	descriptor.packets = 10;
	descriptor.bytes = 0xfffffff0ULL;
	cdx_ipsec_sa_stats(&sa, &c);
	assert(c.packets == 10 && c.bytes == 0xfffffff0ULL);

	/* Torn the same way twice across the 4 GB boundary: the new high word
	 * with the old low one, 2^32 too high, in both readings. They agree,
	 * and are still not believed -- nor is the packet count read with
	 * them. */
	script_reset();
	read_as(11, 0x1fffffff0ULL);
	read_as(11, 0x1fffffff0ULL);
	descriptor.packets = 11;
	descriptor.bytes = 0x1000005a0ULL;
	cdx_ipsec_sa_stats(&sa, &c);
	assert(descriptor_reads == 2);
	assert(c.packets == 10 && c.bytes == 0xfffffff0ULL);

	/* The next reading is the truth, a step from the last one believed:
	 * believed, with the packets it carried. */
	script_reset();
	cdx_ipsec_sa_stats(&sa, &c);
	assert(c.packets == 11 && c.bytes == 0x1000005a0ULL);

	/* Torn the other way, the old high word with the new low one: the
	 * count went down, which SEC's never does. */
	script_reset();
	read_as(12, 0x700ULL);
	read_as(12, 0x700ULL);
	cdx_ipsec_sa_stats(&sa, &c);
	assert(c.packets == 11 && c.bytes == 0x1000005a0ULL);

	/* A pass held off long enough at line rate for the count really to
	 * move 2^32 or more: held back once, then believed when the reading
	 * after it carries on from there, with every packet in between. */
	script_reset();
	descriptor.packets = 5000000;
	descriptor.bytes = 0x1000005a0ULL + (5ULL << 32);
	cdx_ipsec_sa_stats(&sa, &c);
	assert(c.packets == 11 && c.bytes == 0x1000005a0ULL);
	descriptor.packets = 6000000;
	descriptor.bytes += 1000000000;
	cdx_ipsec_sa_stats(&sa, &c);
	assert(c.packets == 6000000);
	assert(c.bytes == 0x1000005a0ULL + (5ULL << 32) + 1000000000);
}

/* A descriptor built without counters is never read for them. */
static void test_no_counters(void)
{
	SAEntry bare = { .direction = CDX_DPA_IPSEC_OUTBOUND,
			 .pSec_sa_context = &context };
	struct cdx_ipsec_sa sa = { .entry = &bare };
	struct cdx_ipsec_counters c;

	script_reset();
	descriptor.packets = 99;
	descriptor.bytes = 9999;
	pdb_next(0, 43);
	cdx_ipsec_sa_stats(&sa, &c);
	assert(!descriptor_reads && !c.packets && !c.bytes);
	/* Its sequence number still reads. */
	assert(c.oseq == 42);
}

static void test_sequence(void)
{
	struct cdx_ipsec_sa sa = { .entry = &entry };
	struct cdx_ipsec_counters c;

	script_reset();
	descriptor.packets = 0;
	descriptor.bytes = 0;

	/* The PDB holds the next number to send; xfrm counts the last one
	 * sent. A fresh SA seeded one past zero has sent nothing. */
	entry.direction = CDX_DPA_IPSEC_OUTBOUND;
	entry.flags = 0;
	pdb_next(0, 1);
	cdx_ipsec_sa_stats(&sa, &c);
	assert(c.oseq == 0);
	pdb_next(0, 0x80000000);
	assert(get_oseq_from_sa(&entry) == 0x7fffffff);

	/* Without ESN only the low word exists, whatever the other holds. SEC
	 * refuses to send FFFFFFFF itself (SEC RM table 9-2), so a space it
	 * has spent reads as ending at FFFFFFFE. */
	pdb_next(0xdeadbeef, 0xffffffff);
	assert(get_oseq_from_sa(&entry) == 0xfffffffe);

	/* With ESN the high word is part of the number, and the borrow crosses
	 * into it. */
	entry.flags = SA_ALLOW_EXT_SEQ_NUM;
	pdb_next(1, 0);
	assert(get_oseq_from_sa(&entry) == 0xffffffffULL);
	pdb_next(2, 5);
	assert(get_oseq_from_sa(&entry) == ((2ULL << 32) | 4));

	/* SEC's store across the carry, landing between the two words of a
	 * reading. Written high word first, the reading pairs the new high
	 * word with the old low one, 2^32 ahead; written low word first, the
	 * old high word with the new low one, 2^32 behind. Either way it does
	 * not agree with the reading after it, and the number reported is the
	 * one the store left. */
	for (int high_first = 0; high_first < 2; high_first++) {
		pdb_next(1, 0xffffffff);
		loads = 0;
		carry_high_first = high_first;
		before_load = sec_carries;
		assert(get_oseq_from_sa(&entry) == ((2ULL << 32) - 1));
		assert(loads > 4);
		before_load = NULL;
	}

	/* A number that never holds still is reported as the lower of its
	 * last two readings: published forward only, low errs safe. */
	pdb_next(3, 100);
	before_load = sec_sends;
	assert(get_oseq_from_sa(&entry) < ((3ULL << 32) | 100) + 2 * CDX_IPSEC_OSEQ_TRIES);
	assert(get_oseq_from_sa(&entry) >= ((3ULL << 32) | 99));
	before_load = NULL;

	/* An inbound SA sends nothing. */
	entry.direction = CDX_DPA_IPSEC_INBOUND;
	cdx_ipsec_sa_stats(&sa, &c);
	assert(c.oseq == 0);

	/* No SA, or one with no entry behind it, reads as nothing at all. */
	cdx_ipsec_sa_stats(NULL, &c);
	assert(!c.packets && !c.bytes && !c.oseq);
	sa.entry = NULL;
	cdx_ipsec_sa_stats(&sa, &c);
	assert(!c.packets && !c.bytes && !c.oseq);
}

int main(void)
{
	test_packet_total();
	test_torn_reading();
	test_implausible_bytes();
	test_no_counters();
	test_sequence();
	printf("ipsec backend: ok\n");
	return 0;
}
