/* The IPsec backend's view of an SA's sequence space and of what SEC counted,
 * compiled from cdx/cdx_ipsec_backend.c and cdx/cdx_dpa_ipsec.c.
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
 *
 * Going the other way, what the backend accepts of a starting sequence number
 * and an anti-replay window, and which of SEC's three windows a width is
 * carried on, with the PDB option values taken from the kernel's own header.
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
typedef uint16_t __be16;
typedef uint32_t __be32;

#define ETH_ALEN 6
#define AF_INET 2
#define AF_INET6 10
#define EIO 5
#define EBUSY 16
#define EINVAL 22
#define EOPNOTSUPP 95
#define U8_MAX ((u8)~0U)
#define U32_MAX ((u32)~0U)
#define U64_MAX ((u64)~0ULL)

union nf_inet_addr {
	u32 all[4];
	__be32 ip;
	__be32 ip6[4];
};
/* All of a port an SA's rebuild reads. */
struct net_device { unsigned int mtu; };

static bool is_zero_ether_addr(const u8 *a)
{
	static const u8 zero[ETH_ALEN];

	return !memcmp(a, zero, ETH_ALEN);
}
static void ether_addr_copy(u8 *dst, const u8 *src) { memcpy(dst, src, ETH_ALEN); }
#define min_t(type, a, b) ((type)(a) < (type)(b) ? (type)(a) : (type)(b))
#define pr_warn(...) ((void)0)
#define pr_err(...) ((void)0)

/* The port question is the backend's too, but not this harness's: every
 * case here names a port that can carry an SA. */
static bool cdx_ipsec_port_supported(struct net_device *dev) { return dev; }

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
#define __force
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
typedef uint16_t U16;

/* The real PDB structures and shared descriptor layout, from the kernel's
 * pdb.h and cdx/dpa_ipsec.h. */
#include "ipsec_backend_types.inc"

typedef struct {
	struct sec_descriptor *sec_desc;
} DpaSecSAContext, *PDpaSecSAContext;
typedef struct {
	u8 direction;
	u16 flags;
	u16 stats_offset;
	u64 seq;
	u16 replay_window;
	u32 replay_seen[SA_REPLAY_SEEN_WORDS];
	PDpaSecSAContext pSec_sa_context;
	/* An outbound SA's egress: its route, the classifier entry its frames
	 * leave SEC by, and the UDP ports a NAT-T SA shares that entry on. */
	struct _tRouteEntry *pRtEntry;
	struct hw_ct *ct;
	struct { u16 sport, dport; } natt;
} SAEntry, *PSAEntry;
/* The two fields of CDX's route an SA's framing is rebuilt from. */
typedef struct _tRouteEntry {
	u8 dstmac[ETH_ALEN];
	U16 mtu;
} RouteEntry;

static bool transaction = true;
static void cdx_ft_assert_held(void) { assert(transaction); }

/* The classifier entry an outbound SA's frames leave SEC by. Removal answers
 * as scripted, EN_EHASH_DELETE_UNSYNCED being the arm that parks the key
 * provably out of the table (the value the ehash patch gives it); each
 * install answers from its script and records the framing it was built
 * from. */
#define EN_EHASH_DELETE_UNSYNCED (-2)
static bool ft_failed;
static bool cdx_ft_failed(void) { return ft_failed; }
static int fp_delete_rc;
static unsigned fp_deletes, fp_installs;
static int fp_install_rc[4];
static RouteEntry fp_installed[4];
static int cdx_ipsec_delete_fp_entry(PSAEntry sa)
{
	assert(transaction && sa->ct && sa->ct->handle);
	fp_deletes++;
	return fp_delete_rc;
}
static int ipsec_install_fp_entry(PSAEntry sa)
{
	assert(transaction && fp_installs < 4);
	fp_installed[fp_installs] = *sa->pRtEntry;
	return fp_install_rc[fp_installs++];
}

/* SEC's reader, compiled from cdx_dpa_ipsec.c, with a hook that can store
 * into the PDB between two of the backend's reads, the way SEC does. */
static void sec_get_replay_from_sa(PSAEntry sa, u64 *seq, u32 *seen);
static void (*between_reads)(void);
static unsigned replay_reads;
static void get_replay_from_sa(PSAEntry sa, u64 *seq, u32 *seen)
{
	replay_reads++;
	sec_get_replay_from_sa(sa, seq, seen);
	if (between_reads)
		between_reads();
}

/* The descriptor reader's own dependencies: SEC's words are big-endian. */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define be32_to_cpu(x) __builtin_bswap32(x)
#define be64_to_cpu(x) __builtin_bswap64(x)
#define cpu_to_be64(x) __builtin_bswap64(x)
#else
#define be32_to_cpu(x) (x)
#define be64_to_cpu(x) (x)
#define cpu_to_be64(x) (x)
#endif
static void sec_get_stats_from_sa(PSAEntry sa, u32 *pkts, u64 *bytes);

/* What the descriptor holds, and what a racing read sees instead. A scripted
 * reading is consumed once; with none left the descriptor reads as it is. */
static struct { u32 packets; u64 bytes; } descriptor, script[16];
static unsigned scripted, script_next, descriptor_reads;
static void get_stats_from_sa(PSAEntry sa, u32 *pkts, u64 *bytes)
{
	/* A descriptor that keeps no counters is never read for them: offset
	 * zero is the PDB's options word. */
	assert(sa->stats_offset);
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

/* Which of SEC's windows a width is carried on. */
static void test_replay_window(void)
{
	SAEntry sa = { .direction = CDX_DPA_IPSEC_INBOUND };

	/* Anti-replay off is off, whatever width is recorded. */
	sa.flags = SA_ALLOW_SEQ_ROLL;
	sa.replay_window = 64;
	assert(cdx_ipsec_ars(&sa) == PDBOPTS_ESP_ARSNONE);

	/* An SA whose creator named no width -- the legacy owner -- keeps the
	 * 64 entries it always had. */
	sa.flags = 0;
	sa.replay_window = 0;
	assert(cdx_ipsec_ars(&sa) == PDBOPTS_ESP_ARS64);

	/* Each of SEC's widths as itself, and anything between them on the
	 * next wider: never a narrower window than was asked for. */
	for (unsigned w = 1; w <= 128; w++) {
		u32 ars;

		sa.replay_window = w;
		ars = cdx_ipsec_ars(&sa);
		if (w <= 32)
			assert(ars == PDBOPTS_ESP_ARS32);
		else if (w <= 64)
			assert(ars == PDBOPTS_ESP_ARS64);
		else
			assert(ars == PDBOPTS_ESP_ARS128);
		assert((ars & PDBOPTS_ESP_ARS_MASK) == ars);
	}
}

/* The spec's sequence space reaches the SA the PDB builders read, and an
 * inbound SA's window reaches the ARS bits. */
static void test_set_sequence(void)
{
	struct cdx_ipsec_sa_spec spec;
	SAEntry sa;

	/* Outbound: the last number sent, which the PDB builder seeds SEC one
	 * past. The window is not an outbound SA's. */
	memset(&spec, 0, sizeof(spec));
	memset(&sa, 0, sizeof(sa));
	spec.dir = CDX_IPSEC_DIR_OUT;
	spec.seq = (2ULL << 32) | 5;
	spec.replay_window = 64;
	spec.replay_seen[0] = 0xffff;
	cdx_ipsec_set_sequence(&sa, &spec);
	assert(sa.seq == ((2ULL << 32) | 5) && sa.replay_window == 0);
	assert(!sa.replay_seen[0]);

	/* Inbound: the highest received, the window, which SEC then keeps at
	 * the width that covers it, and the scorecard it starts from, word for
	 * word in the PDB's own numbering. */
	memset(&sa, 0, sizeof(sa));
	spec.dir = CDX_IPSEC_DIR_IN;
	spec.seq = 900;
	spec.replay_window = 32;
	spec.replay_seen[0] = 0x80000005;
	spec.replay_seen[3] = 0x1;
	cdx_ipsec_set_sequence(&sa, &spec);
	assert(sa.seq == 900 && sa.replay_window == 32);
	assert(sa.replay_seen[0] == 0x80000005 && sa.replay_seen[3] == 1);
	assert(cdx_ipsec_ars(&sa) == PDBOPTS_ESP_ARS32);

	/* A zero width reaches the PDB as anti-replay off, through the flag
	 * the cache create sets from it -- not as the legacy default. */
	memset(&sa, 0, sizeof(sa));
	sa.flags = SA_ALLOW_SEQ_ROLL;
	spec.replay_window = 0;
	cdx_ipsec_set_sequence(&sa, &spec);
	assert(cdx_ipsec_ars(&sa) == PDBOPTS_ESP_ARSNONE);
}

/* Where an inbound SA's window stands, read back from the decapsulation PDB
 * as SEC keeps it: big-endian words, the newest number in the least
 * significant bit of the first scorecard word. */
static SAEntry *inbound_entry;
static unsigned stores_left;
static void sec_stores_again(void)
{
	/* SEC takes another frame: the number moves on, and the scorecard
	 * with it. */
	if (!stores_left)
		return;
	stores_left--;
	pdb.pdb_dec.seq_num = cpu_to_caam32(caam32_to_cpu(pdb.pdb_dec.seq_num) + 1);
	pdb.pdb_dec.anti_replay[0] = cpu_to_caam32(
		(caam32_to_cpu(pdb.pdb_dec.anti_replay[0]) << 1) | 1);
}

/* The replay state an inbound SA's PDB is built with, word for word in SEC's
 * byte order, and read back as it went in. */
static void test_replay_seed(void)
{
	SAEntry in = { .direction = CDX_DPA_IPSEC_INBOUND,
		       .pSec_sa_context = &context,
		       .seq = 5000, .replay_window = 64,
		       .replay_seen = { 0x8000000b, 0x40000001, 0xffffffff, 0x2 } };
	struct ipsec_decap_pdb *dec = &pdb.pdb_dec;
	u32 seen[SA_REPLAY_SEEN_WORDS];
	u64 seq;

	/* Without ESN: the low word only, the width's ARS bits, and the
	 * scorecard with the newest number in the least significant bit of
	 * its first word. */
	memset(&pdb, 0, sizeof(pdb));
	cdx_ipsec_build_in_replay(&in, dec);
	assert(caam32_to_cpu(dec->seq_num) == 5000 && !dec->seq_num_ext_hi);
	assert(dec->options == PDBOPTS_ESP_ARS64);
	assert(caam32_to_cpu(dec->anti_replay[0]) == 0x8000000b &&
	       caam32_to_cpu(dec->anti_replay[1]) == 0x40000001 &&
	       caam32_to_cpu(dec->anti_replay[2]) == 0xffffffff &&
	       caam32_to_cpu(dec->anti_replay[3]) == 0x2);
	get_replay_from_sa(&in, &seq, seen);
	assert(seq == 5000 && !memcmp(seen, in.replay_seen, sizeof(seen)));

	/* With ESN: the high word too, and the ESN option. */
	memset(&pdb, 0, sizeof(pdb));
	in.flags = SA_ALLOW_EXT_SEQ_NUM;
	in.seq = (3ULL << 32) | 7;
	in.replay_window = 128;
	cdx_ipsec_build_in_replay(&in, dec);
	assert(caam32_to_cpu(dec->seq_num) == 7 &&
	       caam32_to_cpu(dec->seq_num_ext_hi) == 3);
	assert(dec->options == (PDBOPTS_ESP_ESN | PDBOPTS_ESP_ARS128));
	get_replay_from_sa(&in, &seq, seen);
	assert(seq == ((3ULL << 32) | 7) &&
	       !memcmp(seen, in.replay_seen, sizeof(seen)));

	/* Anti-replay off: no window and no scorecard, whatever the SA
	 * carried. */
	memset(&pdb, 0, sizeof(pdb));
	in.flags = SA_ALLOW_SEQ_ROLL;
	in.seq = 9;
	cdx_ipsec_build_in_replay(&in, dec);
	assert(dec->options == PDBOPTS_ESP_ARSNONE);
	for (unsigned int i = 0; i < SA_REPLAY_SEEN_WORDS; i++)
		assert(!dec->anti_replay[i]);
	memset(&pdb, 0, sizeof(pdb));
}

static void test_replay_read(void)
{
	SAEntry in = { .direction = CDX_DPA_IPSEC_INBOUND,
		       .pSec_sa_context = &context, .stats_offset = 40 };
	struct cdx_ipsec_sa sa = { .entry = &in };
	struct cdx_ipsec_counters c;

	inbound_entry = &in;
	memset(&pdb, 0, sizeof(pdb));
	script_reset();
	descriptor.packets = descriptor.bytes = 0;
	pdb.pdb_dec.seq_num = cpu_to_caam32(5000);
	pdb.pdb_dec.seq_num_ext_hi = cpu_to_caam32(7);
	pdb.pdb_dec.anti_replay[0] = cpu_to_caam32(0x0000000b);
	pdb.pdb_dec.anti_replay[1] = cpu_to_caam32(0x80000000);
	pdb.pdb_dec.anti_replay[3] = cpu_to_caam32(0x00000001);

	/* The low word alone without ESN, the high one with it, and the
	 * scorecard word for word: bit k of word k / 32 for seq - k. */
	cdx_ipsec_sa_stats(&sa, &c);
	assert(c.seq == 5000 && !c.oseq);
	assert(c.seen[0] == 0xb && c.seen[1] == 0x80000000 &&
	       !c.seen[2] && c.seen[3] == 1);
	in.flags = SA_ALLOW_EXT_SEQ_NUM;
	cdx_ipsec_sa_stats(&sa, &c);
	assert(c.seq == ((7ULL << 32) | 5000));

	/* Two readings that agree, taken while SEC stores between them: the
	 * reading is retaken until it holds still. */
	in.flags = 0;
	replay_reads = 0;
	stores_left = 2;
	between_reads = sec_stores_again;
	cdx_ipsec_sa_stats(&sa, &c);
	assert(c.seq == 5002 && c.seen[0] == ((0xbU << 2) | 3));
	assert(replay_reads == 4);

	/* A window that never holds still is not reported at all, rather than
	 * reported with a scorecard from another frame. */
	stores_left = 100;
	cdx_ipsec_sa_stats(&sa, &c);
	assert(!c.seq && !c.seen[0] && !c.seen[1]);
	between_reads = NULL;

	/* Anti-replay off: SEC keeps no window, and none is read. */
	in.flags = SA_ALLOW_SEQ_ROLL;
	replay_reads = 0;
	cdx_ipsec_sa_stats(&sa, &c);
	assert(!c.seq && !replay_reads);
	inbound_entry = NULL;
}

/* Where the per-SA counters sit in the shared descriptor, for every outer
 * header the encapsulation PDB carries and for decapsulation -- both
 * families -- and that the reader finds there what the descriptor stores. */
static void test_stats_layout(void)
{
	static const struct { u8 direction; u32 header; } cases[] = {
		{ CDX_DPA_IPSEC_OUTBOUND, 20 },	/* IPv4 tunnel or transport */
		{ CDX_DPA_IPSEC_OUTBOUND, 28 },	/* IPv4 tunnel, NAT-T */
		{ CDX_DPA_IPSEC_OUTBOUND, 40 },	/* IPv6 tunnel or transport */
		{ CDX_DPA_IPSEC_OUTBOUND, 48 },	/* IPv6 tunnel, NAT-T */
		{ CDX_DPA_IPSEC_INBOUND, 0 },	/* either family */
	};

	for (unsigned int i = 0; i < ARRAY_SIZE(cases); i++) {
		static struct sec_descriptor d __attribute__((aligned(64)));
		DpaSecSAContext ctx = { .sec_desc = &d };
		SAEntry e = { .direction = cases[i].direction,
			      .pSec_sa_context = &ctx };
		const u64 packets = cpu_to_be64(0x5ULL);
		const u64 bytes = cpu_to_be64(0x200000345ULL);
		size_t pdb_len, expected;
		u32 offset, got_packets;
		u64 got_bytes;
		u8 *base;

		memset(&d, 0, sizeof(d));
		if (e.direction == CDX_DPA_IPSEC_OUTBOUND)
			d.pdb_en.ip_hdr_len = cpu_to_caam32(cases[i].header);
		pdb_len = cdx_ipsec_pdb_len(&e);
		offset = cdx_ipsec_stats_offset(pdb_len);

		/* Right behind the PDB and whatever outer header it carries,
		 * so neither the header nor the anti-replay scorecard is
		 * overwritten by a count. */
		expected = sizeof(u32) +
			   (e.direction == CDX_DPA_IPSEC_OUTBOUND ?
			    sizeof(struct ipsec_encap_pdb) + cases[i].header :
			    sizeof(struct ipsec_decap_pdb));
		assert(offset == expected);
		/* Inside the descriptor, and within the reach of the byte
		 * offset the descriptor's MOVE commands address it by. */
		assert(offset + CDX_DPA_IPSEC_STATS_LEN * sizeof(u32) <=
		       sizeof(d.shared_desc));
		assert(offset + 8 <= 0xff);

		/* What the descriptor stores: the packet count as a 64-bit
		 * word, the byte count as the next. */
		base = (u8 *)d.shared_desc;
		memcpy(base + offset, &packets, sizeof(packets));
		memcpy(base + offset + 8, &bytes, sizeof(bytes));
		e.stats_offset = offset;
		sec_get_stats_from_sa(&e, &got_packets, &got_bytes);
		assert(got_packets == 5 && got_bytes == 0x200000345ULL);
	}
}

/* What the backend accepts of the sequence space and the window. */
static void test_validate(void)
{
	static const u8 peer[ETH_ALEN] = { 2, 0, 0, 0, 0, 1 };
	struct cdx_ipsec_sa_spec spec;

	memset(&spec, 0, sizeof(spec));
	spec.dev = (struct net_device *)&spec;
	spec.spi = 0x1234;
	spec.family = AF_INET;
	spec.crypt.alg = 12;
	spec.crypt.bits = 128;
	spec.dir = CDX_IPSEC_DIR_IN;
	assert(cdx_ipsec_validate(&spec) == 0);

	/* An authenticator only at a truncation SEC has an operation for,
	 * refused before anything is built: SHA-256 at RFC 4868's 128 bits,
	 * not at the 96 an older peer uses. */
	spec.auth.alg = SADB_X_AALG_SHA2_256HMAC;
	spec.auth.bits = 256;
	spec.auth.icv_bits = 128;
	assert(cdx_ipsec_validate(&spec) == 0);
	spec.auth.icv_bits = 96;
	assert(cdx_ipsec_validate(&spec) == -EOPNOTSUPP);
	memset(&spec.auth, 0, sizeof(spec.auth));

	/* What SEC adds to a frame reaches the classifier in a byte, so an SA
	 * whose expansion would not fit is refused rather than wrapped. */
	spec.dev_mtu = 1500;
	spec.mtu = 1438;
	assert(cdx_ipsec_validate(&spec) == 0);
	spec.mtu = 1500 - 255;
	assert(cdx_ipsec_validate(&spec) == 0);
	spec.mtu = 1500 - 256;
	assert(cdx_ipsec_validate(&spec) == -EOPNOTSUPP);
	spec.mtu = 1501;
	assert(cdx_ipsec_validate(&spec) == -EOPNOTSUPP);
	spec.mtu = spec.dev_mtu = 0;

	/* Every window SEC can keep, and none wider: a narrower one would
	 * drop late frames the configuration accepts. */
	spec.replay_window = CDX_IPSEC_REPLAY_WINDOW_MAX;
	assert(cdx_ipsec_validate(&spec) == 0);
	spec.replay_window = CDX_IPSEC_REPLAY_WINDOW_MAX + 1;
	assert(cdx_ipsec_validate(&spec) == -EOPNOTSUPP);

	/* An outbound SA checks nothing, so its window is no reason to refuse
	 * it. */
	spec.dir = CDX_IPSEC_DIR_OUT;
	memcpy(spec.dst_mac, peer, ETH_ALEN);
	spec.replay_window = 4096;
	assert(cdx_ipsec_validate(&spec) == 0);

	/* Without ESN the space is 32 bits, and an outbound SA needs one
	 * number left to send: SEC starts one past the one it is given and
	 * refuses to send FFFFFFFF (SEC RM table 9-2), so FFFFFFFD is the
	 * last start that leaves one. */
	spec.seq = U32_MAX - 2;
	assert(cdx_ipsec_validate(&spec) == 0);
	spec.seq = U32_MAX - 1;
	assert(cdx_ipsec_validate(&spec) == -EINVAL);
	spec.seq = U32_MAX;
	assert(cdx_ipsec_validate(&spec) == -EINVAL);
	spec.seq = (u64)U32_MAX + 1;
	assert(cdx_ipsec_validate(&spec) == -EINVAL);

	/* With ESN the high word is part of the number, and the all-ones
	 * one is refused the same way. */
	spec.esn = true;
	assert(cdx_ipsec_validate(&spec) == 0);
	spec.seq = U64_MAX - 2;
	assert(cdx_ipsec_validate(&spec) == 0);
	spec.seq = U64_MAX - 1;
	assert(cdx_ipsec_validate(&spec) == -EINVAL);
	spec.seq = U64_MAX;
	assert(cdx_ipsec_validate(&spec) == -EINVAL);

	/* An inbound SA may stand at the very top: that is where its window
	 * starts, not a number it has to send. */
	spec.dir = CDX_IPSEC_DIR_IN;
	spec.replay_window = 64;
	assert(cdx_ipsec_validate(&spec) == 0);
	spec.esn = false;
	spec.seq = U32_MAX;
	assert(cdx_ipsec_validate(&spec) == 0);
	spec.seq = (u64)U32_MAX + 1;
	assert(cdx_ipsec_validate(&spec) == -EINVAL);
}

/* Moving an SA's framing: the peer's address and the path's MTU, rebuilt
 * into the classifier entry its frames leave SEC by -- and put back as they
 * were, both of them, when the new entry cannot be installed. */
static void test_set_next_hop(void)
{
	static const u8 was[ETH_ALEN] = { 2, 0, 0, 0, 0, 1 };
	static const u8 now[ETH_ALEN] = { 2, 0, 0, 0, 0, 2 };
	struct net_device port = { .mtu = 1500 };
	struct hw_ct ct = { .handle = &ct };
	SAEntry sa_entry = { .ct = &ct };
	struct cdx_ipsec_sa sa = { .entry = &sa_entry, .dev = &port, .handle = 7 };

	sa_entry.pRtEntry = &sa.route;
#define REARM(mtu_) do { \
	memcpy(sa.route.dstmac, was, ETH_ALEN); sa.route.mtu = (mtu_); \
	sa.stranded = false; ft_failed = false; fp_delete_rc = 0; \
	fp_deletes = fp_installs = 0; memset(fp_install_rc, 0, sizeof(fp_install_rc)); \
	memset(fp_installed, 0, sizeof(fp_installed)); \
} while (0)

	/* A narrower path: the entry is rebuilt to fragment to it. */
	REARM(1500);
	assert(cdx_ipsec_sa_set_next_hop(&sa, now, 1492) == 0);
	assert(fp_deletes == 1 && fp_installs == 1);
	assert(!memcmp(fp_installed[0].dstmac, now, ETH_ALEN) && fp_installed[0].mtu == 1492);
	assert(!memcmp(sa.route.dstmac, now, ETH_ALEN) && sa.route.mtu == 1492);

	/* Never wider than the port, whatever the route says. */
	REARM(1492);
	assert(cdx_ipsec_sa_set_next_hop(&sa, now, 9000) == 0);
	assert(fp_installed[0].mtu == 1500 && sa.route.mtu == 1500);
	port.mtu = 1480;
	REARM(1500);
	assert(cdx_ipsec_sa_set_next_hop(&sa, now, 1500) == 0);
	assert(sa.route.mtu == 1480);
	port.mtu = 1500;

	/* No MTU keeps the one the entry has: a peer that moved, alone. */
	REARM(1400);
	assert(cdx_ipsec_sa_set_next_hop(&sa, now, 0) == 0);
	assert(fp_installed[0].mtu == 1400 && sa.route.mtu == 1400);

	/* An install that fails puts the old framing back, address and MTU,
	 * and reinstalls it. */
	REARM(1500);
	fp_install_rc[0] = -1;
	assert(cdx_ipsec_sa_set_next_hop(&sa, now, 1400) == -EIO);
	assert(fp_installs == 2 && !sa.stranded);
	assert(!memcmp(fp_installed[0].dstmac, now, ETH_ALEN) && fp_installed[0].mtu == 1400);
	assert(!memcmp(fp_installed[1].dstmac, was, ETH_ALEN) && fp_installed[1].mtu == 1500);
	assert(!memcmp(sa.route.dstmac, was, ETH_ALEN) && sa.route.mtu == 1500);

	/* And when that fails too, the SA is stranded on the framing it had. */
	REARM(1500);
	fp_install_rc[0] = fp_install_rc[1] = -1;
	assert(cdx_ipsec_sa_set_next_hop(&sa, now, 1400) == -EIO);
	assert(fp_installs == 2 && sa.stranded);
	assert(!memcmp(sa.route.dstmac, was, ETH_ALEN) && sa.route.mtu == 1500);
	/* Which is terminal for its framing. */
	fp_installs = fp_deletes = 0;
	assert(cdx_ipsec_sa_set_next_hop(&sa, now, 1400) == -EIO);
	assert(fp_deletes == 0 && fp_installs == 0 && sa.route.mtu == 1500);

	/* A removal that cannot prove the key gone moves nothing, for good. */
	REARM(1500);
	fp_delete_rc = -1;
	assert(cdx_ipsec_sa_set_next_hop(&sa, now, 1400) == -EIO);
	assert(sa.stranded && fp_installs == 0);
	assert(!memcmp(sa.route.dstmac, was, ETH_ALEN) && sa.route.mtu == 1500);
	/* The unsynced arm parks the key out of the table, so a rebuild over
	 * it goes ahead. */
	REARM(1500);
	fp_delete_rc = EN_EHASH_DELETE_UNSYNCED;
	assert(cdx_ipsec_sa_set_next_hop(&sa, now, 1400) == 0);
	assert(fp_installs == 1 && sa.route.mtu == 1400 && !sa.stranded);

	/* A NAT-T entry another SA shares would only drop a reference, so it
	 * is refused with nothing touched. */
	REARM(1500);
	sa_entry.natt.sport = sa_entry.natt.dport = 4500;
	ct.natt_out_refcnt = 2;
	assert(cdx_ipsec_sa_set_next_hop(&sa, now, 1400) == -EBUSY);
	assert(fp_deletes == 0 && fp_installs == 0 && sa.route.mtu == 1500);
	ct.natt_out_refcnt = 1;
	assert(cdx_ipsec_sa_set_next_hop(&sa, now, 1400) == 0 && sa.route.mtu == 1400);
	sa_entry.natt.sport = sa_entry.natt.dport = 0;

	/* Refused outright: no address, a route not the SA's own, a failed
	 * backend. */
	REARM(1500);
	assert(cdx_ipsec_sa_set_next_hop(&sa, (const u8[ETH_ALEN]){ 0 }, 1400) == -EINVAL);
	sa_entry.pRtEntry = NULL;
	assert(cdx_ipsec_sa_set_next_hop(&sa, now, 1400) == -EINVAL);
	sa_entry.pRtEntry = &sa.route;
	ft_failed = true;
	assert(cdx_ipsec_sa_set_next_hop(&sa, now, 1400) == -EIO);
	assert(fp_deletes == 0 && fp_installs == 0 && sa.route.mtu == 1500);
#undef REARM
}

int main(void)
{
	test_packet_total();
	test_torn_reading();
	test_implausible_bytes();
	test_no_counters();
	test_sequence();
	test_replay_window();
	test_set_sequence();
	test_replay_seed();
	test_replay_read();
	test_stats_layout();
	test_validate();
	test_set_next_hop();
	printf("ipsec backend: ok\n");
	return 0;
}
