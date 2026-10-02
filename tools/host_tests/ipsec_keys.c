/* The keys an SA is programmed with, compiled from cdx/cdx_ipsec_backend.c,
 * cdx/control_ipsec.c and cdx/cdx_dpa_ipsec.c: what the backend hands the key
 * setter from a spec, what the setter leaves in the SEC context -- the
 * authenticator's protocol operation, its key and the key's length -- and the
 * SEC job that derives an HMAC's split key from it.
 *
 * SEC runs that operation on every frame and fixes the ICV in it. The ICV's
 * length and the key's arrive as two adjacent integers, so a setter that took
 * one for the other would compile, install, and fail every frame the SA
 * carried; the cases below are chosen so that any such swap shows.
 *
 * The split key is SEC's to write, into the buffer the shared descriptor
 * loads for every frame. Here the job ring is a model: it accepts the job or
 * refuses it as a full or unmappable ring would, and "runs" it only when the
 * generator waits, reporting whatever status the case gives SEC -- or the
 * user status a job halted by the fault knob reports. The model holds the
 * generator to the rules a real ring imposes: nothing the job reads or writes
 * is freed or unmapped before it completes, nothing is waited for that was
 * never queued, and a failed job leaves no split key and no authenticator.
 */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint8_t U8;
typedef uint16_t U16;
typedef uint32_t U32;
typedef uint16_t __be16;
typedef uint32_t __be32;
typedef uint64_t dma_addr_t;

#define ETH_ALEN 6
#define EIO 5
#define ENOMEM 12
#define ENODEV 19
#define EINVAL 22
#define ENOSPC 28
#define EOPNOTSUPP 95
#define EBUSY 16
#define EINPROGRESS 115
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define ALIGN(x, a) (((x) + (a) - 1) & ~((a) - 1))
#define DPA_ERROR(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#define log_err(...) fprintf(stderr, __VA_ARGS__)
#define dev_err(dev, ...) ((void)(dev), fprintf(stderr, __VA_ARGS__))
#define dev_dbg(dev, ...) ((void)(dev))
#define memzero_explicit(p, n) memset((p), 0, (n))

union nf_inet_addr {
	u32 all[4];
	__be32 ip;
	__be32 ip6[4];
};
struct net_device;
struct device { int ring; };

struct netlink_ext_ack { const char *_msg; };
#define NL_SET_ERR_MSG(extack, msg) do { \
	struct netlink_ext_ack *__e = (extack); \
	if (__e) __e->_msg = (msg); \
} while (0)

/* SEC's command encodings, from the kernel's own header. */
#include "desc.h"

/* PF_KEY's numbers and SEC's status sources from the kernel, SEC's operation
 * codes and the key bound from cdx, the kernel's split-key result, and the
 * backend's own description of an SA. */
#include "ipsec_keys_types.inc"

/* The SA as far as its keys go. */
typedef struct {
	struct cipher_params cipher_data;
	struct auth_params auth_data;
} DpaSecSAContext, *PDpaSecSAContext;
typedef struct {
	PDpaSecSAContext pSec_sa_context;
} SAEntry, *PSAEntry;

/* --- memory ---------------------------------------------------------- */
#define GFP_KERNEL 1
#define GFP_DMA 2
static bool fail_kmalloc;
static void *descriptor;
static size_t descriptor_size;
static void *kmalloc(size_t size, int flags)
{
	assert(flags == (GFP_KERNEL | GFP_DMA));
	if (fail_kmalloc)
		return NULL;
	assert(!descriptor);
	descriptor = malloc(size);
	descriptor_size = size;
	return descriptor;
}

/* --- DMA: an address is the pointer, and a mapping is counted ------------ */
enum dma_data_direction { DMA_TO_DEVICE = 1, DMA_FROM_DEVICE = 2 };
#define DMA_MAPPING_ERROR (~(dma_addr_t)0)
static int fail_map_at = -1;
static int maps, live_maps;
static dma_addr_t dma_map_single(struct device *dev, void *ptr, size_t size,
				 enum dma_data_direction dir)
{
	(void)dev; (void)size; (void)dir;
	if (maps++ == fail_map_at)
		return DMA_MAPPING_ERROR;
	live_maps++;
	return (dma_addr_t)(uintptr_t)ptr;
}
static int dma_mapping_error(struct device *dev, dma_addr_t addr)
{
	(void)dev;
	return addr == DMA_MAPPING_ERROR;
}

/* --- the job ring ------------------------------------------------------ */
static struct device ring = { 1 };
static struct device *jrdev_g = &ring;
enum { RING_ACCEPTS, RING_FULL, RING_UNMAPPABLE } ring_answer;
/* The status SEC ends an accepted job with: 0 for success. */
static u32 sec_status;
static struct {
	bool outstanding;
	u32 *desc;
	void (*done)(struct device *, u32 *, u32, void *);
	void *arg;
} job;
static unsigned jobs, waits;

static void dma_unmap_single(struct device *dev, dma_addr_t addr, size_t size,
			     enum dma_data_direction dir)
{
	(void)dev; (void)addr; (void)size; (void)dir;
	/* SEC reads the key and writes the split key until the job ends. */
	assert(!job.outstanding);
	assert(live_maps > 0);
	live_maps--;
}
static void kfree(void *p)
{
	/* ... and fetches the descriptor until then. */
	assert(!job.outstanding);
	if (p) {
		assert(p == descriptor);
		free(p);
		descriptor = NULL;
	}
}

/* The descriptor, as the generator built it. */
static struct command { u32 word; dma_addr_t ptr; u32 len; } commands[8];
static unsigned command_count, descriptor_words;
static void record(u32 word, dma_addr_t ptr, u32 len, unsigned words)
{
	assert(command_count < ARRAY_SIZE(commands));
	commands[command_count++] = (struct command){ word, ptr, len };
	descriptor_words += words;
	/* Everything appended has to fit the buffer allocated for it. */
	assert(descriptor_words * sizeof(u32) <= descriptor_size);
}
static void init_job_desc(u32 *const desc, u32 options)
{
	assert(desc == descriptor && !options);
	command_count = descriptor_words = 0;
	record(CMD_DESC_HDR, 0, 0, 1);
}
static void append_key(u32 *const desc, dma_addr_t ptr, unsigned int len, u32 options)
{
	assert(desc == descriptor);
	record(CMD_KEY | options, ptr, len, 1 + sizeof(dma_addr_t) / sizeof(u32));
}
static void append_operation(u32 *const desc, u32 options)
{
	assert(desc == descriptor);
	record(CMD_OPERATION | options, 0, 0, 1);
}
static void append_fifo_load_as_imm(u32 *const desc, const void *data, int len, u32 options)
{
	assert(desc == descriptor && !data && !len);
	record(CMD_FIFO_LOAD | options, 0, 0, 1);
}
static void append_fifo_store(u32 *const desc, dma_addr_t ptr, unsigned int len, u32 options)
{
	assert(desc == descriptor);
	record(CMD_FIFO_STORE | options, ptr, len, 1 + sizeof(dma_addr_t) / sizeof(u32));
}
static u32 *append_jump(u32 *const desc, u32 options)
{
	assert(desc == descriptor);
	record(CMD_JUMP | options, 0, 0, 1);
	return desc;
}
#define CAAM_CMD_SZ sizeof(u32)
#define CAAM_PTR_SZ sizeof(dma_addr_t)

static int caam_jr_enqueue(struct device *dev, u32 *desc,
			   void (*cbk)(struct device *, u32 *, u32, void *), void *areq)
{
	assert(dev == &ring && desc == descriptor);
	jobs++;
	if (ring_answer == RING_FULL)
		return -ENOSPC;
	if (ring_answer == RING_UNMAPPABLE)
		return -EIO;
	assert(!job.outstanding);
	job.outstanding = true;
	job.desc = desc;
	job.done = cbk;
	job.arg = areq;
	return -EINPROGRESS;
}

/* The kernel's completion, reduced to what a single waiter needs. */
struct completion { bool done; };
static void init_completion(struct completion *c) { c->done = false; }
static void complete(struct completion *c) { c->done = true; }
/* SEC's error reporter: every status it is handed is an error. */
#define EBADMSG 74
static int caam_jr_strstatus(struct device *dev, u32 status)
{
	assert(dev == &ring && status);
	return (status & JRSTA_SSRC_MASK) == JRSTA_SSRC_CCB_ERROR ? -EBADMSG : -EINVAL;
}

/* SEC runs the job when the generator waits for it: a job the fault knob
 * armed halts at its first command with the user status it carries, and any
 * other ends with the status the case chose. A successful one stores the
 * whole split key; a failed one may have stored part of it before it
 * stopped, and here always has. */
#define JUMP_TYPE_MASK (0x03 << JUMP_TYPE_SHIFT)
static bool halts(u32 word)
{
	return (word & CMD_MASK) == (u32)CMD_JUMP &&
	       (word & JUMP_TYPE_MASK) == (u32)JUMP_TYPE_HALT_USER;
}
static void sec_runs(void)
{
	u32 status = sec_status;
	unsigned i;

	assert(job.outstanding);
	if (halts(commands[1].word))
		status = JRSTA_SSRC_JUMP_HALT_USER | (commands[1].word & JUMP_OFFSET_MASK);
	else
		for (i = 0; i < command_count; i++)
			if ((commands[i].word & CMD_MASK) == (u32)CMD_FIFO_STORE)
				memset((void *)(uintptr_t)commands[i].ptr, 0xb1,
				       status ? commands[i].len / 2 : commands[i].len);
	job.outstanding = false;
	job.done(&ring, job.desc, status, job.arg);
}
static void wait_for_completion(struct completion *c)
{
	waits++;
	/* Waiting for a job the ring never took would never return. */
	assert(job.outstanding);
	sec_runs();
	assert(c->done);
}

/* The fault knob's countdown, as the kernel's atomic_t would keep it. */
typedef struct { int counter; } atomic_t;
#define ATOMIC_INIT(i) { (i) }
static int atomic_dec_if_positive(atomic_t *v)
{
	int dec = v->counter - 1;

	if (dec >= 0)
		v->counter = dec;
	return dec;
}

/* The cipher half is not this harness's. */
static unsigned cipher_keys;
static int M_ipsec_sa_set_cipher_key(PSAEntry sa, U16 alg, U16 bits, U8 *key)
{
	(void)sa; (void)alg; (void)bits; (void)key;
	cipher_keys++;
	return 0;
}

#include "ipsec_keys_production.inc"

static u8 auth_key[256], split_key[256];
static DpaSecSAContext context = {
	.auth_data = { .auth_key = auth_key, .split_key = split_key },
};
static SAEntry entry = { .pSec_sa_context = &context };

/* A context as the cache create leaves it, and a ring that works. */
static void fresh(void)
{
	memset(auth_key, 0, sizeof(auth_key));
	memset(split_key, 0, sizeof(split_key));
	context.auth_data.auth_type = 0xffff;
	context.auth_data.auth_key_len = 0;
	context.auth_data.split_key_len = context.auth_data.split_key_pad_len = 0xdead;
	cipher_keys = jobs = waits = 0;
	maps = 0;
	fail_map_at = -1;
	fail_kmalloc = false;
	ring_answer = RING_ACCEPTS;
	sec_status = 0;
	jrdev_g = &ring;
}

/* Every job that was built is gone again: freed, unmapped, not in flight. */
static void settled(void)
{
	assert(!job.outstanding && !descriptor && !live_maps);
}

static void auth_spec(struct cdx_ipsec_sa_spec *spec, u8 alg, u16 icv_bits, u16 key_bits)
{
	unsigned b;

	memset(spec, 0, sizeof(*spec));
	spec->auth.alg = alg;
	spec->auth.icv_bits = icv_bits;
	spec->auth.bits = key_bits;
	for (b = 0; b < key_bits / 8u; b++)
		spec->auth.key[b] = (u8)(0x40 + b);
}

/* Every pair SEC has, each with a key whose length is not the ICV's, so a
 * setter that took one length for the other selects another operation, or
 * none, or copies a key of the wrong length. The operation codes are SEC RM
 * table 7-54's and the split-key lengths the MDHA pads' (twice the running
 * digest), not the code's. */
static void test_admitted(void)
{
	static const struct {
		u8 alg;
		u16 icv_bits, key_bits;
		U16 op;
		u32 mdha, split;
	} cases[] = {
		{ SADB_AALG_MD5HMAC, 96, 128, 0x01, OP_ALG_ALGSEL_MD5, 32 },
		{ SADB_AALG_MD5HMAC, 128, 160, 0x06, OP_ALG_ALGSEL_MD5, 32 },
		{ SADB_AALG_SHA1HMAC, 96, 160, 0x02, OP_ALG_ALGSEL_SHA1, 40 },
		{ SADB_AALG_SHA1HMAC, 160, 128, 0x07, OP_ALG_ALGSEL_SHA1, 40 },
		{ SADB_X_AALG_SHA2_256HMAC, 128, 256, 0x0c, OP_ALG_ALGSEL_SHA256, 64 },
		{ SADB_X_AALG_SHA2_384HMAC, 192, 384, 0x0d, OP_ALG_ALGSEL_SHA384, 128 },
		{ SADB_X_AALG_SHA2_512HMAC, 256, 512, 0x0e, OP_ALG_ALGSEL_SHA512, 128 },
		/* XCBC derives its keys inside the operation, and null
		 * authentication has none: neither runs a job. */
		{ SADB_X_AALG_AES_XCBC_MAC, 96, 128, 0x05, 0, 0 },
		{ SADB_X_AALG_NULL, 0, 0, 0x00, 0, 0 },
	};
	struct netlink_ext_ack ack;
	struct cdx_ipsec_sa_spec spec;
	unsigned i;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		fresh();
		auth_spec(&spec, cases[i].alg, cases[i].icv_bits, cases[i].key_bits);
		ack._msg = NULL;
		assert(cdx_ipsec_set_keys(&entry, &spec, &ack) == 0 && !ack._msg);
		assert(context.auth_data.auth_type == cases[i].op);
		assert(context.auth_data.auth_key_len == cases[i].key_bits / 8u);
		assert(!memcmp(auth_key, spec.auth.key, cases[i].key_bits / 8));
		assert(cipher_keys == 0);
		settled();
		if (!cases[i].split) {
			assert(jobs == 0 && waits == 0);
			continue;
		}
		/* One job, waited for, that loads the key into class 2, runs
		 * the HMAC's MDHA initialisation and stores the split key --
		 * as long as the MDHA pads -- into the buffer the shared
		 * descriptor loads it from. */
		assert(jobs == 1 && waits == 1);
		assert(command_count == 5);
		assert(commands[1].word == (CMD_KEY | CLASS_2 | KEY_DEST_CLASS_REG));
		assert(commands[1].ptr == (uintptr_t)auth_key &&
		       commands[1].len == cases[i].key_bits / 8u);
		assert((commands[2].word & OP_ALG_ALGSEL_MASK) == cases[i].mdha);
		assert(commands[4].ptr == (uintptr_t)split_key && commands[4].len == cases[i].split);
		assert(context.auth_data.split_key_len == cases[i].split);
		assert(context.auth_data.split_key_pad_len == ALIGN(cases[i].split, 16u));
		assert(split_key[0] == 0xb1 && split_key[cases[i].split - 1] == 0xb1 &&
		       !split_key[cases[i].split]);
	}
}

/* A truncation SEC has no operation for leaves the context as it was: no
 * operation, no key, no job -- and is the one refusal that does not blame
 * the split key. */
static void test_refused(void)
{
	struct netlink_ext_ack ack = { NULL };
	struct cdx_ipsec_sa_spec spec;

	fresh();
	auth_spec(&spec, SADB_X_AALG_SHA2_256HMAC, 96, 256);
	assert(cdx_ipsec_set_keys(&entry, &spec, &ack) == -EOPNOTSUPP && !ack._msg);
	assert(context.auth_data.auth_type == 0xffff);
	assert(context.auth_data.auth_key_len == 0 && !auth_key[0]);
	assert(jobs == 0 && cipher_keys == 0);
	settled();
}

/* Every way the split key can fail to be derived fails the SA with its own
 * errno and says why, and leaves an SA with no authenticator and no split key
 * rather than one whose frames would carry a key SEC never wrote. */
static void failed(int expected, unsigned expected_jobs, unsigned expected_waits)
{
	struct netlink_ext_ack ack = { NULL };
	struct cdx_ipsec_sa_spec spec;

	auth_spec(&spec, SADB_X_AALG_SHA2_256HMAC, 128, 256);
	assert(cdx_ipsec_set_keys(&entry, &spec, &ack) == expected);
	assert(ack._msg && !strcmp(ack._msg, "cdx: SEC could not derive the HMAC split key"));
	assert(jobs == expected_jobs && waits == expected_waits);
	assert(context.auth_data.auth_type == 0x00);	/* OP_PCL_IPSEC_HMAC_NULL */
	assert(context.auth_data.auth_key_len == 0);
	assert(!auth_key[0] && !auth_key[31]);
	assert(!context.auth_data.split_key_len && !context.auth_data.split_key_pad_len);
	/* Nothing of a split key survives, even the part a failed job stored. */
	for (unsigned i = 0; i < sizeof(split_key); i++)
		assert(!split_key[i]);
	assert(cipher_keys == 0);
	settled();
}

static void test_failures(void)
{
	/* The ring had no room: nothing was queued, so nothing is waited
	 * for, and the ring is busy rather than the SA unsupported. */
	fresh();
	ring_answer = RING_FULL;
	failed(-EBUSY, 1, 0);
	/* The ring could not map the descriptor. */
	fresh();
	ring_answer = RING_UNMAPPABLE;
	failed(-ENOMEM, 1, 0);
	/* SEC ran the job and failed it: its status is reported, and the job
	 * is waited for to the end before anything it uses is released. */
	fresh();
	sec_status = JRSTA_SSRC_CCB_ERROR | 0x11;
	failed(-EIO, 1, 1);
	fresh();
	sec_status = JRSTA_SSRC_DECO | 0x80;
	failed(-EIO, 1, 1);
	/* No descriptor, and no mapping for the key or for the split key. */
	fresh();
	fail_kmalloc = true;
	failed(-ENOMEM, 0, 0);
	fresh();
	fail_map_at = 0;
	failed(-ENOMEM, 0, 0);
	fresh();
	fail_map_at = 1;
	failed(-ENOMEM, 0, 0);
	/* No job ring at all. */
	fresh();
	jrdev_g = NULL;
	failed(-ENODEV, 0, 0);
}

/* The test image's fault knob fails exactly as many jobs as it was armed
 * for, on SEC and through the same completion a real failure takes: the job
 * halts at its first command with the knob's status. */
static void test_fault_knob(void)
{
	struct netlink_ext_ack ack = { NULL };
	struct cdx_ipsec_sa_spec spec;

	split_key_fail_countdown.counter = 2;
	fresh();
	failed(-EIO, 1, 1);
	assert(commands[1].word == (u32)(CMD_JUMP | JUMP_TYPE_HALT_USER | JUMP_TEST_ALL |
					 CDX_SPLIT_KEY_FAULT_STATUS));
	assert(split_key_fail_countdown.counter == 1);
	fresh();
	failed(-EIO, 1, 1);
	assert(split_key_fail_countdown.counter == 0);
	fresh();
	auth_spec(&spec, SADB_X_AALG_SHA2_256HMAC, 128, 256);
	assert(cdx_ipsec_set_keys(&entry, &spec, &ack) == 0 && !ack._msg);
	assert(context.auth_data.split_key_len == 64 && split_key[0] == 0xb1);
	assert(split_key_fail_countdown.counter == 0);
	settled();
}

int main(void)
{
	test_admitted();
	test_refused();
	test_failures();
	test_fault_knob();
	printf("ipsec keys: ok\n");
	return 0;
}
