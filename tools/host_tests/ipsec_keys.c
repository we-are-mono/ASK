/* The keys an SA is programmed with, compiled from cdx/cdx_ipsec_backend.c and
 * cdx/control_ipsec.c: what the backend hands the key setter from a spec, and
 * what the setter leaves in the SEC context -- the authenticator's protocol
 * operation, its key and the key's length.
 *
 * SEC runs that operation on every frame and fixes the ICV in it. The ICV's
 * length and the key's arrive as two adjacent integers, so a setter that took
 * one for the other would compile, install, and fail every frame the SA
 * carried; the cases below are chosen so that any such swap shows.
 */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
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

#define ETH_ALEN 6
#define EOPNOTSUPP 95
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define DPA_ERROR(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)

union nf_inet_addr {
	u32 all[4];
	__be32 ip;
	__be32 ip6[4];
};
struct net_device;

/* PF_KEY's numbers from the kernel, SEC's operation codes and the key bound
 * from cdx, and the backend's own description of an SA. */
#include "ipsec_keys_types.inc"

/* The SA as far as its keys go. */
typedef struct {
	struct cipher_params cipher_data;
	struct auth_params auth_data;
} DpaSecSAContext, *PDpaSecSAContext;
typedef struct {
	PDpaSecSAContext pSec_sa_context;
} SAEntry, *PSAEntry;

/* The split key is SEC's to derive; here it only records that it was asked,
 * and for which key. */
static unsigned split_keys;
static int cdx_ipsec_generate_split_key(struct auth_params *auth)
{
	assert(auth->auth_key_len);
	split_keys++;
	return 0;
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

/* A context as the cache create leaves it: no authentication yet. */
static void fresh(void)
{
	memset(auth_key, 0, sizeof(auth_key));
	context.auth_data.auth_type = 0xffff;
	context.auth_data.auth_key_len = 0;
	split_keys = cipher_keys = 0;
}

/* Every pair SEC has, each with a key whose length is not the ICV's, so a
 * setter that took one length for the other selects another operation, or
 * none, or copies a key of the wrong length. The operation codes are SEC RM
 * table 7-54's, not the code's. */
static void test_admitted(void)
{
	static const struct {
		u8 alg;
		u16 icv_bits, key_bits;
		U16 op;
		bool split;
	} cases[] = {
		{ SADB_AALG_MD5HMAC, 96, 128, 0x01, true },
		{ SADB_AALG_MD5HMAC, 128, 160, 0x06, true },
		{ SADB_AALG_SHA1HMAC, 96, 160, 0x02, true },
		{ SADB_AALG_SHA1HMAC, 160, 128, 0x07, true },
		{ SADB_X_AALG_SHA2_256HMAC, 128, 256, 0x0c, true },
		{ SADB_X_AALG_SHA2_384HMAC, 192, 384, 0x0d, true },
		{ SADB_X_AALG_SHA2_512HMAC, 256, 512, 0x0e, true },
		/* XCBC derives its keys inside the operation, and null
		 * authentication has none: neither has a split key. */
		{ SADB_X_AALG_AES_XCBC_MAC, 96, 128, 0x05, false },
		{ SADB_X_AALG_NULL, 0, 0, 0x00, false },
	};
	struct cdx_ipsec_sa_spec spec;
	unsigned i, b;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		fresh();
		memset(&spec, 0, sizeof(spec));
		spec.auth.alg = cases[i].alg;
		spec.auth.icv_bits = cases[i].icv_bits;
		spec.auth.bits = cases[i].key_bits;
		for (b = 0; b < cases[i].key_bits / 8; b++)
			spec.auth.key[b] = (u8)(0x40 + b);
		assert(cdx_ipsec_set_keys(&entry, &spec) == 0);
		assert(context.auth_data.auth_type == cases[i].op);
		assert(context.auth_data.auth_key_len == cases[i].key_bits / 8u);
		assert(!memcmp(auth_key, spec.auth.key, cases[i].key_bits / 8));
		assert(split_keys == (cases[i].split ? 1u : 0u));
		assert(cipher_keys == 0);
	}
}

/* A truncation SEC has no operation for leaves the context as it was: no
 * operation, no key, no split key. */
static void test_refused(void)
{
	struct cdx_ipsec_sa_spec spec;

	fresh();
	memset(&spec, 0, sizeof(spec));
	spec.auth.alg = SADB_X_AALG_SHA2_256HMAC;
	spec.auth.icv_bits = 96;
	spec.auth.bits = 256;
	memset(spec.auth.key, 0x5a, 32);
	assert(cdx_ipsec_set_keys(&entry, &spec) == -EOPNOTSUPP);
	assert(context.auth_data.auth_type == 0xffff);
	assert(context.auth_data.auth_key_len == 0 && !auth_key[0]);
	assert(split_keys == 0 && cipher_keys == 0);
}

int main(void)
{
	test_admitted();
	test_refused();
	printf("ipsec keys: ok\n");
	return 0;
}
