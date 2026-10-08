/* The SEC shared descriptor an offloaded IPsec SA runs, built by
 * cdx_ipsec_build_shared_descriptor() from cdx/cdx_dpa_ipsec.c with the
 * kernel's own command encoders (desc_constr.h), then walked command by
 * command.
 *
 * A protocol OPERATION returns to the descriptor as soon as DECO has issued
 * its last output store, not once that store has drained (SEC RM 7.7.2.1:
 * blocking only from DECO's standpoint). A MOVE or MATH command that runs in
 * that window can lose the protocol's final partial output word: on the
 * board, one decrypted frame in ~10^5 left SEC with its last four bytes
 * zeroed (A328). So whatever MOVE or MATH follows the protocol must come
 * after a JUMP that waits for the output to drain (RM 7.20.3), and the
 * inbound descriptor, whose per-SA counters run after decapsulation, is
 * where that matters.
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

/* The host's stand-ins for the kernel's register accessors, then SEC's own
 * command encoders. */
#include "regs.h"
#include "desc_constr.h"

size_t caam_ptr_sz = sizeof(dma_addr_t);

typedef uint8_t U8;
typedef uint16_t U16;
typedef uint32_t U32;
typedef uint64_t U64;
typedef uint16_t __be16;

#define EINVAL 22
#define EPERM 1
#define BUG_ON(cond) assert(!(cond))
#define KERN_ERR ""

/* SEC's PDB layout, CDX's shared descriptor around it, and the SA's key
 * parameters and constants, from the sources. */
#include "ipsec_descriptor_types.inc"

typedef struct {
	struct cipher_params cipher_data;
	struct auth_params auth_data;
	struct sec_descriptor *sec_desc;
} DpaSecSAContext, *PDpaSecSAContext;

typedef struct {
	U8 mode;
	U8 direction;
	U16 stats_offset;
	PDpaSecSAContext pSec_sa_context;
} SAEntry, *PSAEntry;

uint32_t cdx_ipsec_key_tag_of(PSAEntry sa)
{
	(void)sa;
	return 2;
}

#include "ipsec_descriptor_production.inc"

/* How many words the command at w takes, for the commands the builder
 * emits. A walk that does not end exactly at the descriptor's length means
 * this table is out of date, not that the descriptor is wrong. */
static unsigned int command_words(const u32 *w)
{
	u32 word = *w, ptr = caam_ptr_sz / CAAM_CMD_SZ;

	switch (word & CMD_MASK) {
	case CMD_KEY:
		return 1 + ((word & KEY_IMM) ? ALIGN(word & KEY_LENGTH_MASK, 4) / 4 : ptr);
	case CMD_STORE:
		/* One from the descriptor buffer names no pointer (append_store()). */
		switch (word & LDST_SRCDST_MASK) {
		case LDST_SRCDST_WORD_DESCBUF_SHARED:
		case LDST_SRCDST_WORD_DESCBUF_JOB:
		case LDST_SRCDST_WORD_DESCBUF_JOB_WE:
		case LDST_SRCDST_WORD_DESCBUF_SHARED_WE:
			return 1;
		}
		/* fall through */
	case CMD_LOAD:
		return 1 + ((word & LDST_IMM) ? ALIGN(word & LDST_LEN_MASK, 4) / 4 : ptr);
	case CMD_MATH:
		return 1 + ((word & MATH_SRC0_MASK) == MATH_SRC0_IMM ||
			    (word & MATH_SRC1_MASK) == MATH_SRC1_IMM);
	case CMD_JUMP:
		/* A non-local jump carries a pointer; the builder emits none. */
		assert(((word >> JUMP_TYPE_SHIFT) & 3) != JUMP_TYPE_NONLOCAL >> JUMP_TYPE_SHIFT);
		return 1;
	case CMD_SEQ_LOAD:
	case CMD_SEQ_FIFO_STORE:
	case CMD_MOVE:
	case CMD_OPERATION:
		return 1;
	}
	fprintf(stderr, "unexpected command 0x%08x\n", word);
	abort();
}

#define DRAINED (JUMP_COND_CALM | JUMP_COND_NIP | JUMP_COND_NIFP | JUMP_COND_NOP)

static void check(const char *name, U8 direction, U16 cipher, U16 auth,
		  U32 split_key_len, U32 auth_key_len)
{
	static struct sec_descriptor sec_desc;
	DpaSecSAContext ctx = {
		.cipher_data = { .cipher_type = cipher, .cipher_key_len = 16 },
		.auth_data = { .auth_type = auth, .split_key_len = split_key_len,
			       .auth_key_len = auth_key_len },
		.sec_desc = &sec_desc,
	};
	SAEntry sa = { .mode = SA_MODE_TUNNEL, .direction = direction, .pSec_sa_context = &ctx };
	u32 *desc = sec_desc.shared_desc;
	unsigned int i, len, operations = 0, after = 0;
	bool drained = false;

	memset(&sec_desc, 0, sizeof(sec_desc));
	/* An IPv4 NAT-T outer header, which an outbound PDB carries. */
	sec_desc.pdb_en.ip_hdr_len = 28;
	assert(cdx_ipsec_build_shared_descriptor(&sa, 0x1000, 0x2000, ETH_HDR_LEN) == 0);

	len = desc_len(desc);
	for (i = (desc[0] & HDR_START_IDX_MASK) >> HDR_START_IDX_SHIFT; i < len;
	     i += command_words(&desc[i])) {
		u32 word = desc[i], type = word & CMD_MASK;

		if (type == (u32)CMD_OPERATION) {
			operations++;
			continue;
		}
		if (!operations)
			continue;
		if (type == (u32)CMD_JUMP && (word & DRAINED) == DRAINED)
			drained = true;
		if (type == (u32)CMD_MOVE || type == (u32)CMD_MATH) {
			after++;
			if (!drained) {
				fprintf(stderr, "%s: command %u (0x%08x) moves data while the protocol's output may still drain\n",
					name, i, word);
				abort();
			}
		}
	}
	assert(i == len);
	assert(operations == 1);
	/* The inbound counters do follow the protocol, so the check above saw
	 * what it is about. */
	assert(direction != CDX_DPA_IPSEC_INBOUND || after);
	printf("%s: %u words, %u moves after the protocol\n", name, len, after);
}

int main(void)
{
	check("inbound cbc", CDX_DPA_IPSEC_INBOUND, OP_PCL_IPSEC_AES_CBC,
	      OP_PCL_IPSEC_HMAC_SHA1_96, 40, 20);
	check("inbound gcm", CDX_DPA_IPSEC_INBOUND, OP_PCL_IPSEC_AES_GCM16,
	      OP_PCL_IPSEC_HMAC_NULL, 0, 0);
	check("outbound cbc", CDX_DPA_IPSEC_OUTBOUND, OP_PCL_IPSEC_AES_CBC,
	      OP_PCL_IPSEC_HMAC_SHA1_96, 40, 20);
	check("outbound gcm", CDX_DPA_IPSEC_OUTBOUND, OP_PCL_IPSEC_AES_GCM16,
	      OP_PCL_IPSEC_HMAC_NULL, 0, 0);
	return 0;
}
