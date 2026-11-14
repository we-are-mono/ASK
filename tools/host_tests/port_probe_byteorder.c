/* nftables' byteorder expression as the port probe models it, against the
 * expression itself, both compiled from the kernel: nft_probe_byteorder() on a
 * register file whose bits are partly known, and nft_byteorder_eval() on the
 * registers of a packet that agrees with every known bit. Whatever the probe
 * calls known must be what the expression leaves there -- on every operation,
 * size and register pair, whatever the registers held before -- and a result
 * whose source was known is known whole, the rest of a 16-bit result's
 * register included, which the expression clears. */
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef uint16_t __be16;
typedef uint32_t __be32;
typedef uint64_t __be64;

#define __force
#define NFT_REG32_SIZE 4
#define NFT_REG32_NUM 20
#define be64_to_cpu(x) __builtin_bswap64(x)
#define cpu_to_be64(x) __builtin_bswap64(x)
#define get_unaligned(p) ({ u64 __v; memcpy(&__v, (p), sizeof(__v)); __v; })
#define put_unaligned(v, p) ({ u64 __v = (v); memcpy((p), &__v, sizeof(__v)); })

/* The board, like the host, is little-endian. */
_Static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "little-endian host");

#include "byteorder_types.inc"

/* The expression's private data is all of it here. */
struct nft_expr {
	struct nft_byteorder priv;
};
static void *nft_expr_priv(const struct nft_expr *expr)
{
	return (void *)&expr->priv;
}
struct nft_regs {
	u32 data[NFT_REG32_NUM];
};
struct nft_pktinfo;
/* What the probe's byteorder step reads of its context. */
struct nft_probe_ctx {
	int stop;
	struct nft_probe_regs regs;
};

#include "byteorder_production.inc"

static u64 seed = 0x9e3779b97f4a7c15ull;
static u32 rnd(void)
{
	seed ^= seed << 13;
	seed ^= seed >> 7;
	seed ^= seed << 17;
	return (u32)(seed >> 16);
}

/* Each byte of a register wholly known, wholly unknown, or partly known, as
 * a payload load, a mask and an immediate leave them. */
static u32 rnd_known(void)
{
	u32 known = 0;

	for (int b = 0; b < 4; b++) {
		u32 byte;

		switch (rnd() % 3) {
		case 0:
			byte = 0;
			break;
		case 1:
			byte = 0xff;
			break;
		default:
			byte = rnd() & 0xff;
			break;
		}
		known |= byte << (8 * b);
	}
	return known;
}

int main(void)
{
	static const u8 sizes[] = { 2, 4, 8 };
	unsigned int cleared = 0;

	for (unsigned int n = 0; n < 200000; n++) {
		struct nft_probe_ctx ctx = { 0 };
		struct nft_expr expr = { 0 };
		struct nft_byteorder *priv = &expr.priv;
		struct nft_regs regs;
		unsigned int words, last;
		bool whole = true;

		priv->size = sizes[rnd() % 3];
		priv->op = rnd() % 2 ? NFT_BYTEORDER_HTON : NFT_BYTEORDER_NTOH;
		words = (priv->size + 3) / 4;
		last = NFT_REG32_NUM - words;
		priv->sreg = rnd() % (last + 1);
		priv->dreg = rnd() % 4 ? rnd() % (last + 1) : priv->sreg;

		for (unsigned int r = 0; r < NFT_REG32_NUM; r++) {
			ctx.regs.data[r] = rnd();
			ctx.regs.known[r] = rnd_known();
			/* A packet's registers: the known bits, anything else. */
			regs.data[r] = (ctx.regs.data[r] & ctx.regs.known[r]) |
				       (rnd() & ~ctx.regs.known[r]);
		}
		/* Sometimes the whole source is known, and the result must be. */
		if (rnd() % 2)
			memset(&ctx.regs.known[priv->sreg], 0xff,
			       words * sizeof(u32));
		for (unsigned int b = 0; b < priv->size; b++)
			if (((u8 *)&ctx.regs.known[priv->sreg])[b] != 0xff)
				whole = false;
		for (unsigned int r = 0; r < NFT_REG32_NUM; r++)
			regs.data[r] = (ctx.regs.data[r] & ctx.regs.known[r]) |
				       (regs.data[r] & ~ctx.regs.known[r]);

		assert(nft_probe_byteorder(&ctx, &expr) == NFT_PROBE_MATCH);
		assert(!ctx.stop);
		nft_byteorder_eval(&expr, &regs, NULL);

		for (unsigned int r = 0; r < NFT_REG32_NUM; r++) {
			if ((regs.data[r] ^ ctx.regs.data[r]) & ctx.regs.known[r]) {
				fprintf(stderr, "size %u op %u sreg %u dreg %u: register %u "
					"is %08x, the probe knows %08x of %08x\n",
					priv->size, priv->op, priv->sreg, priv->dreg, r,
					regs.data[r], ctx.regs.known[r], ctx.regs.data[r]);
				assert(!"the probe knows a bit the expression did not leave");
			}
		}
		if (whole) {
			for (unsigned int w = 0; w < words; w++)
				assert(ctx.regs.known[priv->dreg + w] == ~0u);
			if (priv->size == 2) {
				assert(!(ctx.regs.data[priv->dreg] >> 16));
				cleared++;
			}
		}
	}
	assert(cleared);
	printf("port probe byteorder checks passed\n");
	return 0;
}
