/* Minimal SHA-256 (FIPS 180-4), public-domain style. SPDX-License-Identifier: GPL-2.0+ */
#include "sha256.h"
#include <string.h>

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static const uint32_t K[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
};

static void block(uint32_t h[8], const uint8_t *p)
{
	uint32_t w[64], a, b, c, d, e, f, g, hh, t1, t2;
	int i;

	for (i = 0; i < 16; i++)
		w[i] = (uint32_t)p[i*4] << 24 | (uint32_t)p[i*4+1] << 16 |
		       (uint32_t)p[i*4+2] << 8 | (uint32_t)p[i*4+3];
	for (; i < 64; i++) {
		uint32_t s0 = ROR(w[i-15], 7) ^ ROR(w[i-15], 18) ^ (w[i-15] >> 3);
		uint32_t s1 = ROR(w[i-2], 17) ^ ROR(w[i-2], 19) ^ (w[i-2] >> 10);
		w[i] = w[i-16] + s0 + w[i-7] + s1;
	}
	a = h[0]; b = h[1]; c = h[2]; d = h[3];
	e = h[4]; f = h[5]; g = h[6]; hh = h[7];
	for (i = 0; i < 64; i++) {
		uint32_t S1 = ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25);
		uint32_t ch = (e & f) ^ (~e & g);
		t1 = hh + S1 + ch + K[i] + w[i];
		uint32_t S0 = ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22);
		uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
		t2 = S0 + maj;
		hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	}
	h[0] += a; h[1] += b; h[2] += c; h[3] += d;
	h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

void ft_sha256(const void *data, size_t len, char out_hex[65])
{
	uint32_t h[8] = { 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
			  0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 };
	const uint8_t *p = data;
	uint8_t tail[128];
	size_t i, full = len / 64, rem = len % 64;
	uint64_t bits = (uint64_t)len * 8;

	for (i = 0; i < full; i++)
		block(h, p + i * 64);

	memcpy(tail, p + full * 64, rem);
	tail[rem] = 0x80;
	size_t pad = (rem < 56) ? 64 : 128;
	memset(tail + rem + 1, 0, pad - rem - 1 - 8);
	for (i = 0; i < 8; i++)
		tail[pad - 1 - i] = (uint8_t)(bits >> (8 * i));
	for (i = 0; i < pad; i += 64)
		block(h, tail + i);

	static const char hex[] = "0123456789abcdef";
	for (i = 0; i < 8; i++) {
		out_hex[i*8+0] = hex[(h[i] >> 28) & 0xf];
		out_hex[i*8+1] = hex[(h[i] >> 24) & 0xf];
		out_hex[i*8+2] = hex[(h[i] >> 20) & 0xf];
		out_hex[i*8+3] = hex[(h[i] >> 16) & 0xf];
		out_hex[i*8+4] = hex[(h[i] >> 12) & 0xf];
		out_hex[i*8+5] = hex[(h[i] >> 8) & 0xf];
		out_hex[i*8+6] = hex[(h[i] >> 4) & 0xf];
		out_hex[i*8+7] = hex[h[i] & 0xf];
	}
	out_hex[64] = '\0';
}
