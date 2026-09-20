/* Minimal SHA-256, public-domain style, for the policy ownership fingerprint.
 * Vendored to keep the daemon dependency-free (no libcrypto).
 * SPDX-License-Identifier: GPL-2.0+ */
#ifndef ASK_FLOWTABLE_SHA256_H
#define ASK_FLOWTABLE_SHA256_H

#include <stddef.h>
#include <stdint.h>

void ft_sha256(const void *data, size_t len, char out_hex[65]);

#endif
