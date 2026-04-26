/*
 * Userspace fuzz harness for cmm's RTNL attribute parser.
 *
 * Links the production cmm_parse_rtattr from cmm/src/rtnl_parse.c
 * directly — same compilation unit cmm proper uses — so a regression
 * in the parser's shape (e.g. removing the bounds check) trips ASAN
 * here. The orchestrator-side test (tools/tests/test_cmm_rtnl_fuzz.py)
 * generates malformed inputs (truncated trailing rtattrs, oversized
 * rta_len, etc.) and checks for sanitizer reports in the binary's
 * stderr.
 *
 * Build with -fsanitize=address,undefined; OOB detection is the oracle.
 *
 * Copyright (c) 2026 Mono Technologies Inc.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <linux/rtnetlink.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/rtnl_parse.h"


/* Hook implementation for the parser's overflow diagnostic — fuzzer
 * stub. The production hook in cmm/src/rtnl.c does the real cmm_print
 * call; here we just log to stderr so test cases can observe it if
 * needed. */
void cmm_parse_rtattr_overflow(const char *func, int line, int len_remaining)
{
    fprintf(stderr, "[overflow] %s:%d remaining=%d\n",
            func, line, len_remaining);
}


static int hex_decode(const char *s, uint8_t *out, size_t cap)
{
    size_t n = strlen(s);
    if (n & 1) return -1;
    if (n / 2 > cap) return -1;
    for (size_t i = 0; i < n; i += 2) {
        char b[3] = { s[i], s[i + 1], 0 };
        char *end = NULL;
        unsigned long v = strtoul(b, &end, 16);
        if (end != b + 2) return -1;
        out[i / 2] = (uint8_t)v;
    }
    return (int)(n / 2);
}


int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <hex-bytes> [max=64]\n", argv[0]);
        return 2;
    }
    int max = (argc > 2) ? atoi(argv[2]) : 64;
    if (max <= 0 || max > 4096) max = 64;

    /* Decode into a tight malloc so ASAN's redzones flag any read past
     * the populated portion. A static buffer would mask OOB reads
     * within the unused tail. */
    size_t hex_len = strlen(argv[1]);
    if (hex_len & 1) { fprintf(stderr, "bad hex input\n"); return 2; }
    size_t cap = hex_len / 2;
    if (cap > 8192) { fprintf(stderr, "input too large\n"); return 2; }
    uint8_t *buf = malloc(cap == 0 ? 1 : cap);
    if (!buf) return 2;
    int n = hex_decode(argv[1], buf, cap);
    if (n < 0) { free(buf); fprintf(stderr, "bad hex input\n"); return 2; }

    struct rtattr **tb = calloc((size_t)max + 1, sizeof(*tb));
    if (!tb) { free(buf); return 2; }

    int rc = cmm_parse_rtattr(tb, max, (struct rtattr *)buf, n);

    int found = 0;
    for (int i = 0; i <= max; i++)
        if (tb[i]) found++;

    free(tb);
    free(buf);
    printf("OK rc=%d attrs=%d\n", rc, found);
    return 0;
}
