/*
 * Standalone declaration of cmm_parse_rtattr — extracted from rtnl.c so
 * the userspace fuzzer (cmm/test/cmm_rtnl_fuzzer.c) can link the
 * production parser without dragging in the rest of cmm.
 *
 * Copyright (c) 2026 Mono Technologies Inc.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef CMM_RTNL_PARSE_H
#define CMM_RTNL_PARSE_H

#include <linux/rtnetlink.h>

int cmm_parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len);

/*
 * Implementation hook for the parser's "trailing payload" diagnostic.
 *
 * cmm proper routes this to cmm_print(DEBUG_ERROR, …); the fuzzer
 * routes it to a stderr printf. The hook receives `len_remaining` only
 * — NOT a derived field of `rta`. The original implementation passed
 * `rta->rta_len` here, but `rta` may point past the input buffer when
 * the loop exits with len != 0 (truncated trailing rtattr), which made
 * the dereference an OOB read (ISSUES.md M14). Fixed by dropping that
 * parameter; nothing useful was logged from it anyway.
 */
void cmm_parse_rtattr_overflow(const char *func, int line, int len_remaining);

#endif /* CMM_RTNL_PARSE_H */
