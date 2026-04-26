/*
 * cmm_parse_rtattr — RTA walker shared between cmm proper and the
 * userspace fuzz harness. Both link this .c file directly so the
 * fuzzer exercises the *real* parser shape (ISSUES.md M14: tail
 * dereference of rta->rta_len when len != 0 reads OOB on a
 * truncated trailing rtattr).
 *
 * Logging is delegated to cmm_parse_rtattr_overflow (declared in
 * rtnl_parse.h) — cmm proper provides a cmm_print-backed
 * implementation in rtnl.c, the fuzzer provides a printf stub in
 * cmm/test/cmm_rtnl_fuzzer.c.
 *
 * Copyright (c) 2026 Mono Technologies Inc.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <linux/rtnetlink.h>
#include <string.h>

#include "rtnl_parse.h"

int cmm_parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));

	while (RTA_OK(rta, len)) {
		if (rta->rta_type <= max)
			tb[rta->rta_type] = rta;

		rta = RTA_NEXT(rta, len);
	}

	if (len)
		cmm_parse_rtattr_overflow(__func__, __LINE__, len);

	return 0;
}
