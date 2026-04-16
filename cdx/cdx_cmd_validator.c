/*
 *  Copyright 2026 Mono Gateway
 *
 * SPDX-License-Identifier:    GPL-2.0+
 */

/*
 * Implementation of cdx_dispatch_cmd(). See cdx_cmd_validator.h for
 * the rationale, contract, and usage pattern.
 *
 * Concurrency: this file is stateless. All state lives in the
 * caller's spec table (const) and in the caller-provided pcmd
 * buffer. Concurrency of pcmd and of any data the handlers touch
 * is the caller's responsibility, as it was before A1a.
 */

#include "cdx.h"
#include "fe.h"
#include "cdx_cmd_validator.h"

U16 cdx_dispatch_cmd(const struct cdx_cmd_spec *table, size_t n_entries,
		     U16 cmd_code, U16 cmd_len, U16 *pcmd)
{
	const struct cdx_cmd_spec *spec = NULL;
	U16 reply_len = sizeof(U16);
	U16 rc;
	size_t i;

	/* Look up the command code in the subsystem's table. */
	for (i = 0; i < n_entries; i++) {
		if (table[i].cmd_code == cmd_code) {
			spec = &table[i];
			break;
		}
	}
	if (!spec) {
		pcmd[0] = ERR_UNKNOWN_COMMAND;
		return sizeof(U16);
	}

	/* Length check against [min_len, max_len] inclusive.
	 * An absent handler is a programming error; treat it as
	 * unknown rather than crash. */
	if (!spec->handle) {
		pcmd[0] = ERR_UNKNOWN_COMMAND;
		return sizeof(U16);
	}
	if (cmd_len < spec->min_len || cmd_len > spec->max_len) {
		pcmd[0] = ERR_WRONG_COMMAND_SIZE;
		return sizeof(U16);
	}

	/* Optional semantic validation. */
	if (spec->validate) {
		rc = spec->validate(pcmd, cmd_len);
		if (rc != NO_ERR) {
			pcmd[0] = rc;
			return sizeof(U16);
		}
	}

	/* Hand off to the real work. The handler may rewrite pcmd
	 * and bump reply_len; the dispatcher then stamps the status
	 * word into pcmd[0]. */
	rc = spec->handle(pcmd, cmd_len, &reply_len);
	pcmd[0] = rc;

	/* Defensive: clamp reply_len to at least the status word.
	 * Hitting this branch means a handler trampled reply_len
	 * below its initial value (sizeof(U16)) - a programming
	 * error, since the dispatcher pre-seeds it. Warn once and
	 * return a well-formed 2-byte reply. */
	if (reply_len < sizeof(U16)) {
		WARN_ON_ONCE(1);
		reply_len = sizeof(U16);
	}

	return reply_len;
}
