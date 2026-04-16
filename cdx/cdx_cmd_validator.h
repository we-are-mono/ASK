/*
 *  Copyright 2026 Mono Gateway
 *
 * SPDX-License-Identifier:    GPL-2.0+
 */

/*
 * cdx_cmd_validator - table-driven FCI command dispatch with
 * centralized length and semantic validation.
 *
 * Intent (A1 in ISSUES.md):
 *   Each per-subsystem M_*_cmdproc in control_*.c currently takes
 *   (cmd_code, cmd_len, pcmd) and does its own switch(cmd_code)
 *   plus inline length and field checks. That's error-prone: the
 *   missing check from one case leaks into the next, and reviewers
 *   can't see trust boundaries at a glance.
 *
 *   With this header, a subsystem declares one
 *   `const struct cdx_cmd_spec table[]` describing each supported
 *   command (expected length, optional semantic validator,
 *   handler function pointer), and its M_*_cmdproc becomes a
 *   one-line tail call to cdx_dispatch_cmd(). The dispatcher
 *   centralizes:
 *     - cmd_code lookup and ERR_UNKNOWN_COMMAND on miss,
 *     - length check against an exact or [min, max] byte range
 *       with ERR_WRONG_COMMAND_SIZE on mismatch,
 *     - optional semantic field validation before the handler,
 *     - stamping rbuf[0] with the handler's status,
 *     - defaulting reply_len to sizeof(U16) when the handler
 *       doesn't produce a trailing payload.
 *
 * Handler ABI:
 *   The FCI ABI (see cdx_cmdhandler.h, typedef CmdProc) hands a
 *   subsystem dispatcher a U16 *rbuf that already holds the input
 *   command. The dispatcher may mutate it in place as the reply;
 *   userspace reads rbuf[0] as the status word followed by
 *   (retlen - 2) bytes of payload. Handlers below keep the same
 *   shape: just return the status U16 (the dispatcher stamps it
 *   into pcmd[0] AFTER the handler returns), write any reply
 *   payload into pcmd, and update *out_reply_len to the total
 *   bytes including the status word.
 *
 *   CRITICAL: pcmd is IN/OUT, and the status word is stamped
 *   AFTER the handler runs. A handler that writes reply bytes
 *   into pcmd before it has read all the input fields it needs
 *   will see its own output on the subsequent read. The rule:
 *   extract every input field first (snapshot it, or do all
 *   reads up-front), then build the reply. See the VLAN example
 *   below - vlan_entry_handle reads `action = *(U16 *)pcmd`
 *   before calling the inner functions that may overwrite pcmd
 *   with the query response.
 *
 * Typical usage (pseudocode for control_vlan.c):
 *
 *     static U16 vlan_entry_handle(void *pcmd, U16 cmd_len, U16 *reply_len);
 *     static U16 vlan_reset_handle(void *pcmd, U16 cmd_len, U16 *reply_len);
 *
 *     static const struct cdx_cmd_spec vlan_cmd_table[] = {
 *         CDX_CMD  (CMD_VLAN_ENTRY,       VlanCommand, vlan_entry_handle),
 *         CDX_CMD_NOARG(CMD_VLAN_ENTRY_RESET,         vlan_reset_handle),
 *     };
 *
 *     static U16 M_vlan_cmdproc(U16 cmd_code, U16 cmd_len, U16 *pcmd)
 *     {
 *         return cdx_dispatch_cmd(vlan_cmd_table,
 *                                 ARRAY_SIZE(vlan_cmd_table),
 *                                 cmd_code, cmd_len, pcmd);
 *     }
 */
#ifndef _CDX_CMD_VALIDATOR_H_
#define _CDX_CMD_VALIDATOR_H_

#include "types.h"

/*
 * Semantic validator. Runs after the dispatcher has length-checked
 * the incoming buffer against the spec's [min_len, max_len] range.
 * Returns NO_ERR on success or an FCI error code. May read pcmd
 * and cmd_len; must not mutate them.
 */
typedef U16 (*cdx_cmd_validate_fn)(const void *pcmd, U16 cmd_len);

/*
 * Command handler. Called only after length check and validate
 * (if any) have passed.
 *
 *   pcmd          - in/out buffer. Holds the incoming command on
 *                   entry; may be mutated in place as the reply
 *                   payload. The dispatcher stamps pcmd[0] with
 *                   the handler's return value AFTER the handler
 *                   returns, so any input fields anywhere in the
 *                   buffer must be read BEFORE the handler writes
 *                   its reply. The safest pattern is to copy or
 *                   extract every input you need into locals at
 *                   the top of the handler, then build the reply.
 *   cmd_len       - input command length in bytes (already
 *                   validated against the spec).
 *   out_reply_len - initialized by the dispatcher to sizeof(U16).
 *                   Handler may set it to the total reply length
 *                   in bytes (status word + trailing payload).
 *                   Handlers with a status-only reply leave it
 *                   alone.
 *
 * Returns NO_ERR on success or an FCI error code. The dispatcher
 * writes the return value into pcmd[0] regardless of outcome and
 * returns *out_reply_len.
 */
typedef U16 (*cdx_cmd_handle_fn)(void *pcmd, U16 cmd_len,
				 U16 *out_reply_len);

/*
 * Per-command spec entry. Tables built from these are normally
 * declared `static const` so they end up in .rodata.
 *
 * Length rules:
 *   - min_len == max_len: fixed-size command (set both to
 *     sizeof(struct ...) via CDX_CMD).
 *   - min_len <= max_len: variable-length command in the given
 *     inclusive byte range (CDX_CMD_VAR).
 *   - min_len == max_len == 0: no-argument command (CDX_CMD_NOARG).
 *
 * The dispatcher enforces cmd_len in [min_len, max_len] and
 * returns ERR_WRONG_COMMAND_SIZE if it falls outside. 0-length
 * commands must set both fields to 0.
 */
struct cdx_cmd_spec {
	U16 cmd_code;
	U16 min_len;
	U16 max_len;
	cdx_cmd_validate_fn validate;	/* NULL if no semantic check */
	cdx_cmd_handle_fn   handle;
};

/* Fixed-size command, no semantic validator. */
#define CDX_CMD(CODE, TYPE, HANDLER)					\
	{ .cmd_code = (CODE),						\
	  .min_len  = sizeof(TYPE),					\
	  .max_len  = sizeof(TYPE),					\
	  .validate = NULL,						\
	  .handle   = (HANDLER) }

/* Fixed-size command with a semantic validator. */
#define CDX_CMD_V(CODE, TYPE, VALIDATE, HANDLER)			\
	{ .cmd_code = (CODE),						\
	  .min_len  = sizeof(TYPE),					\
	  .max_len  = sizeof(TYPE),					\
	  .validate = (VALIDATE),					\
	  .handle   = (HANDLER) }

/* Variable-length command in [MIN, MAX] bytes inclusive. */
#define CDX_CMD_VAR(CODE, MIN, MAX, VALIDATE, HANDLER)			\
	{ .cmd_code = (CODE),						\
	  .min_len  = (MIN),						\
	  .max_len  = (MAX),						\
	  .validate = (VALIDATE),					\
	  .handle   = (HANDLER) }

/* No-argument command (cmd_len must equal 0). */
#define CDX_CMD_NOARG(CODE, HANDLER)					\
	{ .cmd_code = (CODE),						\
	  .min_len  = 0,						\
	  .max_len  = 0,						\
	  .validate = NULL,						\
	  .handle   = (HANDLER) }

/* No-argument command with a semantic validator (e.g. to gate on
 * module state before allowing a reset). */
#define CDX_CMD_NOARG_V(CODE, VALIDATE, HANDLER)			\
	{ .cmd_code = (CODE),						\
	  .min_len  = 0,						\
	  .max_len  = 0,						\
	  .validate = (VALIDATE),					\
	  .handle   = (HANDLER) }

/*
 * Dispatch one FCI command through the given spec table.
 *
 * Looks up cmd_code, length-checks, optionally validates, invokes
 * the handler. Writes the final status word into pcmd[0] and
 * returns the total reply length in bytes (always >= sizeof(U16)).
 *
 * The signature mirrors the CmdProc typedef in cdx_cmdhandler.h:
 * a subsystem's M_*_cmdproc can tail-call this directly.
 */
U16 cdx_dispatch_cmd(const struct cdx_cmd_spec *table, size_t n_entries,
		     U16 cmd_code, U16 cmd_len, U16 *pcmd);

#endif /* _CDX_CMD_VALIDATOR_H_ */
