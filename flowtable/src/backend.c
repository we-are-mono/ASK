/* /proc/cdx_flowtable header parsing + the drain wait. SPDX-License-Identifier: GPL-2.0+ */
#include "runtime.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>

static long now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

bool ft_cdx_present(void)
{
	return !access(FT_CDX_MODULE, F_OK);
}

int ft_backend_read(struct ft_ctx *ctx, struct ft_backend *b)
{
	FILE *f = fopen(FT_PROC, "r");
	char line[256];
	int seen = 0;

	memset(b, 0, sizeof(*b));
	if (!f) {
		if (errno == ENOENT)
			return 0;   /* adapter not loaded */
		snprintf(ctx->err, sizeof(ctx->err), "cannot read backend diagnostics: %s", strerror(errno));
		return -1;
	}
	b->present = true;
	while (fgets(line, sizeof(line), f)) {
		char key[64]; char sval[64]; long v;
		/* The per-flow dump follows the header; stop at it. */
		if (!strncmp(line, "flow ", 5))
			break;
		if (sscanf(line, "%63s %63s", key, sval) != 2)
			continue;
		v = strtol(sval, NULL, 0);
		if      (!strcmp(key, "bindings"))       { b->bindings = v; seen |= 1; }
		else if (!strcmp(key, "entries"))        { b->entries = v; }
		else if (!strcmp(key, "handle_refs"))    { b->handle_refs = v; seen |= 2; }
		else if (!strcmp(key, "neighbour_refs")) { b->neighbour_refs = v; seen |= 4; }
		else if (!strcmp(key, "quarantine"))     { b->quarantine = v; seen |= 8; }
		else if (!strcmp(key, "fatal"))          { b->fatal = v; seen |= 16; }
		else if (!strcmp(key, "observe"))        { b->observe = v; seen |= 32; }
		else if (!strcmp(key, "invalidated"))    { b->invalidated = v; seen |= 64; }
		else if (!strcmp(key, "installs"))       { b->installs = v; }
		else if (!strcmp(key, "deletes"))        { b->deletes = v; }
		else if (!strcmp(key, "rearms"))         { b->rearms = v; }
		else if (!strcmp(key, "errors"))         { b->errors = v; }
		else if (!strcmp(key, "qos_mark_mask"))  { b->qos_mark_mask = (uint32_t)strtoul(sval, NULL, 0); }
	}
	int error = ferror(f);
	fclose(f);
	if (error || seen != 127) {
		snprintf(ctx->err, sizeof(ctx->err), "incomplete backend diagnostics");
		return -1;
	}
	return 0;
}

int ft_backend_json(const struct ft_backend *b, char *buf, size_t n)
{
	return snprintf(buf, n,
		"{\"present\": %s, \"bindings\": %ld, \"entries\": %ld, "
		"\"handle_refs\": %ld, \"neighbour_refs\": %ld, \"quarantine\": %ld, "
		"\"installs\": %ld, \"deletes\": %ld, \"rearms\": %ld, \"errors\": %ld, "
		"\"fatal\": %ld, \"invalidated\": %ld, \"observe\": %ld}",
		b->present ? "true" : "false", b->bindings, b->entries,
		b->handle_refs, b->neighbour_refs, b->quarantine,
		b->installs, b->deletes, b->rearms, b->errors,
		b->fatal, b->invalidated, b->observe);
}

int ft_backend_drain(struct ft_ctx *ctx, int timeout_ms)
{
	long deadline = now_ms() + timeout_ms;
	for (;;) {
		struct ft_backend b;
		if (ft_backend_read(ctx, &b))
			return -1;
		if (!b.present)
			return 0;
		if (b.fatal) {
			snprintf(ctx->err, sizeof(ctx->err),
				 "hardware retirement failed; full teardown and fresh boot required");
			return -1;
		}
		if (!b.bindings && !b.entries && !b.handle_refs && !b.neighbour_refs && !b.quarantine)
			return 0;
		if (now_ms() >= deadline) {
			snprintf(ctx->err, sizeof(ctx->err),
				 "old hardware or bindings have not drained; no replacement policy installed");
			return -1;
		}
		struct timespec ts = { 0, 50 * 1000000 };
		nanosleep(&ts, NULL);
	}
}
