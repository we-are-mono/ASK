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
	int seen = 0, optional = 0;

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
		else if (!strcmp(key, "entries"))        { b->entries = v; optional |= 1; }
		else if (!strcmp(key, "handle_refs"))    { b->handle_refs = v; seen |= 2; }
		else if (!strcmp(key, "neighbour_refs")) { b->neighbour_refs = v; seen |= 4; }
		else if (!strcmp(key, "quarantine"))     { b->quarantine = v; seen |= 8; }
		else if (!strcmp(key, "fatal"))          { b->fatal = v; seen |= 16; }
		else if (!strcmp(key, "bypassed"))       { b->bypassed = v; optional |= 512; }
		else if (!strcmp(key, "restarts"))       { b->restarts = v; optional |= 2; }
		else if (!strcmp(key, "resume_failures")) { b->resume_failures = v; optional |= 4; }
		else if (!strcmp(key, "observe"))        { b->observe = v; seen |= 32; }
		else if (!strcmp(key, "invalidated"))    { b->invalidated = v; seen |= 64; }
		else if (!strcmp(key, "installs"))       { b->installs = v; optional |= 8; }
		else if (!strcmp(key, "deletes"))        { b->deletes = v; optional |= 16; }
		else if (!strcmp(key, "rearms"))         { b->rearms = v; optional |= 32; }
		else if (!strcmp(key, "errors"))         { b->errors = v; optional |= 64; }
		else if (!strcmp(key, "qos_mark_mask"))  { b->qos_mark_mask = (uint32_t)strtoul(sval, NULL, 0); optional |= 128; }
		else if (!strcmp(key, "route_mark_mask")) { b->route_mark_mask = (uint32_t)strtoul(sval, NULL, 0); optional |= 256; }
		else if (!strcmp(key, "mcast_enabled"))    { b->mcast_enabled = v; seen |= 128; }
		else if (!strcmp(key, "mcast_installed"))  { b->mcast_installed = v; seen |= 256; }
		else if (!strcmp(key, "mroute_installed")) { b->mroute_installed = v; seen |= 512; }
		/* Once every key read here is in, stop: the rows after the
		 * counters are each buffer a hold of the datapath's transaction
		 * of its own, and thousands of bridged pairs made the health
		 * probe take it hundreds of times (A312). An adapter that prints
		 * a key fewer is read to the end, as before. */
		if (seen == 1023 && optional == 1023)
			break;
	}
	int error = ferror(f);
	fclose(f);
	if (error || seen != 1023) {
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
		"\"fatal\": %ld, \"bypassed\": %ld, \"restarts\": %ld, "
		"\"resume_failures\": %ld, \"invalidated\": %ld, \"observe\": %ld, "
		"\"mcast_enabled\": %ld, \"mcast_installed\": %ld, \"mroute_installed\": %ld}",
		b->present ? "true" : "false", b->bindings, b->entries,
		b->handle_refs, b->neighbour_refs, b->quarantine,
		b->installs, b->deletes, b->rearms, b->errors,
		b->fatal, b->bypassed, b->restarts, b->resume_failures,
		b->invalidated, b->observe,
		b->mcast_enabled, b->mcast_installed, b->mroute_installed);
}

int ft_backend_multicast(struct ft_ctx *ctx, bool on)
{
	FILE *f = fopen(FT_MULTICAST, "w");
	int error;

	if (!f) {
		if (errno == ENOENT)
			return 0;   /* adapter not loaded: nothing is accelerated */
		snprintf(ctx->err, sizeof(ctx->err), "cannot switch multicast acceleration: %s",
			 strerror(errno));
		return -1;
	}
	error = fputs(on ? "Y\n" : "N\n", f) < 0;
	error |= fclose(f) != 0;
	if (error) {
		snprintf(ctx->err, sizeof(ctx->err), "cannot switch multicast acceleration: %s",
			 strerror(errno));
		return -1;
	}
	return 0;
}

int ft_backend_drain(struct ft_ctx *ctx, int timeout_ms, bool multicast)
{
	long deadline = now_ms() + timeout_ms;
	for (;;) {
		struct ft_backend b;
		if (ft_backend_read(ctx, &b))
			return -1;
		if (!b.present)
			return 0;
		/* A latch CDX is restarting the datapath after is waited out like
		 * any other drain: nothing drained under it is final until the
		 * classifier runs again. */
		if (!b.fatal && !b.bindings && !b.entries && !b.handle_refs &&
		    !b.neighbour_refs && !b.quarantine &&
		    (!multicast || (!b.mcast_installed && !b.mroute_installed)))
			return 0;
		if (now_ms() >= deadline) {
			if (b.fatal) {
				snprintf(ctx->err, sizeof(ctx->err),
					 "datapath restarting after an unproven deletion");
				return FT_RESTARTING;
			}
			snprintf(ctx->err, sizeof(ctx->err),
				 "old hardware or bindings have not drained; no replacement policy installed");
			return -1;
		}
		struct timespec ts = { 0, 50 * 1000000 };
		nanosleep(&ts, NULL);
	}
}
