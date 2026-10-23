/* /proc/ask_flowtable status and stats parsing + the drain wait. SPDX-License-Identifier: GPL-2.0+ */
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

struct ft_key {
	const char *name;
	long *value;
};

/* One of the adapter's status or stats files: a "key: value" line each, of
 * which every key named here has to be present. A file that is not there is
 * the adapter not being loaded -- or unloading between two reads -- and
 * clears *present. */
static int ft_keys_read(struct ft_ctx *ctx, const char *path, const struct ft_key *keys,
			size_t n, bool *present)
{
	FILE *f = fopen(path, "r");
	unsigned long found = 0;
	char line[128];
	int error;

	if (!f) {
		if (errno == ENOENT) {
			*present = false;
			return 0;
		}
		snprintf(ctx->err, sizeof(ctx->err), "cannot read backend diagnostics: %s", strerror(errno));
		return -1;
	}
	while (fgets(line, sizeof(line), f)) {
		char key[64];
		long value;

		if (sscanf(line, "%63[^:]: %ld", key, &value) != 2)
			continue;
		for (size_t i = 0; i < n; i++)
			if (!strcmp(key, keys[i].name)) {
				*keys[i].value = value;
				found |= 1UL << i;
			}
	}
	error = ferror(f);
	fclose(f);
	if (error || found != (1UL << n) - 1) {
		snprintf(ctx->err, sizeof(ctx->err), "incomplete backend diagnostics");
		return -1;
	}
	return 0;
}

/* A module parameter: Y or N for a bool, a number otherwise. A parameter that
 * is not there is its module not being loaded, as above. */
static int ft_parameter_read(struct ft_ctx *ctx, const char *path, long *value, bool *present)
{
	FILE *f = fopen(path, "r");
	char text[32], *end;
	bool ok;

	if (!f) {
		if (errno == ENOENT) {
			*present = false;
			return 0;
		}
		snprintf(ctx->err, sizeof(ctx->err), "cannot read %s: %s", path, strerror(errno));
		return -1;
	}
	ok = fgets(text, sizeof(text), f) != NULL;
	fclose(f);
	if (ok && (text[0] == 'Y' || text[0] == 'N') && (text[1] == '\n' || !text[1])) {
		*value = text[0] == 'Y';
	} else if (ok) {
		errno = 0;
		*value = strtol(text, &end, 0);
		ok = end != text && (*end == '\n' || !*end) && !errno;
	}
	if (!ok) {
		snprintf(ctx->err, sizeof(ctx->err), "unreadable module parameter %s", path);
		return -1;
	}
	return 0;
}

int ft_backend_read(struct ft_ctx *ctx, struct ft_backend *b)
{
	const struct ft_key status[] = {
		{ "bindings", &b->bindings }, { "entries", &b->entries },
		{ "handle_refs", &b->handle_refs }, { "neighbour_refs", &b->neighbour_refs },
		{ "quarantine", &b->quarantine }, { "fatal", &b->fatal },
		{ "invalidated", &b->invalidated }, { "bypassed", &b->bypassed },
		{ "restarts", &b->restarts }, { "resume_failures", &b->resume_failures },
		{ "mcast_installed", &b->mcast_installed },
		{ "mroute_installed", &b->mroute_installed },
	};
	const struct ft_key stats[] = {
		{ "installs", &b->installs }, { "deletes", &b->deletes },
		{ "rearms", &b->rearms }, { "errors", &b->errors },
	};
	long qos_mark_mask = 0, route_mark_mask = 0;
	bool present = true;

	memset(b, 0, sizeof(*b));
	/* status first: it is the one read under CDX's transaction, and the
	 * one whose absence says the adapter is not loaded. */
	if (ft_keys_read(ctx, FT_STATUS, status, sizeof(status) / sizeof(status[0]), &present) ||
	    (present && ft_keys_read(ctx, FT_STATS, stats, sizeof(stats) / sizeof(stats[0]), &present)) ||
	    (present && ft_parameter_read(ctx, FT_CDX_MODULE "/parameters/flowtable_observe",
					  &b->observe, &present)) ||
	    (present && ft_parameter_read(ctx, FT_MULTICAST, &b->mcast_enabled, &present)) ||
	    (present && ft_parameter_read(ctx, FT_QOS_MARK_MASK, &qos_mark_mask, &present)) ||
	    (present && ft_parameter_read(ctx, FT_ROUTE_MARK_MASK, &route_mark_mask, &present)))
		return -1;
	if (!present) {
		memset(b, 0, sizeof(*b));
		return 0;   /* adapter not loaded */
	}
	b->present = true;
	b->qos_mark_mask = (uint32_t)qos_mark_mask;
	b->route_mark_mask = (uint32_t)route_mark_mask;
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
