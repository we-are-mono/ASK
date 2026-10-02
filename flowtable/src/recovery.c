/* U-Boot reboot budget; the OS owns the watchdog and its health deadline.
 * SPDX-License-Identifier: GPL-2.0+ */
#include "runtime.h"
#include <errno.h>
#include <spawn.h>
#include <stdio.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define RECOVERY_LOCK FT_RUNTIME "/recovery.lock"
#define BOOT_ID "/proc/sys/kernel/random/boot_id"
#define RECOVERY_LIMIT 3

struct recovery {
	unsigned count;
	char boot[37];
	char reason[128];
};

static bool boot_id_valid(const char *id)
{
	if (strlen(id) != 36) return false;
	for (int i = 0; i < 36; i++) {
		if (i == 8 || i == 13 || i == 18 || i == 23) {
			if (id[i] != '-') return false;
		} else if (!strchr("0123456789abcdef", id[i])) return false;
	}
	return true;
}

/* Read the entire environment to distinguish an absent ASK record from an
 * unreadable environment. Retain only our record; never evaluate values
 * as shell input or print unrelated platform settings. fw_* use the OS's
 * /etc/fw_env.config, including its boot-medium selection and redundancy. */
static int read_record(struct recovery *r)
{
	FILE *f = popen("fw_printenv", "r");
	char *line = NULL;
	size_t size = 0;
	bool seen = false, bad = false;
	if (!f) return -1;
	memset(r, 0, sizeof(*r));
	while (getline(&line, &size, f) >= 0) {
		line[strcspn(line, "\r\n")] = 0;
		if (strncmp(line, "ask_recovery=", 13)) continue;
		const char *value = line + 13;
		size_t n = strlen(value);
		bad |= seen;
		seen = true;
		/* One digit, space, boot UUID, space, nonempty diagnostic. */
		if (n < 40 || n >= 39 + sizeof(r->reason) ||
		    *value < '0' || *value > '3' || value[1] != ' ' || value[38] != ' ') {
			bad = true;
			continue;
		}
		r->count = *value - '0';
		memcpy(r->boot, value + 2, 36);
		bad |= !boot_id_valid(r->boot);
		strcpy(r->reason, value + 39);
	}
	bad |= ferror(f);
	free(line);
	int status = pclose(f);
	return bad || status ? -1 : 0;
}

static int write_record(const struct recovery *r)
{
	/* One variable uses the common CLI of both libubootenv and U-Boot's
	 * tools; their batch-file formats differ. Never kill a flash write. */
	char record[180];
	snprintf(record, sizeof(record), "%u %s %s", r->count, r->boot, r->reason);
	char *argv[] = {"fw_setenv", "ask_recovery", record, NULL};
	extern char **environ;
	pid_t child;
	int status;
	if (posix_spawnp(&child, argv[0], NULL, NULL, argv, environ)) return -1;
	while (waitpid(child, &status, 0) < 0) {
		if (errno != EINTR) return -1;
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status)) return -1;
	struct recovery actual;
	return read_record(&actual) || actual.count != r->count ||
	       strcmp(actual.boot, r->boot) || strcmp(actual.reason, r->reason) ? -1 : 0;
}

int ft_recovery(struct ft_ctx *ctx, const char *verb)
{
	if (strcmp(verb, "arm") && strcmp(verb, "failed") && strcmp(verb, "clear")) {
		snprintf(ctx->err, sizeof(ctx->err), "unknown recovery command");
		return 1;
	}
	int lock = ft_path_lock(ctx, RECOVERY_LOCK, 5000), rc = 1;
	if (lock < 0) return 1;
	struct recovery r;
	char boot[40] = {0};
	FILE *f = fopen(BOOT_ID, "r");
	if (f) { (void)fgets(boot, sizeof(boot), f); fclose(f); }
	boot[strcspn(boot, "\r\n")] = 0;
	if (!boot_id_valid(boot) || read_record(&r)) {
		snprintf(ctx->err, sizeof(ctx->err), "cannot read recovery state; watchdog recovery must stay disabled");
		goto out;
	}
	struct recovery original = r;
	if (!strcmp(verb, "arm")) {
		/* Service restarts and concurrent callers spend at most one attempt
		 * per kernel boot, including after a healthy boot clears the count. */
		if (!strcmp(r.boot, boot)) { rc = 0; goto out; }
		if (r.count >= RECOVERY_LIMIT) {
			snprintf(ctx->err, sizeof(ctx->err), "recovery budget exhausted after %u boots: %s",
				 r.count, r.reason);
			rc = 2; goto out;
		}
		if (r.count) fprintf(stderr, "ask-flowtable: previous recovery: %s\n", r.reason);
		r.count++;
		snprintf(r.reason, sizeof(r.reason), "watchdog armed; failure detail unavailable if this boot hangs");
	} else if (!strcmp(verb, "failed")) {
		if (strcmp(r.boot, boot)) {
			snprintf(ctx->err, sizeof(ctx->err), "recovery was not armed in this boot");
			goto out;
		}
		ft_terminal_reason(r.reason, sizeof(r.reason));
	} else {
		/* The platform calls this after an hour of successful probes, or an
		 * operator after repair. No wall clock or writable rootfs required. */
		r.count = 0;
		snprintf(r.reason, sizeof(r.reason), "recovery budget cleared");
	}
	strcpy(r.boot, boot);
	if (r.count == original.count && !strcmp(r.boot, original.boot) &&
	    !strcmp(r.reason, original.reason)) {
		rc = 0; goto out;
	}
	if (write_record(&r))
		snprintf(ctx->err, sizeof(ctx->err), "cannot commit recovery state; watchdog recovery must stay disabled");
	else rc = 0;
out:
	close(lock);
	return rc;
}
