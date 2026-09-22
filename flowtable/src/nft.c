/* nft process I/O, table ownership inspection, single-flight lock.
 * Shells out to the shipped `nft` (no libnftnl). SPDX-License-Identifier: GPL-2.0+ */
#include "runtime.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/wait.h>

int ft_nft_run(struct ft_ctx *ctx, const char *script, bool check_only, int keepfd)
{
	char err[512];
	char *argv_check[] = { "nft", "--check", "-f", "-", NULL };
	char *argv_apply[] = { "nft", "-f", "-", NULL };
	int rc = ft_nft_exec(check_only ? argv_check : argv_apply, script, err, sizeof(err), keepfd);
	if (rc != 0) {
		char *nl = strchr(err, '\n'); if (nl) *nl = '\0';
		snprintf(ctx->err, sizeof(ctx->err), "nft: %.240s", err[0] ? err : "failed");
		return -1;
	}
	return 0;
}

int ft_nft_inspect(struct ft_ctx *ctx, bool *present, bool *owned, char hash[65], int keepfd)
{
	char out[FT_CONF_MAX * 4];
	char *argv[] = { "nft", "list", "table", "inet", FT_TABLE, NULL };
	int rc = ft_nft_exec(argv, NULL, out, sizeof(out), keepfd);
	*present = false; *owned = false; if (hash) hash[0] = '\0';
	if (rc < 0) goto inspect_error;
	if (rc != 0) {
		/* An unsuccessful lookup is not proof of absence: ENOMEM, denied
		 * access or a broken nft must not authorize a replacement. Confirm
		 * absence with a successful inventory, without parsing stderr. */
		char *tables[] = { "nft", "list", "tables", NULL };
		if (ft_nft_exec(tables, NULL, out, sizeof(out), keepfd) != 0)
			goto inspect_error;
		char *save, *line = strtok_r(out, "\n", &save);
		for (; line; line = strtok_r(NULL, "\n", &save)) {
			char kind[16], family[16], name[64];
			if (sscanf(line, "%15s %15s %63s", kind, family, name) == 3 &&
			    !strcmp(kind, "table") && !strcmp(family, "inet") && !strcmp(name, FT_TABLE))
				goto inspect_error;
		}
		return 0;
	}
	*present = true;
	*owned = ft_marker_owned(out, hash);
	return 0;
inspect_error:
	snprintf(ctx->err, sizeof(ctx->err), "cannot inspect nft table state");
	return -1;
}

int ft_nft_delete(struct ft_ctx *ctx, int keepfd)
{
	bool present, owned; char hash[65];
	if (ft_nft_inspect(ctx, &present, &owned, hash, keepfd))
		return -1;
	if (!present)
		return 0;
	if (!owned) {
		snprintf(ctx->err, sizeof(ctx->err),
			 "refusing to modify a table without this controller's ownership marker");
		return -1;
	}
	char *argv[] = { "nft", "delete", "table", "inet", FT_TABLE, NULL };
	char err[512];
	if (ft_nft_exec(argv, NULL, err, sizeof(err), keepfd) != 0) {
		snprintf(ctx->err, sizeof(ctx->err), "nft delete: %.240s", err[0] ? err : "failed");
		return -1;
	}
	return 0;
}

int ft_path_lock(struct ft_ctx *ctx, const char *path, int timeout_ms)
{
	struct timespec ts;
	long waited = 0;
	int fd;
	/* The lock lives under /run/lock, which a minimal image may not have yet
	 * (the Python helper mkdir'd it too). Create it best-effort. */
	mkdir("/run/lock", 0755);
	fd = open(path, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (fd < 0) {
		snprintf(ctx->err, sizeof(ctx->err), "cannot open lock: %s", strerror(errno));
		return -1;
	}
	while (flock(fd, LOCK_EX | LOCK_NB) < 0) {
		if (errno != EWOULDBLOCK) {
			snprintf(ctx->err, sizeof(ctx->err), "flock: %s", strerror(errno));
			close(fd);
			return -1;
		}
		if (waited >= timeout_ms) {
			snprintf(ctx->err, sizeof(ctx->err), "another policy operation still holds the lock");
			close(fd);
			return -1;
		}
		ts.tv_sec = 0; ts.tv_nsec = 10 * 1000000;
		nanosleep(&ts, NULL);
		waited += 10;
	}
	return fd;
}

int ft_lock(struct ft_ctx *ctx, int timeout_ms)
{
	return ft_path_lock(ctx, FT_LOCK, timeout_ms);
}

