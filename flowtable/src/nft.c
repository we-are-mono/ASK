/* nft process I/O, table ownership inspection, single-flight lock, owner param.
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

/* Run argv (no shell). If input!=NULL, feed it on stdin. Capture combined
 * stdout+stderr into out (out may be NULL). Returns the child exit code, or
 * -1 on spawn failure. */
/* keepfd: an fd whose open-file description the child should inherit across
 * exec (used to hand the flock lease to a committing nft, so an orphaned nft
 * keeps the lock if its controller is killed mid-transaction). -1 for none. */
static int run(char *const argv[], const char *input, char *out, size_t outlen, int keepfd)
{
	int in_pipe[2] = { -1, -1 }, out_pipe[2];
	pid_t pid;
	if (out) out[0] = '\0';
	if (input && pipe(in_pipe) < 0) return -1;
	if (pipe(out_pipe) < 0) { if (input) { close(in_pipe[0]); close(in_pipe[1]); } return -1; }

	pid = fork();
	if (pid < 0) {
		if (input) { close(in_pipe[0]); close(in_pipe[1]); }
		close(out_pipe[0]); close(out_pipe[1]);
		return -1;
	}
	if (pid == 0) {
		if (input) { dup2(in_pipe[0], 0); close(in_pipe[0]); close(in_pipe[1]); }
		else { int n = open("/dev/null", O_RDONLY); if (n >= 0) { dup2(n, 0); close(n); } }
		dup2(out_pipe[1], 1);
		dup2(out_pipe[1], 2);
		close(out_pipe[0]); close(out_pipe[1]);
		/* dup() clears O_CLOEXEC, so this copy survives exec and keeps the
		 * flock's OFD alive even if the parent (its fd) is gone. */
		if (keepfd >= 0)
			(void)dup(keepfd);
		setenv("LC_ALL", "C", 1);
		execvp(argv[0], argv);
		_exit(127);
	}
	if (input) close(in_pipe[0]);
	close(out_pipe[1]);
	if (input) {
		size_t off = 0, len = strlen(input);
		while (off < len) {
			ssize_t w = write(in_pipe[1], input + off, len - off);
			if (w <= 0) break;
			off += (size_t)w;
		}
		close(in_pipe[1]);
	}
	size_t got = 0;
	for (;;) {
		char buf[4096];
		ssize_t r = read(out_pipe[0], buf, sizeof(buf));
		if (r <= 0) break;
		if (out && got + (size_t)r < outlen) { memcpy(out + got, buf, r); got += (size_t)r; }
	}
	if (out && got < outlen) out[got] = '\0';
	close(out_pipe[0]);
	int status;
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

int ft_nft_run(struct ft_ctx *ctx, const char *script, bool check_only, int keepfd)
{
	char err[512];
	char *argv_check[] = { "nft", "--check", "-f", "-", NULL };
	char *argv_apply[] = { "nft", "-f", "-", NULL };
	int rc = run(check_only ? argv_check : argv_apply, script, err, sizeof(err), keepfd);
	if (rc != 0) {
		char *nl = strchr(err, '\n'); if (nl) *nl = '\0';
		snprintf(ctx->err, sizeof(ctx->err), "nft: %.240s", err[0] ? err : "failed");
		return -1;
	}
	return 0;
}

int ft_nft_inspect(struct ft_ctx *ctx, bool *present, bool *owned, char hash[65])
{
	char out[8192];
	char *argv[] = { "nft", "list", "table", "inet", FT_TABLE, NULL };
	int rc = run(argv, NULL, out, sizeof(out), -1);
	(void)ctx;
	*present = false; *owned = false; if (hash) hash[0] = '\0';
	if (rc != 0)
		return 0;   /* absent (or nft error treated as absent) */
	*present = true;
	*owned = ft_marker_owned(out, hash);
	return 0;
}

int ft_nft_delete(struct ft_ctx *ctx, int keepfd)
{
	bool present, owned; char hash[65];
	if (ft_nft_inspect(ctx, &present, &owned, hash))
		return -1;
	if (!present)
		return 0;
	if (!owned) {
		snprintf(ctx->err, sizeof(ctx->err),
			 "refusing to modify a table without this controller's ownership marker");
		return -1;
	}
	char *argv[] = { "nft", "delete", "table", "inet", FT_TABLE, NULL };
	if (run(argv, NULL, NULL, 0, keepfd) != 0) {
		snprintf(ctx->err, sizeof(ctx->err), "nft: could not delete existing table");
		return -1;
	}
	return 0;
}

int ft_lock(struct ft_ctx *ctx, int timeout_ms)
{
	struct timespec ts;
	long waited = 0;
	int fd;
	/* The lock lives under /run/lock, which a minimal image may not have yet
	 * (the Python helper mkdir'd it too). Create it best-effort. */
	mkdir("/run/lock", 0755);
	fd = open(FT_LOCK, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
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
		ts.tv_sec = 0; ts.tv_nsec = 50 * 1000000;
		nanosleep(&ts, NULL);
		waited += 50;
	}
	return fd;
}

void ft_offload_owner(char out[16])
{
	FILE *f = fopen(FT_OWNER_PARAM, "r");
	out[0] = '\0';
	if (!f)
		return;
	if (fgets(out, 16, f)) {
		char *nl = strpbrk(out, "\r\n");
		if (nl) *nl = '\0';
	}
	fclose(f);
}
