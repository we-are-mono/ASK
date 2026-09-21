/* Bounded nft execution and lifetime of its transaction lease.
 * SPDX-License-Identifier: GPL-2.0+ */
#define _GNU_SOURCE
#include "runtime.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef FT_NFT_TIMEOUT_MS
#define FT_NFT_TIMEOUT_MS 5000
#endif
#ifndef FT_NFT_CLEANUP_MS
#define FT_NFT_CLEANUP_MS 1000
#endif

enum { RUN_ERROR = -1, RUN_TIMEOUT = -2, RUN_OUTPUT = -3, RUN_INPUT = -4 };
struct reply { int rc; size_t len; };
/* Normally reaped before returning. An unkillable kernel task may outlive the
 * caller's deadline: its guardian keeps the lease and is reaped on the next
 * attempt. Never accumulate additional jobs behind such a task. */
static pid_t pending;

static int64_t now_ms(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts)) abort();
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int nonblock(int fd)
{
	int flags = fcntl(fd, F_GETFL);
	return flags < 0 ? -1 : fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* Do not assume the caller has its standard streams open. */
static int make_pipe(int p[2])
{
	if (pipe2(p, O_CLOEXEC)) return -1;
	for (int i = 0; i < 2; i++) {
		if (p[i] >= 3) continue;
		int fd = fcntl(p[i], F_DUPFD_CLOEXEC, 3);
		if (fd < 0) { close(p[0]); close(p[1]); p[0] = p[1] = -1; return -1; }
		close(p[i]);
		p[i] = fd;
	}
	return 0;
}

/* Linux close_range also prevents a surviving guardian from retaining the
 * CLI's output, netlink socket, or another invocation's liveness writer. */
static int keep_only(const int *fds, size_t n)
{
	unsigned first = 0;
	for (;;) {
		unsigned next = UINT_MAX;
		for (size_t i = 0; i < n; i++)
			if (fds[i] >= 0 && (unsigned)fds[i] >= first && (unsigned)fds[i] < next)
				next = (unsigned)fds[i];
		if (first < next && close_range(first, next - (next != UINT_MAX), 0)) return -1;
		if (next == UINT_MAX) return 0;
		first = next + 1;
	}
}

static void capture(int fd, char *out, size_t outlen, size_t *got, bool *truncated, bool *eof)
{
	char buf[4096];
	ssize_t n = read(fd, buf, sizeof(buf));
	if (n > 0 && out && outlen) {
		size_t copy = (size_t)n < outlen - 1 - *got ? (size_t)n : outlen - 1 - *got;
		memcpy(out + *got, buf, copy);
		*got += copy;
		out[*got] = '\0';
		if (copy < (size_t)n) *truncated = true;
	} else if (n == 0) {
		*eof = true;
	} else if (n < 0 && errno != EAGAIN && errno != EINTR) {
		*truncated = true; /* an incomplete response must never be parsed */
		*eof = true;
	}
}

static void reap_job(void)
{
	for (;;) {
		pid_t reaped = waitpid(-1, NULL, WNOHANG);
		if (reaped > 0 || (reaped < 0 && errno == EINTR)) continue;
		if (reaped < 0 && errno == ECHILD) return;
		/* Subreaper adoption catches a wrapper that double-forks or leaves
		 * the original process group. Only our own unreaped children are
		 * listed, so their PIDs cannot be recycled while we signal them. */
		FILE *children = fopen("/proc/thread-self/children", "re");
		if (children) {
			long child;
			while (fscanf(children, "%ld", &child) == 1)
				if (child > 0 && child <= INT_MAX) kill((pid_t)child, SIGKILL);
			fclose(children);
		}
		/* An unkillable kernel task deliberately keeps us and the lease
		 * alive; the controller has its own bounded cleanup deadline. */
		struct timespec delay = {.tv_nsec = 10 * 1000000};
		nanosleep(&delay, NULL);
	}
}

/* The guardian, not the controller, is nft's parent. Controller death closes
 * livefd, so even descendants which inherited the lease get cancelled. nft
 * also receives PDEATHSIG in case the guardian itself dies unexpectedly. */
static int supervise(char *const argv[], const char *input, char *out, size_t outlen,
		     int keepfd, int livefd, int64_t deadline)
{
	int in[2] = {-1, -1}, output[2] = {-1, -1};
	pid_t worker, guardian = getpid();
	int rc = RUN_ERROR;
	if (prctl(PR_SET_CHILD_SUBREAPER, 1) || make_pipe(in) || make_pipe(output)) goto done;
	worker = fork();
	if (worker < 0) goto done;
	if (worker == 0) {
		if (setpgid(0, 0) || prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != guardian)
			_exit(127);
		int lease = keepfd < 0 ? -1 : fcntl(keepfd, F_DUPFD, 3);
		if ((keepfd >= 0 && lease < 0) || dup2(in[0], 0) < 0 ||
		    dup2(output[1], 1) < 0 || dup2(output[1], 2) < 0) _exit(127);
		int fds[] = {0, 1, 2, lease};
		if (keep_only(fds, sizeof(fds) / sizeof(fds[0]))) _exit(127);
		signal(SIGTERM, SIG_DFL); signal(SIGINT, SIG_DFL);
		signal(SIGPIPE, SIG_DFL);
		if (setenv("LC_ALL", "C", 1)) _exit(127);
		execvp(argv[0], argv);
		_exit(127);
	}
	/* Both sides establish the group before either exec or cancellation. */
	int group_error = setpgid(worker, worker) && errno != EACCES;
	close(in[0]); in[0] = -1;
	close(output[1]); output[1] = -1;
	size_t sent = 0, len = input ? strlen(input) : 0, got = 0;
	bool truncated = false, eof = false;
	siginfo_t info = {0};
	if (group_error || nonblock(in[1]) || nonblock(output[0])) goto cancel;
	for (;;) {
		if (sent == len && in[1] >= 0) { close(in[1]); in[1] = -1; }
		int64_t remaining = deadline - now_ms();
		if (remaining <= 0) { rc = RUN_TIMEOUT; break; }
		struct pollfd p[] = {{livefd, POLLIN, 0}, {in[1], POLLOUT, 0},
				    {eof ? -1 : output[0], POLLIN, 0}};
		int ready = poll(p, 3, remaining < 10 ? (int)remaining : 10);
		if (ready < 0) { if (errno == EINTR) continue; break; }
		if (p[0].revents) break; /* EOF or cancellation: the controller is gone */
		if (p[2].revents) capture(output[0], out, outlen, &got, &truncated, &eof);
		if (p[1].revents) {
			ssize_t n = write(in[1], input + sent, len - sent);
			if (n > 0) sent += (size_t)n;
			else if (n < 0 && errno != EAGAIN && errno != EINTR) { rc = RUN_INPUT; break; }
		}
		/* WNOWAIT pins the leader PID/PGID until after group cancellation. */
		if (waitid(P_PID, worker, &info, WEXITED | WNOHANG | WNOWAIT)) break;
		if (info.si_pid) {
			rc = info.si_code == CLD_EXITED ? info.si_status : RUN_ERROR;
			if (sent != len) rc = RUN_INPUT;
			break;
		}
	}
cancel:
	/* No grace period: nft commits atomically, and no late writer may survive
 * lease release. The group includes pipe/lease-holding wrapper children. */
	kill(-worker, SIGKILL);
	kill(worker, SIGKILL); /* also covers a failure to establish the group */
	reap_job();
	/* Every writer is gone; only bounded pipe contents remain. */
	if (rc >= 0) {
		while (!eof) capture(output[0], out, outlen, &got, &truncated, &eof);
		if (truncated) rc = RUN_OUTPUT;
	}
done:
	for (int i = 0; i < 2; i++) { if (in[i] >= 0) close(in[i]); if (output[i] >= 0) close(output[i]); }
	return rc;
}

static int write_all(int fd, const void *data, size_t len)
{
	const char *p = data;
	while (len) {
		ssize_t n = write(fd, p, len);
		if (n < 0 && errno == EINTR) continue;
		if (n <= 0) return -1;
		p += n; len -= n;
	}
	return 0;
}

int ft_nft_exec(char *const argv[], const char *input, char *out, size_t outlen, int keepfd)
{
	int result[2] = {-1, -1}, live[2] = {-1, -1}, rc = RUN_ERROR;
	if (out && outlen) out[0] = '\0';
	if (pending) {
		pid_t reaped = waitpid(pending, NULL, WNOHANG);
		if (!reaped || (reaped < 0 && errno != ECHILD)) goto done;
		pending = 0;
	}
	int64_t deadline = now_ms() + FT_NFT_TIMEOUT_MS;
	if (make_pipe(result) || make_pipe(live) || nonblock(result[0])) goto done;
	pid_t pid = fork();
	if (pid < 0) goto done;
	if (!pid) {
		/* Group-directed shutdown must leave this cleanup owner alive.
		 * Controller liveness, not its signal handlers, controls the job. */
		signal(SIGTERM, SIG_IGN); signal(SIGINT, SIG_IGN); signal(SIGPIPE, SIG_IGN);
		signal(SIGCHLD, SIG_DFL);
		sigset_t empty;
		sigemptyset(&empty); sigprocmask(SIG_SETMASK, &empty, NULL);
		int fds[] = {result[1], live[0], keepfd};
		struct reply reply = { .rc = RUN_ERROR, .len = 0 };
		if (!keep_only(fds, sizeof(fds) / sizeof(fds[0])))
			reply.rc = supervise(argv, input, out, outlen, keepfd, live[0], deadline);
		reply.len = out && outlen ? strlen(out) : 0;
		if (!write_all(result[1], &reply, sizeof(reply)) && reply.len)
			write_all(result[1], out, reply.len);
		_exit(0);
	}
	pending = pid;
	close(result[1]); result[1] = -1;
	close(live[0]); live[0] = -1;
	struct reply reply = {0};
	size_t got = 0, body = 0;
	bool eof = false;
	deadline += FT_NFT_CLEANUP_MS;
	while (now_ms() < deadline) {
		struct pollfd p = {eof ? -1 : result[0], POLLIN, 0};
		if (poll(&p, 1, 10) < 0 && errno != EINTR) break;
		if (p.revents) {
			void *dest = got < sizeof(reply) ? (char *)&reply + got : (out ? (void *)(out + body) : NULL);
			size_t len = got < sizeof(reply) ? sizeof(reply) - got : reply.len - body;
			/* Read one extra byte to distinguish EOF from malformed replies. */
			char extra;
			if (!len) { dest = &extra; len = 1; }
			ssize_t n = read(result[0], dest, len);
			if (n == 0) eof = true;
			else if (n < 0) { if (errno != EINTR && errno != EAGAIN) break; }
			else if (got < sizeof(reply)) {
				got += n;
				if (got == sizeof(reply) && reply.len && (!out || reply.len >= outlen)) break;
			} else {
				if ((size_t)n > reply.len - body) break;
				body += n;
				if (out && outlen) out[body] = '\0';
			}
		}
		if (eof) {
			pid_t reaped = waitpid(pid, NULL, WNOHANG);
			if (reaped == pid) {
				pending = 0;
				if (got == sizeof(reply) && body == reply.len) rc = reply.rc;
				goto done;
			}
		}
	}
	rc = RUN_TIMEOUT;
done:
	/* Closing live cancels the job even if its guardian has not finished.
 * Do not kill/reap the guardian here: it must retain the lease until its
 * whole job is gone, including an unkillable kernel task. */
	for (int i = 0; i < 2; i++) { if (result[i] >= 0) close(result[i]); if (live[i] >= 0) close(live[i]); }
	if (rc < 0 && out && outlen)
		snprintf(out, outlen, "%s", rc == RUN_TIMEOUT ? "execution deadline exceeded; transaction outcome requires inspection" :
			 rc == RUN_OUTPUT ? "output incomplete or too large" :
			 rc == RUN_INPUT ? "input was not completely delivered" :
			 pending ? "previous nft cleanup still holds the transaction lease" : "subprocess failed");
	return rc;
}
