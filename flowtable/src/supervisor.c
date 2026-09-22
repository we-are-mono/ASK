/* Service lifecycle and controller crash recovery. SPDX-License-Identifier: GPL-2.0+ */
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
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#ifndef FT_SUPERVISOR_MIN_MS
#define FT_SUPERVISOR_MIN_MS 1000
#endif
#ifndef FT_SUPERVISOR_MAX_MS
#define FT_SUPERVISOR_MAX_MS 30000
#endif
#ifndef FT_SUPERVISOR_STABLE_MS
#define FT_SUPERVISOR_STABLE_MS 60000
#endif
#ifndef FT_SUPERVISOR_STOP_MS
#define FT_SUPERVISOR_STOP_MS 2000
#endif
#ifndef FT_SERVICE_WAIT_MS
#define FT_SERVICE_WAIT_MS 5000
#endif

struct service_state {
	pid_t supervisor, worker;
	unsigned restarts;
	int restart_in_ms, stopping;
};

static int64_t now_ms(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts)) abort();
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int socket_address(struct sockaddr_un *addr)
{
	memset(addr, 0, sizeof(*addr));
	addr->sun_family = AF_UNIX;
	if (sizeof(FT_SERVICE_SOCKET) > sizeof(addr->sun_path)) { errno = ENAMETOOLONG; return -1; }
	strcpy(addr->sun_path, FT_SERVICE_SOCKET);
	return 0;
}

static int close_extra(int keep)
{
	if (keep < 3) return close_range(3, UINT_MAX, 0);
	if (keep > 3 && close_range(3, (unsigned)keep - 1, 0)) return -1;
	return close_range((unsigned)keep + 1, UINT_MAX, 0);
}

static int write_pid(const char *path, pid_t pid)
{
	char temporary[PATH_MAX], text[32];
	int n = snprintf(temporary, sizeof(temporary), "%s.tmp", path);
	if (n < 0 || (size_t)n >= sizeof(temporary)) { errno = ENAMETOOLONG; return -1; }
	int fd = open(temporary, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (fd < 0) return -1;
	n = snprintf(text, sizeof(text), "%ld\n", (long)pid);
	int rc = write(fd, text, (size_t)n) == n ? 0 : -1;
	if (close(fd)) rc = -1;
	if (!rc) rc = rename(temporary, path);
	if (rc) unlink(temporary);
	return rc;
}

static pid_t spawn_worker(const char *conf)
{
	pid_t supervisor = getpid(), pid = fork();
	if (pid) return pid;
	/* Lifetime/control locks belong only to the supervisor. A dead
	 * supervisor must not strand a still-running controller. nft guardians
	 * separately own cancellation and the policy transaction lease. */
	if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != supervisor || close_extra(-1)) _exit(127);
	sigset_t empty;
	sigemptyset(&empty);
	sigprocmask(SIG_SETMASK, &empty, NULL);
	execl("/proc/self/exe", "ask-flowtable", "daemon", "--config", conf, (char *)NULL);
	_exit(127);
}

int ft_supervise(const char *conf, int readyfd)
{
	struct ft_ctx ctx = {0};
	struct service_state state = {.supervisor = getpid()};
	struct sockaddr_un addr;
	int lock = -1, server = -1, signals = -1, stop_client = -1, rc = 1;
	int delay = FT_SUPERVISOR_MIN_MS;
	int64_t due = 0, started = 0, stop_due = 0;
	bool owned_socket = false, killed = false;
	sigset_t mask, previous;
	signal(SIGCHLD, SIG_DFL);
	sigemptyset(&mask);
	sigaddset(&mask, SIGTERM); sigaddset(&mask, SIGINT); sigaddset(&mask, SIGCHLD);
	if (close_extra(readyfd) || sigprocmask(SIG_BLOCK, &mask, &previous)) goto done;
	lock = ft_path_lock(&ctx, FT_SERVICE_LOCK, 0);
	if (lock < 0) goto restore;
	signals = signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK);
	server = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (signals < 0 || server < 0 || socket_address(&addr)) goto restore;
	/* The lifetime lock protects replacement of stale socket/PID files.
	 * Files identify processes for observation only, never for signalling. */
	unlink(FT_SERVICE_SOCKET);
	if (bind(server, (struct sockaddr *)&addr, sizeof(addr))) goto restore;
	owned_socket = true;
	if (chmod(FT_SERVICE_SOCKET, 0600) || listen(server, 8) || write_pid(FT_SUPERVISOR_PID, getpid())) goto restore;
	unlink(FT_WORKER_PID);
	rc = 0;
	for (;;) {
		int64_t now = now_ms();
		if (state.worker) {
			int status;
			pid_t reaped = waitpid(state.worker, &status, WNOHANG);
			if (reaped == state.worker) {
				state.worker = 0;
				unlink(FT_WORKER_PID);
				if (now - started >= FT_SUPERVISOR_STABLE_MS) delay = FT_SUPERVISOR_MIN_MS;
				due = now + delay;
				if (!state.stopping) {
					ft_log(LOG_WARNING, "controller exited (%d); restart in %d ms", status, delay);
				}
				if (delay < FT_SUPERVISOR_MAX_MS)
					delay = delay > FT_SUPERVISOR_MAX_MS / 2 ? FT_SUPERVISOR_MAX_MS : delay * 2;
			}
		}
		if (state.stopping) {
			if (!state.worker) break;
			if (!stop_due) { kill(state.worker, SIGTERM); stop_due = now + FT_SUPERVISOR_STOP_MS; }
			if (!killed && now >= stop_due) { kill(state.worker, SIGKILL); killed = true; }
		} else if (!state.worker && now >= due) {
			if (!ft_cdx_present()) {
				due = now + FT_SUPERVISOR_MAX_MS;
			} else {
				state.worker = spawn_worker(conf);
				if (state.worker < 0) {
					ft_log(LOG_ERR, "cannot fork controller: %s; retry in %d ms", strerror(errno), delay);
					state.worker = 0;
					due = now + delay;
					if (delay < FT_SUPERVISOR_MAX_MS)
						delay = delay > FT_SUPERVISOR_MAX_MS / 2 ? FT_SUPERVISOR_MAX_MS : delay * 2;
				} else {
					started = now;
					state.restarts++;
					if (write_pid(FT_WORKER_PID, state.worker)) { state.stopping = 1; rc = 1; }
				}
			}
		}
		if (readyfd >= 0) {
			(void)write(readyfd, &rc, sizeof(rc));
			close(readyfd); readyfd = -1;
		}
		int wait = 1000;
		int64_t next = state.stopping ? (killed ? now + 1000 : stop_due) : (state.worker ? now + 1000 : due);
		if (next - now < wait) wait = next > now ? (int)(next - now) : 0;
		struct pollfd p[] = {{signals, POLLIN, 0}, {server, POLLIN, 0}};
		if (poll(p, 2, wait) < 0) {
			if (errno != EINTR) { state.stopping = 1; rc = 1; }
			continue;
		}
		if (p[0].revents) {
			struct signalfd_siginfo info;
			for (int i = 0; i < 16 && read(signals, &info, sizeof(info)) == sizeof(info); i++)
				if (info.ssi_signo == SIGTERM || info.ssi_signo == SIGINT) state.stopping = 1;
		}
		if (p[1].revents & POLLIN) {
			int client = accept4(server, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
			if (client < 0) continue;
			struct ucred cred;
			socklen_t len = sizeof(cred);
			struct pollfd request = {client, POLLIN, 0};
			char verb;
			if (getsockopt(client, SOL_SOCKET, SO_PEERCRED, &cred, &len) || cred.uid != geteuid() ||
			    poll(&request, 1, 100) <= 0 || recv(client, &verb, 1, 0) != 1) { close(client); continue; }
			if (verb == 'S') {
				state.stopping = 1; /* durable for this generation before any worker signal */
				if (stop_client >= 0) close(stop_client);
				stop_client = client;
			} else {
				state.restart_in_ms = state.worker || state.stopping ? 0 : (int)(due > now_ms() ? due - now_ms() : 0);
				if (verb == 'P') (void)send(client, &state, sizeof(state), MSG_NOSIGNAL);
				close(client);
			}
		}
	}
restore:
	if (owned_socket) {
		unlink(FT_WORKER_PID); unlink(FT_SUPERVISOR_PID); unlink(FT_SERVICE_SOCKET);
	}
	if (stop_client >= 0) { (void)send(stop_client, &state, sizeof(state), MSG_NOSIGNAL); close(stop_client); }
	if (signals >= 0) close(signals);
	if (server >= 0) close(server);
	if (lock >= 0) close(lock);
	sigprocmask(SIG_SETMASK, &previous, NULL);
done:
	if (readyfd >= 0) { (void)write(readyfd, &rc, sizeof(rc)); close(readyfd); }
	return rc;
}

static int wait_fd(int fd, short events, int64_t deadline)
{
	for (;;) {
		int64_t left = deadline - now_ms();
		if (left <= 0) { errno = ETIMEDOUT; return -1; }
		struct pollfd p = {fd, events, 0};
		int rc = poll(&p, 1, (int)left);
		if (rc > 0) return 0;
		if (rc < 0 && errno != EINTR) return -1;
	}
}

/* 1 means absent; -1 means an existing service did not answer reliably. */
static int request(char verb, struct service_state *state)
{
	struct sockaddr_un addr;
	int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0), rc = -1;
	int64_t deadline = now_ms() + FT_SERVICE_WAIT_MS;
	if (fd < 0) return -1;
	if (socket_address(&addr)) goto done;
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr))) {
		if (errno == ENOENT || errno == ECONNREFUSED) { rc = 1; goto done; }
		if (errno != EINPROGRESS || wait_fd(fd, POLLOUT, deadline)) goto done;
		int error;
		socklen_t len = sizeof(error);
		if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) || error) goto done;
	}
	if (send(fd, &verb, 1, MSG_NOSIGNAL) != 1 || wait_fd(fd, POLLIN, deadline)) goto done;
	if (recv(fd, state, sizeof(*state), 0) == sizeof(*state)) rc = 0;
done:
	close(fd);
	return rc;
}

static int launch(const char *conf)
{
	struct service_state state;
	int rc = request('P', &state);
	if (!rc) return state.stopping ? -1 : 0;
	if (rc < 0) return -1;
	if (!ft_cdx_present()) {
		fprintf(stderr, "ask-flowtable: cdx not loaded; not starting\n");
		ft_log(LOG_NOTICE, "cdx not loaded; not starting");
		return 0;
	}
	int p[2];
	if (pipe2(p, O_CLOEXEC | O_NONBLOCK)) return -1;
	signal(SIGCHLD, SIG_DFL);
	pid_t pid = fork();
	if (!pid) {
		int ready = fcntl(p[1], F_DUPFD_CLOEXEC, 3);
		close(p[0]); close(p[1]);
		if (ready < 0 || setsid() < 0) _exit(1);
		int nullfd = open("/dev/null", O_RDWR);
		if (nullfd < 0) _exit(1);
		for (int i = 0; i < 3; i++) if (dup2(nullfd, i) < 0) _exit(1);
		if (nullfd > 2) close(nullfd);
		_exit(ft_supervise(conf, ready));
	}
	close(p[1]);
	int status = 1;
	if (pid > 0 && !wait_fd(p[0], POLLIN, now_ms() + FT_SERVICE_WAIT_MS))
		if (read(p[0], &status, sizeof(status)) != sizeof(status)) status = 1;
	close(p[0]);
	if (pid > 0 && status) kill(pid, SIGTERM);
	if (pid > 0) (void)waitpid(pid, NULL, WNOHANG);
	return status ? -1 : 0;
}

int ft_service(struct ft_ctx *ctx, const char *verb, const char *conf)
{
	struct service_state state;
	if (!strcmp(verb, "status")) {
		int rc = request('P', &state);
		if (rc > 0) { puts("{\"running\": false}"); return 0; }
		if (!rc) {
			printf("{\"running\": true, \"supervisor_pid\": %ld, \"worker_pid\": %ld, \"restarts\": %u, \"restart_in_ms\": %d, \"stopping\": %s}\n",
			       (long)state.supervisor, (long)state.worker, state.restarts ? state.restarts - 1 : 0,
			       state.restart_in_ms, state.stopping ? "true" : "false");
			return 0;
		}
		goto error;
	}
	if (strcmp(verb, "start") && strcmp(verb, "stop") && strcmp(verb, "restart")) {
		snprintf(ctx->err, sizeof(ctx->err), "unknown service command");
		return -1;
	}
	int control = ft_path_lock(ctx, FT_CONTROL_LOCK, 30000);
	if (control < 0) return -1;
	int rc = 0;
	if (strcmp(verb, "start")) {
		rc = request('S', &state);
		if (rc > 0) rc = 0;
		/* ACK precedes supervisor exit by a few instructions. Wait for its
		 * lifetime lock before replacing this service generation. */
		if (!rc) {
			int lifetime = ft_path_lock(ctx, FT_SERVICE_LOCK, FT_SERVICE_WAIT_MS);
			if (lifetime < 0) rc = -1;
			else close(lifetime);
		}
	}
	if (!strcmp(verb, "stop")) {
		int drained = ft_stop(ctx, rc == 0);
		if (drained) { close(control); return -1; }
	} else if (!rc) {
		rc = launch(conf);
	}
	close(control);
	if (!rc) return 0;
error:
	snprintf(ctx->err, sizeof(ctx->err), "service lifecycle incomplete; inspect service-status and policy status");
	return -1;
}
