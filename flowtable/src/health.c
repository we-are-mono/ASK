/* Read-only health probe for the platform watchdog. SPDX-License-Identifier: GPL-2.0+ */
#define _GNU_SOURCE
#include "runtime.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdio.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

void ft_failure_reason(char *reason, size_t n)
{
	/* What CDX's datapath restart waits for, if one does: context for a
	 * failure, never one itself -- the datapath forwards in software
	 * meanwhile. Read without RTNL, which a failed probe may not get. */
	char degraded[96] = "";
	FILE *f = fopen(FT_CDX_MODULE "/parameters/flowtable_degraded_reason", "r");
	if (f) { (void)fgets(degraded, sizeof(degraded), f); fclose(f); }
	degraded[strcspn(degraded, "\r\n")] = 0;
	snprintf(reason, n, "datapath health check failed or timed out%s%s",
		 degraded[0] ? "; classifier bypassed: " : "", degraded);
}

static int rtnl_probe(struct ft_ctx *ctx)
{
	/* A single RTM_GETLINK takes RTNL in the pinned kernel, including when
	 * no hardware flow is installed. Acquiring RTNL can block inside
	 * sendto(), before recv(), so the parent bounds this whole process. */
	struct { struct nlmsghdr h; struct ifinfomsg i; } request = {
		.h = {.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
		      .nlmsg_type = RTM_GETLINK, .nlmsg_flags = NLM_F_REQUEST, .nlmsg_seq = 1},
		.i = {.ifi_family = AF_UNSPEC, .ifi_index = 1},
	};
	struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
	char buf[8192];
	int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE), rc = -1;
	if (fd < 0) goto error;
	struct timeval timeout = {.tv_sec = 5};
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))) goto out;
	if (sendto(fd, &request, request.h.nlmsg_len, 0, (void *)&kernel, sizeof(kernel)) != request.h.nlmsg_len) goto out;
	ssize_t n = recv(fd, buf, sizeof(buf), 0);
	struct nlmsghdr *reply = (void *)buf;
	if (n >= (ssize_t)sizeof(*reply) && NLMSG_OK(reply, n) &&
	    reply->nlmsg_type == RTM_NEWLINK && reply->nlmsg_seq == 1) rc = 0;
	else if (n >= 0) errno = EPROTO;
out:
	{ int saved = errno; close(fd); errno = saved; }
error:
	if (rc) snprintf(ctx->err, sizeof(ctx->err), "RTNL health check failed: %s", strerror(errno));
	return rc;
}

#ifndef FT_HEALTH_TIMEOUT_MS
#define FT_HEALTH_TIMEOUT_MS 5000
#endif

/* One step of the probe as its child reports it: what it concluded and why,
 * in one write, so a step arrives whole or not at all. */
struct ft_probe_step { int rc; char err[sizeof(((struct ft_ctx *)0)->err)]; };

static void report(int fd, struct ft_ctx *ctx, int rc)
{
	struct ft_probe_step step = {.rc = rc};
	if (!rc) ctx->err[0] = 0;
	memcpy(step.err, ctx->err, sizeof(step.err));
	(void)write(fd, &step, sizeof(step));
}

static long now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* How long CDX's transaction has been held by its current holder, 0 while it
 * is free; -1 where CDX does not say. Read without the transaction. */
static long transaction_held_ms(void)
{
	long held = -1;
	FILE *f = fopen(FT_CDX_MODULE "/parameters/flowtable_hold_ms", "r");
	if (f) { if (fscanf(f, "%ld", &held) != 1) held = -1; fclose(f); }
	return held;
}

int ft_health(struct ft_ctx *ctx)
{
	struct ft_probe_step step;
	int p[2], rc = -1;
	if (pipe2(p, O_CLOEXEC)) goto error;
	pid_t child = fork();
	if (child < 0) { close(p[0]); close(p[1]); goto error; }
	if (!child) {
		struct ft_backend b;
		close(p[0]);
		/* RTNL first: that it answers is a verdict of its own, which
		 * must not wait for CDX's transaction. Then the backend: one
		 * that cannot say is unhealthy. A latch CDX is restarting
		 * after is not, however long the restart waits: the classifier
		 * is bypassed and the ports forward in software. */
		if (!rtnl_probe(ctx)) {
			report(p[1], ctx, 0);
			report(p[1], ctx, ft_backend_read(ctx, &b));
		} else {
			report(p[1], ctx, -1);
		}
		_exit(0);
	}
	close(p[1]);
	long deadline = now_ms() + FT_HEALTH_TIMEOUT_MS;
	struct pollfd event = {.fd = p[0], .events = POLLIN};
	for (int steps = 0; steps < 2; steps++) {
		long left = deadline - now_ms();
		int ready = poll(&event, 1, left > 0 ? (int)left : 0);
		if (ready > 0 && read(p[0], &step, sizeof(step)) == sizeof(step)) {
			if (step.rc) { memcpy(ctx->err, step.err, sizeof(ctx->err)); goto done; }
			continue;
		}
		/* The backend's read waits for CDX's transaction, behind every
		 * caller queued for it: under a route-flap storm with traffic in
		 * software, past the deadline while each holder let it go in
		 * turn, and three such probes rebooted a board that was
		 * forwarding (A411). What nothing behind it gets past is a
		 * holder that keeps it past the deadline. A child that ended
		 * without saying is no such wait. */
		long held = steps && !ready ? transaction_held_ms() : -1;
		if (held >= FT_HEALTH_TIMEOUT_MS)
			snprintf(ctx->err, sizeof(ctx->err), "CDX transaction held for %ld ms", held);
		else if (held >= 0)
			rc = 0;
		else
			snprintf(ctx->err, sizeof(ctx->err), "datapath health probe failed or exceeded its deadline");
		goto done;
	}
	rc = 0;
done:
	/* The unreaped child pins its PID. Never wait for an unkillable RTNL
	 * or transaction waiter: return failure so the platform can reset the
	 * hardware, or success while the transaction changes hands. */
	kill(child, SIGKILL);
	(void)waitpid(child, NULL, WNOHANG);
	close(p[0]);
	return rc;
error:
	snprintf(ctx->err, sizeof(ctx->err), "cannot start health probe: %s", strerror(errno));
	return -1;
}
