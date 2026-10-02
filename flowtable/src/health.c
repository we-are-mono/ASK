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

bool ft_terminal_reason(char *reason, size_t n)
{
	FILE *f = fopen(FT_CDX_MODULE "/parameters/flowtable_terminal_reason", "r");
	reason[0] = 0;
	if (f) { (void)fgets(reason, n, f); fclose(f); }
	reason[strcspn(reason, "\r\n")] = 0;
	bool terminal = reason[0] != 0;
	if (!terminal) snprintf(reason, n, "datapath health check failed or timed out");
	return terminal;
}

static int probe(struct ft_ctx *ctx)
{
	struct ft_backend b;
	char reason[128];
	/* CDX retains the latch even if its flowtable consumer is unloaded. */
	bool terminal = ft_terminal_reason(reason, sizeof(reason));
	if (!terminal && ft_backend_read(ctx, &b)) return -1;
	if (terminal || b.fatal_terminal) {
		snprintf(ctx->err, sizeof(ctx->err), "datapath requires reboot: %s", reason);
		return -1;
	}
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

int ft_health(struct ft_ctx *ctx)
{
	int p[2], rc = -1;
	if (pipe2(p, O_CLOEXEC)) goto error;
	pid_t child = fork();
	if (child < 0) { close(p[0]); close(p[1]); goto error; }
	if (!child) {
		close(p[0]);
		if (!probe(ctx)) ctx->err[0] = 0;
		(void)write(p[1], ctx->err, sizeof(ctx->err));
		_exit(0);
	}
	close(p[1]);
	struct pollfd event = {.fd = p[0], .events = POLLIN};
	int ready = poll(&event, 1, FT_HEALTH_TIMEOUT_MS);
	if (ready > 0 && read(p[0], ctx->err, sizeof(ctx->err)) == sizeof(ctx->err))
		rc = ctx->err[0] ? -1 : 0;
	else
		snprintf(ctx->err, sizeof(ctx->err), "datapath health probe failed or exceeded its deadline");
	/* The unreaped child pins its PID. Never wait for an unkillable RTNL
	 * reader: return failure so the platform can reset the hardware. */
	kill(child, SIGKILL);
	(void)waitpid(child, NULL, WNOHANG);
	close(p[0]);
	return rc;
error:
	snprintf(ctx->err, sizeof(ctx->err), "cannot start health probe: %s", strerror(errno));
	return -1;
}
