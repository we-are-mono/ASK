/* Raw NETLINK_ROUTE socket for interface/link/address change events, modeled
 * on cmm/src/rtnl.c's cmm_nl_open(). We do not parse attributes: any LINK or
 * ADDR event is a cue to re-resolve auto devices and re-apply if the rendered
 * policy changed. SPDX-License-Identifier: GPL-2.0+ */
#include "netlink.h"
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

int ft_nl_open(void)
{
	struct sockaddr_nl addr;
	int fd = socket(PF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd < 0)
		return -1;
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

/* Bound a drain so continuous events cannot starve the reconciliation timer.
 * Returns 1 if at least one message was read (something changed), 0 otherwise. */
int ft_nl_drain(int fd)
{
	char buf[8192];
	int seen = 0;
	for (int i = 0; i < 64; i++) {
		ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
		if (n > 0) { seen = 1; continue; }
		if (n < 0 && (errno == EINTR))
			continue;
		break;   /* EAGAIN/EWOULDBLOCK or error: nothing more to read */
	}
	return seen;
}
