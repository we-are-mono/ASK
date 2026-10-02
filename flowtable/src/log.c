/* Best-effort diagnostics must not block service recovery. SPDX-License-Identifier: GPL-2.0+ */
#include "runtime.h"
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>

void ft_log(int priority, const char *format, ...)
{
	char text[512];
	int prefix = snprintf(text, sizeof(text), "<%d>ask-flowtable[%ld]: ", LOG_DAEMON | priority, (long)getpid());
	va_list ap;
	va_start(ap, format);
	vsnprintf(text + prefix, sizeof(text) - (size_t)prefix, format, ap);
	va_end(ap);
	size_t len = strlen(text);
	int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	struct sockaddr_un addr = {.sun_family = AF_UNIX, .sun_path = "/dev/log"};
	ssize_t sent = fd < 0 ? -1 : sendto(fd, text, len, MSG_DONTWAIT | MSG_NOSIGNAL,
					   (struct sockaddr *)&addr, sizeof(addr));
	if (fd >= 0) close(fd);
	if (sent == (ssize_t)len) return;
	/* The initramfs has no syslog daemon. Preserve its console diagnostics
	 * without allowing a stalled console or logger to stall supervision. */
	fd = open("/dev/console", O_WRONLY | O_NONBLOCK | O_NOCTTY | O_CLOEXEC);
	if (fd >= 0) {
		char *body = strchr(text, '>') + 1;
		text[len++] = '\n';
		(void)write(fd, body, len - (size_t)(body - text));
		close(fd);
	}
}
