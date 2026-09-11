/* Loaded only by the dedicated CMM route-retry test, never by the image. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static ssize_t (*send_message)(int, const struct msghdr *, int);

__attribute__((constructor)) static void resolve_sendmsg(void)
{
    send_message = dlsym(RTLD_NEXT, "sendmsg");
    if (!send_message) _exit(127);
}

ssize_t sendmsg(int fd, const struct msghdr *msg, int flags)
{
    uint16_t code, len;
    unsigned blocked = 0;
    char setting[32], log[512];
    int file, n;
    const struct sockaddr_nl *address = msg->msg_name;

    if (!address || msg->msg_namelen < sizeof(*address)
            || address->nl_family != AF_NETLINK || address->nl_pid != 0
            || msg->msg_iovlen != 2 || msg->msg_iov[0].iov_len != 20)
        return send_message(fd, msg, flags);
    memcpy(&code, (char *)msg->msg_iov[0].iov_base + 16, sizeof(code));
    memcpy(&len, (char *)msg->msg_iov[0].iov_base + 18, sizeof(len));
    if (len != msg->msg_iov[1].iov_len || len > 200
            || (code != 0x0313 && code != 0x0332 && code != 0x0b03 && code != 0x0a15))
        return send_message(fd, msg, flags);

    file = open("/tmp/ask-route-fault", O_RDONLY | O_CLOEXEC);
    if (file >= 0) {
        n = read(file, setting, sizeof(setting) - 1);
        close(file);
        if (n > 0) { setting[n] = 0; blocked = strtoul(setting, NULL, 0); }
    }
    n = snprintf(log, sizeof(log), "%s %04x ", blocked == code ? "reject" : "send", code);
    for (unsigned i = 0; i < len; i++)
        n += snprintf(log + n, sizeof(log) - n, "%02x", ((unsigned char *)msg->msg_iov[1].iov_base)[i]);
    log[n++] = '\n';
    file = open("/tmp/ask-route-fault.log", O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (file >= 0) { (void)write(file, log, n); close(file); }
    if (blocked == code) { errno = EIO; return -1; }
    return send_message(fd, msg, flags);
}
