// SPDX-License-Identifier: GPL-2.0-or-later
/* A translation client for the test image: offers and withdraws translated
 * sessions described by hand, through the same interface a translator uses
 * (ask_xlat.h), so the rig can drive admission, retirement and the keepalive
 * without one. Built only by meta-ask (CONFIG_ASK_XLAT_TEST); no consumer
 * ships it.
 *
 *   echo "in=eth3 proto=tcp src=fd00::2 dst=64:ff9b::a00:e8 sport=40001
 *         dport=5000 nsrc=10.0.0.62 ndst=10.0.0.232 nsport=40001 ndport=5000
 *         tos=copy cookie=1" > /sys/module/ask_xlat_test/parameters/session
 *   cat /sys/module/ask_xlat_test/parameters/session
 *   echo "withdraw cookie=1" > /sys/module/ask_xlat_test/parameters/session
 *   echo flush > /sys/module/ask_xlat_test/parameters/session
 *
 * One line describes the session by its first direction, as it arrives on
 * `in' (src, dst, sport, dport) and as it leaves translated (nsrc, ndst,
 * nsport, ndport); the second direction is its inverse, arriving on `rin',
 * which defaults to the device the route to ndst leaves by. tos is `copy'
 * (each packet's own, the default) or a fixed value. The routes, neighbours,
 * ports and MTU are the adapter's to find; with both ports at 1500 bytes only
 * TCP is offloaded, the IPv4 side's UDP being 1520 bytes as IPv6. Reading lists
 * every session the adapter still owes an answer for, with the callbacks it
 * has had, then the totals. A session's slot is given back when it is said
 * expired, or withdrawn with nothing more to say.
 */
#include <linux/inet.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netdevice.h>
#include <linux/spinlock.h>
#include <net/ip6_route.h>
#include <net/route.h>
#include "ask_xlat.h"

/* As many as a page lists, at the widest each line can be. */
#define XLAT_TEST_SESSIONS 30

static struct xlat_test_session {
	u64 cookie;
	bool used_slot;
	/* Withdrawn while its expired was being said: kept until it arrives. */
	bool withdrawn;
	unsigned int offers;
	unsigned int used;
	unsigned long lastused;
} xlat_test[XLAT_TEST_SESSIONS];
static unsigned int xlat_test_expired, xlat_test_used, xlat_test_unknown;
static unsigned int xlat_test_withdrawals, xlat_test_late;
static DEFINE_SPINLOCK(xlat_test_lock);

/* Under xlat_test_lock. */
static struct xlat_test_session *xlat_test_find(u64 cookie, bool create)
{
	struct xlat_test_session *free = NULL;
	unsigned int i;

	for (i = 0; i < XLAT_TEST_SESSIONS; i++) {
		if (xlat_test[i].used_slot && xlat_test[i].cookie == cookie)
			return &xlat_test[i];
		if (!xlat_test[i].used_slot && !free)
			free = &xlat_test[i];
	}
	if (!create || !free)
		return NULL;
	*free = (struct xlat_test_session){ .cookie = cookie, .used_slot = true };
	return free;
}

/* Both callbacks run with the adapter's transaction held, in process context:
 * they count and take nothing but this module's own lock. The answer frees the
 * session's slot. */
static void xlat_test_expired_cb(u64 cookie)
{
	struct xlat_test_session *s;

	spin_lock_bh(&xlat_test_lock);
	xlat_test_expired++;
	s = xlat_test_find(cookie, false);
	if (s)
		s->used_slot = false;
	else
		xlat_test_unknown++;
	spin_unlock_bh(&xlat_test_lock);
}

static void xlat_test_used_cb(u64 cookie, unsigned long lastused)
{
	struct xlat_test_session *s;

	spin_lock_bh(&xlat_test_lock);
	xlat_test_used++;
	s = xlat_test_find(cookie, false);
	if (s) {
		s->used++;
		s->lastused = lastused;
	} else {
		xlat_test_unknown++;
	}
	spin_unlock_bh(&xlat_test_lock);
}

static const struct ask_xlat_ops xlat_test_ops = {
	.expired = xlat_test_expired_cb,
	.used = xlat_test_used_cb,
};

static int xlat_test_addr(const char *s, union nf_inet_addr *addr, u8 *family)
{
	memset(addr, 0, sizeof(*addr));
	if (strchr(s, ':')) {
		*family = AF_INET6;
		return in6_pton(s, -1, (u8 *)addr->ip6, -1, NULL) ? 0 : -EINVAL;
	}
	*family = AF_INET;
	return in4_pton(s, -1, (u8 *)&addr->ip, -1, NULL) ? 0 : -EINVAL;
}

static int xlat_test_port(const char *s, __be16 *port)
{
	u16 value;
	int rc = kstrtou16(s, 0, &value);

	*port = htons(value);
	return rc;
}

static int xlat_test_ifindex(const char *name, int *ifindex)
{
	struct net_device *dev = dev_get_by_name(&init_net, name);

	if (!dev)
		return -ENODEV;
	*ifindex = dev->ifindex;
	dev_put(dev);
	return 0;
}

/* The device the route to a translated destination leaves by: where, on a
 * symmetric path, the second direction arrives. */
static int xlat_test_route_ifindex(const struct ask_xlat_tuple *x, u8 proto, int *ifindex)
{
	if (x->family == AF_INET6) {
		struct flowi6 fl6 = { .daddr = x->dst.in6, .saddr = x->src.in6,
				      .flowi6_proto = proto };
		struct dst_entry *dst = ip6_route_output(&init_net, NULL, &fl6);
		int rc = dst->error;

		if (!rc)
			*ifindex = dst->dev->ifindex;
		dst_release(dst);
		return rc;
	} else {
		struct flowi4 fl4 = { .daddr = x->dst.ip, .saddr = x->src.ip,
				      .flowi4_proto = proto, .flowi4_flags = FLOWI_FLAG_ANYSRC };
		struct rtable *rt = __ip_route_output_key(&init_net, &fl4);

		if (IS_ERR(rt))
			return PTR_ERR(rt);
		*ifindex = rt->dst.dev->ifindex;
		ip_rt_put(rt);
		return 0;
	}
}

static int xlat_test_parse(char *line, struct ask_xlat_flow *flow, bool *withdraw)
{
	struct ask_xlat_dir *d0 = &flow->dir[0], *d1 = &flow->dir[1];
	bool cookie = false, rin = false;
	char *token, *value;
	u8 family;
	int rc = 0;

	flow->tos = ASK_XLAT_TOS_COPY;
	while (!rc && (token = strsep(&line, " \t\n"))) {
		if (!*token)
			continue;
		if (!strcmp(token, "withdraw")) {
			*withdraw = true;
			continue;
		}
		value = strchr(token, '=');
		if (!value)
			return -EINVAL;
		*value++ = 0;
		if (!strcmp(token, "in")) {
			rc = xlat_test_ifindex(value, &d0->ifindex);
		} else if (!strcmp(token, "rin")) {
			rc = xlat_test_ifindex(value, &d1->ifindex);
			rin = true;
		} else if (!strcmp(token, "proto")) {
			flow->proto = !strcmp(value, "tcp") ? IPPROTO_TCP :
				      !strcmp(value, "udp") ? IPPROTO_UDP : 0;
			rc = flow->proto ? 0 : -EINVAL;
		} else if (!strcmp(token, "src")) {
			rc = xlat_test_addr(value, &d0->match.src, &d0->match.family);
		} else if (!strcmp(token, "dst")) {
			rc = xlat_test_addr(value, &d0->match.dst, &family);
			rc = rc ?: (family == d0->match.family ? 0 : -EINVAL);
		} else if (!strcmp(token, "nsrc")) {
			rc = xlat_test_addr(value, &d0->xlat.src, &d0->xlat.family);
		} else if (!strcmp(token, "ndst")) {
			rc = xlat_test_addr(value, &d0->xlat.dst, &family);
			rc = rc ?: (family == d0->xlat.family ? 0 : -EINVAL);
		} else if (!strcmp(token, "sport")) {
			rc = xlat_test_port(value, &d0->match.sport);
		} else if (!strcmp(token, "dport")) {
			rc = xlat_test_port(value, &d0->match.dport);
		} else if (!strcmp(token, "nsport")) {
			rc = xlat_test_port(value, &d0->xlat.sport);
		} else if (!strcmp(token, "ndport")) {
			rc = xlat_test_port(value, &d0->xlat.dport);
		} else if (!strcmp(token, "tos")) {
			if (strcmp(value, "copy"))
				rc = kstrtou8(value, 0, &flow->tos);
		} else if (!strcmp(token, "cookie")) {
			rc = kstrtou64(value, 0, &flow->cookie);
			cookie = true;
		} else {
			rc = -EINVAL;
		}
	}
	if (rc || !cookie)
		return rc ?: -EINVAL;
	if (*withdraw)
		return 0;
	if (!d0->ifindex || !d0->match.family || !d0->xlat.family || !flow->proto)
		return -EINVAL;
	/* The second direction is the first's inverse. */
	d1->match = (struct ask_xlat_tuple){
		.src = d0->xlat.dst, .dst = d0->xlat.src,
		.sport = d0->xlat.dport, .dport = d0->xlat.sport,
		.family = d0->xlat.family,
	};
	d1->xlat = (struct ask_xlat_tuple){
		.src = d0->match.dst, .dst = d0->match.src,
		.sport = d0->match.dport, .dport = d0->match.sport,
		.family = d0->match.family,
	};
	flow->net = &init_net;
	return rin ? 0 : xlat_test_route_ifindex(&d0->xlat, flow->proto, &d1->ifindex);
}

/* Withdraw one session: its slot goes now, or with the expired a withdrawal
 * came too late for. Under no lock of the adapter's. */
static void xlat_test_withdraw(u64 cookie)
{
	bool quiet = ask_xlat_withdraw(cookie);
	struct xlat_test_session *s;

	spin_lock_bh(&xlat_test_lock);
	xlat_test_withdrawals++;
	xlat_test_late += !quiet;
	s = xlat_test_find(cookie, false);
	if (s && quiet)
		s->used_slot = false;
	else if (s)
		s->withdrawn = true;
	spin_unlock_bh(&xlat_test_lock);
}

/* Withdraw every session still owed an answer. */
static void xlat_test_flush(void)
{
	u64 cookies[XLAT_TEST_SESSIONS];
	unsigned int i, n = 0;

	spin_lock_bh(&xlat_test_lock);
	for (i = 0; i < XLAT_TEST_SESSIONS; i++)
		if (xlat_test[i].used_slot && !xlat_test[i].withdrawn)
			cookies[n++] = xlat_test[i].cookie;
	spin_unlock_bh(&xlat_test_lock);
	for (i = 0; i < n; i++)
		xlat_test_withdraw(cookies[i]);
}

static int xlat_test_set(const char *val, const struct kernel_param *kp)
{
	struct ask_xlat_flow flow = {};
	struct xlat_test_session *s;
	bool withdraw = false, fresh;
	char *line;
	int rc;

	if (sysfs_streq(val, "flush")) {
		xlat_test_flush();
		return 0;
	}
	line = kstrdup(val, GFP_KERNEL);
	if (!line)
		return -ENOMEM;
	rc = xlat_test_parse(line, &flow, &withdraw);
	kfree(line);
	if (rc)
		return rc;
	if (withdraw) {
		xlat_test_withdraw(flow.cookie);
		return 0;
	}
	spin_lock_bh(&xlat_test_lock);
	s = xlat_test_find(flow.cookie, false);
	fresh = !s;
	/* A cookie whose withdrawal still waits for its expired is not offered
	 * again until that has arrived, so the two cannot be told apart wrong. */
	if (s && s->withdrawn)
		rc = -EBUSY;
	else if (!s && !(s = xlat_test_find(flow.cookie, true)))
		rc = -ENOSPC;
	else
		s->offers++;
	spin_unlock_bh(&xlat_test_lock);
	if (rc)
		return rc;
	if (ask_xlat_offer(&flow))
		return 0;
	/* Nothing owed for a refused offer: a slot made for it goes again. */
	spin_lock_bh(&xlat_test_lock);
	if (fresh && s->used_slot && s->cookie == flow.cookie)
		s->used_slot = false;
	spin_unlock_bh(&xlat_test_lock);
	return -EOPNOTSUPP;
}

static int xlat_test_get(char *buf, const struct kernel_param *kp)
{
	unsigned int i;
	int len = 0;

	spin_lock_bh(&xlat_test_lock);
	for (i = 0; i < XLAT_TEST_SESSIONS; i++) {
		const struct xlat_test_session *s = &xlat_test[i];

		if (!s->used_slot)
			continue;
		len += sysfs_emit_at(buf, len,
				     "session cookie=%llu offers=%u used=%u lastused_ms=%u withdrawn=%u\n",
				     s->cookie, s->offers, s->used,
				     s->used ? jiffies_to_msecs(jiffies - s->lastused) : 0,
				     s->withdrawn);
	}
	len += sysfs_emit_at(buf, len,
			     "total expired=%u used=%u unknown=%u withdrawals=%u late=%u\n",
			     xlat_test_expired, xlat_test_used, xlat_test_unknown,
			     xlat_test_withdrawals, xlat_test_late);
	spin_unlock_bh(&xlat_test_lock);
	return len;
}

static const struct kernel_param_ops xlat_test_param_ops = {
	.set = xlat_test_set,
	.get = xlat_test_get,
};
module_param_cb(session, &xlat_test_param_ops, NULL, 0600);
MODULE_PARM_DESC(session, "Offer a translated session described by hand, withdraw one (\"withdraw cookie=N\") or all (\"flush\"); reading lists them with their callbacks");

static int __init xlat_test_init(void)
{
	return ask_xlat_register(&xlat_test_ops);
}

static void __exit xlat_test_exit(void)
{
	WARN_ON(ask_xlat_unregister(&xlat_test_ops));
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ASK translation client for the test image");
MODULE_IMPORT_NS("ASK_XLAT");
module_init(xlat_test_init);
module_exit(xlat_test_exit);
