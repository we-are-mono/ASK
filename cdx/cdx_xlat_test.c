// SPDX-License-Identifier: GPL-2.0-or-later
/* Feasibility hook for translated offload (NAT64, SIIT): installs directions
 * described by hand, so the rig can show what the NAT-PT opcodes put on the
 * wire before any translator feeds them. Not an interface: a translator's own
 * admission path replaces it.
 *
 *   echo "in=eth3 out=eth4 proto=udp src=fd00::2 dst=64:ff9b::a00:e8
 *         sport=1000 dport=2000 nsrc=10.0.0.62 ndst=10.0.0.232 nsport=40000
 *         ndport=2000 smac=<out port> dmac=<next hop> mtu=1500 [tos=0]"
 *         > /sys/module/cdx/parameters/xlat_test
 *   cat /sys/module/cdx/parameters/xlat_test    (each entry's hits)
 *   echo flush > /sys/module/cdx/parameters/xlat_test
 *
 * The match's family is src's, the translation's nsrc's; a rule whose two are
 * the same is plain NAT and goes through the same encoder. */
#include <linux/etherdevice.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netdevice.h>
#include "portdefs.h"
#include "cdx.h"
#include "cdx_flowtable_backend.h"
#include "cdx_flowtable_hw.h"
#include "cdx_xlat_test.h"

#define XLAT_TEST_MAX 8

static struct xlat_test_entry {
	struct cdx_ft_hw *hw;
	struct cdx_ft_rule rule;
} xlat_test[XLAT_TEST_MAX];

static int xlat_test_addr(const char *s, union nf_inet_addr *addr, u8 *family)
{
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

static void xlat_test_release(struct xlat_test_entry *e)
{
	int rc = cdx_ft_hw_del(&e->hw);

	if (rc)
		pr_warn("cdx: xlat_test delete: %d\n", rc);
	dev_put(e->rule.in);
	dev_put(e->rule.out);
	memset(e, 0, sizeof(*e));
}

void cdx_xlat_test_flush(void)
{
	bool any = false;
	int i;

	/* Nothing installed, nothing to lock: module teardown calls this on
	 * an initialization failure too, possibly before the lock exists. */
	for (i = 0; i < XLAT_TEST_MAX; i++)
		any |= !!xlat_test[i].hw;
	if (!any)
		return;
	mutex_lock(&cdx_info->ctrl.mutex);
	for (i = 0; i < XLAT_TEST_MAX; i++)
		if (xlat_test[i].hw)
			xlat_test_release(&xlat_test[i]);
	mutex_unlock(&cdx_info->ctrl.mutex);
}

static int xlat_test_parse(char *line, struct cdx_ft_rule *rule)
{
	u8 family = 0, xfamily = 0, f;
	char *token, *value;
	int rc = 0;

	while (!rc && (token = strsep(&line, " \t\n"))) {
		if (!*token)
			continue;
		value = strchr(token, '=');
		if (!value)
			return -EINVAL;
		*value++ = 0;
		if (!strcmp(token, "in") || !strcmp(token, "out")) {
			struct net_device *dev = dev_get_by_name(&init_net, value);

			if (!dev)
				return -ENODEV;
			if (token[0] == 'i') {
				dev_put(rule->in);
				rule->in = rule->in_logical = dev;
			} else {
				dev_put(rule->out);
				rule->out = rule->out_logical = dev;
			}
		} else if (!strcmp(token, "proto")) {
			rule->proto = !strcmp(value, "tcp") ? IPPROTO_TCP :
				      !strcmp(value, "udp") ? IPPROTO_UDP : 0;
			rc = rule->proto ? 0 : -EINVAL;
		} else if (!strcmp(token, "src")) {
			rc = xlat_test_addr(value, &rule->src, &family);
		} else if (!strcmp(token, "dst")) {
			rc = xlat_test_addr(value, &rule->dst, &f);
			rc = rc ?: (f == family ? 0 : -EINVAL);
		} else if (!strcmp(token, "nsrc")) {
			rc = xlat_test_addr(value, &rule->new_src, &xfamily);
		} else if (!strcmp(token, "ndst")) {
			rc = xlat_test_addr(value, &rule->new_dst, &f);
			rc = rc ?: (f == xfamily ? 0 : -EINVAL);
		} else if (!strcmp(token, "sport")) {
			rc = xlat_test_port(value, &rule->sport);
		} else if (!strcmp(token, "dport")) {
			rc = xlat_test_port(value, &rule->dport);
		} else if (!strcmp(token, "nsport")) {
			rc = xlat_test_port(value, &rule->new_sport);
		} else if (!strcmp(token, "ndport")) {
			rc = xlat_test_port(value, &rule->new_dport);
		} else if (!strcmp(token, "smac")) {
			rc = mac_pton(value, rule->src_mac) ? 0 : -EINVAL;
		} else if (!strcmp(token, "dmac")) {
			rc = mac_pton(value, rule->dst_mac) ? 0 : -EINVAL;
		} else if (!strcmp(token, "mtu")) {
			rc = kstrtou16(value, 0, &rule->mtu);
		} else if (!strcmp(token, "tos")) {
			rc = kstrtou8(value, 0, &rule->xlat_tos);
		} else if (!strcmp(token, "tun")) {
			/* An egress tunnel on a plain direction: the outer header the
			 * entry inserts, its endpoints from tlocal/tremote. */
			bool six = !strcmp(value, "4o6");

			if (!six && strcmp(value, "6o4"))
				return -EINVAL;
			rule->out_tunnel.present = true;
			rule->out_tunnel.mode = six ? CDX_FT_TUNNEL_4O6 : CDX_FT_TUNNEL_6O4;
			rule->out_tunnel.family = six ? AF_INET6 : AF_INET;
			rule->out_tunnel.proto = six ? IPPROTO_IPIP : IPPROTO_IPV6;
			rule->out_tunnel.header_size = six ? sizeof(struct ipv6hdr) : sizeof(struct iphdr);
			if (!rule->out_tunnel.ttl)
				rule->out_tunnel.ttl = 64;
		} else if (!strcmp(token, "tlocal") || !strcmp(token, "tremote")) {
			rc = xlat_test_addr(value, token[1] == 'l' ? &rule->out_tunnel.local :
					    &rule->out_tunnel.remote, &f);
		} else if (!strcmp(token, "tttl")) {
			rc = kstrtou8(value, 0, &rule->out_tunnel.ttl);
		} else if (!strcmp(token, "sess")) {
			/* An egress PPPoE session; the concentrator is dmac. */
			rc = kstrtou16(value, 0, &rule->out_session.id);
			rule->out_session.present = true;
		} else {
			rc = -EINVAL;
		}
	}
	if (rc)
		return rc;
	if (!rule->in || !rule->out || !family || !xfamily || !rule->mtu)
		return -EINVAL;
	rule->family = family;
	rule->next_hop_family = xfamily;
	if (xfamily != family)
		rule->xlat_family = xfamily;
	if (rule->out_session.present)
		ether_addr_copy(rule->out_session.mac, rule->dst_mac);
	if (rule->out_tunnel.present) {
		ether_addr_copy(rule->out_tunnel.mac, rule->dst_mac);
		rule->next_hop_family = rule->out_tunnel.family;
	}
	return 0;
}

static int xlat_test_set(const char *val, const struct kernel_param *kp)
{
	struct cdx_ft_stats_binding stats = {};
	struct xlat_test_entry *slot = NULL;
	struct cdx_ft_rule rule = {};
	char *line;
	int i, rc;

	if (sysfs_streq(val, "flush")) {
		cdx_xlat_test_flush();
		return 0;
	}
	line = kstrdup(val, GFP_KERNEL);
	if (!line)
		return -ENOMEM;
	rc = xlat_test_parse(line, &rule);
	kfree(line);
	if (rc)
		goto put;
	mutex_lock(&cdx_info->ctrl.mutex);
	for (i = 0; i < XLAT_TEST_MAX && !slot; i++)
		if (!xlat_test[i].hw)
			slot = &xlat_test[i];
	rc = slot ? cdx_ft_hw_add(&rule, &stats, &slot->hw) : -ENOSPC;
	if (!rc)
		slot->rule = rule;
	mutex_unlock(&cdx_info->ctrl.mutex);
	if (!rc)
		return 0;
put:
	dev_put(rule.in);
	dev_put(rule.out);
	return rc;
}

static int xlat_test_get(char *buf, const struct kernel_param *kp)
{
	int i, len = 0;

	mutex_lock(&cdx_info->ctrl.mutex);
	for (i = 0; i < XLAT_TEST_MAX; i++) {
		struct xlat_test_entry *e = &xlat_test[i];
		struct cdx_ft_counters c = {};

		if (!e->hw)
			continue;
		cdx_ft_hw_stats(e->hw, &c);
		len += sysfs_emit_at(buf, len, "%d %s->%s proto %u %u->%u packets %llu bytes %llu\n",
				     i, e->rule.family == AF_INET6 ? "ipv6" : "ipv4",
				     e->rule.next_hop_family == AF_INET6 ? "ipv6" : "ipv4",
				     e->rule.proto, ntohs(e->rule.sport), ntohs(e->rule.new_sport),
				     c.packets, c.bytes);
	}
	mutex_unlock(&cdx_info->ctrl.mutex);
	return len;
}

static const struct kernel_param_ops xlat_test_ops = {
	.set = xlat_test_set,
	.get = xlat_test_get,
};
module_param_cb(xlat_test, &xlat_test_ops, NULL, 0600);
MODULE_PARM_DESC(xlat_test, "feasibility hook: install a translated direction by hand");
