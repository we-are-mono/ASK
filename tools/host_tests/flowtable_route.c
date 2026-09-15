/* Compile the production lookup with simulated FIB/device/route allocation. */
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define ERR_PTR(err) ((struct rtable *)(intptr_t)(err))
#define IFF_UP 1
#define RT_SCOPE_LINK 253
#define RT_SCOPE_HOST 254
#define LOOPBACK_IFINDEX 1
#define RTN_UNICAST 1
#define RTN_LOCAL 2
#define RTCF_LOCAL 0x80000000U
struct net_device { int ifindex, flags; };
struct net { struct net_device *loopback_dev; };
struct flowi4 {
	uint32_t saddr, daddr;
	int flowi4_oif, flowi4_l3mdev, flowi4_scope;
	unsigned char flowi4_flags, flowi4_proto;
};
struct fib_info { uint32_t fib_prefsrc; };
struct fib_result {
	struct fib_info *fi;
	void *table;
	struct net_device *dev;
	int type;
};
struct sk_buff { int unused; };
struct rtable { struct net_device *dev; };
#define FIB_RES_DEV(res) ((res).dev)
#define FIB_RES_OIF(res) ((res).dev->ifindex)

static struct net_device device = { .ifindex = 5, .flags = IFF_UP };
static struct net_device loopback = { .ifindex = LOOPBACK_IFINDEX, .flags = IFF_UP };
static struct fib_info info;
static struct rtable route;
static int lookup_error, lookups, builds, selections;
static bool ipv4_is_multicast(uint32_t ip) { return (ntohl(ip) & 0xf0000000) == 0xe0000000; }
static bool ipv4_is_lbcast(uint32_t ip) { return ip == UINT32_MAX; }
static bool ipv4_is_zeronet(uint32_t ip) { return !(ntohl(ip) & 0xff000000); }
static bool ipv4_is_local_multicast(uint32_t ip) { return (ntohl(ip) & 0xffffff00) == 0xe0000000; }
static struct net_device *__ip_dev_find(struct net *net, uint32_t ip, bool hold) { return &device; }
static struct net_device *dev_get_by_index_rcu(struct net *net, int index)
{
	return index == device.ifindex ? &device : NULL;
}
static void *__in_dev_get_rcu(struct net_device *dev) { return dev; }
static uint32_t inet_select_addr(struct net_device *dev, uint32_t dst, int scope)
{
	return htonl(0xc0000201);
}
static struct net_device *l3mdev_master_dev_rcu(struct net_device *dev) { return NULL; }
static int fib_lookup(struct net *net, struct flowi4 *fl, struct fib_result *res, int flags)
{
	lookups++;
	res->fi = &info;
	res->table = &info;
	res->dev = &device;
	res->type = RTN_UNICAST;
	return lookup_error;
}
static void fib_select_path(struct net *net, struct fib_result *res,
			   struct flowi4 *fl, const struct sk_buff *skb) { selections++; }
static struct rtable *__mkroute_output(struct fib_result *res, struct flowi4 *fl,
				      int orig_oif, struct net_device *dev, unsigned int flags)
{
	assert(dev == &device && res->type == RTN_UNICAST);
	assert(orig_oif == device.ifindex && flags == 0);
	builds++;
	route.dev = dev;
	return &route;
}

#include "route_production.inc"

static struct rtable *lookup(int error, unsigned char flags, int oif,
			     struct fib_result *res)
{
	struct net net = { .loopback_dev = &loopback };
	struct flowi4 fl = {
		.saddr = htonl(0xc6336402), .daddr = htonl(0xc6121e02),
		.flowi4_oif = oif, .flowi4_proto = IPPROTO_TCP,
		.flowi4_flags = FLOWI_FLAG_ANYSRC | flags,
	};

	lookup_error = error;
	lookups = builds = selections = 0;
	return ip_route_output_key_hash_rcu(&net, &fl, res, NULL);
}

int main(void)
{
	const int errors[] = { -ENETUNREACH, -EHOSTUNREACH, -EACCES, -EINVAL };
	struct fib_result res = {};
	unsigned int i;

	for (i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
		/* Ordinary callers still permit their existing on-link fallback. */
		assert(lookup(errors[i], 0, device.ifindex, &res) == &route);
		assert(lookups == 1 && builds == 1 && selections == 0);
		assert(!res.fi && !res.table);
		/* Opted-in flowtables must preserve the exact FIB rejection. */
		assert(lookup(errors[i], FLOWI_FLAG_NO_OIF_FALLBACK,
			      device.ifindex, &res) == ERR_PTR(errors[i]));
		assert(lookups == 1 && builds == 0 && selections == 0);
		assert(!res.fi && !res.table);
		assert(lookup(errors[i], 0, 0, &res) == ERR_PTR(errors[i]));
		assert(lookups == 1 && builds == 0 && selections == 0);
	}
	assert(lookup(0, 0, device.ifindex, &res) == &route);
	assert(lookups == 1 && builds == 1 && selections == 1 && res.fi == &info);
	assert(lookup(0, FLOWI_FLAG_NO_OIF_FALLBACK, device.ifindex, &res) == &route);
	assert(lookups == 1 && builds == 1 && selections == 1 && res.fi == &info);
	puts("strict FIB lookup: failures preserved; successful and legacy routes intact");
	return 0;
}
