/* Host harness for the seal's header template (wireguard_seal_port.py): the
 * template structure and the wg_fp_tmpl*() lookup compiled from the kernel's
 * fastpath.c, over a stub peer and a stub wg_fp_build() that builds a header
 * for the port when the caller can transmit on it, as the real one does. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef uint8_t u8;
typedef struct { int counter; } atomic_t;
struct rcu_head { void *unused; };
struct net_device { bool qdisc_owned; };
typedef bool (*wg_fastpath_can_tx_t)(const struct net_device *dev);
typedef int spinlock_t;

#define WG_FP_HLEN 42
#define HZ 250
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define time_before(a, b) ((long)((a) - (b)) < 0)
#define container_of(p, type, member) ((type *)((char *)(p) - __builtin_offsetof(type, member)))
#define rcu_dereference_bh(p) (p)
#define rcu_dereference_protected(p, c) (p)
#define rcu_assign_pointer(p, v) ((p) = (v))
#define lockdep_is_held(l) 1
#define call_rcu(head, fn) fn(head)

static unsigned long jiffies = 1000;
static int builds;

static bool spin_trylock(spinlock_t *l) { return !(*l)++; }
static void spin_unlock(spinlock_t *l) { *l = 0; }

#include "wireguard_seal_tmpl_struct.inc"

struct wg_peer {
	struct wg_fastpath_tmpl *fp_tmpl;
	spinlock_t fp_lock;
	struct net_device *port;
	bool no_route;	/* the build finds no route or neighbour */
};

static struct wg_fastpath_tmpl *wg_fp_build(struct wg_peer *peer, wg_fastpath_can_tx_t can_tx)
{
	struct wg_fastpath_tmpl *t = calloc(1, sizeof(*t));

	assert(t);
	builds++;
	t->expires = jiffies + HZ;
	if (!peer->no_route && can_tx(peer->port))
		t->dev = peer->port;
	return t;
}

static void wg_fp_tmpl_free(struct rcu_head *rcu)
{
	free(container_of(rcu, struct wg_fastpath_tmpl, rcu));
}

#include "wireguard_seal_tmpl_production.inc"

/* cdx's answer: a port a hardware qdisc owns takes nothing from the seal. */
static bool can_tx(const struct net_device *dev)
{
	return !dev->qdisc_owned;
}

int main(void)
{
	struct net_device port = {0};
	struct wg_peer peer = { .port = &port };
	struct wg_fastpath_tmpl *t;

	t = wg_fp_tmpl(&peer, can_tx);
	assert(t && t->dev == &port && builds == 1);

	/* A tree takes the port within the template's second: the frames the
	 * seal would put on the port's forwarding queues would never leave, so
	 * the very next packet is refused, not one a second later. */
	port.qdisc_owned = true;
	t = wg_fp_tmpl(&peer, can_tx);
	assert(!t);

	/* The tree goes: the same template serves again, unrebuilt. */
	port.qdisc_owned = false;
	t = wg_fp_tmpl(&peer, can_tx);
	assert(t && t->dev == &port && builds == 1);

	/* Owned when the template expires: the rebuild declines too. */
	port.qdisc_owned = true;
	jiffies += HZ;
	t = wg_fp_tmpl(&peer, can_tx);
	assert(!t);
	assert(builds == 2);

	/* A template built with no device (no route or neighbour) declines
	 * whatever the caller would say of the port. */
	port.qdisc_owned = false;
	peer.no_route = true;
	jiffies += HZ;
	t = wg_fp_tmpl(&peer, can_tx);
	assert(!t);
	assert(builds == 3);

	wg_fp_tmpl_free(&peer.fp_tmpl->rcu);
	puts("seal: a port taken by a hardware qdisc is refused from the next packet");
	return 0;
}
