/* Host harness for cdx_wg_can_tx() (wireguard_port_choice.py): the production
 * port table, cdx_wg_port() and cdx_wg_can_tx(), over a stub net_device whose
 * private area is the DPAA driver's, reduced to the field the choice reads. */
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>

#define READ_ONCE(x)		(*(volatile __typeof__(x) *)&(x))
#define WRITE_ONCE(x, v)	(*(volatile __typeof__(x) *)&(x) = (v))
#define smp_load_acquire(p)	__atomic_load_n((p), __ATOMIC_ACQUIRE)
#define smp_store_release(p, v)	__atomic_store_n((p), (v), __ATOMIC_RELEASE)

struct eth_iface_info { int unused; };
struct dpa_priv_s { bool ceetm_en; };
struct net_device { struct dpa_priv_s priv; };

static void *netdev_priv(const struct net_device *dev)
{
	return (void *)&dev->priv;
}

#include "wireguard_port_choice_production.inc"

int main(void)
{
	struct net_device port = {0}, other = {0};
	struct eth_iface_info eth;

	cdx_wg_ports[0].dev = &port;
	cdx_wg_ports[0].eth = &eth;
	smp_store_release(&cdx_wg_nports, 1);

	/* A device the fast path has no forwarding queues on. */
	assert(!cdx_wg_can_tx(&other));
	/* A DPAA port with no hardware qdisc. */
	assert(cdx_wg_can_tx(&port));
	/* A tree takes the port: its frames have to go through the class
	 * queues, so the fast path yields it to the slow path. */
	port.priv.ceetm_en = true;
	assert(!cdx_wg_can_tx(&port));
	/* The tree goes: the port is the fast path's again. */
	port.priv.ceetm_en = false;
	assert(cdx_wg_can_tx(&port));

	puts("WireGuard fast path: sends from table ports, yields an owned port");
	return 0;
}
