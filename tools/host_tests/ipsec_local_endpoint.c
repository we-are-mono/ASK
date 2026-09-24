/* The backend's install-time rule that an inbound SA's local endpoint is an
 * address on the port the SA is bound to, compiled from the backend. The
 * address lookup and the port records are stubs that say where an address
 * lives. */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef uint32_t U32;
#define EOPNOTSUPP 95
#define EADDRNOTAVAIL 99
#define AF_INET 2
#define AF_INET6 10
#define SUCCESS 0
#define FAILURE -1
enum { PROTO_IPV4 = 0, PROTO_IPV6 };

#include "ipsec_local_endpoint_types.inc"

struct net_device { const char *name; };
struct dpa_iface_info { uint32_t itf_id; };
/* The fields the rule reads; the rest of the spec is the backend's. */
struct cdx_ipsec_sa_spec { struct net_device *dev; unsigned short family; enum cdx_ipsec_dir dir; };

static struct net_device eth3 = { "eth3" }, eth4 = { "eth4" }, dummy = { "dummy0" };
static struct dpa_iface_info eth3_record = { 3 }, eth4_record = { 4 };
/* Where the looked-up address is: an interface id, or nowhere. */
static int found_on;
static unsigned lookups;
static U32 *asked;
static int asked_family;

static struct dpa_iface_info *dpa_get_ifinfo_by_netdev(const struct net_device *dev)
{
	return dev == &eth3 ? &eth3_record : dev == &eth4 ? &eth4_record : NULL;
}

static int dpa_get_iface_info_by_ipaddress(int family, uint32_t *daddr, uint32_t *tx_fqid,
					   uint32_t *itf_id, uint32_t *portid, uint32_t hash)
{
	(void)hash;
	assert(!tx_fqid && !portid && itf_id);
	lookups++;
	asked = daddr;
	asked_family = family;
	if (found_on < 0)
		return FAILURE;
	*itf_id = (uint32_t)found_on;
	return SUCCESS;
}

#include "ipsec_local_endpoint.inc"

int main(void)
{
	U32 daddr[4] = { 0x0a00003e };
	struct cdx_ipsec_sa_spec in = { &eth4, AF_INET, CDX_IPSEC_DIR_IN };
	struct cdx_ipsec_sa_spec out = { &eth4, AF_INET, CDX_IPSEC_DIR_OUT };

	/* The endpoint on the bound port: accepted, asked by the SA's own
	 * address and family. */
	found_on = 4;
	assert(cdx_ipsec_local_on_port(&in, daddr) == 0);
	assert(lookups == 1 && asked == daddr && asked_family == PROTO_IPV4);
	in.family = AF_INET6;
	assert(cdx_ipsec_local_on_port(&in, daddr) == 0 && asked_family == PROTO_IPV6);
	in.family = AF_INET;

	/* On another port, on a Wi-Fi VAP's record, or on no registered port
	 * at all: refused, each for the same reason. */
	found_on = 3;
	assert(cdx_ipsec_local_on_port(&in, daddr) == -EADDRNOTAVAIL);
	found_on = 17;
	assert(cdx_ipsec_local_on_port(&in, daddr) == -EADDRNOTAVAIL);
	found_on = -1;
	assert(cdx_ipsec_local_on_port(&in, daddr) == -EADDRNOTAVAIL);

	/* A bound device with no port record cannot be carried at all. */
	in.dev = &dummy;
	found_on = 4;
	assert(cdx_ipsec_local_on_port(&in, daddr) == -EOPNOTSUPP);

	/* The rule is the inbound SA's: an outbound one is not asked. */
	lookups = 0;
	found_on = 3;
	assert(cdx_ipsec_local_on_port(&out, daddr) == 0 && !lookups);
	return 0;
}
