/* The IPsec backend's NAT-T port store, compiled from cdx/cdx_ipsec_backend.c.
 * The spec carries the ports in network order, as xfrm hands them over; the SA
 * cache keeps them in host order, which is what the ESP-in-UDP header and the
 * inbound classifier key are built from. */
#include <assert.h>
#include <stdint.h>

typedef uint16_t __be16;

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define be16_to_cpu(x) ((uint16_t)__builtin_bswap16((uint16_t)(x)))
#define cpu_to_be16(x) ((__be16)__builtin_bswap16((uint16_t)(x)))
#else
#define be16_to_cpu(x) ((uint16_t)(x))
#define cpu_to_be16(x) ((__be16)(x))
#endif

#include "ipsec_backend_natt.inc"

int main(void)
{
	unsigned short sport = 0, dport = 0;

	/* Asymmetric, so a swap of the two shows as well as a byte swap. */
	cdx_ipsec_set_natt(&sport, &dport, cpu_to_be16(4500), cpu_to_be16(61000));
	assert(sport == 4500 && dport == 61000);
	return 0;
}
