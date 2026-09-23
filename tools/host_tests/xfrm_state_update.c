/* The kernel's rule for copying an update's encapsulation into a live state,
 * against states built here. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

typedef uint16_t __be16;

enum { XFRM_DEV_OFFLOAD_UNSPECIFIED, XFRM_DEV_OFFLOAD_CRYPTO, XFRM_DEV_OFFLOAD_PACKET };

struct xfrm_encap_tmpl { uint16_t encap_type; __be16 encap_sport, encap_dport; };
struct xfrm_state {
	struct { int type; } xso;
	struct xfrm_encap_tmpl *encap;
};

#include "xfrm_state_update.inc"

int main(void)
{
	struct xfrm_encap_tmpl live = { 2, 4500, 31000 }, same = live;
	struct xfrm_encap_tmpl sport = { 2, 4501, 31000 }, dport = { 2, 4500, 31001 };
	struct xfrm_state x1 = { .encap = &live };
	struct xfrm_state x = { .encap = &same };

	/* A state in software, or one whose hardware only encrypts, takes any
	 * ports: the stack writes them itself. */
	for (int type = XFRM_DEV_OFFLOAD_UNSPECIFIED; type <= XFRM_DEV_OFFLOAD_CRYPTO; type++) {
		x1.xso.type = type;
		x.encap = &sport;
		assert(xfrm_state_update_encap_ok(&x1, &x));
		x.encap = &dport;
		assert(xfrm_state_update_encap_ok(&x1, &x));
	}

	/* A packet-offloaded state keeps its ports or refuses the update. */
	x1.xso.type = XFRM_DEV_OFFLOAD_PACKET;
	x.encap = &same;
	assert(xfrm_state_update_encap_ok(&x1, &x));
	x.encap = &sport;
	assert(!xfrm_state_update_encap_ok(&x1, &x));
	x.encap = &dport;
	assert(!xfrm_state_update_encap_ok(&x1, &x));
	return 0;
}
