/* The kernel's rule for copying an update into a live packet-offloaded
 * state, against states built here. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

typedef uint16_t __be16;
typedef uint32_t u32;

enum { XFRM_DEV_OFFLOAD_UNSPECIFIED, XFRM_DEV_OFFLOAD_CRYPTO, XFRM_DEV_OFFLOAD_PACKET };

struct xfrm_mark { u32 v, m; };
struct xfrm_encap_tmpl { uint16_t encap_type; __be16 encap_sport, encap_dport; };
struct xfrm_state {
	struct { int type; } xso;
	struct { struct xfrm_mark smark; } props;
	struct xfrm_encap_tmpl *encap;
};

#include "xfrm_state_update.inc"

int main(void)
{
	struct xfrm_encap_tmpl live = { 2, 4500, 31000 }, same = live;
	struct xfrm_encap_tmpl sport = { 2, 4501, 31000 }, dport = { 2, 4500, 31001 };
	const struct xfrm_mark mark = { 0x10, 0xffffffff };
	struct xfrm_state x1 = { .encap = &live, .props.smark = mark };
	struct xfrm_state x = { .encap = &same };

	/* A state in software, or one whose hardware only encrypts, takes any
	 * ports and any mark: the stack applies both itself. */
	for (int type = XFRM_DEV_OFFLOAD_UNSPECIFIED; type <= XFRM_DEV_OFFLOAD_CRYPTO; type++) {
		x1.xso.type = type;
		x.encap = &sport;
		assert(xfrm_state_update_offload_ok(&x1, &x));
		x.encap = &dport;
		assert(xfrm_state_update_offload_ok(&x1, &x));
		x.encap = &same;
		x.props.smark = (struct xfrm_mark){ 0x20, 0xffffffff };
		assert(xfrm_state_update_offload_ok(&x1, &x));
		x.props.smark = (struct xfrm_mark){ 0 };
	}

	/* A packet-offloaded state keeps its ports or refuses the update. */
	x1.xso.type = XFRM_DEV_OFFLOAD_PACKET;
	x.encap = &same;
	assert(xfrm_state_update_offload_ok(&x1, &x));
	x.encap = &sport;
	assert(!xfrm_state_update_offload_ok(&x1, &x));
	x.encap = &dport;
	assert(!xfrm_state_update_offload_ok(&x1, &x));
	x.encap = &same;

	/* Likewise its output mark: the same value and mask, or none named,
	 * which keeps the state's. Either half changing is refused. */
	x.props.smark = mark;
	assert(xfrm_state_update_offload_ok(&x1, &x));
	x.props.smark = (struct xfrm_mark){ 0 };
	assert(xfrm_state_update_offload_ok(&x1, &x));
	x.props.smark = (struct xfrm_mark){ 0x20, 0xffffffff };
	assert(!xfrm_state_update_offload_ok(&x1, &x));
	x.props.smark = (struct xfrm_mark){ 0x10, 0xf0 };
	assert(!xfrm_state_update_offload_ok(&x1, &x));
	/* A mark on a state that had none is a change too. */
	x1.props.smark = (struct xfrm_mark){ 0 };
	x.props.smark = mark;
	assert(!xfrm_state_update_offload_ok(&x1, &x));

	/* A state without encapsulation, updated without one, has no ports
	 * to compare. */
	x1.encap = x.encap = 0;
	x.props.smark = (struct xfrm_mark){ 0 };
	assert(xfrm_state_update_offload_ok(&x1, &x));
	return 0;
}
