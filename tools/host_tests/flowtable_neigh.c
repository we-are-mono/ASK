/* Compile the kernel's destination check, including the bind-race guard. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define READ_ONCE(x) (x)
enum { FLOW_OFFLOAD_XMIT_NEIGH, FLOW_OFFLOAD_XMIT_XFRM,
       FLOW_OFFLOAD_XMIT_DIRECT, FLOW_OFFLOAD_XMIT_TC };
struct nf_flowtable { bool use_neigh; };
struct dst_entry { unsigned cookie; };
struct flow_offload_tuple {
    unsigned xmit_type;
    union {
        struct { struct dst_entry *dst_cache; unsigned dst_cookie; };
        uintptr_t direct[2];
    };
};
static unsigned checks;
static struct dst_entry destination = {42};
static struct dst_entry *dst_check(struct dst_entry *dst, unsigned cookie)
{
    assert(dst == &destination); /* A DIRECT union never contains a dst. */
    checks++;
    return cookie == dst->cookie ? dst : NULL;
}
#include "neigh_fallback_production.inc"

int main(void)
{
    struct nf_flowtable table = {0};
    struct flow_offload_tuple tuple = { .xmit_type = FLOW_OFFLOAD_XMIT_DIRECT,
                                       .direct = {1, 2} };
    assert(nf_flow_dst_check(&table, &tuple) && !checks); /* Legacy unchanged. */
    assert(nf_flow_offload_dst(&tuple) == NULL);
    table.use_neigh = true; /* DIRECT construction overlapped with binding. */
    assert(!nf_flow_dst_check(&table, &tuple) && !checks);
    tuple.xmit_type = FLOW_OFFLOAD_XMIT_TC;
    assert(nf_flow_offload_dst(&tuple) == NULL);
    assert(nf_flow_dst_check(&table, &tuple) && !checks);
    for (unsigned mode = 0; mode < 2; mode++) {
        table.use_neigh = mode;
        for (unsigned type = FLOW_OFFLOAD_XMIT_NEIGH; type <= FLOW_OFFLOAD_XMIT_XFRM; type++) {
            tuple.xmit_type = type;
            tuple.dst_cache = &destination; tuple.dst_cookie = 42;
            /* Both keep a destination in that union, and both hand it
             * over. flow_offload_fill_route() fills NEIGH and XFRM from the
             * same branch, so refusing to show a transformed one to the
             * driver would be refusing the flow rather than describing it --
             * and refusing it is how a tunnel ends up carried in software. */
            assert(nf_flow_offload_dst(&tuple) == &destination);
            assert(nf_flow_dst_check(&table, &tuple));
            tuple.dst_cookie = 41;
            assert(!nf_flow_dst_check(&table, &tuple));
        }
    }
    assert(checks == 8);
}
