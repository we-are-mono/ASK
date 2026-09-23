/* The DSCP map's per-frame lookup, compiled from cdx_ceetm_app.c.
 *
 * The table is freed with kfree_rcu() once a port's last filter goes, and the
 * transmit path reads it per frame. The lookup takes its own read-side section
 * rather than trusting whoever called it to be inside one; a dereference
 * outside a section fails here.
 */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#define READ_ONCE(x) (x)
struct rcu_head { void *next; };
struct qman_fq { int id; };
#include "dscp_fq_types.inc"
struct tQM_context_ctl { struct qm_dscp_fq_map *dscp_fq_map; };

static int bh_depth;
static void rcu_read_lock_bh(void) { bh_depth++; }
static void rcu_read_unlock_bh(void) { assert(bh_depth > 0); bh_depth--; }
#define rcu_dereference_bh(p) ({ assert(bh_depth > 0); (p); })

#include "dscp_fq_production.inc"

int main(void)
{
    static struct qm_dscp_fq_map map;
    struct qman_fq ef = { 46 };
    struct tQM_context_ctl port = { 0 };

    /* No map published: nothing, and no section left open. */
    assert(!ceetm_get_dscp_fq(&port, 46) && !bh_depth);
    port.dscp_fq_map = &map;
    map.dscp_fq[46] = &ef;
    assert(ceetm_get_dscp_fq(&port, 46) == &ef && !bh_depth);
    assert(!ceetm_get_dscp_fq(&port, 45) && !bh_depth);
    /* Not a codepoint: refused before the table is touched. */
    assert(!ceetm_get_dscp_fq(&port, MAX_DSCP) && !bh_depth);
    return 0;
}
