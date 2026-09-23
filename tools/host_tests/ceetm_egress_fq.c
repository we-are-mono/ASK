/* Which class queue a (channel, class queue) pair names, and the two readings
 * of its frame queue.
 *
 * There are two, and conflating them is what made this worth pinning. The
 * software Tx path enqueues to the `struct qman_fq` itself; the microcode is
 * handed a *number*, and that number carries the class-queue policer's profile
 * in its top byte. The lookup used to serve the second reading by ORing the
 * byte into the shared object's own fqid -- which every other caller then saw,
 * with no way back, because the clearing branch required the policer to be off.
 *
 * So the invariant here is blunt: asking for the fqid never changes the queue.
 */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint8_t u8; typedef uint32_t u32;
#define CDX_CEETM_MAX_CHANNELS			8
#define CDX_CEETM_MAX_QUEUES_PER_CHANNEL	16
#define DISABLE_POLICER				0
#define ENABLE_POLICER				1
#define ceetm_dbg(...)				do { } while (0)

/* The kernel's fls: one-based index of the highest set bit, zero for zero. */
static int fls(unsigned int x)
{
    int n = 0;
    while (x) { n++; x >>= 1; }
    return n;
}

struct qman_fq { uint32_t fqid; };

struct cq_info {
    struct { struct qman_fq egress_fq; } ceetmfq;
    uint32_t fq_created;
    uint32_t cq_shaper_enable;
    uint8_t  pp_num;
};

struct ceetm_chnl_info {
    struct tQM_context_ctl *qm_ctx;
    struct cq_info cq_info[CDX_CEETM_MAX_QUEUES_PER_CHANNEL];
};

struct tQM_context_ctl { uint32_t chnl_map; };

static struct ceetm_chnl_info qm_chnl_info[CDX_CEETM_MAX_CHANNELS];

/* What a classifier entry hands cdx_get_txfqid(): a mark's egress pair, on a
 * port whose driver state says whether CEETM is on. */
#define ENABLE_EGRESS_QOS
#define DPAA_FWD_TX_QUEUES	16
#define ceetm_err(...)		do { } while (0)
typedef uint32_t U32;
#include "qosmark.inc"
struct dpa_priv_s { bool ceetm_en; void *qm_ctx; };
/* The DPAA driver's ops carry its exported ndo_init; a port of any other
 * driver has ops of its own, and a private area that is not a dpa_priv_s --
 * here, one whose every read is caught. */
struct net_device;
struct net_device_ops { int (*ndo_init)(struct net_device *dev); };
static int dpa_ndo_init(struct net_device *dev) { return 0; }
static int other_ndo_init(struct net_device *dev) { return 0; }
static const struct net_device_ops dpa_ops = { .ndo_init = dpa_ndo_init };
static const struct net_device_ops other_ops = { .ndo_init = other_ndo_init };
struct net_device { const struct net_device_ops *netdev_ops; struct dpa_priv_s priv; };
static unsigned foreign_reads;
static struct dpa_priv_s *netdev_priv(struct net_device *dev)
{
    if (dev->netdev_ops != &dpa_ops)
        foreign_reads++;
    return &dev->priv;
}
struct eth_iface_info {
    struct net_device *net_dev;
    struct qman_fq fwd_tx_fqinfo[DPAA_FWD_TX_QUEUES];
};
/* A hardware qdisc owning the port, reduced to the answer it gives: whether
 * it owns it, and where a mark with no class goes there. Its own resolution
 * is compiled in htb_offload.c. */
static bool tree_live;
static uint32_t tree_channel, tree_cq;
static unsigned tree_asked;
static bool cdx_htb_resolve_class(struct tQM_context_ctl *qm_ctx, uint32_t *channel,
                                  uint32_t *cq)
{
    assert(qm_ctx);
    tree_asked++;
    if (!tree_live)
        return false;
    if (!*channel && !*cq) {
        *channel = tree_channel;
        *cq = tree_cq;
    }
    return true;
}

#include "egress_fq_production.inc"

static struct tQM_context_ctl port, other;

/* Channel `ch' (zero-based), class queue `cq', carrying `fqid'. */
static void provide(unsigned ch, unsigned cq, uint32_t fqid,
                    struct tQM_context_ctl *owner)
{
    qm_chnl_info[ch].qm_ctx = owner;
    qm_chnl_info[ch].cq_info[cq].fq_created = 1;
    qm_chnl_info[ch].cq_info[cq].ceetmfq.egress_fq.fqid = fqid;
}

int main(void)
{
    memset(qm_chnl_info, 0, sizeof(qm_chnl_info));
    /* This port owns channels 0 and 2, so "whichever channel this port owns"
     * is 2 -- the highest, which is what fls() picks out. */
    port.chnl_map = (1u << 0) | (1u << 2);
    other.chnl_map = (1u << 1);
    provide(0, 3, 0x000123, &port);
    provide(2, 5, 0x000456, &port);
    provide(1, 5, 0x000789, &other);

    /* A named channel is one-based, the way the conntrack mark numbers them. */
    struct qman_fq *fq = ceetm_get_egressfq(&port, 1, 3);
    assert(fq && fq->fqid == 0x000123);
    /* Channel zero means the port's own, which here is channel 2. */
    fq = ceetm_get_egressfq(&port, 0, 5);
    assert(fq && fq->fqid == 0x000456);
    /* A channel this port does not own answers for nobody, even though the
     * channel exists and the queue on it does. */
    assert(ceetm_get_egressfq(&port, 2, 5) == NULL);
    assert(ceetm_get_egressfq(&other, 2, 5) != NULL);

    /* Nothing created, no map, out of range. */
    assert(ceetm_get_egressfq(&port, 1, 4) == NULL);
    assert(ceetm_get_egressfq(&port, 1, CDX_CEETM_MAX_QUEUES_PER_CHANNEL) == NULL);
    assert(ceetm_get_egressfq(&port, CDX_CEETM_MAX_CHANNELS + 1, 3) == NULL);
    assert(ceetm_get_egressfq(NULL, 1, 3) == NULL);
    struct tQM_context_ctl empty = { .chnl_map = 0 };
    assert(ceetm_get_egressfq(&empty, 1, 3) == NULL);

    /* ---- the two readings ---- */

    /* With no class-queue policer the number is the queue's own fqid. */
    assert(ceetm_egress_fqid(&port, 1, 3) == 0x000123);
    assert(ceetm_egress_fqid(&port, 0, 5) == 0x000456);
    assert(ceetm_egress_fqid(&port, 1, 4) == 0);
    assert(ceetm_egress_fqid(&port, 2, 5) == 0);

    /* With one, the profile number rides in the top byte -- of the value. */
    qm_chnl_info[0].cq_info[3].cq_shaper_enable = ENABLE_POLICER;
    qm_chnl_info[0].cq_info[3].pp_num = 0x2a;
    assert(ceetm_egress_fqid(&port, 1, 3) == 0x2a000123);

    /* And the queue is untouched by having been asked. This is the whole
     * point: the software Tx path enqueues to this object, and a policer
     * profile number in its fqid is not a frame queue. */
    fq = ceetm_get_egressfq(&port, 1, 3);
    assert(fq->fqid == 0x000123);
    /* Asking repeatedly does not accumulate, either. */
    assert(ceetm_egress_fqid(&port, 1, 3) == 0x2a000123);
    assert(ceetm_egress_fqid(&port, 1, 3) == 0x2a000123);
    assert(fq->fqid == 0x000123);

    /* Turning the policer off is enough to clear the byte, without anything
     * having to remember to undo a write. Under the old lookup this was an
     * `else if' that a fast-path call could skip entirely. */
    qm_chnl_info[0].cq_info[3].cq_shaper_enable = DISABLE_POLICER;
    assert(ceetm_egress_fqid(&port, 1, 3) == 0x000123);
    assert(fq->fqid == 0x000123);

    /* A queue whose stored fqid already has a top byte -- the state the old
     * lookup could leave behind -- is still reported as the hardware's, not
     * doubled up with a second profile number. */
    qm_chnl_info[2].cq_info[5].ceetmfq.egress_fq.fqid = 0x99000456;
    qm_chnl_info[2].cq_info[5].cq_shaper_enable = ENABLE_POLICER;
    qm_chnl_info[2].cq_info[5].pp_num = 0x07;
    assert(ceetm_egress_fqid(&port, 0, 5) == 0x07000456);

    /* ---- what a classifier entry is given ---- */

    qm_chnl_info[2].cq_info[5].ceetmfq.egress_fq.fqid = 0x000456;
    qm_chnl_info[2].cq_info[5].cq_shaper_enable = DISABLE_POLICER;
    provide(2, 0, 0x000400, &port);
    provide(0, 7, 0x000107, &port);
    struct net_device dev = { .netdev_ops = &dpa_ops,
                              .priv = { .ceetm_en = true, .qm_ctx = &port } };
    struct eth_iface_info eth = { .net_dev = &dev };
    union ctentry_qosmark none = { .markval = 0 }, named = { .markval = 0 };

    named.chnl_id = 1;
    named.queue = 7;
    /* No qdisc: a mark with no class is the port's own channel, queue 0, as
     * it has always been; a named pair is itself. */
    tree_live = false;
    assert(cdx_get_txfqid(&eth, &none) == 0x000400);
    assert(cdx_get_txfqid(&eth, &named) == 0x000107);
    /* A qdisc owns the port: the entry is built with what the tree says a
     * class means there -- the default leaf, for no class -- which is the
     * queue the software path puts the same flow's frames on. That covers
     * every caller of this, flows, multicast members and SAs alike. */
    tree_live = true;
    tree_channel = 3;
    tree_cq = 5;
    tree_asked = 0;
    assert(cdx_get_txfqid(&eth, &none) == 0x000456);
    assert(cdx_get_txfqid(&eth, &named) == 0x000107);
    assert(tree_asked == 2);
    /* And the mark itself is never rewritten on the way. */
    assert(!none.chnl_id && !none.queue && named.chnl_id == 1 && named.queue == 7);
    /* Without CEETM on the port neither the tree nor the channels apply. */
    dev.priv.ceetm_en = false;
    eth.fwd_tx_fqinfo[7].fqid = 0x77;
    tree_asked = 0;
    assert(cdx_get_txfqid(&eth, &named) == 0x77 && !tree_asked);

    /* A port whose netdev is not the DPAA driver's has no queue here, and
     * its private area is never read as a DPAA port's -- nor is that of a
     * record with no netdev at all, or one with no ops. */
    struct net_device foreign = { .netdev_ops = &other_ops,
                                  .priv = { .ceetm_en = true, .qm_ctx = &port } };
    struct eth_iface_info other_eth = { .net_dev = &foreign };
    other_eth.fwd_tx_fqinfo[7].fqid = 0x99;
    assert(cdx_get_txfqid(&other_eth, &named) == 0 && !tree_asked && !foreign_reads);
    foreign.netdev_ops = NULL;
    assert(cdx_get_txfqid(&other_eth, &named) == 0 && !foreign_reads);
    other_eth.net_dev = NULL;
    assert(cdx_get_txfqid(&other_eth, &named) == 0);
    assert(dpa_netdev_is_dpaa(&dev) && !dpa_netdev_is_dpaa(NULL));

    puts("CEETM egress fq: channel resolution, bounds, an fqid reading that "
         "leaves the queue alone, and the tree's answer for a classifier entry");
    return 0;
}
