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

    puts("CEETM egress fq: channel resolution, bounds, and an fqid reading "
         "that leaves the queue alone");
    return 0;
}
