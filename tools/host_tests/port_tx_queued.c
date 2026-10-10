/* What is queued for a registered Ethernet port to send, as port_tx_queued()
 * reads it from QMan: the driver's transmit queues, each once, and CDX's
 * forwarding and SEC-output queues to the port, the ones made; nothing on a
 * port a hardware qdisc owns, whose class queues count no bytes.
 */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

typedef uint32_t u32;
typedef uint64_t u64;
#define CONFIG_CPE_FAST_PATH 1
#define DPAA_FWD_TX_QUEUES 8

struct list_head { struct list_head *next, *prev; };
#define container_of(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))
#define list_for_each_entry(pos, head, member)                                  \
    for (pos = container_of((head)->next, typeof(*pos), member);                \
         &pos->member != (head);                                                 \
         pos = container_of(pos->member.next, typeof(*pos), member))

struct qman_fq { u32 fqid; };
struct qm_mcr_queryfq_np { u32 byte_cnt; u32 frm_cnt; };
enum dpa_fq_type { FQ_TYPE_RX_DEFAULT, FQ_TYPE_TX, FQ_TYPE_TX_CONFIRM };
struct dpa_fq { struct qman_fq fq_base; struct list_head list; enum dpa_fq_type fq_type; };
struct dpa_priv_s { struct list_head dpa_fq_list; bool ceetm_en; };
struct net_device { struct dpa_priv_s priv; };
static void *netdev_priv(const struct net_device *dev) { return (void *)&dev->priv; }
struct eth_iface_info {
    struct net_device *net_dev;
    struct qman_fq fwd_tx_fqinfo[DPAA_FWD_TX_QUEUES];
    struct qman_fq sec_tx_fqinfo[DPAA_FWD_TX_QUEUES];
};

/* QMan's counts by FQID, how often each was asked, and one that fails. */
static struct { u32 frames, bytes; int asked; } fqs[64];
static u32 failing;
static int qman_query_fq_np(struct qman_fq *fq, struct qm_mcr_queryfq_np *np)
{
    assert(fq->fqid && fq->fqid < 64);
    fqs[fq->fqid].asked++;
    if (fq->fqid == failing)
        return -EIO;
    np->frm_cnt = fqs[fq->fqid].frames;
    np->byte_cnt = fqs[fq->fqid].bytes;
    return 0;
}

#include "port_tx_queued_production.inc"

static void add(struct net_device *dev, struct dpa_fq *fq, u32 fqid, enum dpa_fq_type type)
{
    struct list_head *head = &dev->priv.dpa_fq_list;

    fq->fq_base.fqid = fqid;
    fq->fq_type = type;
    fq->list.prev = head->prev;
    fq->list.next = head;
    head->prev->next = &fq->list;
    head->prev = &fq->list;
}

int main(void)
{
    static struct net_device dev;
    static struct dpa_fq driver[4];
    static struct eth_iface_info eth = { .net_dev = &dev };
    u64 frames, bytes;

    dev.priv.dpa_fq_list.next = dev.priv.dpa_fq_list.prev = &dev.priv.dpa_fq_list;
    /* Two transmit queues of the driver's, a confirmation queue and a
     * receive queue, which hold nothing sent; two forwarding queues made of
     * eight and one SEC-output queue. */
    add(&dev, &driver[0], 1, FQ_TYPE_TX);
    add(&dev, &driver[1], 2, FQ_TYPE_TX);
    add(&dev, &driver[2], 3, FQ_TYPE_TX_CONFIRM);
    add(&dev, &driver[3], 4, FQ_TYPE_RX_DEFAULT);
    eth.fwd_tx_fqinfo[0].fqid = 10;
    eth.fwd_tx_fqinfo[5].fqid = 11;
    eth.sec_tx_fqinfo[2].fqid = 20;
    for (u32 id = 1; id < 64; id++)
        fqs[id].frames = id, fqs[id].bytes = id * 100;

    assert(port_tx_queued(&eth, &frames, &bytes));
    assert(frames == 1 + 2 + 10 + 11 + 20 && bytes == 100 * frames);
    for (u32 id = 1; id < 64; id++)
        assert(fqs[id].asked == (id == 1 || id == 2 || id == 10 || id == 11 || id == 20));

    /* A queue that cannot be read leaves nothing to go by. */
    failing = 11;
    assert(!port_tx_queued(&eth, &frames, &bytes));
    failing = 0;

    /* A hardware qdisc's class queues count no bytes: nothing is read. */
    for (u32 id = 1; id < 64; id++)
        fqs[id].asked = 0;
    dev.priv.ceetm_en = true;
    assert(!port_tx_queued(&eth, &frames, &bytes));
    for (u32 id = 1; id < 64; id++)
        assert(!fqs[id].asked);

    puts("port_tx_queued: the driver's transmit queues once each, CDX's that were made, none under a qdisc");
    return 0;
}
