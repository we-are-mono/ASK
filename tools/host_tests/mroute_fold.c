/* The routed counter fold, compiled from cdx/ask_flowtable.c, against the one
 * thing it writes: an MFC entry's counters, which ipmr writes too. */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#define FT_MR_OIF_TEXT 136
#define CDX_MC_MAX_LISTENERS 8
#define CDX_FT_VLAN_MAX 2
#define ETH_HLEN 14
#define VLAN_HLEN 4
#define WRITE_ONCE(x, v) ((x) = (v))
#define min_t(t, a, b) ((t)(a) < (t)(b) ? (t)(a) : (t)(b))
typedef struct { long counter; } atomic_long_t;
static inline long atomic_long_read(const atomic_long_t *v) { return v->counter; }
static inline void atomic_long_set(atomic_long_t *v, long i) { v->counter = i; }
static inline void atomic_long_add(long i, atomic_long_t *v) { v->counter += i; }
static unsigned long jiffies = 1000;
struct list_head { struct list_head *next, *prev; };
struct net_device { int unused; };
struct mr_mfc {
    struct { struct { atomic_long_t pkt, bytes; unsigned long lastuse; } res; } mfc_un;
};
union nf_inet_addr { u32 all[4]; };
struct cdx_ft_vlan { u16 proto, id; };
struct cdx_mc_listener { struct net_device *dev; struct cdx_ft_vlan vlan[2]; u8 vlans; };
struct cdx_mc_group_spec {
    struct net_device *in;
    struct cdx_mc_listener listener[8];
    u8 listeners, family;
    union nf_inet_addr src, dst;
};
struct cdx_mc_group { int unused; };
struct cdx_ft_counters { u64 packets, bytes; };
#include "mroute_types.inc"
#include "mroute_fold.inc"

/* An IPv4 datagram of the rig's streams, and the untagged frame carrying it. */
#define L3 184
#define FRAME (ETH_HLEN + L3)

/* What ip_mr_forward() does for every packet the CPU forwards. */
static void cpu_forwards(struct mr_mfc *mfc, long n)
{
    atomic_long_add(n, &mfc->mfc_un.res.pkt);
    atomic_long_add(n * L3, &mfc->mfc_un.res.bytes);
}

static void counted(const struct mr_mfc *mfc, long packets)
{
    assert(atomic_long_read(&mfc->mfc_un.res.pkt) == packets);
    assert(atomic_long_read(&mfc->mfc_un.res.bytes) == packets * L3);
}

/* What the worker does when it adopts a group cdx_mc_group_add() just made. */
static void adopted(struct ft_mr_group *g, struct cdx_mc_group *hw)
{
    g->hw = hw;
    g->folded_packets = g->folded_bytes = 0;
    g->fold_suspect = false;
}

/* What ft_mr_counters() decides before a fold: only a group something in
 * hardware carries has a count to fold, with its own ingress framing. */
static void fold(struct ft_mr_group *g, const struct cdx_ft_counters *c)
{
    if (g->hw)
        ft_mr_fold(g, c, g->in_tags);
}

int main(void)
{
    struct mr_mfc mfc;
    struct cdx_mc_group first, second;
    struct ft_mr_group g;
    struct cdx_ft_counters hw = { 0, 0 };

    memset(&mfc, 0, sizeof(mfc));
    memset(&g, 0, sizeof(g));
    g.mfc = &mfc;

    /* The CPU forwards the packets that resolved the entry and every one
     * before the worker installs it. With no hardware group there is
     * nothing to fold. */
    cpu_forwards(&mfc, 10);
    fold(&g, &hw);
    counted(&mfc, 10);

    /* Installed: a fresh group's zero adds nothing, and erases nothing. */
    adopted(&g, &first);
    fold(&g, &hw);
    counted(&mfc, 10);
    hw = (struct cdx_ft_counters){ 5, 5 * FRAME };
    jiffies = 2000;
    fold(&g, &hw);
    counted(&mfc, 15);
    assert(mfc.mfc_un.res.lastuse == 2000);
    /* Folding the same counts twice is not new traffic, and not new use. */
    jiffies = 3000;
    fold(&g, &hw);
    counted(&mfc, 15);
    assert(mfc.mfc_un.res.lastuse == 2000);

    /* Refused: the hardware group goes and the CPU carries three more. */
    g.hw = NULL;
    cpu_forwards(&mfc, 3);
    fold(&g, &hw);
    counted(&mfc, 18);

    /* Admitted again: a new hardware group, counting from zero. The entry's
     * count may not go back to it. */
    adopted(&g, &second);
    hw = (struct cdx_ft_counters){ 0, 0 };
    fold(&g, &hw);
    counted(&mfc, 18);
    hw = (struct cdx_ft_counters){ 2, 2 * FRAME };
    fold(&g, &hw);
    counted(&mfc, 20);

    /* A tagged ingress: the tag is framing the kernel never counted. */
    g.in_tags = 1;
    hw = (struct cdx_ft_counters){ 6, 2 * FRAME + 4 * (FRAME + VLAN_HLEN) };
    fold(&g, &hw);
    counted(&mfc, 24);

    /* Bytes moved but no packet yet: the two were read apart. Nothing is
     * added now and nothing is lost -- the next fold carries them. */
    hw.bytes += FRAME + VLAN_HLEN;
    fold(&g, &hw);
    counted(&mfc, 24);
    hw.packets += 1;
    fold(&g, &hw);
    counted(&mfc, 25);

    /* A sample below what was already folded is distrusted: no wrap into a
     * huge addition, no jump, and while the next sample is sane the baseline
     * stays where it was -- the low one was the misread, and nothing is
     * counted twice. */
    hw = (struct cdx_ft_counters){ 1, FRAME + VLAN_HLEN };
    fold(&g, &hw);
    counted(&mfc, 25);
    hw = (struct cdx_ft_counters){ 8, 2 * FRAME + 6 * (FRAME + VLAN_HLEN) };
    fold(&g, &hw);
    counted(&mfc, 26);

    /* The other misread: a count high by 2^32 bytes, taken as a carry
     * propagated, is folded and cannot be taken back. Every true sample after
     * it is below the baseline. Distrusting them all would fold nothing, and
     * leave the count and lastuse standing, until 4 GiB more had passed --
     * to a daemon, a stream that stopped. The second one in a row says the
     * baseline is what is wrong, and folding goes on from there. */
    {
        const u64 carry = 1ull << 32;
        long bogus;

        hw.packets += 1;
        hw.bytes += FRAME + VLAN_HLEN + carry;
        fold(&g, &hw);
        bogus = atomic_long_read(&mfc.mfc_un.res.bytes);
        assert(atomic_long_read(&mfc.mfc_un.res.pkt) == 27);
        hw.bytes -= carry;
        hw.packets += 2;
        hw.bytes += 2 * (FRAME + VLAN_HLEN);
        jiffies = 4000;
        fold(&g, &hw);                          /* one below: nothing */
        assert(atomic_long_read(&mfc.mfc_un.res.pkt) == 27);
        hw.packets += 3;
        hw.bytes += 3 * (FRAME + VLAN_HLEN);
        jiffies = 5000;
        fold(&g, &hw);                          /* two: the baseline moves */
        assert(atomic_long_read(&mfc.mfc_un.res.pkt) == 27);
        hw.packets += 4;
        hw.bytes += 4 * (FRAME + VLAN_HLEN);
        jiffies = 6000;
        fold(&g, &hw);                          /* and counting resumes */
        assert(atomic_long_read(&mfc.mfc_un.res.pkt) == 31);
        assert(atomic_long_read(&mfc.mfc_un.res.bytes) == bogus + 4 * L3);
        assert(mfc.mfc_un.res.lastuse == 6000);
        assert(!g.fold_suspect);
    }
    return 0;
}
