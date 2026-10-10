/* What a registered Ethernet port's standard counters report while CDX holds
 * it.
 *
 * Transmit is what the port's MAC sent: an offloaded frame was counted when the
 * classifier enqueued it, before QMan decided, and one an egress congestion
 * group refused never left. So the netdev's own counts as CDX took the port --
 * or what the port reported at the first reading of it that stood still -- carry on
 * by the MAC's advance since, whatever the enqueue counted. Receive
 * adds what the port's own enqueues lost to a congestion group, as drops, and
 * what it found no buffer for, as misses, from 32-bit BMI counts carried past
 * their wrap.
 */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t s64;
#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))
typedef void *t_Handle;
#define __iomem
#define RX 0
#define ETH_FCS_LEN 4
#define ETH_HLEN 14
#define ETH_ZLEN 60
#define CDX_IFSTATS_PORT_RX_OVERHEAD ETH_HLEN
#define printk(...) do { } while (0)
typedef enum { e_FM_PORT_COUNTERS_DISCARD_FRAME = 7,
               e_FM_PORT_COUNTERS_RX_OUT_OF_BUFFERS_DISCARD = 13 } e_FmPortCounters;

#include "port_counters_flags.inc"

struct rtnl_link_stats64 {
    u64 rx_packets, tx_packets, rx_bytes, tx_bytes, rx_dropped, tx_dropped, rx_missed_errors;
};
struct cdx_ft_stats { u64 bytes, packets; };
/* The mEMAC's transmit counters and its receive drops, each two 32-bit halves. */
struct memac_regs {
    u32 toct_l, toct_u, tfrm_l, tfrm_u, txpf_l, txpf_u;
    u32 tuca_l, tuca_u, tmca_l, tmca_u, tbca_l, tbca_u;
    u32 rdrp_l, rdrp_u;
};
struct fm_port_model { u32 discards, no_buffer; };
typedef struct { t_Handle h_Dev; } t_LnxWrpFmPortDev;
/* The SDK driver sets link and speed at probe -- down, and the MAC's fastest --
 * and never again: they say nothing of the link. */
struct mac_device { void *port_dev[2]; void *vaddr; bool link; uint16_t speed, max_speed; };
struct dpa_priv_s { struct mac_device *mac_dev; };
struct net_device;
struct net_device_ops { void (*ndo_get_stats64)(struct net_device *, struct rtnl_link_stats64 *); };
struct net_device {
    char name[16]; struct dpa_priv_s priv; bool dpaa; const struct net_device_ops *netdev_ops;
    unsigned int mtu;
};
#define VLAN_ETH_HLEN 18
#define VLAN_HLEN 4
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define READ_ONCE(x) (x)

#include "port_counters_types.inc"

struct dpa_iface_info {
    struct dpa_iface_info *next;
    u32 if_flags;
    char name[16];
    struct eth_iface_info eth_info;
    void *stats;
};

static struct dpa_iface_info *dpa_interface_info;
static int dpa_devlist_lock, locked;
static void spin_lock(int *lock) { assert(lock == &dpa_devlist_lock && !locked); locked = 1; }
static void spin_unlock(int *lock) { assert(lock == &dpa_devlist_lock && locked); locked = 0; }
static bool dpa_netdev_is_dpaa(const struct net_device *dev) { return dev && dev->dpaa; }
static void *netdev_priv(const struct net_device *dev) { return (void *)&dev->priv; }
/* Time passes only where the code waits; a frame on its way to the MAC's count
 * gets there once enough of it has (transit_advance(), below). */
typedef u64 ktime_t;
static u64 now_us;
static ktime_t ktime_get(void) { return now_us; }
static long long ktime_us_delta(ktime_t later, ktime_t earlier) { return (long long)(later - earlier); }
static void transit_advance(unsigned long us);
static void queue_take(unsigned long us);
static void udelay(unsigned long us) { now_us += us; transit_advance(us); queue_take(us); }

/* The MAC: what it has sent, kept whole, and served in halves. A carry may be
 * due between an upper half's read and the lower's. As measured on the rig,
 * its own PAUSE frames are among its good frames (TFRM) and octets (TOCT), and
 * not among its unicast, multicast or broadcast ones. It also drops frames it
 * received, when its FIFO is full. */
static struct { u64 unicast, multicast, broadcast, octets, pause, rx_dropped; } mac;
static struct memac_regs regs;
static int carry_on_read;
/* Something the MAC sends while a reading is under way: on the given register
 * read of it, counted from the reading's first. */
enum { NOTHING, PAUSE, DATA };
static int inject_what;
static unsigned inject_at, inject_every, reads;
static void halves(u32 *low, u32 *high, u64 value) { *low = (u32)value; *high = (u32)(value >> 32); }
static u32 ioread32be(const u32 *reg)
{
    if (reg == &regs.toct_l && carry_on_read && !--carry_on_read)
        mac.octets += 0x100;    /* the lower half wraps between the reads */
    if (inject_what != NOTHING &&
        (++reads == inject_at || (inject_every && reads % inject_every == 0))) {
        if (inject_what == PAUSE)
            mac.pause++, mac.octets += 64;
        else
            mac.unicast++, mac.octets += 1000 + ETH_FCS_LEN;
    }
    halves(&regs.toct_l, &regs.toct_u, mac.octets);
    halves(&regs.tfrm_l, &regs.tfrm_u, mac.unicast + mac.multicast + mac.broadcast + mac.pause);
    halves(&regs.txpf_l, &regs.txpf_u, mac.pause);
    halves(&regs.tuca_l, &regs.tuca_u, mac.unicast);
    halves(&regs.tmca_l, &regs.tmca_u, mac.multicast);
    halves(&regs.tbca_l, &regs.tbca_u, mac.broadcast);
    halves(&regs.rdrp_l, &regs.rdrp_u, mac.rx_dropped);
    return *reg;
}
/* Frames FMan has taken from a queue, of `bytes' each, which the MAC counts
 * one at a time once each is on the wire: the first `left_us' from now, each
 * after it `frame_us' later. */
static struct { u64 frames, bytes, left_us, frame_us; } transit;
static void transit_advance(unsigned long us)
{
    while (transit.frames && us >= transit.left_us) {
        us -= transit.left_us;
        mac.unicast++;
        mac.octets += transit.bytes + ETH_FCS_LEN;
        transit.frames--;
        transit.left_us = transit.frame_us;
    }
    if (transit.frames)
        transit.left_us -= us;
}
static struct fm_port_model rx_port;
static t_LnxWrpFmPortDev rx_wrapper = { .h_Dev = &rx_port };
static u32 FM_PORT_GetCounter(t_Handle h, e_FmPortCounters counter)
{
    assert(h == &rx_port);
    if (counter == e_FM_PORT_COUNTERS_DISCARD_FRAME)
        return rx_port.discards;
    assert(counter == e_FM_PORT_COUNTERS_RX_OUT_OF_BUFFERS_DISCARD);
    return rx_port.no_buffer;
}

/* The driver's own counts, which dev_get_stats() starts from. */
static u64 driver_tx, driver_tx_bytes;
static void dpa_get_stats64(struct net_device *dev, struct rtnl_link_stats64 *s)
{
    (void)dev;
    s->tx_packets += driver_tx;
    s->tx_bytes += driver_tx_bytes;
}
static const struct net_device_ops dpa_ops = { .ndo_get_stats64 = dpa_get_stats64 };

/* The record the enqueue and UPDATE_ETH_RX_STATS count into. */
static struct cdx_ft_stats record_rx, record_tx;
static void cdx_ifstats_read(const void *record, struct cdx_ft_stats *rx, struct cdx_ft_stats *tx)
{
    assert(record && locked);
    *rx = record_rx;
    *tx = record_tx;
}
static void cdx_ifstats_fold(struct rtnl_link_stats64 *storage, u64 rx_bytes, u64 rx_packets,
                             u64 tx_bytes, u64 tx_packets, unsigned rx_overhead, unsigned tx_overhead)
{
    assert(rx_overhead == ETH_HLEN && !tx_overhead);
    storage->rx_packets += rx_packets;
    storage->rx_bytes += rx_bytes - rx_packets * rx_overhead;
    storage->tx_packets += tx_packets;
    storage->tx_bytes += tx_bytes;
}
static void cdx_ft_ifstats_fold(const struct net_device *dev, struct rtnl_link_stats64 *storage)
{
    (void)dev; (void)storage;
    assert(!locked);
}

/* What the kernel has enqueued for the port and FMan not yet taken, in frames
 * and bytes, as QMan's queue counts read; none readable on a port a hardware
 * qdisc owns. `enqueue_on_read' has the kernel enqueue a frame just after the
 * given reading of them -- the driver counts it, the reading does not -- which
 * a freeze of the kernel's transmit does not stop: the driver sends without
 * the lock it waits on. `offload_on_read' has the classifier enqueue one
 * instead, which the port's record counts. `take_in_gap' has FMan take a frame
 * of `take_bytes' from the queue during the next wait, which the MAC counts
 * only after it. */
static struct {
    u64 frames, bytes, take_bytes;
    bool qdisc;
    int enqueue_on_read, offload_on_read, take_in_gap;
} queue;
static void queue_take(unsigned long us)
{
    if (!queue.take_in_gap || !queue.frames)
        return;
    queue.take_in_gap = 0;
    queue.frames--, queue.bytes -= queue.take_bytes;
    transit.frames++, transit.bytes = queue.take_bytes, transit.left_us = 1;
    (void)us;
}
/* The speed the PHY reports for the link, or none. Read under RTNL and never
 * under dpa_devlist_lock: reading a PHY may sleep. */
static uint32_t phy_speed;
static uint32_t fwd_cgr_link_speed(struct net_device *dev, uint32_t fallback)
{
    (void)dev;
    assert(!locked);
    return phy_speed ?: fallback;
}
/* Resizing a port's egress bound: a QMan management command, which can fail. */
static int cgr_fails;
static int fwd_cgr_set(struct eth_iface_info *eth, uint32_t speed, bool init)
{
    assert(locked && !init);
    if (cgr_fails)
        return -5;
    eth->fwd_cgr_speed = speed;
    eth->fwd_cgr_mtu = eth->net_dev->mtu;
    return 0;
}
#define netdev_warn(dev, ...) do { (void)(dev); } while (0)
static int tx_frozen, frozen_reads, tx_freezes, queue_reads;
static void netif_tx_lock_bh(struct net_device *dev) { (void)dev; assert(!tx_frozen); tx_frozen = 1; tx_freezes++; }
static void netif_tx_unlock_bh(struct net_device *dev) { (void)dev; assert(tx_frozen); tx_frozen = 0; }
static bool port_tx_queued(const struct eth_iface_info *eth, u64 *frames, u64 *bytes)
{
    (void)eth;
    queue_reads++;
    if (queue.qdisc)
        return false;
    frozen_reads += tx_frozen;
    *frames = queue.frames;
    *bytes = queue.bytes;
    if (queue.enqueue_on_read && !--queue.enqueue_on_read) {
        queue.frames++, queue.bytes += 300;
        driver_tx++, driver_tx_bytes += 300;
    }
    if (queue.offload_on_read && !--queue.offload_on_read) {
        queue.frames++, queue.bytes += 800;
        record_tx.packets++, record_tx.bytes += 800;
    }
    return true;
}

#include "port_counters_production.inc"

static struct mac_device mac_dev = { .vaddr = &regs, .link = false, .speed = 10000, .max_speed = 10000 };
static struct net_device eth3 = { .name = "eth3", .dpaa = true, .netdev_ops = &dpa_ops, .mtu = 1500 };
static struct dpa_iface_info port, wifi;
static int record;

/* A port as CDX takes it: the MAC's fastest speed, and the link's at 10G as
 * the statistics hook will have it once the port's queues are made. */
static struct eth_iface_info fresh_port(void)
{
    return (struct eth_iface_info){ .net_dev = &eth3, .speed = 10000, .tx_wire.link_speed = 10000 };
}

/* The longest a frame FMan has taken from a queue takes to reach the MAC's
 * count: its time on the wire -- MTU, two tags, header, FCS, preamble and gap
 * -- at the link's speed, and the readings' margin after. */
static u64 on_wire_us(unsigned int mtu, unsigned int speed)
{
    return DIV_ROUND_UP(8 * (mtu + 4 + 4 + 14 + 4 + 8 + 12), speed) + MEMAC_TX_PRIME_GAP_US;
}

/* dev_get_stats(): the driver's counts, then the hook. */
static struct rtnl_link_stats64 read_stats(u64 rx_dropped)
{
    struct rtnl_link_stats64 s = { .rx_dropped = rx_dropped };

    dpa_get_stats64(&eth3, &s);
    virt_iface_stats_callback(&eth3, &s);
    assert(!locked);
    return s;
}

static void transmit(u64 frames, u64 frame_len)
{
    mac.unicast += frames;
    mac.octets += frames * (frame_len + ETH_FCS_LEN);
}

/* What the port's MAC sent for somebody, which its counters have to come to:
 * every frame, and their bytes without the FCS. */
static u64 sent_frames(void) { return mac.unicast + mac.multicast + mac.broadcast; }
static u64 sent_bytes(void) { return mac.octets - mac.pause * 64 - ETH_FCS_LEN * sent_frames(); }

/* A PAUSE frame or a data frame sent on every register read a reading makes in
 * turn: whichever read it lands on, the counters never step back, and once the
 * MAC has sent something after it they are exact again -- the reading that
 * caught it half-counted adds nothing for good (A349). `offset' is what the
 * counters stood above the MAC's own sent counts when the sweep began. */
static void race_sweep(int what, u64 packets_offset, u64 bytes_offset)
{
    for (unsigned at = 1; at <= 48; at++) {
        struct rtnl_link_stats64 before = read_stats(3), during, quiet, after;

        inject_what = what, inject_at = at, reads = 0;
        during = read_stats(3);
        inject_what = NOTHING;
        quiet = read_stats(3);
        transmit(2, 500);
        after = read_stats(3);
        assert(during.tx_packets >= before.tx_packets && during.tx_bytes >= before.tx_bytes);
        assert(quiet.tx_packets >= during.tx_packets && quiet.tx_bytes >= during.tx_bytes);
        assert(after.tx_packets == packets_offset + sent_frames());
        assert(after.tx_bytes == bytes_offset + sent_bytes());
    }
}

int main(void)
{
    struct rtnl_link_stats64 s;

    mac_dev.port_dev[RX] = &rx_wrapper;
    eth3.priv.mac_dev = &mac_dev;
    port = (struct dpa_iface_info){ .if_flags = IF_TYPE_ETHERNET | IF_TYPE_PHYSICAL | IF_STATS_ENABLED,
                                    .eth_info = fresh_port(), .stats = &record };
    strcpy(port.name, "eth3");
    wifi = (struct dpa_iface_info){ .if_flags = IF_TYPE_WLAN, .next = &port };
    strcpy(wifi.name, "wlan0");
    dpa_interface_info = &wifi;
    /* What the port did before CDX took it: the kernel's frames, which the
     * driver and the MAC both counted, and drops of its own. */
    driver_tx = 100, driver_tx_bytes = 10000;
    transmit(100, 100 - ETH_FCS_LEN);
    rx_port.discards = 7;
    rx_port.no_buffer = 9;
    mac.rx_dropped = 11;

    /* CDX takes the port: where it stands then is where everything counts
     * from, whether or not anything reads the counters before the first
     * offloaded frame. */
    port_counters_prime(&port.eth_info);
    assert(port.eth_info.tx_wire.ready && !locked);

    /* Offloaded frames before anyone reads: the enqueue counted 1000, the
     * port sent 400, and its group refused the rest, which the port they
     * came in by lost. The receive record's frames are folded in, restated
     * as the driver counts them. */
    record_tx = (struct cdx_ft_stats){ .packets = 1000, .bytes = 1000 * 1000 };
    record_rx = (struct cdx_ft_stats){ .packets = 10, .bytes = 10 * 100 };
    transmit(400, 1000);
    rx_port.discards += 600;
    s = read_stats(3);
    assert(s.tx_packets == 100 + 400 && s.tx_bytes == 10000 + 400 * 1000);
    assert(s.rx_packets == 10 && s.rx_bytes == 10 * (100 - ETH_HLEN));
    assert(s.rx_dropped == 3 + 600 && !s.rx_missed_errors);
    /* Frames the port found no buffer for are missed, not dropped. */
    rx_port.no_buffer += 50;
    s = read_stats(3);
    assert(s.rx_dropped == 3 + 600 && s.rx_missed_errors == 50);

    /* The kernel's own frames leave by the same MAC: counted there once,
     * whatever the driver's own count says meanwhile. */
    transmit(5, 60);
    driver_tx += 5, driver_tx_bytes += 300;
    s = read_stats(3);
    assert(s.tx_packets == 100 + 405 && s.tx_bytes == 10000 + 400 * 1000 + 5 * 60);

    /* PAUSE frames the port sends itself are no frames anybody sent. */
    mac.pause += 10, mac.octets += 10 * 64;
    s = read_stats(3);
    assert(s.tx_packets == 100 + 405 && s.tx_bytes == 10000 + 400 * 1000 + 5 * 60);

    /* One sent while a reading is under way, on whichever register read it
     * lands, is never counted as a frame for good, nor its 64 octets; nor is
     * a data frame sent between the frame counts' read and the octets'. */
    race_sweep(PAUSE, s.tx_packets - sent_frames(), s.tx_bytes - sent_bytes());
    s = read_stats(3);
    race_sweep(DATA, s.tx_packets - sent_frames(), s.tx_bytes - sent_bytes());
    /* PAUSE frames on every few reads, so that no reading's retries find a
     * quiet moment: the one that stands is a moment off, low rather than
     * high, so it is passed over, and the next reading -- with nothing sent
     * since -- is exact. */
    for (unsigned every = 3; every <= 11; every++) {
        struct rtnl_link_stats64 before = read_stats(3), during, quiet, after;
        u64 packets_offset = before.tx_packets - sent_frames();
        u64 bytes_offset = before.tx_bytes - sent_bytes();

        inject_what = PAUSE, inject_at = 0, inject_every = every, reads = 0;
        during = read_stats(3);
        inject_what = NOTHING, inject_every = 0;
        quiet = read_stats(3);
        assert(during.tx_packets >= before.tx_packets && during.tx_bytes >= before.tx_bytes);
        assert(quiet.tx_packets >= during.tx_packets && quiet.tx_bytes >= during.tx_bytes);
        assert(quiet.tx_packets == packets_offset + sent_frames());
        assert(quiet.tx_bytes == bytes_offset + sent_bytes());
        transmit(1, 700);
        after = read_stats(3);
        assert(after.tx_packets == packets_offset + sent_frames());
        assert(after.tx_bytes == bytes_offset + sent_bytes());
    }
    s = read_stats(3);

    /* A carry into the upper half between its two reads is read again, not
     * torn into a count 4G out. */
    s = read_stats(3);
    u64 jump = 0xfffffff0u - (u32)mac.octets;
    mac.octets += jump;
    s = read_stats(3);
    u64 bytes = s.tx_bytes;
    carry_on_read = 1;
    s = read_stats(3);
    assert(!carry_on_read && s.tx_bytes == bytes + 0x100);

    /* Nothing clears the MAC's counts at run time. Were they reset anyway,
     * the counters hold where they stood and count on from there. */
    u64 frames = s.tx_packets;
    bytes = s.tx_bytes;
    mac.unicast = mac.multicast = mac.broadcast = mac.octets = mac.pause = 0;
    s = read_stats(3);
    assert(s.tx_packets == frames && s.tx_bytes == bytes);
    transmit(3, 100);
    s = read_stats(3);
    assert(s.tx_packets == frames + 3 && s.tx_bytes == bytes + 300);
    /* A reset first seen by a reading that is not whole is not counted on
     * from: the counts hold until a whole one. */
    frames = s.tx_packets;
    bytes = s.tx_bytes;
    mac.unicast = mac.multicast = mac.broadcast = mac.octets = mac.pause = 0;
    inject_what = PAUSE, inject_at = 0, inject_every = 3, reads = 0;
    s = read_stats(3);
    inject_what = NOTHING, inject_every = 0;
    assert(s.tx_packets == frames && s.tx_bytes == bytes);
    s = read_stats(3);
    assert(s.tx_packets == frames && s.tx_bytes == bytes);
    transmit(2, 100);
    s = read_stats(3);
    assert(s.tx_packets == frames + 2 && s.tx_bytes == bytes + 200);

    /* The BMI counts wrap at 32 bits; the sampler keeps up with them, and a
     * reading after the wrap still adds only what is new. */
    rx_port.discards = 0xfffffff0u;
    rx_port.no_buffer = 0xffffffffu;
    dpa_port_counters_sample();
    assert(!locked);
    u64 dropped = port.eth_info.rx_discarded.total, missed = port.eth_info.rx_no_buffer.total;
    rx_port.discards = 0x10;
    rx_port.no_buffer = 2;
    s = read_stats(3);
    assert(s.rx_dropped == 3 + dropped + 0x20 && s.rx_missed_errors == missed + 3);

    /* Frames the receive MAC dropped itself, its FIFO full because FMan had
     * not drained it, are missed as well (A352): FMan never saw them, or saw
     * them cut short and discarded them, and counted neither. From where the
     * MAC stood when CDX took the port, as everything else. */
    u64 discarded = s.rx_dropped;
    missed = s.rx_missed_errors;
    mac.rx_dropped += 20;
    s = read_stats(3);
    assert(s.rx_missed_errors == missed + 20 && s.rx_dropped == discarded);
    /* The MAC's counters reset: what it has dropped since is all new. */
    mac.rx_dropped = 4;
    s = read_stats(3);
    assert(s.rx_missed_errors == missed + 20 + 4 && s.rx_dropped == discarded);
    mac.rx_dropped += 6;
    s = read_stats(3);
    assert(s.rx_missed_errors == missed + 30);

    /* Where the counters start from is taken whole as well: a PAUSE frame
     * sent while CDX takes the port, on whichever read it lands, leaves the
     * port's transmit counts exactly the driver's at the time plus what the
     * MAC sent after; a data frame sent then is where the MAC stood or sent
     * after, with its bytes either way, never one without the other. */
    for (int what = PAUSE; what <= DATA; what++) {
        for (unsigned at = 1; at <= 48; at++) {
            struct dpa_iface_info taken = port;

            taken.eth_info = fresh_port();
            inject_what = what, inject_at = at, reads = 0;
            port_counters_prime(&taken.eth_info);
            inject_what = NOTHING;
            assert(taken.eth_info.tx_wire.ready);
            dpa_interface_info = &taken;
            transmit(4, 250);
            s = read_stats(3);
            dpa_interface_info = &wifi;
            if (s.tx_packets == driver_tx + 4)
                assert(s.tx_bytes == driver_tx_bytes + 4 * 250);
            else
                assert(what == DATA && s.tx_packets == driver_tx + 5 &&
                       s.tx_bytes == driver_tx_bytes + 4 * 250 + 1000);
        }
    }

    /* A port that sends without pause while CDX takes it, so that no reading
     * of its MAC is ever whole: where it starts from is not guessed. It goes
     * on as a port without a MAC would -- the driver's counts and the
     * enqueue's -- until a reading is whole, and carries on from exactly
     * what it reported then, by what the MAC sends after. */
    for (int what = PAUSE; what <= DATA; what++) {
        struct dpa_iface_info busy = port;
        struct rtnl_link_stats64 quiet, after;
        u64 began = now_us;

        busy.eth_info = fresh_port();
        inject_what = what, inject_at = 0, inject_every = 3, reads = 0;
        port_counters_prime(&busy.eth_info);
        assert(!busy.eth_info.tx_wire.ready && now_us - began <= MEMAC_TX_PRIME_BUDGET_US);
        assert(now_us - began > MEMAC_TX_PRIME_BUDGET_US / 2);
        dpa_interface_info = &busy;
        s = read_stats(3);
        assert(s.tx_packets == driver_tx + record_tx.packets);
        inject_what = NOTHING, inject_every = 0;
        quiet = read_stats(3);
        assert(busy.eth_info.tx_wire.ready);
        assert(quiet.tx_packets == driver_tx + record_tx.packets);
        assert(quiet.tx_bytes == driver_tx_bytes + record_tx.bytes);
        transmit(3, 400);
        after = read_stats(3);
        assert(after.tx_packets == quiet.tx_packets + 3 && after.tx_bytes == quiet.tx_bytes + 3 * 400);
        dpa_interface_info = &wifi;
    }

    /* Frames the kernel had enqueued and the MAC not yet sent when CDX took
     * the port: the driver counted them as they were enqueued and the MAC
     * counts them as they leave, and they are counted once. The kernel's
     * transmit is held while the queues are read, so that none joins them
     * meanwhile. */
    {
        struct dpa_iface_info queued = port;

        queued.eth_info = fresh_port();
        driver_tx += 10, driver_tx_bytes += 10 * 500;
        queue.frames = 10, queue.bytes = 10 * 500;
        frozen_reads = 0;
        port_counters_prime(&queued.eth_info);
        assert(queued.eth_info.tx_wire.ready && frozen_reads && !tx_frozen);
        dpa_interface_info = &queued;
        s = read_stats(3);
        assert(s.tx_packets == driver_tx && s.tx_bytes == driver_tx_bytes);
        queue.frames = queue.bytes = 0;
        transmit(10, 500);
        s = read_stats(3);
        assert(s.tx_packets == driver_tx && s.tx_bytes == driver_tx_bytes);
        driver_tx += 3, driver_tx_bytes += 3 * 200;
        transmit(3, 200);
        s = read_stats(3);
        assert(s.tx_packets == driver_tx && s.tx_bytes == driver_tx_bytes);
        dpa_interface_info = &wifi;
    }

    /* Frames FMan had taken from their queue and the MAC not yet counted when
     * CDX took the port are in the driver's count alone. Readings a frame's
     * time on the wire apart at the link's speed -- jumbo frames at 1G here,
     * two of them back to back -- see one arrive while the other is still on
     * its way, and the counts start from a pair taken once both have. */
    {
        struct dpa_iface_info moving = port;
        u64 began = now_us;

        moving.eth_info = fresh_port();
        phy_speed = 1000, eth3.mtu = 9000;
        driver_tx += 2, driver_tx_bytes += 2 * 9000;
        transit.frames = 2, transit.bytes = 9000;
        transit.left_us = transit.frame_us = 9000 * 8 / 1000;
        port_counters_prime(&moving.eth_info);
        assert(moving.eth_info.tx_wire.ready && now_us - began <= MEMAC_TX_PRIME_BUDGET_US);
        udelay(1000);
        dpa_interface_info = &moving;
        s = read_stats(3);
        assert(s.tx_packets == driver_tx && s.tx_bytes == driver_tx_bytes);
        driver_tx += 2, driver_tx_bytes += 2 * 700;
        transmit(2, 700);
        s = read_stats(3);
        assert(s.tx_packets == driver_tx && s.tx_bytes == driver_tx_bytes);
        dpa_interface_info = &wifi;
        phy_speed = 0, eth3.mtu = 1500;
    }

    /* A gigabit port linked at 10M as CDX takes it: a frame is on its way to
     * the MAC's count for as long as on_wire_us() at that speed, and the
     * readings are that far apart, at the speed the PHY reports; the MAC's
     * fastest is a hundred times too soon. */
    {
        struct dpa_iface_info linked = port;

        linked.eth_info = fresh_port();
        linked.eth_info.speed = 1000;
        phy_speed = 10;
        driver_tx += 1, driver_tx_bytes += 1500;
        transit.frames = 1, transit.bytes = 1500;
        transit.left_us = on_wire_us(1500, 10);
        port_counters_prime(&linked.eth_info);
        assert(linked.eth_info.tx_wire.ready && !transit.frames);
        phy_speed = 0;
        dpa_interface_info = &linked;
        s = read_stats(3);
        assert(s.tx_packets == driver_tx && s.tx_bytes == driver_tx_bytes);
        transmit(2, 600);
        driver_tx += 2, driver_tx_bytes += 2 * 600;
        s = read_stats(3);
        assert(s.tx_packets == driver_tx && s.tx_bytes == driver_tx_bytes);
        dpa_interface_info = &wifi;
    }

    /* From the statistics hook, a port CDX could not read standing still as
     * it took it: nothing is read while CDX is still making its queues; then
     * its readings are timed by the speed the link last reported -- 1G as
     * CDX took it, 100M once it changed -- even when its egress bound could
     * not follow. */
    {
        struct dpa_iface_info linked = port;

        linked.eth_info = fresh_port();
        linked.eth_info.speed = 1000;
        linked.eth_info.tx_wire.link_speed = 0;
        queue.qdisc = true;
        port_counters_prime(&linked.eth_info);
        assert(!linked.eth_info.tx_wire.ready);
        queue.qdisc = false;
        dpa_interface_info = &linked;
        int reads = queue_reads;
        s = read_stats(3);
        assert(!linked.eth_info.tx_wire.ready && queue_reads == reads);
        assert(s.tx_packets == driver_tx + record_tx.packets);
        phy_speed = 100;
        dpa_fwd_cgr_follow_link(&eth3);
        assert(!linked.eth_info.tx_wire.link_speed);
        /* The queues made, as at 1G; then the link changes speed. */
        linked.eth_info.tx_wire.link_speed = linked.eth_info.fwd_cgr_speed = 1000;
        linked.eth_info.fwd_cgr_mtu = eth3.mtu;
        cgr_fails = 1;
        dpa_fwd_cgr_follow_link(&eth3);
        assert(linked.eth_info.tx_wire.link_speed == 100 && linked.eth_info.fwd_cgr_speed == 1000);
        cgr_fails = 0;
        dpa_fwd_cgr_follow_link(&eth3);
        assert(linked.eth_info.fwd_cgr_speed == 100);
        /* The link goes down, and reports no speed: the last one stands. */
        phy_speed = 0;
        dpa_fwd_cgr_follow_link(&eth3);
        assert(linked.eth_info.tx_wire.link_speed == 100 && linked.eth_info.fwd_cgr_speed == 100);
        driver_tx += 1, driver_tx_bytes += 1500;
        transit.frames = 1, transit.bytes = 1500;
        transit.left_us = on_wire_us(1500, 100);
        s = read_stats(3);
        assert(!linked.eth_info.tx_wire.ready && !transit.frames);
        s = read_stats(3);
        assert(linked.eth_info.tx_wire.ready);
        u64 reported = driver_tx + record_tx.packets, reported_bytes = driver_tx_bytes + record_tx.bytes;
        assert(s.tx_packets == reported && s.tx_bytes == reported_bytes);
        transmit(2, 600);
        s = read_stats(3);
        assert(s.tx_packets == reported + 2 && s.tx_bytes == reported_bytes + 2 * 600);
        dpa_interface_info = &wifi;
    }

    /* A frame the kernel enqueued while the queues were read, which the
     * freeze does not stop: the driver counted it and the reading of the
     * queues did not, so that pair is passed over, and the next counts it
     * as queued. */
    {
        struct dpa_iface_info slipped = port;

        slipped.eth_info = fresh_port();
        /* The first reading of the queues only says they can be read; the
         * enqueue comes after the second pair's. */
        queue.enqueue_on_read = 3;
        port_counters_prime(&slipped.eth_info);
        assert(slipped.eth_info.tx_wire.ready && !queue.enqueue_on_read && queue.frames == 1);
        dpa_interface_info = &slipped;
        s = read_stats(3);
        assert(s.tx_packets == driver_tx && s.tx_bytes == driver_tx_bytes);
        queue.frames = queue.bytes = 0;
        transmit(1, 300);
        s = read_stats(3);
        assert(s.tx_packets == driver_tx && s.tx_bytes == driver_tx_bytes);
        dpa_interface_info = &wifi;
    }

    /* A frame FMan took from its queue between the two readings, and the MAC
     * had not counted by the second: it left the queue's count and joined no
     * other, so that pair is passed over too. */
    {
        struct dpa_iface_info taking = port;

        taking.eth_info = fresh_port();
        driver_tx += 1, driver_tx_bytes += 400;
        queue.frames = 1, queue.bytes = queue.take_bytes = 400;
        queue.take_in_gap = 1;
        port_counters_prime(&taking.eth_info);
        assert(taking.eth_info.tx_wire.ready && !queue.frames && !transit.frames);
        dpa_interface_info = &taking;
        udelay(1000);
        s = read_stats(3);
        assert(s.tx_packets == driver_tx && s.tx_bytes == driver_tx_bytes);
        dpa_interface_info = &wifi;
    }

    /* A link too slow for two readings a frame's time apart within the time
     * CDX may hold the kernel's transmit: no reading is tried, then or from
     * the statistics hook, and the port goes on by the driver's counts and
     * the record's. */
    {
        struct dpa_iface_info slow = port;
        int freezes = tx_freezes;

        slow.eth_info = fresh_port();
        phy_speed = 10, eth3.mtu = 9000;
        frozen_reads = 0;
        port_counters_prime(&slow.eth_info);
        assert(!slow.eth_info.tx_wire.ready && !frozen_reads && tx_freezes == freezes);
        slow.eth_info.tx_wire.link_speed = 10;
        dpa_interface_info = &slow;
        s = read_stats(3);
        assert(!slow.eth_info.tx_wire.ready && !frozen_reads);
        assert(s.tx_packets == driver_tx + record_tx.packets);
        dpa_interface_info = &wifi;
        phy_speed = 0, eth3.mtu = 1500;
    }

    /* Taken later, from the statistics hook: what was queued then -- of the
     * kernel's and of the offloaded frames the enqueue's record counts -- is
     * counted once too. A reading the kernel enqueued during is passed over,
     * and so is every reading of a port a hardware qdisc owns, whose class
     * queues count no bytes; the port goes on by the driver's counts and the
     * record's meanwhile. */
    {
        struct dpa_iface_info late = port;
        struct cdx_ft_stats record_was = record_tx;

        late.eth_info = fresh_port();
        queue.qdisc = true;
        port_counters_prime(&late.eth_info);
        assert(!late.eth_info.tx_wire.ready);
        dpa_interface_info = &late;
        driver_tx += 4, driver_tx_bytes += 4 * 100;
        queue.frames = 4, queue.bytes = 4 * 100;
        record_tx.packets += 6, record_tx.bytes += 6 * 1000;
        queue.frames += 6, queue.bytes += 6 * 1000;
        /* Nor is a reading that cannot be taken waited out, under the lock,
         * at every read of its counters. */
        u64 at = now_us;
        s = read_stats(3);
        assert(!late.eth_info.tx_wire.ready && now_us == at);
        assert(s.tx_packets == driver_tx + record_tx.packets && s.tx_bytes == driver_tx_bytes + record_tx.bytes);
        queue.qdisc = false;
        queue.enqueue_on_read = 2;
        s = read_stats(3);
        assert(!late.eth_info.tx_wire.ready && !queue.enqueue_on_read);
        assert(s.tx_packets + 1 == driver_tx + record_tx.packets);
        /* So is one an offloaded frame joined the queues after their second
         * reading: the record counted it, and the reading did not. */
        queue.offload_on_read = 2;
        s = read_stats(3);
        assert(!late.eth_info.tx_wire.ready && !queue.offload_on_read);
        assert(s.tx_packets == driver_tx + record_tx.packets);
        s = read_stats(3);
        assert(late.eth_info.tx_wire.ready);
        u64 reported = driver_tx + record_tx.packets, reported_bytes = driver_tx_bytes + record_tx.bytes;
        assert(s.tx_packets == reported && s.tx_bytes == reported_bytes);
        transmit(4, 100), transmit(1, 300), transmit(6, 1000), transmit(1, 800);
        queue.frames = queue.bytes = 0;
        s = read_stats(3);
        assert(s.tx_packets == reported && s.tx_bytes == reported_bytes);
        transmit(2, 50);
        s = read_stats(3);
        assert(s.tx_packets == reported + 2 && s.tx_bytes == reported_bytes + 100);
        dpa_interface_info = &wifi;
        record_tx = record_was;
    }

    /* A port with no statistics enabled gets nothing added. */
    port.if_flags &= ~IF_STATS_ENABLED;
    s = read_stats(3);
    assert(s.tx_packets == driver_tx && s.rx_dropped == 3);
    port.if_flags |= IF_STATS_ENABLED;
    /* One CDX took without a MAC to read keeps the enqueue's count. */
    struct dpa_iface_info bare = port;
    bare.eth_info = fresh_port();
    mac_dev.vaddr = NULL;
    port_counters_prime(&bare.eth_info);
    assert(!bare.eth_info.tx_wire.ready);
    dpa_interface_info = &bare;
    s = read_stats(3);
    assert(s.tx_packets == driver_tx + 1000);

    puts("port counters: transmit from the MAC since the port was taken, untorn and never "
         "backwards; drops and misses past a 32-bit wrap");
    return 0;
}
