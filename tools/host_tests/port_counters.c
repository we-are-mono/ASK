/* What a registered Ethernet port's standard counters report while CDX holds
 * it.
 *
 * Transmit is what the port's MAC sent: an offloaded frame was counted when the
 * classifier enqueued it, before QMan decided, and one an egress congestion
 * group refused never left. So the netdev's own counts as CDX took the port
 * carry on by the MAC's advance since, whatever the enqueue counted. Receive
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
/* The mEMAC's transmit counters, each two 32-bit halves. */
struct memac_regs {
    u32 toct_l, toct_u, tfrm_l, tfrm_u, txpf_l, txpf_u;
};
struct fm_port_model { u32 discards, no_buffer; };
typedef struct { t_Handle h_Dev; } t_LnxWrpFmPortDev;
struct mac_device { void *port_dev[2]; void *vaddr; };
struct dpa_priv_s { struct mac_device *mac_dev; };
struct net_device;
struct net_device_ops { void (*ndo_get_stats64)(struct net_device *, struct rtnl_link_stats64 *); };
struct net_device {
    char name[16]; struct dpa_priv_s priv; bool dpaa; const struct net_device_ops *netdev_ops;
};

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

/* The MAC: what it has sent, kept whole, and served in halves. A carry may be
 * due between an upper half's read and the lower's. Its own PAUSE frames are
 * among its good frames and octets. */
static struct { u64 frames, octets, pause; } mac;
static struct memac_regs regs;
static int carry_on_read;
static u32 ioread32be(const u32 *reg)
{
    if (reg == &regs.toct_l && carry_on_read && !--carry_on_read)
        mac.octets += 0x100;    /* the lower half wraps between the reads */
    regs.toct_l = (u32)mac.octets;
    regs.toct_u = (u32)(mac.octets >> 32);
    regs.tfrm_l = (u32)mac.frames;
    regs.tfrm_u = (u32)(mac.frames >> 32);
    regs.txpf_l = (u32)mac.pause;
    regs.txpf_u = (u32)(mac.pause >> 32);
    return *reg;
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

#include "port_counters_production.inc"

static struct mac_device mac_dev = { .vaddr = &regs };
static struct net_device eth3 = { .name = "eth3", .dpaa = true, .netdev_ops = &dpa_ops };
static struct dpa_iface_info port, wifi;
static int record;

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
    mac.frames += frames;
    mac.octets += frames * (frame_len + ETH_FCS_LEN);
}

int main(void)
{
    struct rtnl_link_stats64 s;

    mac_dev.port_dev[RX] = &rx_wrapper;
    eth3.priv.mac_dev = &mac_dev;
    port = (struct dpa_iface_info){ .if_flags = IF_TYPE_ETHERNET | IF_TYPE_PHYSICAL | IF_STATS_ENABLED,
                                    .eth_info = { .net_dev = &eth3 }, .stats = &record };
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
    mac.pause += 10, mac.frames += 10, mac.octets += 10 * 64;
    s = read_stats(3);
    assert(s.tx_packets == 100 + 405 && s.tx_bytes == 10000 + 400 * 1000 + 5 * 60);

    /* A carry into the upper half between its two reads is read again, not
     * torn into a count 4G out. */
    mac.octets = 0xfffffff0u;
    port.eth_info.tx_wire.mac_octets = mac.octets - mac.pause * 64;
    u64 bytes = s.tx_bytes;
    carry_on_read = 1;
    s = read_stats(3);
    assert(!carry_on_read && s.tx_bytes == bytes + 0x100);

    /* A count that goes back -- nothing does that at run time -- reads as no
     * change, never as fewer frames, and counts on from there. */
    u64 frames = s.tx_packets;
    mac.frames -= 3;
    s = read_stats(3);
    assert(s.tx_packets == frames);
    mac.frames += 3;
    s = read_stats(3);
    assert(s.tx_packets == frames + 3);

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

    /* A port with no statistics enabled gets nothing added. */
    port.if_flags &= ~IF_STATS_ENABLED;
    s = read_stats(3);
    assert(s.tx_packets == driver_tx && s.rx_dropped == 3);
    port.if_flags |= IF_STATS_ENABLED;
    /* One CDX took without a MAC to read keeps the enqueue's count. */
    struct dpa_iface_info bare = port;
    bare.eth_info = (struct eth_iface_info){ .net_dev = &eth3 };
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
