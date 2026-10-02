/* Whether a bridge hook other than the multicast learner's own would see a
 * forwarded frame, compiled from the adapter against the shape of the
 * kernel's per-netns hook lists.
 *
 * A hardware entry replicates at the classifier, before any of them runs, so
 * while one is registered at PRE_ROUTING, FORWARD or POST_ROUTING no bridged
 * flow may be carried. The learner's own hook, at PRE_ROUTING, never counts:
 * it only observes. LOCAL_IN and LOCAL_OUT see only what the host
 * receives or sends, which a plain bridged flow never is. A route's copies
 * are: the routed learner asks about LOCAL_OUT and POST_ROUTING for a copy
 * routed into a bridge, and a copy handed up through LOCAL_IN is confirmed
 * only once ipmr has forwarded it.
 *
 * The bridge device's own netdev ingress hook sees what the bridge hands up
 * to the host: an nftables netdev chain there, an inet one at ingress, or a
 * netfilter BPF program keeps a flow the bridge hands up in software. A
 * flowtable's hook sits there as well and does not count. A port's chains are
 * judged by nft_port_dependent() instead, for what they do to the stream.
 */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef uint16_t u16;

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define BIT(n) (1UL << (n))
#define IS_ENABLED(x) (x)
#define CONFIG_NETFILTER_FAMILY_BRIDGE 1
#define rcu_read_lock() ((void)0)
#define rcu_read_unlock() ((void)0)
#define rcu_dereference(p) (p)

/* As include/uapi/linux/netfilter_bridge.h numbers them. */
enum {
    NF_BR_PRE_ROUTING,
    NF_BR_LOCAL_IN,
    NF_BR_FORWARD,
    NF_BR_LOCAL_OUT,
    NF_BR_POST_ROUTING,
    NF_BR_BROUTING,
    NF_BR_NUMHOOKS,
};

/* As include/linux/netfilter.h has them in 6.12: an nftables base chain is
 * NF_TABLES, a netfilter BPF link BPF, and a flowtable's hook is left
 * UNDEFINED -- the label for it came later. */
enum nf_hook_ops_type {
    NF_HOOK_OP_UNDEFINED,
    NF_HOOK_OP_NF_TABLES,
    NF_HOOK_OP_BPF,
};
struct nf_hook_ops { int priority; enum nf_hook_ops_type hook_ops_type; };
struct nf_hook_entry { void *hook; void *priv; };
/* The entries, then the trailer of each one's registering ops, as
 * net/netfilter/core.c allocates them. */
struct nf_hook_entries {
    u16 num_hook_entries;
    struct nf_hook_entry hooks[];
};
static struct nf_hook_ops **nf_hook_entries_get_hook_ops(const struct nf_hook_entries *e)
{
    return (struct nf_hook_ops **)&e->hooks[e->num_hook_entries];
}

/* As include/net/netns/netfilter.h sizes it: NF_INET_NUMHOOKS slots, one
 * fewer than NF_BR_NUMHOOKS counts. */
static struct {
    struct { struct nf_hook_entries *hooks_bridge[NF_BR_NUMHOOKS - 1]; } nf;
} init_net;

static struct nf_hook_ops ft_mc_hook_ops, nft_chain, ebtables, br_netfilter;
/* At a device's own netdev hooks: an nftables netdev chain, or an inet one at
 * ingress; a netfilter BPF program; a flowtable. */
static struct nf_hook_ops netdev_chain = { .hook_ops_type = NF_HOOK_OP_NF_TABLES };
static struct nf_hook_ops bpf_prog = { .hook_ops_type = NF_HOOK_OP_BPF };
static struct nf_hook_ops flowtable = { .hook_ops_type = NF_HOOK_OP_UNDEFINED };

/* A device's netdev ingress hook, as include/linux/netdevice.h has it. */
#define CONFIG_NETFILTER_INGRESS 1
struct net_device {
    struct nf_hook_entries *nf_hooks_ingress;
};

#include "mcast_bridge_filter.inc"

/* Entries for `n` ops, as net/netfilter/core.c lays them out, or none. */
static struct nf_hook_entries *entries(unsigned int n, __builtin_va_list ap)
{
    struct nf_hook_entries *e;

    if (!n)
        return NULL;
    e = calloc(1, sizeof(*e) + n * (sizeof(e->hooks[0]) + sizeof(void *)));
    assert(e);
    e->num_hook_entries = n;
    for (unsigned int i = 0; i < n; i++)
        nf_hook_entries_get_hook_ops(e)[i] = __builtin_va_arg(ap, struct nf_hook_ops *);
    return e;
}

/* Register `n` ops at `hook`, replacing what was there. */
static void registered(unsigned int hook, unsigned int n, ...)
{
    __builtin_va_list ap;

    free(init_net.nf.hooks_bridge[hook]);
    __builtin_va_start(ap, n);
    init_net.nf.hooks_bridge[hook] = entries(n, ap);
    __builtin_va_end(ap);
}

/* Register `n` ops at `dev`'s netdev ingress hook, replacing what was there. */
static void on_device(struct net_device *dev, unsigned int n, ...)
{
    __builtin_va_list ap;

    free(dev->nf_hooks_ingress);
    __builtin_va_start(ap, n);
    dev->nf_hooks_ingress = entries(n, ap);
    __builtin_va_end(ap);
}

static void netdev_hooks(void)
{
    struct net_device bridge = { 0 };

    /* Nothing there, and a flowtable's hook: it acts only on the conntrack
     * flows a rule offered it, and this kernel gives it no type. */
    assert(!ft_dev_nf_ingress_hooked(&bridge));
    on_device(&bridge, 1, &flowtable);
    assert(!ft_dev_nf_ingress_hooked(&bridge));

    /* A chain beside it, either side of it. */
    on_device(&bridge, 2, &flowtable, &netdev_chain);
    assert(ft_dev_nf_ingress_hooked(&bridge));
    on_device(&bridge, 2, &netdev_chain, &flowtable);
    assert(ft_dev_nf_ingress_hooked(&bridge));

    /* A netfilter BPF program reads what it likes. */
    on_device(&bridge, 1, &bpf_prog);
    assert(ft_dev_nf_ingress_hooked(&bridge));
    on_device(&bridge, 0);
    assert(!ft_dev_nf_ingress_hooked(&bridge));
}

int main(void)
{
    /* Nothing registered, or only the learner's own hook, which observes. */
    assert(!ft_mc_bridge_filtered());
    registered(NF_BR_PRE_ROUTING, 1, &ft_mc_hook_ops);
    assert(!ft_mc_bridge_filtered());

    /* Another hook beside it at PRE_ROUTING, before or after it. */
    registered(NF_BR_PRE_ROUTING, 2, &ebtables, &ft_mc_hook_ops);
    assert(ft_mc_bridge_filtered());
    registered(NF_BR_PRE_ROUTING, 2, &ft_mc_hook_ops, &ebtables);
    assert(ft_mc_bridge_filtered());
    registered(NF_BR_PRE_ROUTING, 1, &ft_mc_hook_ops);

    /* An nftables bridge chain at FORWARD; br_netfilter at POST_ROUTING,
     * whatever it would then do with the frame. */
    registered(NF_BR_FORWARD, 1, &nft_chain);
    assert(ft_mc_bridge_filtered());
    registered(NF_BR_FORWARD, 0);
    assert(!ft_mc_bridge_filtered());
    registered(NF_BR_POST_ROUTING, 1, &br_netfilter);
    assert(ft_mc_bridge_filtered());
    registered(NF_BR_POST_ROUTING, 0);

    /* The host's own traffic is none of a forwarded frame's business. */
    registered(NF_BR_LOCAL_IN, 1, &nft_chain);
    registered(NF_BR_LOCAL_OUT, 1, &ebtables);
    assert(!ft_mc_bridge_filtered());

    /* It is a routed copy's, though: one routed into a bridge leaves by the
     * bridge's LOCAL_OUT and POST_ROUTING, which the routed learner asks
     * about. */
    assert(ft_bridge_hooked(BIT(NF_BR_LOCAL_OUT) | BIT(NF_BR_POST_ROUTING)));
    registered(NF_BR_LOCAL_OUT, 0);
    assert(!ft_bridge_hooked(BIT(NF_BR_LOCAL_OUT) | BIT(NF_BR_POST_ROUTING)));
    registered(NF_BR_POST_ROUTING, 1, &br_netfilter);
    assert(ft_bridge_hooked(BIT(NF_BR_LOCAL_OUT) | BIT(NF_BR_POST_ROUTING)));

    for (unsigned int i = 0; i < ARRAY_SIZE(init_net.nf.hooks_bridge); i++)
        registered(i, 0);

    netdev_hooks();
    return 0;
}
