/* Whether anything that can still change a confirmed copy's fate runs after
 * the routed learner's observer at POST_ROUTING, compiled from the adapter
 * against the shape of the kernel's per-netns hook lists.
 *
 * The observer sits at the last priority. At an equal priority netfilter puts
 * a hook registered later ahead of the ones already there, so what follows the
 * observer is whatever held the last priority when it registered: conntrack's
 * confirmation, which is the kernel's own and registers with no type, and
 * possibly an nftables chain, which is not. A BPF program cannot be there: a
 * netfilter BPF link refuses the last priority.
 */
#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef uint8_t u8;
typedef uint16_t u16;

#define AF_INET 2
#define AF_INET6 10
#define rcu_read_lock() ((void)0)
#define rcu_read_unlock() ((void)0)
#define rcu_dereference(p) (p)
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/* As include/uapi/linux/netfilter.h and include/linux/netfilter.h have them. */
enum { NF_INET_PRE_ROUTING, NF_INET_LOCAL_IN, NF_INET_FORWARD,
       NF_INET_LOCAL_OUT, NF_INET_POST_ROUTING, NF_INET_NUMHOOKS };
enum nf_hook_ops_type { NF_HOOK_OP_UNDEFINED, NF_HOOK_OP_NF_TABLES, NF_HOOK_OP_BPF };
struct nf_hook_ops {
    int priority;
    enum nf_hook_ops_type hook_ops_type;
};
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

static struct {
    struct {
        struct nf_hook_entries *hooks_ipv4[NF_INET_NUMHOOKS];
        struct nf_hook_entries *hooks_ipv6[NF_INET_NUMHOOKS];
    } nf;
} init_net;

static unsigned ft_mr_idx(u8 family) { return family == AF_INET6; }
static struct nf_hook_ops ft_mr_confirm_ops[2] = {
    { .priority = INT_MAX }, { .priority = INT_MAX },
};

#include "mroute_confirm_order.inc"

/* The kernel's own at the last priority, what a user can put there, and a
 * typed hook no user can. */
static struct nf_hook_ops conntrack_confirm = { INT_MAX, NF_HOOK_OP_UNDEFINED };
static struct nf_hook_ops nat = { 100, NF_HOOK_OP_UNDEFINED };
static struct nf_hook_ops nft_filter = { 0, NF_HOOK_OP_NF_TABLES };
static struct nf_hook_ops nft_last = { INT_MAX, NF_HOOK_OP_NF_TABLES };
static struct nf_hook_ops bpf_last = { INT_MAX, NF_HOOK_OP_BPF };

/* What a netfilter BPF link registers: typed, at a priority of its own. */
static struct nf_hook_ops bpf_filter = { 10, NF_HOOK_OP_BPF };

/* The family's list at `hook`, in the order given: the order netfilter would
 * run them in. */
static void registered_at(u8 family, unsigned hook, unsigned n, __builtin_va_list ap)
{
    struct nf_hook_entries **slot = family == AF_INET6 ?
        &init_net.nf.hooks_ipv6[hook] : &init_net.nf.hooks_ipv4[hook];
    struct nf_hook_entries *e;

    free(*slot);
    *slot = NULL;
    if (!n)
        return;
    e = calloc(1, sizeof(*e) + n * (sizeof(e->hooks[0]) + sizeof(void *)));
    assert(e);
    e->num_hook_entries = n;
    for (unsigned i = 0; i < n; i++)
        nf_hook_entries_get_hook_ops(e)[i] = __builtin_va_arg(ap, struct nf_hook_ops *);
    *slot = e;
}

static void at(u8 family, unsigned hook, unsigned n, ...)
{
    __builtin_va_list ap;

    __builtin_va_start(ap, n);
    registered_at(family, hook, n, ap);
    __builtin_va_end(ap);
}

/* The family's POST_ROUTING list. */
static void registered(u8 family, unsigned n, ...)
{
    struct nf_hook_entries **slot = family == AF_INET6 ?
        &init_net.nf.hooks_ipv6[NF_INET_POST_ROUTING] :
        &init_net.nf.hooks_ipv4[NF_INET_POST_ROUTING];
    struct nf_hook_entries *e;
    __builtin_va_list ap;

    free(*slot);
    *slot = NULL;
    if (!n)
        return;
    e = calloc(1, sizeof(*e) + n * (sizeof(e->hooks[0]) + sizeof(void *)));
    assert(e);
    e->num_hook_entries = n;
    __builtin_va_start(ap, n);
    for (unsigned i = 0; i < n; i++)
        nf_hook_entries_get_hook_ops(e)[i] = __builtin_va_arg(ap, struct nf_hook_ops *);
    __builtin_va_end(ap);
    *slot = e;
}

int main(void)
{
    struct nf_hook_ops *v4 = &ft_mr_confirm_ops[0], *v6 = &ft_mr_confirm_ops[1];

    /* Nothing registered at all: nothing follows. */
    assert(!ft_mr_observer_followed(AF_INET));
    /* Filter and NAT chains run before it, at their own priorities, and
     * conntrack's confirmation after it is the kernel's own. */
    registered(AF_INET, 4, &nft_filter, &nat, v4, &conntrack_confirm);
    assert(!ft_mr_observer_followed(AF_INET));
    /* An nftables chain at the last priority registered after the observer
     * went ahead of it, and ran before it confirmed. */
    registered(AF_INET, 4, &nft_filter, &nft_last, v4, &conntrack_confirm);
    assert(!ft_mr_observer_followed(AF_INET));
    /* One registered before it -- the observer registers afresh whenever a
     * family's first group appears -- runs after it, and can still drop,
     * queue or steal the copy. */
    registered(AF_INET, 4, &nft_filter, v4, &nft_last, &conntrack_confirm);
    assert(ft_mr_observer_followed(AF_INET));
    /* Any typed hook there counts the same. None but a chain can be there
     * today -- a netfilter BPF link refuses the last priority -- so this
     * only keeps the walk from depending on which type it is. */
    registered(AF_INET, 3, v4, &conntrack_confirm, &bpf_last);
    assert(ft_mr_observer_followed(AF_INET));
    /* Per family: the other family's list is its own. */
    assert(!ft_mr_observer_followed(AF_INET6));
    registered(AF_INET6, 2, v6, &nft_last);
    assert(ft_mr_observer_followed(AF_INET6));
    /* Another family's observer is not this one's: a list holding only the
     * IPv4 observer has nothing after this family's. */
    registered(AF_INET6, 2, v4, &nft_last);
    assert(!ft_mr_observer_followed(AF_INET6));

    registered(AF_INET, 0);
    registered(AF_INET6, 0);

    /* A netfilter BPF program anywhere a copy passes -- prerouting, forward,
     * postrouting, before the observer as much as after it -- can judge it
     * by its ports, and nothing reads it. Elsewhere, and in the other
     * family, it is nothing to the group; and no hook that is not one is
     * taken for one. */
    assert(!ft_mr_bpf_hooked(AF_INET) && !ft_mr_bpf_hooked(AF_INET6));
    at(AF_INET, NF_INET_PRE_ROUTING, 2, &nft_filter, &nat);
    at(AF_INET, NF_INET_POST_ROUTING, 3, &nft_filter, v4, &conntrack_confirm);
    assert(!ft_mr_bpf_hooked(AF_INET));
    static const unsigned crossed[] = {
        NF_INET_PRE_ROUTING, NF_INET_FORWARD, NF_INET_POST_ROUTING,
    };
    for (unsigned i = 0; i < ARRAY_SIZE(crossed); i++) {
        at(AF_INET, crossed[i], 3, &nft_filter, &bpf_filter, &nat);
        assert(ft_mr_bpf_hooked(AF_INET) && !ft_mr_bpf_hooked(AF_INET6));
        at(AF_INET, crossed[i], 1, &nft_filter);
        assert(!ft_mr_bpf_hooked(AF_INET));
        at(AF_INET6, crossed[i], 1, &bpf_filter);
        assert(ft_mr_bpf_hooked(AF_INET6) && !ft_mr_bpf_hooked(AF_INET));
        at(AF_INET6, crossed[i], 0);
    }
    at(AF_INET, NF_INET_LOCAL_IN, 1, &bpf_filter);
    at(AF_INET, NF_INET_LOCAL_OUT, 1, &bpf_filter);
    assert(!ft_mr_bpf_hooked(AF_INET));
    for (unsigned h = 0; h < NF_INET_NUMHOOKS; h++) {
        at(AF_INET, h, 0);
        at(AF_INET6, h, 0);
    }
    return 0;
}
