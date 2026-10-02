/* The x_tables port probe, as patch 148 adds it to ip_tables, ip6_tables,
 * x_tables and the netfilter core, run over rule blobs laid out the way
 * ip_tables lays a replaced table out: base chains ending in their policy,
 * user chains between an ERROR head and an unconditional RETURN, a final
 * ERROR entry, jumps naming the first rule after a chain's head. The probe's
 * own code comes from the patch; ip_packet_match() and
 * ifname_compare_aligned() come from the kernel tree; ipv6_masked_addr_cmp()
 * is restated below, and is the one piece that could drift from the kernel. */
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint32_t __be32;

#define IFNAMSIZ 16
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define READ_ONCE(x) (x)
#define rcu_dereference(p) (p)
#define __rcu
#define __read_mostly
#define EXPORT_SYMBOL_GPL(sym) extern int xt_probe_exported
#define BUILD_BUG_ON(c) _Static_assert(!(c), #c)
#define NF_INVF(ptr, flag, boolean) ((boolean) ^ !!((ptr)->invflags & (flag)))

#define NF_DROP 0
#define NF_ACCEPT 1
#define NF_QUEUE 3
#define NF_REPEAT 4
#define XT_RETURN (-NF_REPEAT - 1)

enum {
	NF_INET_PRE_ROUTING, NF_INET_LOCAL_IN, NF_INET_FORWARD,
	NF_INET_LOCAL_OUT, NF_INET_POST_ROUTING, NF_INET_NUMHOOKS,
};
enum { NFPROTO_IPV4 = 2, NFPROTO_ARP = 3, NFPROTO_IPV6 = 10 };
enum nf_hook_ops_type {
	NF_HOOK_OP_UNDEFINED, NF_HOOK_OP_NF_TABLES, NF_HOOK_OP_BPF,
	NF_HOOK_OP_XTABLES, NF_HOOK_OP_NAT,
};

/* The read side of RCU, which the core asserts its caller holds. */
static int rcu_depth;
static bool rcu_read_lock_held(void) { return rcu_depth > 0; }
#define RCU_LOCKDEP_WARN(c, s) assert(!(c))

/* The packet path's section: xt_replace_table() waits for it, so every read
 * of a table has to sit inside one, with bottom halves off. */
static int bh_depth, recseq_depth;
static unsigned int recseq_sections;
static void local_bh_disable(void) { bh_depth++; }
static void local_bh_enable(void) { assert(bh_depth > 0); bh_depth--; }
static unsigned int xt_write_recseq_begin(void)
{
	assert(bh_depth > 0 && !recseq_depth);
	recseq_depth++;
	recseq_sections++;
	return 1;
}
static void xt_write_recseq_end(unsigned int addend)
{
	assert(addend == 1 && recseq_depth == 1 && bh_depth > 0);
	recseq_depth--;
}

/* ---- x_tables, as the uapi and x_tables.h lay it out --------------------- */

#define XT_ALIGN(s) (((s) + 7) & ~(size_t)7)

struct sk_buff;
struct nf_hook_state;
typedef unsigned int nf_hookfn(void *priv, struct sk_buff *skb,
			       const struct nf_hook_state *state);

struct xt_match {
	const char *name;
};

struct xt_target {
	const char *name;
	unsigned int (*target)(struct sk_buff *skb, const void *par);
};

struct xt_counters {
	u64 pcnt, bcnt;
};

struct xt_entry_match {
	union {
		struct {
			u16 match_size;
			char name[29];
			u8 revision;
		} user;
		struct {
			u16 match_size;
			struct xt_match *match;
		} kernel;
		u16 match_size;
	} u;
	unsigned char data[0];
};

struct xt_entry_target {
	union {
		struct {
			u16 target_size;
			char name[29];
			u8 revision;
		} user;
		struct {
			u16 target_size;
			struct xt_target *target;
		} kernel;
		u16 target_size;
	} u;
	unsigned char data[0];
};

struct xt_standard_target {
	struct xt_entry_target target;
	int verdict;
};

#define xt_ematch_foreach(pos, entry) \
	for ((pos) = (struct xt_entry_match *)entry->elems; \
	     (pos) < (struct xt_entry_match *)((char *)(entry) + \
		     (entry)->target_offset); \
	     (pos) = (struct xt_entry_match *)((char *)(pos) + \
		     (pos)->u.match_size))

struct xt_table_info {
	unsigned int size;
	unsigned int number;
	unsigned int initial_entries;
	unsigned int hook_entry[NF_INET_NUMHOOKS];
	unsigned int underflow[NF_INET_NUMHOOKS];
	unsigned int stacksize;
	void ***jumpstack;
	unsigned char entries[] __attribute__((aligned(8)));
};

struct xt_table {
	struct xt_table_info *private;
};

#define IPT_F_FRAG		0x01
#define IPT_F_GOTO		0x02
#define IPT_INV_VIA_IN		0x01
#define IPT_INV_VIA_OUT		0x02
#define IPT_INV_SRCIP		0x08
#define IPT_INV_DSTIP		0x10
#define IPT_INV_FRAG		0x20
#define IPT_INV_PROTO		0x40

struct ipt_ip {
	struct in_addr src, dst;
	struct in_addr smsk, dmsk;
	char iniface[IFNAMSIZ], outiface[IFNAMSIZ];
	unsigned char iniface_mask[IFNAMSIZ], outiface_mask[IFNAMSIZ];
	u16 proto;
	u8 flags;
	u8 invflags;
};

struct ipt_entry {
	struct ipt_ip ip;
	unsigned int nfcache;
	u16 target_offset;
	u16 next_offset;
	unsigned int comefrom;
	struct xt_counters counters;
	unsigned char elems[0];
};

#define IP6T_F_PROTO		0x01
#define IP6T_F_GOTO		0x04
#define IP6T_INV_VIA_IN		0x01
#define IP6T_INV_VIA_OUT	0x02
#define IP6T_INV_SRCIP		0x08
#define IP6T_INV_DSTIP		0x10
#define IP6T_INV_PROTO		0x40

struct ip6t_ip6 {
	struct in6_addr src, dst;
	struct in6_addr smsk, dmsk;
	char iniface[IFNAMSIZ], outiface[IFNAMSIZ];
	unsigned char iniface_mask[IFNAMSIZ], outiface_mask[IFNAMSIZ];
	u16 proto;
	u8 tos;
	u8 flags;
	u8 invflags;
};

struct ip6t_entry {
	struct ip6t_ip6 ipv6;
	unsigned int nfcache;
	u16 target_offset;
	u16 next_offset;
	unsigned int comefrom;
	struct xt_counters counters;
	unsigned char elems[0];
};

/* ---- the netfilter core, as far as the probe reads it --------------------- */

struct nf_hook_ops {
	nf_hookfn *hook;
	void *priv;
	u8 pf;
	enum nf_hook_ops_type hook_ops_type:8;
	unsigned int hooknum;
};

struct nf_hook_entry {
	nf_hookfn *hook;
	void *priv;
};

/* As the kernel lays it out: the original ops of each hook follow the
 * entries, which is where nf_hook_entries_get_hook_ops() finds them. */
struct nf_hook_entries {
	u16 num_hook_entries;
	struct nf_hook_entry hooks[];
};

static struct nf_hook_ops **nf_hook_entries_get_hook_ops(const struct nf_hook_entries *e)
{
	return (struct nf_hook_ops **)&e->hooks[e->num_hook_entries];
}

struct nf_nat_lookup_hook_priv {
	struct nf_hook_entries *entries;
};

struct net {
	struct {
		struct nf_hook_entries *hooks_ipv4[NF_INET_NUMHOOKS];
		struct nf_hook_entries *hooks_ipv6[NF_INET_NUMHOOKS];
	} nf;
};

struct net_device {
	char name[IFNAMSIZ] __attribute__((aligned(sizeof(long))));
};

union nf_inet_addr {
	u32 all[4];
	__be32 ip;
	struct in6_addr in6;
};

struct nft_port_probe {
	u8 family;
	union nf_inet_addr saddr;
	union nf_inet_addr daddr;
	const struct net_device *in;
	const struct net_device * const *out;
	unsigned int nout;
	bool bridged;
};

struct nf_xt_probe_hook {
	int (*port_dependent)(struct net *net, const struct nft_port_probe *probe);
};

struct iphdr {
	u8 protocol;
	__be32 saddr;
	__be32 daddr;
};

/* What every table's hook would run in the kernel, here only compared
 * against: the probe never calls a hook. */
static unsigned int ipt_do_table(void *priv, struct sk_buff *skb,
				 const struct nf_hook_state *state)
{
	abort();
}
static unsigned int ip6t_do_table(void *priv, struct sk_buff *skb,
				  const struct nf_hook_state *state)
{
	abort();
}
/* A table's module running it through a wrapper of its own, as mangle does,
 * and an nf_tables chain sharing the NAT core's lookups. */
static unsigned int mangle_hook(void *priv, struct sk_buff *skb,
				const struct nf_hook_state *state)
{
	abort();
}
static unsigned int nft_chain_hook(void *priv, struct sk_buff *skb,
				   const struct nf_hook_state *state)
{
	abort();
}

/* The kernel's own, from include/linux/netfilter/x_tables.h. */
#include "ifname.inc"

/* ipv6_masked_addr_cmp() from include/net/ipv6.h, restated: whether the
 * masked addresses differ. */
static bool ipv6_masked_addr_cmp(const struct in6_addr *a1,
				 const struct in6_addr *m,
				 const struct in6_addr *a2)
{
	unsigned int i;

	for (i = 0; i < 16; i++)
		if ((a1->s6_addr[i] ^ a2->s6_addr[i]) & m->s6_addr[i])
			return true;
	return false;
}

/* Every read of a rule is a read of the table in force, inside the
 * packet path's section. */
static inline struct ipt_entry *ipt_get_entry(const void *base, unsigned int offset)
{
	assert(recseq_depth == 1);
	return (struct ipt_entry *)((const char *)base + offset);
}
static inline struct ipt_entry *ipt_next_entry(const struct ipt_entry *entry)
{
	return (struct ipt_entry *)((const char *)entry + entry->next_offset);
}
static inline const struct xt_entry_target *ipt_get_target_c(const struct ipt_entry *e)
{
	return (const struct xt_entry_target *)((const char *)e + e->target_offset);
}
static inline struct ip6t_entry *ip6t_get_entry(const void *base, unsigned int offset)
{
	assert(recseq_depth == 1);
	return (struct ip6t_entry *)((const char *)base + offset);
}
static inline struct ip6t_entry *ip6t_next_entry(const struct ip6t_entry *entry)
{
	return (struct ip6t_entry *)((const char *)entry + entry->next_offset);
}
static inline const struct xt_entry_target *ip6t_get_target_c(const struct ip6t_entry *e)
{
	return (const struct xt_entry_target *)((const char *)e + e->target_offset);
}

/* Hoisted to file scope by the patch, which the probe names for a hook
 * without an input or output device. */
static const char nulldevname[IFNAMSIZ] __attribute__((aligned(sizeof(long))));

/* The kernel's own, from net/ipv4/netfilter/ip_tables.c. */
#include "ip_packet_match.inc"

/* The patch's: the pure-match and passing-target lists, both walkers, and
 * the core's dispatcher. */
#include "xt_probe_lists.inc"
#define get_entry ipt_get_entry
#include "ipt_probe.inc"
#undef get_entry
#define get_entry ip6t_get_entry
#include "ip6t_probe.inc"
#undef get_entry
#include "xt_probe_core.inc"

/* ---- building tables ------------------------------------------------------ */

/* Everything a case allocates, freed when it ends. */
static void *arena[1024];
static unsigned int arena_used;
static void *alloc(size_t size)
{
	void *p = calloc(1, size);

	assert(p && arena_used < ARRAY_SIZE(arena));
	arena[arena_used++] = p;
	return p;
}
static void arena_free(void)
{
	while (arena_used)
		free(arena[--arena_used]);
}

/* Extensions by name, as the kernel resolves a rule's to the registered
 * match or target. */
static struct xt_match matches[64];
static unsigned int nmatches;
static struct xt_match *match_named(const char *name)
{
	unsigned int i;

	for (i = 0; i < nmatches; i++)
		if (!strcmp(matches[i].name, name))
			return &matches[i];
	assert(nmatches < ARRAY_SIZE(matches));
	matches[nmatches].name = name;
	return &matches[nmatches++];
}

static unsigned int some_target(struct sk_buff *skb, const void *par)
{
	abort();
}
static struct xt_target standard = { .name = "" };
static struct xt_target targets[64];
static unsigned int ntargets;
static struct xt_target *target_named(const char *name)
{
	unsigned int i;

	for (i = 0; i < ntargets; i++)
		if (!strcmp(targets[i].name, name))
			return &targets[i];
	assert(ntargets < ARRAY_SIZE(targets));
	targets[ntargets].name = name;
	targets[ntargets].target = some_target;
	return &targets[ntargets++];
}

enum act { A_NONE, A_ACCEPT, A_DROP, A_RETURN, A_QUEUE, A_JUMP, A_GOTO, A_TARGET };

/* One rule as iptables would be told it. Inversion bits are the family's
 * IPT_INV_ or IP6T_INV_ ones, which agree on everything used here. */
struct rule {
	const char *src, *dst;		/* "address[/len]"; none is any */
	const char *in, *out;		/* a trailing '+' is a wildcard */
	u8 inv;
	u16 proto;
	bool frag;			/* -f, IPv4 */
	const char *match[3];
	enum act act;
	const char *to;			/* a chain, or an extension target */
};

struct chain {
	const char *name;		/* none for a base chain */
	int hook;
	enum act policy;
	struct rule *rules;
	unsigned int n, cap;
	unsigned int head, start, tail;
};

struct spec {
	int family;
	struct chain chains[48];
	unsigned int n;
};

static struct chain *chain_add(struct spec *s)
{
	assert(s->n < ARRAY_SIZE(s->chains));
	return memset(&s->chains[s->n++], 0, sizeof(struct chain));
}
static struct chain *base_chain(struct spec *s, int hook, enum act policy)
{
	struct chain *c = chain_add(s);

	c->hook = hook;
	c->policy = policy;
	return c;
}
static struct chain *user_chain(struct spec *s, const char *name)
{
	struct chain *c = chain_add(s);

	c->name = name;
	c->hook = -1;
	return c;
}
static void add(struct chain *c, struct rule r)
{
	if (c->n == c->cap) {
		c->cap = c->cap ? 2 * c->cap : 8;
		c->rules = realloc(c->rules, c->cap * sizeof(*c->rules));
		assert(c->rules);
	}
	c->rules[c->n++] = r;
}
static void spec_free(struct spec *s)
{
	unsigned int i;

	for (i = 0; i < s->n; i++)
		free(s->chains[i].rules);
	s->n = 0;
}

/* An extension target with room for a name after it, as ERROR's is. */
#define EXT_TARGET_SIZE XT_ALIGN(sizeof(struct xt_entry_target) + 32)

static size_t entry_size(int family)
{
	return family == 4 ? sizeof(struct ipt_entry) : sizeof(struct ip6t_entry);
}
static size_t rule_size(int family, const struct rule *r)
{
	size_t size = entry_size(family);
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(r->match) && r->match[i]; i++)
		size += XT_ALIGN(sizeof(struct xt_entry_match));
	if (r->act == A_TARGET)
		return size + EXT_TARGET_SIZE;
	return size + XT_ALIGN(sizeof(struct xt_standard_target));
}
static size_t error_size(int family)
{
	return entry_size(family) + EXT_TARGET_SIZE;
}
static size_t standard_size(int family)
{
	return entry_size(family) + XT_ALIGN(sizeof(struct xt_standard_target));
}

static const struct chain *chain_named(const struct spec *s, const char *name)
{
	unsigned int i;

	for (i = 0; i < s->n; i++)
		if (s->chains[i].name && !strcmp(s->chains[i].name, name))
			return &s->chains[i];
	assert(!"no such chain");
	return NULL;
}

static void iface(const char *name, char *field, unsigned char *mask)
{
	size_t len;

	if (!name)
		return;
	len = strlen(name);
	memcpy(field, name, len);
	if (len && name[len - 1] == '+') {
		field[len - 1] = 0;
		memset(mask, 0xff, len - 1);
	} else {
		memset(mask, 0xff, len + 1);
	}
}

static void prefix(int family, const char *text, void *addr, void *mask)
{
	char buf[64];
	char *slash;
	unsigned int len, bits = family == 4 ? 32 : 128, i;
	unsigned char *a = addr, *m = mask;

	if (!text)
		return;
	snprintf(buf, sizeof(buf), "%s", text);
	slash = strchr(buf, '/');
	len = bits;
	if (slash) {
		*slash = 0;
		len = (unsigned int)atoi(slash + 1);
	}
	assert(inet_pton(family == 4 ? AF_INET : AF_INET6, buf, addr) == 1);
	for (i = 0; i < bits / 8; i++) {
		unsigned int have = len > 8 * i ? len - 8 * i : 0;

		m[i] = have >= 8 ? 0xff : (unsigned char)(0xff00 >> have);
		a[i] &= m[i];
	}
}

/* An entry's header and target, its matches between them; returns how long
 * it is. */
static size_t entry_at(unsigned char *base, unsigned int off, int family,
		       const struct rule *r, u8 flags,
		       struct xt_target *target, int verdict)
{
	unsigned char *e = base + off;
	size_t at = entry_size(family);
	struct xt_entry_target *t;
	u16 *target_offset, *next_offset;
	unsigned int i;

	if (family == 4) {
		struct ipt_entry *v4 = (struct ipt_entry *)e;

		if (r) {
			prefix(4, r->src, &v4->ip.src, &v4->ip.smsk);
			prefix(4, r->dst, &v4->ip.dst, &v4->ip.dmsk);
			iface(r->in, v4->ip.iniface, v4->ip.iniface_mask);
			iface(r->out, v4->ip.outiface, v4->ip.outiface_mask);
			v4->ip.proto = r->proto;
			v4->ip.invflags = r->inv;
			if (r->frag)
				flags |= IPT_F_FRAG;
		}
		v4->ip.flags = flags;
		target_offset = &v4->target_offset;
		next_offset = &v4->next_offset;
	} else {
		struct ip6t_entry *v6 = (struct ip6t_entry *)e;

		if (r) {
			prefix(6, r->src, &v6->ipv6.src, &v6->ipv6.smsk);
			prefix(6, r->dst, &v6->ipv6.dst, &v6->ipv6.dmsk);
			iface(r->in, v6->ipv6.iniface, v6->ipv6.iniface_mask);
			iface(r->out, v6->ipv6.outiface, v6->ipv6.outiface_mask);
			v6->ipv6.proto = r->proto;
			if (r->proto)
				flags |= IP6T_F_PROTO;
			v6->ipv6.invflags = r->inv;
		}
		v6->ipv6.flags = flags;
		target_offset = &v6->target_offset;
		next_offset = &v6->next_offset;
	}
	for (i = 0; r && i < ARRAY_SIZE(r->match) && r->match[i]; i++) {
		struct xt_entry_match *m = (struct xt_entry_match *)(e + at);

		m->u.kernel.match_size = XT_ALIGN(sizeof(*m));
		m->u.kernel.match = match_named(r->match[i]);
		at += XT_ALIGN(sizeof(*m));
	}
	*target_offset = (u16)at;
	t = (struct xt_entry_target *)(e + at);
	t->u.kernel.target = target;
	if (target == &standard) {
		t->u.kernel.target_size = XT_ALIGN(sizeof(struct xt_standard_target));
		((struct xt_standard_target *)t)->verdict = verdict;
	} else {
		t->u.kernel.target_size = EXT_TARGET_SIZE;
	}
	at += t->u.kernel.target_size;
	*next_offset = (u16)at;
	return at;
}

static int standard_verdict(enum act act)
{
	switch (act) {
	case A_ACCEPT:	return -NF_ACCEPT - 1;
	case A_DROP:	return -NF_DROP - 1;
	case A_RETURN:	return XT_RETURN;
	case A_QUEUE:	return -NF_QUEUE - 1;
	default:	abort();
	}
}

/* Lay a table out and hand it over as the one in force. */
static struct xt_table *build(struct spec *s)
{
	struct xt_table_info *info;
	struct xt_table *table;
	unsigned int off = 0, i, j;
	int f = s->family;

	for (i = 0; i < s->n; i++) {
		struct chain *c = &s->chains[i];

		if (c->name) {
			c->head = off;
			off += error_size(f);
		}
		c->start = off;
		for (j = 0; j < c->n; j++)
			off += rule_size(f, &c->rules[j]);
		c->tail = off;
		off += standard_size(f);
	}
	info = alloc(sizeof(*info) + off + error_size(f));
	info->size = off + error_size(f);
	for (i = 0; i < s->n; i++) {
		const struct chain *c = &s->chains[i];
		unsigned int at = c->start;

		if (c->name) {
			entry_at(info->entries, c->head, f, NULL, 0, target_named("ERROR"), 0);
		} else {
			info->hook_entry[c->hook] = c->start;
			info->underflow[c->hook] = c->tail;
		}
		for (j = 0; j < c->n; j++) {
			const struct rule *r = &c->rules[j];
			unsigned int size = rule_size(f, r);
			u8 go = f == 4 ? IPT_F_GOTO : IP6T_F_GOTO;
			size_t laid;

			switch (r->act) {
			case A_NONE:
				laid = entry_at(info->entries, at, f, r, 0, &standard,
						(int)(at + size));
				break;
			case A_JUMP:
			case A_GOTO:
				laid = entry_at(info->entries, at, f, r,
						r->act == A_GOTO ? go : 0, &standard,
						(int)chain_named(s, r->to)->start);
				break;
			case A_TARGET:
				laid = entry_at(info->entries, at, f, r, 0,
						target_named(r->to), 0);
				break;
			default:
				laid = entry_at(info->entries, at, f, r, 0, &standard,
						standard_verdict(r->act));
				break;
			}
			assert(laid == size);
			at += size;
		}
		entry_at(info->entries, c->tail, f, NULL, 0, &standard,
			 standard_verdict(c->name ? A_RETURN : c->policy));
	}
	entry_at(info->entries, off, f, NULL, 0, target_named("ERROR"), 0);
	table = alloc(sizeof(*table));
	table->private = info;
	return table;
}

/* Register a hook, as nf_register_net_hook() leaves the family's list at
 * that hook: the entries, then the ops they came from. */
static struct nf_hook_entries **hook_list(struct net *net, int family, int hook)
{
	return family == 4 ? &net->nf.hooks_ipv4[hook] : &net->nf.hooks_ipv6[hook];
}
static void entries_append(struct nf_hook_entries **list, enum nf_hook_ops_type type,
			   nf_hookfn *fn, void *priv)
{
	const struct nf_hook_entries *old = *list;
	unsigned int n = old ? old->num_hook_entries : 0, i;
	struct nf_hook_entries *e;
	struct nf_hook_ops *ops = alloc(sizeof(*ops));

	e = alloc(sizeof(*e) + (n + 1) * (sizeof(struct nf_hook_entry) +
					  sizeof(struct nf_hook_ops *)));
	e->num_hook_entries = (u16)(n + 1);
	for (i = 0; i < n; i++) {
		e->hooks[i] = old->hooks[i];
		nf_hook_entries_get_hook_ops(e)[i] = nf_hook_entries_get_hook_ops(old)[i];
	}
	ops->hook = fn;
	ops->priv = priv;
	ops->hook_ops_type = type;
	e->hooks[n].hook = fn;
	e->hooks[n].priv = priv;
	nf_hook_entries_get_hook_ops(e)[n] = ops;
	*list = e;
}
static void hook_add(struct net *net, int family, int hooknum, enum nf_hook_ops_type type,
		     nf_hookfn *fn, void *priv)
{
	entries_append(hook_list(net, family, hooknum), type, fn, priv);
}

/* A table on every hook it has a base chain for, typed as ip_tables and
 * ip6_tables type theirs. */
static struct xt_table *table_on(struct net *net, struct spec *s, enum nf_hook_ops_type type,
				 nf_hookfn *fn)
{
	struct xt_table *table = build(s);
	unsigned int i;

	for (i = 0; i < s->n; i++)
		if (!s->chains[i].name)
			hook_add(net, s->family, s->chains[i].hook, type, fn, table);
	return table;
}
static struct xt_table *filter(struct net *net, struct spec *s)
{
	return table_on(net, s, NF_HOOK_OP_XTABLES,
			s->family == 4 ? ipt_do_table : ip6t_do_table);
}

/* The NAT core's hook at a hook number, and a NAT table registered with it
 * rather than with netfilter. */
static struct nf_nat_lookup_hook_priv *nat_core(struct net *net, int family, int hooknum)
{
	struct nf_nat_lookup_hook_priv *nat = alloc(sizeof(*nat));

	hook_add(net, family, hooknum, NF_HOOK_OP_NAT, nft_chain_hook, nat);
	return nat;
}
static struct xt_table *nat_table(struct nf_nat_lookup_hook_priv *pre,
				  struct nf_nat_lookup_hook_priv *post, struct spec *s)
{
	struct xt_table *table = build(s);
	nf_hookfn *fn = s->family == 4 ? ipt_do_table : ip6t_do_table;
	unsigned int i;

	for (i = 0; i < s->n; i++) {
		if (s->chains[i].name)
			continue;
		entries_append(s->chains[i].hook == NF_INET_PRE_ROUTING ?
			       &pre->entries : &post->entries,
			       NF_HOOK_OP_UNDEFINED, fn, table);
	}
	return table;
}

/* ---- asking ----------------------------------------------------------------- */

static struct net_device eth3 = { "eth3" }, eth4 = { "eth4" }, eth4_7 = { "eth4.7" },
			 wlan0 = { "wlan0" };
static const char *source4 = "198.51.100.7", *group4 = "239.9.11.1";
static const char *source6 = "2001:db8::7", *group6 = "ff1e::9:11:1";

/* Whether x_tables could tell the stream's ports apart, as the routed
 * learner asks it: under RCU, with every section closed again after. */
static int ask(struct net *net, int family, const struct net_device *in,
	       const struct net_device *const *out, unsigned int nout)
{
	struct nft_port_probe probe = {
		.family = family == 4 ? NFPROTO_IPV4 : NFPROTO_IPV6,
		.in = in,
		.out = out,
		.nout = nout,
	};
	int af = family == 4 ? AF_INET : AF_INET6;
	int rc;

	assert(inet_pton(af, family == 4 ? source4 : source6, &probe.saddr) == 1);
	assert(inet_pton(af, family == 4 ? group4 : group6, &probe.daddr) == 1);
	rcu_depth++;
	rc = nf_xt_port_dependent(net, &probe);
	rcu_depth--;
	assert(!bh_depth && !recseq_depth);
	return rc;
}
static int ask1(struct net *net, int family, const struct net_device *in,
		const struct net_device *out)
{
	return ask(net, family, in, &out, 1);
}

/* One case: a namespace with no table, and a family's tables in it. */
static struct net net;
static struct spec spec;
static void begin(int family)
{
	memset(&net, 0, sizeof(net));
	spec_free(&spec);
	spec.family = family;
}
static void end(void)
{
	spec_free(&spec);
	arena_free();
}

/* A FORWARD chain holding one rule, policy as given, alone in a table. */
static int one_rule(int family, struct rule r, enum act policy,
		    const struct net_device *in, const struct net_device *out)
{
	int rc;

	begin(family);
	add(base_chain(&spec, NF_INET_FORWARD, policy), r);
	filter(&net, &spec);
	rc = ask1(&net, family, in, out);
	end();
	return rc;
}

static void dispatch(void)
{
	const struct net_device *none = NULL;

	/* No table, or no module: nothing judges the stream apart. */
	begin(4);
	assert(ask1(&net, 4, &eth4, &eth3) == 0 && ask1(&net, 6, &eth4, &eth3) == 0);
	add(base_chain(&spec, NF_INET_FORWARD, A_DROP), (struct rule){ .act = A_DROP });
	filter(&net, &spec);
	nf_ipt_probe_hook = NULL;
	assert(ask1(&net, 4, &eth4, &eth3) == 0);
	nf_ipt_probe_hook = &ipt_probe_hook;
	assert(ask1(&net, 4, &eth4, &eth3) == 1);
	/* Another family has no x_tables answer to give: dependent. */
	{
		struct nft_port_probe probe = { .family = NFPROTO_ARP, .in = &eth4 };

		rcu_depth++;
		assert(nf_xt_port_dependent(&net, &probe) == 1);
		rcu_depth--;
	}
	/* What a bridge forwards crosses no x_tables hook, whatever the
	 * tables drop, and needs no output to be judged. */
	{
		const struct net_device *out = &eth3;
		struct nft_port_probe probe = { .family = NFPROTO_IPV4, .in = &eth4,
						.out = &out, .nout = 1, .bridged = true };

		rcu_depth++;
		assert(nf_xt_port_dependent(&net, &probe) == 0);
		probe.nout = 0;
		assert(nf_xt_port_dependent(&net, &probe) == 0);
		rcu_depth--;
	}
	/* A stream that leaves nowhere is not one to judge. */
	assert(ask(&net, 4, &eth4, NULL, 0) == -EINVAL);
	assert(ask(&net, 4, &eth4, &none, 1) == -EINVAL);
	assert(ask1(&net, 4, NULL, &eth3) == -EINVAL);
	end();
}

static void initial_tables(int family)
{
	/* The tables a module instantiates, every policy ACCEPT, at every hook
	 * a forwarded copy crosses and the local ones it does not. */
	begin(family);
	base_chain(&spec, NF_INET_LOCAL_IN, A_ACCEPT);
	base_chain(&spec, NF_INET_FORWARD, A_ACCEPT);
	base_chain(&spec, NF_INET_LOCAL_OUT, A_ACCEPT);
	filter(&net, &spec);
	assert(ask1(&net, family, &eth4, &eth3) == 0);
	end();
	/* A local hook's DROP is not on the forwarded path. */
	begin(family);
	base_chain(&spec, NF_INET_LOCAL_IN, A_DROP);
	add(base_chain(&spec, NF_INET_LOCAL_OUT, A_ACCEPT), (struct rule){ .act = A_DROP });
	filter(&net, &spec);
	assert(ask1(&net, family, &eth4, &eth3) == 0);
	end();
}

/* The router image's own legacy ruleset: forward pairs for LAN and WLAN,
 * the WAN masqueraded. */
static void meta_ask_ruleset(void)
{
	struct nf_nat_lookup_hook_priv *pre, *post;
	struct spec nat = { .family = 4 };
	struct chain *fwd, *post_nat;
	const struct net_device *both[] = { &eth3, &eth4_7 };

	begin(4);
	base_chain(&spec, NF_INET_LOCAL_IN, A_ACCEPT);
	fwd = base_chain(&spec, NF_INET_FORWARD, A_ACCEPT);
	base_chain(&spec, NF_INET_LOCAL_OUT, A_ACCEPT);
	add(fwd, (struct rule){ .in = "eth3", .out = "eth4", .act = A_ACCEPT });
	add(fwd, (struct rule){ .in = "eth4", .out = "eth3", .match = { "state" },
				 .act = A_ACCEPT });
	add(fwd, (struct rule){ .in = "wlan0", .out = "eth4", .act = A_ACCEPT });
	add(fwd, (struct rule){ .in = "eth4", .out = "wlan0", .match = { "state" },
				 .act = A_ACCEPT });
	filter(&net, &spec);
	pre = nat_core(&net, 4, NF_INET_PRE_ROUTING);
	post = nat_core(&net, 4, NF_INET_POST_ROUTING);
	base_chain(&nat, NF_INET_PRE_ROUTING, A_ACCEPT);
	post_nat = base_chain(&nat, NF_INET_POST_ROUTING, A_ACCEPT);
	add(post_nat, (struct rule){ .out = "eth4", .act = A_TARGET, .to = "MASQUERADE" });
	nat_table(pre, post, &nat);

	/* WAN to LAN, untagged or tagged, alone or together: accepted, and
	 * never masqueraded, since eth4 names the WAN port and no VLAN on it. */
	assert(ask1(&net, 4, &eth4, &eth3) == 0);
	assert(ask1(&net, 4, &eth4, &eth4_7) == 0);
	assert(ask(&net, 4, &eth4, both, 2) == 0);
	assert(ask1(&net, 4, &eth4, &wlan0) == 0);
	/* Out of the WAN port: masqueraded, which no address-keyed copy is. */
	assert(ask1(&net, 4, &eth3, &eth4) == 1);
	spec_free(&nat);
	end();

	/* IPv6: one conntrack accept, ahead of an accepting policy. */
	begin(6);
	add(base_chain(&spec, NF_INET_FORWARD, A_ACCEPT),
	    (struct rule){ .match = { "conntrack" }, .act = A_ACCEPT });
	filter(&net, &spec);
	assert(ask1(&net, 6, &eth4, &eth3) == 0);
	assert(ask1(&net, 6, &eth3, &eth4) == 0);
	end();
}

static void port_rules(int family)
{
	const char *g = family == 4 ? group4 : group6;
	const char *other = family == 4 ? "239.9.11.2" : "ff1e::9:11:2";
	const char *block = family == 4 ? "239.0.0.0/8" : "ff00::/8";

	/* A port of the group dropped: the other ports would ride the entry. */
	assert(one_rule(family, (struct rule){ .dst = g, .proto = IPPROTO_UDP,
		.match = { "udp" }, .act = A_DROP }, A_ACCEPT, &eth4, &eth3) == 1);
	/* Another group's, or another protocol's: not this stream. */
	assert(one_rule(family, (struct rule){ .dst = other, .proto = IPPROTO_UDP,
		.match = { "udp" }, .act = A_DROP }, A_ACCEPT, &eth4, &eth3) == 0);
	assert(one_rule(family, (struct rule){ .dst = g, .proto = IPPROTO_TCP,
		.match = { "tcp" }, .act = A_DROP }, A_ACCEPT, &eth4, &eth3) == 0);
	/* But not TCP is the stream itself, and not UDP is not. */
	assert(one_rule(family, (struct rule){ .dst = g, .proto = IPPROTO_TCP,
		.inv = IPT_INV_PROTO, .act = A_DROP }, A_ACCEPT, &eth4, &eth3) == 1);
	assert(one_rule(family, (struct rule){ .dst = g, .proto = IPPROTO_UDP,
		.inv = IPT_INV_PROTO, .act = A_DROP }, A_ACCEPT, &eth4, &eth3) == 0);
	/* The whole scope accepted ahead of a dropping policy: every packet. */
	assert(one_rule(family, (struct rule){ .dst = block, .act = A_ACCEPT },
			A_DROP, &eth4, &eth3) == 0);
	/* Only what a match accepts: the rest meets the policy. */
	assert(one_rule(family, (struct rule){ .dst = g, .proto = IPPROTO_UDP,
		.match = { "udp" }, .act = A_ACCEPT }, A_DROP, &eth4, &eth3) == 1);
	/* A protocol named takes every packet of the stream in IPv4, whose
	 * header carries it. IPv6 finds it after the extension headers, and a
	 * later fragment whose fragment header is followed by another has
	 * nothing there: the rule takes the rest of the stream, and that
	 * fragment meets the policy. */
	assert(one_rule(family, (struct rule){ .dst = g, .proto = IPPROTO_UDP,
		.act = A_ACCEPT }, A_DROP, &eth4, &eth3) == (family == 6));
	assert(one_rule(family, (struct rule){ .dst = g, .proto = IPPROTO_TCP,
		.inv = IPT_INV_PROTO, .act = A_ACCEPT }, A_DROP, &eth4, &eth3) == (family == 6));
	assert(one_rule(family, (struct rule){ .dst = g, .proto = IPPROTO_UDP,
		.act = A_ACCEPT }, A_ACCEPT, &eth4, &eth3) == 0);
	/* A queue, whatever reaches it. */
	assert(one_rule(family, (struct rule){ .dst = g, .act = A_QUEUE },
			A_ACCEPT, &eth4, &eth3) == 1);
	/* A rule with no target falls through, its match or not. */
	assert(one_rule(family, (struct rule){ .dst = g, .match = { "udp" },
		.act = A_NONE }, A_ACCEPT, &eth4, &eth3) == 0);
	/* Logging and tracing change nothing; a mark does. */
	assert(one_rule(family, (struct rule){ .dst = g, .act = A_TARGET, .to = "LOG" },
			A_ACCEPT, &eth4, &eth3) == 0);
	assert(one_rule(family, (struct rule){ .match = { "udp" }, .act = A_TARGET,
		.to = "NFLOG" }, A_ACCEPT, &eth4, &eth3) == 0);
	assert(one_rule(family, (struct rule){ .act = A_TARGET, .to = "TRACE" },
			A_ACCEPT, &eth4, &eth3) == 0);
	assert(one_rule(family, (struct rule){ .dst = g, .act = A_TARGET, .to = "MARK" },
			A_ACCEPT, &eth4, &eth3) == 1);
	assert(one_rule(family, (struct rule){ .act = A_TARGET, .to = "CT" },
			A_ACCEPT, &eth4, &eth3) == 1);
	/* A match that records the packet for another rule to read, or one
	 * this list does not know, whatever the rule's verdict. */
	assert(one_rule(family, (struct rule){ .match = { "recent" }, .act = A_ACCEPT },
			A_ACCEPT, &eth4, &eth3) == 1);
	assert(one_rule(family, (struct rule){ .match = { "comment", "connlabel" },
		.act = A_ACCEPT }, A_ACCEPT, &eth4, &eth3) == 1);
	assert(one_rule(family, (struct rule){ .match = { "nosuchmatch" }, .act = A_NONE },
			A_ACCEPT, &eth4, &eth3) == 1);
	/* socket can restore the socket's mark onto the packet. */
	assert(one_rule(family, (struct rule){ .match = { "socket" }, .act = A_NONE },
			A_ACCEPT, &eth4, &eth3) == 1);
	/* A match that drops a packet itself, whatever the rule says: hashlimit
	 * one it has no room to give a bucket -- by destination port, a full
	 * table drops the ports that came last -- and connlimit one it cannot
	 * count. Even a rule that only logs, or one with no target at all. */
	assert(one_rule(family, (struct rule){ .dst = g, .match = { "hashlimit" },
		.act = A_TARGET, .to = "LOG" }, A_ACCEPT, &eth4, &eth3) == 1);
	assert(one_rule(family, (struct rule){ .dst = g, .match = { "hashlimit" },
		.act = A_ACCEPT }, A_ACCEPT, &eth4, &eth3) == 1);
	assert(one_rule(family, (struct rule){ .dst = g, .match = { "connlimit" },
		.act = A_NONE }, A_ACCEPT, &eth4, &eth3) == 1);
	assert(one_rule(family, (struct rule){ .dst = g, .match = { "connlimit" },
		.act = A_ACCEPT }, A_ACCEPT, &eth4, &eth3) == 1);
	/* A plain limit keeps one bucket, drops nothing itself, and only
	 * decides its rule. */
	assert(one_rule(family, (struct rule){ .dst = g, .match = { "limit" },
		.act = A_TARGET, .to = "LOG" }, A_ACCEPT, &eth4, &eth3) == 0);
	/* A comment changes nothing for a policy that accepts too. No match is
	 * evaluated, so even one that always applies may not, and with a
	 * dropping policy behind it the rest of the stream may meet the drop. */
	assert(one_rule(family, (struct rule){ .match = { "comment" }, .act = A_ACCEPT },
			A_ACCEPT, &eth4, &eth3) == 0);
	assert(one_rule(family, (struct rule){ .match = { "comment" }, .act = A_ACCEPT },
			A_DROP, &eth4, &eth3) == 1);
	/* Not this source: skipped, recent and all. */
	assert(one_rule(family, (struct rule){
		.src = family == 4 ? "192.0.2.1" : "2001:db8::1",
		.match = { "recent" }, .act = A_DROP }, A_ACCEPT, &eth4, &eth3) == 0);
	assert(one_rule(family, (struct rule){
		.src = family == 4 ? "192.0.2.1" : "2001:db8::1", .inv = IPT_INV_SRCIP,
		.act = A_DROP }, A_ACCEPT, &eth4, &eth3) == 1);
}

static void fragments(void)
{
	/* -f singles out later fragments, which the entry carries as well. */
	assert(one_rule(4, (struct rule){ .frag = true, .act = A_DROP }, A_ACCEPT,
			&eth4, &eth3) == 1);
	assert(one_rule(4, (struct rule){ .frag = true, .inv = IPT_INV_FRAG,
		.act = A_DROP }, A_ACCEPT, &eth4, &eth3) == 1);
	assert(one_rule(4, (struct rule){ .frag = true, .act = A_TARGET, .to = "LOG" },
			A_ACCEPT, &eth4, &eth3) == 0);
	/* A whole accept for later fragments only leaves the rest to the
	 * policy. */
	assert(one_rule(4, (struct rule){ .frag = true, .act = A_ACCEPT }, A_DROP,
			&eth4, &eth3) == 1);
}

static void devices(int family)
{
	/* Per oif: a drop toward every device but one. */
	assert(one_rule(family, (struct rule){ .out = "eth3", .inv = IPT_INV_VIA_OUT,
		.act = A_DROP }, A_ACCEPT, &eth4, &eth3) == 0);
	assert(one_rule(family, (struct rule){ .out = "eth3", .inv = IPT_INV_VIA_OUT,
		.act = A_DROP }, A_ACCEPT, &eth4, &eth4) == 1);
	/* A wildcard covers the VLAN as well as the port. */
	assert(one_rule(family, (struct rule){ .out = "eth4+", .act = A_DROP },
			A_ACCEPT, &eth3, &eth4_7) == 1);
	assert(one_rule(family, (struct rule){ .out = "eth4", .act = A_DROP },
			A_ACCEPT, &eth3, &eth4_7) == 0);
	assert(one_rule(family, (struct rule){ .in = "eth3", .act = A_DROP },
			A_ACCEPT, &eth4, &eth4_7) == 0);
	assert(one_rule(family, (struct rule){ .in = "eth4", .act = A_DROP },
			A_ACCEPT, &eth4, &eth4_7) == 1);
	/* At postrouting IPv4 names no input. ip6mr has made the output the
	 * copy's device by then, which ip6_output() hands the hook as its
	 * input. iptables refuses -i in POSTROUTING itself, not in a chain it
	 * jumps to. */
	begin(family);
	add(base_chain(&spec, NF_INET_POST_ROUTING, A_ACCEPT),
	    (struct rule){ .act = A_JUMP, .to = "out" });
	add(user_chain(&spec, "out"), (struct rule){ .in = "eth3", .act = A_DROP });
	filter(&net, &spec);
	assert(ask1(&net, family, &eth4, &eth3) == (family == 6));
	assert(ask1(&net, family, &eth4, &eth4_7) == 0);
	end();
	begin(family);
	add(base_chain(&spec, NF_INET_POST_ROUTING, A_ACCEPT),
	    (struct rule){ .act = A_JUMP, .to = "out" });
	add(user_chain(&spec, "out"), (struct rule){ .in = "eth4", .act = A_DROP });
	filter(&net, &spec);
	assert(ask1(&net, family, &eth4, &eth3) == 0);
	end();
	/* Any oif dropped is the group dependent. */
	{
		const struct net_device *both[] = { &eth3, &eth4_7 };

		begin(family);
		add(base_chain(&spec, NF_INET_FORWARD, A_ACCEPT),
		    (struct rule){ .out = "eth4.7", .act = A_DROP });
		filter(&net, &spec);
		assert(ask(&net, family, &eth4, both, 2) == 1);
		assert(ask(&net, family, &eth4, both, 1) == 0);
		end();
	}
}

static void chains(int family)
{
	struct chain *fwd, *c;

	/* A jump to a chain that drops some of the stream. */
	begin(family);
	fwd = base_chain(&spec, NF_INET_FORWARD, A_ACCEPT);
	add(fwd, (struct rule){ .act = A_JUMP, .to = "ports" });
	add(user_chain(&spec, "ports"), (struct rule){ .proto = IPPROTO_UDP,
		.match = { "udp" }, .act = A_DROP });
	filter(&net, &spec);
	assert(ask1(&net, family, &eth4, &eth3) == 1);
	end();

	/* One that only returns. */
	begin(family);
	fwd = base_chain(&spec, NF_INET_FORWARD, A_ACCEPT);
	add(fwd, (struct rule){ .act = A_JUMP, .to = "ports" });
	c = user_chain(&spec, "ports");
	add(c, (struct rule){ .match = { "udp" }, .act = A_RETURN });
	add(c, (struct rule){ .match = { "udp" }, .act = A_TARGET, .to = "LOG" });
	filter(&net, &spec);
	assert(ask1(&net, family, &eth4, &eth3) == 0);
	end();

	/* One that accepts every packet: whatever the base chain does after
	 * the jump, nothing reaches it ... */
	begin(family);
	fwd = base_chain(&spec, NF_INET_FORWARD, A_DROP);
	add(fwd, (struct rule){ .act = A_JUMP, .to = "all" });
	add(fwd, (struct rule){ .act = A_DROP });
	add(user_chain(&spec, "all"), (struct rule){ .act = A_ACCEPT });
	filter(&net, &spec);
	assert(ask1(&net, family, &eth4, &eth3) == 0);
	end();
	/* ... unless the jump may not be taken. */
	begin(family);
	fwd = base_chain(&spec, NF_INET_FORWARD, A_ACCEPT);
	add(fwd, (struct rule){ .match = { "udp" }, .act = A_JUMP, .to = "all" });
	add(fwd, (struct rule){ .act = A_DROP });
	add(user_chain(&spec, "all"), (struct rule){ .act = A_ACCEPT });
	filter(&net, &spec);
	assert(ask1(&net, family, &eth4, &eth3) == 1);
	end();

	/* A goto pushes nothing: what returns from its chain meets the base
	 * chain's policy. */
	for (int policy = 0; policy < 2; policy++) {
		begin(family);
		fwd = base_chain(&spec, NF_INET_FORWARD, policy ? A_DROP : A_ACCEPT);
		add(fwd, (struct rule){ .act = A_GOTO, .to = "back" });
		add(fwd, (struct rule){ .act = A_ACCEPT });
		add(user_chain(&spec, "back"), (struct rule){ .match = { "udp" },
			.act = A_RETURN });
		filter(&net, &spec);
		assert(ask1(&net, family, &eth4, &eth3) == policy);
		end();
	}
	/* A jump returns to the rule after it instead, which accepts. */
	begin(family);
	fwd = base_chain(&spec, NF_INET_FORWARD, A_DROP);
	add(fwd, (struct rule){ .act = A_JUMP, .to = "back" });
	add(fwd, (struct rule){ .act = A_ACCEPT });
	add(user_chain(&spec, "back"), (struct rule){ .match = { "udp" }, .act = A_RETURN });
	filter(&net, &spec);
	assert(ask1(&net, family, &eth4, &eth3) == 0);
	end();
	/* Or drops: what returned meets it, though the jump took everything. */
	begin(family);
	fwd = base_chain(&spec, NF_INET_FORWARD, A_ACCEPT);
	add(fwd, (struct rule){ .act = A_JUMP, .to = "back" });
	add(fwd, (struct rule){ .act = A_DROP });
	c = user_chain(&spec, "back");
	add(c, (struct rule){ .match = { "udp" }, .act = A_RETURN });
	add(c, (struct rule){ .act = A_ACCEPT });
	filter(&net, &spec);
	assert(ask1(&net, family, &eth4, &eth3) == 1);
	end();
	/* A goto through two chains: a return from the second leaves the
	 * first as well, past the rule after the jump into it. */
	begin(family);
	fwd = base_chain(&spec, NF_INET_FORWARD, A_ACCEPT);
	add(fwd, (struct rule){ .act = A_JUMP, .to = "first" });
	add(fwd, (struct rule){ .act = A_ACCEPT });
	c = user_chain(&spec, "first");
	add(c, (struct rule){ .act = A_GOTO, .to = "second" });
	add(c, (struct rule){ .act = A_DROP });
	add(user_chain(&spec, "second"), (struct rule){ .act = A_RETURN });
	filter(&net, &spec);
	assert(ask1(&net, family, &eth4, &eth3) == 0);
	end();

	/* A goto that may not be taken leaves the rest to the base chain. */
	begin(family);
	fwd = base_chain(&spec, NF_INET_FORWARD, A_ACCEPT);
	add(fwd, (struct rule){ .match = { "udp" }, .act = A_GOTO, .to = "all" });
	add(fwd, (struct rule){ .act = A_DROP });
	add(user_chain(&spec, "all"), (struct rule){ .act = A_ACCEPT });
	filter(&net, &spec);
	assert(ask1(&net, family, &eth4, &eth3) == 1);
	end();

	/* Rules with no target fall through, however many: a jump to the next
	 * entry nests nothing. */
	begin(family);
	fwd = base_chain(&spec, NF_INET_FORWARD, A_ACCEPT);
	for (int i = 0; i < 40; i++)
		add(fwd, (struct rule){ .act = A_NONE });
	filter(&net, &spec);
	assert(ask1(&net, family, &eth4, &eth3) == 0);
	end();

	/* RETURN in the base chain is the policy. */
	for (int policy = 0; policy < 2; policy++) {
		begin(family);
		fwd = base_chain(&spec, NF_INET_FORWARD, policy ? A_DROP : A_ACCEPT);
		add(fwd, (struct rule){ .match = { "udp" }, .act = A_RETURN });
		add(fwd, (struct rule){ .act = A_ACCEPT });
		filter(&net, &spec);
		assert(ask1(&net, family, &eth4, &eth3) == policy);
		end();
	}
}

static void hooks_and_tables(int family)
{
	struct spec more = { .family = family };
	struct nf_nat_lookup_hook_priv *pre, *post;
	nf_hookfn *own = family == 4 ? ipt_do_table : ip6t_do_table;

	/* A mangle table, run through a wrapper of its own module's: at
	 * prerouting it sees no output device and applies to every oif ... */
	begin(family);
	add(base_chain(&spec, NF_INET_PRE_ROUTING, A_ACCEPT),
	    (struct rule){ .in = "eth4", .match = { "udp" }, .act = A_TARGET, .to = "MARK" });
	table_on(&net, &spec, NF_HOOK_OP_XTABLES, mangle_hook);
	assert(ask1(&net, family, &eth4, &eth3) == 1);
	assert(ask1(&net, family, &eth4, &eth4_7) == 1);
	assert(ask1(&net, family, &eth3, &eth4) == 0);
	end();
	begin(family);
	add(base_chain(&spec, NF_INET_PRE_ROUTING, A_ACCEPT),
	    (struct rule){ .out = "eth3", .act = A_DROP });
	table_on(&net, &spec, NF_HOOK_OP_XTABLES, mangle_hook);
	assert(ask1(&net, family, &eth4, &eth3) == 0);
	end();
	/* ... at forward and postrouting, per oif; postrouting's input is no
	 * device, or the oif, never the one the stream arrived on. */
	begin(family);
	add(base_chain(&spec, NF_INET_FORWARD, A_ACCEPT),
	    (struct rule){ .out = "eth4.7", .act = A_TARGET, .to = "MARK" });
	add(base_chain(&spec, NF_INET_POST_ROUTING, A_ACCEPT),
	    (struct rule){ .in = "eth4", .act = A_DROP });
	table_on(&net, &spec, NF_HOOK_OP_XTABLES, mangle_hook);
	assert(ask1(&net, family, &eth4, &eth3) == 0);
	assert(ask1(&net, family, &eth4, &eth4_7) == 1);
	end();
	begin(family);
	add(base_chain(&spec, NF_INET_POST_ROUTING, A_ACCEPT),
	    (struct rule){ .out = "eth3", .act = A_TARGET, .to = "DSCP" });
	table_on(&net, &spec, NF_HOOK_OP_XTABLES, mangle_hook);
	assert(ask1(&net, family, &eth4, &eth4_7) == 0);
	assert(ask1(&net, family, &eth4, &eth3) == 1);
	end();

	/* A NAT table is on no hook of its own: found through the NAT core's
	 * lookups, among nf_tables chains the walk leaves alone. */
	begin(family);
	pre = nat_core(&net, family, NF_INET_PRE_ROUTING);
	post = nat_core(&net, family, NF_INET_POST_ROUTING);
	entries_append(&pre->entries, NF_HOOK_OP_NF_TABLES, nft_chain_hook, &more);
	add(base_chain(&spec, NF_INET_PRE_ROUTING, A_ACCEPT),
	    (struct rule){ .in = "eth4", .match = { "udp" }, .act = A_TARGET, .to = "DNAT" });
	base_chain(&spec, NF_INET_POST_ROUTING, A_ACCEPT);
	nat_table(pre, post, &spec);
	assert(ask1(&net, family, &eth4, &eth3) == 1);
	assert(ask1(&net, family, &eth3, &eth4) == 0);
	end();
	/* An empty lookup list, and a NAT core with none yet. */
	begin(family);
	nat_core(&net, family, NF_INET_PRE_ROUTING);
	assert(ask1(&net, family, &eth4, &eth3) == 0);
	end();

	/* A hook whose type does not say it is a table is not read as one,
	 * whatever its private data looks like. */
	begin(family);
	add(base_chain(&spec, NF_INET_FORWARD, A_ACCEPT), (struct rule){ .act = A_DROP });
	table_on(&net, &spec, NF_HOOK_OP_UNDEFINED, own);
	assert(ask1(&net, family, &eth4, &eth3) == 0);
	end();

	/* Every table at a hook, in the order the hook runs them: one that
	 * accepts does not excuse the next. */
	begin(family);
	base_chain(&spec, NF_INET_FORWARD, A_ACCEPT);
	filter(&net, &spec);
	add(base_chain(&more, NF_INET_FORWARD, A_ACCEPT), (struct rule){ .act = A_DROP });
	filter(&net, &more);
	assert(ask1(&net, family, &eth4, &eth3) == 1);
	spec_free(&more);
	end();
	/* And the other family's tables are not this family's. */
	begin(family);
	more.family = family == 4 ? 6 : 4;
	add(base_chain(&more, NF_INET_FORWARD, A_ACCEPT), (struct rule){ .act = A_DROP });
	filter(&net, &more);
	assert(ask1(&net, family, &eth4, &eth3) == 0);
	spec_free(&more);
	end();
}

static void bounds(int family)
{
	const char *far = family == 4 ? "10.0.0.1" : "fd00::1";
	const struct net_device *outs[9];
	unsigned int i;
	struct chain *fwd;

	for (i = 0; i < ARRAY_SIZE(outs); i++)
		outs[i] = &eth3;
	/* 4096 rules a walk, the policy among them. */
	for (unsigned int rules = 4095; rules <= 4096; rules++) {
		begin(family);
		fwd = base_chain(&spec, NF_INET_FORWARD, A_ACCEPT);
		for (i = 0; i < rules; i++)
			add(fwd, (struct rule){ .dst = far, .act = A_DROP });
		filter(&net, &spec);
		assert(ask1(&net, family, &eth4, &eth3) == (rules == 4095 ? 0 : -E2BIG));
		end();
	}
	/* 32768 a probe: eight oifs of 4001 rules fit, nine do not. */
	begin(family);
	fwd = base_chain(&spec, NF_INET_FORWARD, A_ACCEPT);
	for (i = 0; i < 4000; i++)
		add(fwd, (struct rule){ .dst = far, .act = A_DROP });
	filter(&net, &spec);
	recseq_sections = 0;
	assert(ask(&net, family, &eth4, outs, 8) == 0 && recseq_sections == 8);
	assert(ask(&net, family, &eth4, outs, 9) == -E2BIG);
	end();
	/* 31 chains nested by jumps, and not 32. */
	for (unsigned int depth = 31; depth <= 32; depth++) {
		static char names[33][8];

		begin(family);
		fwd = base_chain(&spec, NF_INET_FORWARD, A_ACCEPT);
		snprintf(names[1], sizeof(names[1]), "c1");
		add(fwd, (struct rule){ .act = A_JUMP, .to = names[1] });
		for (i = 1; i <= depth; i++) {
			struct chain *c = user_chain(&spec, names[i]);

			if (i < depth) {
				snprintf(names[i + 1], sizeof(names[i + 1]), "c%u", i + 1);
				add(c, (struct rule){ .act = A_JUMP, .to = names[i + 1] });
			}
		}
		filter(&net, &spec);
		assert(ask1(&net, family, &eth4, &eth3) == (depth == 31 ? 0 : -E2BIG));
		end();
	}
}

int main(void)
{
	nf_ipt_probe_hook = &ipt_probe_hook;
	nf_ip6t_probe_hook = &ip6t_probe_hook;
	dispatch();
	for (int family = 4; family <= 6; family += 2) {
		initial_tables(family);
		port_rules(family);
		devices(family);
		chains(family);
		hooks_and_tables(family);
		bounds(family);
	}
	meta_ask_ruleset();
	fragments();
	assert(!rcu_depth && !bh_depth && !recseq_depth);
	puts("x_tables port probe cases passed");
	return 0;
}
