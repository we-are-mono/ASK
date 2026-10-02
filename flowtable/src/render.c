/* Render an enabled policy to nftables text. Faithful port of the Python
 * render(). SPDX-License-Identifier: GPL-2.0+ */
#include "policy.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

/* buf NULL measures: off still advances by what would have been written. */
struct out {
	char  *buf;
	size_t len;
	size_t off;
	bool   ovf;
};

static void emit(struct out *o, const char *fmt, ...)
{
	va_list ap;
	size_t room = o->buf && o->off < o->len ? o->len - o->off : 0;
	int n;
	va_start(ap, fmt);
	n = vsnprintf(room ? o->buf + o->off : NULL, room, fmt, ap);
	va_end(ap);
	if (n < 0) { o->ovf = true; return; }
	o->off += (size_t)n;
	if (o->buf && o->off >= o->len)
		o->ovf = true;
}

/* Build the selector prefix common to every expansion of a match (proto,
 * addresses, explicit ports, mark) into pfx. Every field is bounded, so the
 * prefix fits; a false return would mean the rule text was cut short. */
static bool match_prefix(const struct ft_match *m, char *pfx, size_t n)
{
	size_t o = 0;
	int i;
	pfx[0] = '\0';
#define ADD(...) do { \
		int _k = snprintf(pfx + o, o < n ? n - o : 0, __VA_ARGS__); \
		if (_k > 0) o += (size_t)_k; \
	} while (0)
	if (m->has_proto)
		ADD("%smeta l4proto %s", o ? " " : "", m->proto);
	for (i = 0; i < 4; i++)
		if (m->has_addr[i])
			ADD("%sct %s %s", o ? " " : "", FT_ADDR_EXPR[i], m->addr[i]);
	for (i = 0; i < 4; i++)
		if (m->has_port[i])
			ADD("%sct %s %s", o ? " " : "", FT_PORT_EXPR[i], m->portspec[i]);
	if (m->has_mark)
		ADD("%sct mark & %#x == %#x", o ? " " : "", m->mark_mask, m->mark_value);
#undef ADD
	return o < n;
}

/* Emit the admission lines for one match. action is "return" (exclude) or
 * "flow add @fast" (scope). A "port" shorthand expands to one line per port
 * field; an empty match yields the bare action (scope "any"). */
static void emit_match(struct out *o, const struct ft_match *m, const char *action)
{
	char pfx[512];
	if (!match_prefix(m, pfx, sizeof(pfx))) {
		o->ovf = true;
		return;
	}

	if (m->has_port_any) {
		int i;
		for (i = 0; i < 4; i++) {
			if (pfx[0])
				emit(o, "  %s ct %s %s %s\n", pfx, FT_PORT_EXPR[i], m->port_any, action);
			else
				emit(o, "  ct %s %s %s\n", FT_PORT_EXPR[i], m->port_any, action);
		}
		return;
	}
	if (pfx[0])
		emit(o, "  %s %s\n", pfx, action);
	else
		emit(o, "  %s\n", action);
}

/* The flowtable's hook and flags, shared by the table and by a membership
 * update of it. Netfilter refuses an update naming another hook or priority,
 * and one whose flags differ in offload from the live flowtable's; nft always
 * sends the update's flags, so they have to be restated. */
#define FT_HOOK  "hook ingress priority 0;"
#define FT_FLAGS "flags offload;"

int ft_render(struct ft_ctx *ctx, const struct ft_policy *p,
	      uint32_t qos_mark_mask, char *buf, size_t buflen)
{
	struct out o = { buf, buflen, 0, false };
	char hash[65];
	uint32_t refused = ~qos_mark_mask & 0xffffffffu;
	int i;

	if (!p->enabled) {
		snprintf(ctx->err, sizeof(ctx->err), "disabled policy has no table to render");
		return -1;
	}
	ft_policy_hash(p, hash);

	emit(&o, "table inet %s {\n", FT_TABLE);
	emit(&o, " comment \"%s%s\"\n", FT_MARKER, hash);
	emit(&o, " flowtable " FT_FLOWTABLE " { " FT_HOOK " devices = { ");
	for (i = 0; i < p->ndevices; i++)
		emit(&o, "%s\"%s\"", i ? ", " : "", p->devices[i]);
	emit(&o, " }; " FT_FLAGS " }\n");
	emit(&o, " chain admit {\n");
	emit(&o, "  type filter hook forward priority 10; policy accept;\n");
	/* Both families. The adapter has carried IPv6 since the increment that
	 * followed this line being written, and the supported scope has said so
	 * ever since -- but this gate was never widened, so a box running the
	 * default-on service offloaded no IPv6 at all, in any topology, and
	 * nothing noticed: every IPv6 test writes an nft table of its own and
	 * never renders this chain. An address-scoped match below stays IPv4 by
	 * construction and simply will not match a v6 flow, which is the right
	 * answer until a match can name its family. */
	emit(&o, "  meta nfproto != { ipv4, ipv6 } return\n");
	emit(&o, "  meta l4proto != { tcp, udp } return\n");
	emit(&o, "  ct direction != original return\n");
	emit(&o, "  ct state != established return\n");
	emit(&o, "  ct mark & %#x != 0x0 return\n", refused);
	for (i = 0; i < p->nexclude; i++)
		emit_match(&o, &p->exclude[i], "return");
	for (i = 0; i < p->nscope; i++)
		emit_match(&o, &p->scope[i], "flow add @fast");
	emit(&o, " }\n}\n");

	if (o.ovf) {
		snprintf(ctx->err, sizeof(ctx->err), "rendered ruleset exceeds buffer");
		return -1;
	}
	return (int)o.off;
}

static bool policy_has(const struct ft_policy *p, const char *name)
{
	int i;

	for (i = 0; i < p->ndevices; i++)
		if (!strcmp(p->devices[i], name))
			return true;
	return false;
}

/* One nft script, so one transaction: an add and a delete commit or abort
 * together. Netfilter binds an added device while preparing the transaction
 * and unbinds a deleted one at commit; the devices in both lists are left
 * alone, and with them every hardware flow that ingresses on them. */
int ft_render_membership(struct ft_ctx *ctx, const struct ft_policy *p,
			 const struct ft_devices *installed, char *buf, size_t buflen)
{
	struct out o = { buf, buflen, 0, false };
	int i, n = 0;

	if (buflen)
		buf[0] = '\0';   /* nothing to change is an empty script */
	for (i = 0; i < p->ndevices; i++)
		if (!ft_devices_has(installed, p->devices[i]))
			emit(&o, n++ ? ", \"%s\"" : "add flowtable inet " FT_TABLE " " FT_FLOWTABLE
			     " { " FT_HOOK " devices = { \"%s\"", p->devices[i]);
	if (n)
		emit(&o, " }; " FT_FLAGS " }\n");
	for (i = n = 0; i < installed->n; i++)
		if (!policy_has(p, installed->name[i]))
			emit(&o, n++ ? ", \"%s\"" : "delete flowtable inet " FT_TABLE " " FT_FLOWTABLE
			     " { " FT_HOOK " devices = { \"%s\"", installed->name[i]);
	if (n)
		emit(&o, " }; }\n");
	if (o.ovf) {
		snprintf(ctx->err, sizeof(ctx->err), "rendered device update exceeds buffer");
		return -1;
	}
	return (int)o.off;
}

long ft_render_bound(struct ft_ctx *ctx, const struct ft_policy *p)
{
	/* No adapter mask refuses every mark bit: the longest guard line. */
	int n = ft_render(ctx, p, 0, NULL, 0);
	long bound;

	if (n < 0)
		return -1;
	bound = n;
	/* Each resolved device renders as `, "name"`. */
	if (p->devices_auto)
		bound += (long)FT_MAX_DEVICES * (FT_IFNAME_MAX + 4);
	return bound;
}
