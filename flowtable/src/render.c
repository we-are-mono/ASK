/* Render an enabled policy to nftables text. Faithful port of the Python
 * render(). SPDX-License-Identifier: GPL-2.0+ */
#include "policy.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

struct out {
	char  *buf;
	size_t len;
	size_t off;
	bool   ovf;
};

static void emit(struct out *o, const char *fmt, ...)
{
	va_list ap;
	int n;
	va_start(ap, fmt);
	n = vsnprintf(o->buf + o->off, o->off < o->len ? o->len - o->off : 0, fmt, ap);
	va_end(ap);
	if (n < 0) { o->ovf = true; return; }
	o->off += (size_t)n;
	if (o->off >= o->len)
		o->ovf = true;
}

/* Build the selector prefix common to every expansion of a match (proto,
 * addresses, explicit ports, mark) into pfx. */
static void match_prefix(const struct ft_match *m, char *pfx, size_t n)
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
}

/* Emit the admission lines for one match. action is "return" (exclude) or
 * "flow add @fast" (scope). A "port" shorthand expands to one line per port
 * field; an empty match yields the bare action (scope "any"). */
static void emit_match(struct out *o, const struct ft_match *m, const char *action)
{
	char pfx[512];
	match_prefix(m, pfx, sizeof(pfx));

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
	emit(&o, " flowtable fast { hook ingress priority 0; devices = { ");
	for (i = 0; i < p->ndevices; i++)
		emit(&o, "%s\"%s\"", i ? ", " : "", p->devices[i]);
	emit(&o, " }; flags offload; }\n");
	emit(&o, " chain admit {\n");
	emit(&o, "  type filter hook forward priority 10; policy accept;\n");
	emit(&o, "  meta nfproto != ipv4 return\n");
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
