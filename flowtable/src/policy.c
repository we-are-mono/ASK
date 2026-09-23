/* Shared field order + policy fingerprint. SPDX-License-Identifier: GPL-2.0+ */
#include "policy.h"
#include "sha256.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

/* Index 0..3 = source, destination, reply_source, reply_destination. The nft
 * expression and the conf token for each must stay aligned by index. */
const char *const FT_ADDR_EXPR[4] = {
	"original ip saddr", "original ip daddr",
	"reply ip saddr",    "reply ip daddr",
};
const char *const FT_ADDR_KEY[4] = {
	"saddr", "daddr", "reply-saddr", "reply-daddr",
};
const char *const FT_PORT_EXPR[4] = {
	"original proto-src", "original proto-dst",
	"reply proto-src",    "reply proto-dst",
};
const char *const FT_PORT_KEY[4] = {
	"sport", "dport", "reply-sport", "reply-dport",
};

/* Bounded append: never forms a pointer past the buffer end, and *o saturates
 * at n so a truncated canonical form still hashes deterministically. */
static void app(char *b, size_t n, size_t *o, const char *fmt, ...)
{
	va_list ap;
	int k;
	if (*o >= n) { *o = n; return; }
	va_start(ap, fmt);
	k = vsnprintf(b + *o, n - *o, fmt, ap);
	va_end(ap);
	if (k < 0) return;
	*o += (size_t)k;
	if (*o > n) *o = n;
}

static void append_match(char *b, size_t n, size_t *o, const struct ft_match *m)
{
	int i;
	if (m->has_proto)
		app(b, n, o, "|p=%s", m->proto);
	for (i = 0; i < 4; i++)
		if (m->has_addr[i])
			app(b, n, o, "|a%d=%s", i, m->addr[i]);
	for (i = 0; i < 4; i++)
		if (m->has_port[i])
			app(b, n, o, "|q%d=%s", i, m->portspec[i]);
	if (m->has_port_any)
		app(b, n, o, "|pa=%s", m->port_any);
	if (m->has_mark)
		app(b, n, o, "|m=%x/%x", m->mark_value, m->mark_mask);
	app(b, n, o, "|n=%s;", m->name);
}

void ft_policy_hash(const struct ft_policy *p, char out[65])
{
	/* Deterministic canonical serialization; list order is significant and
	 * preserved, field order within a match is fixed by index. Independent
	 * of qos_mark_mask so the marker is stable across adapter reloads.
	 *
	 * An explicit device list is configuration and is covered. The ports
	 * "devices auto" resolved to are not: they are whichever ports are up
	 * at this moment, so covering them made every link change a different
	 * policy, and reconciling a different policy replaces the table --
	 * retiring every offloaded flow, on every port, because a spare port's
	 * link flapped. The daemon follows membership on the live flowtable
	 * instead, and `check` (which resolves nothing) agrees with the table. */
	char buf[FT_CONF_MAX * 2];
	size_t n = sizeof(buf), o = 0;
	int i;

	app(buf, n, &o, "v%d|en=%d|auto=%d",
	    p->version, p->enabled ? 1 : 0, p->devices_auto ? 1 : 0);
	for (i = 0; !p->devices_auto && i < p->ndevices; i++)
		app(buf, n, &o, "|d=%s", p->devices[i]);
	app(buf, n, &o, "#scope");
	for (i = 0; i < p->nscope; i++)
		append_match(buf, n, &o, &p->scope[i]);
	app(buf, n, &o, "#exclude");
	for (i = 0; i < p->nexclude; i++)
		append_match(buf, n, &o, &p->exclude[i]);

	ft_sha256(buf, o, out);
}
