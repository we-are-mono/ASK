/* Native /etc/ask/offload.conf parser + validation. Mirrors the rejection
 * surface of the Python engine's validate()/match(). SPDX-License-Identifier: GPL-2.0+ */
#include "policy.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>

#define FAIL(...) do { snprintf(ctx->err, sizeof(ctx->err), __VA_ARGS__); return -1; } while (0)

/* ---- scalar validators ------------------------------------------------- */

static int parse_bool(struct ft_ctx *ctx, const char *s, bool *out)
{
	if (!strcmp(s, "yes") || !strcmp(s, "true"))  { *out = true;  return 0; }
	if (!strcmp(s, "no")  || !strcmp(s, "false")) { *out = false; return 0; }
	FAIL("enabled: expected yes or no");
}

static int parse_u32(const char *s, uint32_t *out)
{
	char *end;
	unsigned long v;
	int base = (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) ? 16 : 10;
	if (!*s) return -1;
	errno = 0;
	v = strtoul(s, &end, base);
	if (errno || *end || v > 0xffffffffUL)
		return -1;
	*out = (uint32_t)v;
	return 0;
}

/* Validate an IPv4 address or CIDR, strict (host bits must be zero), and write
 * the canonical "a.b.c.d/nn" into out. A bare address is /32. */
static int parse_cidr(struct ft_ctx *ctx, const char *field, const char *s, char *out, size_t n)
{
	char work[64];
	unsigned o0, o1, o2, o3;
	int pfx = 32, consumed = 0;
	uint32_t addr, mask;

	if (strlen(s) >= sizeof(work))
		FAIL("%s: expected IPv4 address or prefix", field);
	strcpy(work, s);
	char *slash = strchr(work, '/');
	if (slash) {
		char *end;
		long p;
		*slash = '\0';
		errno = 0;
		p = strtol(slash + 1, &end, 10);
		if (end == slash + 1 || errno || *end || p < 0 || p > 32)
			FAIL("%s: invalid prefix length", field);
		pfx = (int)p;
	}
	if (sscanf(work, "%u.%u.%u.%u%n", &o0, &o1, &o2, &o3, &consumed) != 4 ||
	    work[consumed] != '\0' || o0 > 255 || o1 > 255 || o2 > 255 || o3 > 255)
		FAIL("%s: expected IPv4 address or prefix", field);

	addr = (o0 << 24) | (o1 << 16) | (o2 << 8) | o3;
	mask = pfx ? (0xffffffffu << (32 - pfx)) : 0;
	if (addr & ~mask)
		FAIL("%s: host bits set in a network prefix", field);
	snprintf(out, n, "%u.%u.%u.%u/%d", o0, o1, o2, o3, pfx);
	return 0;
}

/* "N" or "lo-hi", each 1..65535, lo<=hi. Canonical form written to out. */
static int parse_portspec(struct ft_ctx *ctx, const char *s, char *out, size_t n)
{
	char *dash = strchr(s, '-');
	long lo, hi;
	char *end;
	if (dash) {
		char lobuf[16];
		size_t l = (size_t)(dash - s);
		if (l == 0 || l >= sizeof(lobuf))
			FAIL("port: expected N or lo-hi in 1..65535");
		memcpy(lobuf, s, l); lobuf[l] = '\0';
		errno = 0; lo = strtol(lobuf, &end, 10);
		if (errno || *end || lo < 1 || lo > 65535) FAIL("port: expected N or lo-hi in 1..65535");
		errno = 0; hi = strtol(dash + 1, &end, 10);
		if (errno || *end || hi < 1 || hi > 65535) FAIL("port: expected N or lo-hi in 1..65535");
		if (lo > hi) FAIL("port: min exceeds max");
		snprintf(out, n, "%ld-%ld", lo, hi);
		return 0;
	}
	errno = 0; lo = strtol(s, &end, 10);
	if (errno || *end || lo < 1 || lo > 65535)
		FAIL("port: expected N or lo-hi in 1..65535");
	snprintf(out, n, "%ld", lo);
	return 0;
}

/* ---- tokenizer --------------------------------------------------------- */

/* Return next whitespace-separated token (double-quotes group), advancing *pp.
 * Returns token length, 0 at end. A '#' outside quotes ends the line. */
static int next_token(const char **pp, const char *end, char *tok, size_t n)
{
	const char *p = *pp;
	size_t o = 0;
	while (p < end && (*p == ' ' || *p == '\t')) p++;
	if (p >= end || *p == '#' || *p == '\n') { *pp = p; return 0; }
	if (*p == '"') {
		p++;
		while (p < end && *p != '"' && *p != '\n') {
			if (o + 1 < n) tok[o++] = *p;
			p++;
		}
		/* An unterminated quote is a truncated or hand-mangled line, not a
		 * bare word: reject it rather than accept the run up to the newline
		 * (which would read `scope "any` as `any`). -1 ends the caller's token
		 * loop and trips its "expected a value"/empty-scope checks. */
		if (p >= end || *p != '"') { *pp = p; return -1; }
		p++;
	} else {
		while (p < end && *p != ' ' && *p != '\t' && *p != '#' && *p != '\n') {
			if (o + 1 < n) tok[o++] = *p;
			p++;
		}
	}
	tok[o] = '\0';
	*pp = p;
	return (int)o;
}

/* ---- match line parsing ------------------------------------------------ */

static int addr_index(const char *k)
{
	int i;
	for (i = 0; i < 4; i++) if (!strcmp(k, FT_ADDR_KEY[i])) return i;
	return -1;
}
static int port_index(const char *k)
{
	int i;
	for (i = 0; i < 4; i++) if (!strcmp(k, FT_PORT_KEY[i])) return i;
	return -1;
}

static int is_portspec_tok(const char *s)
{
	int seen = 0;
	for (; *s; s++) {
		if (isdigit((unsigned char)*s)) seen = 1;
		else if (*s == '-') continue;
		else return 0;
	}
	return seen;
}

static int is_addr_tok(const char *s)
{
	return strchr(s, '.') != NULL;
}

/* Grammar (native, shorthand + keyed both accepted):
 *   any                              scope only, stands alone
 *   tcp | udp                        protocol shorthand
 *   <port|lo-hi>                     port shorthand (matches any port field)
 *   <cidr> [ -> <cidr> ]             source [and destination] address
 *   proto tcp|udp                    protocol
 *   saddr|daddr|reply-saddr|reply-daddr <cidr>
 *   sport|dport|reply-sport|reply-dport <port|lo-hi>
 *   port <port|lo-hi>                any-port shorthand, keyed
 *   mark <value>/<mask>
 *   name <text>
 */
static int parse_match(struct ft_ctx *ctx, const char **pp, const char *end,
		       struct ft_match *m, bool exclusion)
{
	char key[64], val[64];
	int selectors = 0, ai, pi;

	memset(m, 0, sizeof(*m));
	while (next_token(pp, end, key, sizeof(key)) > 0) {
		if (!strcmp(key, "any")) {
			if (exclusion) FAIL("exclusion: at least one selector is required");
			if (next_token(pp, end, val, sizeof(val)) > 0)
				FAIL("scope: 'any' takes no other selectors");
			return 0;
		}
		/* --- shorthands (no explicit key) --- */
		if (!strcmp(key, "tcp") || !strcmp(key, "udp")) {
			if (m->has_proto) FAIL("match: duplicate protocol");
			m->has_proto = true;
			memcpy(m->proto, key, 4);
			selectors++;
			continue;
		}
		if (is_portspec_tok(key)) {
			if (m->has_port_any) FAIL("match: duplicate port");
			if (parse_portspec(ctx, key, m->port_any, sizeof(m->port_any)))
				return -1;
			m->has_port_any = true;
			selectors++;
			continue;
		}
		if (is_addr_tok(key)) {
			if (m->has_addr[0]) FAIL("match: duplicate source address");
			if (parse_cidr(ctx, "saddr", key, m->addr[0], sizeof(m->addr[0])))
				return -1;
			m->has_addr[0] = true;
			selectors++;
			/* optional "-> <cidr>" destination */
			const char *save = *pp;
			if (next_token(pp, end, val, sizeof(val)) > 0 && !strcmp(val, "->")) {
				if (next_token(pp, end, val, sizeof(val)) <= 0 || !is_addr_tok(val))
					FAIL("match: '->' expects a destination address");
				if (parse_cidr(ctx, "daddr", val, m->addr[1], sizeof(m->addr[1])))
					return -1;
				m->has_addr[1] = true;
			} else {
				*pp = save;   /* not an arrow; put the token back */
			}
			continue;
		}
		/* --- keyed forms --- */
		if (!strcmp(key, "name")) {
			if (next_token(pp, end, val, sizeof(val)) <= 0 ||
			    strlen(val) < 1 || strlen(val) > FT_NAME_MAX)
				FAIL("match name: expected 1..64 characters");
			snprintf(m->name, sizeof(m->name), "%s", val);
			continue;
		}
		if (next_token(pp, end, val, sizeof(val)) <= 0)
			FAIL("match: '%s' expects a value", key);

		if (!strcmp(key, "proto")) {
			if (strcmp(val, "tcp") && strcmp(val, "udp"))
				FAIL("protocol: only tcp and udp are supported");
			if (m->has_proto) FAIL("match: duplicate protocol");
			m->has_proto = true;
			memcpy(m->proto, val, 4);
			selectors++;
		} else if ((ai = addr_index(key)) >= 0) {
			if (m->has_addr[ai]) FAIL("match: duplicate %s", key);
			if (parse_cidr(ctx, key, val, m->addr[ai], sizeof(m->addr[ai])))
				return -1;
			m->has_addr[ai] = true;
			selectors++;
		} else if ((pi = port_index(key)) >= 0) {
			if (m->has_port[pi]) FAIL("match: duplicate %s", key);
			if (parse_portspec(ctx, val, m->portspec[pi], sizeof(m->portspec[pi])))
				return -1;
			m->has_port[pi] = true;
			selectors++;
		} else if (!strcmp(key, "port")) {
			if (m->has_port_any) FAIL("match: duplicate port");
			if (parse_portspec(ctx, val, m->port_any, sizeof(m->port_any)))
				return -1;
			m->has_port_any = true;
			selectors++;
		} else if (!strcmp(key, "mark")) {
			char *slash = strchr(val, '/');
			uint32_t value, mask;
			if (m->has_mark) FAIL("match: duplicate mark");
			if (!slash) FAIL("mark: expected value/mask");
			*slash = '\0';
			if (parse_u32(val, &value) || parse_u32(slash + 1, &mask))
				FAIL("mark: value and mask must be 0..0xffffffff");
			if (mask == 0 || (value & ~mask))
				FAIL("mark: nonzero mask must contain every value bit");
			m->has_mark = true;
			m->mark_value = value;
			m->mark_mask = mask;
			selectors++;
		} else {
			FAIL("match: unknown selector '%s'", key);
		}
	}
	/* A scope with no selectors (a bare "scope", or only a "name") would render
	 * the match-all "flow add @fast" and silently offload everything, defeating
	 * the very boundary a scope is for. "any" is the explicit way to say that
	 * and returns above; anything else must carry at least one selector. */
	if (selectors == 0) {
		if (exclusion)
			FAIL("exclusion: at least one selector is required");
		FAIL("scope: at least one selector is required, or 'any'");
	}
	return 0;
}

/* ---- top-level parse --------------------------------------------------- */

int ft_conf_parse(struct ft_ctx *ctx, const char *text, size_t len, struct ft_policy *out)
{
	const char *p = text, *end = text + len;
	bool seen_enabled = false, seen_devices = false, seen_version = false;
	char key[64], val[64];

	if (len > FT_CONF_MAX)
		FAIL("configuration exceeds 64 KiB");

	memset(out, 0, sizeof(*out));
	out->version = 1;
	out->enabled = true;   /* default-on: absent 'enabled' means yes */

	while (p < end) {
		const char *line_end = memchr(p, '\n', (size_t)(end - p));
		const char *lp = p;
		const char *lend = line_end ? line_end : end;
		p = line_end ? line_end + 1 : end;

		if (next_token(&lp, lend, key, sizeof(key)) <= 0)
			continue;  /* blank or comment-only */

		if (!strcmp(key, "version")) {
			if (seen_version) FAIL("duplicate key: version");
			seen_version = true;
			if (next_token(&lp, lend, val, sizeof(val)) <= 0 || strcmp(val, "1"))
				FAIL("unsupported configuration version");
			out->version = 1;
			if (next_token(&lp, lend, val, sizeof(val)) > 0)
				FAIL("version: takes a single value");
		} else if (!strcmp(key, "enabled")) {
			if (seen_enabled) FAIL("duplicate key: enabled");
			seen_enabled = true;
			if (next_token(&lp, lend, val, sizeof(val)) <= 0)
				FAIL("enabled: expected yes or no");
			if (parse_bool(ctx, val, &out->enabled)) return -1;
			if (next_token(&lp, lend, val, sizeof(val)) > 0)
				FAIL("enabled: takes a single value");
		} else if (!strcmp(key, "devices")) {
			if (seen_devices) FAIL("duplicate key: devices");
			seen_devices = true;
			int first = next_token(&lp, lend, val, sizeof(val));
			if (first <= 0) FAIL("devices: expected auto or interface names");
			if (!strcmp(val, "auto")) {
				out->devices_auto = true;
				if (next_token(&lp, lend, val, sizeof(val)) > 0)
					FAIL("devices: 'auto' takes no interface names");
			} else {
				do {
					int i;
					if (out->ndevices >= FT_MAX_DEVICES)
						FAIL("devices: at most %d interfaces", FT_MAX_DEVICES);
					if (!ft_ifname_valid(val))
						FAIL("devices: invalid interface name '%s'", val);
					for (i = 0; i < out->ndevices; i++)
						if (!strcmp(out->devices[i], val))
							FAIL("devices: duplicate '%s'", val);
					/* ft_ifname_valid bounds len to FT_IFNAME_MAX; copy incl. NUL. */
					memcpy(out->devices[out->ndevices], val, strlen(val) + 1);
					out->ndevices++;
				} while (next_token(&lp, lend, val, sizeof(val)) > 0);
			}
		} else if (!strcmp(key, "scope")) {
			if (out->nscope >= FT_MAX_RULES) FAIL("scope: at most %d matches", FT_MAX_RULES);
			if (parse_match(ctx, &lp, lend, &out->scope[out->nscope], false)) return -1;
			out->nscope++;
		} else if (!strcmp(key, "exclude")) {
			if (out->nexclude >= FT_MAX_RULES) FAIL("exclude: at most %d matches", FT_MAX_RULES);
			if (parse_match(ctx, &lp, lend, &out->exclude[out->nexclude], true)) return -1;
			out->nexclude++;
		} else {
			FAIL("unknown configuration key: %s", key);
		}
	}

	/* An enabled policy must name its scope explicitly — the built-in default
	 * conf says "scope any", so silently offloading everything when a hand
	 * edit dropped the line would be a surprise, not a convenience. */
	return ft_validate(ctx, out);
}

int ft_validate(struct ft_ctx *ctx, const struct ft_policy *p)
{
	if (p->version != 1)
		FAIL("unsupported configuration version");
	if (!p->enabled)
		return 0;
	/* "devices auto" is resolved by the daemon against the live interface
	 * set; until then the count is unknown, so defer the 2..N check. A bare
	 * device list is checked now. Two is the minimum forwarding set. */
	if (!p->devices_auto && (p->ndevices < 2 || p->ndevices > FT_MAX_DEVICES))
		FAIL("devices: expected 2 to %d interfaces", FT_MAX_DEVICES);
	if (p->devices_auto && p->ndevices > FT_MAX_DEVICES)
		FAIL("devices: at most %d interfaces", FT_MAX_DEVICES);
	if (p->nscope < 1)
		FAIL("enabled policy requires an explicit admission scope");
	if (p->nscope > FT_MAX_RULES || p->nexclude > FT_MAX_RULES)
		FAIL("scope/exclude: too many matches");
	/* Measure the table apply will render, so check and apply agree. */
	long need = ft_render_bound(ctx, p);
	if (need < 0)
		return -1;
	if (need > FT_RENDER_MAX)
		FAIL("policy renders to %ld bytes, over the %d-byte limit", need, FT_RENDER_MAX);
	return 0;
}
