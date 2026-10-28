/* /proc/ask_flowtable status and stats parsing + the drain wait. SPDX-License-Identifier: GPL-2.0+ */
#include "runtime.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>

static long now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

bool ft_cdx_present(void)
{
	return !access(FT_CDX_MODULE, F_OK);
}

struct ft_key {
	const char *name;
	long *value;
};

/* One of the adapter's status or stats files: a "key: value" line each, of
 * which every key named here has to be present. A file that is not there is
 * the adapter not being loaded -- or unloading between two reads -- and
 * clears *present. */
static int ft_keys_read(struct ft_ctx *ctx, const char *path, const struct ft_key *keys,
			size_t n, bool *present)
{
	FILE *f = fopen(path, "r");
	unsigned long found = 0;
	char line[128];
	int error;

	if (!f) {
		if (errno == ENOENT) {
			*present = false;
			return 0;
		}
		snprintf(ctx->err, sizeof(ctx->err), "cannot read backend diagnostics: %s", strerror(errno));
		return -1;
	}
	while (fgets(line, sizeof(line), f)) {
		char key[64];
		long value;

		if (sscanf(line, "%63[^:]: %ld", key, &value) != 2)
			continue;
		for (size_t i = 0; i < n; i++)
			if (!strcmp(key, keys[i].name)) {
				*keys[i].value = value;
				found |= 1UL << i;
			}
	}
	error = ferror(f);
	fclose(f);
	if (error || found != (1UL << n) - 1) {
		snprintf(ctx->err, sizeof(ctx->err), "incomplete backend diagnostics");
		return -1;
	}
	return 0;
}

/* A module parameter: Y or N for a bool, a number otherwise. A parameter that
 * is not there is its module not being loaded, as above. */
static int ft_parameter_read(struct ft_ctx *ctx, const char *path, long *value, bool *present)
{
	FILE *f = fopen(path, "r");
	char text[32], *end;
	bool ok;

	if (!f) {
		if (errno == ENOENT) {
			*present = false;
			return 0;
		}
		snprintf(ctx->err, sizeof(ctx->err), "cannot read %s: %s", path, strerror(errno));
		return -1;
	}
	ok = fgets(text, sizeof(text), f) != NULL;
	fclose(f);
	if (ok && (text[0] == 'Y' || text[0] == 'N') && (text[1] == '\n' || !text[1])) {
		*value = text[0] == 'Y';
	} else if (ok) {
		errno = 0;
		*value = strtol(text, &end, 0);
		ok = end != text && (*end == '\n' || !*end) && !errno;
	}
	if (!ok) {
		snprintf(ctx->err, sizeof(ctx->err), "unreadable module parameter %s", path);
		return -1;
	}
	return 0;
}

int ft_backend_read(struct ft_ctx *ctx, struct ft_backend *b)
{
	const struct ft_key status[] = {
		{ "bindings", &b->bindings }, { "entries", &b->entries },
		{ "handle_refs", &b->handle_refs }, { "neighbour_refs", &b->neighbour_refs },
		{ "quarantine", &b->quarantine }, { "fatal", &b->fatal },
		{ "invalidated", &b->invalidated }, { "bypassed", &b->bypassed },
		{ "restarts", &b->restarts }, { "resume_failures", &b->resume_failures },
		{ "mcast_installed", &b->mcast_installed },
		{ "mroute_installed", &b->mroute_installed },
	};
	const struct ft_key stats[] = {
		{ "installs", &b->installs }, { "deletes", &b->deletes },
		{ "rearms", &b->rearms }, { "errors", &b->errors },
	};
	long qos_mark_mask = 0, route_mark_mask = 0;
	bool present = true;

	memset(b, 0, sizeof(*b));
	/* status first: it is the one read under CDX's transaction, and the
	 * one whose absence says the adapter is not loaded. */
	if (ft_keys_read(ctx, FT_STATUS, status, sizeof(status) / sizeof(status[0]), &present) ||
	    (present && ft_keys_read(ctx, FT_STATS, stats, sizeof(stats) / sizeof(stats[0]), &present)) ||
	    (present && ft_parameter_read(ctx, FT_CDX_MODULE "/parameters/flowtable_observe",
					  &b->observe, &present)) ||
	    (present && ft_parameter_read(ctx, FT_MULTICAST, &b->mcast_enabled, &present)) ||
	    (present && ft_parameter_read(ctx, FT_QOS_MARK_MASK, &qos_mark_mask, &present)) ||
	    (present && ft_parameter_read(ctx, FT_ROUTE_MARK_MASK, &route_mark_mask, &present)))
		return -1;
	if (!present) {
		memset(b, 0, sizeof(*b));
		return 0;   /* adapter not loaded */
	}
	b->present = true;
	b->qos_mark_mask = (uint32_t)qos_mark_mask;
	b->route_mark_mask = (uint32_t)route_mark_mask;
	return 0;
}

int ft_backend_json(const struct ft_backend *b, char *buf, size_t n)
{
	return snprintf(buf, n,
		"{\"present\": %s, \"bindings\": %ld, \"entries\": %ld, "
		"\"handle_refs\": %ld, \"neighbour_refs\": %ld, \"quarantine\": %ld, "
		"\"installs\": %ld, \"deletes\": %ld, \"rearms\": %ld, \"errors\": %ld, "
		"\"fatal\": %ld, \"bypassed\": %ld, \"restarts\": %ld, "
		"\"resume_failures\": %ld, \"invalidated\": %ld, \"observe\": %ld, "
		"\"mcast_enabled\": %ld, \"mcast_installed\": %ld, \"mroute_installed\": %ld}",
		b->present ? "true" : "false", b->bindings, b->entries,
		b->handle_refs, b->neighbour_refs, b->quarantine,
		b->installs, b->deletes, b->rearms, b->errors,
		b->fatal, b->bypassed, b->restarts, b->resume_failures,
		b->invalidated, b->observe,
		b->mcast_enabled, b->mcast_installed, b->mroute_installed);
}

/* ---- the hardware QoS budget, for `status` alone ------------------------
 *
 * The keys at the end of status that describe it, the class mask's parameter
 * (read with the rest by ft_backend_read()), and the qos_ports and
 * qos_classes rows (docs/flowtable/procfs.md). Nothing the health probe or a
 * drain reads depends on any of it. Every field printed is the adapter's: a
 * key or a field missing or garbled fails the read, as ft_backend_read()'s
 * own do, rather than reading as zero or none. */

/* JSON text grown as it is written. A failed allocation is remembered, so the
 * writer need not check each write. */
struct ft_json {
	char *text;
	size_t len, size;
	bool failed;
};

static void ft_json_add(struct ft_json *j, const char *format, ...)
	__attribute__((format(printf, 2, 3)));
static void ft_json_add(struct ft_json *j, const char *format, ...)
{
	va_list ap;
	size_t size;
	char *text;
	int n;

	if (j->failed)
		return;
	va_start(ap, format);
	n = vsnprintf(NULL, 0, format, ap);
	va_end(ap);
	if (n < 0) {
		j->failed = true;
		return;
	}
	if (j->len + (size_t)n >= j->size) {
		size = j->size ? j->size : 4096;
		while (size <= j->len + (size_t)n)
			size *= 2;
		text = realloc(j->text, size);
		if (!text) {
			j->failed = true;
			return;
		}
		j->text = text;
		j->size = size;
	}
	va_start(ap, format);
	vsnprintf(j->text + j->len, j->size - j->len, format, ap);
	va_end(ap);
	j->len += (size_t)n;
}

/* A string, quoted and escaped. A device name may hold any byte but '/', ':'
 * and whitespace, a quote and a backslash among them. */
static void ft_json_string(struct ft_json *j, const char *s)
{
	ft_json_add(j, "\"");
	for (; *s; s++) {
		unsigned char c = (unsigned char)*s;

		if (c == '"' || c == '\\')
			ft_json_add(j, "\\%c", c);
		else if (c < 0x20)
			ft_json_add(j, "\\u%04x", c);
		else
			ft_json_add(j, "%c", c);
	}
	ft_json_add(j, "\"");
}

/* A bitmap of channels as their numbers. */
static void ft_json_channels(struct ft_json *j, uint32_t bits)
{
	bool first = true;

	ft_json_add(j, "[");
	for (unsigned int bit = 0; bit < 32; bit++)
		if (bits & (UINT32_C(1) << bit)) {
			ft_json_add(j, "%s%u", first ? "" : ", ", bit);
			first = false;
		}
	ft_json_add(j, "]");
}

/* One row of qos_ports or qos_classes: its tag, then `key=value` fields one
 * space apart. An empty field, one without its '=' or more of them than any
 * row has is malformed; so is a line too long to be one. The longest a port
 * row can be is under 300 bytes, both its channel lists full. */
#define FT_QOS_FIELDS 16
#define FT_QOS_LINE   512
struct ft_qos_row {
	int n;
	const char *key[FT_QOS_FIELDS], *value[FT_QOS_FIELDS];
};

static bool ft_qos_row_split(char *line, const char *tag, struct ft_qos_row *r)
{
	size_t tag_len = strlen(tag);
	char *end = strchr(line, '\n'), *field, *space, *eq;

	if (!end || strncmp(line, tag, tag_len) || line[tag_len] != ' ')
		return false;
	*end = '\0';
	r->n = 0;
	for (field = line + tag_len + 1;; field = space + 1) {
		space = strchr(field, ' ');
		if (space)
			*space = '\0';
		eq = strchr(field, '=');
		if (!eq || eq == field || r->n == FT_QOS_FIELDS)
			return false;
		*eq = '\0';
		r->key[r->n] = field;
		r->value[r->n++] = eq + 1;
		if (!space)
			return true;
	}
}

static const char *ft_qos_field(const struct ft_qos_row *r, const char *key)
{
	for (int i = 0; i < r->n; i++)
		if (!strcmp(r->key[i], key))
			return r->value[i];
	return NULL;
}

/* An unsigned number in `base', 10 or 16: its digits and nothing else -- no
 * sign, space or prefix -- and at most `max'. */
static bool ft_qos_number(const char *s, int base, unsigned long max, unsigned long *out)
{
	const char *digits = base == 16 ? "0123456789abcdef" : "0123456789";
	char *end;

	if (!s || !*s || s[strspn(s, digits)])
		return false;
	errno = 0;
	*out = strtoul(s, &end, base);
	return !*end && !errno && *out <= max;
}

/* A number, or "-" for none. */
static bool ft_qos_optional(const char *s, int base, unsigned long max, unsigned long *out,
			    bool *none)
{
	*none = s && !strcmp(s, "-");
	return *none || ft_qos_number(s, base, max, out);
}

/* A list of channel numbers, comma-separated, or "-" for none. */
static bool ft_qos_channels(const char *s, uint32_t *bits)
{
	char number[3];
	unsigned long channel;
	size_t len;

	*bits = 0;
	if (!s)
		return false;
	if (!strcmp(s, "-"))
		return true;
	for (;;) {
		len = strcspn(s, ",");
		if (!len || len >= sizeof(number))
			return false;
		memcpy(number, s, len);
		number[len] = '\0';
		if (!ft_qos_number(number, 10, 31, &channel))
			return false;
		*bits |= UINT32_C(1) << channel;
		if (!s[len])
			return true;
		s += len + 1;
	}
}

/* A port's name, as a netdev's can be: one to FT_IFNAME_MAX bytes. */
static bool ft_qos_name(const char *s, char name[FT_IFNAME_MAX + 1])
{
	size_t len = s ? strlen(s) : 0;

	if (!len || len > FT_IFNAME_MAX)
		return false;
	memcpy(name, s, len + 1);
	return true;
}

/* A tc handle as tc prints it, major and minor in hex; a parent may be the
 * qdisc itself, `1:'. */
static bool ft_qos_handle(const char *s, bool qdisc, char handle[sizeof("ffff:ffff")])
{
	size_t major = s ? strspn(s, "0123456789abcdef") : 0, minor;

	if (!major || major > 4 || s[major] != ':')
		return false;
	minor = strspn(s + major + 1, "0123456789abcdef");
	if (minor > 4 || s[major + 1 + minor] || (!minor && !qdisc))
		return false;
	memcpy(handle, s, major + 1 + minor + 1);
	return true;
}

struct ft_qos_port {
	char dev[FT_IFNAME_MAX + 1];
	bool tree;
	uint32_t channels, held;
	unsigned long spare, leaves, leaves_free, policers;
};

static bool ft_qos_port_parse(const struct ft_qos_row *r, struct ft_qos_port *p)
{
	unsigned long tree;

	memset(p, 0, sizeof(*p));
	if (!ft_qos_number(ft_qos_field(r, "tree"), 10, 1, &tree))
		return false;
	p->tree = tree;
	return ft_qos_name(ft_qos_field(r, "dev"), p->dev) &&
	       ft_qos_channels(ft_qos_field(r, "channels"), &p->channels) &&
	       ft_qos_number(ft_qos_field(r, "spare"), 10, 32, &p->spare) &&
	       ft_qos_channels(ft_qos_field(r, "held"), &p->held) &&
	       ft_qos_number(ft_qos_field(r, "leaves"), 10, 0xffff, &p->leaves) &&
	       ft_qos_number(ft_qos_field(r, "leaves_free"), 10, 0xffff, &p->leaves_free) &&
	       ft_qos_number(ft_qos_field(r, "policers"), 10, 0xffff, &p->policers);
}

struct ft_qos_class {
	char dev[FT_IFNAME_MAX + 1], classid[sizeof("ffff:ffff")], parent[sizeof("ffff:ffff")];
	bool inner, unmarked;
	unsigned long channel, queue, slot, depth, qos, mark;
};

/* An inner class has no class queue, slot, depth, value or mark; a leaf has
 * all but perhaps the mark, which the mask may not reach. */
static bool ft_qos_class_parse(const struct ft_qos_row *r, struct ft_qos_class *c)
{
	const char *kind = ft_qos_field(r, "kind"), *mark = ft_qos_field(r, "mark");
	bool queue_none = false, slot_none = false, depth_none = false, qos_none = false;

	memset(c, 0, sizeof(*c));
	if (!kind || (strcmp(kind, "inner") && strcmp(kind, "leaf")))
		return false;
	c->inner = !strcmp(kind, "inner");
	c->unmarked = mark && !strcmp(mark, "-");
	return ft_qos_name(ft_qos_field(r, "dev"), c->dev) &&
	       ft_qos_handle(ft_qos_field(r, "classid"), false, c->classid) &&
	       ft_qos_handle(ft_qos_field(r, "parent"), true, c->parent) &&
	       ft_qos_number(ft_qos_field(r, "channel"), 10, 31, &c->channel) &&
	       ft_qos_optional(ft_qos_field(r, "queue"), 10, 15, &c->queue, &queue_none) &&
	       ft_qos_optional(ft_qos_field(r, "slot"), 10, 0xff, &c->slot, &slot_none) &&
	       ft_qos_optional(ft_qos_field(r, "depth"), 10, 0xffffffffUL, &c->depth,
			       &depth_none) &&
	       ft_qos_optional(ft_qos_field(r, "qos"), 16, 0x7fffff, &c->qos, &qos_none) &&
	       (c->unmarked || (mark && !strncmp(mark, "0x", 2) &&
				ft_qos_number(mark + 2, 16, 0xffffffffUL, &c->mark))) &&
	       queue_none == c->inner && slot_none == c->inner && depth_none == c->inner &&
	       qos_none == c->inner && (!c->inner || c->unmarked);
}

/* Each row of a QoS file into `items', grown as it fills, up to `limit'. A
 * file that is not there is the adapter unloading between two reads, which
 * clears *present as ft_keys_read() does. */
static int ft_qos_rows(struct ft_ctx *ctx, const char *path, const char *tag, size_t item_size,
		       size_t limit, bool (*parse)(const struct ft_qos_row *, void *),
		       void **items, size_t *count, bool *present)
{
	char line[FT_QOS_LINE];
	struct ft_qos_row row;
	size_t size = 0;
	FILE *f = fopen(path, "r");
	void *grown;
	int error;

	*items = NULL;
	*count = 0;
	if (!f) {
		if (errno == ENOENT) {
			*present = false;
			return 0;
		}
		snprintf(ctx->err, sizeof(ctx->err), "cannot read QoS rows: %s", strerror(errno));
		return -1;
	}
	while (fgets(line, sizeof(line), f)) {
		if (*count == limit || !ft_qos_row_split(line, tag, &row)) {
			snprintf(ctx->err, sizeof(ctx->err), "malformed QoS row in %s", path);
			goto fail;
		}
		if (*count == size) {
			size = size ? size * 2 : 16;
			grown = realloc(*items, size * item_size);
			if (!grown) {
				snprintf(ctx->err, sizeof(ctx->err), "cannot read QoS rows: out of memory");
				goto fail;
			}
			*items = grown;
		}
		if (!parse(&row, (char *)*items + *count * item_size)) {
			snprintf(ctx->err, sizeof(ctx->err), "malformed QoS row in %s", path);
			goto fail;
		}
		(*count)++;
	}
	error = ferror(f);
	fclose(f);
	if (!error)
		return 0;
	snprintf(ctx->err, sizeof(ctx->err), "cannot read QoS rows: %s", strerror(errno));
	free(*items);
	*items = NULL;
	return -1;
fail:
	fclose(f);
	free(*items);
	*items = NULL;
	return -1;
}

static bool ft_qos_port_item(const struct ft_qos_row *r, void *item)
{
	return ft_qos_port_parse(r, item);
}

static bool ft_qos_class_item(const struct ft_qos_row *r, void *item)
{
	return ft_qos_class_parse(r, item);
}

/* The most rows either file has: a port per Ethernet port of the SoC, a class
 * per leaf and per channel of every port's tree, with room to spare. */
#define FT_QOS_PORTS_MAX   FT_MAX_DEVICES
#define FT_QOS_CLASSES_MAX 4096

static void ft_qos_json_class(struct ft_json *j, const struct ft_qos_class *c)
{
	ft_json_add(j, "{\"classid\": ");
	ft_json_string(j, c->classid);
	ft_json_add(j, ", \"parent\": ");
	ft_json_string(j, c->parent);
	ft_json_add(j, ", \"kind\": \"%s\", \"channel\": %lu, ", c->inner ? "inner" : "leaf",
		    c->channel);
	if (c->inner)
		ft_json_add(j, "\"queue\": null, \"slot\": null, \"depth\": null, \"qos\": null, ");
	else
		ft_json_add(j, "\"queue\": %lu, \"slot\": %lu, \"depth\": %lu, \"qos\": %lu, ",
			    c->queue, c->slot, c->depth, c->qos);
	if (c->unmarked)
		ft_json_add(j, "\"mark\": null}");
	else
		ft_json_add(j, "\"mark\": %lu}", c->mark);
}

int ft_qos_json(struct ft_ctx *ctx, const struct ft_backend *b, char **json)
{
	static const char *const fields[] = { "queue", "channel", "policer", "remark", "dscp" };
	long channels, channels_used, channels_held, channels_free;
	long policers, policers_used, policers_free, leaves, mark_shift, mark_bits;
	long layout[2 * sizeof(fields) / sizeof(fields[0])];
	char names[2 * sizeof(fields) / sizeof(fields[0])][32];
	struct ft_key keys[10 + sizeof(layout) / sizeof(layout[0])] = {
		{ "qos_channels", &channels }, { "qos_channels_used", &channels_used },
		{ "qos_channels_held", &channels_held }, { "qos_channels_free", &channels_free },
		{ "qos_policers", &policers }, { "qos_policers_used", &policers_used },
		{ "qos_policers_free", &policers_free }, { "qos_leaves_per_port", &leaves },
		{ "qos_mark_shift", &mark_shift }, { "qos_mark_bits", &mark_bits },
	};
	struct ft_qos_port *ports = NULL;
	struct ft_qos_class *classes = NULL;
	size_t nports = 0, nclasses = 0, i, k;
	struct ft_json j = { 0 };
	bool present = b->present, first;
	void *items;

	*json = NULL;
	for (i = 0; i < sizeof(layout) / sizeof(layout[0]); i++) {
		snprintf(names[i], sizeof(names[i]), "qos_class_%s_%s", fields[i / 2],
			 i % 2 ? "bits" : "shift");
		keys[10 + i] = (struct ft_key){ names[i], &layout[i] };
	}
	if (present && ft_keys_read(ctx, FT_STATUS, keys, sizeof(keys) / sizeof(keys[0]), &present))
		return -1;
	if (present) {
		if (ft_qos_rows(ctx, FT_QOS_PORTS, "port", sizeof(*ports), FT_QOS_PORTS_MAX,
				ft_qos_port_item, &items, &nports, &present))
			return -1;
		ports = items;
	}
	if (present) {
		if (ft_qos_rows(ctx, FT_QOS_CLASSES, "class", sizeof(*classes), FT_QOS_CLASSES_MAX,
				ft_qos_class_item, &items, &nclasses, &present)) {
			free(ports);
			return -1;
		}
		classes = items;
	}
	if (!present) {
		/* No adapter, or one unloading between the reads: nothing to say. */
		ft_json_add(&j, "null");
		goto out;
	}
	ft_json_add(&j, "{\"mark_mask\": %lu, \"mark_shift\": %ld, \"mark_bits\": %ld, \"class\": {",
		    (unsigned long)b->qos_mark_mask, mark_shift, mark_bits);
	for (i = 0; i < sizeof(fields) / sizeof(fields[0]); i++)
		ft_json_add(&j, "%s\"%s\": {\"shift\": %ld, \"bits\": %ld}", i ? ", " : "", fields[i],
			    layout[2 * i], layout[2 * i + 1]);
	ft_json_add(&j, "}, \"channels\": {\"total\": %ld, \"used\": %ld, \"held\": %ld, \"free\": %ld}, "
		    "\"policers\": {\"total\": %ld, \"used\": %ld, \"free\": %ld}, \"ports\": {",
		    channels, channels_used, channels_held, channels_free,
		    policers, policers_used, policers_free);
	/* Each port with its tree's classes. A class of a port the ports' read
	 * did not find was made after it, and waits for the next read. */
	for (i = 0; i < nports; i++) {
		const struct ft_qos_port *p = &ports[i];

		ft_json_add(&j, "%s", i ? ", " : "");
		ft_json_string(&j, p->dev);
		ft_json_add(&j, ": {\"tree\": %s, \"channels\": ", p->tree ? "true" : "false");
		ft_json_channels(&j, p->channels);
		ft_json_add(&j, ", \"spare\": %lu, \"held\": ", p->spare);
		ft_json_channels(&j, p->held);
		/* The pool is the FMan's, so what is free of it is free to every
		 * port alike. */
		ft_json_add(&j, ", \"leaves\": {\"total\": %ld, \"used\": %lu, \"free\": %lu}, "
			    "\"policers\": {\"total\": %ld, \"used\": %lu, \"free\": %ld}, \"classes\": [",
			    leaves, p->leaves, p->leaves_free, policers, p->policers, policers_free);
		first = true;
		for (k = 0; k < nclasses; k++)
			if (!strcmp(classes[k].dev, p->dev)) {
				ft_json_add(&j, "%s", first ? "" : ", ");
				ft_qos_json_class(&j, &classes[k]);
				first = false;
			}
		ft_json_add(&j, "]}");
	}
	ft_json_add(&j, "}}");
out:
	free(ports);
	free(classes);
	if (j.failed) {
		free(j.text);
		snprintf(ctx->err, sizeof(ctx->err), "cannot report QoS: out of memory");
		return -1;
	}
	*json = j.text;
	return 0;
}

int ft_backend_multicast(struct ft_ctx *ctx, bool on)
{
	FILE *f = fopen(FT_MULTICAST, "w");
	int error;

	if (!f) {
		if (errno == ENOENT)
			return 0;   /* adapter not loaded: nothing is accelerated */
		snprintf(ctx->err, sizeof(ctx->err), "cannot switch multicast acceleration: %s",
			 strerror(errno));
		return -1;
	}
	error = fputs(on ? "Y\n" : "N\n", f) < 0;
	error |= fclose(f) != 0;
	if (error) {
		snprintf(ctx->err, sizeof(ctx->err), "cannot switch multicast acceleration: %s",
			 strerror(errno));
		return -1;
	}
	return 0;
}

int ft_backend_drain(struct ft_ctx *ctx, int timeout_ms, bool multicast)
{
	long deadline = now_ms() + timeout_ms;
	for (;;) {
		struct ft_backend b;
		if (ft_backend_read(ctx, &b))
			return -1;
		if (!b.present)
			return 0;
		/* A latch CDX is restarting the datapath after is waited out like
		 * any other drain: nothing drained under it is final until the
		 * classifier runs again. */
		if (!b.fatal && !b.bindings && !b.entries && !b.handle_refs &&
		    !b.neighbour_refs && !b.quarantine &&
		    (!multicast || (!b.mcast_installed && !b.mroute_installed)))
			return 0;
		if (now_ms() >= deadline) {
			if (b.fatal) {
				snprintf(ctx->err, sizeof(ctx->err),
					 "datapath restarting after an unproven deletion");
				return FT_RESTARTING;
			}
			snprintf(ctx->err, sizeof(ctx->err),
				 "old hardware or bindings have not drained; no replacement policy installed");
			return -1;
		}
		struct timespec ts = { 0, 50 * 1000000 };
		nanosleep(&ts, NULL);
	}
}
