/* Ownership-marker recognition, split out as a pure function so it can be
 * host-tested without a live nft. Given the text of `nft list table inet
 * ask_flowtable`, decide whether the table is ours (carries our marker as its
 * table-level comment) and return its 64-hex hash, and read back the devices
 * its flowtable is bound to. SPDX-License-Identifier: GPL-2.0+ */
#include "policy.h"
#include <ctype.h>
#include <string.h>

int ft_marker_owned(const char *out, char hash[65])
{
	if (hash)
		hash[0] = '\0';
	/* Search only before the first chain: our render puts the table comment
	 * ahead of the chains, and a foreign table of the same name that merely
	 * carries the marker string in a rule comment (inside a chain) must not be
	 * mistaken for ours and deleted. Do not bound on "flowtable " — it also
	 * occurs in the table name "ask_flowtable". */
	const char *body = strchr(out, '{');
	const char *hdr_end = strstr(out, "chain ");
	const char *mark = body ? strstr(body, FT_MARKER) : NULL;
	int i;

	if (!mark || (hdr_end && mark >= hdr_end))
		return 0;
	const char *h = mark + strlen(FT_MARKER);
	for (i = 0; i < 64; i++)
		if (!((h[i] >= '0' && h[i] <= '9') || (h[i] >= 'a' && h[i] <= 'f')))
			return 0;
	if (h[64] != '"')   /* exactly marker + 64 hex, nothing more */
		return 0;
	if (hash) {
		memcpy(hash, h, 64);
		hash[64] = '\0';
	}
	return 1;
}

/* Every name the controller renders passes this, and none of these
 * characters is one nft's list syntax uses around a device, so the listing
 * below reads back exactly the names the controller wrote. A name added to
 * the owned table by hand can contain a separator and be misread; its count
 * then disagrees with the bindings or the update naming it fails, and either
 * way the full transaction replaces the table. */
bool ft_ifname_valid(const char *s)
{
	size_t n = strlen(s), i;

	if (n < 1 || n > FT_IFNAME_MAX)
		return false;
	for (i = 0; i < n; i++)
		if (!isalnum((unsigned char)s[i]) && s[i] != '_' && s[i] != '.' && s[i] != '-')
			return false;
	return true;
}

bool ft_devices_has(const struct ft_devices *d, const char *name)
{
	int i;

	for (i = 0; i < d->n; i++)
		if (!strcmp(d->name[i], name))
			return true;
	return false;
}

/* The flowtable is declared ahead of the chains, as the marker is, in both
 * this controller's render and nft's listing of it. nft 1.1.1 lists the
 * devices bare (`devices = { eth3, eth4 }`), 1.1.6 quotes each one, and a
 * flowtable left with no device lists no devices line at all. */
int ft_marker_devices(const char *out, struct ft_devices *d)
{
	static const char decl[] = "flowtable " FT_FLOWTABLE " {";
	static const char list[] = "devices = {";
	const char *body = strchr(out, '{');
	const char *hdr_end = strstr(out, "chain ");
	const char *ft = body ? strstr(body, decl) : NULL;
	const char *p, *end, *devices;

	d->n = -1;
	if (!ft || (hdr_end && ft >= hdr_end))
		return -1;
	d->n = 0;
	p = ft + sizeof(decl) - 1;
	/* The first closing brace ends either the device list or, when there
	 * is none, the declaration itself. */
	end = strchr(p, '}');
	devices = strstr(p, list);
	if (!end) {
		d->n = -1;
		return -1;
	}
	if (!devices || devices > end)
		return 0;
	for (p = devices + sizeof(list) - 1; ; ) {
		const char *e;
		size_t len;

		while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == ',' || *p == '"'))
			p++;
		if (p == end)
			return 0;
		for (e = p; e < end && !strchr(" \t\n,\"", *e); e++)
			;
		len = (size_t)(e - p);
		if (len > FT_IFNAME_MAX || d->n == FT_MAX_DEVICES)
			break;
		memcpy(d->name[d->n], p, len);
		d->name[d->n][len] = '\0';
		if (!ft_ifname_valid(d->name[d->n]))
			break;
		d->n++;
		p = e;
	}
	d->n = -1;
	return -1;
}
