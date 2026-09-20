/* Ownership-marker recognition, split out as a pure function so it can be
 * host-tested without a live nft. Given the text of `nft list table inet
 * ask_flowtable`, decide whether the table is ours (carries our marker as its
 * table-level comment) and return its 64-hex hash. SPDX-License-Identifier: GPL-2.0+ */
#include "policy.h"
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
