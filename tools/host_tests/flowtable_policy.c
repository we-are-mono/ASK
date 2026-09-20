/* Host harness for the ask-flowtable policy engine. Compiled by
 * test_flowtable_policy_host.py against the real flowtable/src sources so the
 * validator, renderer, and ownership fingerprint are tested natively without
 * the rig. Reads a conf policy on stdin.
 *
 *   flowtable_policy check                 -> "OK <hash>" or "REJECT: <msg>"
 *   flowtable_policy render [--mask HEX]    -> the nft text, or "REJECT: <msg>"
 *
 * "devices auto" is resolved to a fixed pair for render preview, since the host
 * has no CDX ports; explicit device lists render as written.
 * SPDX-License-Identifier: GPL-2.0+
 */
#include "policy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
	struct ft_ctx ctx;
	struct ft_policy p;
	/* One byte past the limit so the engine's own >64 KiB check can fire. */
	char text[FT_CONF_MAX + 2], buf[FT_CONF_MAX * 2];
	uint32_t mask = 0;
	const char *mode = argc > 1 ? argv[1] : "check";
	int i;

	for (i = 2; i < argc; i++)
		if (!strcmp(argv[i], "--mask") && i + 1 < argc)
			mask = (uint32_t)strtoul(argv[++i], NULL, 0);

	size_t n = fread(text, 1, sizeof(text) - 1, stdin);
	text[n] = '\0';

	/* Ownership-marker recognition over `nft list table` text — fed crafted
	 * output, no conf involved. */
	if (!strcmp(mode, "marker")) {
		char h[65];
		if (ft_marker_owned(text, h)) printf("OWNED %s\n", h);
		else printf("FOREIGN\n");
		return 0;
	}

	if (ft_conf_parse(&ctx, text, n, &p)) {
		printf("REJECT: %s\n", ctx.err);
		return 2;
	}
	if (!strcmp(mode, "check")) {
		char h[65];
		ft_policy_hash(&p, h);
		printf("OK %s\n", h);
		return 0;
	}
	if (!strcmp(mode, "render")) {
		if (p.enabled && p.devices_auto && p.ndevices == 0) {
			strcpy(p.devices[0], "eth3");
			strcpy(p.devices[1], "eth4");
			p.ndevices = 2;
		}
		if (ft_render(&ctx, &p, mask, buf, sizeof(buf)) < 0) {
			printf("REJECT: %s\n", ctx.err);
			return 3;
		}
		fputs(buf, stdout);
		return 0;
	}
	printf("REJECT: unknown mode\n");
	return 4;
}
