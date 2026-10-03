/* Host harness for the ask-flowtable policy engine. Compiled by
 * flowtable_policy_host.py against the real flowtable/src sources so the
 * validator, renderer, and ownership fingerprint are tested natively without
 * the rig. Reads a conf policy on stdin.
 *
 *   flowtable_policy check                 -> "OK <hash>" or "REJECT: <msg>"
 *   flowtable_policy render [--mask HEX] [--resolve A,B,...]
 *                                          -> the nft text, or "REJECT: <msg>"
 *   flowtable_policy membership --installed A,B,... [--resolve A,B,...]
 *                                          -> the device update script
 *   flowtable_policy marker | devices      -> reads `nft list table` text
 *
 * "devices auto" is resolved to --resolve, or to a fixed pair, since the host
 * has no CDX ports; explicit device lists render as written.
 * SPDX-License-Identifier: GPL-2.0+
 */
#include "policy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A comma-separated list into an array of names; returns the count. */
static int names(const char *list, char out[][FT_IFNAME_MAX + 1])
{
	char copy[FT_MAX_DEVICES * (FT_IFNAME_MAX + 1) + 1], *save, *name;
	int n = 0;

	snprintf(copy, sizeof(copy), "%s", list);
	for (name = strtok_r(copy, ",", &save); name && n < FT_MAX_DEVICES;
	     name = strtok_r(NULL, ",", &save))
		snprintf(out[n++], FT_IFNAME_MAX + 1, "%s", name);
	return n;
}

int main(int argc, char **argv)
{
	struct ft_ctx ctx;
	struct ft_policy p;
	struct ft_devices installed = { .n = 0 };
	/* One byte past the limit so the engine's own >64 KiB check can fire. */
	char text[FT_CONF_MAX + 2], buf[FT_RENDER_MAX + 1];
	const char *resolve = NULL;
	uint32_t mask = 0;
	const char *mode = argc > 1 ? argv[1] : "check";
	int i;

	for (i = 2; i < argc; i++)
		if (!strcmp(argv[i], "--mask") && i + 1 < argc)
			mask = (uint32_t)strtoul(argv[++i], NULL, 0);
		else if (!strcmp(argv[i], "--resolve") && i + 1 < argc)
			resolve = argv[++i];
		else if (!strcmp(argv[i], "--installed") && i + 1 < argc)
			installed.n = names(argv[++i], installed.name);

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
	if (!strcmp(mode, "devices")) {
		struct ft_devices d;
		if (ft_marker_devices(text, &d)) {
			printf("UNREADABLE %d\n", d.n);
			return 0;
		}
		printf("DEVICES");
		for (i = 0; i < d.n; i++)
			printf(" %s", d.name[i]);
		printf("\n");
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
	if (p.enabled && p.devices_auto && p.ndevices == 0) {
		if (resolve) {
			p.ndevices = names(resolve, p.devices);
		} else {
			strcpy(p.devices[0], "eth3");
			strcpy(p.devices[1], "eth4");
			p.ndevices = 2;
		}
	}
	if (!strcmp(mode, "render")) {
		if (ft_render(&ctx, &p, mask, buf, sizeof(buf)) < 0) {
			printf("REJECT: %s\n", ctx.err);
			return 3;
		}
		fputs(buf, stdout);
		return 0;
	}
	if (!strcmp(mode, "membership")) {
		if (ft_render_membership(&ctx, &p, &installed, buf, sizeof(buf)) < 0) {
			printf("REJECT: %s\n", ctx.err);
			return 3;
		}
		fputs(buf, stdout);
		return 0;
	}
	printf("REJECT: unknown mode\n");
	return 4;
}
