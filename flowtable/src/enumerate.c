/* Resolve "devices auto" to the up CDX physical ports (driver fsl_dpa).
 * Wi-Fi VAPs (driver wlan_pcie) are naturally excluded, which is correct: a
 * Wi-Fi download ingresses on the physical WAN port and offload keys on the
 * physical ingress port. SPDX-License-Identifier: GPL-2.0+ */
#include "runtime.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>

#define FT_DRIVER "fsl_dpa"

static int is_phys_up(const char *ifn)
{
	char path[256], link[256], state[32];
	ssize_t n;
	FILE *f;

	/* driver name via /sys/class/net/<if>/device/driver symlink basename */
	snprintf(path, sizeof(path), "/sys/class/net/%s/device/driver", ifn);
	n = readlink(path, link, sizeof(link) - 1);
	if (n <= 0)
		return 0;
	link[n] = '\0';
	const char *base = strrchr(link, '/');
	base = base ? base + 1 : link;
	if (strcmp(base, FT_DRIVER))
		return 0;

	/* carrier-up: operstate == "up" */
	snprintf(path, sizeof(path), "/sys/class/net/%s/operstate", ifn);
	f = fopen(path, "r");
	if (!f)
		return 0;
	state[0] = '\0';
	if (fgets(state, sizeof(state), f)) {
		char *nl = strpbrk(state, "\r\n");
		if (nl) *nl = '\0';
	}
	fclose(f);
	return !strcmp(state, "up");
}

static int cmpstr(const void *a, const void *b)
{
	return strcmp((const char *)a, (const char *)b);
}

int ft_enumerate(struct ft_policy *p)
{
	DIR *d = opendir("/sys/class/net");
	struct dirent *e;
	char names[FT_MAX_DEVICES][FT_IFNAME_MAX + 1];
	int n = 0;

	if (!d)
		return 0;
	while ((e = readdir(d)) && n < FT_MAX_DEVICES) {
		if (e->d_name[0] == '.')
			continue;
		if (strlen(e->d_name) > FT_IFNAME_MAX)
			continue;
		/* A port renamed to something the controller cannot render and
		 * read back is left out rather than written into nft. */
		if (!ft_ifname_valid(e->d_name))
			continue;
		if (is_phys_up(e->d_name)) {
			snprintf(names[n], sizeof(names[n]), "%s", e->d_name);
			n++;
		}
	}
	closedir(d);

	qsort(names, n, sizeof(names[0]), cmpstr);
	for (int i = 0; i < n; i++)
		memcpy(p->devices[i], names[i], sizeof(names[i]));
	p->ndevices = n;
	return n;
}
