/* Shared library add-on to iptables to add connmark matching support.
 *
 * (C) 2002,2004 MARA Systems AB <http://www.marasystems.com>
 * by Henrik Nordstrom <hno@marasystems.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#include <xtables.h>
#include <linux/netfilter/xt_qosconnmark.h>

enum {
	F_MARK    = 1 << 0,
	F_SR_MARK = 1 << 1,
};

static int parse64(const char *s, char **end, uint64_t *value)
{
	uint64_t v;
	char *my_end;

	errno = 0;
	v = (uint64_t)strtoull(s, &my_end, 0);

	if (my_end == s)
		return false;
	if (end != NULL)
		*end = my_end;

	if (errno != ERANGE) {
		if (value != NULL)
			*value = v;
		if (end == NULL)
			return *my_end == '\0';
		return true;
	}

	return false;
}

static void qosconnmark_mt_help(void)
{
	printf(
"qosconnmark match options:\n"
"[!] --mark value[/mask]    Match qosconnmark value with optional mask\n");
}

static const struct option qosconnmark_mt_opts[] = {
	{.name = "mark", .has_arg = true, .val = '1'},
	XT_GETOPT_TABLEEND,
};

static int
qosconnmark_mt_parse(int c, char **argv, int invert, unsigned int *flags,
                  const void *entry, struct xt_entry_match **match)
{
	struct xt_qosconnmark_mtinfo1 *info = (void *)(*match)->data;
	uint64_t mark, mask = UINT64_MAX;
	char *end;

	switch (c) {
	case '1': /* --mark */
		xtables_param_act(XTF_ONLY_ONCE, "qosconnmark", "--mark", *flags & F_MARK);
		if (!parse64(optarg, &end, &mark))
			xtables_param_act(XTF_BAD_VALUE, "qosconnmark", "--mark", optarg);
		if (*end == '/')
			if (!parse64(end + 1, &end, &mask))
				xtables_param_act(XTF_BAD_VALUE, "qosconnmark", "--mark", optarg);
		if (*end != '\0')
			xtables_param_act(XTF_BAD_VALUE, "qosconnmark", "--mark", optarg);

		if (invert)
			info->invert = true;
		info->mark = mark;
		info->mask = mask;
		*flags    |= F_MARK;
		return true;
	}
	return false;
}

static void print_mark(uint64_t mark, uint64_t mask)
{
	if (mask != UINT64_MAX)
		printf("0x%" PRIx64 "/0x%" PRIx64 " ", mark, mask);
	else
		printf("0x%" PRIx64 " ", mark);
}

static void qosconnmark_mt_check(unsigned int flags)
{
	if (flags == 0)
		xtables_error(PARAMETER_PROBLEM,
		           "qosconnmark: The --mark option is required");
}

static void
qosconnmark_mt_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	const struct xt_qosconnmark_mtinfo1 *info = (const void *)match->data;

	printf(" qosconnmark match ");
	if (info->invert)
		printf("!");
	print_mark((uint64_t)info->mark, (uint64_t)info->mask);
}

static void
qosconnmark_mt_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_qosconnmark_mtinfo1 *info = (const void *)match->data;

	if (info->invert)
		printf(" !");

	printf(" --mark ");
	print_mark((uint64_t)info->mark, (uint64_t)info->mask);
}

static struct xtables_match qosconnmark_match = {
	.version       = XTABLES_VERSION,
	.name          = "qosconnmark",
	.revision      = 1,
	.family        = NFPROTO_UNSPEC,
	.size          = XT_ALIGN(sizeof(struct xt_qosconnmark_mtinfo1)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_qosconnmark_mtinfo1)),
	.help          = qosconnmark_mt_help,
	.parse         = qosconnmark_mt_parse,
	.final_check   = qosconnmark_mt_check,
	.print         = qosconnmark_mt_print,
	.save          = qosconnmark_mt_save,
	.extra_opts    = qosconnmark_mt_opts,
};

void _init(void)
{
	xtables_register_match(&qosconnmark_match);
}
