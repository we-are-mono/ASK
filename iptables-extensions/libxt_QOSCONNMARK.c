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
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_QOSCONNMARK.h>

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

static void qosconnmark_tg_help(void)
{
	printf(
"QOSCONNMARK target options:\n"
"  --set-xmark value[/ctmask]    Zero mask bits and XOR qosconnmark with value\n"
"  --save-mark [--ctmask mask] [--nfmask mask]\n"
"                                Copy qosconnmark to qosmark using masks\n"
"  --restore-mark [--ctmask mask] [--nfmask mask]\n"
"                                Copy qosmark to qosconnmark using masks\n"
"  --set-mark value[/mask]       Set qosconntrack mark value\n"
"  --save-mark [--mask mask]     Save the packet qosmark in the connection\n"
"  --restore-mark [--mask mask]  Restore saved qosmark value\n"
"  --and-mark value              Binary AND the qosconnmark with bits\n"
"  --or-mark value               Binary OR  the qosconnmark with bits\n"
"  --xor-mark value              Binary XOR the qosconnmark with bits\n"
);
}

static const struct option qosconnmark_tg_opts[] = {
	{.name = "set-xmark",     .has_arg = true,  .val = '='},
	{.name = "set-mark",      .has_arg = true,  .val = '-'},
	{.name = "and-mark",      .has_arg = true,  .val = '&'},
	{.name = "or-mark",       .has_arg = true,  .val = '|'},
	{.name = "xor-mark",      .has_arg = true,  .val = '^'},
	{.name = "save-mark",     .has_arg = false, .val = 'S'},
	{.name = "restore-mark",  .has_arg = false, .val = 'R'},
	{.name = "ctmask",        .has_arg = true,  .val = 'c'},
	{.name = "nfmask",        .has_arg = true,  .val = 'n'},
	{.name = "mask",          .has_arg = true,  .val = 'm'},
	XT_GETOPT_TABLEEND,
};

static void qosconnmark_tg_init(struct xt_entry_target *target)
{
	struct xt_qosconnmark_tginfo1 *info = (void *)target->data;

	info->ctmask = UINT64_MAX;
	info->nfmask = UINT64_MAX;
}

static int qosconnmark_tg_parse(int c, char **argv, int invert,
                             unsigned int *flags, const void *entry,
                             struct xt_entry_target **target)
{
	struct xt_qosconnmark_tginfo1 *info = (void *)(*target)->data;
	uint64_t value, mask = UINT64_MAX;
	char *end;

	switch (c) {
	case '=': /* --set-xmark */
	case '-': /* --set-mark */
		xtables_param_act(XTF_ONE_ACTION, "QOSCONNMARK", *flags & F_MARK);
		if (!parse64(optarg, &end, &value))
			xtables_param_act(XTF_BAD_VALUE, "QOSCONNMARK", "--set-xmark/--set-mark", optarg);
		if (*end == '/')
			if (!parse64(end + 1, &end, &mask))
				xtables_param_act(XTF_BAD_VALUE, "QOSCONNMARK", "--set-xmark/--set-mark", optarg);
		if (*end != '\0')
			xtables_param_act(XTF_BAD_VALUE, "QOSCONNMARK", "--set-xmark/--set-mark", optarg);
		info->mode   = XT_QOSCONNMARK_SET;
		info->mark = value;
		info->ctmask = mask;
		if (c == '-')
			info->ctmask |= value;
		*flags |= F_MARK;
		return true;

	case '&': /* --and-mark */
		xtables_param_act(XTF_ONE_ACTION, "QOSCONNMARK", *flags & F_MARK);
		if (!parse64(optarg, NULL, &mask))
			xtables_param_act(XTF_BAD_VALUE, "QOSCONNMARK", "--and-mark", optarg);
		info->mode   = XT_QOSCONNMARK_SET;
		info->mark = 0;
		info->ctmask = ~mask;
		*flags      |= F_MARK;
		return true;

	case '|': /* --or-mark */
		xtables_param_act(XTF_ONE_ACTION, "QOSCONNMARK", *flags & F_MARK);
		if (!parse64(optarg, NULL, &value))
			xtables_param_act(XTF_BAD_VALUE, "QOSCONNMARK", "--or-mark", optarg);
		info->mode   = XT_QOSCONNMARK_SET;
		info->mark = value;
		info->ctmask = value;
		*flags      |= F_MARK;
		return true;

	case '^': /* --xor-mark */
		xtables_param_act(XTF_ONE_ACTION, "QOSCONNMARK", *flags & F_MARK);
		if (!parse64(optarg, NULL, &value))
			xtables_param_act(XTF_BAD_VALUE, "QOSCONNMARK", "--xor-mark", optarg);
		info->mode   = XT_QOSCONNMARK_SET;
		info->mark = value;
		info->ctmask = 0;
		*flags      |= F_MARK;
		return true;

	case 'S': /* --save-mark */
		xtables_param_act(XTF_ONE_ACTION, "QOSCONNMARK", *flags & F_MARK);
		info->mode = XT_QOSCONNMARK_SAVE_QOSMARK;
		*flags |= F_MARK | F_SR_MARK;
		return true;

	case 'R': /* --restore-mark */
		xtables_param_act(XTF_ONE_ACTION, "QOSCONNMARK", *flags & F_MARK);
		info->mode = XT_QOSCONNMARK_RESTORE_QOSMARK;
		*flags |= F_MARK | F_SR_MARK;
		return true;

	case 'n': /* --nfmask */
		if (!(*flags & F_SR_MARK))
			xtables_error(PARAMETER_PROBLEM, "QOSCONNMARK: --save-mark "
			           "or --restore-mark is required for --nfmask");
		if (!parse64(optarg, NULL, &value))
			xtables_param_act(XTF_BAD_VALUE, "QOSCONNMARK", "--nfmask", optarg);
		info->nfmask = value;
		return true;

	case 'c': /* --ctmask */
		if (!(*flags & F_SR_MARK))
			xtables_error(PARAMETER_PROBLEM, "QOSCONNMARK: --save-mark "
			           "or --restore-mark is required for --ctmask");
		if (!parse64(optarg, NULL, &value))
			xtables_param_act(XTF_BAD_VALUE, "QOSCONNMARK", "--ctmask", optarg);
		info->ctmask = value;
		return true;

	case 'm': /* --mask */
		if (!(*flags & F_SR_MARK))
			xtables_error(PARAMETER_PROBLEM, "QOSCONNMARK: --save-mark "
			           "or --restore-mark is required for --mask");
		if (!parse64(optarg, NULL, &value))
			xtables_param_act(XTF_BAD_VALUE, "QOSCONNMARK", "--mask", optarg);
		info->nfmask = info->ctmask = value;
		return true;
	}

	return false;
}

static void qosconnmark_tg_check(unsigned int flags)
{
	if (!flags)
		xtables_error(PARAMETER_PROBLEM,
		           "QOSCONNMARK target: No operation specified");
}

static void
qosconnmark_tg_print(const void *ip, const struct xt_entry_target *target,
                  int numeric)
{
	const struct xt_qosconnmark_tginfo1 *info = (const void *)target->data;

	switch (info->mode) {
	case XT_QOSCONNMARK_SET:
		if (info->mark == 0)
			printf(" QOSCONNMARK and 0x%" PRIx64, (uint64_t)~info->ctmask);
		else if (info->mark == info->ctmask)
			printf(" QOSCONNMARK or 0x%" PRIx64, (uint64_t)info->mark);
		else if (info->ctmask == 0)
			printf(" QOSCONNMARK xor 0x%" PRIx64, (uint64_t)info->mark);
		else if (info->ctmask == UINT64_MAX)
			printf(" QOSCONNMARK set 0x%" PRIx64, (uint64_t)info->mark);
		else
			printf(" QOSCONNMARK xset 0x%" PRIx64 "/0x%" PRIx64,
			       (uint64_t)info->mark, (uint64_t)info->ctmask);
		break;
	case XT_QOSCONNMARK_SAVE_QOSMARK:
		if (info->nfmask == UINT64_MAX && info->ctmask == UINT64_MAX)
			printf(" QOSCONNMARK save");
		else if (info->nfmask == info->ctmask)
			printf(" QOSCONNMARK save mask 0x%" PRIx64, (uint64_t)info->nfmask);
		else
			printf(" QOSCONNMARK save nfmask 0x%" PRIx64 " ctmask ~0x%" PRIx64,
			       (uint64_t)info->nfmask, (uint64_t)info->ctmask);
		break;
	case XT_QOSCONNMARK_RESTORE_QOSMARK:
		if (info->ctmask == UINT64_MAX && info->nfmask == UINT64_MAX)
			printf(" QOSCONNMARK restore");
		else if (info->ctmask == info->nfmask)
			printf(" QOSCONNMARK restore mask 0x%" PRIx64, (uint64_t)info->ctmask);
		else
			printf(" QOSCONNMARK restore ctmask 0x%" PRIx64 " nfmask ~0x%" PRIx64,
			       (uint64_t)info->ctmask, (uint64_t)info->nfmask);
		break;
	default:
		printf(" ERROR: UNKNOWN QOSCONNMARK MODE");
		break;
	}
}

static void
qosconnmark_tg_save(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_qosconnmark_tginfo1 *info = (const void *)target->data;

	switch (info->mode) {
	case XT_QOSCONNMARK_SET:
		printf(" --set-xmark 0x%" PRIx64 "/0x%" PRIx64, (uint64_t)info->mark, (uint64_t)info->ctmask);
		break;
	case XT_QOSCONNMARK_SAVE_QOSMARK:
		printf(" --save-mark --nfmask 0x%" PRIx64 " --ctmask 0x%" PRIx64,
		       (uint64_t)info->nfmask, (uint64_t)info->ctmask);
		break;
	case XT_QOSCONNMARK_RESTORE_QOSMARK:
		printf(" --restore-mark --nfmask 0x%" PRIx64 " --ctmask 0x%" PRIx64,
		       (uint64_t)info->nfmask, (uint64_t)info->ctmask);
		break;
	default:
		printf(" ERROR: UNKNOWN QOSCONNMARK MODE");
		break;
	}
}

static struct xtables_target qosconnmark_target = {
	.version       = XTABLES_VERSION,
	.name          = "QOSCONNMARK",
	.revision      = 1,
	.family        = NFPROTO_UNSPEC,
	.size          = XT_ALIGN(sizeof(struct xt_qosconnmark_tginfo1)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_qosconnmark_tginfo1)),
	.help          = qosconnmark_tg_help,
	.init          = qosconnmark_tg_init,
	.parse         = qosconnmark_tg_parse,
	.final_check   = qosconnmark_tg_check,
	.print         = qosconnmark_tg_print,
	.save          = qosconnmark_tg_save,
	.extra_opts    = qosconnmark_tg_opts,
};

void _init(void)
{
	xtables_register_target(&qosconnmark_target);
}
