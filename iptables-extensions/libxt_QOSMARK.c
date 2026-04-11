/* Shared library add-on to iptables to add NFMARK matching support. */
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
#include <linux/netfilter/xt_QOSMARK.h>

enum {
	F_MARK = 1 << 0,
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

static void qosmark_tg_help(void)
{
	printf(
"QOSMARK target options:\n"
"  --set-xmark value[/mask]  Clear bits in mask and XOR value into qosmark\n"
"  --set-mark value[/mask]   Clear bits in mask and OR value into qosmark\n"
"  --and-mark bits           Binary AND the qosmark with bits\n"
"  --or-mark bits            Binary OR the qosmark with bits\n"
"  --xor-mask bits           Binary XOR the qosmark with bits\n"
"\n");
}

static const struct option qosmark_tg_opts[] = {
	{.name = "set-xmark", .has_arg = true, .val = 'X'},
	{.name = "set-mark",  .has_arg = true, .val = '='},
	{.name = "and-mark",  .has_arg = true, .val = '&'},
	{.name = "or-mark",   .has_arg = true, .val = '|'},
	{.name = "xor-mark",  .has_arg = true, .val = '^'},
	XT_GETOPT_TABLEEND,
};

static int qosmark_tg_parse(int c, char **argv, int invert, unsigned int *flags,
                         const void *entry, struct xt_entry_target **target)
{
	struct xt_qosmark_tginfo2 *info = (void *)(*target)->data;
	uint64_t value, mask = UINT64_MAX;
	char *end;

	switch (c) {
	case 'X': /* --set-xmark */
	case '=': /* --set-mark */
		xtables_param_act(XTF_ONE_ACTION, "QOSMARK", *flags & F_MARK);
		xtables_param_act(XTF_NO_INVERT, "QOSMARK", "--set-xmark/--set-mark", invert);
		if (!parse64(optarg, &end, &value))
			xtables_param_act(XTF_BAD_VALUE, "QOSMARK", "--set-xmark/--set-mark", optarg);
		if (*end == '/')
			if (!parse64(end + 1, &end, &mask))
				xtables_param_act(XTF_BAD_VALUE, "QOSMARK", "--set-xmark/--set-mark", optarg);
		if (*end != '\0')
			xtables_param_act(XTF_BAD_VALUE, "QOSMARK", "--set-xmark/--set-mark", optarg);
		info->mark = value;
		info->mask = mask;

		if (c == '=')
			info->mask = value | mask;
		break;

	case '&': /* --and-mark */
		xtables_param_act(XTF_ONE_ACTION, "QOSMARK", *flags & F_MARK);
		xtables_param_act(XTF_NO_INVERT, "QOSMARK", "--and-mark", invert);
		if (!parse64(optarg, NULL, &mask))
			xtables_param_act(XTF_BAD_VALUE, "QOSMARK", "--and-mark", optarg);
		info->mark = 0;
		info->mask = ~mask;
		break;

	case '|': /* --or-mark */
		xtables_param_act(XTF_ONE_ACTION, "QOSMARK", *flags & F_MARK);
		xtables_param_act(XTF_NO_INVERT, "QOSMARK", "--or-mark", invert);
		if (!parse64(optarg, NULL, &value))
			xtables_param_act(XTF_BAD_VALUE, "QOSMARK", "--or-mark", optarg);
		info->mark = value;
		info->mask = value;
		break;

	case '^': /* --xor-mark */
		xtables_param_act(XTF_ONE_ACTION, "QOSMARK", *flags & F_MARK);
		xtables_param_act(XTF_NO_INVERT, "QOSMARK", "--xor-mark", invert);
		if (!parse64(optarg, NULL, &value))
			xtables_param_act(XTF_BAD_VALUE, "QOSMARK", "--xor-mark", optarg);
		info->mark = value;
		info->mask = 0;
		break;

	default:
		return false;
	}

	*flags |= F_MARK;
	return true;
}

static void qosmark_tg_check(unsigned int flags)
{
	if (flags == 0)
		xtables_error(PARAMETER_PROBLEM, "QOSMARK: One of the --set-xmark, "
		           "--{and,or,xor,set}-mark options is required");
}

static void qosmark_tg_print(const void *ip, const struct xt_entry_target *target,
                          int numeric)
{
	const struct xt_qosmark_tginfo2 *info = (const void *)target->data;

	if (info->mark == 0)
		printf(" QOSMARK and 0x%" PRIx64, (uint64_t)~info->mask);
	else if (info->mark == info->mask)
		printf(" QOSMARK or 0x%" PRIx64, (uint64_t)info->mark);
	else if (info->mask == 0)
		printf(" QOSMARK xor 0x%" PRIx64, (uint64_t)info->mark);
	else if (info->mask == UINT64_MAX)
		printf(" QOSMARK set 0x%" PRIx64, (uint64_t)info->mark);
	else
		printf(" QOSMARK xset 0x%" PRIx64 "/0x%" PRIx64, (uint64_t)info->mark, (uint64_t)info->mask);
}

static void qosmark_tg_save(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_qosmark_tginfo2 *info = (const void *)target->data;

	printf(" --set-xmark 0x%" PRIx64 "/0x%" PRIx64, (uint64_t)info->mark, (uint64_t)info->mask);
}

static struct xtables_target qosmark_target = {
	.version       = XTABLES_VERSION,
	.name          = "QOSMARK",
	.revision      = 2,
	.family        = NFPROTO_UNSPEC,
	.size          = XT_ALIGN(sizeof(struct xt_qosmark_tginfo2)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_qosmark_tginfo2)),
	.help          = qosmark_tg_help,
	.parse         = qosmark_tg_parse,
	.final_check   = qosmark_tg_check,
	.print         = qosmark_tg_print,
	.save          = qosmark_tg_save,
	.extra_opts    = qosmark_tg_opts,
};

void _init(void)
{
	xtables_register_target(&qosmark_target);
}
