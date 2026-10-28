/* The adapter's QoS report over a cdx that answers what each case sets: the
 * status keys, in the layout ft_kv() writes, and the rows of qos_ports and
 * qos_classes, word for word. */
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#define IFNAMSIZ	16
#define GFP_KERNEL	0
#define __ffs(x) ((unsigned long)__builtin_ctzl(x))
#define hweight32(w) __builtin_popcount((u32)(w))
#define TC_H_MAJ_MASK	0xFFFF0000U
#define TC_H_MIN_MASK	0x0000FFFFU
#define TC_H_MAJ(h)	((h) & TC_H_MAJ_MASK)
#define TC_H_MIN(h)	((h) & TC_H_MIN_MASK)
#define TC_H_MAKE(maj, min) (((maj) & TC_H_MAJ_MASK) | ((min) & TC_H_MIN_MASK))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(*(a)))
struct net_device;

/* What one read renders, whole. */
struct seq_file { char buf[1 << 16]; size_t len; };
static void seq_printf(struct seq_file *seq, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	seq->len += vsnprintf(seq->buf + seq->len, sizeof(seq->buf) - seq->len, fmt, ap);
	va_end(ap);
	assert(seq->len < sizeof(seq->buf));
}
/* The kernel's: what was written, never what would have been, and always
 * terminated; here a truncation is a bug in the caller's sizing. */
static int scnprintf(char *buf, size_t size, const char *fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(buf, size, fmt, ap);
	va_end(ap);
	assert(n >= 0 && (size_t)n < size);
	return n;
}
static long strscpy(char *dst, const char *src, size_t size)
{
	size_t n = strlen(src);

	assert(n < size);
	memcpy(dst, src, n + 1);
	return (long)n;
}
static unsigned allocations;
static bool allocation_fails;
static void *kmalloc_array(size_t n, size_t size, int gfp)
{
	if (allocation_fails)
		return NULL;
	allocations++;
	return calloc(n, size);
}
static void kfree(void *p)
{
	if (p)
		allocations--;
	free(p);
}

#include "qos_report_types.inc"

static unsigned int ft_qos_mark_mask;

/* ---- cdx, as a case sets it ------------------------------------------- */

#define PORTS	4
#define CLASSES	(64 + 32)
static struct cdx_qos_budget budget;
static struct {
	unsigned index;
	struct cdx_qos_port port;
	struct cdx_qos_class classes[CLASSES + 1];
	int count;
} ports[PORTS];
static unsigned nports;

void cdx_qos_budget(struct cdx_qos_budget *b)
{
	*b = budget;
}

/* The next port at or past *index, in index order, as cdx walks them. */
int cdx_qos_port_next(unsigned int *index, struct cdx_qos_port *p,
		      struct cdx_qos_class *classes, unsigned int max)
{
	for (unsigned ii = 0; ii < nports; ii++) {
		if (ports[ii].index < *index)
			continue;
		*index = ports[ii].index;
		*p = ports[ii].port;
		if (!classes)
			return 0;
		if ((unsigned)ports[ii].count > max)
			return -ENOSPC;
		memcpy(classes, ports[ii].classes, ports[ii].count * sizeof(*classes));
		return ports[ii].count;
	}
	return -ENOENT;
}

#include "qos_report_production.inc"

/* ---- reading it back ---------------------------------------------------- */

/* The keys in the order the file gives them, each line in ft_kv()'s layout:
 * the key and its colon in 36 columns, the value right-aligned in 12. */
static unsigned keys(const struct seq_file *seq, char names[][40], unsigned long long *values,
		     unsigned max)
{
	const char *line = seq->buf;
	unsigned n = 0;

	while (*line) {
		const char *end = strchr(line, '\n'), *colon = strchr(line, ':');

		assert(end && colon && colon < end && n < max);
		assert(end - line == 48 && line[47] != ' ');
		memcpy(names[n], line, colon - line);
		names[n][colon - line] = '\0';
		values[n] = strtoull(colon + 1, NULL, 10);
		n++;
		line = end + 1;
	}
	return n;
}

static void status_is(u32 mask, const char *const *want_keys, const unsigned long long *want,
		      unsigned count)
{
	static struct seq_file seq;
	char names[32][40];
	unsigned long long values[32];

	ft_qos_mark_mask = mask;
	seq.len = 0;
	seq.buf[0] = '\0';
	ft_qos_status(&seq);
	assert(keys(&seq, names, values, ARRAY_SIZE(names)) == count);
	for (unsigned ii = 0; ii < count; ii++) {
		if (strcmp(names[ii], want_keys[ii]) || values[ii] != want[ii])
			fprintf(stderr, "status line %u: %s = %llu, want %s = %llu\n", ii, names[ii],
				values[ii], want_keys[ii], want[ii]);
		assert(!strcmp(names[ii], want_keys[ii]) && values[ii] == want[ii]);
	}
}

/* What the status adds, in its order. */
static void test_status(void)
{
	static const char *const names[] = {
		"qos_channels", "qos_channels_used", "qos_channels_held", "qos_channels_free",
		"qos_policers", "qos_policers_used", "qos_policers_free", "qos_leaves_per_port",
		"qos_mark_shift", "qos_mark_bits",
		"qos_class_queue_shift", "qos_class_queue_bits",
		"qos_class_channel_shift", "qos_class_channel_bits",
		"qos_class_policer_shift", "qos_class_policer_bits",
		"qos_class_remark_shift", "qos_class_remark_bits",
		"qos_class_dscp_shift", "qos_class_dscp_bits",
	};
	unsigned long long want[ARRAY_SIZE(names)] = {
		32, 3, 2, 27,
		63, 5, 58, 64,
		0, 0,
		0, 4, 4, 6, 10, 6, 16, 1, 17, 6,
	};

	/* Three channels mapped, two held -- one quarantined, one whose drain
	 * failed -- and five profiles spoken for, one of them pending: still
	 * held for the flows of a filter that went. Classification off. */
	budget = (struct cdx_qos_budget){
		.channels = 32, .channels_used = 3, .channels_held = 2,
		.policers = 63, .policers_used = 5, .leaves = 64,
	};
	status_is(0, names, want, ARRAY_SIZE(names));
	/* The test image's mask: the queue field alone. */
	want[8] = 4, want[9] = 4;
	status_is(0xf0, names, want, ARRAY_SIZE(names));
	/* Beside mwan3, in the word's upper half: queue, channel and policer. */
	want[8] = 16, want[9] = 16;
	status_is(0xffff0000, names, want, ARRAY_SIZE(names));
	/* A board whose device tree gives eight channels, all of them held or
	 * mapped, and a pool with nothing left. */
	budget = (struct cdx_qos_budget){
		.channels = 8, .channels_used = 6, .channels_held = 2,
		.policers = 63, .policers_used = 63, .leaves = 64,
	};
	want[0] = 8, want[1] = 6, want[2] = 2, want[3] = 0;
	want[5] = 63, want[6] = 0;
	want[8] = 0, want[9] = 23;
	status_is(0x7fffff, names, want, ARRAY_SIZE(names));
}

static struct cdx_qos_class leaf(u16 major, u16 minor, u16 parent, u8 channel, u8 queue, u8 slot,
				 u32 depth)
{
	return (struct cdx_qos_class){
		.classid = TC_H_MAKE((u32)major << 16, minor), .parent = parent,
		.channel = channel, .queue = queue, .slot = slot, .inner = false,
		.depth = depth,
	};
}

static struct cdx_qos_class inner(u16 major, u16 minor, u8 channel)
{
	return (struct cdx_qos_class){
		.classid = TC_H_MAKE((u32)major << 16, minor), .parent = 0,
		.channel = channel, .queue = CDX_QOS_NONE, .slot = CDX_QOS_NONE, .inner = true,
	};
}

/* eth3's tree: an inner class holding channel 0 with a leaf under it, and
 * leaves of their own at the root, one of them the example procfs.md gives,
 * each at the depth the cap gave its queue. eth4 has no tree, and two
 * channels its last one left quarantined. lan1's tree has a major past nine
 * and a minor at the top of its range, and a depth at the top of its. */
static void world(void)
{
	budget = (struct cdx_qos_budget){
		.channels = 32, .channels_used = 4, .channels_held = 2,
		.policers = 63, .policers_used = 3, .leaves = 64,
	};
	memset(ports, 0, sizeof(ports));
	nports = 3;
	ports[0].index = 3;
	ports[0].port = (struct cdx_qos_port){
		.name = "eth3", .ifindex = 5, .channels = 0x100013, .spare = 1, .held = 0,
		.leaves = 3, .policers = 2, .tree = true,
	};
	ports[0].classes[0] = inner(1, 1, 0);
	ports[0].classes[1] = leaf(1, 0xa, 1, 0, 5, 0, 128);
	ports[0].classes[2] = leaf(1, 0x23, 0, 4, 7, 3, 41);
	ports[0].classes[3] = leaf(1, 0x24, 0, 20, 2, 1, 1);
	ports[0].count = 4;
	ports[1].index = 4;
	ports[1].port = (struct cdx_qos_port){
		.name = "eth4", .ifindex = 6, .held = 0x60,
	};
	ports[2].index = 9;
	ports[2].port = (struct cdx_qos_port){
		.name = "lan1", .ifindex = 9, .channels = 0x80000000, .leaves = 1, .policers = 1,
		.tree = true,
	};
	ports[2].classes[0] = leaf(0x10, 0xffff, 0, 31, 15, 0, 0xffffffff);
	ports[2].count = 1;
}

static void rows_are(int (*show)(struct seq_file *, void *), const char *want)
{
	static struct seq_file seq;

	seq.len = 0;
	seq.buf[0] = '\0';
	assert(show(&seq, NULL) == 0);
	if (strcmp(seq.buf, want))
		fprintf(stderr, "rendered:\n%swanted:\n%s", seq.buf, want);
	assert(!strcmp(seq.buf, want));
	assert(!allocations);
}

static void test_ports(void)
{
	world();
	ft_qos_mark_mask = 0xffff0000;
	rows_are(ft_qos_ports_show,
		 "port dev=eth3 tree=1 channels=0,1,4,20 spare=1 held=- leaves=3 leaves_free=61 policers=2\n"
		 "port dev=eth4 tree=0 channels=- spare=0 held=5,6 leaves=0 leaves_free=64 policers=0\n"
		 "port dev=lan1 tree=1 channels=31 spare=0 held=- leaves=1 leaves_free=63 policers=1\n");
	/* Every channel the instance has, on one port: the longest list. */
	ports[0].port.channels = 0xffffffff;
	ports[0].port.held = 0xffffffff;
	nports = 1;
	rows_are(ft_qos_ports_show,
		 "port dev=eth3 tree=1 channels=0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,"
		 "20,21,22,23,24,25,26,27,28,29,30,31 spare=1 held=0,1,2,3,4,5,6,7,8,9,10,11,12,13,"
		 "14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31 leaves=3 leaves_free=61 policers=2\n");
	/* No port of cdx's: an empty file. */
	nports = 0;
	rows_are(ft_qos_ports_show, "");
}

static void test_classes(void)
{
	static struct seq_file seq;

	world();
	/* Beside mwan3: queue and channel are both in reach, so every leaf's
	 * class is a mark. */
	ft_qos_mark_mask = 0xffff0000;
	rows_are(ft_qos_classes_show,
		 "class dev=eth3 classid=1:1 parent=1: kind=inner channel=0 queue=- slot=- depth=- qos=- mark=-\n"
		 "class dev=eth3 classid=1:a parent=1:1 kind=leaf channel=0 queue=5 slot=0 depth=128 qos=000015 mark=0x150000\n"
		 "class dev=eth3 classid=1:23 parent=1: kind=leaf channel=4 queue=7 slot=3 depth=41 qos=000057 mark=0x570000\n"
		 "class dev=eth3 classid=1:24 parent=1: kind=leaf channel=20 queue=2 slot=1 depth=1 qos=000152 mark=0x1520000\n"
		 "class dev=lan1 classid=10:ffff parent=10: kind=leaf channel=31 queue=15 slot=0 depth=4294967295 qos=00020f mark=0x20f0000\n");
	/* The low half, as beside pbr: the same values, unshifted. */
	ft_qos_mark_mask = 0xffff;
	rows_are(ft_qos_classes_show,
		 "class dev=eth3 classid=1:1 parent=1: kind=inner channel=0 queue=- slot=- depth=- qos=- mark=-\n"
		 "class dev=eth3 classid=1:a parent=1:1 kind=leaf channel=0 queue=5 slot=0 depth=128 qos=000015 mark=0x15\n"
		 "class dev=eth3 classid=1:23 parent=1: kind=leaf channel=4 queue=7 slot=3 depth=41 qos=000057 mark=0x57\n"
		 "class dev=eth3 classid=1:24 parent=1: kind=leaf channel=20 queue=2 slot=1 depth=1 qos=000152 mark=0x152\n"
		 "class dev=lan1 classid=10:ffff parent=10: kind=leaf channel=31 queue=15 slot=0 depth=4294967295 qos=00020f mark=0x20f\n");
	/* Beside both: eight bits, queue and channels 1 to 15. A class on a
	 * channel past them has no mark this mask can carry. */
	ft_qos_mark_mask = 0xff000000;
	rows_are(ft_qos_classes_show,
		 "class dev=eth3 classid=1:1 parent=1: kind=inner channel=0 queue=- slot=- depth=- qos=- mark=-\n"
		 "class dev=eth3 classid=1:a parent=1:1 kind=leaf channel=0 queue=5 slot=0 depth=128 qos=000015 mark=0x15000000\n"
		 "class dev=eth3 classid=1:23 parent=1: kind=leaf channel=4 queue=7 slot=3 depth=41 qos=000057 mark=0x57000000\n"
		 "class dev=eth3 classid=1:24 parent=1: kind=leaf channel=20 queue=2 slot=1 depth=1 qos=000152 mark=-\n"
		 "class dev=lan1 classid=10:ffff parent=10: kind=leaf channel=31 queue=15 slot=0 depth=4294967295 qos=00020f mark=-\n");
	/* The test image's: the queue field alone, which names no channel. */
	ft_qos_mark_mask = 0xf0;
	rows_are(ft_qos_classes_show,
		 "class dev=eth3 classid=1:1 parent=1: kind=inner channel=0 queue=- slot=- depth=- qos=- mark=-\n"
		 "class dev=eth3 classid=1:a parent=1:1 kind=leaf channel=0 queue=5 slot=0 depth=128 qos=000015 mark=-\n"
		 "class dev=eth3 classid=1:23 parent=1: kind=leaf channel=4 queue=7 slot=3 depth=41 qos=000057 mark=-\n"
		 "class dev=eth3 classid=1:24 parent=1: kind=leaf channel=20 queue=2 slot=1 depth=1 qos=000152 mark=-\n"
		 "class dev=lan1 classid=10:ffff parent=10: kind=leaf channel=31 queue=15 slot=0 depth=4294967295 qos=00020f mark=-\n");
	/* Classification off. */
	ft_qos_mark_mask = 0;
	rows_are(ft_qos_classes_show,
		 "class dev=eth3 classid=1:1 parent=1: kind=inner channel=0 queue=- slot=- depth=- qos=- mark=-\n"
		 "class dev=eth3 classid=1:a parent=1:1 kind=leaf channel=0 queue=5 slot=0 depth=128 qos=000015 mark=-\n"
		 "class dev=eth3 classid=1:23 parent=1: kind=leaf channel=4 queue=7 slot=3 depth=41 qos=000057 mark=-\n"
		 "class dev=eth3 classid=1:24 parent=1: kind=leaf channel=20 queue=2 slot=1 depth=1 qos=000152 mark=-\n"
		 "class dev=lan1 classid=10:ffff parent=10: kind=leaf channel=31 queue=15 slot=0 depth=4294967295 qos=00020f mark=-\n");

	/* A port whose classes outgrow what the budget says a port can have
	 * fails the read rather than leaving them out, and no memory behind. */
	ports[0].count = 64 + 32 + 1;
	for (int ii = 4; ii < ports[0].count; ii++)
		ports[0].classes[ii] = leaf(1, 0x100 + ii, 0, 1, 0, 0, 1);
	seq.len = 0;
	assert(ft_qos_classes_show(&seq, NULL) == -ENOSPC && !allocations);
	/* And a read with no memory for them fails as such. */
	world();
	allocation_fails = true;
	seq.len = 0;
	assert(ft_qos_classes_show(&seq, NULL) == -ENOMEM && !seq.len);
	allocation_fails = false;
	/* No port with a tree: an empty file. */
	nports = 0;
	rows_are(ft_qos_classes_show, "");
}

int main(void)
{
	test_status();
	test_ports();
	test_classes();
	printf("qos report: passed\n");
	return 0;
}
