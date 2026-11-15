/* The bound of a DPAA port's queues to the CPU is production code
 * (dpaa_eth_priv_ingress_cgr*_init()); QMan's congestion groups are the
 * simulated boundary, recording the threshold each group is created with.
 *
 * Every private port receives into one shared pool, which each port probed
 * after the first raises by its own share (CONFIG_FSL_DPAA_ETH_MAX_BUF_COUNT
 * per CPU) only once the port's groups are made, so the pool's count a port
 * sees at that point depends on how many ports probed before it. Its bound
 * has to be the port's own share, whatever that count: one port's flood then
 * holds no more of the pool than another's. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef unsigned int uint;

#define max_t(type, x, y) ({ type __x = (x); type __y = (y); __x > __y ? __x : __y; })
#define min_t(type, x, y) ({ type __x = (x); type __y = (y); __x < __y ? __x : __y; })
#define clamp_t(type, val, lo, hi) min_t(type, max_t(type, val, lo), hi)

static unsigned int errors;
#define pr_err(...) (errors++)
#define pr_debug(...) do { } while (0)

/* The pool's share per port per CPU, the Kconfig value, varied by the cases
 * below; and the CPUs the kernel could bring up. */
static int max_buf_count;
#define CONFIG_FSL_DPAA_ETH_MAX_BUF_COUNT max_buf_count
static unsigned int possible_cpus;
#define num_possible_cpus() possible_cpus
/* The module parameter. */
static uint ingress_quarters;

#define QM_CGR_EN 0x01
#define QM_CGR_WE_MODE 0x0001
#define QM_CGR_WE_CS_THRES 0x0002
#define QM_CGR_WE_CSCN_EN 0x0004
#define QM_CGR_WE_CSTD_EN 0x0008
#define QMAN_CGR_FLAG_USE_INIT 0x00000001
#define QMAN_CGR_MODE_FRAME 0x00000001

struct qm_cgr_cs_thres { u64 requested; };
struct qm_mcc_initcgr {
	u16 we_mask;
	struct {
		u8 mode, cscn_en, cstd_en;
		struct qm_cgr_cs_thres cs_thres;
	} cgr;
};
struct qman_cgr { u32 cgrid; };
struct dpa_bp {
	union {
		int target_count;
		int config_count;
	};
};
struct mac_device { u8 addr[6]; };
struct dpa_priv_s {
	struct dpa_bp *dpa_bp;
	struct mac_device *mac_dev;
	struct qman_cgr ingress_cgr;
	struct qman_cgr ingress_cgr_hi_prio;
	bool use_ingress_cgr;
};

/* The groups a port made, and the threshold each asked for. */
#define GROUPS 4
static unsigned int created;
static u64 threshold[GROUPS];
static u32 next_cgrid;

static inline int qm_cgr_cs_thres_set64(struct qm_cgr_cs_thres *th, u64 val, int roundup)
{
	th->requested = val;
	return 0;
}

static int qman_alloc_cgrid(u32 *cgrid)
{
	*cgrid = next_cgrid++;
	return 0;
}

static void qman_release_cgrid(u32 cgrid)
{
}

static int qman_create_cgr(struct qman_cgr *cgr, u32 flags, struct qm_mcc_initcgr *opts)
{
	if (created == GROUPS || !(opts->we_mask & QM_CGR_WE_CS_THRES) ||
	    opts->cgr.mode != QMAN_CGR_MODE_FRAME)
		return -1;
	threshold[created++] = opts->cgr.cs_thres.requested;
	return 0;
}

static inline void dpa_destroy_cgr(struct qman_cgr *cgr)
{
}

#include "dpaa_ingress_bound_production.inc"

/* The pool's count when port `port' (1 for the first probed) makes its
 * groups, as dpaa_eth_priv_probe() orders the raise (see the driver). */
static int pool_seen(unsigned int port)
{
	int count = CONFIG_FSL_DPAA_ETH_MAX_BUF_COUNT;

	for (unsigned int earlier = 2; earlier <= port; earlier++)
		if (earlier < port || POOL_RAISED_BEFORE_INGRESS)
			count += POOL_RAISED * CONFIG_FSL_DPAA_ETH_MAX_BUF_COUNT;
	return count;
}

int main(void)
{
	/* The defaults first (the Kconfig share, the LS1046A's four cores, half
	 * a share), so the first failure reported is the board's own. */
	static const int shares[] = { 128, 64, 512, 2048 };
	static const unsigned int cpus[] = { 4, 1, 2, 8 };
	static const uint quarters[] = { 2, 0, 1, 3, 4, 9 };
	unsigned int failures = 0, cases = 0;

	for (size_t s = 0; s < sizeof(shares) / sizeof(shares[0]); s++)
	for (size_t c = 0; c < sizeof(cpus) / sizeof(cpus[0]); c++)
	for (size_t q = 0; q < sizeof(quarters) / sizeof(quarters[0]); q++)
	for (unsigned int port = 1; port <= 5; port++) {
		struct mac_device mac = { { 0x02, 0, 0, 0, 0, (u8)port } };
		struct dpa_bp pool;
		struct dpa_priv_s priv = { .dpa_bp = &pool, .mac_dev = &mac };
		uint clamped = quarters[q] < 1 ? 1 : quarters[q] > 4 ? 4 : quarters[q];
		u64 own, expected;

		max_buf_count = shares[s];
		possible_cpus = cpus[c];
		ingress_quarters = quarters[q];
		pool.config_count = pool_seen(port);
		own = (u64)max_buf_count * possible_cpus * clamped / 4;
		expected = own ? own : 1;
		created = 0;
		errors = 0;
		cases++;
		if (INGRESS_INIT(&priv) || errors || !created || !priv.use_ingress_cgr) {
			fprintf(stderr, "port %u: no ingress group made\n", port);
			return 1;
		}
		for (unsigned int g = 0; g < created; g++) {
			if (threshold[g] == expected)
				continue;
			if (failures++ < 8)
				fprintf(stderr,
					"port %u, probed with the shared pool at %d buffers "
					"(%d per CPU per port, %u CPUs, ingress_quarters %u), "
					"bounds its queues to the CPU at %llu frames "
					"(group %u of %u), not at its own share's %llu\n",
					port, pool.config_count, max_buf_count, possible_cpus,
					ingress_quarters, (unsigned long long)threshold[g], g + 1,
					created, (unsigned long long)expected);
			break;
		}
	}
	if (failures) {
		fprintf(stderr, "%u of %u port probes bounded the port's queues by the pool's "
			"count, not the port's own share\n", failures, cases);
		return 1;
	}
	printf("%u port probes: each port's queues to the CPU bounded by its own share\n", cases);
	return 0;
}
