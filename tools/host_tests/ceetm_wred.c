/* The RED curve a tc qdisc describes, against the one the congestion group
 * ends up holding.
 *
 * RED says "start dropping at min, reach probability P at max". The CCG says
 * "reach P at MaxTH, getting there at Slope", so the minimum is implied rather
 * than stored. Converting between them is arithmetic with three separately
 * encoded mantissa-exponent fields, and the invariant that matters is not that
 * each field round-trips but that the curve does: the implied minimum has to
 * land back on the minimum the operator asked for.
 */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

typedef uint16_t U16;

#define CEETM_SUCCESS			0
#define CEETM_FAILURE			-1
#define CDX_CEETM_MAX_CHANNELS		8
#define NUM_PQS				8
#define NUM_WBFQS			8
#define MAX_SCHEDULER_QUEUES		(NUM_PQS + NUM_WBFQS)
#define DEFAULT_CQ_DEPTH		8
#define ceetm_err(...)			((void)0)
#define ceetm_dbg(...)			((void)0)

#define QM_CCGR_WE_MODE		0x0002
#define QM_CCGR_WE_TD_EN	0x0004
#define QM_CCGR_WE_TD_MODE	0x0008
#define QM_CCGR_WE_TD_THRES	0x0010
#define QM_CCGR_WE_WR_EN_R	0x0020
#define QM_CCGR_WE_WR_EN_Y	0x0040
#define QM_CCGR_WE_WR_EN_G	0x0080
#define QM_CCGR_WE_WR_PARM_R	0x0100
#define QM_CCGR_WE_WR_PARM_Y	0x0200
#define QM_CCGR_WE_WR_PARM_G	0x0400

static uint64_t div64_u64(uint64_t a, uint64_t b) { return b ? a / b : 0; }

/* The two encodings this file converts into, exactly as the SDK declares them:
 *   MaxTH = MA * 2^Mn,  Slope = SA / 2^Sn,  MaxP = 4 * (Pn + 1)
 *   CS threshold = TA * 2^Tn
 */
struct qm_cgr_wr_parm {
	union {
		uint32_t word;
		struct {
			uint32_t Pn:6;
			uint32_t Sn:6;
			uint32_t SA:7;
			uint32_t Mn:5;
			uint32_t MA:8;
		} __attribute__((packed));
	};
} __attribute__((packed));

struct qm_cgr_cs_thres {
	union {
		uint16_t hword;
		struct {
			uint16_t TA:8;
			uint16_t Tn:5;
			uint16_t __reserved:3;
		} __attribute__((packed));
	};
} __attribute__((packed));

static uint64_t qm_cgr_cs_thres_get64(const struct qm_cgr_cs_thres *th)
{
	return (uint64_t)th->TA << th->Tn;
}
static int qm_cgr_cs_thres_set64(struct qm_cgr_cs_thres *th, uint64_t val,
				 int roundup)
{
	uint32_t e = 0;
	int oddbit = 0;

	while (val > 0xff) {
		oddbit = val & 1;
		val >>= 1;
		e++;
		if (roundup && oddbit)
			val++;
	}
	th->Tn = e;
	th->TA = val;
	return 0;
}

struct qm_ceetm_ccg_params {
	struct {
		uint8_t mode:1;
		uint8_t td_en:1;
		uint8_t td_mode:1;
		uint8_t cscn_en:1;
		uint8_t wr_en_g:1;
		uint8_t wr_en_y:1;
		uint8_t wr_en_r:1;
	} __attribute__((packed));
	struct qm_cgr_cs_thres td_thres;
	struct qm_cgr_cs_thres cs_thres_in;
	struct qm_cgr_cs_thres cs_thres_out;
	signed char oal;
	struct qm_cgr_wr_parm wr_parm_g;
	struct qm_cgr_wr_parm wr_parm_y;
	struct qm_cgr_wr_parm wr_parm_r;
};

struct qm_ceetm_ccg { int idx; };
struct classque_info {
	void *ccg;
	uint32_t qdepth;
};
struct ceetm_chnl_info {
	struct classque_info cq_info[MAX_SCHEDULER_QUEUES];
};
static struct ceetm_chnl_info qm_chnl_info[CDX_CEETM_MAX_CHANNELS];

/* What the hardware was last told. */
static struct qm_ceetm_ccg_params last_params;
static uint16_t last_mask;
static unsigned ccg_set_calls;
static bool ccg_set_fails;
static int qman_ceetm_ccg_set(struct qm_ceetm_ccg *ccg, uint16_t we_mask,
			      const struct qm_ceetm_ccg_params *params)
{
	assert(ccg);
	if (ccg_set_fails)
		return -EIO;
	last_params = *params;
	last_mask = we_mask;
	ccg_set_calls++;
	return 0;
}

/* Frame-mode tail drop, as the leaf class has it without a RED qdisc. */
static unsigned td_calls;
static uint32_t td_depth;
static int ceetm_cfg_td_on_class_queue(struct ceetm_chnl_info *chnl_ctx,
				       uint32_t index, uint32_t tdthresh)
{
	assert(chnl_ctx && index < MAX_SCHEDULER_QUEUES);
	td_calls++;
	td_depth = tdthresh;
	return 0;
}

#include "wred_production.inc"

/* ------------------------------------------------------------------ */

/* The curve the hardware holds, read back out of its own encoding. */
static double maxth_of(const struct qm_cgr_wr_parm *p)
{
	return (double)p->MA * (double)(1u << p->Mn);
}
static double slope_of(const struct qm_cgr_wr_parm *p)
{
	return (double)p->SA / (double)(1ull << p->Sn);
}
static double maxp_of(const struct qm_cgr_wr_parm *p)
{
	return 4.0 * (p->Pn + 1);
}
/* MinTH is not stored: it is where the slope reaches zero below MaxTH. */
static double minth_of(const struct qm_cgr_wr_parm *p)
{
	return maxth_of(p) - maxp_of(p) / slope_of(p);
}

static void check_curve(uint32_t min, uint32_t max, double probability,
			uint32_t limit)
{
	uint32_t prob = (uint32_t)(probability * 4294967296.0);
	const struct qm_cgr_wr_parm *p = &last_params.wr_parm_g;
	double got_min, got_max, got_p, span = max - min;

	assert(!ceetm_set_class_wred(0, 3, min, max, prob, limit));

	/* Bytes, for both the curve and the tail drop, so they cannot disagree
	 * about the unit. */
	assert(last_params.mode == 0);
	assert(last_params.td_en == 1 && last_params.td_mode == 1);
	assert(last_params.wr_en_g && last_params.wr_en_y && last_params.wr_en_r);
	/* One curve, on every colour. */
	assert(!memcmp(&last_params.wr_parm_g, &last_params.wr_parm_y,
		       sizeof(last_params.wr_parm_g)));
	assert(!memcmp(&last_params.wr_parm_g, &last_params.wr_parm_r,
		       sizeof(last_params.wr_parm_g)));
	/* The mantissa the encoding insists on, or the gradient loses its
	 * precision. */
	assert(p->SA >= 64 && p->SA <= 127);

	got_max = maxth_of(p);
	got_min = minth_of(p);
	got_p = maxp_of(p) / 256.0;

	/* The top of the curve, within the eight-bit mantissa's resolution. */
	assert(got_max <= max && got_max > max * 0.99);
	/* The probability, within 4/256 -- Pn's own step. */
	assert(got_p <= probability + 4.0 / 256.0 + 1e-9);
	assert(got_p > probability - 4.0 / 256.0 - 1e-9);
	/* And the invariant that matters: the minimum the curve implies is the
	 * minimum that was asked for. Tolerated against the span rather than
	 * against min itself, because that is what the slope's mantissa
	 * quantises. */
	assert(got_min > min - span * 0.05);
	assert(got_min < min + span * 0.05);

	/* The tail drop is the qdisc's own limit, within the same resolution. */
	assert(qm_cgr_cs_thres_get64(&last_params.td_thres) <= limit);
	assert(qm_cgr_cs_thres_get64(&last_params.td_thres) > limit * 0.99);
}

int main(void)
{
	struct qm_ceetm_ccg ccg = { .idx = 3 };
	unsigned ii;

	qm_chnl_info[0].cq_info[3].ccg = &ccg;

	/* The shapes an operator actually writes, from a small buffer on a
	 * slow class to a deep one on a fast link. */
	check_curve(30000, 100000, 0.02, 400000);
	check_curve(15000, 45000, 0.02, 180000);
	check_curve(100000, 300000, 0.10, 1000000);
	check_curve(1000, 4000, 0.50, 16000);
	check_curve(250000, 1000000, 0.01, 4000000);
	/* A narrow band wants a steep slope; a very wide one a gentle slope.
	 * Both have to stay inside the mantissa the encoding allows. */
	check_curve(99000, 100000, 0.02, 400000);
	check_curve(1000, 8000000, 0.02, 16000000);

	/* Degenerate curves are refused rather than encoded into something
	 * that would drop at a depth nobody asked for. */
	assert(ceetm_set_class_wred(0, 3, 100, 100, 1u << 26, 4000) == -EINVAL);
	assert(ceetm_set_class_wred(0, 3, 200, 100, 1u << 26, 4000) == -EINVAL);
	assert(ceetm_set_class_wred(0, 3, 10, 100, 1u << 26, 0) == -EINVAL);
	assert(ceetm_set_class_wred(CDX_CEETM_MAX_CHANNELS, 3, 10, 100,
				    1u << 26, 4000) == -EINVAL);
	assert(ceetm_set_class_wred(0, MAX_SCHEDULER_QUEUES, 10, 100,
				    1u << 26, 4000) == -EINVAL);
	/* A class queue with no congestion group has nothing to configure. */
	qm_chnl_info[0].cq_info[4].ccg = NULL;
	assert(ceetm_set_class_wred(0, 4, 10, 100, 1u << 26, 4000) == -ENODEV);

	/* A hardware refusal is reported, not swallowed. */
	ccg_set_fails = true;
	assert(ceetm_set_class_wred(0, 3, 10, 100, 1u << 26, 4000) == -EIO);
	ccg_set_fails = false;

	/* Taking the curve away puts the class queue back on the frame-counted
	 * tail drop it has without a RED qdisc. */
	ii = ccg_set_calls;
	assert(!ceetm_clear_class_wred(0, 3, 128));
	assert(ccg_set_calls == ii + 1);
	assert(!last_params.wr_en_g && !last_params.wr_en_y && !last_params.wr_en_r);
	assert(last_mask == (QM_CCGR_WE_WR_EN_G | QM_CCGR_WE_WR_EN_Y |
			     QM_CCGR_WE_WR_EN_R));
	assert(td_calls == 1 && td_depth == 128);
	assert(ceetm_clear_class_wred(0, 4, 128) == -ENODEV);

	printf("CEETM WRED: 7 curves encode with their implied minimum back on the "
	       "one asked for, %u refusals\n", 6u);
	return 0;
}
