/* The RED curve a tc qdisc describes, against the one the congestion group
 * ends up holding.
 *
 * RED says "start dropping at min, reach probability P at max". The CCG says
 * "reach P at MaxTH, getting there at Slope", so the minimum is implied rather
 * than stored. Converting between them is arithmetic with three separately
 * encoded mantissa-exponent fields, and the invariant that matters is not that
 * each field round-trips but that the curve does: the implied minimum has to
 * land back on the minimum the operator asked for.
 *
 * Every group counts frames, a curve's included (A337): what a queued frame
 * holds is a buffer, however short the frame. The curves that reach the
 * hardware are RED's bytes converted to frames by cdx_htb.c, so they are
 * small -- a few frames to a few hundred -- where MaxTH is exact and the
 * slope's mantissa is the coarse part.
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
#define max_t(t, a, b)		((t)(a) > (t)(b) ? (t)(a) : (t)(b))
#define DIV_ROUND_UP(n, d)	(((n) + (d) - 1) / (d))

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

#define DEFAULT_WBFQ_WEIGHT		1

/* Each congestion group remembers whether its curve is on, as the hardware
 * would, so a test can ask after a whole sequence rather than one call. */
struct qm_ceetm_ccg { int idx; bool wred_on; };
struct classque_info {
	void *ccg;
	void *cq;
	uint32_t ceetm_idx;
	union {
		uint32_t ch_shaper_enable;
		uint32_t weight;
	};
	uint32_t qdepth;
	bool wred;
	uint32_t wred_parm;
};
struct qm_ceetm_channel { int idx; };
struct ceetm_chnl_info {
	struct qm_ceetm_channel *channel;
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
	/* One curve for every colour, so the three enables move together. */
	if (we_mask & QM_CCGR_WE_WR_EN_G) {
		assert(!!(we_mask & QM_CCGR_WE_WR_EN_Y) && !!(we_mask & QM_CCGR_WE_WR_EN_R));
		assert(params->wr_en_g == params->wr_en_y && params->wr_en_g == params->wr_en_r);
		ccg->wred_on = params->wr_en_g;
	}
	return 0;
}

/* The scheduler side of configuring and resetting a class queue, which this
 * file is not about: recorded, and never failing. */
struct qm_ceetm_weight_code { int code; };
static int qman_ceetm_ratio2wbfs(uint32_t n, uint32_t d, struct qm_ceetm_weight_code *w,
				 int roundup)
{ (void)d; (void)roundup; w->code = (int)n; return 0; }
static int qman_ceetm_set_queue_weight(void *cq, struct qm_ceetm_weight_code *w)
{ (void)cq; (void)w; return 0; }
static int qman_ceetm_channel_set_group_cr_eligibility(struct qm_ceetm_channel *ch, int g, int on)
{ assert(ch); (void)g; (void)on; return 0; }
static int qman_ceetm_channel_set_group_er_eligibility(struct qm_ceetm_channel *ch, int g, int on)
{ assert(ch); (void)g; (void)on; return 0; }
static int qman_ceetm_channel_set_cq_cr_eligibility(struct qm_ceetm_channel *ch, uint32_t idx, int on)
{ assert(ch); (void)idx; (void)on; return 0; }
static int qman_ceetm_channel_set_cq_er_eligibility(struct qm_ceetm_channel *ch, uint32_t idx, int on)
{ assert(ch); (void)idx; (void)on; return 0; }

/* Frame-mode tail drop, as the leaf class has it without a RED qdisc, and as
 * the production setter records it. */
static unsigned td_calls;
static uint32_t td_depth;
static int ceetm_cfg_td_on_class_queue(struct ceetm_chnl_info *chnl_ctx,
				       uint32_t index, uint32_t tdthresh)
{
	assert(chnl_ctx && index < MAX_SCHEDULER_QUEUES);
	if (ccg_set_fails)
		return CEETM_FAILURE;
	td_calls++;
	td_depth = tdthresh;
	chnl_ctx->cq_info[index].qdepth = tdthresh;
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

	/* Frames, for both the curve and the tail drop, as every class queue's
	 * group counts: never switched to bytes and back with frames queued. */
	assert(last_params.mode == 1);
	assert(last_mask & QM_CCGR_WE_MODE);
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
	/* And what the hardware layer records is what the group now holds. */
	assert(qm_chnl_info[0].cq_info[3].qdepth == limit && qm_chnl_info[0].cq_info[3].wred);
}

/* The implied minimum of a curve asked for at min..max, exactly as the group
 * encodes it, for a band too narrow to check against check_curve()'s
 * tolerance. */
static double implied_min(uint32_t min, uint32_t max, uint32_t prob)
{
	assert(!ceetm_set_class_wred(0, 3, min, max, prob, max + 1));
	return minth_of(&last_params.wr_parm_g);
}

int main(void)
{
	struct qm_ceetm_ccg ccg = { .idx = 3 };
	unsigned ii;

	qm_chnl_info[0].cq_info[3].ccg = &ccg;

	/* The shapes an operator writes, as cdx_htb.c hands them over: RED's
	 * bytes divided by a 1,542-byte frame, and scaled down where the tree
	 * gave the queue less than the limit asked for. 30,000 to 100,000
	 * bytes with a 400,000-byte limit; 15,000 to 45,000 of 180,000;
	 * 100,000 to 300,000 of a megabyte; one to four megabytes cut to the
	 * 768 frames a tree left it. */
	check_curve(19, 64, 0.02, 259);
	check_curve(9, 29, 0.02, 116);
	check_curve(64, 194, 0.10, 648);
	check_curve(191, 575, 0.02, 768);
	/* A tight band, and a curve scaled down onto a shallow queue. */
	check_curve(2, 6, 0.02, 10);
	check_curve(0, 2, 0.02, 56);
	check_curve(0, 2, 0.99, 1);
	/* The encoding is not limited to frame-sized numbers: a narrow band
	 * wants a steep slope, a very wide one a gentle slope, and both have to
	 * stay inside the mantissa the encoding allows. */
	check_curve(99000, 100000, 0.02, 400000);
	check_curve(1000, 8000000, 0.02, 16000000);

	/* The narrowest band the encoding draws with its implied minimum where
	 * it was put. The slope tops out at 127 per frame, and MaxP never
	 * reaches 256 -- a probability below 2^32 is at most 252 -- so two
	 * frames at any probability, which a converted curve is widened to.
	 * Every band of two lands its minimum exactly, at the steepest
	 * probability and the gentlest. */
	assert(ceetm_wred_min_band(0) == 2 && ceetm_wred_min_band(1u << 26) == 2);
	assert(ceetm_wred_min_band(0xffffffffu) == 2 && ceetm_wred_maxp(0xffffffffu) == 252);
	assert(ceetm_wred_maxp(0) == 4 && ceetm_wred_maxp(1u << 31) == 128);
	for (ii = 0; ii < 64; ii++) {
		uint32_t prob = ii * (0xffffffffu / 63), band = ceetm_wred_min_band(prob);

		assert(implied_min(0, band, prob) == 0.0);
		assert(implied_min(17, 17 + band, prob) == 17.0);
		assert(implied_min(200, 200 + band, prob) == 200.0);
	}
	/* One frame is too narrow where the probability is high: the slope
	 * would have to be 252 per frame, and is drawn at 127, so the curve
	 * starts a frame early. */
	assert(implied_min(10, 11, 0xffffffffu) < 9.1);

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

	/* A hardware refusal is reported, not swallowed, and recorded as
	 * nothing having changed. */
	assert(!ceetm_set_class_wred(0, 3, 19, 64, 1u << 26, 259));
	ccg_set_fails = true;
	assert(ceetm_set_class_wred(0, 3, 10, 100, 1u << 26, 4000) == -EIO);
	ccg_set_fails = false;
	assert(qm_chnl_info[0].cq_info[3].qdepth == 259 && qm_chnl_info[0].cq_info[3].wred);

	/* A curve and depth the group already holds are not written again: a
	 * tree's cap draws every RED leaf again whenever any share moves, and a
	 * write that changes nothing could still fail and cost the leaf its
	 * curve. Another curve, or the same one at another depth, is written. */
	ii = ccg_set_calls;
	ccg_set_fails = true;
	assert(!ceetm_set_class_wred(0, 3, 19, 64, 1u << 26, 259));
	ccg_set_fails = false;
	assert(ccg_set_calls == ii);
	assert(!ceetm_set_class_wred(0, 3, 19, 70, 1u << 26, 259));
	assert(ccg_set_calls == ii + 1);
	assert(!ceetm_set_class_wred(0, 3, 19, 70, 1u << 26, 300));
	assert(ccg_set_calls == ii + 2);
	assert(qm_chnl_info[0].cq_info[3].qdepth == 300);

	/* Taking the curve away puts the class queue back on the frame-counted
	 * tail drop it has without a RED qdisc. */
	ii = ccg_set_calls;
	assert(!ceetm_clear_class_wred(0, 3, 128));
	assert(ccg_set_calls == ii + 1);
	assert(!last_params.wr_en_g && !last_params.wr_en_y && !last_params.wr_en_r);
	assert(last_mask == (QM_CCGR_WE_WR_EN_G | QM_CCGR_WE_WR_EN_Y |
			     QM_CCGR_WE_WR_EN_R));
	assert(td_calls == 1 && td_depth == 128);
	assert(!ccg.wred_on && !qm_chnl_info[0].cq_info[3].wred &&
	       qm_chnl_info[0].cq_info[3].qdepth == 128);
	assert(ceetm_clear_class_wred(0, 4, 128) == -ENODEV);
	/* Zero frames would be no tail drop at all, and is refused. */
	assert(ceetm_clear_class_wred(0, 3, 0) == -EINVAL);

	/* A tree's cap resizes a queue's tail drop and nothing else: a curve
	 * running there stays on, untouched. */
	assert(!ceetm_set_class_wred(0, 3, 19, 64, 1u << 26, 259));
	ii = ccg_set_calls;
	assert(!ceetm_set_class_depth(0, 3, 56));
	assert(td_depth == 56 && ccg.wred_on && ccg_set_calls == ii);
	{
		uint32_t depth;
		bool curve;

		/* And reads back what each queue holds, to tell a queue that
		 * shrinks from one that grows. */
		assert(!ceetm_class_queue_state(0, 3, &depth, &curve));
		assert(depth == 56 && curve);
		assert(!ceetm_clear_class_wred(0, 3, 128));
		assert(!ceetm_class_queue_state(0, 3, &depth, &curve));
		assert(depth == 128 && !curve);
		assert(ceetm_class_queue_state(0, 4, &depth, &curve) == -ENODEV);
		assert(ceetm_class_queue_state(CDX_CEETM_MAX_CHANNELS, 3, &depth,
					       &curve) == -EINVAL);
	}
	assert(ceetm_set_class_depth(0, 3, 0) == -EINVAL);
	assert(ceetm_set_class_depth(0, 4, 56) == -ENODEV);
	assert(ceetm_set_class_depth(0, MAX_SCHEDULER_QUEUES, 56) == -EINVAL);
	ccg_set_fails = true;
	assert(ceetm_set_class_depth(0, 3, 56) == -EIO);
	ccg_set_fails = false;
	assert(qm_chnl_info[0].cq_info[3].qdepth == 128);

	/* A curve outlives everything that only reconfigures a class queue's
	 * depth, so the paths that hand a queue to a new class, or back to its
	 * defaults, have to take it off themselves. A leaf deleted with a RED
	 * qdisc on it is reset before that qdisc's destroy arrives, and the
	 * destroy then names a class that is gone. A queue given back is
	 * parked at a frame, all the classifier entries still naming it can
	 * put on it until they are installed again. */
	assert(CEETM_PARKED_CQ_DEPTH == 1);
	static struct qm_ceetm_channel channel = { .idx = 0 };
	struct qm_ceetm_ccg weighted = { .idx = 9 };

	qm_chnl_info[0].channel = &channel;
	qm_chnl_info[0].cq_info[NUM_PQS + 1].ccg = &weighted;
	for (ii = 0; ii < 2; ii++) {
		uint32_t queue = ii ? NUM_PQS + 1 : 3;
		struct qm_ceetm_ccg *group = qm_chnl_info[0].cq_info[queue].ccg;

		assert(!ceetm_set_class_wred(0, queue, 10, 40, 1u << 26, 160));
		assert(group->wred_on && qm_chnl_info[0].cq_info[queue].wred);
		assert(!ceetm_reset_class_queue(0, queue));
		assert(!group->wred_on && td_depth == CEETM_PARKED_CQ_DEPTH);
		assert(qm_chnl_info[0].cq_info[queue].qdepth == CEETM_PARKED_CQ_DEPTH);
		assert(!qm_chnl_info[0].cq_info[queue].wred);
		/* And configuring a queue for a class starts it on plain tail
		 * drop, whatever the previous owner left behind. The same curve
		 * goes on again after the reset took it off, not skipped as one
		 * the group still holds. */
		assert(!ceetm_set_class_wred(0, queue, 10, 40, 1u << 26, 160));
		assert(group->wred_on && qm_chnl_info[0].cq_info[queue].wred);
		assert(!ceetm_set_class_queue(0, queue, ii ? 4 : 0, 1));
		assert(!group->wred_on && td_depth == 1);
		assert(!qm_chnl_info[0].cq_info[queue].wred);
	}
	/* A congestion group that will not take the change is reported. */
	assert(!ceetm_set_class_wred(0, 3, 10, 40, 1u << 26, 160));
	ccg_set_fails = true;
	assert(ceetm_reset_class_queue(0, 3) == -EIO);
	assert(ceetm_set_class_queue(0, 3, 0, 1) == -EIO);
	ccg_set_fails = false;
	assert(ccg.wred_on && qm_chnl_info[0].cq_info[3].wred);
	assert(!ceetm_reset_class_queue(0, 3) && !ccg.wred_on);

	printf("CEETM WRED: %u curves encode in frames with their implied minimum back "
	       "on the one asked for, bands of %u frames land it exactly, %u refusals, "
	       "and configure and reset take a curve off\n", 9u, 2u, 6u);
	return 0;
}
