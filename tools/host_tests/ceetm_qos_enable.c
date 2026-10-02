/* Turning a port's QoS on and off has to be symmetric.
 *
 * The SDK's LNI shaper is one-shot in both directions -- enabling one that is
 * already enabled is an error, and so is disabling one that is not -- so a
 * port that comes up and goes down again has to leave that shaper exactly as
 * it found it. Anything else works once and fails the second time, which is a
 * qdisc torn down and built again, or CMM toggling QOSENABLE.
 *
 * The excess rate is the other half: a channel's class queues are excess
 * eligible by default, so a zero excess rate is not "no cap", it is no
 * bandwidth.
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
#define QOS_ENERR_NOT_CONFIGURED	1
#define QOS_ENERR_IO			2
#define CDX_CEETM_MAX_CHANNELS		8
#define NUM_CHANNEL_SHAPERS		8
#define MAX_SCHEDULER_QUEUES		16
#define CEETM_TOKEN_WHOLE_MAXVAL	0x7ff
#define CEETM_TOKEN_FRAC_MAXVAL		0x1fff
#define CEETM_DEFA_BSIZE		0x2000
#define CEETM_DEFA_OAL			24
#define ceetm_err(...)			((void)0)
#define ceetm_dbg(...)			((void)0)

struct qm_ceetm_rate { uint16_t whole, fraction; };
struct qm_ceetm_sp { unsigned idx, dcp_idx; };
struct qm_ceetm_lni {
	unsigned idx, dcp_idx;
	struct qm_ceetm_sp *sp;
	bool shaper_enable;	/* the SDK's own one-shot flag */
};
struct qm_ceetm_channel { unsigned idx; };
struct shaper_info {
	uint64_t rate;
	uint32_t enable;
	uint32_t bsize;
	struct qm_ceetm_rate token_cr;
	struct qm_ceetm_rate token_er;
};
struct dpa_iface_info { char name[16]; };
struct dpa_priv_s { void *qm_ctx; bool ceetm_en; };
struct net_device { struct dpa_priv_s priv; };
struct tQM_context_ctl {
	struct dpa_iface_info *iface_info;
	struct net_device *net_dev;
	struct qm_ceetm_lni *lni;
	struct qm_ceetm_sp *sp;
	uint32_t qos_enabled;
	uint32_t chnl_map;
	struct shaper_info shaper_info;
};
struct ceetm_chnl_info {
	struct qm_ceetm_channel *channel;
	uint32_t idx;
	struct shaper_info shaper_info;
};

static struct ceetm_chnl_info qm_chnl_info[CDX_CEETM_MAX_CHANNELS];

/* What the hardware was last told, so the test can read it back. */
static struct qm_ceetm_rate lni_cr, lni_er, chnl_cr[CDX_CEETM_MAX_CHANNELS],
			    chnl_er[CDX_CEETM_MAX_CHANNELS];
static unsigned sp_ceetm_mode_calls;

static bool is_max(struct qm_ceetm_rate r)
{
	return r.whole == CEETM_TOKEN_WHOLE_MAXVAL &&
	       r.fraction == CEETM_TOKEN_FRAC_MAXVAL;
}

static int qman_ceetm_lni_set_commit_rate(struct qm_ceetm_lni *lni,
					  const struct qm_ceetm_rate *r, uint32_t limit)
{ (void)lni; (void)limit; lni_cr = *r; return 0; }
static int qman_ceetm_lni_set_excess_rate(struct qm_ceetm_lni *lni,
					  const struct qm_ceetm_rate *r, uint32_t limit)
{ (void)lni; (void)limit; lni_er = *r; return 0; }
static int qman_ceetm_channel_set_commit_rate(struct qm_ceetm_channel *ch,
					      const struct qm_ceetm_rate *r, uint32_t limit)
{ (void)limit; chnl_cr[ch->idx] = *r; return 0; }
static int qman_ceetm_channel_set_excess_rate(struct qm_ceetm_channel *ch,
					      const struct qm_ceetm_rate *r, uint32_t limit)
{ (void)limit; chnl_er[ch->idx] = *r; return 0; }
static int qman_ceetm_sp_set_lni(struct qm_ceetm_sp *sp, struct qm_ceetm_lni *lni)
{ assert(sp && lni); return 0; }
/* The two refusals this file exists to respect. */
static int qman_ceetm_lni_enable_shaper(struct qm_ceetm_lni *lni, int coupled, int oal)
{
	(void)coupled; (void)oal;
	if (lni->shaper_enable)
		return -EINVAL;
	lni->shaper_enable = true;
	return 0;
}
static int qman_ceetm_lni_disable_shaper(struct qm_ceetm_lni *lni)
{
	if (!lni->shaper_enable)
		return -EINVAL;
	lni->shaper_enable = false;
	return 0;
}
static int qman_sp_enable_ceetm_mode(unsigned dcp, unsigned idx)
{ (void)dcp; (void)idx; sp_ceetm_mode_calls++; return 0; }
static void dpa_enable_ceetm(struct net_device *dev) { dev->priv.ceetm_en = true; }

#include "qos_enable_production.inc"

int main(void)
{
	struct qm_ceetm_sp sp = { .idx = 1, .dcp_idx = 0 };
	struct qm_ceetm_lni lni = { .idx = 2, .dcp_idx = 0 };
	struct qm_ceetm_channel channel = { .idx = 0 };
	struct dpa_iface_info iface = { .name = "eth3" };
	struct net_device dev = { 0 };
	struct tQM_context_ctl ctx = {
		.iface_info = &iface, .net_dev = &dev, .lni = &lni, .sp = &sp,
	};
	struct qm_ceetm_rate rate = { .whole = 100, .fraction = 7 };
	unsigned cycle;

	qm_chnl_info[0].channel = &channel;
	qm_chnl_info[0].idx = 0;

	/* Nothing to enable without a channel. */
	assert(ceetm_enable_or_disable_qos(&ctx, 1) == QOS_ENERR_NOT_CONFIGURED);
	assert(!lni.shaper_enable);

	ctx.chnl_map = 1u << 0;
	/* A channel with a rate of its own, and a ceiling above it. */
	qm_chnl_info[0].shaper_info.enable = 1;
	qm_chnl_info[0].shaper_info.bsize = CEETM_DEFA_BSIZE;
	qm_chnl_info[0].shaper_info.token_cr = rate;
	qm_chnl_info[0].shaper_info.token_er = (struct qm_ceetm_rate){ .whole = 50 };

	for (cycle = 0; cycle < 3; cycle++) {
		assert(ceetm_enable_or_disable_qos(&ctx, 1) == CEETM_SUCCESS);
		assert(ctx.qos_enabled && dev.priv.ceetm_en);
		assert(lni.shaper_enable);
		assert(sp_ceetm_mode_calls == cycle + 1);
		/* Enabling again is a no-op, not a second enable of a shaper
		 * the SDK would refuse. */
		assert(ceetm_enable_or_disable_qos(&ctx, 1) == CEETM_SUCCESS);
		assert(sp_ceetm_mode_calls == cycle + 1);

		/* The channel keeps the excess rate it was configured with.
		 * Passing zero here left every class queue on it -- all
		 * excess-eligible by default -- with nothing to send against. */
		assert(chnl_cr[0].whole == rate.whole &&
		       chnl_cr[0].fraction == rate.fraction);
		assert(chnl_er[0].whole == 50 && !is_max(chnl_er[0]));
		/* An LNI's shaper is coupled, so its excess rate is whatever
		 * the committed one leaves unused: zero by construction. */
		assert(!lni_er.whole && !lni_er.fraction);

		assert(ceetm_enable_or_disable_qos(&ctx, 0) == CEETM_SUCCESS);
		assert(!ctx.qos_enabled);
		/* The shaper has to come back off, or the next enable fails
		 * inside setup with the port already half committed. */
		assert(!lni.shaper_enable);
		assert(is_max(chnl_cr[0]) && is_max(chnl_er[0]));
		/* Disabling twice is a no-op, not a second disable. */
		assert(ceetm_enable_or_disable_qos(&ctx, 0) == CEETM_SUCCESS);
		assert(!lni.shaper_enable);
	}

	printf("CEETM enable/disable: %u on-off cycles, shaper symmetric, excess rate preserved\n",
	       cycle);
	return 0;
}
