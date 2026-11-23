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
/* The channel ceiling, as the production header states it. */
#include "qos_enable_constants.inc"
#define MAX_SCHEDULER_QUEUES		16
#define BIT(n)				(1UL << (n))
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
typedef uint64_t u64;
typedef int64_t ktime_t;
#define IF_TYPE_ETHERNET		1
struct eth_iface_info { int unused; };
struct dpa_iface_info { char name[16]; uint32_t if_flags; struct eth_iface_info eth_info; };
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
/* How many of them the device tree gave, as ceetm_init_channels() read it. */
static uint32_t channel_count = CDX_CEETM_MAX_CHANNELS;
uint32_t ceetm_channel_count(void) { return channel_count; }

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
/* A channel shaper the hardware refuses, for an enable failing half way. */
static bool channel_rate_fails;
static int qman_ceetm_channel_set_commit_rate(struct qm_ceetm_channel *ch,
					      const struct qm_ceetm_rate *r, uint32_t limit)
{ (void)limit; if (channel_rate_fails) return -EIO; chnl_cr[ch->idx] = *r; return 0; }
static int qman_ceetm_channel_set_excess_rate(struct qm_ceetm_channel *ch,
					      const struct qm_ceetm_rate *r, uint32_t limit)
{ (void)limit; chnl_er[ch->idx] = *r; return 0; }
/* The sub-portal's CEETM mode bit, which mapping an LNI to it sets, as the
 * SDK's qman_ceetm_sp_set_lni() does; and whether the senders take class
 * queues. A port in the mode with senders on the plain queues sends nothing. */
static bool sp_mode;
static unsigned net_syncs;
static int qman_ceetm_sp_set_lni(struct qm_ceetm_sp *sp, struct qm_ceetm_lni *lni)
{ assert(sp && lni); sp_mode = true; return 0; }
static unsigned sp_mode_offs;
static int qman_sp_disable_ceetm_mode(unsigned dcp, unsigned idx)
{ (void)dcp; (void)idx; sp_mode = false; sp_mode_offs++; return 0; }

/* The plain queues ceetm_flush_plain() reads: what they hold, how many leave
 * while each poll sleeps -- only with the sub-portal out of CEETM, which is
 * when QMan serves them -- and the read that fails, counted down. On a clock
 * the sleeps advance. */
static u64 plain_frames, plain_per_poll;
static int plain_read_fails_in = -1;
static ktime_t fake_now;
static ktime_t ktime_get(void) { return fake_now; }
static ktime_t ktime_add_us(ktime_t t, u64 us) { return t + (ktime_t)us * 1000; }
static bool ktime_before(ktime_t a, ktime_t b) { return a < b; }
static void usleep_range(unsigned long min, unsigned long max)
{
	(void)max;
	fake_now += (ktime_t)min * 1000;
	if (!sp_mode)
		plain_frames -= plain_frames < plain_per_poll ? plain_frames : plain_per_poll;
}
static bool cdx_port_plain_queued(const struct eth_iface_info *eth, u64 *frames, u64 *bytes)
{
	assert(eth);
	*bytes = 0;
	if (plain_read_fails_in >= 0 && !plain_read_fails_in--)
		return false;
	*frames = plain_frames;
	return true;
}
static int qman_ceetm_lni_is_shaper_enabled(struct qm_ceetm_lni *lni)
{ return lni->shaper_enable; }
static void synchronize_net(void) { net_syncs++; }
/* The two refusals this file exists to respect. */
static bool lni_shaper_fails;
static int qman_ceetm_lni_enable_shaper(struct qm_ceetm_lni *lni, int coupled, int oal)
{
	(void)coupled; (void)oal;
	if (lni->shaper_enable || lni_shaper_fails)
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
{ (void)dcp; (void)idx; sp_ceetm_mode_calls++; sp_mode = true; return 0; }
static void dpa_enable_ceetm(struct net_device *dev)
{
	/* Before the switch: a sender that chose a plain queue after it would
	 * strand its frame there (A458). */
	assert(!sp_mode);
	dev->priv.ceetm_en = true;
}
static void dpa_disable_ceetm(struct net_device *dev) { dev->priv.ceetm_en = false; }

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
		/* The teardown's quiesce takes the sub-portal out of the mode
		 * after its drain (ceetm_quiesce_port()), not this. */
		sp_mode = false;
	}

	/* An enable that fails half way -- the LNI mapped, the sub-portal in
	 * CEETM mode, its shaper on, a channel's shaper refused -- leaves the
	 * port as it found it: the senders on the plain queues, the shaper off
	 * and the plain queues' channel served. It used to leave the mode on
	 * and ceetm_en clear, the port sending nothing, and every retry
	 * refused for the shaper still on. */
	channel_rate_fails = true;
	assert(ceetm_enable_or_disable_qos(&ctx, 1) == QOS_ENERR_IO);
	assert(!ctx.qos_enabled && !dev.priv.ceetm_en);
	assert(!lni.shaper_enable && !sp_mode && net_syncs == 1);
	channel_rate_fails = false;
	assert(ceetm_enable_or_disable_qos(&ctx, 1) == CEETM_SUCCESS);
	assert(ctx.qos_enabled && dev.priv.ceetm_en && lni.shaper_enable && sp_mode);
	assert(ceetm_enable_or_disable_qos(&ctx, 0) == CEETM_SUCCESS);
	sp_mode = false;
	/* And one that fails inside the LNI's setup, the sub-portal already
	 * in the mode and its shaper refused. */
	lni_shaper_fails = true;
	assert(ceetm_enable_or_disable_qos(&ctx, 1) == QOS_ENERR_IO);
	assert(!ctx.qos_enabled && !dev.priv.ceetm_en && !lni.shaper_enable && !sp_mode);
	lni_shaper_fails = false;

	/* ---- what a switch to CEETM left on the plain queues (A458) ---- */
	u64 flushed;
	unsigned offs;
	sp_mode_offs = 0;	/* the unwinds above took it out of the mode */
	/* Nothing to do on a port not in CEETM. */
	plain_frames = 100;
	assert(ceetm_flush_plain(&ctx, &flushed) == 0 && !flushed && !sp_mode_offs);
	assert(ceetm_enable_or_disable_qos(&ctx, 1) == CEETM_SUCCESS && sp_mode);
	/* Not an Ethernet port's record: refused, the mode left alone. */
	assert(ceetm_flush_plain(&ctx, &flushed) == -ENODEV && sp_mode && !sp_mode_offs);
	iface.if_flags = IF_TYPE_ETHERNET;
	/* Empty queues: the mode is not touched. */
	plain_frames = 0;
	assert(ceetm_flush_plain(&ctx, &flushed) == 0 && !flushed && sp_mode && !sp_mode_offs);
	/* A port that sends: out of the mode until they are empty, and back. */
	plain_frames = 100;
	plain_per_poll = 40;
	assert(ceetm_flush_plain(&ctx, &flushed) == 0 && flushed == 100 && sp_mode);
	assert(sp_mode_offs == 1 && !plain_frames);
	/* One that cannot: back in the mode once the bound is up, what is left
	 * said, for a later try. */
	plain_frames = 100;
	plain_per_poll = 0;
	offs = sp_mode_offs;
	assert(ceetm_flush_plain(&ctx, &flushed) == 100 && !flushed && sp_mode);
	assert(sp_mode_offs == offs + 1);
	/* A read failing half way: back in the mode all the same. */
	plain_per_poll = 10;
	plain_read_fails_in = 2;
	assert(ceetm_flush_plain(&ctx, &flushed) == -EIO && sp_mode);
	plain_read_fails_in = -1;
	plain_frames = 0;
	assert(ceetm_enable_or_disable_qos(&ctx, 0) == CEETM_SUCCESS);
	sp_mode = false;

	/* A port's channel can be any the SoC has, the last of the thirty-two
	 * included: both directions program its shaper, as they do channel
	 * zero's. The walk was once bounded by the eight channel shapers NXP's
	 * tree had, so a channel past them kept the shaper the last tree left
	 * on it. */
	assert(CDX_CEETM_MAX_CHANNELS == 32);
	struct qm_ceetm_channel last = { .idx = CDX_CEETM_MAX_CHANNELS - 1 },
				middle = { .idx = 20 };
	qm_chnl_info[CDX_CEETM_MAX_CHANNELS - 1].channel = &last;
	qm_chnl_info[CDX_CEETM_MAX_CHANNELS - 1].idx = CDX_CEETM_MAX_CHANNELS - 1;
	qm_chnl_info[CDX_CEETM_MAX_CHANNELS - 1].shaper_info = qm_chnl_info[0].shaper_info;
	qm_chnl_info[20].channel = &middle;
	qm_chnl_info[20].idx = 20;
	qm_chnl_info[20].shaper_info = qm_chnl_info[0].shaper_info;
	ctx.chnl_map = 1u << 20 | 1u << (CDX_CEETM_MAX_CHANNELS - 1);
	assert(ceetm_enable_or_disable_qos(&ctx, 1) == CEETM_SUCCESS);
	assert(chnl_cr[20].whole == rate.whole && chnl_er[20].whole == 50);
	assert(chnl_cr[CDX_CEETM_MAX_CHANNELS - 1].whole == rate.whole &&
	       chnl_er[CDX_CEETM_MAX_CHANNELS - 1].whole == 50);
	assert(ceetm_enable_or_disable_qos(&ctx, 0) == CEETM_SUCCESS);
	assert(is_max(chnl_cr[20]) && is_max(chnl_er[20]));
	assert(is_max(chnl_cr[CDX_CEETM_MAX_CHANNELS - 1]) &&
	       is_max(chnl_er[CDX_CEETM_MAX_CHANNELS - 1]));
	sp_mode = false;
	/* Only the channels the device tree gave: one past them is not walked
	 * at all, whatever the map says. */
	channel_count = 20;
	chnl_cr[20] = (struct qm_ceetm_rate){ 0 };
	assert(ceetm_enable_or_disable_qos(&ctx, 1) == CEETM_SUCCESS);
	assert(!chnl_cr[20].whole && !chnl_cr[20].fraction);
	assert(ceetm_enable_or_disable_qos(&ctx, 0) == CEETM_SUCCESS);
	channel_count = CDX_CEETM_MAX_CHANNELS;

	printf("CEETM enable/disable: %u on-off cycles, shaper symmetric, excess rate preserved\n",
	       cycle);
	return 0;
}
