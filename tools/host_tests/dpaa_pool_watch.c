/* The receive pool watch's verdicts are production code (dpa_pool_step(),
 * dpa_pool_wants_queued() and dpa_pool_added() in dpaa_eth_pool.c); the
 * readings that feed them -- BMan's count, the ports' discards, the per-CPU
 * counts, the frames waiting for the CPU -- are given here, as the work
 * function reads them on the DK: 640 buffers per port per CPU, five ports,
 * four CPUs, a refill threshold of 80. What a reseed puts in is modelled as
 * dpaa_eth_reseed_bpool() adds it, eight at a time and never past what was
 * asked, or less where a case has an allocation fail.
 *
 * Each case checks what a reading decides: when an episode begins and how
 * many buffers it puts back; that a single dry reading is none, nor an empty
 * pool nothing is lost from, while one frame lost in two dry seconds is; that
 * frames waiting for the CPU and the pool's size bound the reseed; that an
 * idle second does not end an episode, and half the pool does; that a pool
 * left short of half is topped up; that an episode adds at most the pool's
 * size and says once that it is spent; and that a later loss is an episode
 * of its own. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t s64;

#define S32_MAX INT32_MAX
#define min(x, y) ({ __typeof__(x) __x = (x); __typeof__(y) __y = (y); \
		     (void)(&__x == &__y); __x < __y ? __x : __y; })
#define min_t(type, x, y) ({ type __x = (x); type __y = (y); __x < __y ? __x : __y; })
#define max_t(type, x, y) ({ type __x = (x); type __y = (y); __x > __y ? __x : __y; })
#define clamp_t(type, val, lo, hi) min_t(type, max_t(type, val, lo), hi)
#define WRITE_ONCE(x, val) ((x) = (val))

#include "dpaa_pool_watch_production.inc"

#define SIZE (640 * 5 * 4)
#define LOW (80 * 4)

static unsigned int failures;

#define CHECK(cond, ...) do {						\
	if (!(cond)) {							\
		failures++;						\
		printf("FAIL %s:%d: %s: ", __func__, __LINE__, #cond);	\
		printf(__VA_ARGS__);					\
		printf("\n");						\
	}								\
} while (0)

/* One reading, as dpa_pool_watch_fn() takes it: the waiting frames only
 * where the watch reads them. */
static enum dpa_pool_verdict reading(struct dpa_pool_episode *e, u32 free, u32 discards,
				     s64 seeded, u64 queued, u32 *want)
{
	if (!dpa_pool_wants_queued(e, free, SIZE, LOW))
		queued = 0;
	return dpa_pool_step(e, free, discards, seeded, queued, SIZE, LOW, want);
}

/* As dpaa_eth_reseed_bpool(): eight at a time, while eight more fit. */
static u32 reseed(struct dpa_pool_episode *e, u32 want)
{
	u32 added = want - want % DPA_POOL_BATCH;

	dpa_pool_added(e, added);
	return added;
}

static void healthy_pool_is_quiet(void)
{
	struct dpa_pool_episode e = {0};
	u32 want = 99;

	for (int i = 0; i < 5; i++)
		CHECK(reading(&e, SIZE, 0, SIZE, 0, &want) == DPA_POOL_QUIET && !want, "%u", want);
	/* Discards with buffers to spare are some other port's trouble. */
	CHECK(reading(&e, LOW, 50, SIZE, 0, &want) == DPA_POOL_QUIET, "at the threshold");
	CHECK(reading(&e, LOW, 50, SIZE, 0, &want) == DPA_POOL_QUIET, "at the threshold");
	CHECK(e.episodes == 0 && e.reseeded == 0, "%llu %llu",
	      (unsigned long long)e.episodes, (unsigned long long)e.reseeded);
}

static void one_dry_reading_is_none(void)
{
	struct dpa_pool_episode e = {0};
	u32 want;

	CHECK(reading(&e, 0, 30, SIZE, 0, &want) == DPA_POOL_QUIET, "first dry reading");
	CHECK(reading(&e, 5000, 0, SIZE, 0, &want) == DPA_POOL_QUIET, "buffers again");
	CHECK(reading(&e, 0, 30, SIZE, 0, &want) == DPA_POOL_QUIET, "dry again, once");
	CHECK(e.episodes == 0, "%llu", (unsigned long long)e.episodes);
}

/* An empty pool nothing arrives at loses nothing by waiting; the first frame
 * it loses, however sparse the traffic, makes the episode. */
static void sparse_traffic_still_counts(void)
{
	struct dpa_pool_episode e = {0};
	u32 want;

	for (int i = 0; i < 10; i++)
		CHECK(reading(&e, 0, 0, 12720, 0, &want) == DPA_POOL_QUIET, "idle and empty");
	CHECK(reading(&e, 0, 1, 12720, 0, &want) == DPA_POOL_OPEN && want == 12720,
	      "one frame lost, %u", want);

	/* The frame lost in the first of the two dry seconds counts. */
	e = (struct dpa_pool_episode){0};
	CHECK(reading(&e, 0, 1, 12720, 0, &want) == DPA_POOL_QUIET, "first dry reading");
	CHECK(reading(&e, 0, 0, 12720, 0, &want) == DPA_POOL_OPEN, "second, quiet");
}

/* The latch itself: everything lost, the counts as they were. */
static void dry_pool_is_put_back(void)
{
	struct dpa_pool_episode e = {0};
	u32 want;

	CHECK(reading(&e, 0, 159, 12720, 0, &want) == DPA_POOL_QUIET, "first dry reading");
	CHECK(reading(&e, 0, 111, 12720, 0, &want) == DPA_POOL_OPEN, "second dry reading");
	CHECK(want == 12720, "put back what the counts hold, %u", want);
	CHECK(e.episodes == 1, "%llu", (unsigned long long)e.episodes);
	reseed(&e, want);
	CHECK(reading(&e, 12720, 0, 12720, 0, &want) == DPA_POOL_CLOSE && !want, "receiving again");
	CHECK(e.added == 12720 && e.reseeded == 12720, "%llu %llu",
	      (unsigned long long)e.added, (unsigned long long)e.reseeded);
	CHECK(reading(&e, 12720, 0, 12720, 0, &want) == DPA_POOL_QUIET, "over");
}

static void reseed_is_bounded(void)
{
	struct dpa_pool_episode e = {0};
	u32 want;

	/* Frames waiting for the CPU are still in the counts until it takes
	 * them, and hold buffers BMan does not have. */
	reading(&e, 0, 10, 12720, 1000, &want);
	CHECK(reading(&e, 10, 10, 12720, 1000, &want) == DPA_POOL_OPEN && want == 11710,
	      "less what waits, %u", want);

	/* Never past the pool's size, whatever the counts say. */
	e = (struct dpa_pool_episode){0};
	reading(&e, 100, 10, 20000, 0, &want);
	CHECK(reading(&e, 100, 10, 20000, 0, &want) == DPA_POOL_OPEN && want == SIZE - 100,
	      "within the size, %u", want);

	/* Dry with nothing missing by the counts: the buffers are held, not
	 * lost. The episode is counted and said, and nothing added. */
	e = (struct dpa_pool_episode){0};
	reading(&e, 100, 10, 300, 500, &want);
	CHECK(reading(&e, 100, 10, 300, 500, &want) == DPA_POOL_OPEN && want == 0,
	      "nothing missing, %u", want);
	CHECK(e.episodes == 1, "%llu", (unsigned long long)e.episodes);
}

/* An idle second, the pool still empty, does not end the episode, nor a
 * pool past the threshold but short of half its size, which is topped up
 * instead; half the pool does. */
static void episode_ends_at_half_the_pool(void)
{
	struct dpa_pool_episode e = {0};
	enum dpa_pool_verdict v;
	u32 want;

	reading(&e, 0, 10, 12720, 0, &want);
	CHECK(reading(&e, 0, 10, 12720, 0, &want) == DPA_POOL_OPEN, "open");
	reseed(&e, 1000);
	/* All of it lost again, and nothing arriving this second. */
	v = reading(&e, 0, 0, 12720, 0, &want);
	CHECK(v == DPA_POOL_TOPUP && want == SIZE - 1000, "idle second, within the allowance: %d %u",
	      v, want);
	reseed(&e, 1000);
	/* Short of half, with frames waiting for the CPU: topped up less
	 * those. */
	v = reading(&e, 2000, 0, 12720, 100, &want);
	CHECK(v == DPA_POOL_TOPUP && want == 12720 - 2000 - 100, "short of half: %d %u", v, want);
	CHECK(reseed(&e, want) == 10616, "eight at a time");
	CHECK(reading(&e, SIZE / 2, 0, 12720, 0, &want) == DPA_POOL_CLOSE, "half the pool");
	CHECK(e.episodes == 1 && e.added == 1000 + 1000 + 10616, "%llu %llu",
	      (unsigned long long)e.episodes, (unsigned long long)e.added);
}

/* Buffers lost as fast as they go back: the episode adds the pool's size in
 * all and says once that it is spent; a later loss is an episode of its
 * own, with its own allowance. */
static void episode_adds_at_most_the_size(void)
{
	struct dpa_pool_episode e = {0};
	enum dpa_pool_verdict v;
	unsigned int spent = 0;
	u32 want;

	reading(&e, 0, 10, 12720, 0, &want);
	CHECK(reading(&e, 0, 10, 12720, 0, &want) == DPA_POOL_OPEN && want == 12720, "%u", want);
	reseed(&e, want);
	for (int i = 0; i < 10; i++) {
		v = reading(&e, 0, 10, 12720, 0, &want);
		CHECK(v == DPA_POOL_TOPUP || v == DPA_POOL_SPENT || v == DPA_POOL_QUIET, "%d", v);
		CHECK(v == DPA_POOL_TOPUP || !want, "%d %u", v, want);
		spent += v == DPA_POOL_SPENT;
		reseed(&e, want);
	}
	CHECK(e.added == SIZE && e.reseeded == SIZE, "the episode added %llu",
	      (unsigned long long)e.added);
	CHECK(spent == 1, "said %u times", spent);
	CHECK(reading(&e, SIZE / 2, 0, 12720, 0, &want) == DPA_POOL_CLOSE, "over");
	reading(&e, 0, 10, 12720, 0, &want);
	CHECK(reading(&e, 0, 10, 12720, 0, &want) == DPA_POOL_OPEN && want == 12720, "%u", want);
	CHECK(e.episodes == 2 && e.allowance == SIZE, "%llu %u",
	      (unsigned long long)e.episodes, e.allowance);
}

/* A reseed short of what was asked -- an allocation that failed, or eight
 * at a time leaving a few over -- is made up at the next reading, and an
 * allowance left too small for a batch is spent. */
static void short_reseed_is_made_up(void)
{
	struct dpa_pool_episode e = {0};
	u32 want;

	reading(&e, 0, 10, 12720, 0, &want);
	CHECK(reading(&e, 0, 10, 12720, 0, &want) == DPA_POOL_OPEN && want == 12720, "%u", want);
	dpa_pool_added(&e, 0);
	CHECK(reading(&e, 0, 10, 12720, 0, &want) == DPA_POOL_TOPUP && want == 12720, "%u", want);
	dpa_pool_added(&e, 3000);
	/* Receiving again, but on less than half the pool. */
	CHECK(reading(&e, 3000, 0, 12720, 0, &want) == DPA_POOL_TOPUP && want == 9720, "%u", want);
	reseed(&e, want);
	CHECK(reading(&e, 12720, 0, 12720, 0, &want) == DPA_POOL_CLOSE, "receiving again");
	CHECK(e.added == 12720, "%llu", (unsigned long long)e.added);

	/* Five left, less than a batch: spent, not stuck. */
	e = (struct dpa_pool_episode){0};
	reading(&e, 0, 10, SIZE, 0, &want);
	CHECK(reading(&e, 0, 10, SIZE, 0, &want) == DPA_POOL_OPEN && want == SIZE, "%u", want);
	dpa_pool_added(&e, SIZE - 85);
	CHECK(reading(&e, 0, 10, SIZE, 0, &want) == DPA_POOL_TOPUP && want == 85, "%u", want);
	CHECK(reseed(&e, want) == 80, "eight at a time");
	CHECK(reading(&e, 0, 10, SIZE, 0, &want) == DPA_POOL_SPENT && want == 0, "%u", want);
	CHECK(reading(&e, 0, 10, SIZE, 0, &want) == DPA_POOL_QUIET, "said once");
}

int main(void)
{
	healthy_pool_is_quiet();
	one_dry_reading_is_none();
	sparse_traffic_still_counts();
	dry_pool_is_put_back();
	reseed_is_bounded();
	episode_ends_at_half_the_pool();
	episode_adds_at_most_the_size();
	short_reseed_is_made_up();
	if (failures) {
		printf("%u failures\n", failures);
		return 1;
	}
	printf("pool watch: every case holds\n");
	return 0;
}
