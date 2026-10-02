/* The control subsystems CDX brings up under ctrl.mutex at load and takes
 * down at unload, compiled from cdx_main.c.
 *
 * Every step can fail, and the module's deinit chain calls the exit whatever
 * the init returned, so the pair has to agree on exactly which subsystems are
 * up: each exit runs once, only for a subsystem whose init succeeded, and in
 * the reverse of the order they came up -- forwarding state before the QoS
 * queues and interfaces it names. */
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define __init
#define ENOMEM 12

enum { TX, QM, IPSEC, MC4, MC6, STEPS };

/* What is up in the stubs' own view, so a double exit or an exit of something
 * that never came up is caught where it happens. */
static bool up[STEPS];
static unsigned fail_at = STEPS;
static int trace[2 * STEPS], traced;

static int step_init(int step)
{
    assert(!up[step]);
    trace[traced++] = step;
    if ((unsigned)step == fail_at)
        return -ENOMEM;
    up[step] = true;
    return 0;
}
static void step_exit(int step)
{
    assert(up[step]);
    trace[traced++] = -1 - step;
    up[step] = false;
}

static int tx_init(void) { return step_init(TX); }
static void tx_exit(void) { step_exit(TX); }
static int qm_init(void) { return step_init(QM); }
static void qm_exit(void) { step_exit(QM); }
#ifdef DPA_IPSEC_OFFLOAD
static int ipsec_init(void) { return step_init(IPSEC); }
static void ipsec_exit(void) { step_exit(IPSEC); }
#endif
static int mc4_init(void) { return step_init(MC4); }
static void mc4_exit(void) { step_exit(MC4); }
static int mc6_init(void) { return step_init(MC6); }
static void mc6_exit(void) { step_exit(MC6); }

#include "cdx_subsys.inc"

static bool built(int step)
{
#ifdef DPA_IPSEC_OFFLOAD
    (void)step;
    return true;
#else
    return step != IPSEC;
#endif
}

static void all_down(void)
{
    for (int s = 0; s < STEPS; s++)
        assert(!up[s]);
}

int main(void)
{
    unsigned points = 0;

    /* Every failure point, and none (point == STEPS). */
    for (unsigned point = 0; point <= STEPS; point++) {
        int expected[2 * STEPS], n = 0, rc;

        if (point < STEPS && !built(point))
            continue;
        fail_at = point;
        traced = 0;
        rc = cdx_subsys_init();
        assert(point < STEPS ? rc == -ENOMEM : rc == 0);

        /* In order, stopping at the one that failed. */
        for (int s = 0; s < STEPS; s++) {
            if (!built(s))
                continue;
            expected[n++] = s;
            if ((unsigned)s == point)
                break;
        }
        /* Then every one that came up, in reverse, and nothing else. */
        for (int s = STEPS - 1; s >= 0; s--)
            if (built(s) && (unsigned)s < point)
                expected[n++] = -1 - s;

        cdx_subsys_exit();
        assert(traced == n);
        assert(!memcmp(trace, expected, n * sizeof(trace[0])));
        all_down();

        /* A second exit finds nothing up and calls nothing. */
        cdx_subsys_exit();
        assert(traced == n);

        /* And the pair starts over cleanly: nothing was left marked up. */
        fail_at = STEPS;
        traced = 0;
        assert(cdx_subsys_init() == 0);
        cdx_subsys_exit();
        all_down();
        points++;
    }
    printf("CDX subsystem fault points passed: %u (%s)\n", points,
#ifdef DPA_IPSEC_OFFLOAD
           "with IPsec"
#else
           "without IPsec"
#endif
          );
    return 0;
}
