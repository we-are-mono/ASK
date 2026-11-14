/* Execute production QMan management-command code -- a portal's command and
 * answer bookkeeping, the frame-queue and work-queue queries, and the host
 * command's timeout description -- against a modelled QMan that can stop
 * answering, and answer late. Only the portal's registers, the CPU, time and
 * printing are substituted. */
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef void *t_Handle;

#define register
#define likely(x) (x)
#define unlikely(x) (x)
#define __maybe_unused __attribute__((unused))
#define READ_ONCE(x) (x)
#define DPA_ASSERT(x) ((void)0)
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define max(a, b) ((a) > (b) ? (a) : (b))
/* The model keeps every field in CPU order. */
#define be16_to_cpu(x) (x)
#define be24_to_cpu(x) (x)
#define be32_to_cpu(x) (x)
#define cpu_to_be16(x) (x)
#define cpu_to_be32(x) (x)
#define lwsync() ((void)0)
#define dcbf(p) ((void)(p))
#define dcbit_ro(p) ((void)(p))
#define pr_err(...) ((void)0)
#define mcr_result_str(res) "failed"

#include "qman_defines.inc"

struct qm_mcr_queryfq_np {
    u8 state;
    u32 fqd_link;
    u16 odp_seq, orp_nesn, orp_ea_hseq, orp_ea_tseq;
    u32 orp_ea_hptr, orp_ea_tptr, pfdr_hptr, pfdr_tptr;
    u16 ics_surp;
    u32 byte_cnt, frm_cnt;
    u16 ra1_sfdr, ra2_sfdr, od1_sfdr, od2_sfdr, od3_sfdr;
};
struct qm_mcr_querywq {
    struct { u16 id; } channel;
    u32 wq_len[8];
};
struct qm_mc_command {
    u8 __dont_write_directly__verb;
    union {
        struct { u32 fqid; } queryfq;
        struct { struct { u16 id; } channel; } querywq;
    };
};
struct qm_mc_result {
    u8 verb;
    u8 result;
    union {
        struct qm_mcr_queryfq_np queryfq_np;
        struct qm_mcr_querywq querywq;
    };
};
struct qm_eqcr_entry { u8 bytes[64]; };
struct qm_addr { int unused; };
struct qm_eqcr { struct qm_eqcr_entry *cursor; };
#include "qman_mc_struct.inc"
struct qm_portal { struct qm_addr addr; struct qm_eqcr eqcr; struct qm_mc mc; int cpu; };
/* A CPU sharing another's portal has no config, nor a ring of its own. */
struct qman_portal { struct qm_portal p; const void *config; };
struct qman_fq { u32 fqid; };

#define NCPU 4
enum { QM_REG_EQCR_CI_CINH, QM_REG_DQRR_PI_CINH, QM_REG_DQRR_CI_CINH, QM_REGS };

/* What each portal's QMan does: answers the command its valid bit marks as
 * new, into the slot after the last answer, while it answers at all. */
static struct model {
    bool answering;
    u8 next_vbit, next_slot;
    unsigned executed;
    u32 regs[QM_REGS];
} model[NCPU];
static struct qm_mc_command cr[NCPU];
static struct qm_mc_result rr[NCPU][2];
static struct qm_eqcr_entry ring[NCPU][QM_EQCR_SIZE] __attribute__((aligned(64 * QM_EQCR_SIZE)));
static struct qman_portal portals[NCPU];
static struct qman_portal *affine_portals[NCPU];
static u32 frames_by_fqid[0x200];
static int current_cpu;
static bool irqs_off, preempt_off;
static unsigned long spins;
static u64 now_us;

static void model_step(void)
{
    for (int c = 0; c < NCPU; c++) {
        struct model *m = &model[c];
        u8 verb = cr[c].__dont_write_directly__verb;
        struct qm_mc_result *res = &rr[c][m->next_slot];

        if (!m->answering || !verb || (verb & QM_MCC_VERB_VBIT) != m->next_vbit)
            continue;
        memset(res, 0, sizeof(*res));
        /* The slot not answered into reads zero, as the inactive one does. */
        rr[c][m->next_slot ^ 1].verb = 0;
        res->verb = verb & QM_MCC_VERB_MASK;
        res->result = QM_MCR_RESULT_OK;
        switch (verb & QM_MCC_VERB_MASK) {
        case QM_MCC_VERB_QUERYFQ_NP:
            res->queryfq_np.frm_cnt = frames_by_fqid[cr[c].queryfq.fqid];
            break;
        case QM_MCR_VERB_QUERYWQ:
        case QM_MCR_VERB_QUERYWQ_DEDICATED:
            res->querywq.channel.id = cr[c].querywq.channel.id;
            for (unsigned i = 0; i < 8; i++)
                res->querywq.wq_len[i] = i + 1;
            break;
        default:
            assert(!"unmodelled management command");
        }
        m->executed++;
        m->next_slot ^= 1;
        m->next_vbit ^= QM_MCC_VERB_VBIT;
    }
}

static u8 __raw_readb(const u8 *p)
{
    model_step();
    return *(const volatile u8 *)p;
}

/* A wait QMan alone can end, and here never does. */
static void cpu_relax(void)
{
    if (++spins > 10000000) {
        fprintf(stderr, "a management command waited for QMan without bound%s\n",
                irqs_off ? ", with interrupts masked" : "");
        abort();
    }
}

static void udelay(unsigned long us) { now_us += us; }

/* linux/iopoll.h, on the modelled clock. */
#define read_poll_timeout_atomic(op, val, cond, delay_us, timeout_us, delay_before_read, args...) \
    ({ \
        u64 __timeout = now_us + (timeout_us); \
        for (;;) { \
            (val) = op(args); \
            if (cond) \
                break; \
            if (now_us > __timeout) { \
                (val) = op(args); \
                break; \
            } \
            udelay(delay_us); \
        } \
        (cond) ? 0 : -ETIMEDOUT; \
    })

#define qm_in(reg) (model[portal->cpu].regs[QM_REG_##reg])

static struct qman_portal *get_affine_portal(void) { return affine_portals[current_cpu]; }
static void put_affine_portal(void) { }
#define PORTAL_IRQ_LOCK(p, flags) do { (void)(flags); assert(!irqs_off); irqs_off = true; } while (0)
#define PORTAL_IRQ_UNLOCK(p, flags) do { (void)(flags); assert(irqs_off); irqs_off = false; } while (0)
static int get_cpu(void) { assert(!preempt_off); preempt_off = true; return current_cpu; }
static void put_cpu(void) { assert(preempt_off); preempt_off = false; }
static int dummy_mask;
#define qman_affine_cpus() (&dummy_mask)
#define cpumask_first(mask) ((void)(mask), 0)
#define for_each_online_cpu(cpu) for ((cpu) = 0; (cpu) < NCPU; (cpu)++)

static int scnprintf(char *buf, size_t size, const char *fmt, ...)
{
    va_list ap;
    int n;

    if (!size)
        return 0;
    va_start(ap, fmt);
    n = vsnprintf(buf, size, fmt, ap);
    va_end(ap);
    return n < 0 ? 0 : (size_t)n >= size ? (int)size - 1 : n;
}

#include "qman_mc_low.inc"
#include "qman_mc_high.inc"

typedef struct {
    struct qman_fq *hc_tx_fq, *hc_tx_conf_fq, *hc_tx_err_fq;
    u16 hcCh;
} t_LnxWrpFmDev;
#include "qman_mc_describe.inc"

static struct qman_fq command_fq = { 0x100 }, answer_fq = { 0x101 }, error_fq = { 0x102 };
static t_LnxWrpFmDev device = { &command_fq, &answer_fq, &error_fq, 0x9 };

static void setup(void)
{
    memset(model, 0, sizeof(model));
    memset(cr, 0, sizeof(cr));
    memset(rr, 0, sizeof(rr));
    memset(portals, 0, sizeof(portals));
    for (int c = 0; c < NCPU; c++) {
        struct qm_portal *p = &portals[c].p;

        /* qm_mc_init() on a portal that has answered nothing since reset. */
        p->cpu = c;
        p->mc.cr = &cr[c];
        p->mc.rr = rr[c];
        p->mc.rridx = 1;
        p->mc.vbit = QM_MCC_VERB_VBIT;
        p->eqcr.cursor = &ring[c][0];
        portals[c].config = &portals[c];
        model[c] =(struct model){ .answering = true, .next_vbit = QM_MCC_VERB_VBIT, .next_slot = 1 };
        affine_portals[c] = &portals[c];
    }
    memset(frames_by_fqid, 0, sizeof(frames_by_fqid));
    spins = 0;
}

static void describe(char *buf, size_t size)
{
    memset(buf, 0, size);
    QmDescribeCB(&device, buf, size);
    assert(!irqs_off && !preempt_off);
}

static void expect(const char *got, const char *want)
{
    if (strcmp(got, want)) {
        fprintf(stderr, "got:  %s\nwant: %s\n", got, want);
        abort();
    }
}

int main(void)
{
    char buf[256];
    struct qm_mcr_queryfq_np np;
    struct qm_mc_command before;
    u64 start;

    /* QMan answering: every queue, the channel, and both rings described. */
    setup();
    current_cpu = 2;
    frames_by_fqid[0x101] = 1;
    model[0].regs[QM_REG_DQRR_PI_CINH] = 5;
    model[0].regs[QM_REG_DQRR_CI_CINH] = 4;
    portals[1].p.eqcr.cursor = &ring[1][3];
    model[1].regs[QM_REG_EQCR_CI_CINH] = 1;
    describe(buf, sizeof(buf));
    expect(buf, "frames queued: command 0, answer 1, error 0; channel 0x9 wq0-7: 1 2 3 4 5 6 7 8; "
                "its portal holds 1 unprocessed; enqueue rings hold 0 2 0 0");
    assert(model[2].executed == 4 && !portals[2].p.mc.abandoned);
    /* A CPU sharing another's portal reads as having none. */
    portals[3].config = NULL;
    assert(qman_affine_portal_eqcr_fill(3) == -ENODEV &&
           qman_affine_portal_dqrr_pending(3) == -ENODEV);
    describe(buf, sizeof(buf));
    expect(buf, "frames queued: command 0, answer 1, error 0; channel 0x9 wq0-7: 1 2 3 4 5 6 7 8; "
                "its portal holds 1 unprocessed; enqueue rings hold 0 2 0 -19");

    /* QMan not answering this CPU's portal: the description says so within
     * its bound, and asks nothing after the query that went unanswered. */
    setup();
    current_cpu = 2;
    frames_by_fqid[0x100] = 7;
    frames_by_fqid[0x101] = 1;
    model[2].answering = false;
    portals[2].p.eqcr.cursor = &ring[2][1];
    start = now_us;
    describe(buf, sizeof(buf));
    expect(buf, "frames queued: command -1, answer -1, error -1; QMan did not answer cpu 2's "
                "portal in 10000 us; its portal holds 0 unprocessed; enqueue rings hold 0 0 1 0");
    assert(now_us - start <= HC_DESCRIBE_TIMEOUT_US + 2 * QM_MC_DELAY_US);
    assert(portals[2].p.mc.abandoned && cr[2].queryfq.fqid == 0x100);
    assert((cr[2].__dont_write_directly__verb & QM_MCC_VERB_MASK) == QM_MCC_VERB_QUERYFQ_NP);

    /* Still unanswered: a bounded query gives up without writing a command,
     * which QMan would not see and whose answer would be the old one. */
    memcpy(&before, &cr[2], sizeof(before));
    start = now_us;
    assert(qman_query_fq_np_timeout(&answer_fq, &np, 500) == -ETIMEDOUT);
    assert(!memcmp(&before, &cr[2], sizeof(before)) && model[2].executed == 0);
    assert(now_us - start <= 500 + 2 * QM_MC_DELAY_US);
    assert(!irqs_off);

    /* The late answer comes: the next command, of any kind, takes it first
     * and is then answered itself -- its own count, not the abandoned one's. */
    model[2].answering = true;
    memset(&np, 0, sizeof(np));
    assert(qman_query_fq_np(&answer_fq, &np) == 0);
    assert(np.frm_cnt == 1 && model[2].executed == 2 && !portals[2].p.mc.abandoned);
    describe(buf, sizeof(buf));
    expect(buf, "frames queued: command 7, answer 1, error 0; channel 0x9 wq0-7: 1 2 3 4 5 6 7 8; "
                "its portal holds 0 unprocessed; enqueue rings hold 0 0 1 0");

    /* The other portals never took part. */
    for (int c = 0; c < NCPU; c++)
        assert(c == 2 || model[c].executed == 0);
    puts("ok");
    return 0;
}
