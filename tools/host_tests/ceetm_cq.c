/* Exercise the SDK CQ management command and ownership of the last frame. */
#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint8_t u8;
typedef uint16_t u16;
#define cpu_to_be16 htobe16
#define be64_to_cpu be64toh
#define be32_to_cpu be32toh
#define __maybe_unused
#define EXPORT_SYMBOL(name)
#define DPA_ASSERT assert
#define pr_err(...) ((void)0)
#define cpu_relax() ((void)0)
#define QM_CEETM_VERB_CQ_PEEK_POP_XFDRREAD 0x7c
#define QM_MCR_VERB_MASK 0x7f
#define QM_MCR_RESULT_OK 0xf0
struct qm_fd { uint64_t opaque_addr; uint32_t opaque, status; };
struct qm_ceetm_channel { unsigned idx, dcp_idx; };
struct qm_ceetm_cq { unsigned idx; struct qm_ceetm_channel *parent; };
struct qm_mcr_ceetm_cq_peek_pop_xsfdrread {
    u8 verb, result, stat;
    u16 dctidx;
    struct qm_fd fd;
};
struct qm_mc_command { struct { u16 cqid, xsfdr; u8 ct, dcpid; } cq_ppxr; };
struct qm_mc_result {
    union {
        struct { u8 verb, result; };
        struct qm_mcr_ceetm_cq_peek_pop_xsfdrread cq_ppxr;
    };
};
struct qman_portal { int p; };
static struct qman_portal portal;
static struct qm_mc_command command;
static struct qm_mc_result result;
static unsigned pins;
static bool locked;
static u8 next_stat, next_result = QM_MCR_RESULT_OK;
static struct qm_fd next_fd;
static struct qman_portal *get_affine_portal(void) { assert(!pins++); return &portal; }
static void put_affine_portal(void) { assert(pins == 1 && !locked); pins--; }
#define PORTAL_IRQ_LOCK(p, flags) do { assert(!locked); locked = true; (flags) = 0; } while (0)
#define PORTAL_IRQ_UNLOCK(p, flags) do { \
    assert(locked); locked = false; \
    /* Another management command can overwrite RR as soon as we unlock. */ \
    memset(&result, 0xa5, sizeof(result)); \
} while (0)
static struct qm_mc_command *qm_mc_start(int *p)
{ assert(locked && p == &portal.p); memset(&command, 0, sizeof(command)); return &command; }
static void qm_mc_commit(int *p, u8 verb)
{
    assert(locked && p == &portal.p && verb == QM_CEETM_VERB_CQ_PEEK_POP_XFDRREAD);
    assert(command.cq_ppxr.dcpid == 1);
    if (command.cq_ppxr.ct == 2)
        assert(command.cq_ppxr.xsfdr == htobe16(0x345));
    else
        assert(command.cq_ppxr.cqid == htobe16((37 << 4) | 11));
    result.cq_ppxr = (struct qm_mcr_ceetm_cq_peek_pop_xsfdrread){
        .verb = verb, .result = next_result, .stat = next_stat, .fd = next_fd};
}
static struct qm_mc_result *qm_mc_result(int *p)
{ assert(locked && p == &portal.p); return &result; }
#include "cq_production.inc"

int main(void)
{
    struct qm_ceetm_channel ch = {.idx = 37, .dcp_idx = 1};
    struct qm_ceetm_cq cq = {.idx = 11, .parent = &ch};
    const struct qm_fd expected = {.opaque_addr = 0x123456789abcdefULL,
                                  .opaque = 0xaabbccdd, .status = 0x12345678};
    next_fd = (struct qm_fd){.opaque_addr = htobe64(expected.opaque_addr),
                            .opaque = htobe32(expected.opaque), .status = htobe32(expected.status)};
    struct qm_fd fd = {0}, empty = {0};
    next_stat = 4;
    assert(qman_ceetm_cq_pop(&cq, &fd) == -EAGAIN && !memcmp(&fd, &empty, sizeof(fd)));
    for (unsigned stat = 1; stat <= 3; stat += 2) {
        next_stat = stat;
        assert(qman_ceetm_cq_pop(&cq, &fd) == 1);
        assert(!memcmp(&fd, &expected, sizeof(fd)));
    }
    fd = empty; next_stat = 2;
    assert(qman_ceetm_cq_pop(&cq, &fd) == 0 && !memcmp(&fd, &empty, sizeof(fd)));
    next_result = 0xff;
    assert(qman_ceetm_cq_pop(&cq, &fd) == -EIO && !memcmp(&fd, &empty, sizeof(fd)));
    next_result = QM_MCR_RESULT_OK;
    struct qm_mcr_ceetm_cq_peek_pop_xsfdrread ppxr;
    assert(qman_ceetm_cq_peek_pop_xsfdrread(&cq, 2, 0x345, &ppxr) == 0);
    assert(!pins && !locked);
    puts("CEETM CQ: command endianness, portal lifetime, prefetch, last frame and errors passed");
    return 0;
}
