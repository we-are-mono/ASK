/* The two VLAN header manipulations and the description they read, compiled
 * from CDX against the shipped SDK header. What this pins down is what a
 * hardware run cannot show cheaply: which record each tag of a flow-described
 * stack counts into, in which order the ucode sees them, and that a stack with
 * a record missing names none at all rather than aiming one tag's counter
 * update at the unallocated offset zero, which belongs to another interface. */
#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define cpu_to_be32(x) __builtin_bswap32((uint32_t)(x))
#define cpu_to_be16(x) __builtin_bswap16((uint16_t)(x))
#else
#define cpu_to_be32(x) ((uint32_t)(x))
#define cpu_to_be16(x) ((uint16_t)(x))
#endif
#define be32_to_cpu(x) cpu_to_be32(x)
#define be16_to_cpu(x) cpu_to_be16(x)
#define MAX_OPCODES 16
#define SUCCESS 0
#define FAILURE -1
#define RX_IFSTATS 0
#define IF_TYPE_VLAN 2
#define ETHERTYPE_PPPOE 0x8864
#define ETHER_ADDR_LEN 6
#define DPA_ERROR(...) ((void)0)
#define DPA_INFO(...) ((void)0)
typedef uint8_t U8;
typedef uint16_t U16;
typedef uint32_t U32;
#define ALIGN(x, a) (((x) + (a) - 1) & ~((a) - 1))

#include "vlan_hm_types.inc"

struct ins_entry_info {
    unsigned opc_count, param_size, eth_type, flags, sec_tag;
    uint8_t *paramptr, *opcptr;
    uint32_t *vlan_hdrs;
    struct dpa_l2hdr_info l2_info;
    /* An encapsulation naming a tunnel reaches past the L2 half into this
     * one, so the description apply_l2_encap() fills spans both. */
    struct dpa_l3hdr_info l3_info;
};

static uint32_t stats_base = 0x1000;
static unsigned lookups;
static int port_unregistered;
static uint32_t get_logical_ifstats_base(void) { return stats_base; }
/* Whether the ingress is a registered port, which never has VLAN records of
 * its own. Only a strip with no description of its own asks: a flow that
 * described a stack names its records, and never needs the port. */
static int dpa_get_num_vlan_iface_stats_entries(unsigned iif, unsigned underlying, uint32_t *n)
{
    lookups++;
    assert(iif == 5 && underlying == 5);
    *n = 0;
    return port_unregistered ? FAILURE : SUCCESS;
}

static char display_log[512];
static void printk(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    size_t used = strlen(display_log);
    vsnprintf(display_log + used, sizeof(display_log) - used, fmt, ap);
    va_end(ap);
}
static void disp_buf(const void *buf, unsigned size) { }
#define htonl(x) cpu_to_be32(x)

#include "vlan_hm.inc"

/* The parameter area, word aligned as the firmware's entry is: the encoder
 * writes the VLAN headers through a uint32_t pointer. One guard word before
 * the parameters and poison after them show what a call touched. */
static union { uint32_t words[12]; uint8_t bytes[48]; } area;
#define PARAMS (area.bytes + 4)

static void poison(void) { memset(&area, 0xa5, sizeof(area)); }

static uint32_t word_at(const uint8_t *bytes)
{
    uint32_t word;

    memcpy(&word, bytes, sizeof(word));
    return be32_to_cpu(word);
}

static void guards_intact(const uint8_t *end)
{
    for (unsigned i = 0; i < 4; i++)
        assert(area.bytes[i] == 0xa5);
    for (const uint8_t *p = end; p < area.bytes + sizeof(area); p++)
        assert(*p == 0xa5);
}

/* A description of `count` egress tags, innermost first as dpa_l2hdr_info
 * orders them, each naming the record index given (zero for none). */
static struct ins_entry_info egress(size_t size, unsigned count, const uint16_t *tci,
                                    const uint8_t *indices, int flow, uint8_t *opcode)
{
    struct ins_entry_info info = {
        .opc_count = 1, .param_size = size, .paramptr = PARAMS, .opcptr = opcode,
        .eth_type = 0x0800,
    };

    poison();
    opcode[0] = opcode[1] = 0xa5;
    info.l2_info.num_egress_vlan_hdrs = count;
    info.l2_info.vlan_flow_ifstats = flow;
    for (unsigned i = 0; i < count; i++) {
        info.l2_info.egress_vlan_hdrs[i].tpid = 0x8100;
        info.l2_info.egress_vlan_hdrs[i].tci = tci[i];
        info.l2_info.vlan_stats_offsets[i] = indices ? indices[i] : 0;
    }
    return info;
}

static struct ins_entry_info ingress(size_t size, unsigned count, const uint16_t *tci,
                                     const uint8_t *indices, int flow, uint8_t *opcode)
{
    struct ins_entry_info info = {
        .opc_count = 1, .param_size = size, .paramptr = PARAMS, .opcptr = opcode,
    };

    poison();
    /* The strip fills only the VIDs it validates and ORs its flags in, so it
     * relies on the entry arriving zeroed, as the classifier's does. Model
     * that for the fixed part of its parameters and poison the rest. */
    memset(PARAMS, 0, sizeof(struct en_ehash_strip_all_vlan_hdrs));
    opcode[0] = opcode[1] = 0xa5;
    info.l2_info.num_ingress_vlan_hdrs = count;
    info.l2_info.vlan_present = !!count;
    info.l2_info.vlan_flow_ifstats = flow;
    for (unsigned i = 0; i < count; i++) {
        info.l2_info.ingress_vlan_hdrs[i].tpid = 0x8100;
        info.l2_info.ingress_vlan_hdrs[i].tci = tci[i];
        info.l2_info.ingress_vlan_stats_offsets[i] = indices ? indices[i] : 0;
    }
    return info;
}

static const struct en_ehash_strip_all_vlan_hdrs *strip_params(void)
{
    return (const struct en_ehash_strip_all_vlan_hdrs *)PARAMS;
}

int main(void)
{
    /* Innermost first, as the description orders them: 300 inside 100. */
    const uint16_t qinq[] = { 300, 100 }, single[] = { 100 }, priority[] = { 0 };
    const uint8_t both[] = { 0x0d, 0x0f }, one[] = { 0x0d }, partial[] = { 0x0d, 0 };
    const uint8_t none[] = { 0, 0 };
    uint8_t opcode[2];
    struct ins_entry_info info;

    assert(sizeof(struct en_ehash_insert_vlan_hdr) == 4);
    assert(sizeof(struct en_ehash_strip_all_vlan_hdrs) == 12);
    assert(sizeof(struct en_ehash_stats) == 16);

    /* ---- the insert -----------------------------------------------------
     *
     * One tag with a record: the pointer goes straight into the word, in
     * plain-pool units of sixteen bytes from the base. */
    info = egress(8, 1, single, one, 1, opcode);
    assert(create_vlan_ins_hm(&info) == SUCCESS);
    assert(word_at(PARAMS) == ((1u << 24) | (stats_base + 0x0d * 16)));
    assert(word_at(PARAMS + 4) == ((100u << 16) | 0x0800));
    assert(opcode[0] == INSERT_VLAN_HDR && opcode[1] == 0xa5 && info.opc_count == 2);
    assert(info.paramptr == PARAMS + 8 && info.param_size == 0);
    assert(info.eth_type == 0x8100);
    guards_intact(PARAMS + 8);
    assert(!lookups);
    display_log[0] = 0;
    assert(display_vlanhdr_insert_opc(PARAMS) == PARAMS + 8);

    /* One tag and no record: the header is still inserted, and the word
     * carries the count with a null pointer -- the statistics-disabled
     * encoding, not record zero. */
    info = egress(8, 1, single, none, 1, opcode);
    assert(create_vlan_ins_hm(&info) == SUCCESS);
    assert(word_at(PARAMS) == (1u << 24));
    assert(word_at(PARAMS + 4) == ((100u << 16) | 0x0800));
    assert(info.paramptr == PARAMS + 8 && info.param_size == 0);
    guards_intact(PARAMS + 8);

    /* Two tags, both with records: the list form. The headers are written
     * outermost first, each followed by the type of what comes next -- the
     * inner TPID after the outer tag, IP after the inner. The records are
     * listed the other way round, innermost first, because the ucode inserts
     * the innermost header first and counts the k-th record after the k-th
     * insertion: the inner device's record then sees the frame with only its
     * own tag on, and the outer's sees both, as their own counters would. The
     * list is padded to a word. */
    info = egress(16, 2, qinq, both, 1, opcode);
    assert(create_vlan_ins_hm(&info) == SUCCESS);
    assert(word_at(PARAMS) == ((2u << 24) | stats_base));
    assert(word_at(PARAMS + 4) == ((100u << 16) | 0x8100));   /* outer, then the inner tag */
    assert(word_at(PARAMS + 8) == ((300u << 16) | 0x0800));   /* inner, then IP */
    assert(PARAMS[12] == 0x0d && PARAMS[13] == 0x0f);         /* inner's record, then outer's */
    assert(info.eth_type == 0x8100);
    assert(info.paramptr == PARAMS + 16 && info.param_size == 0);
    guards_intact(PARAMS + 16);
    /* The vendor's display helper reads the same list; its own size
     * arithmetic ignores the word alignment the encoder applies, so only
     * its walk of the parameters is exercised here, not its return. */
    display_log[0] = 0;
    display_vlanhdr_insert_opc(PARAMS);
    assert(strstr(display_log, "stats offset 13::") && strstr(display_log, "stats offset 15::"));

    /* Two tags with one record missing: none at all, because the list form
     * has no way to skip a tag and zero there is another owner's record. */
    info = egress(16, 2, qinq, partial, 1, opcode);
    assert(create_vlan_ins_hm(&info) == SUCCESS);
    assert(word_at(PARAMS) == (2u << 24));
    assert(info.paramptr == PARAMS + 12 && info.param_size == 4);
    guards_intact(PARAMS + 12);

    /* A priority tag (VID 0) never counts, records or not. */
    info = egress(8, 1, priority, one, 1, opcode);
    assert(create_vlan_ins_hm(&info) == SUCCESS);
    assert(word_at(PARAMS) == (1u << 24));

    /* Refusals leave every cursor untouched and write no opcode. The vendor's
     * insert lays the headers down before it sizes the record list, so a
     * list that does not fit leaves them behind in an entry the caller then
     * discards; nothing past them is touched. */
    info = egress(15, 2, qinq, both, 1, opcode);
    assert(create_vlan_ins_hm(&info) == FAILURE);
    assert(info.opc_count == 1 && info.param_size == 15 && info.paramptr == PARAMS);
    assert(opcode[0] == 0xa5 && word_at(PARAMS) == 0xa5a5a5a5);
    guards_intact(PARAMS + 12);
    info = egress(16, 2, qinq, both, 1, opcode);
    info.opc_count = MAX_OPCODES;
    assert(create_vlan_ins_hm(&info) == FAILURE);
    guards_intact(PARAMS);
    assert(!lookups);

    /* ---- the strip ------------------------------------------------------
     *
     * One tag with a record: count one, pointer direct, and no lookup at all:
     * the flow named the record, so there is nothing to ask the port. */
    info = ingress(12, 1, single, one, 1, opcode);
    assert(insert_remove_vlan_hm(&info, 5, 5) == SUCCESS);
    assert(!lookups);
    assert(be16_to_cpu(strip_params()->vlan_id[0]) == 100 && !strip_params()->vlan_id[1]);
    assert(word_at(PARAMS + 4) == ((1u << 24) | (stats_base + 0x0d * 16)));
    assert(!strip_params()->op_flags);
    assert(opcode[0] == STRIP_ALL_VLAN_HDRS && opcode[1] == 0xa5 && info.opc_count == 2);
    assert(info.paramptr == PARAMS + 12 && info.param_size == 0);
    guards_intact(PARAMS + 12);
    display_log[0] = 0;
    assert(display_strip_allvlan_hdr_opc(PARAMS) == PARAMS + 12);

    /* Two tags with records: the list form, outermost first like the VIDs it
     * sits beside, padded to a word; the two bytes of padding are part of the
     * parameter size. */
    info = ingress(16, 2, qinq, both, 1, opcode);
    assert(insert_remove_vlan_hm(&info, 5, 5) == SUCCESS);
    assert(!lookups);
    assert(be16_to_cpu(strip_params()->vlan_id[0]) == 100);
    assert(be16_to_cpu(strip_params()->vlan_id[1]) == 300);
    assert(word_at(PARAMS + 4) == ((2u << 30) | (2u << 24) | stats_base));
    assert(strip_params()->stats_offsets[0] == 0x0f && strip_params()->stats_offsets[1] == 0x0d);
    assert(info.paramptr == PARAMS + 16 && info.param_size == 0);
    guards_intact(PARAMS + 16);
    display_log[0] = 0;
    assert(display_strip_allvlan_hdr_opc(PARAMS) == PARAMS + 16);

    /* A record missing, or no tags at all: the disabled encoding, a zero word. */
    info = ingress(16, 2, qinq, partial, 1, opcode);
    assert(insert_remove_vlan_hm(&info, 5, 5) == SUCCESS);
    assert(word_at(PARAMS + 4) == 0);
    assert(info.paramptr == PARAMS + 12 && info.param_size == 4);
    guards_intact(PARAMS + 12);
    info = ingress(12, 0, NULL, NULL, 1, opcode);
    assert(insert_remove_vlan_hm(&info, 5, 5) == SUCCESS);
    assert(word_at(PARAMS + 4) == 0 && !lookups);
    assert(!strip_params()->vlan_id[0] && !strip_params()->vlan_id[1]);
    assert(!strip_params()->op_flags);

    /* No description at all -- a flow that named no encapsulation, or an
     * untagged multicast group: no tag to validate and no record, and the word
     * is the statistics base with a count of zero, as it has always been for
     * such an entry. The port is still asked whether it is a registered one,
     * once, and a refusal refuses the entry without touching its cursors. */
    info = ingress(12, 0, NULL, NULL, 0, opcode);
    assert(insert_remove_vlan_hm(&info, 5, 5) == SUCCESS);
    assert(lookups == 1);
    assert(word_at(PARAMS + 4) == stats_base);
    assert(!strip_params()->vlan_id[0] && !strip_params()->vlan_id[1]);
    assert(opcode[0] == STRIP_ALL_VLAN_HDRS && info.opc_count == 2);
    assert(info.paramptr == PARAMS + 12 && info.param_size == 0);
    guards_intact(PARAMS + 12);
    port_unregistered = 1;
    info = ingress(12, 0, NULL, NULL, 0, opcode);
    assert(insert_remove_vlan_hm(&info, 5, 5) == FAILURE);
    assert(info.opc_count == 1 && info.param_size == 12 && opcode[0] == 0xa5);
    assert(!strip_params()->word);
    port_unregistered = 0;
    info = ingress(11, 0, NULL, NULL, 0, opcode);
    assert(insert_remove_vlan_hm(&info, 5, 5) == FAILURE);
    assert(info.opc_count == 1 && info.param_size == 11 && opcode[0] == 0xa5);
    lookups = 0;

    /* Refusals leave the cursors alone and write nothing past the zeroed
     * fixed part of the parameters. */
    info = ingress(15, 2, qinq, both, 1, opcode);
    assert(insert_remove_vlan_hm(&info, 5, 5) == FAILURE);
    assert(info.opc_count == 1 && info.param_size == 15 && opcode[0] == 0xa5);
    assert(!strip_params()->vlan_id[0] && !strip_params()->word);
    guards_intact(PARAMS + 12);
    info = ingress(11, 1, single, one, 1, opcode);
    assert(insert_remove_vlan_hm(&info, 5, 5) == FAILURE);
    assert(!strip_params()->vlan_id[0] && !strip_params()->word);
    guards_intact(PARAMS + 12);

    /* SEC's internal tag overrides the already stripped ingress VLAN stack
     * and must validate exactly one tag, without borrowing its statistics. */
    info = ingress(12, 2, qinq, both, 1, opcode);
    info.sec_tag = 0x345;
    assert(insert_remove_vlan_hm(&info, 5, 5) == SUCCESS);
    assert(be16_to_cpu(strip_params()->vlan_id[0]) == 0x345);
    assert(!strip_params()->vlan_id[1] && !strip_params()->word && !strip_params()->op_flags);
    assert(opcode[0] == STRIP_ALL_VLAN_HDRS && info.opc_count == 2 && !info.param_size);
    assert(!lookups);
    guards_intact(PARAMS + 12);
    info = ingress(11, 0, NULL, NULL, 0, opcode);
    info.sec_tag = 1;
    assert(insert_remove_vlan_hm(&info, 5, 5) == FAILURE);
    assert(info.opc_count == 1 && info.param_size == 11 && opcode[0] == 0xa5);
    info = ingress(12, 0, NULL, NULL, 0, opcode);
    info.sec_tag = 4094; info.opc_count = MAX_OPCODES;
    assert(insert_remove_vlan_hm(&info, 5, 5) == FAILURE);
    assert(info.paramptr == PARAMS && opcode[0] == 0xa5 && !lookups);

    /* ---- what puts the records into the description ---------------------
     *
     * The caller's encapsulation carries one index per tag on each side, and
     * apply_l2_encap() copies them across and marks the stack flow-described. */
    {
        struct cdx_l2_encap encap = {};

        memset(&info, 0, sizeof(info));
        encap.num_ingress = 2;
        encap.ingress[0].tpid = 0x8100; encap.ingress[0].tci = 300;
        encap.ingress[1].tpid = 0x8100; encap.ingress[1].tci = 100;
        encap.ingress_vlan_stats_index[0] = 0x0e;
        encap.ingress_vlan_stats_index[1] = 0x10;
        encap.num_egress = 1;
        encap.egress[0].tpid = 0x8100; encap.egress[0].tci = 200;
        encap.egress_vlan_stats_index[0] = 0x13;
        assert(apply_l2_encap(&info, &encap) == SUCCESS);
        assert(info.l2_info.vlan_flow_ifstats);
        assert(info.l2_info.num_ingress_vlan_hdrs == 2 && info.l2_info.num_egress_vlan_hdrs == 1);
        assert(info.l2_info.ingress_vlan_stats_offsets[0] == 0x0e);
        assert(info.l2_info.ingress_vlan_stats_offsets[1] == 0x10);
        assert(info.l2_info.vlan_stats_offsets[0] == 0x13 && !info.l2_info.vlan_stats_offsets[1]);
        assert(info.l2_info.vlan_present && !info.l2_info.pppoe_present);

        /* No tags, no indices: still flow-described, so the strip emits the
         * disabled word without asking the port. */
        memset(&info, 0, sizeof(info));
        encap = (struct cdx_l2_encap){};
        assert(apply_l2_encap(&info, &encap) == SUCCESS);
        assert(info.l2_info.vlan_flow_ifstats && !info.l2_info.vlan_present);
        assert(!vlan_flow_stats_named(info.l2_info.ingress_vlan_stats_offsets, 0));
    }
    assert(vlan_flow_stats_named(both, 2) && !vlan_flow_stats_named(partial, 2));
    assert(vlan_flow_stats_named(one, 1) && !vlan_flow_stats_named(none, 1));
    puts("VLAN HM record indices, ordering, suppression and refusal checks passed");
}
