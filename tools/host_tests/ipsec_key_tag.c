/* The IPsec offline port's keys, compiled from cdx: what the composers write
 * for a decrypted flow and for an outbound SA, which SA a flow's key is made
 * to name, which of the port's tables it goes in, where a miss on one of them
 * goes, and what an SA's delete leaves of its frame queue ids.
 *
 * Every SA's FROM_SEC queue feeds the port, so the SA a frame left SEC by is
 * something only its enqueue FQID tells, and every key the port holds has to
 * end in the FQID of the SA it was made for, exactly as the key generator
 * extracts it: port id, the tuple its counterpart on an Ethernet port keys
 * on, then the FQID's 24 bits, most significant first. The table sizes come
 * from cdx_pcd.xml on the command line, so a composer and a table that
 * disagree fail here. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define cpu_to_be16(x) __builtin_bswap16((uint16_t)(x))
#define cpu_to_be32(x) __builtin_bswap32((uint32_t)(x))
#else
#define cpu_to_be16(x) ((uint16_t)(x))
#define cpu_to_be32(x) ((uint32_t)(x))
#endif
#define DPA_PACKED __attribute__((packed))
#define DPA_ERROR(...) ((void)0)
#define DPA_INFO(...) ((void)0)
#define DPAIPSEC_ERROR(...) ((void)0)
#define SUCCESS 0
#define FAILURE -1
#define EN_EHASH_DELETE_UNSYNCED (-2)
#define PROTO_IPV4 0
#define PROTO_IPV6 1
#define IPPROTO_UDP 17
typedef uint8_t U8;
typedef uint16_t U16;
typedef uint32_t U32;
typedef uint16_t u16;

struct dpa_bp;
struct dpa_fq;
struct port_bman_pool_info { int pool_id; };

#include "sec_key_types.inc"

/* The conntrack fields the composers and the SA lookup read. */
#define FFTYPE_IPV4 1
#define FFTYPE_IPV6 2
typedef struct {
	U8 fftype, proto;
	U16 Sport, Dport;
	U32 Saddr_v4, Daddr_v4;
	U32 Saddr_v6[4], Daddr_v6[4];
	U16 hSAEntry[SA_MAX_OP];
	U16 sec_expansion;
} CtEntry, *PCtEntry;
#define IS_IPV6_FLOW(e) (((e)->fftype & FFTYPE_IPV6) != 0)

/* The SA cache's fields the same code reads. */
typedef struct {
	U32 to_sec_fqid, to_cp_fqid;
	void *dpa_ipsecsa_handle;
} DpaSecSAContext, *PDpaSecSAContext;
typedef struct {
	struct { union { U32 a6[4]; } daddr; U32 saddr[4]; U32 spi; } id;
	U8 family, direction;
	U16 handle, mtu, dev_mtu;
	struct { unsigned short sport, dport; } natt;
	int natt_arr_index;
	PDpaSecSAContext pSec_sa_context;
	struct hw_ct *ct;
} SAEntry, *PSAEntry;
#define IS_NATT_SA(entry) (entry->natt.sport && entry->natt.dport)

struct en_exthash_tbl_entry {
	struct { uint8_t key[64]; } hashentry;
	uint8_t *ipsec_preempt_params;
};

/* Only the fields cdx_ipsec_fill_sec_info() reads and writes. */
struct ins_entry_info {
	uint32_t tbl_type, port_id, to_sec_fqid, sec_tag;
	uint16_t tnl_hdr_size, sa_family;
	void *td;
	struct { uint8_t ipsec_inbound_flow:1; } l3_info;
};

struct cdx_fman_info {
	struct table_info *tbl_info;
	struct cdx_port_info *portinfo;
	uint32_t max_ports, num_tables;
};

static PSAEntry sa_cache[8];
static void *M_ipsec_sa_cache_lookup_by_h(U16 handle)
{
	return handle < 8 ? sa_cache[handle] : NULL;
}
static bool ready = true;
static bool cdx_dpa_ipsec_ready(void) { return ready; }
static struct ipsec_info ipsecinfo;
static struct ipsec_info *ipsec_instance = &ipsecinfo;

/* The table delete, answering what a case scripts, and what an SA's delete
 * leaves of its FQIDs. */
static int delete_rc;
static unsigned deletes;
static int cdx_ehash_delete_entry(void *td, uint16_t index, void *handle)
{
	(void)td; (void)index; (void)handle;
	deletes++;
	return delete_rc;
}
static void *kept;
static void cdx_dpa_ipsecsa_keep_fqids(void *handle) { kept = handle; }
#define kfree(p) free(p)

#include "sec_key_production.inc"

#define FQID 0x012345u
static void tag_is(const uint8_t *key, uint32_t at)
{
	assert(key[at] == 0x01 && key[at + 1] == 0x23 && key[at + 2] == 0x45);
}

/* A flow's key, as insert_entry_in_classif_table_encap() composes one for a
 * direction some SA decrypts: the tuple, then the SA's FQID. */
static void flows(void)
{
	const struct { uint8_t proto, fftype; uint32_t shared, sec; } cases[] = {
		{ IPPROTOCOL_TCP, FFTYPE_IPV4, TCP4_KEYSIZE, SEC_TCP4_KEYSIZE },
		{ IPPROTOCOL_UDP, FFTYPE_IPV4, UDP4_KEYSIZE, SEC_UDP4_KEYSIZE },
		{ IPPROTOCOL_TCP, FFTYPE_IPV6, TCP6_KEYSIZE, SEC_TCP6_KEYSIZE },
		{ IPPROTOCOL_UDP, FFTYPE_IPV6, UDP6_KEYSIZE, SEC_UDP6_KEYSIZE },
	};

	for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		CtEntry ct = { .fftype = cases[i].fftype, .proto = cases[i].proto,
			       .Sport = cpu_to_be16(1000), .Dport = cpu_to_be16(2000),
			       .Saddr_v4 = 0x0a0000c6, .Daddr_v4 = 0x0b0000c6 };
		uint8_t key[64];
		uint32_t size;

		ct.Saddr_v6[0] = 0x000080fe;
		ct.Daddr_v6[3] = 0x01000000;
		memset(key, 0xee, sizeof(key));
		size = fill_key_info(&ct, key, IPSEC_PORTID);
		/* Untagged, it is exactly the key an Ethernet port's table holds. */
		assert(size == cases[i].shared);
		size = cdx_ipsec_key_tag(key, size, FQID);
		assert(size == cases[i].sec);
		assert(key[0] == IPSEC_PORTID);
		tag_is(key, cases[i].shared);
		/* The tuple is where the port's key generator puts it. */
		if (cases[i].fftype == FFTYPE_IPV4) {
			assert(!memcmp(key + 1, &ct.Saddr_v4, 4) && !memcmp(key + 5, &ct.Daddr_v4, 4));
			assert(key[9] == cases[i].proto && !memcmp(key + 10, &ct.Sport, 2) &&
			       !memcmp(key + 12, &ct.Dport, 2));
		} else {
			assert(!memcmp(key + 1, ct.Saddr_v6, 16) && !memcmp(key + 17, ct.Daddr_v6, 16));
			assert(key[33] == cases[i].proto && !memcmp(key + 34, &ct.Sport, 2) &&
			       !memcmp(key + 36, &ct.Dport, 2));
		}
		assert(key[size] == 0xee);	/* nothing past it */
	}
}

/* An SA's own key. An outbound SA's entry is on the offline port and carries
 * its FQID; an inbound SA's is on the port the peer's frames arrive by and
 * does not, which is why the untagged size is the shared table's. NAT-T SAs
 * are keyed on the UDP tuple and live in the UDP tables. */
static void sas(void)
{
	DpaSecSAContext ctx = { .to_cp_fqid = FQID };
	SAEntry sa = { .pSec_sa_context = &ctx };
	struct en_exthash_tbl_entry entry;
	uint32_t size;

	sa.id.daddr.a6[0] = 0x7a01a8c0;
	sa.id.saddr[0] = 0x0101a8c0;
	sa.id.spi = cpu_to_be32(0x0a878e3e);
	for (unsigned family = PROTO_IPV4; family <= PROTO_IPV6; family++) {
		sa.family = family;
		sa.natt.sport = sa.natt.dport = 0;
		memset(&entry, 0xee, sizeof(entry));
		size = fill_ipsec_key_info(&sa, &entry, IPSEC_PORTID);
		assert(size == (family == PROTO_IPV4 ? ESP4_KEYSIZE : ESP6_KEYSIZE));
		size = cdx_ipsec_key_tag(entry.hashentry.key, size, cdx_ipsec_key_tag_of(&sa));
		assert(size == (family == PROTO_IPV4 ? SEC_ESP4_KEYSIZE : SEC_ESP6_KEYSIZE));
		tag_is(entry.hashentry.key, size - CDX_IPSEC_KEY_TAG_LEN);
		/* The SPI just ahead of the FQID, as the key generator orders
		 * its known fields. */
		assert(!memcmp(entry.hashentry.key + size - CDX_IPSEC_KEY_TAG_LEN - 4,
			       &sa.id.spi, 4));

		sa.natt.sport = 4500;
		sa.natt.dport = 4500;
		memset(&entry, 0xee, sizeof(entry));
		size = fill_natt_key_info(&sa, &entry, IPSEC_PORTID);
		assert(size == (family == PROTO_IPV4 ? UDP4_KEYSIZE : UDP6_KEYSIZE));
		size = cdx_ipsec_key_tag(entry.hashentry.key, size, cdx_ipsec_key_tag_of(&sa));
		assert(size == (family == PROTO_IPV4 ? SEC_UDP4_KEYSIZE : SEC_UDP6_KEYSIZE));
		tag_is(entry.hashentry.key, size - CDX_IPSEC_KEY_TAG_LEN);
	}
}

static void *table(uint32_t type) { return (void *)(uintptr_t)(0x100 + type); }

/* Which SA a flow's entry names, and where it goes. */
static void fill_sec_info(void)
{
	DpaSecSAContext in_ctx = { .to_sec_fqid = 0x300, .to_cp_fqid = 0x302 };
	DpaSecSAContext out_ctx = { .to_sec_fqid = 0x401, .to_cp_fqid = 0x402 };
	SAEntry in = { .direction = CDX_DPA_IPSEC_INBOUND, .pSec_sa_context = &in_ctx };
	SAEntry out = { .direction = CDX_DPA_IPSEC_OUTBOUND, .pSec_sa_context = &out_ctx,
			.mtu = 1438, .dev_mtu = 1500 };
	const uint32_t decrypted[] = { IPV4_TCP_TABLE, IPV4_UDP_TABLE, IPV6_TCP_TABLE,
				       IPV6_UDP_TABLE };
	struct ins_entry_info info;
	CtEntry ct = { 0 };

	memset(&ipsecinfo, 0, sizeof(ipsecinfo));
	ipsecinfo.ofport_portid = IPSEC_PORTID;
	/* The tables the port has: its own, by the types they replace. */
	for (uint32_t type = 0; type < MAX_MATCH_TABLES; type++)
		if (type <= ESP_IPV6_TABLE || type == ETHERNET_TABLE)
			ipsecinfo.ofport_td[type] = table(type);
	sa_cache[2] = &in;
	sa_cache[3] = &out;

	/* A decrypted direction: the offline port's table of the flow's type,
	 * keyed on the inbound SA's TO_CP FQID. */
	ct.hSAEntry[1] = 2;
	for (unsigned i = 0; i < 4; i++) {
		memset(&info, 0, sizeof(info));
		info.tbl_type = decrypted[i];
		info.td = (void *)1;
		assert(cdx_ipsec_fill_sec_info(&ct, &info) == 0);
		assert(info.l3_info.ipsec_inbound_flow && info.sec_tag == in_ctx.to_cp_fqid);
		assert(info.td == table(decrypted[i]) && info.port_id == IPSEC_PORTID);
		assert(!info.to_sec_fqid);
	}
	/* A UDP flow without ports the encoder files under multicast, which the
	 * port keys on nothing of the SA: refused, and nothing half set. */
	memset(&info, 0, sizeof(info));
	info.tbl_type = IPV4_MULTICAST_TABLE;
	info.td = (void *)1;
	assert(cdx_ipsec_fill_sec_info(&ct, &info) == -1);
	assert(!info.l3_info.ipsec_inbound_flow && info.td == (void *)1);
	/* A type the port has no table for is refused rather than handed back
	 * as a NULL descriptor; so is a port that is not there at all. */
	ipsecinfo.ofport_td[IPV6_UDP_TABLE] = NULL;
	info.tbl_type = IPV6_UDP_TABLE;
	assert(cdx_ipsec_fill_sec_info(&ct, &info) == -1);
	ipsecinfo.ofport_td[IPV6_UDP_TABLE] = table(IPV6_UDP_TABLE);
	ready = false;
	info.tbl_type = IPV4_TCP_TABLE;
	assert(cdx_ipsec_fill_sec_info(&ct, &info) == -1);
	ready = true;

	/* A handle the cache no longer holds refuses the entry, whichever end
	 * names it, rather than installing it as though the SA were absent. */
	ct.hSAEntry[1] = 6;
	memset(&info, 0, sizeof(info));
	info.tbl_type = IPV4_TCP_TABLE;
	info.td = (void *)1;
	assert(cdx_ipsec_fill_sec_info(&ct, &info) == -1);
	assert(!info.l3_info.ipsec_inbound_flow && info.td == (void *)1);
	ct.hSAEntry[1] = 0;
	ct.hSAEntry[0] = 6;
	assert(cdx_ipsec_fill_sec_info(&ct, &info) == -1 && !info.to_sec_fqid);

	/* An encrypted direction names no key and stays where it was. */
	ct.hSAEntry[1] = 0;
	ct.hSAEntry[0] = 3;
	memset(&info, 0, sizeof(info));
	info.tbl_type = IPV4_TCP_TABLE;
	info.td = (void *)1;
	assert(cdx_ipsec_fill_sec_info(&ct, &info) == 0);
	assert(info.to_sec_fqid == out_ctx.to_sec_fqid && info.tnl_hdr_size == 62);
	assert(!info.l3_info.ipsec_inbound_flow && !info.sec_tag && info.td == (void *)1);

	/* One tunnel feeding another: decrypted by one SA, encrypted by the
	 * next, and keyed on the first. */
	ct.hSAEntry[1] = 2;
	memset(&info, 0, sizeof(info));
	info.tbl_type = IPV6_TCP_TABLE;
	assert(cdx_ipsec_fill_sec_info(&ct, &info) == 0);
	assert(info.to_sec_fqid == out_ctx.to_sec_fqid && info.sec_tag == in_ctx.to_cp_fqid);
	assert(info.td == table(IPV6_TCP_TABLE));
	sa_cache[2] = sa_cache[3] = NULL;
}

/* Where a miss on a table goes: the scheme found by type when the table's
 * port classifies with it, else that port's Ethernet distribution. */
static void miss_chain(void)
{
	int shared_udp, shared_tup3, shared_eth, sec_udp, sec_eth;
	struct cdx_dist_info eth_dists[] = {
		{ .type = IPV4_UDP_DIST, .handle = &shared_udp },
		{ .type = IPV4_3TUPLE_UDP_DIST, .handle = &shared_tup3 },
		{ .type = ETHERNET_DIST, .handle = &shared_eth },
	};
	struct cdx_dist_info sec_dists[] = {
		{ .type = IPV4_UDP_DIST, .handle = &sec_udp },
		{ .type = ETHERNET_DIST, .handle = &sec_eth },
	};
	struct cdx_port_info ports[] = {
		{ .portid = 1, .max_dist = 3, .dist_info = eth_dists },
		{ .portid = IPSEC_PORTID, .max_dist = 2, .dist_info = sec_dists },
		{ .portid = 10, .max_dist = 3, .dist_info = eth_dists },
	};
	struct cdx_fman_info finfo = { .portinfo = ports, .max_ports = 3 };
	struct table_info eth_udp = { .type = IPV4_UDP_TABLE, .port_idx = 1u << 1 };
	struct table_info wifi_udp = { .type = IPV4_UDP_TABLE, .port_idx = 1u << 10 };
	struct table_info sec = { .type = IPV4_UDP_TABLE, .port_idx = 1u << IPSEC_PORTID };
	struct table_info nowhere = { .type = IPV4_UDP_TABLE };

	assert(miss_scheme_on_port(&finfo, &eth_udp, &shared_tup3) == &shared_tup3);
	assert(miss_scheme_on_port(&finfo, &wifi_udp, &shared_tup3) == &shared_tup3);
	assert(miss_scheme_on_port(&finfo, &sec, &shared_tup3) == &sec_eth);
	/* Found by type on the IPsec port first: the Ethernet ports' own. */
	assert(miss_scheme_on_port(&finfo, &eth_udp, &sec_eth) == &shared_eth);
	assert(miss_scheme_on_port(&finfo, &sec, &sec_eth) == &sec_eth);
	/* A named distribution no port has at all: the table's own port's
	 * Ethernet one, on the IPsec port as on any other. */
	assert(miss_scheme_on_port(&finfo, &sec, NULL) == &sec_eth);
	assert(miss_scheme_on_port(&finfo, &eth_udp, NULL) == &shared_eth);
	assert(miss_scheme_on_port(&finfo, &nowhere, &shared_tup3) == &shared_tup3);
	/* A port with neither the scheme nor an Ethernet distribution has no
	 * miss to program, which the caller refuses. */
	ports[1].max_dist = 1;
	assert(miss_scheme_on_port(&finfo, &sec, &shared_tup3) == NULL);
}

/* What an SA's delete leaves of its FQIDs: an entry that may still be linked
 * keeps them, one proven out or merely unproven does not. */
static void deletes_keep(void)
{
	int sainfo;
	DpaSecSAContext ctx = { .to_cp_fqid = FQID, .dpa_ipsecsa_handle = &sainfo };
	SAEntry sa = { .direction = CDX_DPA_IPSEC_OUTBOUND, .pSec_sa_context = &ctx };
	const int rcs[] = { SUCCESS, EN_EHASH_DELETE_UNSYNCED, FAILURE };

	for (unsigned i = 0; i < 3; i++) {
		sa.ct = calloc(1, sizeof(*sa.ct));
		assert(sa.ct);
		sa.ct->handle = &sa;
		delete_rc = rcs[i];
		kept = NULL;
		assert(cdx_ipsec_delete_fp_entry(&sa) == rcs[i]);
		assert(!sa.ct && kept == (rcs[i] == FAILURE ? &sainfo : NULL));
	}
	/* The outbound NAT-T entry is the SA's own as well, and deleting it
	 * deletes it. */
	sa.natt.sport = sa.natt.dport = 4500;
	sa.ct = calloc(1, sizeof(*sa.ct));
	assert(sa.ct);
	sa.ct->handle = &sa;
	sa.ct->natt_out_refcnt = 2;
	delete_rc = SUCCESS;
	deletes = 0;
	assert(cdx_ipsec_delete_fp_entry(&sa) == 0 && deletes == 1 && !sa.ct);
}

int main(void)
{
	flows();
	sas();
	fill_sec_info();
	miss_chain();
	deletes_keep();
	printf("offline-port keys: flows and SAs keyed on their FQID, tables and misses on the port\n");
	return 0;
}
