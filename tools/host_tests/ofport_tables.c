/* The tables an offline port reports to its owner, compiled from devoh.c and
 * dpa_cfg.c.
 *
 * An offline port's flags word holds OF_FQID_VALID, IN_USE, PORT_VALID and the
 * port type. Table types run up to MAX_MATCH_TABLES, and get_ofport_info()
 * used to collect the types present on the port as bits of that same word: a
 * PPPoE (8), Ethernet (9), IPv6 3-tuple UDP (12) or bridged IPv6 multicast (13)
 * table landed on a port flag, and every bit stayed after its table went. The
 * shipped PCD attaches all four to both offline ports. So the checks below are
 * that the flags come back as they went in, that each table type is reported
 * exactly while its table is attached, and that the types the IPsec port's
 * consumers ask for are reported as the tables themselves. Every check runs
 * and is reported, so a run against a broken build says which ones broke. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define DPA_ERROR(...) ((void)0)
#define DPA_INFO(...) ((void)0)

#include "ofport_types.inc"

struct qman_portal;
struct qm_dqrr_entry;
struct qman_fq;
enum qman_cb_dqrr_result { qman_cb_dqrr_consume };
typedef enum qman_cb_dqrr_result (*qman_cb_dqrr)(struct qman_portal *, struct qman_fq *,
						 const struct qm_dqrr_entry *);
struct qman_fq { struct { qman_cb_dqrr dqrr; } cb; };
struct dpa_fq { struct qman_fq fq_base; };
struct oh_iface_info { uint32_t portid; };

struct cdx_fman_info {
	struct table_info *tbl_info;
	uint32_t num_tables;
};
struct cdx_fman_info *fman_info;

/* devoh.c's own handlers, which a released port's queues go back to. */
static enum qman_cb_dqrr_result ofport_rx_defa(struct qman_portal *p, struct qman_fq *fq,
					       const struct qm_dqrr_entry *dq)
{ (void)p; (void)fq; (void)dq; return qman_cb_dqrr_consume; }
static enum qman_cb_dqrr_result ofport_rx_err(struct qman_portal *p, struct qman_fq *fq,
					      const struct qm_dqrr_entry *dq)
{ (void)p; (void)fq; (void)dq; return qman_cb_dqrr_consume; }

#include "ofport_tables.inc"
#include "ofport_config.inc"

static unsigned failures;
#define CHECK(cond, ...) do { if (!(cond)) { failures++; \
	printf("FAIL %s:%d: ", __func__, __LINE__); printf(__VA_ARGS__); putchar('\n'); } \
	} while (0)

#define IPSEC_HANDLE 1
#define WIFI_HANDLE 2
static struct oh_iface_info oh[MAX_OF_PORTS];
static struct dpa_fq rx[MAX_OF_PORTS], err[MAX_OF_PORTS];
static struct table_info tables[MAX_MATCH_TABLES];

static void *table_id(uint32_t type) { return (void *)(uintptr_t)(0x1000 + 0x10 * type); }

/* The ports as devoh registers them: valid, their queues created, typed. */
static void register_ports(void)
{
	memset(offline_port_info, 0, sizeof(offline_port_info));
	for (unsigned ii = 0; ii < MAX_OF_PORTS; ii++) {
		offline_port_info[0][ii].ohinfo = &oh[ii];
		offline_port_info[0][ii].rx_dpa_fq = &rx[ii];
		offline_port_info[0][ii].err_dpa_fq = &err[ii];
	}
	oh[IPSEC_HANDLE].portid = IPSEC_PORTID;
	oh[WIFI_HANDLE].portid = WIFI_PORTID;
	offline_port_info[0][IPSEC_HANDLE].flags = PORT_TYPE_IPSEC | OF_FQID_VALID | PORT_VALID;
	offline_port_info[0][WIFI_HANDLE].flags = PORT_TYPE_WIFI | OF_FQID_VALID | PORT_VALID;
}

/* One table of each type in `types`, attached to `ports` (a portid bitmap)
 * and to an Ethernet port besides, as the shared PCD tables are. */
static void attach(const uint32_t *types, unsigned count, uint32_t ports)
{
	static struct cdx_fman_info finfo;

	memset(tables, 0, sizeof(tables));
	for (unsigned ii = 0; ii < count; ii++) {
		tables[ii].type = types[ii];
		tables[ii].port_idx = ports | (1u << 1);
		tables[ii].id = table_id(types[ii]);
	}
	finfo.tbl_info = tables;
	finfo.num_tables = count;
	fman_info = &finfo;
}

/* Ask the port for its tables and check the answer: every type in `types` is
 * reported as its own table, every other type as none, and the port's flags
 * are what they were. */
static void expect(int handle, const uint32_t *types, unsigned count, const char *what)
{
	uint32_t flags = offline_port_info[0][handle].flags, channel = 0xdead;
	void *td[MAX_MATCH_TABLES];

	memset(td, 0xa5, sizeof(td));
	offline_port_info[0][handle].channel = 0x42 + handle;
	CHECK(get_ofport_info(0, handle, &channel, td) == 0, "%s: port refused", what);
	CHECK(channel == 0x42u + handle, "%s: channel", what);
	CHECK(offline_port_info[0][handle].flags == flags,
	      "%s: flags 0x%x became 0x%x", what, flags, offline_port_info[0][handle].flags);
	for (uint32_t type = 0; type < MAX_MATCH_TABLES; type++) {
		int attached = 0;

		for (unsigned ii = 0; ii < count; ii++)
			attached |= types[ii] == type;
		CHECK(td[type] == (attached ? table_id(type) : NULL),
		      "%s: type %u reported %p, attached %d", what, type, td[type], attached);
	}
}

int main(void)
{
	static const uint32_t colliding[] = { COLLIDING_TYPES };
	int handle;

	/* The shipped configuration: every table on both offline ports. */
	register_ports();
	attach(oh_table_types, ARRAY_LEN(oh_table_types), (1u << IPSEC_PORTID) | (1u << WIFI_PORTID));
	handle = alloc_offline_port(0, PORT_TYPE_IPSEC, NULL, NULL);
	CHECK(handle == IPSEC_HANDLE, "IPsec claim got %d", handle);
	expect(IPSEC_HANDLE, oh_table_types, ARRAY_LEN(oh_table_types), "IPsec, shipped tables");
	CHECK((offline_port_info[0][IPSEC_HANDLE].flags & PORT_TYPE_MASK) == PORT_TYPE_IPSEC,
	      "IPsec port type 0x%x", offline_port_info[0][IPSEC_HANDLE].flags & PORT_TYPE_MASK);

	/* The types the IPsec port's consumers look up, one by one: the SA's
	 * own table and an inbound flow's. Each is the table itself. */
	{
		uint32_t channel;
		void *td[MAX_MATCH_TABLES];

		CHECK(get_ofport_info(0, IPSEC_HANDLE, &channel, td) == 0, "IPsec port refused");
		for (unsigned ii = 0; ii < ARRAY_LEN(ipsec_used_types); ii++)
			CHECK(td[ipsec_used_types[ii]] == table_id(ipsec_used_types[ii]),
			      "IPsec lookup of type %u", ipsec_used_types[ii]);
	}

	/* Released and claimed again, as an IPsec re-initialisation does: the
	 * port is still the IPsec one, and the Wi-Fi claim still finds its own. */
	CHECK(release_offline_port(0, IPSEC_HANDLE) == 0, "IPsec release");
	CHECK(offline_port_info[0][IPSEC_HANDLE].rx_dpa_fq->fq_base.cb.dqrr == ofport_rx_defa,
	      "released port's default queue");
	handle = alloc_offline_port(0, PORT_TYPE_IPSEC, NULL, NULL);
	CHECK(handle == IPSEC_HANDLE, "IPsec claimed again got %d", handle);
	handle = alloc_offline_port(0, PORT_TYPE_WIFI, NULL, NULL);
	CHECK(handle == WIFI_HANDLE, "Wi-Fi claim got %d", handle);
	expect(WIFI_HANDLE, oh_table_types, ARRAY_LEN(oh_table_types), "Wi-Fi, shipped tables");
	CHECK(release_offline_port(0, WIFI_HANDLE) == 0, "Wi-Fi release");
	handle = alloc_offline_port(0, PORT_TYPE_WIFI, NULL, NULL);
	CHECK(handle == WIFI_HANDLE, "Wi-Fi claimed again got %d", handle);

	/* Each type that shares a bit with a port flag, alone, on each port:
	 * attached it is reported and the flags stay; detached again -- a PCD
	 * reloaded without it -- it is reported as no table, not as the one it
	 * used to be. */
	for (unsigned ii = 0; ii < ARRAY_LEN(colliding); ii++) {
		for (int port = IPSEC_HANDLE; port <= WIFI_HANDLE; port++) {
			char what[64];

			register_ports();
			handle = alloc_offline_port(0, port == IPSEC_HANDLE ? PORT_TYPE_IPSEC :
						    PORT_TYPE_WIFI, NULL, NULL);
			CHECK(handle == port, "claim of port %d got %d", port, handle);
			attach(&colliding[ii], 1, 1u << oh[port].portid);
			snprintf(what, sizeof(what), "port %d, type %u attached", port, colliding[ii]);
			expect(port, &colliding[ii], 1, what);
			attach(NULL, 0, 0);
			snprintf(what, sizeof(what), "port %d, type %u detached", port, colliding[ii]);
			expect(port, NULL, 0, what);
			CHECK(release_offline_port(0, port) == 0, "release of port %d", port);
			handle = alloc_offline_port(0, port == IPSEC_HANDLE ? PORT_TYPE_IPSEC :
						    PORT_TYPE_WIFI, NULL, NULL);
			CHECK(handle == port, "port %d claimed again after type %u got %d",
			      port, colliding[ii], handle);
		}
	}

	/* A port nobody has claimed answers nothing. */
	register_ports();
	{
		uint32_t channel = 7;
		void *td[MAX_MATCH_TABLES] = { 0 };

		CHECK(get_ofport_info(0, IPSEC_HANDLE, &channel, td) == -1 && channel == 7,
		      "unclaimed port answered");
		CHECK(get_ofport_info(0, MAX_OF_PORTS, &channel, td) == -1, "handle out of range");
		CHECK(get_ofport_info(MAX_FRAME_MANAGERS, 0, &channel, td) == -1, "fman out of range");
	}

	if (failures) {
		printf("%u offline-port table checks failed\n", failures);
		return 1;
	}
	puts("offline-port tables: flags kept, types reported while attached, IPsec lookups unchanged");
	return 0;
}
