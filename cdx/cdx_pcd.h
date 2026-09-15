/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Description of the ASK FMan PCD.
 *
 * The shape is fixed by the microcode and by cdx_sp.xml, not by board layout:
 * twelve classification groups, one KeyGen scheme per group shared by every
 * port, and one external hash table per group per port.
 *
 * Group order is load bearing. A scheme's kgNextEngineParams.cc.grpId selects
 * a group in the port's CC root tree, and cdx_sp.xml addresses the PPPoE relay
 * table by a hardcoded offset from the CC base. Reordering cdx_pcd_groups[]
 * silently repoints both. See docs/in-kernel-pcd.md.
 */
#ifndef CDX_PCD_H
#define CDX_PCD_H

#include <linux/types.h>
#include "fm_ext.h"
#include "fm_pcd_ext.h"
#include "fm_port_ext.h"
#include "fm_eh_types.h"
#include "cdx_ioctl.h"

/* One classification group: a hash table replicated per port, plus the single
 * shared scheme that dispatches into it. */
#define CDX_PCD_NUM_GROUPS	12
/* Widest key in cdx_pcd_groups[] is five extracts (the 5-tuple schemes). */
#define CDX_PCD_MAX_EXTRACTS	5
/* Widest protocol set is two (an L3 header plus its L4 or ESP header). */
#define CDX_PCD_MAX_UNITS	2

/*
 * Network-environment distinction units, in the order they are handed to
 * FM_PCD_NetEnvCharacteristicsSet(). A scheme names its units by index, so
 * this order is part of the ABI between cdx_pcd_groups[] and the net env.
 * fmc derived the same order by sorting protocol names; it is spelled out
 * here so the coupling is visible rather than emergent.
 */
enum cdx_pcd_unit {
	CDX_PCD_UNIT_ETH,
	CDX_PCD_UNIT_IPSEC_ESP,
	CDX_PCD_UNIT_IPV4,
	CDX_PCD_UNIT_IPV6,
	CDX_PCD_UNIT_PPPOE,
	CDX_PCD_UNIT_TCP,
	CDX_PCD_UNIT_UDP,
	CDX_PCD_NUM_UNITS
};

/* One full-field extract in a scheme's hash key. */
struct cdx_pcd_extract {
	e_NetHeaderType		hdr;
	e_FmPcdHdrIndex		hdr_index;
	/* NET_HEADER_FIELD_* constant for hdr. Stored width-agnostically and
	 * written to the t_FmPcdFields member that the KeyGen driver reads for
	 * this header -- see cdx_pcd_set_field(). */
	u32			field;
};

struct cdx_pcd_group {
	/* External hash table, instantiated once per port. */
	const char		*table_name;
	u16			key_size;	/* matchKeySize */
	u16			hash_res_mask;	/* hashResMask */
	u8			table_type;	/* enum in fm_eh_types.h */

	/* KeyGen scheme, instantiated once and shared by every port. */
	const char		*scheme_name;
	u32			base_fqid;
	u16			num_fqids;	/* hashDistributionNumOfFqids */
	u8			dist_type;	/* enum in cdx_ioctl.h */
	u8			num_units;
	u8			units[CDX_PCD_MAX_UNITS];
	u8			num_extracts;
	struct cdx_pcd_extract	extracts[CDX_PCD_MAX_EXTRACTS];
};

/* Indexed by group id: cdx_pcd_groups[n] is CC root group n on every port. */
extern const struct cdx_pcd_group cdx_pcd_groups[CDX_PCD_NUM_GROUPS];
extern const e_NetHeaderType cdx_pcd_units[CDX_PCD_NUM_UNITS];

/*
 * Write @extract into @entry as a full-field extraction. The KeyGen driver
 * reads a different member of the t_FmPcdFields union for each header type
 * (GetKnownProtMask() in fm_kg.c), and the members differ in width, so the
 * field value cannot simply be assigned through any one of them.
 * Returns 0, or -EINVAL for a header cdx does not classify on.
 */
int cdx_pcd_set_extract(t_FmPcdExtractEntry *entry,
			const struct cdx_pcd_extract *extract);

/* Every group's hash table is created with this many keys. */
#define CDX_PCD_MAX_NUM_OF_KEYS		512

/*
 * A port that takes part in classification. Built at startup from the DPAA
 * netdevs and the offline-port registry; see cdx_pcd_ports.c.
 */
struct cdx_pcd_port {
	e_FmPortType	type;
	u8		fm_index;
	u8		number;		/* device-tree cell-index */
	u8		portid;		/* logical port id -> prsResultPrivateInfo */
	/* 0 for offline, 1 for 1G, 10 for 10G -- the encoding cdx_port_info
	 * carries in its `type` field. */
	u8		speed;
	char		name[CDX_CTRL_PORT_NAME_LEN];
};

#define CDX_PCD_MAX_PORTS	16

/*
 * Enumerate the classification ports of FMan @fm_index into @ports (at most
 * CDX_PCD_MAX_PORTS), sorted by port class then cell-index. On success also
 * stores the FMan wrapper device the ports belong to in @fm_dev.
 *
 * Caller holds RTNL. Returns the number of ports, or negative on error.
 */
int cdx_pcd_enumerate_ports(u8 fm_index, struct cdx_pcd_port *ports,
			    unsigned int max_ports, void **fm_dev);

/* Everything the builder created, and everything teardown needs to undo. */
struct cdx_pcd_port_state {
	t_Handle	h_port;
	t_Handle	tables[CDX_PCD_NUM_GROUPS];
	unsigned int	num_tables;
	t_Handle	cctree;
	bool		was_enabled;
	bool		pcd_set;
	/* FM_PORT_SetPCD() is handed pointers to these, so they outlive the
	 * call rather than living on the builder's stack. */
	t_FmPortPcdParams	pcd;
	t_FmPortPcdPrsParams	prs;
	t_FmPortPcdKgParams	kg;
	t_FmPortPcdCcParams	cc;
};

/* Several kilobytes of FMan parameter blocks -- allocate it, never a local. */
struct cdx_pcd_state {
	u8			fm_index;
	void			*fm_dev;	/* t_LnxWrpFmDev * */
	t_Handle		h_fm;
	t_Handle		h_pcd;
	t_Handle		net_env;
	t_Handle		schemes[CDX_PCD_NUM_GROUPS];
	unsigned int		num_schemes;
	unsigned int		num_ports;
	struct cdx_pcd_port	ports[CDX_PCD_MAX_PORTS];
	struct cdx_pcd_port_state port_state[CDX_PCD_MAX_PORTS];
};

/*
 * Install the whole PCD on FMan @fm_index: soft parser, network environment,
 * one hash table per group per port, a CC root tree per port, the shared
 * KeyGen schemes, and FM_PORT_SetPCD on every port. On failure everything
 * already created is released before returning.
 *
 * Caller holds RTNL and the cdx control mutex. Returns 0, or negative.
 */
int cdx_pcd_build(u8 fm_index, struct cdx_pcd_state *state);

/*
 * Detach and release what can be released: ports, schemes, trees, net env.
 * The external hash tables are not reclaimable -- the SDK has no working delete
 * for them under USE_ENHANCED_EHASH (ISSUES.md A138) -- so a failed or
 * torn-down build leaks them and the FMan needs a reboot before the classifier
 * can be installed again.
 */
void cdx_pcd_teardown(struct cdx_pcd_state *state);

#endif /* CDX_PCD_H */
