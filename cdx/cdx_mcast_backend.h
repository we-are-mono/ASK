/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef CDX_MCAST_BACKEND_H
#define CDX_MCAST_BACKEND_H

#include <linux/types.h>
#include <linux/netfilter.h>

#include "cdx_flowtable_backend.h"

struct net_device;
struct cdx_mc_group;

/* How many listeners one group may replicate to.
 *
 * MC_MAX_LISTENERS_PER_GROUP, which is what the legacy owner enforces and what
 * sizes the group's member array. It is not a hardware bound and nothing names
 * one: the programming path is a loop, one external-hash entry per listener,
 * threaded into the next. It is repeated here rather than widened because a
 * bridged group's listeners are physical ports in this ownership mode and a
 * gateway has five, so no reachable configuration approaches it -- and because
 * a number that has never been measured should not be quietly raised by the
 * caller that would first depend on it.
 */
#define CDX_MC_MAX_LISTENERS	8

/* One listener: a physical CDX port and the tags this group's frames leave it
 * with, outermost first, in the order the wire carries them.
 *
 * A bridged listener's tags are not the port's own -- the port has no VLAN
 * interface in this ownership mode and would describe none -- they are what the
 * bridge would have added on egress for this group's VLAN, which is a tag when
 * the port is a tagged member of it and nothing when the port is untagged.
 * Resolving that is the caller's, because it is a question about bridge
 * configuration and this side knows only ports.
 */
struct cdx_mc_listener {
	struct net_device *dev;
	struct cdx_ft_vlan vlan[CDX_FT_VLAN_MAX];
	u8 vlans;
};

/* A group, described once and installed in one pass.
 *
 * The legacy control plane spells this as a sequence of FCI commands -- an ADD
 * naming up to five listeners and an UPDATE for each batch after that --
 * because MC4Command is a wire message with a fixed-depth listener array and
 * CMM forwards whatever arrives. Nothing here has that constraint: a caller
 * that watched the bridge's MDB already knows the whole port set, so the group
 * is described whole and there is no window in which a half-built one is
 * reachable.
 *
 * `src` is a specific sender and is never zero. The classifier composes
 * {portid, saddr, daddr, protocol} into an external *hash* table, so a masked
 * source cannot match -- a wildcard would change the hash rather than widen
 * it. MC4Command.src_addr_mask is a wire field the tree reads nowhere and
 * could not have honoured. A caller holding a (*,G) membership therefore has
 * to learn a source before it has a group to install; that is the traffic
 * half of the learner, not something this interface can paper over.
 *
 * Addresses are in network byte order, `family` selects the arm of each, and
 * the unused bytes of both are zero so whole specs compare bytewise.
 */
struct cdx_mc_group_spec {
	/* The physical port this group's frames arrive on. It is part of the
	 * classifier key rather than merely a validity check, so a stream of
	 * the same (S,G) arriving on a different port misses this entry and is
	 * forwarded in software.
	 *
	 * That does not mean a second ingress can have an entry of its own.
	 * One group id and one root entry exist per address pair, so the
	 * second one is refused with -EEXIST; see cdx_mc_group_add(). */
	struct net_device *in;
	union nf_inet_addr src;
	union nf_inet_addr dst;
	u8 family;
	u8 listeners;
	struct cdx_mc_listener listener[CDX_MC_MAX_LISTENERS];
};

/* Group operations run inside the flowtable backend's transaction, taken with
 * cdx_ft_begin() and asserted with cdx_ft_assert_held(). There is deliberately
 * no transaction of this subsystem's own, for the reason the SA interface
 * gives: a group and a flow reach the same classifier through the same control
 * mutex, and a second lock would have to be ordered against that one for no
 * gain. Every operation below requires the transaction, and no backend
 * operation calls back into the adapter.
 */

/* Whether this device can carry a group, as an ingress or as a listener.
 *
 * The same identity question cdx_ft_port_supported() asks, and deliberately
 * the same answer: a group's ports are the flowtable's ports and a device that
 * could not carry a flow cannot carry a replica either. Unlike an SA, which may
 * legitimately be installed before its link has carrier, a group describes
 * traffic that is already flowing -- the caller learned the source from a frame
 * -- so the liveness half of that test is met by construction rather than
 * waived.
 */
bool cdx_mc_port_supported(struct net_device *dev);

/* Install a group and return its opaque owner.
 *
 * Every listener is programmed or none is. A partially replicated group is a
 * silently broken one: the matched frame never reaches the bridge, so listeners
 * the hardware did not take on do not fall back to software -- they simply stop
 * receiving. The caller therefore gets an error and keeps the whole group in
 * software, where the bridge is still flooding it.
 *
 * Devices are borrowed. The caller pins every one of them, the ingress and each
 * listener, for as long as the group lives -- which is the same discipline a
 * flow's rule keeps, and for the same reason: the entry names ports that must
 * not be unregistered underneath it.
 *
 * -EOPNOTSUPP: a device, address family or group address cannot be carried.
 * -EEXIST: this address pair already has a group. Note that the pair is the
 *          whole of that test -- the ingress is not part of it, because one
 *          group id and one root entry exist per pair. So a second ingress for
 *          one (S,G) is refused rather than given an entry of its own, and a
 *          caller seeing this on a group it does not know about is looking at
 *          the same stream arriving somewhere else.
 * -ENOSPC: no free group id, or the external hash table is full.
 * -ENOMEM: no memory for the group's own bookkeeping.
 * -EIO: an entry could not be built or the classifier refused the key.
 * On any error nothing is installed and *result is NULL.
 */
int cdx_mc_group_add(const struct cdx_mc_group_spec *spec,
		     struct cdx_mc_group **result);

/* Replace a group's listener set, keeping its key, its classifier entry and
 * its group id.
 *
 * This is what a join or a leave against an already-installed group becomes,
 * and it exists rather than being spelled as delete-then-add because those two
 * are not equivalent on the wire: between them the group's key is absent from
 * the classifier and its frames take the exception path, so every remaining
 * listener would see a gap because a different listener came or went. An IPTV
 * deployment changes membership whenever anyone changes channel, so that gap
 * would be the normal case rather than an edge one.
 *
 * What actually happens is a pointer swap. The root entry's REPLICATE opcode
 * names the head of the chain the microcode walks, so the new set is built
 * unpublished and then becomes the chain in one store; the key never leaves the
 * table. The old chain goes to the quarantine rather than being freed, because
 * a walk already under way can still be inside it.
 *
 * The spec's key must equal the installed one -- a caller with a new key wants
 * a new group. The same all-or-nothing rule as add: on failure the previously
 * installed listener set is still the one in hardware and nothing changed.
 */
int cdx_mc_group_replace(struct cdx_mc_group *group,
			 const struct cdx_mc_group_spec *spec);

/* Always consumes *group. Releases every listener entry, the classifier entry
 * and the group id, and drops the group's ingress MAC subscription. Storage
 * the microcode may still be walking goes through the same quarantine barrier
 * the legacy delete path uses rather than being freed directly.
 */
void cdx_mc_group_del(struct cdx_mc_group **group);

/* What the classifier counted for this group: frames matched on ingress, once
 * each, not once per replica. A caller reporting per-listener delivery wants
 * the port's own counters instead -- the replication happens below this entry
 * and nothing between here and the wire counts it separately.
 */
void cdx_mc_group_stats(const struct cdx_mc_group *group,
			struct cdx_ft_counters *stats);

#endif
