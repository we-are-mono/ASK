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
 * MC_MAX_LISTENERS_PER_GROUP, which sizes the group's member array. It is not
 * a hardware bound and nothing names
 * one: the programming path is a loop, one external-hash entry per listener,
 * threaded into the next. It is the backend's admission limit: a group with
 * more listeners stays in software. A bridged group gets one framing per
 * port, so on a five-port gateway it stays below the limit, but a routed group
 * reaches it through VLAN-distinct listeners on one port, and the rig does
 * (mroute_capacity.py). Eight is what has been measured, not the silicon's
 * maximum, so it should not be quietly raised by the caller that would first
 * depend on it.
 */
#define CDX_MC_MAX_LISTENERS	8

/* One listener: a physical CDX port and the tags this group's frames leave it
 * with, outermost first, in the order the wire carries them.
 *
 * A bridged listener's tags are not the port's own -- CDX keeps no VLAN
 * interface for the port and would describe none -- they are what the
 * bridge would have added on egress for this group's VLAN, which is a tag when
 * the port is a tagged member of it and nothing when the port is untagged.
 * Resolving that is the caller's, because it is a question about bridge
 * configuration and this side knows only ports.
 *
 * A listener is identified by its whole framing rather than by its device --
 * its port, its tags and, for a routed copy, the address it leaves with -- so
 * one port may appear twice in a group with different tags or addresses and
 * may not appear twice with the same ones. Two tagged copies out of one port
 * is what a gateway carrying several VLANs on one link replicates, and nothing
 * below this interface objects: each listener gets its own external-hash
 * entry, built from its own encapsulation and threaded into the chain by
 * pointer.
 */
struct cdx_mc_listener {
	struct net_device *dev;
	struct cdx_ft_vlan vlan[CDX_FT_VLAN_MAX];
	u8 vlans;
	/* A routed copy in a bridged group: one stream that a bridge forwards
	 * to some ports and the host routes to others is one classifier key,
	 * so it is one group, and its root preserves the hop count and keys on
	 * the frame's own Ethernet pair for the bridged copies. A routed copy
	 * therefore decrements the hop count in its own entry and leaves with
	 * `src_mac`, as a router's would. Meaningless in a routed group, whose
	 * root decrements for every copy and all of whose copies are routed. */
	bool routed;
	/* The address a routed copy leaves with: that of the device ipmr sends
	 * it through, which builds the copy's header there, and a bridge or a
	 * VLAN device on one forwards it unchanged. That is the port's own only
	 * when the device is the port -- a VLAN device can be given another,
	 * and a bridge carries one of its ports' or the one it was given -- so
	 * the caller, which knows the device, names it and nothing below
	 * falls back to the port's. Required, a unicast address, for every copy
	 * of a routed group and every routed copy of a bridged one; zero for a
	 * bridged copy, which keeps its sender's. */
	u8 src_mac[ETH_ALEN];
};

/* A group, described once and installed in one pass.
 *
 * A caller that watched the bridge's MDB already knows the whole port set, so
 * the group is described whole and there is no window in which a half-built
 * one is reachable.
 *
 * `src` is a specific sender and is never zero. The classifier composes
 * {portid, saddr, daddr, protocol} into an external *hash* table, so a masked
 * source cannot match -- a wildcard would change the hash rather than widen
 * it. A caller holding a (*,G) membership therefore has to learn a source
 * before it has a group to install; that is the traffic half of the learner,
 * not something this interface can paper over.
 *
 * Addresses are in network byte order, `family` selects the arm of each, and
 * the unused bytes of both are zero so whole specs compare bytewise.
 */
struct cdx_mc_group_spec {
	/* The physical port this group's frames arrive on. It is part of the
	 * classifier key rather than merely a validity check, so a stream of
	 * the same (S,G) arriving on a different port misses this entry, and
	 * may have an entry of its own; see cdx_mc_group_add(). */
	struct net_device *in;
	/* The tags this group's frames carry on `in`, outermost first, and
	 * the only ones the root accepts: it validates and strips exactly
	 * these, so the same key on another VLAN of the port -- untagged
	 * included -- is excepted to Linux rather than replicated as though it
	 * were this group's. The key itself names no VLAN, which is why this
	 * has to. Empty for a group that arrives untagged, which is also what
	 * a bridge's PVID resolves an untagged frame to. */
	struct cdx_ft_vlan in_vlan[CDX_FT_VLAN_MAX];
	u8 in_vlans;
	union nf_inet_addr src;
	union nf_inet_addr dst;
	/* A bridged group's frames' own Ethernet pair. The root is keyed on it
	 * in the bridged multicast table and every listener rebuilds Ethernet
	 * with it, because a bridge forwards a frame with the addresses it
	 * arrived with and the only way the hardware can know them is to have
	 * matched them. Required for a bridged group, zero for a routed one,
	 * whose copies each name the address they leave with. */
	u8 dst_mac[ETH_ALEN];
	u8 src_mac[ETH_ALEN];
	u8 family;
	u8 listeners;
	/* A bridge preserves IP hop counts and Ethernet addresses; a router
	 * decrements the one and rewrites the other. */
	bool bridged;
	/* No listener at all: the stream is dropped where it is matched rather
	 * than reach the CPU, as a bridge drops one its snooping says nobody
	 * wants. Bridged only, with `listeners` 0. The root keeps its key and
	 * counts what it drops, and a replace swaps listeners back in without
	 * the key leaving the table. */
	bool discard;
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

/* Whether this device is a CDX physical port, answerable from a notifier.
 *
 * The identity half of the test above, without the onif resolution that needs
 * the transaction and without the liveness that needs RTNL. It exists because
 * the MDB switchdev handler runs holding RTNL and so cannot take the
 * transaction at all, yet still has to decide whether to take a membership on
 * — see docs/flowtable/multicast.md. dpa_netdev_is_physical() answers under
 * its own lock, so this is safe from a notifier and from an RTNL holder.
 *
 * A caller that gets `true` here has not been promised the port will pass
 * cdx_mc_port_supported() later; a port can lose carrier, and that check is
 * the authoritative one.
 */
bool cdx_mc_port_identity(struct net_device *dev);

/* Install a group and return its opaque owner.
 *
 * Every listener is programmed or none is. A partially replicated group is a
 * silently broken one: the matched frame never reaches the bridge, so listeners
 * the hardware did not take on do not fall back to software -- they simply stop
 * receiving. The caller therefore gets an error and keeps the whole group in
 * software, where the bridge is still flooding it.
 *
 * Devices are borrowed. The ingress is kept: the group subscribes it to the
 * frames' destination MAC and unsubscribes through it when it is deleted, so
 * the caller pins it for as long as the group lives. A listener is read only
 * during the call that names it -- its port, framing and MTU go into its
 * entry, and its name into the query dump -- so the caller pins each for the
 * call, and replace() is a call like this one. Nothing here reads a listener's
 * device afterwards; the hardware names its port's queues, not the device.
 *
 * -EOPNOTSUPP: a device, address family or group address cannot be carried,
 *          a bridged group names no Ethernet pair to key on, a routed copy
 *          names no address to leave with, or a listener is named twice.
 * -EEXIST: another group holds this classifier key: the same ingress port and
 *          address pair and, for a bridged group, the same Ethernet pair. The
 *          ingress tags are not part of it -- the key names no VLAN -- so two
 *          groups that differ only there are one entry and the second is
 *          refused. The same (S,G) on another port, or from another sender
 *          into a bridge, is a different key and may be added.
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
 * table. A walk already under way can still be inside the old chain, so it is
 * freed only once the barrier that follows has completed, and goes to the
 * quarantine if that fails.
 *
 * The spec's key must equal the installed one -- a caller with a new key wants
 * a new group. The same all-or-nothing rule as add: on failure the previously
 * installed listener set is still the one in hardware and nothing changed.
 */
int cdx_mc_group_replace(struct cdx_mc_group *group,
			 const struct cdx_mc_group_spec *spec);

/* Always consumes *group. Releases every listener entry, the classifier entry
 * and the group id, and drops the group's ingress MAC subscription. Storage
 * the microcode may still be walking goes through the quarantine barrier
 * rather than being freed directly.
 */
void cdx_mc_group_del(struct cdx_mc_group **group);

/* How many groups added here are not yet deleted, whatever became of the
 * module that added them. Transaction held. */
unsigned int cdx_mc_group_count(void);

/* How many group ids of `family` are held, and in *slots, unless it is NULL,
 * how many the family has. Every group of the family holds one, whichever
 * caller added it -- the bridged and the routed groups draw on one space --
 * and an add that finds none free is refused with -ENOSPC. Transaction
 * held. */
unsigned int cdx_mc_group_ids(u8 family, unsigned int *slots);

/* What the classifier counted for this group: frames matched on ingress, once
 * each, not once per replica. A caller reporting per-listener delivery wants
 * the port's own counters instead -- the replication happens below this entry
 * and nothing between here and the wire counts it separately.
 *
 * Returns whether the counters were read. When they were not, *stats is zero,
 * which is no sample: a caller taking deltas from one would see a count gone
 * backwards, and one that re-bases on it would count the whole stream again.
 */
bool cdx_mc_group_stats(const struct cdx_mc_group *group,
			struct cdx_ft_counters *stats);

#endif
