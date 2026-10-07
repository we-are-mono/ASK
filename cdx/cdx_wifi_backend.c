// SPDX-License-Identifier: GPL-2.0-or-later
/* VAP registration for the flowtable adapter.
 *
 * Driven by a netdev, which is why the id is allocated here rather than
 * received and why every field comes off the device.
 */

#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/slab.h>
#include <net/net_namespace.h>

/* portdefs.h first, as cdx_ipsec_backend.c does: it reaches the SDK's
 * types_linux.h, whose TRUE and FALSE are unguarded, so anything that defines
 * them first turns that header into a redefinition error. */
#include "portdefs.h"
#include "cdx.h"
#include "cdx_flowtable_backend.h"
#include "cdx_wifi_backend.h"
#include "devman.h"
#include "dpa_wifi.h"
#include "globals.h"
#include "layer2.h"
#include "system.h"

/* Everything teardown needs, and deliberately not the device.
 *
 * VWD borrows rather than pins: vwd_vap_up() takes a reference, stores the
 * pointer in vap->wifi_dev and puts the reference back before it returns,
 * leaving its own netdev notifier to clear the pointer when the device
 * unregisters. Pinning here instead would not make that pointer safer and
 * would make unregistration impossible -- unregister_netdevice() waits for
 * every reference, and this one would not be dropped until a worker that runs
 * after unregistration dropped it.
 *
 * So the fields teardown reads are copied at registration: the id names the
 * VWD slot, the onif index names the logical interface (not derivable from the
 * id -- add_onif() picks the first free slot in its own table), and the name
 * is only what the handler logs. None of them is read back from the device,
 * which by then may be gone.
 */
struct cdx_wifi_vap {
	/* Compared against a netdev to refuse registering it twice, never
	 * dereferenced. Kept until the VAP is deleted, which can be after the
	 * device unregistered; the adapter does not offer a device reusing
	 * that address until then. */
	const struct net_device *dev;
	u32 itf_index;
	u16 vapid;
	char ifname[IFNAMSIZ];
};

/* Which ids are in use, and where the next search starts.
 *
 * Both are read and written only under the flowtable transaction, which every
 * entry point below asserts, so neither needs a lock of its own. That is the
 * same reasoning the SA cache uses, and for the same reason: an owner that
 * serialises all of its control-plane work through one mutex does not gain
 * anything from a second one guarding a table only that work touches.
 */
static struct cdx_wifi_vap *cdx_wifi_slot[MAX_WIFI_VAPS];
static u16 cdx_wifi_next_vapid;

/* Prefers a free slot that already carries its frame queues, and rotates
 * only among fresh ones.
 *
 * The id is not just an index here: it names a VWD slot whose 65 frame queues
 * are built on first open and kept until module exit, a physical_port at
 * PORT_WIFI_IDX + id, and a sysfs attribute. Rotating through the whole id
 * space before reusing any of it -- the first version of this -- meant every
 * hostapd restart or link bounce claimed a fresh slot and built its queues,
 * until all 32 slots held them: 2080 frame queues for a board with two VAPs,
 * each set built under RTNL. Reusing a built slot bounds that by the peak
 * number of VAPs alive at once.
 *
 * Handing a freed id back is safe because nothing resolves an id without
 * checking what it currently names: the dequeue path tests the slot's state
 * and device under vaplock, the encoder reaches a VAP only through a record
 * dpa_get_ifinfo_by_netdev() has confirmed VWD still owns, and entries that
 * named the old VAP were retired at NETDEV_GOING_DOWN, before the slot was
 * released.
 */
static int cdx_wifi_alloc_vapid(u16 *out)
{
	unsigned int tries;
	u16 cand;

	for (cand = 0; cand < MAX_WIFI_VAPS; cand++)
		if (!cdx_wifi_slot[cand] && dpaa_vwd_vap_built(cand)) {
			*out = cand;
			return 0;
		}
	for (tries = 0; tries < MAX_WIFI_VAPS; tries++) {
		cand = cdx_wifi_next_vapid++ % MAX_WIFI_VAPS;
		if (cdx_wifi_slot[cand])
			continue;
		*out = cand;
		return 0;
	}
	return -ENOSPC;
}

bool cdx_wifi_vap_supported(struct net_device *dev)
{
	if (!dev || !net_eq(dev_net(dev), &init_net))
		return false;
	/* The classifier finishes a frame by writing an ethernet header and
	 * enqueueing it, and vap_rx_fwd_pkt() hands the result to the device's
	 * ordinary transmit. A device that does not present that header has
	 * nothing for either half to write, so it is refused here. */
	if (dev->type != ARPHRD_ETHER || dev->addr_len != ETH_ALEN)
		return false;
	/* VWD owns the offline port a VAP's frames are classified against and
	 * the slot table the id comes from. It is brought up during cdx module
	 * init, before the adapter registers the notifier that calls this, so
	 * a false here means teardown has started rather than that the caller
	 * arrived too early. */
	return dpaa_vwd_ready();
}
EXPORT_SYMBOL_NS_GPL(cdx_wifi_vap_supported, ASK_CDX_FLOWTABLE);

int cdx_wifi_vap_add(struct net_device *dev, struct cdx_wifi_vap **result)
{
	struct physical_port *port;
	struct cdx_wifi_vap *vap;
	struct vap_cmd_s cmd;
	/* dev->dev_addr is const and the registration helpers below are not,
	 * so the address is taken once into a local rather than cast const
	 * away at three call sites. */
	u8 mac[ETH_ALEN];
	u16 vapid;
	int rc;

	cdx_ft_assert_held();
	ASSERT_RTNL();

	*result = NULL;
	if (!cdx_wifi_vap_supported(dev))
		return -EOPNOTSUPP;

	for (vapid = 0; vapid < MAX_WIFI_VAPS; vapid++)
		if (cdx_wifi_slot[vapid] && cdx_wifi_slot[vapid]->dev == dev)
			return -EEXIST;

	rc = cdx_wifi_alloc_vapid(&vapid);
	if (rc)
		return rc;

	vap = kzalloc(sizeof(*vap), GFP_KERNEL);
	if (!vap)
		return -ENOMEM;

	port = phy_port_get(PORT_WIFI_IDX + vapid);
	ether_addr_copy(mac, dev->dev_addr);

	/* The order is the one the failure handling below unwinds: the
	 * logical interface first because
	 * dpa_add_wlan_if() records its index, and the VWD slot last because
	 * it is the only step that publishes a pointer the datapath can
	 * reach. Nothing is visible to a classifier until the ADD returns. */
	if (!add_onif(dev->name, &port->itf, NULL,
		      IF_TYPE_WLAN | IF_TYPE_PHYSICAL)) {
		rc = -ENOSPC;
		goto err_free;
	}

	if (dpa_add_wlan_if(dev->name, &port->itf, vapid, mac)) {
		rc = -EIO;
		goto err_onif;
	}
	/* The port's own hardware address, which the encoder writes as the
	 * source of every frame leaving through this VAP. Read from the netdev
	 * for the reason the ethernet ports now are: a copy taken at
	 * registration is a copy that a later address change does not reach. */
	ether_addr_copy(port->mac_addr, mac);

	memset(&cmd, 0, sizeof(cmd));
	cmd.vapid = vapid;
	cmd.ifindex = dev->ifindex;
	strscpy((char *)cmd.ifname, dev->name, sizeof(cmd.ifname));
	ether_addr_copy(cmd.macaddr, mac);

	cmd.action = CONFIGURE;
	if (dpaa_vwd_vap_cmd(&cmd)) {
		rc = -EIO;
		goto err_onif;
	}

	cmd.action = ADD;
	if (dpaa_vwd_vap_cmd(&cmd)) {
		rc = -EIO;
		goto err_configured;
	}

	vap->dev = dev;
	vap->vapid = vapid;
	vap->itf_index = port->itf.index;
	strscpy(vap->ifname, dev->name, sizeof(vap->ifname));
	cdx_wifi_slot[vapid] = vap;
	*result = vap;
	return 0;

err_configured:
	/* Back to CLOSE, not merely un-added: the slot has to be reusable by a
	 * different device, and a CONFIGURE onto one still holding this
	 * device's name is refused. */
	cmd.action = RELEASE;
	dpaa_vwd_vap_cmd(&cmd);
err_onif:
	/* Releases the devman record with it. */
	remove_onif_by_index(port->itf.index);
err_free:
	kfree(vap);
	return rc;
}
EXPORT_SYMBOL_NS_GPL(cdx_wifi_vap_add, ASK_CDX_FLOWTABLE);

void cdx_wifi_vap_del(struct cdx_wifi_vap **vap)
{
	struct cdx_wifi_vap *v = *vap;
	struct vap_cmd_s cmd;

	cdx_ft_assert_held();
	ASSERT_RTNL();

	if (!v)
		return;
	*vap = NULL;

	/* Only cached fields: this runs after the device may have unregistered,
	 * and nothing here is allowed to follow that pointer. */
	memset(&cmd, 0, sizeof(cmd));
	cmd.vapid = v->vapid;
	strscpy((char *)cmd.ifname, v->ifname, sizeof(cmd.ifname));

	/* REMOVE fails when the slot is not open, which is the expected case
	 * for a device that has already unregistered: VWD's own notifier took
	 * the VAP down as the device went, leaving the slot configured. The
	 * RELEASE is what this call is really for in that case, and it is why
	 * neither return value is checked -- both orders reach CLOSE, which is
	 * the only postcondition that matters. */
	cmd.action = REMOVE;
	dpaa_vwd_vap_cmd(&cmd);
	cmd.action = RELEASE;
	dpaa_vwd_vap_cmd(&cmd);

	remove_onif_by_index(v->itf_index);

	cdx_wifi_slot[v->vapid] = NULL;
	kfree(v);
}
EXPORT_SYMBOL_NS_GPL(cdx_wifi_vap_del, ASK_CDX_FLOWTABLE);
