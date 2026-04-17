/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */


#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/random.h>
#include <linux/siphash.h>
#include "cdx.h"
#include "cdx_cmd_validator.h"
#include "control_bridge.h"
#include "misc.h"
#include "cdx_ioctl.h"
#include "cdx_common.h"

/* #define CONTROL_BRIDGE_DEBUG 1 */


/* l2 flow hash table */
struct flow_bucket l2flow_hash_table[NUM_BT_ENTRIES];

/* Per-boot random key for the l2flow hash. SipHash + this key
 * prevents an attacker who can choose flow keys (MACs, VLAN tags,
 * ethertype, session_id) from crafting colliding inputs to chain
 * a single bucket and DoS lookups. */
static hsiphash_key_t l2flow_hashkey __read_mostly;

/*
 * Concurrency:
 *   l2flow_hash_table[] (NUM_BT_ENTRIES buckets of hlist_head)
 *      - Mutated by M_bridge_cmdproc() on CMD_BRIDGE_L2FLOW_*
 *        commands and walked by l2flow_find_entry() from the same
 *        dispatcher and by query_Rx.c. LOCK-FREE on both sides
 *        today; a concurrent delete during a walk is UAF.
 *
 *        KNOWN GAP: adding a subsystem lock here requires matching
 *        walkers in query_Rx.c and any other reader paths in a
 *        single coordinated change. The attack surface is gated
 *        behind the cdx ioctl dispatch (CAP_NET_ADMIN, G1), so all
 *        callers today are trusted, but the race is real under
 *        concurrent ioctls.
 *   l2flow_hashkey (hsiphash_key_t)
 *      - Set once in bridge_init() via get_random_bytes(); never
 *        mutated at runtime. Lock-free reads are safe.
 *   L2Bridge_timeout
 *      - Set once at init; read at runtime; lock-free is fine.
 *
 * Contexts:
 *   bridge_init()        - module load.
 *   M_bridge_cmdproc()   - process, ioctl dispatcher.
 *   l2flow_*() helpers   - process, called under the dispatcher.
 */

/* flow timer infrastructure */
U32 L2Bridge_timeout;

#ifdef CONTROL_BRIDGE_DEBUG
static void display_flow_tuples(struct L2Flow *entry)
{
	printk("destmac: ");
	display_mac_addr(&entry->da[0]);
	printk("srcmac: ");
	display_mac_addr(&entry->sa[0]);
	printk("ethertype\t0x%x\n", entry->ethertype);
	printk("session id\t%d\n", entry->session_id);
	printk("svlan tag\t0x%x\n", entry->svlan_tag);
	printk("cvlan tag\t0x%x\n", entry->cvlan_tag);
}

static void display_flow_entry(struct L2Flow_entry *entry)
{
	printk("entry %p\ntuples:\n", entry);
	display_flow_tuples(&entry->l2flow);
	printk("last timer %d\n", entry->last_l2flow_timer);
	printk("output if %s\n", entry->out_ifname);
	printk("input if %s\n", entry->in_ifname);
	printk("status %d\n", entry->status);
	printk("hwflow %p\n", entry->ct);
}
#endif


static void l2flow_remove(struct L2Flow_entry *entry)
{
	U32 hash = entry->hash;

	cdx_timer_del(&entry->timer);
#ifdef CONTROL_BRIDGE_DEBUG
	display_flow_entry(entry);
#endif
	/* remove from hw tables */
	if (delete_l2br_entry_classif_table(entry)) {
		DPA_ERROR("%s::failed to remove entry\n",
				__func__);
		return;
	}
	l2flow_hash_table[hash].num_entries--;
#ifdef CONTROL_BRIDGE_DEBUG
	printk("%s::entry removed from flow table, count%d\n",
			__func__, l2flow_hash_table[hash].num_entries);
#endif
}

static int M_bridge_expire_l2_flow_entry(struct L2Flow_entry *entry)
{
	L2BridgeL2FlowEntryCommand *message;
	HostMessage *pmsg;

	// Send indication message
	pmsg = msg_alloc();
	if (!pmsg)
		goto err;

	message = (L2BridgeL2FlowEntryCommand *)pmsg->data;

	// Prepare indication message
	memset(message, 0 , sizeof(*message));
	message->action =  ACTION_REMOVED;
	/* Copy dest and src MAC addresses separately to avoid FORTIFY_SOURCE
	 * warning about writing 12 bytes into a 6-byte field */
	memcpy(message->destaddr, entry->l2flow.da, ETHER_ADDR_LEN);
	memcpy(message->srcaddr, entry->l2flow.sa, ETHER_ADDR_LEN);
	message->ethertype = entry->l2flow.ethertype;
	message->svlan_tag = entry->l2flow.svlan_tag;
	message->cvlan_tag = entry->l2flow.cvlan_tag;
	message->session_id = entry->l2flow.session_id;
#ifdef VLAN_FILTER
	message->vid = entry->l2flow.vid;
	message->vlan_flags = entry->l2flow.vlan_flags;
#endif
	pmsg->code = CMD_RX_L2BRIDGE_FLOW_ENTRY;
	pmsg->length = sizeof(*message);

	if (msg_send(pmsg) < 0)
		goto err;

	//l2flow_remove(entry);
	return 0;

err:
	printk("%s::err in msg send\n", __func__);
	entry->status |= L2_BRIDGE_TIMED_OUT;
	return 1;
}

static void br_timer_refresh(struct L2Flow_entry *pEntry)
{
	struct hw_ct *ct;
	if ((ct = pEntry->ct) != NULL)
	{
		hw_ct_get_active(ct);
		pEntry->last_l2flow_timer = (cdx_timer_t)ct->timestamp;
	}
}

cdx_timer_t br_get_time_remaining(struct L2Flow_entry *pEntry)
{
	cdx_timer_t latest_time;
	cdx_timer_t elapsed_time;
	TIMER_ENTRY *timer = &pEntry->timer;

	br_timer_refresh(pEntry);
	latest_time = pEntry->last_l2flow_timer; 
	elapsed_time = ct_timer - latest_time;	

	return elapsed_time >= timer->timerdata ? 0 : timer->timerdata - elapsed_time;
}

static void br_timer_update(struct L2Flow_entry *pEntry)
{
	TIMER_ENTRY *timer = &pEntry->timer;
	cdx_timer_t oldtimer = timer->timerdata;
	timer->timerdata =  L2Bridge_timeout;
	// Only update timer if first time or new period is less than old
	if (oldtimer == 0 || timer->timerdata < oldtimer)
	{
		cdx_timer_t newtimeout;
		if (oldtimer == 0)
			newtimeout = ct_timer + timer->timerdata;
		else
			newtimeout = timer->timeout - oldtimer + timer->timerdata;
		//DPRINT_ERROR("oldtimer=%u, timer->timerdata=%u, ct_timer=%u, newtimeout=%u\n", oldtimer, timer->timerdata, ct_timer, newtimeout);
		cdx_timer_del(timer);
		cdx_timer_add(timer, TIME_BEFORE(newtimeout, ct_timer) ? 1 : newtimeout - ct_timer);
	}
}



static int L2Bridge_timer(TIMER_ENTRY *timer)
{
	int rc;
	struct L2Flow_entry *entry = container_of(timer, typeof(struct L2Flow_entry), timer);

	//check activity bit from hw flow
	timer->period = br_get_time_remaining(entry);

	//if ((time_elapsed >= L2Bridge_timeout) || (entry->status & L2_BRIDGE_TIMED_OUT)) {
	if ( (timer->period == 0) || (entry->status & L2_BRIDGE_TIMED_OUT) )
	{
		rc = M_bridge_expire_l2_flow_entry(entry);
		if (rc == 0)
			return 0;

		printk("%s::M_bridge_expire_l2_flow_entry failed\n", __func__);		
		timer->period = 1;
	}
	return 1;
}


static struct L2Flow_entry *l2flow_find_entry(U32 hash, struct L2Flow *l2flow)
{
	struct L2Flow_entry *entry;

#ifdef CONTROL_BRIDGE_DEBUG
	printk("%s::entry hash %x flow table %p, head %p count %d\n",
			__func__, hash,
			&l2flow_hash_table[hash].flowlist,
			l2flow_hash_table[hash].flowlist.first,
			l2flow_hash_table[hash].num_entries);
#endif
	hlist_for_each_entry(entry, &l2flow_hash_table[hash].flowlist, node)
	{
		if (memcmp(l2flow, &entry->l2flow, sizeof(struct L2Flow)) == 0) 
			return entry;
	}
	return NULL;
}

static int l2flow_add(struct L2Flow_entry *entry, U32 hash)
{
	INIT_HLIST_NODE(&entry->node);
	entry->hash = hash;

	//add to hw table
	if (add_l2flow_to_hw(entry)) {
		return -1;
	}
	/* Add software entry to local hash */
	hlist_add_head(&entry->node, &l2flow_hash_table[hash].flowlist);
	//add time stamp to flow
	entry->last_l2flow_timer = ct_timer;
	//added entries to flow list
	l2flow_hash_table[hash].num_entries++;
#ifdef CONTROL_BRIDGE_DEBUG
	printk("%s::entry added to flow table %p head %p count %d\n",
			__func__, 
			&l2flow_hash_table[hash].flowlist,
			l2flow_hash_table[hash].flowlist.first,
			l2flow_hash_table[hash].num_entries);
#endif
	cdx_timer_init(&entry->timer, L2Bridge_timer);
	br_timer_update(entry);
	//cdx_timer_add(&entry->timer, L2Bridge_timeout);
	return 0;
}

static int l2flow_update(struct L2Flow_entry *entry, char *input_itf, char *output_itf, U32 hash)
{
	struct L2Flow_entry *new_entry;

	/*
	 * To update the l2flow, deleting the existing entry and updating the entry
	 * configuration and adding the entry(Here the change for update is input and
	 * output interfaces in entry). L2flow is distributed in different tables, not
	 * in single table, so it is not easy to update. This is the reason, instead of
	 * updating the l2flow deletting it and adding new one. 
	 */
	/* Copy the existing entry before removing it.*/
	new_entry = (struct L2Flow_entry *) kzalloc(sizeof(struct L2Flow_entry), GFP_KERNEL);
	if (new_entry == NULL) {
		printk("%s()::%d Failed to allocate memory.\n", __func__, __LINE__);
		return ERR_NOT_ENOUGH_MEMORY;
	}
	memcpy(&new_entry->l2flow, &entry->l2flow, sizeof(struct L2Flow));

	/*Remove the existing entry */
	l2flow_remove(entry);

	/*Update the input output interface names. */
	strncpy(&new_entry->out_ifname[0], output_itf, IF_NAME_SIZE);
	new_entry->out_ifname[IF_NAME_SIZE - 1] = '\0';
	strncpy(&new_entry->in_ifname[0], input_itf, IF_NAME_SIZE);
	new_entry->in_ifname[IF_NAME_SIZE - 1] = '\0';
	new_entry->last_l2flow_timer = ct_timer;
#ifdef CONTROL_BRIDGE_DEBUG
	printk("%s()::%d output iface <%s> input iface <%s>\n", __func__, __LINE__, &new_entry->out_ifname[0], &new_entry->in_ifname[0]);
#endif
	if (l2flow_add(new_entry, hash)) {
		printk("%s()::%d Failed to add entry hash %u.\n", __func__, __LINE__, hash);
		kfree(new_entry);
		return ERR_BRIDGE_ENTRY_ADD_FAILURE;
	}
#ifdef CONTROL_BRIDGE_DEBUG
	printk("entry added successfully hash %u.\n", hash);
#endif

	return 0;
}

static void l2flows_timeout_update(void)
{
	struct L2Flow_entry *entry;
	int hash_index = 0;

	for (hash_index = 0; hash_index < NUM_BT_ENTRIES; hash_index++)
	{
		if (l2flow_hash_table[hash_index].num_entries)
		{
			hlist_for_each_entry(entry, &l2flow_hash_table[hash_index].flowlist, node)
			{
				br_timer_update(entry);
			}
		}
	}

	return;
}

static int M_bridge_handle_l2flow(U16 *p, U16 Length)
{
	U16 ackstatus = CMD_OK;
	POnifDesc pOnif = NULL;
	POnifDesc pInif = NULL;
	U32 hash = 0;
	struct L2Flow l2flow;
	struct L2Flow_entry *l2flow_entry = NULL;
	char reset_action = 0;
	PL2BridgeL2FlowEntryCommand pcmd;

	if(Length != sizeof(L2BridgeL2FlowEntryCommand))
		return ERR_WRONG_COMMAND_SIZE;
	pcmd = (PL2BridgeL2FlowEntryCommand)p;

	if ((pcmd->action == ACTION_QUERY) || (pcmd->action == ACTION_QUERY_CONT))
		goto skip_fill;

	if (pcmd->proto) {
		printk("%s::l3 flows not supported now\n", __func__);
		return ERR_WRONG_COMMAND_PARAM;
	}
	//fill flow params from command
	memset(&l2flow, 0, sizeof(struct L2Flow));
	memcpy(&l2flow.da[0], pcmd->destaddr, 6);
	memcpy(&l2flow.sa[0], pcmd->srcaddr, 6);
	l2flow.ethertype = pcmd->ethertype;
	l2flow.session_id = pcmd->session_id;
	l2flow.svlan_tag = pcmd->svlan_tag;
	l2flow.cvlan_tag = pcmd->cvlan_tag;
#ifdef VLAN_FILTER
	l2flow.vid = pcmd->vid;
	l2flow.vlan_flags = pcmd->vlan_flags;
#endif

	//compute hash and check if this flow exists
	hash = hsiphash(&l2flow, sizeof(struct L2Flow), &l2flow_hashkey);
	hash &= NUM_BT_ENTRIES - 1;
	l2flow_entry = l2flow_find_entry(hash, &l2flow);
skip_fill:
	switch(pcmd->action) {
		case ACTION_REGISTER:
#ifdef CONTROL_BRIDGE_DEBUG
			printk("%s::ACTION_REGISTER\n", __func__);
#endif
			if (l2flow_entry) {
				printk("%s::flow exists, trying to add again\n", __func__);
				ackstatus = ERR_BRIDGE_ENTRY_ALREADY_EXISTS;
				goto func_ret;
			}
			//allocate new entry if it is register action
			l2flow_entry = (struct L2Flow_entry *)
				kzalloc(sizeof(struct L2Flow_entry), GFP_KERNEL);
			if (l2flow_entry == NULL) {
				ackstatus = ERR_NOT_ENOUGH_MEMORY;
				goto func_ret;
			}
			if((pOnif = get_onif_by_name(pcmd->output_name)) == NULL) {
				kfree(l2flow_entry);
				ackstatus = ERR_UNKNOWN_INTERFACE;
				goto func_ret;
			}
			if ((pInif = get_onif_by_name(pcmd->input_name)) == NULL) {
				kfree(l2flow_entry);
				ackstatus = ERR_UNKNOWN_INTERFACE;
				goto func_ret;
			}
			strscpy(l2flow_entry->out_ifname, pcmd->output_name,
					sizeof(l2flow_entry->out_ifname));
			strscpy(l2flow_entry->in_ifname, pcmd->input_name,
					sizeof(l2flow_entry->in_ifname));
			memcpy(&l2flow_entry->l2flow, &l2flow, sizeof(struct L2Flow));
			l2flow_entry->last_l2flow_timer = ct_timer;
			//TODO: add mark / qos code back in
			//l2flow_entry->mark = pcmd->mark;
#ifdef CONTROL_BRIDGE_DEBUG
			printk("%s::output_name %s\n", __func__,
					pcmd->output_name);
			printk("%s::input_name %s\n", __func__,
					pcmd->input_name);
#endif
			if (l2flow_add(l2flow_entry, hash)) {
				ackstatus = ERR_BRIDGE_ENTRY_ADD_FAILURE;
				kfree(l2flow_entry);
				goto func_ret;
			}
			break;

		case ACTION_UPDATE:
			//l2flow_entry->mark = pcmd->mark;
#ifdef CONTROL_BRIDGE_DEBUG
			printk("%s::ACTION_UPDATE\n", __func__);
#endif
			if (!l2flow_entry) {
				ackstatus = ERR_BRIDGE_ENTRY_NOT_FOUND;
				goto func_ret;
			}
			if((pOnif = get_onif_by_name(pcmd->output_name)) == NULL) {
				ackstatus = ERR_UNKNOWN_INTERFACE;
				goto func_ret;
			}
			if ((pInif = get_onif_by_name(pcmd->input_name)) == NULL) {
				ackstatus = ERR_UNKNOWN_INTERFACE;
				goto func_ret;
			}
			ackstatus = l2flow_update(l2flow_entry, pcmd->input_name, pcmd->output_name, hash);
			break;

		case ACTION_DEREGISTER:
#ifdef CONTROL_BRIDGE_DEBUG
			printk("%s::ACTION_DEREGISTER\n", __func__);
#endif
			if (!l2flow_entry) {
#ifdef CONTROL_BRIDGE_DEBUG
				printk("%s::ACTION_DEREGISTER flow not found\n", __func__);
#endif
				ackstatus = ERR_BRIDGE_ENTRY_NOT_FOUND;
				goto func_ret;
			}
			l2flow_remove(l2flow_entry);
			break;

		case ACTION_QUERY:
			reset_action = 1;
			fallthrough;
		case ACTION_QUERY_CONT:
			ackstatus = rx_Get_Next_Hash_L2FlowEntry(pcmd, reset_action);
			return ackstatus;
		default:
			ackstatus = ERR_UNKNOWN_ACTION;
			break;
	}//End switch
func_ret:
	return ackstatus;
}

static int M_bridge_handle_control(U16 code, U16 *p, U16 Length)
{
	U16 ackstatus = CMD_OK;
	PL2BridgeControlCommand prsp = (PL2BridgeControlCommand)p;

	switch (code) {
		case CMD_RX_L2BRIDGE_FLOW_TIMEOUT: 
			{
				U32 timeout;

				timeout = (prsp->mode_timeout * HZ);
				if (L2Bridge_timeout != timeout) {
					L2Bridge_timeout = timeout;
#ifdef CONTROL_BRIDGE_DEBUG
					printk("%s::timeout changed to %d\n", __func__, 
							timeout/HZ);
#endif
					/* Updating all the l2flows timeout */
					l2flows_timeout_update();
				}
				break;
			}

		case CMD_RX_L2BRIDGE_MODE:
			if (prsp->mode_timeout != L2_BRIDGE_MODE_AUTO) {
				printk("%s::manual mode not supported\n", __func__);
				ackstatus = ERR_WRONG_COMMAND_PARAM;
			}
			break;

		default:
			ackstatus = ERR_UNKNOWN_COMMAND;
			break;
	}
	return ackstatus;
}

/* This function sets the bridged status of interface
	 (if its part of bridged or not and its corresponding bridge
	 mac address */
static int M_bridged_itf_update(U16 code, U16 *p, U16 Length)
{
	pBridgedItfCommand br_cmd = (pBridgedItfCommand)p;
	int ret;

	ret = dpa_set_bridged_itf(br_cmd->ifname, br_cmd->is_bridged, br_cmd->br_macaddr);
	if (ret < 0)
		return ERR_UNKNOWN_INTERFACE;	

	return CMD_OK;
}

/*
 * CMD_RX_L2BRIDGE_{ENABLE,ADD,REMOVE,QUERY_STATUS,FLOW_RESET}: the
 * old cmdproc just `break`'d for these, so the reply is status-only
 * with CMD_OK (= NO_ERR = 0). Preserve exactly. No length check in
 * the old code either -> CDX_CMD_VAR(0, U16_MAX).
 */
static U16 bridge_noop_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	(void)pcmd;
	(void)cmd_len;
	(void)out_reply_len;
	return NO_ERR;
}

/*
 * CMD_RX_L2BRIDGE_QUERY_ENTRY: old cmdproc always wrote
 * L2BridgeQueryEntryResponse{eof=1} into pcmd and returned
 * acklen = sizeof(L2BridgeQueryEntryResponse), ackstatus = CMD_OK.
 * The dispatcher stamps pcmd[0] = NO_ERR after this handler, which
 * overwrites the eof byte's low U16 slot — but the old code did
 * the exact same thing via *p = ackstatus after writing prsp->eof,
 * so the net wire layout is identical.
 */
static U16 bridge_query_entry_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	PL2BridgeQueryEntryResponse prsp = (PL2BridgeQueryEntryResponse)pcmd;

	(void)cmd_len;
	prsp->eof = 1;
	*out_reply_len = sizeof(L2BridgeQueryEntryResponse);
	return NO_ERR;
}

/*
 * CMD_RX_L2BRIDGE_FLOW_ENTRY: action snapshot at entry; query-
 * success reply uses the VLAN/IPv4-style sizeof(U16) + sizeof(
 * L2BridgeL2FlowEntryCommand) layout (NOT the PPPoE/tunnel
 * sizeof(struct) layout). Inner handler's own length check
 * enforces exact sizeof(L2BridgeL2FlowEntryCommand).
 */
static U16 bridge_flow_entry_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	U16 action = *(U16 *)pcmd;
	U16 rc = (U16)M_bridge_handle_l2flow(pcmd, cmd_len);

	if (rc == NO_ERR && (action == ACTION_QUERY || action == ACTION_QUERY_CONT))
		*out_reply_len = sizeof(U16) + sizeof(L2BridgeL2FlowEntryCommand);
	return rc;
}

/*
 * M_bridge_handle_control takes cmd_code as an argument — old
 * cmdproc passed the matching code through. Split into two
 * wrappers here because the dispatcher doesn't forward cmd_code.
 * Neither the old cmdproc nor the inner handler length-checks
 * these, so CDX_CMD_VAR(0, U16_MAX) preserves behavior.
 */
static U16 bridge_flow_timeout_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	(void)out_reply_len;
	return (U16)M_bridge_handle_control(CMD_RX_L2BRIDGE_FLOW_TIMEOUT, pcmd, cmd_len);
}

static U16 bridge_mode_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	(void)out_reply_len;
	return (U16)M_bridge_handle_control(CMD_RX_L2BRIDGE_MODE, pcmd, cmd_len);
}

static U16 bridged_itf_update_handle(void *pcmd, U16 cmd_len, U16 *out_reply_len)
{
	(void)out_reply_len;
	return (U16)M_bridged_itf_update(CMD_BRIDGED_ITF_UPDATE, pcmd, cmd_len);
}

static const struct cdx_cmd_spec bridge_cmd_table[] = {
	CDX_CMD_VAR(CMD_RX_L2BRIDGE_ENABLE,       0, U16_MAX, NULL, bridge_noop_handle),
	CDX_CMD_VAR(CMD_RX_L2BRIDGE_ADD,          0, U16_MAX, NULL, bridge_noop_handle),
	CDX_CMD_VAR(CMD_RX_L2BRIDGE_REMOVE,       0, U16_MAX, NULL, bridge_noop_handle),
	CDX_CMD_VAR(CMD_RX_L2BRIDGE_QUERY_STATUS, 0, U16_MAX, NULL, bridge_noop_handle),
	CDX_CMD_VAR(CMD_RX_L2BRIDGE_FLOW_RESET,   0, U16_MAX, NULL, bridge_noop_handle),
	CDX_CMD_VAR(CMD_RX_L2BRIDGE_QUERY_ENTRY,  0, U16_MAX, NULL, bridge_query_entry_handle),
	CDX_CMD    (CMD_RX_L2BRIDGE_FLOW_ENTRY,   L2BridgeL2FlowEntryCommand, bridge_flow_entry_handle),
	CDX_CMD_VAR(CMD_RX_L2BRIDGE_FLOW_TIMEOUT, 0, U16_MAX, NULL, bridge_flow_timeout_handle),
	CDX_CMD_VAR(CMD_RX_L2BRIDGE_MODE,         0, U16_MAX, NULL, bridge_mode_handle),
	CDX_CMD_VAR(CMD_BRIDGED_ITF_UPDATE,       0, U16_MAX, NULL, bridged_itf_update_handle),
};

static U16 M_bridge_cmdproc(U16 cmd_code, U16 cmd_len, U16 *p)
{
#ifdef CONTROL_BRIDGE_DEBUG
	printk("%s::cmd code %x p %p\n", __func__, cmd_code, p);
#endif
	return cdx_dispatch_cmd(bridge_cmd_table, ARRAY_SIZE(bridge_cmd_table),
				cmd_code, cmd_len, p);
}



int bridge_interface_deregister( U16 phy_port_id )
{
	printk(KERN_CRIT "%s\n", __func__);
	return 0;
}

int bridge_interface_register( uint8_t *name, U16 phy_port_id )
{

	printk(KERN_CRIT "%s\n", __func__);
	return 0;
}

static int  M_bridge_handle_reset(void)
{
	U16 ackstatus = CMD_OK;
	printk("%s::implement this\n", __func__);
	return ackstatus;
}

int bridge_init(void)
{
	int i;
	set_cmd_handler(EVENT_BRIDGE, M_bridge_cmdproc);
	L2Bridge_timeout = L2_BRIDGE_DEFAULT_TIMEOUT * HZ;
	get_random_bytes(&l2flow_hashkey, sizeof(l2flow_hashkey));
	for (i = 0; i < NUM_BT_ENTRIES; i++)
		INIT_HLIST_HEAD(&l2flow_hash_table[i].flowlist);
	return 0;
}

void bridge_exit(void)
{
	M_bridge_handle_reset();
}

