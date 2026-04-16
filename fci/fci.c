/*
 *
 *  Copyright (C) 2007 Mindspeed Technologies, Inc. 
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

#include <linux/socket.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <linux/timer.h>
#include <linux/time.h>
#include <net/net_namespace.h>
#include "fci.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mindspeed Technologies");
MODULE_DESCRIPTION("Fast Control Interface");

static char __initdata fci_version[] = "0.04";

/* Statics functions prototypes */
static int fci_fe_inbound_parser(FCI_MSG *fci_msg, FCI_MSG *fci_rep);
static int fci_fe_register(void);
static void fci_fe_unregister(void);

static void __fci_fe_inbound_data(struct sk_buff *skb);

static int fci_type_to_nl_type (int fci_nl_type);
static int fci_fe_init(void);
static void fci_fe_exit(void);

static int fci_outbound_fe_data(unsigned short fcode, unsigned short len, unsigned short *payload);

/*
 * Concurrency:
 *   this_fci (file-scope pointer)
 *      - Allocated once in fci_init() during module load, freed
 *        once in fci_exit() at module unload. No runtime
 *        mutation. this_fci->fci_nl_sock[] is set during init,
 *        released at exit.
 *   this_fci->stats.*
 *      - Counters bumped from the netlink inbound callback and
 *        from outbound paths. Not protected by any lock - a
 *        concurrent bump on two CPUs may lose one increment.
 *        These are non-critical statistics, so the race is
 *        acceptable; a reader of stats via the proc entry may
 *        likewise see a value slightly behind reality.
 *
 * Contexts:
 *   __fci_fe_inbound_data                - netlink rx callback
 *                                          (process, from netlink
 *                                          worker).
 *   fci_outbound_{unicast,multicast,err} - process, caller-driven.
 *   fci_proc_*                           - process, /proc read.
 *   fci_fe_init/exit                     - module load/unload.
 */
static FCI *this_fci;


/************************** COMMON FUNCTIONS *********************************/

/*
 * fci_init -
 *
 *
 */
static int fci_init(void)
{
	int rc;

	if ((this_fci = kmalloc (sizeof (FCI), GFP_KERNEL)) == NULL)
	{
		printk(KERN_ERR "FCI: out of memory (%zu)\n", sizeof (FCI));

//		this_fci->stats.mem_alloc_err++;
		rc = -ENOMEM;
		goto err0;
	}

	/* zeroed the fci main structure */
	memset(this_fci, 0, sizeof(FCI));

	/* Initialize Fast Forward support in FCI */
	if((rc = fci_fe_init()) < 0)
	{
		printk(KERN_ERR "FCI: fci_fe_init() failed\n");
		goto err1;
	}
	
	/* Open others required sockets here */

	return 0;

err1:
	kfree(this_fci);
err0:
	return rc;
}


static void fci_exit(void)
{
	fci_fe_exit();

	kfree(this_fci);
}

/*
 * fci_open_netlink -
 *
 * Create new NETLINK socket for the given protocol 
 */
static int fci_open_netlink (unsigned long proto)
{

	FCI_PRINTK(FCI_NL, "fci_open_netlink() FCI type %ld\n", proto);

	if(proto == FCI_NL_FF)
	{
		struct netlink_kernel_cfg cfg = {
			.input	= __fci_fe_inbound_data,
			.groups	= 1,
		};

		if((this_fci->fci_nl_sock[FCI_NL_FF] = netlink_kernel_create (&init_net, NETLINK_FF, &cfg)) == 0)
		{
			this_fci->stats.kernel_create_err++;

			return -ENOMEM;
		}
	}
	else
	{
		this_fci->stats.unknown_sock_type++;

		return -ESOCKTNOSUPPORT;
	}

	return 0;
}

static void fci_close_netlink (unsigned long proto)
{
	/* release netlink socket */
	netlink_kernel_release(this_fci->fci_nl_sock[proto]);
}

/*
 * fci_outbound_unicast -
 *
 * This callback is invoked whenever the kernel space sends
 * message to the user space.
 */
static void fci_outbound_unicast(int nl_type, struct sk_buff *skb, u32 pid)
{
	FCI_PRINTK(FCI_OUTBOUND, "%s: size=%d bytes, FCI nl_sock_type %d pid %u\n", __func__, skb->len, fci_type_to_nl_type(nl_type), pid);

	NETLINK_CB(skb).portid = 0;	/* from kernel */

	/* unicast */
	NETLINK_CB(skb).dst_group = 0;	
	
	/* send message to user space process */
	netlink_unicast (this_fci->fci_nl_sock[nl_type], skb, pid, MSG_DONTWAIT);

	/* Update sucess stats */
	this_fci->stats.tx_msg++;

	this_fci->stats.sock_stats[nl_type].tx_msg++;
}

/*
 * fci_outbound_multicast -
 *
 * This callback is invoked whenever the kernel space sends
 * message to the user space.
 */
static int fci_outbound_multicast(int nl_type, struct sk_buff *skb, int group)
{
	gfp_t allocation = in_interrupt() ? GFP_ATOMIC : GFP_KERNEL;
	int rc = 0;

	FCI_PRINTK(FCI_OUTBOUND, "%s: size=%d bytes, FCI nl_sock_type %d group %x\n", __func__, skb->len, fci_type_to_nl_type(nl_type), group);

	NETLINK_CB(skb).portid = 0;	/* from kernel */

	/* send message only if at least one user space client is listening the socket */
	if (netlink_has_listeners(this_fci->fci_nl_sock[nl_type], group))
	{
		/* the group we want to talk to */
		NETLINK_CB(skb).dst_group = group;
	
		/* send message all user space listeners */
		rc = netlink_broadcast(this_fci->fci_nl_sock[nl_type], skb, 0, group, allocation);
		if (rc < 0)
		{
			if (printk_ratelimit())
				printk(KERN_ERR "FCI: netlink_broadcast() failed (rc=%d)\n", rc);
	
			goto err_exit;
		}
	}
	else
	{
		/* this skb has not been used */
		kfree_skb(skb);
	}

	/* Update sucess stats */
	this_fci->stats.tx_msg++;

	this_fci->stats.sock_stats[nl_type].tx_msg++;

	return 0;

err_exit:
	/* Update error stats */
	this_fci->stats.tx_msg_err++;

	this_fci->stats.sock_stats[nl_type].tx_msg_err++;
	
	return rc;
}

/*
 * fci_outbound_err -
 *
 * This callback is invoked whenever the kernel space sends
 * message to the user space.
 */
static void fci_outbound_err(int nl_type, struct sk_buff *skb, u32 pid, struct nlmsghdr *nlh, int err)
{
	struct nlmsgerr *errmsg;
	struct nlmsghdr *rep;

	FCI_PRINTK(FCI_OUTBOUND, "%s: size=%d bytes, FCI nl_sock_type %d pid %u\n", __func__, skb->len, fci_type_to_nl_type(nl_type), pid);

	rep = __nlmsg_put(skb, pid, nlh->nlmsg_seq,
			NLMSG_ERROR, sizeof(struct nlmsgerr), 0);

	errmsg = nlmsg_data(rep);
	errmsg->error = err;
	memcpy(&errmsg->msg, nlh, err ? nlh->nlmsg_len : sizeof(*nlh));

	NETLINK_CB(skb).portid = 0;	/* from kernel */

	/* unicast */
	NETLINK_CB(skb).dst_group = 0;	
	
	/* send message to user space process */
	netlink_unicast (this_fci->fci_nl_sock[nl_type], skb, pid, MSG_DONTWAIT);

	/* Update sucess stats */
	this_fci->stats.tx_msg++;

	this_fci->stats.sock_stats[nl_type].tx_msg++;
}


/*
 * fci_type_to_nl_type -
 *
 *
 */
static int fci_type_to_nl_type (int fci_nl_type)
{
	int nl_type;

	switch (fci_nl_type)
	{
	case FCI_NL_FF:
		nl_type = NETLINK_FF;
		break;

	default:
		nl_type = -1;
		break;
	}

	return nl_type;
}



/****************************** Fast Forward Support ********************************/

/*
 * fci_fe_init -
 *
 *
 */
static int fci_fe_init(void)
{
	int rc;

	/* Create netlink socket for Fast Forward */
	if((rc = fci_open_netlink((unsigned long) FCI_NL_FF)) < 0)
	{
		printk(KERN_ERR "FCI: fci_open_netlink() failed (FCI type %d)\n", FCI_NL_FF);
		goto err0;
	}

	/* Connect to the Forward Engine */
	if((rc = fci_fe_register()) < 0)
	{
		printk(KERN_ERR "FCI: fci_fe_register() failed\n");	
		goto err1;
	}

	return 0;

err1:
	fci_close_netlink(FCI_NL_FF);
err0:
	return rc;
}

/*
 * fci_fe_exit -
 *
 *
 */
static void fci_fe_exit(void)
{
	fci_fe_unregister();
	fci_close_netlink(FCI_NL_FF);
}


/*
 * fci_fe_register -
 *
 */
static int fci_fe_register(void)
{
	int rc;
	/* register the FCI module to the FPP Forward Engine */
	if((rc = comcerto_fpp_register_event_cb((void *)fci_outbound_fe_data)) < 0)
	{
		printk(KERN_ERR "FCI: fpp_register_event_cb() failed !\n");

		return rc;
	}
	return 0;
}

/*
 * fci_fe_unregister -
 *
 */
static void fci_fe_unregister(void)
{
	/* disconect FCI module from the FPP Forward Engine */
	comcerto_fpp_register_event_cb(NULL);
}

/*
 * fci_alloc_msg - allocates a skb suitable for containing a FCI netlink message
 *
 */
static struct sk_buff *fci_alloc_msg(void)
{
	struct sk_buff *skb;
	gfp_t flags = in_interrupt() ? GFP_ATOMIC : GFP_KERNEL;

	skb = nlmsg_new(FCI_MSG_SIZE, flags);
	if (!skb)
	{
		printk(KERN_ERR "FCI: nlmsg_new() failed\n");

		this_fci->stats.mem_alloc_err++;

		goto err;
	}

	return skb;

err:
	return NULL;
}

/*
 * fci_outbound_fe_data -
 *
 * This callback is invoked whenever the forward engine sends
 * message to the user space.
 */
static int fci_outbound_fe_data(u16 fcode, u16 len, u16 *payload)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	FCI_MSG *fci_msg;
	int rc;

	FCI_PRINTK(FCI_OUTBOUND, "\nFCI: fci_outbound_fe_data()\n");

	skb = fci_alloc_msg();
	if (!skb)
	{
		this_fci->stats.rx_msg_err++;
		rc = -ENOMEM;
		goto err;
	}

	nlh = nlmsg_put(skb, 0, 0, 0, len + FCI_MSG_HDR_SIZE, 0);

	fci_msg = nlmsg_data(nlh);

	fci_msg->fcode = fcode;
	fci_msg->length = len;

	/* build fci message with sender's data */
	memcpy(fci_msg->payload, payload, len);

	/* pass data to the netlink subsystem */
	return fci_outbound_multicast(FCI_NL_FF, skb, NL_FF_GROUP);

err:
	return rc;
}

/*
 * __fci_fe_inbound_data -
 *
 * This callback is invoked whenever the user space sends a netlink
 * message of the NETLINK_FF protocol type to the kernel.
 */
static void __fci_fe_inbound_data(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	struct nlmsghdr *rep;
	struct sk_buff *nskb;
	FCI_MSG *fci_msg, *fci_rep;
	int rc;
	size_t payload_bytes;

	FCI_PRINTK(FCI_INBOUND, "FCI: %s\n", __func__);

	/* Trust skb->len as the authoritative size; the sender's
	 * nlmsg_len can be set to the aligned value (NLMSG_ALIGN)
	 * while the actual skb carries only the unaligned payload,
	 * which libfci does by convention. The real OOB risk is
	 * fci_msg->length claiming more payload than the skb
	 * carries, so validate that directly against skb->len
	 * rather than the sender-supplied nlmsg_len. */
	if (skb->len < NLMSG_LENGTH(FCI_MSG_HDR_SIZE)) {
		this_fci->stats.rx_msg_err++;
		return;
	}
	nlh = nlmsg_hdr(skb);

	fci_msg = nlmsg_data(nlh);
	payload_bytes = skb->len - NLMSG_LENGTH(FCI_MSG_HDR_SIZE);
	if (fci_msg->length > FCI_MSG_MAX_PAYLOAD ||
	    fci_msg->length > payload_bytes) {
		this_fci->stats.rx_msg_err++;
		return;
	}

	this_fci->stats.rx_msg++;

	this_fci->stats.sock_stats[FCI_NL_FF].rx_msg++;

	nskb = fci_alloc_msg();
	if (nskb)
	{
		rep = nlmsg_put(nskb, NETLINK_CB(skb).portid, nlh->nlmsg_seq, 0, 0, 0);

		fci_rep = nlmsg_data(rep);

		/* Process command received from User Space */
		rc = fci_fe_inbound_parser(fci_msg, fci_rep);
		if (rc < 0)
		{
			nlmsg_cancel(nskb, rep);
			fci_outbound_err(FCI_NL_FF, nskb, NETLINK_CB(skb).portid, nlh, rc);
			this_fci->stats.rx_msg_err++;
		}
		else
		{
			skb_put(nskb, FCI_MSG_HDR_SIZE + fci_rep->length);
			nlmsg_end(nskb, rep);
			fci_outbound_unicast(FCI_NL_FF, nskb, NETLINK_CB(skb).portid);
		}
	}
	else
	{
		this_fci->stats.rx_msg_err++;
	}
}


/*
 * fci_fe_inbound_parser -
 *
 *
 */
static int fci_fe_inbound_parser(FCI_MSG *fci_msg, FCI_MSG *fci_rep)
{
	int rc = 0;

	FCI_PRINTK(FCI_INBOUND, "FCI: fci_fe_inbound_parser()\n");

	fci_rep->length = 0;
	rc = comcerto_fpp_send_command(fci_msg->fcode, fci_msg->length, fci_msg->payload, &fci_rep->length, fci_rep->payload);

	if (fci_rep->length > FCI_MSG_MAX_PAYLOAD)
		fci_rep->length = FCI_MSG_MAX_PAYLOAD;

	fci_rep->fcode = fci_msg->fcode;

	return rc;
}

/***************************** MISCS FUNCTIONS ********************************/

static int fci_proc_single_open(struct seq_file *m, void *v)
{
	seq_printf(m, "\n");
	seq_printf(m, "FCI Messages:\n");
	seq_printf(m, "Sent:%ld\n", this_fci->stats.tx_msg);
	seq_printf(m, "Received:%ld\n", this_fci->stats.rx_msg);
	seq_printf(m, "Sent errors:%ld\n", this_fci->stats.tx_msg_err);
	seq_printf(m, "Received errors:%ld\n", this_fci->stats.rx_msg_err);
	seq_printf(m, "\n");
	seq_printf(m, "Fast Forward Messages:\n");
	seq_printf(m, "Sent:%ld\n", this_fci->stats.sock_stats[FCI_NL_FF].tx_msg);
	seq_printf(m, "Received:%ld\n", this_fci->stats.sock_stats[FCI_NL_FF].rx_msg);
	seq_printf(m, "Sent errors:%ld\n", this_fci->stats.sock_stats[FCI_NL_FF].tx_msg_err);
	seq_printf(m, "Received errors:%ld\n", this_fci->stats.sock_stats[FCI_NL_FF].rx_msg_err);
	seq_printf(m, "\n");

	seq_printf(m, "\n");
	seq_printf(m, "Errors:\n");
	seq_printf(m, "Memory allocation errors:%ld\n", this_fci->stats.mem_alloc_err);
	seq_printf(m, "Kernel socket creation errors:%ld\n", this_fci->stats.kernel_create_err);
	seq_printf(m, "Unknow socket type:%ld\n", this_fci->stats.unknown_sock_type);

	return 0;

}

static int fci_proc_open(struct inode *inode, struct  file *file)
{
	return single_open(file, fci_proc_single_open, NULL);
}

static const struct proc_ops fci_proc_fops = {
	.proc_open = fci_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};
/*
 * fci_module_init -
 *
 */
static int fci_module_init(void)
{
	int rc;

	FCI_PRINTK(FCI_INIT, "Initializing Fast Control Interface v%s\n", fci_version);

	if((rc = fci_init()) < 0)
	{
		printk(KERN_ERR "FCI: fci init failed\n");
	
		return rc;
	}

	/* Create /proc/fci entry */
	proc_create("fci", 0444, NULL, &fci_proc_fops);

	return 0;
}


/*
 * fci_module_exit -
 *
 */
static void fci_module_exit(void)
{
	FCI_PRINTK(FCI_INIT, "Unloading Fast Control Interface\n");

	/* Remove /proc/fci entry */
	remove_proc_entry("fci", NULL);

	/* clean-up before leaving */
	fci_exit();
}


module_init(fci_module_init);
module_exit(fci_module_exit);
