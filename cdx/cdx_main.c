/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017-2018,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

//uncomment to start dpa_app from cdx module
#define START_DPA_APP 1

/*
 * Minimum FMAN microcode package the ASK data path requires.
 * Matches ASK_UCODE_PACKAGE_NUMBER in sdk_fman fm_common.h.
 */
#define CDX_MIN_FW_PACKAGE 209

/*
 * Concurrency (module-level):
 *   cdx_info->ctrl.mutex
 *      - Module-global mutex covering the subsystem init/exit
 *        sequence here, the flowtable transaction (see
 *        cdx_flowtable_backend.c) and the timer wheels (see
 *        cdx_timer.c — the timer kthread and every wheel mutator
 *        take this same mutex; there is no separate wheel spinlock).
 *   cdx_info->ctrl.timer_thread
 *      - kthread started under ctrl->mutex in cdx_ctrl_init;
 *        consumes the timer wheels under ctrl->mutex.
 *   deinit_fn[], init_level
 *      - Written only during module init (single-threaded) and
 *        read only at unload; no runtime concurrency.
 *
 * Contexts:
 *   cdx_module_{init,exit}  - module load/unload, single-threaded.
 *   cdx_ctrl_{init,deinit}  - called from module init/exit.
 */
#define DEFINE_GLOBALS
#include "portdefs.h"
#include <linux/rtnetlink.h>
#include <linux/delay.h>
#include "cdx.h"
#include "cdx_flowtable.h"
#include "cdx_htb.h"
#include "control_tx.h"
#include "module_qm.h"
#include "control_ipsec.h"
#include "dpa_control_mc.h"
#include "dpa_ipsec.h"

#ifdef CDX_DEBUG_KEY_ZEROING
/* H2 regression tripwire — see cdx_dpa_ipsec.c for design rationale.
 * Forward-declared here so cdx_main.c does not need to pull in the
 * full cdx_dpa_ipsec.h surface (which references types not in scope
 * at this point in the include order).
 */
int  cdx_ipsec_init_key_zeroing_probe(void);
void cdx_ipsec_remove_key_zeroing_probe(void);
#endif

#ifdef CDX_DEBUG_MC_HCSYNC_FAIL
/* Multicast HC-sync fault-injection knob — see dpa_control_mc.c for
 * design rationale. Forward-declared for the same reason as above:
 * dpa_control_mc.h needs types this translation unit has not pulled in
 * at this point in the include order.
 */
int  cdx_mc_init_hcsync_fail_probe(void);
void cdx_mc_remove_hcsync_fail_probe(void);
#endif

#ifdef CDX_DEBUG_SPLIT_KEY_FAIL
/* IPsec split-key fault-injection knob - see cdx_dpa_ipsec.c for design
 * rationale. Forward-declared for the include-order reason above.
 */
int  cdx_ipsec_init_split_key_fail_probe(void);
void cdx_ipsec_remove_split_key_fail_probe(void);
#endif

/* Quarantine terminal disposition (cdx_ehash.c) — forward-declared for the
 * include-order reason above; the full contract lives in cdx_common.h. */
void cdx_ehash_quarantine_abandon(void);

#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include "lnxwrp_fsl_fman.h"

static uint32_t init_level;
static cdx_deinit_func deinit_fn[MAX_CDX_INIT_FUNCTIONS];

/* Configuration and final teardown need both locks. RTNL holders may flush
 * flowtable callbacks which need ctrl.mutex, and the flowtable's admission
 * path takes RTNL with ctrl.mutex held (it only trylocks, for this reason).
 * Never wait for either lock while holding the other. */
void cdx_ctrl_lock_with_rtnl(void)
{
	for (;;) {
		rtnl_lock();
		if (mutex_trylock(&cdx_info->ctrl.mutex))
			return;
		rtnl_unlock();
		mutex_lock(&cdx_info->ctrl.mutex);
		mutex_unlock(&cdx_info->ctrl.mutex);
	}
}

void cdx_ctrl_unlock_with_rtnl(void)
{
	mutex_unlock(&cdx_info->ctrl.mutex);
	rtnl_unlock();
}

void register_cdx_deinit_func(cdx_deinit_func func)
{
	if (init_level == MAX_CDX_INIT_FUNCTIONS) {
		printk("%s::cant register deinit function, increase MAX_CDX_INIT_FUNCTIONS\n", __func__);
		return;
	}
	deinit_fn[init_level] = func;
	init_level++;
	return;
}

/* The subsystems whose state the flowtable backends drive: the physical
 * ports, the CEETM channels and class queues, the IPsec SA caches with the
 * SEC job ring and datapath frame-queue hook, and the multicast group
 * tables. Each is torn down only if it came up, in the reverse order. */
static bool cdx_tx_up, cdx_qm_up, cdx_mc4_up, cdx_mc6_up;
#ifdef DPA_IPSEC_OFFLOAD
static bool cdx_ipsec_up;
#endif

static int __init cdx_subsys_init(void)
{
	int rc;

	rc = tx_init();
	if (rc < 0)
		return rc;
	cdx_tx_up = true;
	rc = qm_init();
	if (rc < 0)
		return rc;
	cdx_qm_up = true;
#ifdef DPA_IPSEC_OFFLOAD
	rc = ipsec_init();
	if (rc < 0)
		return rc;
	cdx_ipsec_up = true;
#endif
	rc = mc4_init();
	if (rc < 0)
		return rc;
	cdx_mc4_up = true;
	rc = mc6_init();
	if (rc < 0)
		return rc;
	cdx_mc6_up = true;
	return 0;
}

/* Forwarding state first, then the QoS queues and interfaces it names. */
static void cdx_subsys_exit(void)
{
	if (cdx_mc6_up)
		mc6_exit();
	cdx_mc6_up = false;
	if (cdx_mc4_up)
		mc4_exit();
	cdx_mc4_up = false;
#ifdef DPA_IPSEC_OFFLOAD
	if (cdx_ipsec_up)
		ipsec_exit();
	cdx_ipsec_up = false;
#endif
	if (cdx_qm_up)
		qm_exit();
	cdx_qm_up = false;
	if (cdx_tx_up)
		tx_exit();
	cdx_tx_up = false;
}

static void cdx_ctrl_deinit(void)
{
	cdx_ctrl_lock_with_rtnl();
	if (dpa_cfg_quiesce())
		pr_err("cdx: cannot quiesce DPA ports before control teardown\n");
	cdx_subsys_exit();
	/* Last on purpose: the exit chain above (the multicast and IPsec
	 * teardowns included) can still park entries whose delete failed,
	 * so the abandon must run after every subsystem's teardown, not
	 * from an individual _exit hook partway down the chain. */
	cdx_ehash_quarantine_abandon();
	cdx_ctrl_unlock_with_rtnl();
}

static int __init cdx_ctrl_init(struct _cdx_info *cdx_info)
{
	struct _cdx_ctrl *ctrl = &cdx_info->ctrl;
	int rc;

	mutex_init(&ctrl->mutex);

	ctrl->dev = &cdx_info->dev;
	rc = cdx_ctrl_timer_init(ctrl);
	if (rc)
		goto error;
	mutex_lock(&ctrl->mutex);
	rc = cdx_subsys_init();
	mutex_unlock(&ctrl->mutex);
	if (!rc)
		wake_up_process(ctrl->timer_thread);
	register_cdx_deinit_func(cdx_ctrl_deinit);
error:
	return rc;
}


#ifdef START_DPA_APP
static void cdx_free_modprobe_argv(struct subprocess_info *info)
{
	kfree(info->argv);
}


static int start_dpa_app(void)
{
	int retval;
	struct subprocess_info *info;
	static char *envp[] = {
		"HOME=/",
		"TERM=linux",
		"PATH=/sbin:/usr/sbin:/bin:/usr/bin",
		NULL
	};
	static char *modprobe_path = "/usr/bin/dpa_app";

	char **argv = kmalloc(sizeof(char *[3]), GFP_KERNEL);
	if (!argv)
		return -ENOMEM;

	argv[0] = modprobe_path;
	argv[1] = NULL;
	retval = 0;
	printk("%s::calling dpa_app argv %p\n", __func__, argv);
	info = call_usermodehelper_setup(modprobe_path, argv, envp, GFP_KERNEL,
			NULL, cdx_free_modprobe_argv, NULL);
	if (info) {
		retval = call_usermodehelper_exec(info, (UMH_WAIT_PROC | UMH_KILLABLE));
	}
	return retval;
}
#endif

static void cdx_deinit_device(void)
{
	device_unregister(&cdx_info->dev);
	return;
}

/* This function is required by device_register(), do not remove */
static void cdx_dev_release(struct device *dev)
{
	return;
}

static int cdx_init_device(void)
{
	int rc;

	cdx_info->dev.init_name = "cdx";
	cdx_info->dev.release = cdx_dev_release;
	rc = device_register(&cdx_info->dev);
	if (rc != 0)
		printk("%s::device_register failed\n", __func__);
	else
		register_cdx_deinit_func(cdx_deinit_device);
	return rc;
}

static void cdx_module_deinit(void)
{
	int ii;

	/* A loaded flowtable adapter pins CDX. Its callbacks and hardware
	 * have drained before provider shutdown can run. */
	/* Give up the netdev's ndo_setup_tc before anything it reaches is torn
	 * down. The driver holds a pointer into this module's text rather than a
	 * symbol reference, so a tc command can arrive right up to here; running
	 * this ahead of the deinit chain is deliberate, because that chain runs
	 * after the QoS objects a qdisc command would configure have gone.
	 * Safe on the initialization-failure path too, where nothing registered. */
	cdx_htb_exit();
	/* Stop the remaining internal writer before terminal retries release
	 * both locks. Timer storage survives until its normal exit callback. */
	cdx_ctrl_timer_stop();
	/* And the terminal-failure port-stop work: unload quiesces the ports
	 * below itself, and the work takes the control lock and cdx_info. */
	cdx_ft_fatal_stop();

	/* Stop classification before any dependent subsystem releases queues.
	 * Keep both locks available between retries and release them before
	 * callbacks which unregister netdevices. External users pin the module. */
	if (fman_info) {
		cdx_ctrl_lock_with_rtnl();
		while (dpa_cfg_quiesce()) {
			cdx_ctrl_unlock_with_rtnl();
			pr_warn_ratelimited("cdx: waiting for DPA port shutdown; reboot if hardware cannot recover\n");
			msleep(1000);
			cdx_ctrl_lock_with_rtnl();
		}
		cdx_flowtable_quiesced();
		/* Reclaim queued TX frames while dependent pools are still alive. */
		qm_quiesce();
		/* And the frame the discard queue may hold, for the same reason. */
		cdx_discard_exit();
		cdx_ctrl_unlock_with_rtnl();
	}

	for (ii = init_level - 1; ii >= 0; ii--) {
		if (deinit_fn[ii])
			deinit_fn[ii]();
	}
	kfree(cdx_info);
	return;
}

static int cdx_check_fman_firmware(void)
{
	struct device_node *np;
	struct platform_device *pdev;
	struct fm *fm;
	u16 pkg = 0;
	u8 maj = 0, min = 0;
	int rc;

	np = of_find_compatible_node(NULL, NULL, "fsl,fman");
	if (!np) {
		pr_err("cdx: fsl,fman device-tree node not found\n");
		return -ENODEV;
	}
	pdev = of_find_device_by_node(np);
	of_node_put(np);
	if (!pdev) {
		pr_err("cdx: fsl,fman platform device not ready\n");
		return -EPROBE_DEFER;
	}

	fm = fm_bind(&pdev->dev);
	rc = fm_get_fw_rev(fm, &pkg, &maj, &min);
	fm_unbind(fm);
	if (rc) {
		pr_err("cdx: cannot read FMAN firmware revision (%d)\n", rc);
		return rc;
	}

	if (pkg < CDX_MIN_FW_PACKAGE) {
		pr_err("cdx: FMAN firmware %u.%u.%u lacks ASK support "
		       "(need package >= %u). Load the ASK microcode in U-Boot.\n",
		       pkg, maj, min, CDX_MIN_FW_PACKAGE);
		return -ENODEV;
	}

	pr_info("cdx: FMAN firmware %u.%u.%u - ASK supported\n",
		pkg, maj, min);
	return 0;
}

static int __init cdx_module_init(void)
{
	int rc = 0;
	int ii;

	printk(KERN_INFO "%s\n", __func__);

	rc = cdx_check_fman_firmware();
	if (rc)
		return rc;

	for(ii = 0; ii < MAX_CDX_INIT_FUNCTIONS; ii++)
		deinit_fn[ii] = NULL;
	init_level = 0;

	cdx_info = kzalloc(sizeof(struct _cdx_info), GFP_KERNEL);
	if (!cdx_info)
	{
		printk(KERN_ERR "%s: Error allocating cdx_info structure\n", __func__);
		return (-ENOMEM);
	}
	rc = cdx_init_device();
	if (rc != 0) {
		printk("%s::cdx_init_device failed\n", __func__);
		goto exit;
	}
	rc = cdx_flowtable_guard_init();
	if (rc)
		goto exit;
	/* Keep the failed-port guard until the configuration cleanup below has
	 * detached PCD and released physical interface records. */
	register_cdx_deinit_func(cdx_flowtable_guard_exit);
	/* Run after control teardown, while FMAN metadata is still available. */
	register_cdx_deinit_func(dpa_cfg_deinit);
	rc = cdx_ctrl_init(cdx_info);
	if (rc != 0) {
		printk("%s::cdx_ctrl_init failed\n", __func__);
		goto exit;
	}
	/* After cdx_ctrl_init, which is where qm_init builds every CEETM
	 * channel and class queue a qdisc command can configure. */
	rc = cdx_htb_init();
	if (rc != 0) {
		printk("%s::cdx_htb_init failed\n", __func__);
		goto exit;
	}
	rc = devman_init_linux_stats();
	if (rc != 0)  {
		printk("%s::devman_init call to register for linux stats failed\n", __func__);
		goto exit;
	}
	rc = cdx_driver_init();
	if (rc != 0)  {
		printk("%s::cdx_driver_init failed\n", __func__);
		goto exit;
	}
	/* creating a /proc/fqid_stats dir for listing fqids created by cdx module */
	if (cdx_init_fqid_procfs() == 0)
		register_cdx_deinit_func(cdx_deinit_fqid_procfs);
#ifdef CDX_DEBUG_KEY_ZEROING
	if (cdx_ipsec_init_key_zeroing_probe() == 0)
		register_cdx_deinit_func(cdx_ipsec_remove_key_zeroing_probe);
	else
		printk(KERN_WARNING "%s::cdx_ipsec_init_key_zeroing_probe failed\n", __func__);
#endif
#ifdef CDX_DEBUG_MC_HCSYNC_FAIL
	if (cdx_mc_init_hcsync_fail_probe() == 0)
		register_cdx_deinit_func(cdx_mc_remove_hcsync_fail_probe);
	else
		printk(KERN_WARNING "%s::cdx_mc_init_hcsync_fail_probe failed\n", __func__);
#endif
#ifdef CDX_DEBUG_SPLIT_KEY_FAIL
	if (cdx_ipsec_init_split_key_fail_probe() == 0)
		register_cdx_deinit_func(cdx_ipsec_remove_split_key_fail_probe);
	else
		printk(KERN_WARNING "%s::cdx_ipsec_init_split_key_fail_probe failed\n", __func__);
#endif
#ifdef START_DPA_APP
	rc = start_dpa_app();
	if (rc != 0)  {
		printk("%s::start_dpa_app failed rc %d\n", __func__, rc);
		/* cant pass error code from start_dpa_app */
		rc = -EIO;
		goto exit;
	}
	printk("%s::start_dpa_app successful\n", __func__);
#endif
#ifdef CFG_WIFI_OFFLOAD
	/* What this claims is the offline port the board declared for Wi-Fi
	 * (dpa-fman0-oh@3, sized for it in the device tree), its buffer pools
	 * and the per-VAP frame-queue machinery. Without it the absence surfaces
	 * several layers away, as a frame queue that cannot be resolved, with
	 * nothing in the message naming Wi-Fi. */
	rc = dpaa_vwd_init();
	if (rc != 0)  {
		/* Not fatal. What failed is a claim on board-specific resources
		 * -- the Wi-Fi offline port, its buffer pool, the first Ethernet
		 * port's private data -- and a board without them is a gateway
		 * without Wi-Fi offload, not a gateway without offload.
		 * dpaa_vwd_ready() stays false, so cdx_wifi_vap_supported()
		 * refuses every VAP and dpaa_vwd_vap_cmd() refuses any that
		 * reaches it; nothing else here depends on it. */
		pr_warn("%s: Wi-Fi offload unavailable, VWD init failed (%d)\n",
			__func__, rc);
		rc = 0;
	}
#endif
	// initialize global fragmentation params
	if (cdx_init_frag_module()) { 
		printk("%s::cdx_init_frag_module failed\n", __func__);
		rc = -EIO;
		goto exit;
	}

#ifdef DPA_IPSEC_OFFLOAD
	/* This builds the offline port, the SEC buffer pool and the PCD frame
	 * queues -- resources no control plane can substitute for. Without them
	 * SEC has nowhere to put a frame, and the first symptom is a shared
	 * descriptor that cannot be created, several layers away from the
	 * cause. */
	if (cdx_dpa_ipsec_init()) {
		/* Not fatal, for the reason the Wi-Fi failure above is not: what
		 * failed is a claim on board-specific resources -- the IPsec
		 * offline port, its buffer pool, the PCD frame queues -- and a
		 * board without them is a gateway without IPsec offload, not a
		 * gateway without offload. cdx_ipsec_ready() stays false, so
		 * the XFRM provider refuses every SA and the encoder never arms;
		 * nothing else here depends on it. */
		pr_warn("%s: IPsec offload unavailable, DPA IPsec init failed\n",
			__func__);
	}

#endif
	return 0;

exit:
	if (rc) {
		printk("<<<<<<<<<<<<<<<<<<<< CDX module failed initialization >>>>>>>>>>>>>>>>>>>>>>>>>\n");
		cdx_module_deinit();
	}
	return rc;
}

static void __exit cdx_module_exit(void)
{
	printk(KERN_INFO "%s\n", __func__);
	cdx_module_deinit();
}

MODULE_LICENSE("GPL");
module_init(cdx_module_init);
module_exit(cdx_module_exit);
