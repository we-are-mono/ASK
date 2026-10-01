/*
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017-2018,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 */

/*
 * Concurrency:
 *   The IPsec SA lifecycle (add, remove, update) is driven by the
 *   flowtable adapter's XFRM provider through cdx_ipsec_backend.c,
 *   inside the flowtable transaction, which holds ctrl->mutex (see
 *   cdx_main.c). SA state mutations therefore run single-threaded
 *   with respect to each other.
 *
 *   Per-SA DMA maps (auth_key_dma, crypto_key_dma, shared_desc):
 *      - Maps/unmaps happen inside a single call to
 *        cdx_ipsec_create_shareddescriptor(); error paths unwind
 *        via goto labels. No cross-call ownership.
 *
 *   Key material (cipher_key, auth_key, split_key):
 *      - Allocated during SA context construction, freed via
 *        cdx_ipsec_sec_sa_context_free() with kfree_sensitive so
 *        the slab is zeroed before reuse.
 *
 *   SA classification table (DDR, accessed by SEC/CAAM hardware):
 *      - Reads are lock-free from the hardware fast path. Writes
 *        (insert/delete) go through the same serialized command
 *        path. SA_SH_DESC_BUILT flag is rolled back on error so a
 *        retry sees consistent state.
 *
 *   NAT-T SPI array (per-flow preempt_params):
 *      - arr_index selection uses get_free_natt_arr_index, bounded
 *        by MAX_SPI_PER_FLOW. Mutations serialized by the same
 *        command path.
 *
 * Contexts:
 *   cdx_ipsec_add/remove/update_*     - process, flowtable transaction.
 *   cdx_ipsec_sec_sa_context_*        - process, under command path.
 *   split_key_done (CAAM callback)    - softirq; the kernel's own, it
 *                                       touches only the per-call
 *                                       split_key_result, which
 *                                       cdx_ipsec_generate_split_key()
 *                                       keeps alive until it completes.
 */
#ifdef DPA_IPSEC_OFFLOAD
#include <linux/delay.h>
#include <linux/udp.h>
#include <linux/random.h>
#include <linux/reboot.h>
#include "error.h"
#include "desc.h"
#include "jr.h"
#include "pdb.h"
#include "desc_constr.h"
/* The kernel's split-key job completion and pad lengths; after
 * desc_constr.h, whose struct alginfo it names. */
#include "key_gen.h"
/* intern.h needs compat.h and regs.h in scope first; pdb.h and
 * desc_constr.h above already pull them in, so it goes last. */
#include "intern.h"

#include "misc.h"
#include "cdx.h"
#include "cdx_common.h"
#include "control_ipv4.h"
#include "control_ipv6.h"
#include "layer2.h"
#include "control_ipsec.h"

#include "cdx_dpa_ipsec.h"
#include "fm_ehash.h"
#include "dpa_control_mc.h"
#include "fe.h"
#include "cdx_flowtable_backend.h"

//#define CDX_DPA_DEBUG	1

#ifdef CDX_DEBUG_KEY_ZEROING
/*
 * H2 regression tripwire — DEBUG-ONLY, NOT FOR PRODUCTION.
 *
 * The H2 fix replaced kfree with kfree_sensitive on cipher_key /
 * auth_key / split_key in cdx_ipsec_sec_sa_context_free; the
 * sensitive variant zeroes the buffer before returning the slot to
 * the slab allocator. A regression to plain kfree leaves the bytes
 * in place where the next slab consumer can read them.
 *
 * To make that observable from user space, this probe snapshots the
 * bytes at the cipher_key buffer's address immediately after
 * kfree_sensitive returns, and exposes the snapshot via
 * /proc/cdx/last_freed_key. The read is a deliberate UAF: the
 * buffer is freed but not yet handed to a new owner. KASAN would
 * trap it on instrumented builds, so the read is wrapped in
 * kasan_disable_current() / kasan_enable_current(); both are no-ops
 * without CONFIG_KASAN, so the same code compiles either way.
 * KFENCE-sampled allocations cannot be read after free at all — the
 * object's page is guard-protected and the access would fault with a
 * use-after-free report — so those events are recorded with an empty
 * snapshot (captured=false) and the test retries with a fresh SA.
 *
 * The snapshot is best-effort by design: SLUB may write its freelist
 * pointer into the slot before the memcpy, and another context may
 * reallocate the slot entirely, in which case the snapshot holds the
 * new owner's bytes. Accepted — the file is root-only (0400) on a
 * test-image-only build, and the test asserts on byte patterns, not
 * exact contents.
 *
 * The seq counter increments on every observed cipher_key free so a
 * reader can tell a fresh capture from a stale one; without it, a
 * snapshot latched by an earlier test's teardown would satisfy a
 * naive captured=true poll.
 *
 * Production (Armbian) builds DO NOT define CDX_DEBUG_KEY_ZEROING.
 * The flag is set only in the meta-ask test image. cdx_module_init
 * prints a pr_warn_once at boot if the probe is on, so an
 * accidental enable surfaces loudly.
 */
#include <linux/kasan.h>
#include <linux/kfence.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#define CDX_KEY_ZEROING_SNAPSHOT_LEN MAX_CIPHER_KEY_LEN

static DEFINE_MUTEX(cdx_key_zeroing_lock);
static struct {
	u64    seq;
	void  *addr;
	size_t len;
	bool   captured;
	u8     snapshot[CDX_KEY_ZEROING_SNAPSHOT_LEN];
} cdx_key_zeroing_state;

static struct proc_dir_entry *cdx_key_zeroing_dir;
static struct proc_dir_entry *cdx_key_zeroing_file;

static void cdx_ipsec_capture_post_free(void *p, size_t n)
{
	size_t to_copy;

	if (!p || !n)
		return;

	to_copy = min(n, (size_t)CDX_KEY_ZEROING_SNAPSHOT_LEN);

	mutex_lock(&cdx_key_zeroing_lock);
	cdx_key_zeroing_state.seq++;
	cdx_key_zeroing_state.addr = p;
	if (is_kfence_address(p)) {
		/* KFENCE guard-protects the page on free; reading it
		 * would fault and splat. Record the event with an empty
		 * snapshot so the reader knows to retry with a new
		 * allocation (which is virtually never KFENCE-sampled).
		 */
		cdx_key_zeroing_state.len      = 0;
		cdx_key_zeroing_state.captured = false;
	} else {
		cdx_key_zeroing_state.len = to_copy;
		/* Deliberate UAF: p was just handed to the slab. The
		 * bytes are still readable until SLUB writes its
		 * freelist pointer or a new owner allocates the slot.
		 * KASAN must be told to ignore this single memcpy.
		 */
		kasan_disable_current();
		memcpy(cdx_key_zeroing_state.snapshot, p, to_copy);
		kasan_enable_current();
		cdx_key_zeroing_state.captured = true;
	}
	mutex_unlock(&cdx_key_zeroing_lock);
}

static int cdx_key_zeroing_show(struct seq_file *m, void *v)
{
	u8 buf[CDX_KEY_ZEROING_SNAPSHOT_LEN];
	void *addr;
	size_t i, n;
	u64 seq;
	bool captured;

	mutex_lock(&cdx_key_zeroing_lock);
	seq      = cdx_key_zeroing_state.seq;
	addr     = cdx_key_zeroing_state.addr;
	n        = cdx_key_zeroing_state.len;
	captured = cdx_key_zeroing_state.captured;
	memcpy(buf, cdx_key_zeroing_state.snapshot, n);
	mutex_unlock(&cdx_key_zeroing_lock);

	seq_printf(m, "seq=%llu addr=%p len=%zu captured=%s\n",
		   seq, addr, n, captured ? "true" : "false");
	for (i = 0; i < n; i++)
		seq_printf(m, "%02x", buf[i]);
	seq_putc(m, '\n');
	return 0;
}

static int cdx_key_zeroing_open(struct inode *inode, struct file *file)
{
	return single_open(file, cdx_key_zeroing_show, NULL);
}

static const struct proc_ops cdx_key_zeroing_proc_ops = {
	.proc_open    = cdx_key_zeroing_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

int cdx_ipsec_init_key_zeroing_probe(void)
{
	pr_warn_once("cdx: CDX_DEBUG_KEY_ZEROING is on — diagnostic probe leaks freed-key snapshots via /proc/cdx/last_freed_key; do not ship\n");
	cdx_key_zeroing_dir = proc_mkdir("cdx", NULL);
	if (!cdx_key_zeroing_dir)
		return -ENOMEM;
	cdx_key_zeroing_file = proc_create("last_freed_key", 0400,
					   cdx_key_zeroing_dir,
					   &cdx_key_zeroing_proc_ops);
	if (!cdx_key_zeroing_file) {
		proc_remove(cdx_key_zeroing_dir);
		cdx_key_zeroing_dir = NULL;
		return -ENOMEM;
	}
	return 0;
}

void cdx_ipsec_remove_key_zeroing_probe(void)
{
	if (cdx_key_zeroing_file) {
		proc_remove(cdx_key_zeroing_file);
		cdx_key_zeroing_file = NULL;
	}
	if (cdx_key_zeroing_dir) {
		proc_remove(cdx_key_zeroing_dir);
		cdx_key_zeroing_dir = NULL;
	}
}
#else
static inline void cdx_ipsec_capture_post_free(void *p, size_t n) { }
#endif /* CDX_DEBUG_KEY_ZEROING */

#define CLASS_SHIFT		25
#define CLASS_MASK		(0x03 << CLASS_SHIFT)

#define CLASS_NONE		(0x00 << CLASS_SHIFT)
#define CLASS_1			(0x01 << CLASS_SHIFT)
#define CLASS_2			(0x02 << CLASS_SHIFT)
#define CLASS_BOTH		(0x03 << CLASS_SHIFT)

#define PREHDR_IDLEN_SHIFT	32
#define PREHDR_OFFSET_SHIFT	26
#define PREHDR_BPID_SHIFT	16
#define PREHDR_ADDBUF_SHIFT	24
#define PREHDR_ABS_SHIFT	25
#define PREHDR_BSIZE_SHIFT	0
#define PREHDR_TBPID_SHIFT      40
#define PREHDR_TBP_SIZE_SHIFT   48


#define PREHDR_IDLEN_MASK	GENMASK_ULL(39,32)
#define PREHDR_OFFSET_MASK	GENMASK_ULL(27,26)
#define PREHDR_BPID_MASK	GENMASK_ULL(23,16)
#define PREHDR_ADDBUF_MASK	GENMASK_ULL(24,24)
#define PREHDR_ABS_MASK		GENMASK_ULL(25,25)
#define PREHDR_BSIZE_MASK	GENMASK_ULL(15,0)
#define PREHDR_TBPID_MASK	GENMASK_ULL(47,40)
#define PREHDR_TBP_SIZE_MASK 	GENMASK_ULL(48,50)


#define PREHEADER_PREP_IDLEN(preh, idlen) \
	(preh) |= ((u64)(idlen) << PREHDR_IDLEN_SHIFT) & PREHDR_IDLEN_MASK

#define PREHEADER_PREP_BPID(preh, bpid) \
	(preh) |= ((u64)(bpid) << PREHDR_BPID_SHIFT) & PREHDR_BPID_MASK

#define PREHEADER_PREP_ADDBUF(preh, addbuf) \
	(preh) |= ((u64)(addbuf) << PREHDR_ADDBUF_SHIFT) & PREHDR_ADDBUF_MASK

#define PREHEADER_PREP_ABS(preh, abs) \
	(preh) |= ((u64)(abs) << PREHDR_ABS_SHIFT) & PREHDR_ABS_MASK

#define PREHEADER_PREP_BSIZE(preh, bufsize) \
	(preh) |= ((u64)(bufsize) << PREHDR_BSIZE_SHIFT) & PREHDR_BSIZE_MASK

// setting the table buffer pool ID
#define PREHEADER_PREP_TBPID(preh, bpid) \
	(preh) |= ((u64)(bpid) << PREHDR_TBPID_SHIFT) & PREHDR_TBPID_MASK

// setting the table buffer pool size

#define PREHEADER_PREP_OFFSET(preh, offs) \
	(preh) |= ((u64)(offs) << PREHDR_OFFSET_SHIFT) & PREHDR_OFFSET_MASK



#define SEQ_NUM_HI_MASK         0xFFFFFFFF00000000
#define SEQ_NUM_LOW_MASK        0x00000000FFFFFFFF

#define POST_SEC_OUT_DATA_OFFSET 128 //bytes multiple of 64
#define POST_SEC_IN_DATA_OFFSET  128 //bytes multiple of 64

#define ETH_HDR_LEN		14
#define PPPOE_HDR_LEN		8 
#define UDP_HEADER_LEN          8

struct ipsec_info *ipsec_instance;
int sec_era;
U64 post_sec_out_data_off;
U64 post_sec_in_data_off;

static struct device *jrdev_g;

static bool cdx_ipsec_cipher_is_gcm(uint32_t cipher_type)
{
	return cipher_type == OP_PCL_IPSEC_AES_GCM8 ||
	       cipher_type == OP_PCL_IPSEC_AES_GCM12 ||
	       cipher_type == OP_PCL_IPSEC_AES_GCM16;
}

/*
 * Sharing policy for the IPsec protocol shared descriptor (SEC RM rev 0,
 * §7.3.1/7.3.2 sharing rules, §9.1 protocol-op PDB behaviour, header SC
 * bit definition).
 *
 * The PDB embedded in the shared descriptor is live state (encap: ESP
 * sequence counter; decap: sequence + anti-replay window), so the header
 * flags decide correctness, not just throughput:
 *
 *  - HDR_SAVECTX carries the CCB context registers from one job into the
 *    next when the same DECO runs the same SA back-to-back (SERIAL
 *    self-sharing — exactly what SEC's scheduler prefers once per-SA
 *    load rises). The bit exists for operations split across several
 *    jobs; for independent per-packet jobs it seeds packet N+1 with
 *    packet N's residue. AES-GCM keeps GHASH/counter state in class-1
 *    context, so inherited residue corrupts the ICV of nearly every
 *    packet once self-sharing kicks in (NXP DNCPE-2358's ">18% load"
 *    ICV failures). CBC/CTR/CCM protocol machines fully re-init their
 *    context from PDB/keys per packet and are immune. The kernel CAAM
 *    library draws the same line: cnstr_shdsc_{gcm,rfc4106,rfc4543}_*
 *    omit SAVECTX while the CBC/XTS constructors keep it.
 *
 *  - HDR_SHARE_NEVER forces every job to refetch the descriptor from
 *    memory "without any consideration for any pending writes to update
 *    the Shared Descriptor PDB from another DECO" (RM §9.1) — duplicate
 *    ESP sequence numbers are the documented outcome, and 21-25 % of
 *    wire seqs were duplicates when GCM ran this way.
 *
 *  - HDR_SHARE_WAIT hands the descriptor to the next job once the
 *    protocol engine signals OK-to-Share (RM §9.1) and yields the
 *    cleanest wire (0.086 % duplicate seqs at blast scale), but the
 *    per-job handshake serializes the SA at ~73 kpps (~0.87 Gbit/s at
 *    1390 bytes) and line-rate TCP bursts overrun it and tail-drop
 *    (measured 65 Mbit/s with ~1000 retransmits on a 10 s stream).
 *
 * GCM therefore runs SERIAL without SAVECTX; the other ciphers
 * keep the SERIAL+SAVECTX arrangement they have always shipped with.
 * The paired half of the fix is in save_sa_state_in_external_mem():
 * RM §7.3.1 requires every job of a WAIT/SERIAL flow to STORE the PDB
 * back so SEC orders descriptor refetches against prior jobs' updates.
 *
 * Measured on the DNCPE-2358 setup (hardware encap, Linux peer with
 * replay-window 32): the legacy SERIAL+SAVECTX flags produce ~2.8M
 * ICV failures per 12 s at blast load; SERIAL without SAVECTX plus
 * the PDB store produces zero ICV failures and 2.55 Gbit/s TCP with
 * 20 retransmits — ahead of the CBC+HMAC production path on the same
 * boot (2.37 Gbit/s, 842 retransmits). The ESP-level replay-window
 * rejections still measured then (~0.45 % at full TCP rate, 0.154 %
 * on CBC at blast scale, and the WAIT figure above) were distinct
 * frames sharing a sequence number, not wire duplicates. SEC orders
 * an SA's jobs only among frames carrying the same ICID (RM §7.3.2),
 * and FMan-fed frames carried ICID 0 against the CPU portals' 63
 * until the SDK FMan driver kept the firmware's port ICIDs (kernel
 * patch 106). NEVER sharing is documented by the RM itself to
 * duplicate sequence numbers.
 */
static uint32_t cdx_ipsec_sh_desc_hdr_flags(PSAEntry sa)
{
	if (cdx_ipsec_cipher_is_gcm(sa->pSec_sa_context->cipher_data.cipher_type))
		return HDR_SHARE_SERIAL;

	return HDR_SAVECTX | HDR_SHARE_SERIAL;
}

extern int cdx_ipsec_sa_fq_check_if_retired_state(void *dpa_ipsecsa_handle, int fq_num);

extern int cdx_dpa_ipsec_retire_fq(void *handle, int fq_num);

/* #define PRINT_DESC  */
#ifdef PRINT_DESC
void cdx_ipsec_print_desc ( U32 *desc,const char* function, int line)
{
	int  desc_length,ii;
	desc_length = desc_len(desc);
	printk(KERN_ERR "\n%s(%d) -  Desc length: %d,  dump: \n",function,line, desc_length);
	for ( ii=0; ii< desc_length; ii++){ 
		printk(KERN_ERR "0x%08x \n", caam32_to_cpu(desc[ii]));
	}


}
#endif

/* Idempotent: runs from both the module deinit chain and the reboot
 * notifier — whichever fires first drops our consumer count so
 * caam_jr's .shutdown doesn't find the ring busy. The command path
 * is quiescent by the time either runs (daemons stopped / module
 * exiting), so no split-key job can be in flight. */
static void cdx_ipsec_release_jr(void)
{
	struct device *jrdev = xchg(&jrdev_g, NULL);

	if (jrdev)
		caam_jr_free(jrdev);
}

/* Whether an SA can be built at all: the DPA side (offline port, pool,
 * frame queues) and the SEC side (a job ring) are both claimed at module
 * init, and either can be missing on a board whose device tree does not
 * describe it. Consulted before anything that would touch either -- SA
 * admission by both owners, the xfrmdev attachment that advertises the
 * capability, the table descriptors the encoder arms with -- so that the
 * absence is a refusal at the entry rather than a fault several layers in.
 * The job ring is also given back by the reboot notifier, which makes this
 * false for the shutdown as well. */
bool cdx_ipsec_ready(void)
{
	return cdx_dpa_ipsec_ready() && READ_ONCE(jrdev_g);
}

static int cdx_ipsec_reboot_notify(struct notifier_block *nb,
		unsigned long action, void *data)
{
	cdx_ipsec_release_jr();
	return NOTIFY_DONE;
}

static struct notifier_block cdx_ipsec_reboot_nb = {
	.notifier_call = cdx_ipsec_reboot_notify,
};

int cdx_ipsec_init(void)
{
	struct caam_drv_private *ctrlpriv;

	printk(KERN_INFO "%s\n", __func__);
	ipsec_instance = dpa_get_ipsec_instance();
	post_sec_out_data_off = ((uint64_t )POST_SEC_OUT_DATA_OFFSET /64);
	post_sec_in_data_off = ((uint64_t )POST_SEC_IN_DATA_OFFSET / 64);
	/* get the jr device (caam_jr_alloc returns ERR_PTR, never NULL) */
	jrdev_g  = caam_jr_alloc();
	if (IS_ERR(jrdev_g)) {
		log_err("Failed to get the job ring device, check the dts\n");
		jrdev_g = NULL;
		return -ENODEV;
	}
	/* The CAAM controller (the job ring's parent) holds the detected SEC
	 * era; LS1046A reports era 8. The era gates PDBOPTS_ESP_AOFL in the
	 * transport-mode decap PDB, a SEC >= 5.3 (era > 4) feature.
	 * caam_get_era() stores a negative errno when the era cannot be
	 * discovered, so fall back to the historical value of 4 then. */
	ctrlpriv = dev_get_drvdata(jrdev_g->parent);
	sec_era = ctrlpriv->era;
	if (sec_era < 0) {
		pr_warn("%s SEC era not reported by CAAM (%d), assuming 4\n",
				__func__, sec_era);
		sec_era = 4;
	} else {
		printk(KERN_INFO "%s SEC era= %d\n", __func__, sec_era);
	}
	register_reboot_notifier(&cdx_ipsec_reboot_nb);
	printk(KERN_INFO "%s job ring device= %p\n", __func__,jrdev_g);
	return 0;
}

void cdx_ipsec_deinit(void)
{
	unregister_reboot_notifier(&cdx_ipsec_reboot_nb);
	cdx_ipsec_release_jr();
}


/* How many bytes larger than what it is handed an outbound SA's frames leave
 * SEC: its port's MTU less its own, the whole of ESP's overhead (A227), as
 * they stood when the SA was installed. A flowtable direction carries its own,
 * from its outer path at admission (CtEntry.sec_expansion); this is what an
 * entry without one gets. */
static u16 cdx_ipsec_expansion_of(PSAEntry sa)
{
	return sa->dev_mtu > sa->mtu ? sa->dev_mtu - sa->mtu : 0;
}

bool cdx_ipsec_sa_outbound(u16 handle)
{
	PSAEntry sa = M_ipsec_sa_cache_lookup_by_h(handle);

	return sa && sa->direction == CDX_DPA_IPSEC_OUTBOUND;
}

/* Allocation is shared by both directions and retained with the queues. */
uint32_t cdx_ipsec_key_tag_of(PSAEntry sa)
{
	return ipsec_get_key_tag(sa->pSec_sa_context->dpa_ipsecsa_handle);
}

/* The tables a decrypted flow may be classified in on the offline port: the
 * ones whose forwarding actions validate the SA VLAN. The shared
 * encoder files a UDP flow without ports under multicast, which that port has
 * no table for, so such a flow stays in software. */
static bool cdx_ipsec_decrypted_table(uint32_t tbl_type)
{
	return tbl_type == IPV4_TCP_TABLE || tbl_type == IPV4_UDP_TABLE ||
	       tbl_type == IPV6_TCP_TABLE || tbl_type == IPV6_UDP_TABLE;
}

int cdx_ipsec_fill_sec_info( PCtEntry entry, struct ins_entry_info *info)
{
	int i;
	PSAEntry sa;

	/* A handle the SA cache does not hold is a refusal, not a direction
	 * without that SA: a decrypted direction skipped here would be
	 * installed on its physical port, keyed to match the same tuple in
	 * the clear, and an encrypted one would leave unencrypted. */
	for (i = 0; i < SA_MAX_OP; i++)
		if (entry->hSAEntry[i] &&
		    !M_ipsec_sa_cache_lookup_by_h(entry->hSAEntry[i]))
			return -1;
  
	for (i=0;i < SA_MAX_OP;i++)
	{ 
		if((sa = M_ipsec_sa_cache_lookup_by_h(entry->hSAEntry[i])) 
					!= NULL)
		{ 
			if(sa->direction == CDX_DPA_IPSEC_OUTBOUND )
			{
				info->to_sec_fqid = 
				sa->pSec_sa_context->to_sec_fqid;
				info->sa_family = sa->family ;
				info->tnl_hdr_size = entry->sec_expansion ?:
						     cdx_ipsec_expansion_of(sa);
#ifdef CDX_DPA_DEBUG	
				printk(KERN_CRIT "%s OutBound SA info->to_sec_fqid  = %d\n", __func__,info->to_sec_fqid );
#endif				
			}else{
				/* Every SA reaches this offline port. A tuple hit
				 * must validate the tag of the SA for which Linux
				 * admitted the decrypted flow. */
				if (!cdx_ipsec_decrypted_table(info->tbl_type))
					return -1;
				info->l3_info.ipsec_inbound_flow = 1;
				info->sec_tag = cdx_ipsec_key_tag_of(sa);
				if (dpa_ipsec_ofport_td(ipsec_instance,
					info->tbl_type, &info->td, &info->port_id))
					return -1;
#ifdef CDX_DPA_DEBUG
//			printk(KERN_CRIT "%s InBound SA info->td  = %d\n", __func__,info->td );
#endif
			}
		}
	}
	return 0;
}

/* Call after the SA's request queue is OOS. SEC RM CSTA[IDLE] proves that
 * jobs already dequeued by QI have also finished; QMan retirement alone does
 * not. A busy or wedged SEC is not permission to reuse a descriptor or tag.
 * Other SAs may continue running: one idle observation is sufficient once
 * this SA can no longer submit work. */
bool cdx_ipsec_wait_sec_idle(void)
{
	struct caam_drv_private *ctrlpriv;
	unsigned int tries;

	if (!jrdev_g)
		return false;
	ctrlpriv = dev_get_drvdata(jrdev_g->parent);
	for (tries = 0; tries < 100; tries++) {
		if (rd_reg32(&ctrlpriv->ctrl->perfmon.status) & BIT(1))
			return true;
		usleep_range(100, 200);
	}
	return false;
}

void cdx_ipsec_sec_sa_context_free(PDpaSecSAContext pdpa_sec_context )
{
	/*
	 * A24b: if cdx_dpa_ipsecsa_release fails (qman_oos_fq did not move
	 * the FQ to OOS), QMan still owns the sainfo memory and may invoke
	 * dqrr/ern callbacks on it. Freeing the per-SA crypto material below
	 * — cipher_key, auth_key, split_key — would
	 * UAF those buffers from the SEC pipeline (they are DMA-mapped while
	 * any in-flight op is still resident). Leak the sec_context entirely
	 * and let the operator restart to recover the resources. The leak is
	 * surfaced via the pr_warn here and dpa_ipsec_ern_count.
	 *
	 * Pre-init error paths (handle == NULL) skip the release call and
	 * proceed to free the crypto material — the buffers were never
	 * DMA-mapped to SEC, so it's safe.
	 */
	if (pdpa_sec_context->dpa_ipsecsa_handle) {
		if (cdx_dpa_ipsecsa_release(pdpa_sec_context->dpa_ipsecsa_handle)
				!= SUCCESS) {
			pr_warn_ratelimited(
				"cdx: SA release failed for handle %p — leaking sec_context (A24b)\n",
				pdpa_sec_context->dpa_ipsecsa_handle);
			return;
		}
	}
	/* Release the SA-lifetime key mappings before freeing the buffers.
	 * Guards mirror the map sites in cdx_ipsec_create_shareddescriptor;
	 * 0 means the SA never got a descriptor built. */
	if (jrdev_g) {
		if (pdpa_sec_context->crypto_key_dma)
			dma_unmap_single(jrdev_g,
					pdpa_sec_context->crypto_key_dma,
					pdpa_sec_context->cipher_data.cipher_key_len,
					DMA_TO_DEVICE);
		if (pdpa_sec_context->auth_key_dma) {
			if (pdpa_sec_context->auth_data.split_key_len)
				dma_unmap_single(jrdev_g,
						pdpa_sec_context->auth_key_dma,
						pdpa_sec_context->auth_data.split_key_pad_len,
						DMA_TO_DEVICE);
			else
				dma_unmap_single(jrdev_g,
						pdpa_sec_context->auth_key_dma,
						pdpa_sec_context->auth_data.auth_key_len,
						DMA_TO_DEVICE);
		}
	}

	if (pdpa_sec_context->cipher_data.cipher_key) {
		void *cipher_addr = pdpa_sec_context->cipher_data.cipher_key;

		kfree_sensitive(cipher_addr);
		cdx_ipsec_capture_post_free(cipher_addr, MAX_CIPHER_KEY_LEN);
	}
	if(pdpa_sec_context->auth_data.auth_key)
		kfree_sensitive(pdpa_sec_context->auth_data.auth_key);
	if(pdpa_sec_context->auth_data.split_key)
		kfree_sensitive(pdpa_sec_context->auth_data.split_key);
	kfree(pdpa_sec_context);
}

/* natt_arr_mask enables bits according to the number of spi
 * entries per 5 tuple. This function returns the free index
 * bit index available in the mask */
static int get_free_natt_arr_index(uint16_t natt_arr_mask)
{
	int i = 0;
	while(i < MAX_SPI_PER_FLOW)
	{
		if (!(natt_arr_mask & (1 << i)))
			break;
		i++;
	}
	return i;	
}

/* This function sets the corresponding bit in the array mask
 * to mark it as being used */
static inline void set_natt_arr_mask(uint16_t* natt_arr_mask,int index)
{
	*natt_arr_mask |= cpu_to_be16(1<<index);
}


/* This function resets the corresponding bit in the array mask
 * to make it available */
static inline void reset_natt_arr_mask(uint16_t *natt_arr_mask,int index)
{
	*natt_arr_mask &= ~cpu_to_be16(1<<index);
}

int cdx_ipsec_delete_fp_entry(PSAEntry pSA)
{
	struct hw_ct *hwct;
	struct en_exthash_tbl_entry *natt_tbl_entry;
	struct en_ehash_ipsec_preempt_op *ipsec_preempt_params;
	int rc;

	DPA_INFO("%s(%d) dir: %s , handle %x fqid %x\n",
		__func__,__LINE__,(pSA->direction)?"INBOUND":"OUTBOUND",
		pSA->handle,
		pSA->pSec_sa_context ? pSA->pSec_sa_context->to_sec_fqid : 0);
	/* A NAT-T root remains installed until its last SA owner leaves. */
	if (IS_NATT_SA(pSA) && pSA->ct && (pSA->ct->handle))
	{
		natt_tbl_entry = pSA->ct->handle;
		if (pSA->direction == CDX_DPA_IPSEC_OUTBOUND && pSA->ct->natt_out_refcnt > 1) {
			pSA->ct->natt_out_refcnt--;
			pSA->ct = NULL;
			return 0;
		}
		if ((pSA->direction == CDX_DPA_IPSEC_INBOUND) && (pSA->ct->natt_in_refcnt > 1))
		{
			ipsec_preempt_params = ( struct en_ehash_ipsec_preempt_op *)natt_tbl_entry->ipsec_preempt_params;
			pSA->ct->natt_in_refcnt--;
			reset_natt_arr_mask(&ipsec_preempt_params->natt_arr_mask, pSA->natt_arr_index);
			ipsec_preempt_params->spi_param[pSA->natt_arr_index].spi = 0;
			ipsec_preempt_params->spi_param[pSA->natt_arr_index].fqid = 0;
			pSA->ct = NULL;
			return 0;
		}
			
	}
	if ((pSA->ct) && (pSA->ct->handle)) {
		/* The table entry belongs to cdx_ehash_delete_entry() on every
		 * arm of the DeleteKey contract, so the teardown below runs
		 * unconditionally instead of bailing out with the entry still
		 * owned by nobody (ISSUES.md A95). hw_ct is pure software with
		 * no hardware reference, so releasing it after a failed delete
		 * is safe and leaves no stale pointer to a handle this SA no
		 * longer owns.
		 *
		 * What the entry names is another matter, and this is the only
		 * place that knows: both callers -- the SA delete and an
		 * outbound next-hop rebuild, after which the SA holds no entry
		 * for its own delete to find -- come through here. A key that
		 * may still be linked may still resolve, so the ports stop, as
		 * any such key demands. An inbound SA's entry enqueues to its
		 * TO_SEC FQID, and an outbound one validates its SEC tag: both
		 * identities must stay reserved past the SA's release. The
		 * unsynced arm is out of the table and parked; it needs
		 * neither. */
		rc = cdx_ehash_delete_entry(pSA->ct->td, pSA->ct->index,
				pSA->ct->handle);
		if (rc)
			DPA_ERROR("%s::unable to remove entry from hash table\n", __func__);
		if (rc && rc != EN_EHASH_DELETE_UNSYNCED) {
			if (pSA->pSec_sa_context &&
			    pSA->pSec_sa_context->dpa_ipsecsa_handle)
				cdx_dpa_ipsecsa_keep_fqids(pSA->pSec_sa_context->dpa_ipsecsa_handle);
			cdx_ft_fatal();
		}
		pSA->ct->handle =  NULL;
		hwct = pSA->ct;
		pSA->ct = NULL;
		kfree(hwct);
		/* Propagate the tri-state (negative on failure) rather than
		 * flattening to -1; today's callers only test truthiness, so
		 * this only preserves information. */
		if (rc)
			return rc;
	}
	return 0;
}

static int cdx_ipsec_release_sa_ctx_cbk(struct timer_entry_t *entry)
{
	PSAEntry         pSA;
	PDpaSecSAContext sa_context;
	int32_t ii, ret;
	bool fq_stuck = false;

	pSA  = container_of(entry, SAEntry, deletion_timer);
	cdx_timer_del(entry);
	/* check frame queues states */
	for (ii=0; ii<NUM_FQS_PER_SA; ii++)
	{
		if (pSA->flags & (SA_FQ_WAIT_B4_FREE << ii))
		{
			ret = cdx_ipsec_sa_fq_check_if_retired_state(pSA->pSec_sa_context->dpa_ipsecsa_handle, ii);
			/* if fq is not in retired state, restart timer */
			if (ret)
			{
				/*
				 * A24b: cap the poll loop. A permanently-stuck FQ
				 * (SEC pipeline wedge, hardware fault) without this
				 * cap pins the SAEntry forever and prevents fresh
				 * SA installs from reusing the slot. On cap-hit we
				 * log loudly and skip the final free — sainfo +
				 * crypto material leak, but the rest of cdx stays
				 * recoverable in-band.
				 */
				pSA->deletion_iter++;
				if (pSA->deletion_iter >= SA_RELEASE_MAX_ITER) {
					pr_warn_ratelimited(
						"cdx: SA release timeout on handle=0x%x fq[%d] after %u polls — leaking SA resources (A24b)\n",
						pSA->handle, (int)ii, pSA->deletion_iter);
					fq_stuck = true;
					break;
				}
				cdx_timer_init((TIMER_ENTRY *)&pSA->deletion_timer,
					cdx_ipsec_release_sa_ctx_cbk);
				cdx_timer_add((TIMER_ENTRY *)&pSA->deletion_timer,
					SA_CTX_RELEASE_TIMER_VAL);
				return 0;
			}
			pSA->flags &= ~((SA_FQ_WAIT_B4_FREE << ii));
		}
	}
	if (fq_stuck) {
		/*
		 * Don't touch sainfo / sec_context / SAEntry — qman may still
		 * deliver dqrr/ern callbacks through the unretired FQ. Drop the
		 * SAEntry from cache lists so traffic can't hit it again, but
		 * leave the per-SA memory alone until the OS reboots.
		 */
		sa_remove_from_list_fqid(pSA);
		return 0;
	}
	/* delete from list_fq */
	sa_remove_from_list_fqid(pSA);

	sa_context = pSA->pSec_sa_context;
	cdx_ipsec_sec_sa_context_free(sa_context);
	pSA->pSec_sa_context = NULL;
	/* free sa memory */
	sa_free(pSA);
	return 0;
}

void cdx_ipsec_release_sa_resources(PSAEntry pSA)
{
	int ii,ret;
	pSA->flags |= SA_DELETE;
	/* Delete the hash table entry. On failure the callee has already
	 * disposed of ct/handle under the ehash tri-state (quarantine or
	 * loud leak) and cleared pSA->ct - nothing is deferred to the
	 * release timer any more. An entry that may still be linked has pinned
	 * the FQIDs and SEC identity the release below would otherwise free. */
	cdx_ipsec_delete_fp_entry(pSA);

	/* change frame queues states */
	if ((pSA->pSec_sa_context) &&
	    (pSA->pSec_sa_context->dpa_ipsecsa_handle))
	{
		for (ii = 0; ii < NUM_FQS_PER_SA; ii++) {
			ret = cdx_dpa_ipsec_retire_fq(pSA->pSec_sa_context->dpa_ipsecsa_handle, ii);

			if (ret == 1)
				pSA->flags |= (SA_FQ_WAIT_B4_FREE << ii);

		}
	}

	/* defer resource release */
	cdx_timer_init((TIMER_ENTRY *)&pSA->deletion_timer,
			cdx_ipsec_release_sa_ctx_cbk);
	cdx_timer_add((TIMER_ENTRY *)&pSA->deletion_timer,
			SA_CTX_RELEASE_TIMER_VAL);
	return;
}

PDpaSecSAContext  cdx_ipsec_sec_sa_context_alloc(uint32_t handle)
{

	PDpaSecSAContext pdpa_sec_context; 
	pdpa_sec_context = Heap_Alloc(sizeof( DpaSecSAContext));
	if(!pdpa_sec_context )
	{
		return NULL;
	}  	
	memset(pdpa_sec_context , 0, sizeof(DpaSecSAContext));
	pdpa_sec_context->cipher_data.cipher_key =
		kzalloc(MAX_CIPHER_KEY_LEN, GFP_KERNEL);
	if (!pdpa_sec_context->cipher_data.cipher_key) {
		log_err("Could not allocate memory for cipher key\n");
		cdx_ipsec_sec_sa_context_free(pdpa_sec_context); 
		return NULL;
	}
	memset(pdpa_sec_context->cipher_data.cipher_key, 0, MAX_CIPHER_KEY_LEN);
	pdpa_sec_context->auth_data.auth_key =
		kzalloc(MAX_AUTH_KEY_LEN, GFP_KERNEL);
	if (!pdpa_sec_context->auth_data.auth_key) {
		log_err("Could not allocate memory for authentication key\n");
		cdx_ipsec_sec_sa_context_free(pdpa_sec_context); 
		return NULL;
	}
	memset(pdpa_sec_context->auth_data.auth_key, 0, MAX_AUTH_KEY_LEN);

	pdpa_sec_context->auth_data.split_key =
		kzalloc(MAX_AUTH_KEY_LEN, GFP_KERNEL);
	if (!pdpa_sec_context->auth_data.split_key) {
		log_err("Could not allocate memory for authentication split key\n");
		cdx_ipsec_sec_sa_context_free(pdpa_sec_context); 
		return NULL;
	}
	memset(pdpa_sec_context->auth_data.split_key, 0, MAX_AUTH_KEY_LEN);

	pdpa_sec_context->dpa_ipsecsa_handle  = cdx_dpa_ipsecsa_alloc(NULL, handle);
	if(pdpa_sec_context->dpa_ipsecsa_handle){
		pdpa_sec_context->sec_desc =
			get_shared_desc(pdpa_sec_context->dpa_ipsecsa_handle);
		pdpa_sec_context->to_sec_fqid =
			get_fqid_to_sec(pdpa_sec_context->dpa_ipsecsa_handle);
		pdpa_sec_context->to_cp_fqid =
			ipsec_get_to_cp_fqid(pdpa_sec_context->dpa_ipsecsa_handle);
	}
	else {
		cdx_ipsec_sec_sa_context_free(pdpa_sec_context); 
		return NULL;
	}
	return pdpa_sec_context;	
}

/* How much of the shared descriptor the PDB takes, the per-SA counters that
 * trail it included.
 *
 * The encapsulation PDB carries the outer header it prepends after its fixed
 * part -- 20 bytes for IPv4, 40 for IPv6, 8 more for the UDP header of NAT-T
 * -- rounded up to whole words, and ip_hdr_len says how much. The
 * decapsulation PDB has no header of its own to carry: its length, and so the
 * counters' place, is the same for either family.
 */
static size_t cdx_ipsec_pdb_len(PSAEntry sa)
{
	struct sec_descriptor *sec_desc = sa->pSec_sa_context->sec_desc;
	size_t len = CDX_DPA_IPSEC_STATS_LEN * sizeof(u32);

	if (sa->direction == CDX_DPA_IPSEC_OUTBOUND)
		return len + sizeof(struct ipsec_encap_pdb) +
		       ((caam32_to_cpu(sec_desc->pdb_en.ip_hdr_len) + 3) & ~3);
	return len + sizeof(struct ipsec_decap_pdb);
}

/* Where the per-SA counters sit in the shared descriptor, in bytes: the last
 * CDX_DPA_IPSEC_STATS_LEN words of the PDB area, which starts behind the
 * descriptor's header word. The descriptor's MOVE commands address them by
 * this offset, and get_stats_from_sa() reads them there. */
static uint32_t cdx_ipsec_stats_offset(size_t pdb_len)
{
	return sizeof(((struct sec_descriptor *)NULL)->hdr_word) + pdb_len -
	       CDX_DPA_IPSEC_STATS_LEN * sizeof(u32);
}

static  void build_stats_descriptor_part(PSAEntry sa, size_t pdb_len)
{
	uint32_t *desc;
	uint32_t stats_offset;
	PDpaSecSAContext pSec_sa_context ;


	BUG_ON(!sa);

	pSec_sa_context= sa->pSec_sa_context;
	desc = (u32 *) pSec_sa_context->sec_desc->shared_desc;

	stats_offset = cdx_ipsec_stats_offset(pdb_len);
	sa->stats_offset = stats_offset;
	memset((u8 *)desc + stats_offset, 0, CDX_DPA_IPSEC_STATS_LEN * sizeof(u32));

	/* Copy from descriptor to MATH REG 0 the current statistics */
	append_move(desc, MOVE_SRC_DESCBUF | MOVE_DEST_MATH0 | MOVE_WAITCOMP |
			(stats_offset << MOVE_OFFSET_SHIFT) | sizeof(u64));

	/* increment REG0 by 1 */
	append_math_add_imm_u32(desc, REG0, REG0, IMM, 1);

	/* Store in the descriptor but not in external memory */
	append_move(desc, MOVE_SRC_MATH0 | MOVE_DEST_DESCBUF | MOVE_WAITCOMP |
			(stats_offset << MOVE_OFFSET_SHIFT) | sizeof(u64));

	/* Copy from descriptor to MATH REG 0 the current statistics */
	append_move(desc, MOVE_SRC_DESCBUF | MOVE_DEST_MATH0 | MOVE_WAITCOMP |
			((stats_offset + 8) << MOVE_OFFSET_SHIFT) | sizeof(u64));

	// inbound 
	if (sa->direction  == CDX_DPA_IPSEC_INBOUND)
	{
		// getting decrypted data size + padded bytes
		append_math_add(desc, REG0, VARSEQINLEN, REG0, MATH_LEN_8BYTE);

		// getting the padded bytes
		append_math_add_imm_u32(desc, REG2, VARSEQOUTLEN, IMM, 0);

		// reducing the padded bytes
		append_math_sub(desc, REG0, REG0, REG2, MATH_LEN_8BYTE);
		
	}
	else
	{
		append_math_add(desc, REG0, SEQINLEN, REG0, MATH_LEN_8BYTE);
	}

	/* Store in the descriptor but not in external memory */
	append_move(desc, MOVE_SRC_MATH0 | MOVE_DEST_DESCBUF | MOVE_WAITCOMP |
			((stats_offset + 8) << MOVE_OFFSET_SHIFT) | sizeof(u64));
}

void get_stats_from_sa(PSAEntry sa, u32* pkts, u64* bytes)
{
	uint32_t *desc;
	uint32_t *stats_desc;
	uint64_t* bytes_desc;

	PDpaSecSAContext pSec_sa_context = sa->pSec_sa_context;

	desc = (u32 *) pSec_sa_context->sec_desc->shared_desc;
	stats_desc = (u32 *)(desc + sa->stats_offset / 4);

	stats_desc++;
	*pkts =  be32_to_cpu(*stats_desc);
	/* increment 8 bytes to go to byte cnt */
	stats_desc++;
	bytes_desc = (uint64_t*)stats_desc;
	*bytes = be64_to_cpu(*bytes_desc);

	return;
}

/* The next ESN sequence number an outbound SA will send, high word then low,
 * each read once. */
static u64 cdx_ipsec_next_esn(struct sec_descriptor *sec_desc)
{
	u64 hi = caam32_to_cpu(READ_ONCE(sec_desc->pdb_en.seq_num_ext_hi));

	return hi << 32 | caam32_to_cpu(READ_ONCE(sec_desc->pdb_en.seq_num));
}

/* How many readings of an ESN number to take before settling for one. */
#define CDX_IPSEC_OSEQ_TRIES 8

/* The last sequence number an outbound SA put on the wire, in the units xfrm's
 * own oseq counts. The PDB holds the next one to send -- SEC sends the stored
 * value and then increments it, which is why cdx_ipsec_build_out_sa_pdb()
 * seeds it one past sa->seq -- so this is that value less one.
 *
 * Without ESN only the low word exists: one aligned load, and the difference
 * taken in 32 bits to match. With ESN the number spans two words that SEC's
 * store rewrites one after the other, and a reading across the carry can pair
 * either word's new value with the other's old one -- 2^32 out, high or low.
 * Re-reading the high word around the low one does not settle it, since the
 * store may write either word first; so the whole number is read until two
 * readings agree. One that never holds still is reported as the lower of its
 * last two readings: the number is only ever published forward, where low
 * errs safe and high would have a re-added SA skip 2^32 numbers.
 */
u64 get_oseq_from_sa(PSAEntry sa)
{
	struct sec_descriptor *sec_desc = sa->pSec_sa_context->sec_desc;
	unsigned int tries;
	u64 next, again, low;

	if (!(sa->flags & SA_ALLOW_EXT_SEQ_NUM))
		return (u32)(caam32_to_cpu(READ_ONCE(sec_desc->pdb_en.seq_num)) - 1);
	next = cdx_ipsec_next_esn(sec_desc);
	low = next;
	for (tries = 0; tries < CDX_IPSEC_OSEQ_TRIES; tries++) {
		again = cdx_ipsec_next_esn(sec_desc);
		if (again == next)
			return next - 1;
		low = min(next, again);
		next = again;
	}
	return low - 1;
}

static_assert(sizeof_field(struct ipsec_decap_pdb, anti_replay) ==
	      SA_REPLAY_SEEN_WORDS * sizeof(u32));

/* Where an inbound SA's anti-replay window stands, as SEC keeps it in the
 * PDB: the highest sequence number received, with the ESN high word when the
 * SA has one, and the scorecard. SEC keeps the scorecard with the newest
 * number in the least significant bit of its first word and each bit to the
 * left one older, carrying on into the next word (SEC RM, IPsec anti-replay
 * checking) -- so bit k of word k / 32 stands for seq - k. Each word is read
 * once here; the caller reads twice to know the reading did not straddle a
 * store.
 */
void get_replay_from_sa(PSAEntry sa, u64 *seq, u32 *seen)
{
	struct sec_descriptor *sec_desc = sa->pSec_sa_context->sec_desc;
	unsigned int i;

	*seq = caam32_to_cpu(READ_ONCE(sec_desc->pdb_dec.seq_num));
	if (sa->flags & SA_ALLOW_EXT_SEQ_NUM)
		*seq |= (u64)caam32_to_cpu(READ_ONCE(sec_desc->pdb_dec.seq_num_ext_hi)) << 32;
	for (i = 0; i < SA_REPLAY_SEEN_WORDS; i++)
		seen[i] = caam32_to_cpu((__force u32)READ_ONCE(sec_desc->pdb_dec.anti_replay[i]));
}

static inline void save_sa_state_in_external_mem(PSAEntry sa)
{
	uint32_t *desc;
	uint32_t stats_offset;
	uint32_t off_w, len_w;
	PDpaSecSAContext pSec_sa_context = sa->pSec_sa_context;

	desc = (u32 *) pSec_sa_context->sec_desc->shared_desc;


	/* statistics offset = predetermined offset */
	stats_offset = sa->stats_offset;

	/* RM §7.3.1: in a WAIT/SERIAL sharing flow every job must write the
	 * PDB back to memory with a STORE — that is what makes SEC order
	 * later shared-descriptor fetches against prior jobs' PDB updates
	 * (encap seq counter; decap seq + anti-replay window). The PDB
	 * occupies words 1..stats and the stats words trail it, so cover
	 * both in one store. Applies to every cipher: the legacy stats-only
	 * store left CBC/CCM/CTR refetches unordered, measured as ~840 TCP
	 * retransmits per 10 s at 2.37 Gbit/s on CBC+HMAC where GCM with
	 * this store shows ~20 (ISSUES.md N19). */
	off_w = 1;
	len_w = stats_offset / 4 - 1 + CDX_DPA_IPSEC_STATS_LEN;

	/* Store command: in the case of the Descriptor Buffer the length
	 * is specified in 4-byte words, but in all other cases the length
	 * is specified in bytes. Offset in 4 byte words */
	append_store(desc, 0, len_w, LDST_CLASS_DECO |
			(off_w << LDST_OFFSET_SHIFT) |
			LDST_SRCDST_WORD_DESCBUF_SHARED);

	/* Jump with CALM to be sure previous operation was finished */
	append_jump(desc, JUMP_COND_CALM | (1 << JUMP_OFFSET_SHIFT));
}


static int cdx_ipsec_build_shared_descriptor(PSAEntry sa,
		dma_addr_t auth_key_dma,
		dma_addr_t crypto_key_dma, u32 bytes_to_copy)
{
	uint32_t *desc, *key_jump_cmd;
	//uint32_t  copy_ptr_index = 0;
	size_t pdb_len;
	uint32_t sa_op;
	uint32_t hdr_flags;
	PDpaSecSAContext pSec_sa_context;

	pSec_sa_context =sa->pSec_sa_context;

	desc = (u32 *) pSec_sa_context->sec_desc->shared_desc;
	pdb_len = cdx_ipsec_pdb_len(sa);

	/* Sharing policy is correctness-critical for the stateful PDB —
	 * see cdx_ipsec_sh_desc_hdr_flags(). */
	hdr_flags = cdx_ipsec_sh_desc_hdr_flags(sa);

	init_sh_desc_pdb(desc, hdr_flags, pdb_len);
	if (sa->direction  == CDX_DPA_IPSEC_OUTBOUND)
		sa_op = OP_TYPE_ENCAP_PROTOCOL;
	else
		sa_op = OP_TYPE_DECAP_PROTOCOL;

	/* Key jump */
	if (((pSec_sa_context->auth_data.split_key_len) || 
		 (pSec_sa_context->auth_data.auth_key_len)) &&
		 (pSec_sa_context->cipher_data.cipher_key_len))
		key_jump_cmd = append_jump(desc, CLASS_BOTH | JUMP_TEST_ALL |
				   JUMP_COND_SHRD | JUMP_COND_SELF);
	else if (pSec_sa_context->cipher_data.cipher_key_len)
		key_jump_cmd = append_jump(desc, CLASS_1| JUMP_TEST_ALL |
				   JUMP_COND_SHRD | JUMP_COND_SELF);
	else
		key_jump_cmd = append_jump(desc, CLASS_2| JUMP_TEST_ALL |
			   JUMP_COND_SHRD | JUMP_COND_SELF);

	/* check whether a split of a normal key is used */
	if (pSec_sa_context->auth_data.split_key_len)
		/* Append split authentication key */
		append_key(desc, auth_key_dma, pSec_sa_context->auth_data.split_key_len,
				CLASS_2 | KEY_ENC | KEY_DEST_MDHA_SPLIT);
	else if (pSec_sa_context->auth_data.auth_key_len)
		/* Append normal authentication key */
		append_key(desc, auth_key_dma, pSec_sa_context->auth_data.auth_key_len,
				CLASS_2 | KEY_DEST_CLASS_REG);

	/* Append cipher key */
	if (pSec_sa_context->cipher_data.cipher_key_len)
		append_key(desc, crypto_key_dma, pSec_sa_context->cipher_data.cipher_key_len,
		   CLASS_1 | KEY_DEST_CLASS_REG);

	set_jump_tgt_here(desc, key_jump_cmd);
	if (bytes_to_copy == 0)
		goto skip_byte_copy;

	if (bytes_to_copy != ETH_HDR_LEN)
		return -EINVAL;
	{
		u8 vlan[4];
		u32 math0_bytes = LDST_CLASS_DECO | (0x38 << LDST_SRCDST_SHIFT);
		u32 math2_bytes = LDST_CLASS_DECO | (0x3a << LDST_SRCDST_SHIFT);

		/* SEC RM table 7-18: assemble MACs, internal VLAN, EtherType
		 * contiguously in Math0..2, then push them in one FIFO move
		 * (separate unaligned pushes would introduce gaps, RM 7.7.6).
		 * Consume 14 bytes and emit 18; IPsec starts at the same input.
		 */
		cdx_ipsec_vlan_tag(vlan, cdx_ipsec_key_tag_of(sa));
		append_seq_load(desc, 12, math0_bytes);
		append_seq_load(desc, 2, math2_bytes);
		append_load_as_imm(desc, vlan, sizeof(vlan),
				   LDST_CLASS_DECO | (0x39 << LDST_SRCDST_SHIFT) |
				   (4 << LDST_OFFSET_SHIFT));
		append_move(desc, MOVE_SRC_MATH0 | MOVE_DEST_OUTFIFO |
			    MOVE_WAITCOMP | (ETH_HDR_LEN + 4));
		append_seq_fifo_store(desc, FIFOST_TYPE_MESSAGE_DATA, ETH_HDR_LEN + 4);
	}

skip_byte_copy:

	/* The per-SA counters, for either outer family: cdx_ipsec_pdb_len()
	 * places them past whatever outer header the PDB carries. Outbound
	 * they count the input before the protocol runs, inbound what it left
	 * after. */
	if (sa->direction  != CDX_DPA_IPSEC_INBOUND)
	{
#ifdef PRINT_DESC
		cdx_ipsec_print_desc ( desc,__func__,__LINE__);
#endif
		build_stats_descriptor_part(sa, pdb_len);
#ifdef PRINT_DESC
		cdx_ipsec_print_desc ( desc,__func__,__LINE__);
#endif
	}

	if(sa->mode == SA_MODE_TUNNEL)
	{
		uint32_t op_word = OP_PCLID_IPSEC_TUNNEL | sa_op |
				pSec_sa_context->cipher_data.cipher_type |
				pSec_sa_context->auth_data.auth_type;
		/* Protocol specific operation */
		append_operation(desc, op_word);
	}
	else {
		uint32_t op_word = OP_PCLID_IPSEC | sa_op |
				pSec_sa_context->cipher_data.cipher_type |
				pSec_sa_context->auth_data.auth_type;
		/* Protocol specific operation */
		append_operation(desc, op_word);
	}

	if (sa->direction  == CDX_DPA_IPSEC_INBOUND)
	{
#ifdef PRINT_DESC
		cdx_ipsec_print_desc ( desc,__func__,__LINE__);
#endif
		build_stats_descriptor_part(sa, pdb_len);
#ifdef PRINT_DESC
		cdx_ipsec_print_desc ( desc,__func__,__LINE__);
#endif
	}

	save_sa_state_in_external_mem(sa);

#ifdef PRINT_DESC
	//if (sa->direction == CDX_DPA_IPSEC_OUTBOUND)
	cdx_ipsec_print_desc ( desc,__func__,__LINE__);
#endif
	if (desc_len(desc) >= MAX_CAAM_SHARED_DESCSIZE) {
		printk("%s:: Descriptor length increased more than 50 words :%x \n", __func__, desc_len(desc));
		/* shared_desc is MAX_SHARED_DESC_SIZE (62) words — zeroing to
		 * MAX_CAAM_DESCSIZE (64) overran the array by 8 bytes into the
		 * preheader alignment slack */
		memset((uint8_t *)desc + sa->stats_offset, 0,
				MAX_SHARED_DESC_SIZE * sizeof(u32) -
				sa->stats_offset);
		return -EPERM;
	}

	return 0;
}

/* The anti-replay window SEC keeps for an inbound SA, as PDB options, or
 * -EOPNOTSUPP for a width it keeps no window of.
 *
 * The ESP decapsulation PDB names three widths in its ARS bits -- 32, 64 and
 * 128 entries (RM table 9-10) -- and ipsec_decap_pdb always has room for the
 * widest scorecard. SEC's stand-alone anti-replay command takes any width up
 * to 128, but the ESP protocol does not expose it, and the 128-entry window
 * is the tunnel-mode protocol's alone: a transport SA runs the legacy one
 * (OP_PCLID_IPSEC), for which ARS128 is not a width. Each width maps to its
 * own window and nothing else maps at all. Linux refuses a number
 * replay_window or more behind the top, so a width carried on a wider window
 * would take late frames the state refuses, and on a narrower one would drop
 * frames it takes. The backend refuses such an SA when it is added
 * (cdx_ipsec_replay_window_supported()); this will not build one either. A
 * zero width comes with SA_ALLOW_SEQ_ROLL, which is anti-replay off.
 */
static int cdx_ipsec_ars(PSAEntry sa)
{
	if (sa->flags & SA_ALLOW_SEQ_ROLL)
		return PDBOPTS_ESP_ARSNONE;
	switch (sa->replay_window) {
	case 32:
		return PDBOPTS_ESP_ARS32;
	case 64:
		return PDBOPTS_ESP_ARS64;
	case 128:
		if (sa->mode == SA_MODE_TUNNEL)
			return PDBOPTS_ESP_ARS128;
		break;
	}
	return -EOPNOTSUPP;
}

/* The decapsulation PDB's replay state: where the window stands, whether its
 * numbers are extended, how wide it is, and the scorecard it starts from --
 * clear for a fresh SA, the history a re-added state brought with it
 * otherwise, so nothing it accepted before is accepted again. Options are left
 * in CPU order, as the rest of the builder keeps them until it converts the
 * word.
 *
 * With ESN the stored high word is the window top's. The SEC RM says SEC
 * holds its own stored ESN back after a rollover until the whole window is
 * past it (IPsec ESP decapsulation, "Optional use of ESN"), which in the
 * first window-width of numbers after a rollover is one below the top's. It
 * does not say which it expects of a window seeded there, nor how it tells
 * that stretch from the start of a fresh SA, whose window reaches below
 * number zero in the same way. The rig check in docs/flowtable/ipsec.md
 * settles it; until then, a state re-added inside that stretch is the case
 * to watch.
 *
 * A width SEC keeps no window of builds nothing (cdx_ipsec_ars()).
 */
static int cdx_ipsec_build_in_replay(PSAEntry sa, struct ipsec_decap_pdb *pdb)
{
	int ars = cdx_ipsec_ars(sa);
	unsigned int i;

	if (ars < 0)
		return ars;
	pdb->seq_num = cpu_to_caam32(sa->seq & SEQ_NUM_LOW_MASK);
	if (sa->flags & SA_ALLOW_EXT_SEQ_NUM) {
		pdb->seq_num_ext_hi =
			cpu_to_caam32((sa->seq & SEQ_NUM_HI_MASK) >> 32);
		pdb->options |= PDBOPTS_ESP_ESN;
	}
	pdb->options |= ars;
	if (!(sa->flags & SA_ALLOW_SEQ_ROLL))
		for (i = 0; i < SA_REPLAY_SEEN_WORDS; i++)
			pdb->anti_replay[i] =
				(__force __be32)cpu_to_caam32(sa->replay_seen[i]);
	return 0;
}

static int cdx_ipsec_build_in_sa_pdb(PSAEntry sa)
{
	struct sec_descriptor *sec_desc;
	PDpaSecSAContext psec_as_context;
	struct decap_ccm_opt *ccm_opt;
	uint8_t *salt;
	int rc;
	/*struct iphdr *outer_ip_hdr;*/

	psec_as_context = sa->pSec_sa_context;
	sec_desc= psec_as_context->sec_desc;
	memset(&sec_desc->pdb_dec, 0, sizeof(sec_desc->pdb_dec));

	rc = cdx_ipsec_build_in_replay(sa, &sec_desc->pdb_dec);
	if (rc)
		return rc;

	if(sa->mode == SA_MODE_TUNNEL)
	{
		/*
		 * Updated the offset to the point in frame were the encrypted
		 * stuff starts.
		 */
		sec_desc->pdb_dec.options |= (sa->header_len << PDBHDRLEN_ESP_DECAP_SHIFT);
		if (sa->natt.sport && sa->natt.dport) {
			/* UDP nat traversal so remove the UDP header also. */         
			sec_desc->pdb_dec.options &= 0xf000ffff;
			sec_desc->pdb_dec.options |= ((sa->header_len+UDP_HEADER_LEN) << PDBHDRLEN_ESP_DECAP_SHIFT);
		}
		/* by default copy dscp from outer to inner header */
		sec_desc->pdb_dec.options |= PDBHMO_ESP_DIFFSERV;

		if (sa->hdr_flags) {
			/*if (sa->hdr_flags & SA_HDR_COPY_TOS)
				sec_desc->pdb_dec.options |= PDBHMO_ESP_DIFFSERV; */
			if (sa->hdr_flags & SA_HDR_DEC_TTL)
				sec_desc->pdb_dec.options |= PDBHMO_ESP_DECAP_DEC_TTL;
			if (sa->hdr_flags & SA_HDR_COPY_DF)
			{
				pr_info("Copy DF bit not supported for inbound SAs");
			}
		}
	}
	else
	{
		sec_desc->pdb_dec.options |= PDBOPTS_ESP_OUTFMT;
		if (sec_era > 4)
			sec_desc->pdb_dec.options |= PDBOPTS_ESP_AOFL;

		if(sa->family == PROTO_IPV4)
		{
			sec_desc->pdb_dec.options |= (sizeof(ipv4_hdr_t) << PDBHDRLEN_ESP_DECAP_SHIFT);
			sec_desc->pdb_dec.options |= PDBOPTS_ESP_VERIFY_CSUM;
		}
		else{
			sec_desc->pdb_dec.options |= (sizeof(ipv6_hdr_t) << PDBHDRLEN_ESP_DECAP_SHIFT);
			sec_desc->pdb_dec.options |= PDBOPTS_ESP_IPVSN;
		}
		sec_desc->pdb_dec.options |= (0x01 << PDB_NH_OFFSET_SHIFT);

	}

	/*        sec_desc->pdb_dec.hmo_ip_hdr_len =
		  cpu_to_caam16(sec_desc->pdb_dec.hmo_ip_hdr_len); */
	sec_desc->pdb_dec.options = cpu_to_caam32(sec_desc->pdb_dec.options);

	salt = sa->pSec_sa_context->cipher_data.cipher_key +
						sa->pSec_sa_context->cipher_data.cipher_key_len;
	if ((sa->pSec_sa_context->cipher_data.cipher_type == OP_PCL_IPSEC_AES_GCM8) ||
			(sa->pSec_sa_context->cipher_data.cipher_type == OP_PCL_IPSEC_AES_GCM12) ||
			(sa->pSec_sa_context->cipher_data.cipher_type == OP_PCL_IPSEC_AES_GCM16))
	{
		memcpy(sec_desc->pdb_dec.gcm.salt, salt, AES_GCM_SALT_LEN);
	}

	/* CTR — RFC 3686: nonce trails the AES key, block-counter starts at 1 */
	else if (sa->pSec_sa_context->cipher_data.cipher_type == OP_PCL_IPSEC_AES_CTR)
	{
		memcpy(sec_desc->pdb_dec.ctr.ctr_nonce, salt, AES_CTR_SALT_LEN);
		sec_desc->pdb_dec.ctr.ctr_initial = cpu_to_caam32(1);
	}

	/* CCM */ // RFC 4309
	else if (sa->pSec_sa_context->cipher_data.cipher_type == OP_PCL_IPSEC_AES_CCM8)
	{
		memcpy((u8 *)(&sec_desc->pdb_dec.ccm.salt[1]), salt, AES_CCM_SALT_LEN);
		sec_desc->pdb_dec.ccm.salt[0] = 0;
		ccm_opt = (struct decap_ccm_opt *)&sec_desc->pdb_dec.ccm.ccm_opt;
		ccm_opt->b0_flags = AES_CCM_ICV8_IV_FLAG;
		ccm_opt->ctr_flags = AES_CCM_CTR_FLAG;
		ccm_opt->ctr_initial = AES_CCM_INIT_COUNTER;
	}
	else if (sa->pSec_sa_context->cipher_data.cipher_type == OP_PCL_IPSEC_AES_CCM12)
	{
		memcpy((u8 *)(&sec_desc->pdb_dec.ccm.salt[1]), salt, AES_CCM_SALT_LEN);
		sec_desc->pdb_dec.ccm.salt[0] = 0;
		ccm_opt = (struct decap_ccm_opt *)&sec_desc->pdb_dec.ccm.ccm_opt;
		ccm_opt->b0_flags = AES_CCM_ICV12_IV_FLAG;
		ccm_opt->ctr_flags = AES_CCM_CTR_FLAG;
		ccm_opt->ctr_initial = AES_CCM_INIT_COUNTER;
	}
	else if (sa->pSec_sa_context->cipher_data.cipher_type == OP_PCL_IPSEC_AES_CCM16)
	{
		memcpy((u8 *)(&sec_desc->pdb_dec.ccm.salt[1]), salt, AES_CCM_SALT_LEN);
		sec_desc->pdb_dec.ccm.salt[0] = 0;
		ccm_opt = (struct decap_ccm_opt *)&sec_desc->pdb_dec.ccm.ccm_opt;
		ccm_opt->b0_flags = AES_CCM_ICV16_IV_FLAG;
		ccm_opt->ctr_flags = AES_CCM_CTR_FLAG;
		ccm_opt->ctr_initial = AES_CCM_INIT_COUNTER;
	}
	return 0;
}

static int cdx_ipsec_build_out_sa_pdb(PSAEntry sa)
{
	struct sec_descriptor *sec_desc;
	PDpaSecSAContext psec_as_context;
	struct iphdr *outer_ip_hdr;
	struct ipv6hdr *outer_ip6_hdr;
	struct encap_ccm_opt *ccm_opt;
	uint8_t	*salt;

	uint64_t next_seq;

	psec_as_context = sa->pSec_sa_context;
	sec_desc= psec_as_context->sec_desc;
	memset(&sec_desc->pdb_en, 0, sizeof(sec_desc->pdb_en));

	//sec_desc->pdb_en.spi = cpu_to_caam32(sa->id.spi);
	sec_desc->pdb_en.spi = sa->id.spi;

	/* The PDB carries the sequence number the SEC will emit NEXT (it
	 * sends the stored value, then increments). sa->seq is the kernel
	 * checkpoint of the last sequence used — 0 on a fresh SA — so seed
	 * one past it: RFC 4303 starts the wire at 1, and Linux peers drop
	 * a seq-0 ESP packet as a replay. */
	next_seq = sa->seq + 1;

	if (sa->flags & SA_ALLOW_EXT_SEQ_NUM ) {
		sec_desc->pdb_en.seq_num_ext_hi =
			cpu_to_caam32((next_seq & SEQ_NUM_HI_MASK) >> 32);
		sec_desc->pdb_en.options |= PDBOPTS_ESP_ESN;
	}
	sec_desc->pdb_en.seq_num =
		cpu_to_caam32(next_seq & SEQ_NUM_LOW_MASK);


	/* The counter modes need an IV that never repeats under the key, and
	 * SEC's random ones are 64 bits: two collide after about 2^32 frames,
	 * and one GCM collision gives away the authentication key. Without
	 * IVSRC, SEC sends the PDB's IV and counts it up per frame, and the
	 * PDB store carries it from job to job. Each SA starts at a random
	 * point, as Linux's seqiv salts each instance, so a re-add with the
	 * same key and a stale sequence number cannot repeat one either. CBC
	 * keeps SEC's random IVs: it needs them unpredictable, not unique. */
	switch (psec_as_context->cipher_data.cipher_type) {
	case OP_PCL_IPSEC_AES_GCM8:
	case OP_PCL_IPSEC_AES_GCM12:
	case OP_PCL_IPSEC_AES_GCM16:
		sec_desc->pdb_en.gcm.iv = cpu_to_caam64(get_random_u64());
		break;
	case OP_PCL_IPSEC_AES_CCM8:
	case OP_PCL_IPSEC_AES_CCM12:
	case OP_PCL_IPSEC_AES_CCM16:
		sec_desc->pdb_en.ccm.iv = cpu_to_caam64(get_random_u64());
		break;
	case OP_PCL_IPSEC_AES_CTR:
		sec_desc->pdb_en.ctr.iv = cpu_to_caam64(get_random_u64());
		break;
	default:
		sec_desc->pdb_en.options |= PDBOPTS_ESP_IVSRC;
		break;
	}

	if(sa->mode == SA_MODE_TUNNEL)
	{
		sec_desc->pdb_en.options |= PDBOPTS_OIHI_FROM_PDB;

		if (sa->hdr_flags) {
			if (sa->hdr_flags & SA_HDR_DEC_TTL)
				sec_desc->pdb_en.options |= PDBHMO_ESP_ENCAP_DEC_TTL;
			if (sa->hdr_flags & SA_HDR_COPY_DF){
				if (sa->family == PROTO_IPV4)
					sec_desc->pdb_en.options |= PDBHMO_ESP_DFBIT ;
				else
					pr_warn("Copy DF not supported for IPv6 SA");
			}

		}

		/* Copy the outer header and generate the original header checksum */
		memcpy(&sec_desc->pdb_en.ip_hdr[0],
				&sa->tunnel.ip4,
				sa->header_len);
		sec_desc->pdb_en.ip_hdr_len = sa->header_len ;
		if (sa->natt.sport && sa->natt.dport) {
			struct udphdr *udp_hdr;
			uint8_t *tmp;
			tmp = (uint8_t *) &sec_desc->pdb_en.ip_hdr[0];
			udp_hdr = (struct udphdr *) (tmp + sa->header_len);
			udp_hdr->source = htons(sa->natt.sport);
			udp_hdr->dest = htons(sa->natt.dport);
			udp_hdr->check = 0x0000;
			udp_hdr->len = 0x0000;
			/* ip header should include the 4 byte of UDP port fileds */
			sec_desc->pdb_en.ip_hdr_len += UDP_HEADER_LEN ;
			sec_desc->pdb_en.options |= PDBOPTS_NAT;
			sec_desc->pdb_en.options |= PDBOPTS_NAT_UDP_CHECKSM;

			if (sa->header_len == IPV4_HDR_SIZE ) {
				outer_ip_hdr = (struct iphdr *)
					&sec_desc->pdb_en.ip_hdr[0];
				outer_ip_hdr->protocol = IPPROTO_UDP;
			}else{
				outer_ip6_hdr = (struct ipv6hdr *) &sec_desc->pdb_en.ip_hdr[0];
				outer_ip6_hdr->nexthdr = IPPROTO_UDP;
			}
		}

		/* Update endianness of this value to match SEC endianness: */
		sec_desc->pdb_en.ip_hdr_len =
			cpu_to_caam32(sec_desc->pdb_en.ip_hdr_len);

		if (sa->family == PROTO_IPV4) {
			outer_ip_hdr = (struct iphdr *) &sec_desc->pdb_en.ip_hdr[0];
			if (!sa->natt.sport && !sa->natt.dport) 
				outer_ip_hdr->protocol = IPPROTO_ESP; 
			outer_ip_hdr->tot_len = ((sec_desc->pdb_en.ip_hdr_len >> 16) & 0xffff) ;
			outer_ip_hdr->check =
				ip_fast_csum((unsigned char *)outer_ip_hdr,
						outer_ip_hdr->ihl);
		}
		else{
			outer_ip6_hdr = (struct ipv6hdr *) &sec_desc->pdb_en.ip_hdr[0];
			if (!sa->natt.sport && !sa->natt.dport)
				outer_ip6_hdr->nexthdr = IPPROTO_ESP;
		}
	}
	else /* transport mode */
	{
		sec_desc->pdb_en.options |= PDBOPTS_ESP_INCIPHDR;

		if(sa->family == PROTO_IPV4)
		{
			sec_desc->pdb_en.ip_hdr_len = sizeof(ipv4_hdr_t);
			sec_desc->pdb_en.options |= PDBOPTS_ESP_UPDATE_CSUM;
		}
		else{
			sec_desc->pdb_en.ip_hdr_len = sizeof(ipv6_hdr_t);
			sec_desc->pdb_en.options |= PDBOPTS_ESP_IPV6;
		}
		sec_desc->pdb_en.options |= (0x01 << PDB_NH_OFFSET_SHIFT);
		sec_desc->pdb_en.options |= (IPPROTO_ESP << PDBNH_ESP_ENCAP_SHIFT);
		/* Update endianness of this value to match SEC endianness: */
		sec_desc->pdb_en.ip_hdr_len = cpu_to_caam32(sec_desc->pdb_en.ip_hdr_len);
	}


	sec_desc->pdb_en.options = cpu_to_caam32(sec_desc->pdb_en.options);
	salt = sa->pSec_sa_context->cipher_data.cipher_key+sa->pSec_sa_context->cipher_data.cipher_key_len;
	/*printk("%s(%d) salt [0] %02x,[1] %02x [2] %02x, [3] %02x\n",
		__func__,__LINE__,salt[0],salt[1],salt[2],salt[3]); */
	if ((sa->pSec_sa_context->cipher_data.cipher_type == OP_PCL_IPSEC_AES_GCM8) ||
			(sa->pSec_sa_context->cipher_data.cipher_type == OP_PCL_IPSEC_AES_GCM12) ||
			(sa->pSec_sa_context->cipher_data.cipher_type == OP_PCL_IPSEC_AES_GCM16))
	{
		memcpy(sec_desc->pdb_en.gcm.salt, salt,  AES_GCM_SALT_LEN);
	}

	/* CTR — RFC 3686. The per-packet 8-byte iv counts up from the PDB's. */
	else if (sa->pSec_sa_context->cipher_data.cipher_type == OP_PCL_IPSEC_AES_CTR)
	{
		memcpy(sec_desc->pdb_en.ctr.ctr_nonce, salt, AES_CTR_SALT_LEN);
		sec_desc->pdb_en.ctr.ctr_initial = cpu_to_caam32(1);
	}

	/* AES CCM */
	else if (sa->pSec_sa_context->cipher_data.cipher_type == OP_PCL_IPSEC_AES_CCM8)
	{
		memcpy((u8 *)(&sec_desc->pdb_en.ccm.salt[1]), salt, AES_CCM_SALT_LEN);
		sec_desc->pdb_en.ccm.salt[0] = 0;
		ccm_opt = (struct encap_ccm_opt *)&sec_desc->pdb_en.ccm.ccm_opt;
		ccm_opt->b0_flags = AES_CCM_ICV8_IV_FLAG;
		ccm_opt->ctr_flags = AES_CCM_CTR_FLAG;
		ccm_opt->ctr_initial = AES_CCM_INIT_COUNTER;
	}
	else if (sa->pSec_sa_context->cipher_data.cipher_type == OP_PCL_IPSEC_AES_CCM12)
	{
		memcpy((u8 *)(&sec_desc->pdb_en.ccm.salt[1]), salt, AES_CCM_SALT_LEN);
		sec_desc->pdb_en.ccm.salt[0] = 0;
		ccm_opt = (struct encap_ccm_opt *)&sec_desc->pdb_en.ccm.ccm_opt;
		ccm_opt->b0_flags = AES_CCM_ICV12_IV_FLAG;
		ccm_opt->ctr_flags = AES_CCM_CTR_FLAG;
		ccm_opt->ctr_initial = AES_CCM_INIT_COUNTER;
	}
	else if (sa->pSec_sa_context->cipher_data.cipher_type == OP_PCL_IPSEC_AES_CCM16)
	{
		memcpy((u8 *)(&sec_desc->pdb_en.ccm.salt[1]), salt, AES_CCM_SALT_LEN);
		sec_desc->pdb_en.ccm.salt[0] = 0;
		ccm_opt = (struct encap_ccm_opt *)&sec_desc->pdb_en.ccm.ccm_opt;
		ccm_opt->b0_flags = AES_CCM_ICV16_IV_FLAG;
		ccm_opt->ctr_flags = AES_CCM_CTR_FLAG;
		ccm_opt->ctr_initial = AES_CCM_INIT_COUNTER;
	}

	return 0;
}

int  cdx_ipsec_create_shareddescriptor(PSAEntry sa, uint32_t bytes_to_copy)
{
	struct sec_descriptor *sec_desc;
	dma_addr_t auth_key_dma = 0;
	dma_addr_t crypto_key_dma;
	dma_addr_t shared_desc_dma;
	int ret = 0;
	uint32_t bpid;
	uint32_t buf_size;
	PDpaSecSAContext psec_sa_context;

	if (!jrdev_g)
		return -ENODEV;
	if (cdx_dpa_get_ipsec_pool_info(&bpid, &buf_size))
		return -EIO;
	psec_sa_context = sa->pSec_sa_context;
	if (sa->direction == CDX_DPA_IPSEC_OUTBOUND)
		ret = cdx_ipsec_build_out_sa_pdb(sa);
	else
		ret = cdx_ipsec_build_in_sa_pdb(sa);
	if (ret)
		return ret;

	/* check whether a split or a normal key is used */
	if (psec_sa_context->auth_data.split_key_len) {
		auth_key_dma = dma_map_single(jrdev_g, 
				psec_sa_context->auth_data.split_key,
				psec_sa_context->auth_data.split_key_pad_len,
				DMA_TO_DEVICE);
		if (dma_mapping_error(jrdev_g, auth_key_dma)) {
			log_err("Could not DMA map authentication key\n");
			return -EINVAL;
		}
	}
	else if (psec_sa_context->auth_data.auth_key_len) {
		auth_key_dma = dma_map_single(jrdev_g, 
				psec_sa_context->auth_data.auth_key,
				psec_sa_context->auth_data.auth_key_len,
				DMA_TO_DEVICE);
		if (dma_mapping_error(jrdev_g, auth_key_dma)) {
			log_err("Could not DMA map authentication key\n");
			return -EINVAL;
		}
	}

	crypto_key_dma = dma_map_single(jrdev_g,
			psec_sa_context->cipher_data.cipher_key,
			psec_sa_context->cipher_data.cipher_key_len,
			DMA_TO_DEVICE);
	if (dma_mapping_error(jrdev_g, crypto_key_dma)) {
		log_err("Could not DMA map cipher key\n");
		ret = -EINVAL;
		goto err_unmap_auth;
	}

	/*
	 * The shared descriptor, which has to fit in the words SEC's queue
	 * interface leaves it (MAX_CAAM_SHARED_DESCSIZE).
	 *
	 * There is no second, larger form. NXP's extended builder took an
	 * outbound SA that overflowed this one by loading the rest of its
	 * program from a side buffer, and it never stored the PDB back after
	 * a job: nothing ordered SEC's refetch of the sequence number against
	 * another DECO's update of it (RM 7.3.1, save_sa_state_in_external_mem()),
	 * and the number read back for xfrm stayed where the SA was installed,
	 * so a keying daemon re-adding the SA from it restarted it behind
	 * numbers its peer had already seen. The internal VLAN leaves only
	 * one word below the rejection threshold: CBC or CCM with a split
	 * HMAC key behind an IPv6 NAT-T outer header builds 49 words (GCM,
	 * with no authentication key, 46). An SA that overflows is therefore
	 * a change to the builder, said loudly, and the SA is refused rather
	 * than installed on a descriptor that cannot keep its sequence.
	 */
	ret = cdx_ipsec_build_shared_descriptor(sa, auth_key_dma, crypto_key_dma,
			bytes_to_copy);
	if (ret) {
		WARN_ONCE(ret == -EPERM,
			  "cdx: IPsec SA spi %#x overflows the %d-word shared descriptor\n",
			  be32_to_cpu((__force __be32)sa->id.spi), MAX_CAAM_SHARED_DESCSIZE);
		log_err("Failed to create SEC descriptor for SA with spi %#x\n",
			be32_to_cpu((__force __be32)sa->id.spi));
		ret = -EFAULT;
		goto err_unmap_crypto;
	}

	sec_desc = psec_sa_context->sec_desc;
	/* setup preheader */

	PREHEADER_PREP_IDLEN(sec_desc->preheader,
			desc_len(sec_desc->shared_desc));
	PREHEADER_PREP_BPID(sec_desc->preheader, bpid);
	PREHEADER_PREP_BSIZE(sec_desc->preheader, buf_size); // 0 indicates max size
	if (sa->direction  == CDX_DPA_IPSEC_INBOUND) {
		PREHEADER_PREP_OFFSET(sec_desc->preheader,
				post_sec_in_data_off);
	}
	else
	{
		PREHEADER_PREP_OFFSET(sec_desc->preheader,
				post_sec_out_data_off);
	}
	//printk("%s::preheader %p\n", __func__,
	//	(void *)sec_desc->preheader);
	sec_desc->preheader = cpu_to_caam64(sec_desc->preheader);

	/* The KEY commands embedded above reference these bus addresses on
	 * every SEC job — keep the mappings alive for the SA lifetime
	 * instead of unmapping here (DMA-API use-after-unmap otherwise;
	 * ISSUES.md N18). Released in cdx_ipsec_sec_sa_context_free(). */
	psec_sa_context->crypto_key_dma = crypto_key_dma;
	psec_sa_context->auth_key_dma = auth_key_dma;
	/* Flush the CPU-cached writes to sec_desc (preheader, PDB,
	 * shared_desc) out to memory so the SEC engine reads them
	 * correctly later. The address is unused; only the cache-sync
	 * side-effect of the map/unmap pair matters. */
	shared_desc_dma = dma_map_single(jrdev_g, sec_desc,
			sizeof(struct sec_descriptor),
			DMA_TO_DEVICE);
	dma_unmap_single(jrdev_g, shared_desc_dma,
			sizeof(struct sec_descriptor),
			DMA_TO_DEVICE);
	return 0;

err_unmap_crypto:
	dma_unmap_single(jrdev_g, crypto_key_dma,
			psec_sa_context->cipher_data.cipher_key_len,
			DMA_TO_DEVICE);
err_unmap_auth:
	/* mirror the map-site guard (split_key_len); the mapped length is
	 * still split_key_pad_len */
	if (psec_sa_context->auth_data.split_key_len)
		dma_unmap_single(jrdev_g, auth_key_dma,
				psec_sa_context->auth_data.split_key_pad_len,
				DMA_TO_DEVICE);
	else if (psec_sa_context->auth_data.auth_key_len)
		dma_unmap_single(jrdev_g, auth_key_dma,
				psec_sa_context->auth_data.auth_key_len,
				DMA_TO_DEVICE);
	return ret;
}

#ifdef CDX_DEBUG_SPLIT_KEY_FAIL
/*
 * Split-key fault injection -- DEBUG-ONLY, NOT FOR PRODUCTION.
 *
 * Deriving an SA's HMAC split key is a SEC job, and one that fails on real
 * hardware means a full or faulted job ring -- not reproducible on demand.
 * Write a decimal count to /proc/cdx_split_key_fail and that many of the
 * following split-key jobs halt on SEC with a user status before doing
 * anything else (a JUMP of type "halt with user-specified status", SEC RM
 * 7.20.1.5), so the job completes with an error through the same callback
 * a real failure takes. Reading the file back reports how many are still
 * armed.
 *
 * Production (Armbian) builds DO NOT define CDX_DEBUG_SPLIT_KEY_FAIL. The
 * flag is set only in the meta-ask test image, and the probe pr_warn_once's
 * at init so an accidental enable surfaces loudly.
 */
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

#define SPLIT_KEY_FAIL_PROC_NAME "cdx_split_key_fail"
/* What an armed job reports: any non-zero LOCAL OFFSET is an error. */
#define CDX_SPLIT_KEY_FAULT_STATUS 0x5a

static atomic_t split_key_fail_countdown = ATOMIC_INIT(0);
static struct proc_dir_entry *split_key_fail_proc;

/* Whether this job is one of the armed ones, consuming it if so. */
static bool cdx_ipsec_split_key_fault(void)
{
	/* atomic_dec_if_positive() returns the post-decrement value, so
	 * >= 0 means an armed job was actually taken. */
	return atomic_dec_if_positive(&split_key_fail_countdown) >= 0;
}

static int split_key_fail_show(struct seq_file *m, void *v)
{
	seq_printf(m, "armed=%d\n", atomic_read(&split_key_fail_countdown));
	return 0;
}

static int split_key_fail_open(struct inode *inode, struct file *file)
{
	return single_open(file, split_key_fail_show, NULL);
}

static ssize_t split_key_fail_write(struct file *file, const char __user *buf,
				    size_t len, loff_t *ppos)
{
	char kbuf[16];
	unsigned int n;

	if (len == 0 || len >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, buf, len))
		return -EFAULT;
	kbuf[len] = '\0';
	if (kstrtouint(strim(kbuf), 0, &n))
		return -EINVAL;
	/* The countdown is an atomic_t, so anything that would not survive
	 * the cast is rejected rather than silently wrapped negative. */
	if (n > (unsigned int)INT_MAX)
		return -EINVAL;
	atomic_set(&split_key_fail_countdown, (int)n);
	return len;
}

static const struct proc_ops split_key_fail_proc_ops = {
	.proc_open    = split_key_fail_open,
	.proc_read    = seq_read,
	.proc_write   = split_key_fail_write,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

int cdx_ipsec_init_split_key_fail_probe(void)
{
	pr_warn_once("cdx: CDX_DEBUG_SPLIT_KEY_FAIL is on - /proc/%s can fail IPsec split-key jobs; do not ship\n",
		     SPLIT_KEY_FAIL_PROC_NAME);
	split_key_fail_proc = proc_create(SPLIT_KEY_FAIL_PROC_NAME, 0600, NULL,
					  &split_key_fail_proc_ops);
	return split_key_fail_proc ? 0 : -ENOMEM;
}

void cdx_ipsec_remove_split_key_fail_probe(void)
{
	if (split_key_fail_proc) {
		proc_remove(split_key_fail_proc);
		split_key_fail_proc = NULL;
	}
}
#endif /* CDX_DEBUG_SPLIT_KEY_FAIL */

/* The MDHA algorithm an authenticator's split key is derived with, or 0 when
 * it has none: XCBC derives its keys inside the protocol operation. */
static int cdx_ipsec_get_split_key_info(struct auth_params *auth_param, u32 *hmac_alg)
{
	switch (auth_param->auth_type) {
		case OP_PCL_IPSEC_HMAC_MD5_96:
		case OP_PCL_IPSEC_HMAC_MD5_128:
			*hmac_alg = OP_ALG_ALGSEL_MD5;
			break;
		case OP_PCL_IPSEC_HMAC_SHA1_96:
		case OP_PCL_IPSEC_HMAC_SHA1_160:
			*hmac_alg = OP_ALG_ALGSEL_SHA1;
			break;
		case OP_PCL_IPSEC_HMAC_SHA2_256_128:
			*hmac_alg = OP_ALG_ALGSEL_SHA256;
			break;
		case OP_PCL_IPSEC_HMAC_SHA2_384_192:
			*hmac_alg = OP_ALG_ALGSEL_SHA384;
			break;
		case OP_PCL_IPSEC_HMAC_SHA2_512_256:
			*hmac_alg = OP_ALG_ALGSEL_SHA512;
			break;
		case OP_PCL_IPSEC_AES_XCBC_MAC_96:
			*hmac_alg = 0;
			break;
		default:
			log_err("Unsupported authentication algorithm\n");
			return -EINVAL;
	}
	return 0;
}

/* Derive the SA's HMAC split key: the key's inner and outer pads, which SEC
 * writes encrypted under its job-descriptor key-encryption key and which the
 * shared descriptor then loads for every frame (KEY_ENC | KEY_DEST_MDHA_SPLIT).
 *
 * Returns 0 once the key is in place, and otherwise a negative errno with no
 * split key recorded: -ENOMEM when the job could not be built or mapped,
 * -EBUSY when the job ring had no room for it, -EIO when SEC failed it. An SA
 * whose split key was never written would carry a key SEC never derived, and
 * every frame it authenticated would fail its peer's check or SEC's own.
 *
 * The job is waited for without a bound, as the kernel's gen_split_key()
 * waits. A job the ring accepted always completes, and the descriptor, both
 * buffers and the result it reports into must all outlive it: giving up
 * early would leave SEC reading a freed descriptor and its completion
 * writing into a returned stack frame. Every caller is in process context.
 */
int cdx_ipsec_generate_split_key(struct auth_params *auth_param)
{
	struct split_key_result result;
	dma_addr_t dma_addr_in, dma_addr_out;
	u32 *desc, alg_sel = 0, key_len, pad_len;
	int ret;

	auth_param->split_key_len = 0;
	auth_param->split_key_pad_len = 0;
	if (!jrdev_g)
		return -ENODEV;

	ret = cdx_ipsec_get_split_key_info(auth_param, &alg_sel);
	/* exit if error or there is no need to compute a split key */
	if (ret < 0 || alg_sel == 0)
		return ret;
	key_len = split_key_len(alg_sel);
	pad_len = split_key_pad_len(alg_sel);

	desc = kmalloc(CAAM_CMD_SZ * 6 + CAAM_PTR_SZ * 2, GFP_KERNEL | GFP_DMA);
	if (!desc) {
		log_err("Allocate memory failed for split key desc\n");
		return -ENOMEM;
	}

	dma_addr_in = dma_map_single(jrdev_g, auth_param->auth_key,
			auth_param->auth_key_len, DMA_TO_DEVICE);
	if (dma_mapping_error(jrdev_g, dma_addr_in)) {
		dev_err(jrdev_g, "Unable to DMA map the input key address\n");
		ret = -ENOMEM;
		goto out_free;
	}

	dma_addr_out = dma_map_single(jrdev_g, auth_param->split_key, pad_len,
			DMA_FROM_DEVICE);
	if (dma_mapping_error(jrdev_g, dma_addr_out)) {
		dev_err(jrdev_g, "Unable to DMA map the output key address\n");
		ret = -ENOMEM;
		goto out_unmap_in;
	}
	init_job_desc(desc, 0);
#ifdef CDX_DEBUG_SPLIT_KEY_FAIL
	/* First, so an armed job does nothing but fail. */
	if (cdx_ipsec_split_key_fault())
		append_jump(desc, JUMP_TYPE_HALT_USER | JUMP_TEST_ALL |
			    CDX_SPLIT_KEY_FAULT_STATUS);
#endif

	append_key(desc, dma_addr_in, auth_param->auth_key_len,
			CLASS_2 | KEY_DEST_CLASS_REG);

	/* Sets MDHA up into an HMAC-INIT */
	/*	append_operation(desc, (OP_ALG_TYPE_CLASS2 << OP_ALG_TYPE_SHIFT) | */
	append_operation(desc, OP_ALG_TYPE_CLASS2 |
			alg_sel | OP_ALG_AAI_HMAC |
			OP_ALG_DECRYPT | OP_ALG_AS_INIT);

	/* Do a FIFO_LOAD of zero, this will trigger the internal key expansion
	   into both pads inside MDHA */
	append_fifo_load_as_imm(desc, NULL, 0, LDST_CLASS_2_CCB |
			FIFOLD_TYPE_MSG | FIFOLD_TYPE_LAST2);

	/* FIFO_STORE with the explicit split-key content store
	 * (0x26 output type) */
	append_fifo_store(desc, dma_addr_out, key_len,
			LDST_CLASS_2_CCB | FIFOST_TYPE_SPLIT_KEK);

	/* The kernel's own completion for split-key jobs: split_key_done()
	 * reports SEC's status through caam_jr_strstatus() and completes. */
	result.err = 0;
	init_completion(&result.completion);
	ret = caam_jr_enqueue(jrdev_g, desc, split_key_done, &result);
	if (ret == -EINPROGRESS) {
		wait_for_completion(&result.completion);
		ret = result.err ? -EIO : 0;
	} else {
		/* Nothing was queued, so there is nothing to wait for. A full
		 * ring is busy rather than out of space, and a descriptor it
		 * could not map is out of memory like ours above. */
		log_err("split key job not queued: %d\n", ret);
		ret = ret == -ENOSPC ? -EBUSY : ret == -EIO ? -ENOMEM : ret;
	}

	dma_unmap_single(jrdev_g, dma_addr_out, pad_len, DMA_FROM_DEVICE);
out_unmap_in:
	dma_unmap_single(jrdev_g, dma_addr_in, auth_param->auth_key_len,
			DMA_TO_DEVICE);
out_free:
	kfree(desc);
	if (!ret) {
		auth_param->split_key_len = key_len;
		auth_param->split_key_pad_len = pad_len;
	} else {
		/* A job SEC failed may have stored part of a key before it
		 * stopped; none of it is kept. */
		memzero_explicit(auth_param->split_key, pad_len);
	}
	return ret;
}

/* Fill the key information required for NATT (UDP) connection */
static int fill_natt_key_info(PSAEntry sa, struct en_exthash_tbl_entry *tbl_entry, uint32_t port_id)
{
	union dpa_key *key;
	unsigned char *saddr, *daddr;
	uint32_t key_size;
	int i;

	key = (union dpa_key *)&tbl_entry->hashentry.key[0];
	/*portid added to key */
	key->portid = port_id;

	if(sa->family == PROTO_IPV4)
	{
		key_size = (sizeof(struct ipv4_tcpudp_key) + 1);
		key->ipv4_tcpudp_key.ipv4_saddr = sa->id.saddr[0];
		key->ipv4_tcpudp_key.ipv4_daddr = sa->id.daddr.a6[0];
		key->ipv4_tcpudp_key.ipv4_protocol = IPPROTO_UDP;
		key->ipv4_tcpudp_key.ipv4_sport = cpu_to_be16(sa->natt.sport);
		key->ipv4_tcpudp_key.ipv4_dport = cpu_to_be16(sa->natt.dport);
	}
	else
	{
		saddr = (unsigned char*)&sa->id.saddr[0];
		daddr = (unsigned char*)&sa->id.daddr.a6[0];
		key_size = (sizeof(struct ipv6_tcpudp_key) + 1);
		for (i = 0; i < 16; i++)
			key->ipv6_tcpudp_key.ipv6_saddr[i] = saddr[i];
		for (i = 0; i < 16; i++)
			key->ipv6_tcpudp_key.ipv6_daddr[i] = daddr[i];

		key->ipv6_tcpudp_key.ipv6_protocol = IPPROTO_UDP;
		key->ipv6_tcpudp_key.ipv6_sport = cpu_to_be16(sa->natt.sport);
		key->ipv6_tcpudp_key.ipv6_dport = cpu_to_be16(sa->natt.dport);
	}
	return(key_size);
}

static int fill_ipsec_key_info(PSAEntry sa, struct en_exthash_tbl_entry *tbl_entry, 
		uint32_t port_id)
{
	union dpa_key *key;
	uint32_t key_size;
	uint32_t ii;
	uint8_t *sptr;

	key = (union dpa_key *)&tbl_entry->hashentry.key[0];
	//portid added to key
	key->portid = port_id;
	key_size = 1;

	if(sa->family == PROTO_IPV4)
	{
		key_size += sizeof(struct ipv4_esp_key);
		key->ipv4_esp_key.ipv4_daddr = sa->id.daddr.a6[0];
		key->ipv4_esp_key.ipv4_protocol = IPPROTOCOL_ESP;
		key->ipv4_esp_key.spi = sa->id.spi;
	}
	else
	{
		key_size += sizeof(struct ipv6_esp_key);
		sptr = (uint8_t *)&sa->id.daddr;
		for (ii = 0; ii < 16; ii++)
			key->ipv6_tcpudp_key.ipv6_saddr[ii] = *(sptr + ii);
		key->ipv6_esp_key.ipv6_protocol = IPPROTOCOL_ESP;
		key->ipv6_esp_key.spi = sa->id.spi;
	}
	return (key_size);
}


static int get_tbl_type(PSAEntry sa) 
{
	if (IS_NATT_SA(sa))
	{
		if(sa->family == PROTO_IPV4)
			return IPV4_UDP_TABLE;
		else
			return IPV6_UDP_TABLE;
	}
	else
	{
		
		if(sa->family == PROTO_IPV4)
			return ESP_IPV4_TABLE;
		else
			return ESP_IPV6_TABLE;
	}

}

/* This function processes NAT-T packets by
 - Checks if there are any NATT SAs with the matched 5-tuple entries
 - If found and already programmed to Fast path, update the array mask and fill the new spi's in the fast path entry
-- If not found then add the new entry as UDP tuple entry

Inbound SAs share their UDP classifier but retain distinct SEC tags; the SPI
selects the decrypting SA. Outbound rekeying SAs share both the UDP output root
and its tag. That tag is reserved exclusively for authenticated encrypted
output of this tunnel, and is never assigned to an inbound SA.
*/

int cdx_ipsec_process_udp_classification_table_entry(PSAEntry sa)
{
	/* Check if the entry already exists */
	PSAEntry natt_sa;
	int arr_index;
	struct en_exthash_tbl_entry *natt_tbl_entry;
	struct en_ehash_ipsec_preempt_op *ipsec_preempt_params;
	uint32_t* sa_addr;
	uint32_t bytes_to_copy = ETH_HDR_LEN;

	natt_sa = M_ipsec_get_matched_natt_tunnel(sa);

	if (natt_sa && natt_sa->ct)
	{
		/* An output root authorizes encrypted output for this exact
		 * UDP tunnel, not an inbound SA's plaintext. Rekeying SAs may
		 * share that root and tag; inbound identities never share it.
		 * A built descriptor cannot change identity under queued work. */
		if (sa->direction == CDX_DPA_IPSEC_OUTBOUND) {
			/* The shared action also owns the egress framing and MTU. */
			if (sa->netdev != natt_sa->netdev ||
			    !sa->pRtEntry || !natt_sa->pRtEntry ||
			    sa->pRtEntry->itf != natt_sa->pRtEntry->itf ||
			    sa->pRtEntry->mtu != natt_sa->pRtEntry->mtu ||
			    memcmp(sa->pRtEntry->dstmac, natt_sa->pRtEntry->dstmac,
				   ETHER_ADDR_LEN))
				goto err_ret;
			if (sa->flags & SA_SH_DESC_BUILT) {
				if (cdx_ipsec_key_tag_of(sa) != cdx_ipsec_key_tag_of(natt_sa))
					goto err_ret;
			} else {
				ipsec_share_key_tag(sa->pSec_sa_context->dpa_ipsecsa_handle,
						    natt_sa->pSec_sa_context->dpa_ipsecsa_handle);
			}
		}
		if (sa->direction == CDX_DPA_IPSEC_INBOUND)
			sa_addr = &sa->id.daddr.a6[0];
		else
			sa_addr = &sa->id.saddr[0];

		if( dpa_get_iface_info_by_ipaddress(sa->family, sa_addr, NULL,
					NULL , NULL, (uint32_t)sa->handle) != SUCCESS)
		{
			DPA_ERROR("%s:: dpa_get_iface_info_by_ipaddress returned error\n", 
					__func__);
			 goto err_ret;
		}
		if (!(sa->flags & SA_SH_DESC_BUILT))
		{
			if (cdx_ipsec_create_shareddescriptor(sa, bytes_to_copy)) {
				DPA_ERROR("%s::unable to create shared desc\n", __func__);
				goto err_ret;
			}
			sa->flags |= SA_SH_DESC_BUILT;
		}

		sa->ct = natt_sa->ct;
		
		/* We need to lock this section of code */
		if (sa->direction ==  CDX_DPA_IPSEC_INBOUND)
		{
			/* update in table entry */
			natt_tbl_entry = (struct en_exthash_tbl_entry *)sa->ct->handle;
			ipsec_preempt_params = (struct en_ehash_ipsec_preempt_op*) natt_tbl_entry->ipsec_preempt_params;
			arr_index = get_free_natt_arr_index(be16_to_cpu(ipsec_preempt_params->natt_arr_mask));
			if (arr_index >= MAX_SPI_PER_FLOW)
			{
				/* No refcount was taken on the shared ct; leaving
				 * the pointer set would make a later delete steal a
				 * reference this SA never held. Callers enter with
				 * sa->ct NULL, so this restores that invariant. */
				sa->ct = NULL;
				goto err_ret;
			}
			sa->ct->natt_in_refcnt++;
			ipsec_preempt_params->spi_param[arr_index].spi = sa->id.spi;
			ipsec_preempt_params->spi_param[arr_index].fqid = cpu_to_be32(sa->pSec_sa_context->to_sec_fqid);
			set_natt_arr_mask(&ipsec_preempt_params->natt_arr_mask, arr_index);
			sa->natt_arr_index = arr_index;
#ifdef CDX_DPA_DEBUG
			printk(" SPI : %x - natt_arr_mask :%x\n", sa->id.spi, ipsec_preempt_params->natt_arr_mask);
			display_ehash_tbl_entry(&natt_tbl_entry->hashentry, 14);
#endif
		}
		else
			sa->ct->natt_out_refcnt++;
	}
	else{
		if (cdx_ipsec_add_classification_table_entry(sa))
			goto err_ret;
		if (sa->direction ==  CDX_DPA_IPSEC_INBOUND)
			sa->ct->natt_in_refcnt = 1;
		else
			sa->ct->natt_out_refcnt = 1;
	}
	
	return SUCCESS;
err_ret:
	return FAILURE;
}

int  cdx_ipsec_add_classification_table_entry(PSAEntry sa)
{
	int retval;
	uint32_t flags;
	uint8_t *ptr;
	uint32_t key_size;
	int tbl_type;
	struct ins_entry_info *info;
	struct en_exthash_tbl_entry *tbl_entry;
	uint32_t sa_dir_in = 0;
	uint32_t  itf_id = 0;
	uint32_t bytes_to_copy = ETH_HDR_LEN;
	bool sh_desc_just_built = false;


#ifdef CDX_DPA_DEBUG
	printk("%s:: direction %d\n", __func__, sa->direction);
#endif

	info = kzalloc(sizeof(struct ins_entry_info), GFP_KERNEL);
	if (!info) {
		DPA_ERROR("%s::unable to alloc mem for ins_info\n", __func__);
		//remove shared desc here??? TBD
		return FAILURE;
	}
	memset(info, 0, sizeof(struct ins_entry_info));

	tbl_entry = NULL;
	//allocate hw ct entry
	sa->ct = (struct hw_ct *)kzalloc(sizeof(struct hw_ct), GFP_KERNEL);
	if (!sa->ct) {
		DPA_ERROR("%s::unable to alloc mem for hw_ct\n", __func__);
		goto err_ret;
	}
	memset(sa->ct, 0, sizeof(struct hw_ct));

	//fman used for ipsec on this SOC, hardcode it for LS1043/46 as there is only one FMAN
	info->fm_idx = IPSEC_FMAN_IDX;
	//get pcd handle based on determined fman
	info->fm_pcd = dpa_get_pcdhandle(info->fm_idx);
	if (!info->fm_pcd) {
		DPA_ERROR("%s::unable to get fm_pcd_handle for fmindex %d\n",
				__func__, info->fm_idx);
		goto err_ret;
	}


	flags = 0;
	tbl_type = get_tbl_type(sa);
	if (tbl_type ==  -1) {
		DPA_ERROR("%s::unable to get tbl type\n",
				__func__);
		goto err_ret;
	}

	//get portand table info
	if(sa->direction == CDX_DPA_IPSEC_INBOUND)
	{
		//inbound
		/* Add the Flow to the ESP table of wan port*/
		sa_dir_in = 1;
#ifdef CDX_DPA_DEBUG
		printk("%s::inbound sa\n", __func__);
#endif
		/* The port the local endpoint is on keys the classifier entry.
		 * The SA's device is not looked up here: it is the port the SA
		 * is bound to (sa->netdev), set by its creator. */
		if( dpa_get_iface_info_by_ipaddress(sa->family, &sa->id.daddr.a6[0], NULL,
					&itf_id , &info->port_id, (uint32_t)sa->handle) != SUCCESS)
		{
			DPA_ERROR("%s:: dpa_get_iface_info_by_ipaddress returned error\n",
					__func__);
			goto err_ret;
		}
		//get table descriptor based on type and port
		sa->ct->td = dpa_get_tdinfo(info->fm_idx, info->port_id,
				tbl_type);
		if (sa->ct->td == NULL) {
			DPA_ERROR("%s::unable to get td for portid %d, type %d\n",
					__func__, info->port_id, tbl_type);
			goto err_ret;
		}
		/*
		 * storing the interface id for the inbound sa.
		 * This is used for finding interface stats pointer for pppoe interface
		 * May also can be used for orginal interface stats also.
		 */
		info->sa_itf_id = itf_id;
		dpa_get_l2l3_info_by_itf_id( itf_id, &info->l2_info, &info->l3_info);
#ifdef CDX_DPA_DEBUG
		/*       printk("%s:: Got the table id for portid %d and key type %d as %p \n",
					__func__, info->port_id, key_info->type, sa->ct->td); */
#endif
	} else {
		/* Add the Flow to the ESP table of sec offline port*/
#ifdef CDX_DPA_DEBUG
		printk("%s::outbound sa\n", __func__);
#endif
		sa_dir_in = 0;
		if (dpa_ipsec_ofport_td(ipsec_instance, tbl_type, &sa->ct->td,
				&info->port_id)) {
			DPA_ERROR("%s::no IPsec offline port for the ESP table\n",
					__func__);
			goto err_ret;
		}

		if( dpa_get_iface_info_by_ipaddress(sa->family, &sa->id.saddr[0], NULL,
					NULL , NULL, (uint32_t)sa->handle) != SUCCESS)
		{
			DPA_ERROR("%s:: dpa_get_iface_info_by_ipaddress returned error\n",
					__func__);
			goto err_ret;
		}

		if (dpa_get_out_tx_info_by_itf_id(sa->pRtEntry,
					&info->l2_info, &info->l3_info,
					(uint32_t)sa->handle)) {
			DPA_ERROR("%s:: dpa_get_out_tx_info_by_itf_id returned error\n",
					__func__);
			goto err_ret;
		}
	}
	//create shared descriptoy
	/* In case of outbound SA , whenever there is no route,  
	 * we are removing the fastpath entry from the outbound ESP table
	 * when there is again a valid route, we are adding to the outbound ESP 
	 * table, to add to outbound ESP table 
	 * cdx_ipsec_add_classification_table_entry() is used,
	 * cdx_ipsec_add_classification_table_entry() is not only adding to ESP 
	 * fastpath table, also building shared descriptor
	 * when cdx_ipsec_add_classification_table_entry() it is called 2nd time
	 * onwards, we need not build shared descriptor,
	 * to know whether shared descriptor already built or not.
	 *  SA_SH_DESC_BUILT flag is introduced 
	 */ 
	if (!(sa->flags & SA_SH_DESC_BUILT))
	{
		if (cdx_ipsec_create_shareddescriptor(sa, bytes_to_copy)) {
			DPA_ERROR("%s::unable to create shared desc\n", __func__);
			goto err_ret;
		}
		sa->flags |= SA_SH_DESC_BUILT;
		sh_desc_just_built = true;
	}
	//get table descriptor based on type and port
	info->td = sa->ct->td;
	//allocate hash table entry
	tbl_entry = ExternalHashTableAllocEntry(info->td);
	if (!tbl_entry) {
		DPA_ERROR("%s::unable to alloc hash tbl memory\n",
				__func__);
		goto err_ret;
	}
#ifdef CDX_DPA_DEBUG
	/*	printk("%s: Sa direction = %d Table id = %d port id = %d\n ", __func__,sa_dir_in, info->td,
			info->port_id); */
#endif
	if (info->td == NULL) {
		DPA_ERROR("%s:: wrong table id passed \n",
				__func__);
		goto err_ret;
	}
	/* Fill key information from entry */
	/* For NATT use the 5 tuple key info */
	if (IS_NATT_SA(sa))
		key_size = fill_natt_key_info(sa, tbl_entry, info->port_id);
	else
		key_size = fill_ipsec_key_info(sa, tbl_entry, info->port_id);
	if (!key_size) {
		DPA_ERROR("%s::unable to compose key\n",
				__func__);
		goto err_ret;
	}
	/* An outbound SA's entry is on the offline port, where every SA's
	 * output and every decrypted frame is classified: it matches only
	 * what this SA encrypted, and never a decrypted packet built to look
	 * like it. */
	if (!sa_dir_in)
		info->sec_tag = cdx_ipsec_key_tag_of(sa);

	/*round off keysize to next 4 bytes boundary */
	ptr = (uint8_t *)&tbl_entry->hashentry.key[0];
	ptr += ALIGN(key_size, TBLENTRY_OPC_ALIGN);
	/*set start of opcode list */
	info->opcptr = ptr;
	/*ptr now after opcode section */
	ptr += MAX_OPCODES;
	flags = 0;
#ifdef ENABLE_FLOW_TIME_STAMPS
	SET_TIMESTAMP_ENABLE(flags);
	tbl_entry->hashentry.timestamp_counter =
		cpu_to_be32(dpa_get_timestamp_addr(EXTERNAL_TIMESTAMP_TIMERID));
	tbl_entry->hashentry.timestamp = cpu_to_be32(JIFFIES32);
	sa->ct->timestamp = JIFFIES32;
#endif
#ifdef ENABLE_FLOW_STATISTICS
	SET_STATS_ENABLE(flags);
#endif
	/*set offset to first opcode */
	SET_OPC_OFFSET(flags, (uint32_t)(info->opcptr - (uint8_t *)tbl_entry));
	/*set param offset*/
	SET_PARAM_OFFSET(flags, (uint32_t)(ptr - (uint8_t *)tbl_entry));
	/*param_ptr now points after timestamp location */
	tbl_entry->hashentry.flags = cpu_to_be16(flags);
	/*param pointer and opcode pointer now valid */
	info->paramptr = ptr;
	info->param_size = (MAX_EN_EHASH_ENTRY_SIZE -
			GET_PARAM_OFFSET(flags));
#ifdef CDX_DPA_DEBUG
	/*	printk("%s:: displaying SA table entry key\n",__func__);
		display_buf(&key_info->key.key_array[0],  key_info->dpa_key.size); */
#endif
	if(sa_dir_in) {
		//fix mtu and fqid for packets to sec
		info->l2_info.fqid = sa->pSec_sa_context->to_sec_fqid;
		info->l2_info.mtu = 0xffff;
		info->to_sec_fqid = sa->pSec_sa_context->to_sec_fqid;
	}
	if (fill_ipsec_actions(sa, info, sa_dir_in)) {
		DPA_ERROR("%s::unable to fill actions\n", __func__);
		goto err_ret;
	}
	if( IS_NATT_SA(sa) && sa_dir_in)
		tbl_entry->ipsec_preempt_params = info->preempt_params;
	else
		tbl_entry->enqueue_params = info->enqueue_params;

	sa->ct->handle = tbl_entry;
#ifdef CDX_DPA_DEBUG
	display_ehash_tbl_entry(&tbl_entry->hashentry, key_size);
#endif
	/*insert entry into hash table */
	retval = ExternalHashTableAddKey(info->td, key_size, tbl_entry);
	if (retval == -1) {
		DPA_ERROR("%s::unable to add entry in hash table\n", __func__);
		goto err_ret;
	}
	sa->ct->index = (uint16_t)retval;
	kfree(info);
	return SUCCESS;
err_ret:
	/* If we built the shared descriptor in this call but the table
	 * insert later failed, clear the flag so a retry rebuilds the
	 * descriptor from a consistent state. pSec_sa_context lifetime
	 * is owned elsewhere, so don't free it here. */
	if (sh_desc_just_built)
		sa->flags &= ~SA_SH_DESC_BUILT;
	if (sa->ct)
	{
		kfree(sa->ct);
		sa->ct = NULL;
	}
	if (tbl_entry)
		ExternalHashTableEntryFree(tbl_entry);
	/*free hw flow entry if allocated */
	kfree(info);
	return FAILURE;
}

#endif /* DPA_IPSEC_OFFLOAD */
