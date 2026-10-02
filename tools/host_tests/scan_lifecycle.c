/* Execute production scan code with deterministic interruptions at every
 * sleeping boundary. Kernel/firmware substitutes assert ownership contracts. */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

typedef uint8_t t_u8;
typedef uint16_t t_u16;
typedef uint32_t t_u32;
typedef uint64_t t_u64;
typedef uint8_t u8;
#define STA_CFG80211
#define UAP_CFG80211
#define DEBUG_LEVEL1
#define MFW_D 1
#define KERNEL_VERSION(a,b,c) (((a)<<16)|((b)<<8)|(c))
#define CFG80211_VERSION_CODE KERNEL_VERSION(6,12,0)
#define MTRUE 1
#define MFALSE 0
#define ENTER() ((void)0)
#define LEAVE() ((void)0)
#define PRINTM(...) ((void)0)
#define MLAN_BSS_TYPE_STA 0
#define MLAN_BSS_TYPE_UAP 1
#define MLAN_BSS_ROLE_UAP 1
#define MLAN_STATUS_SUCCESS 0
#define MLAN_STATUS_FAILURE 1
#define MLAN_STATUS_PENDING 2
#define MOAL_NO_WAIT 0
#define MOAL_IOCTL_WAIT 1
#define MLAN_IOCTL_SCAN 1
#define MLAN_ACT_SET 1
#define MLAN_OID_SCAN_CANCEL 1
#define WIFI_STATUS_SCAN_TIMEOUT 1
#define WOAL_EVENT_CFG80211_INFORM_BSS 1
#define GFP_KERNEL 0
#define GFP_ATOMIC 1
#define ETH_ALEN 6
#define EVENT_BG_SCAN_REPORT 1
#define HOST_MLME_AUTH_PENDING 1
#define WLAN_USER_SCAN_CHAN_MAX 4
#define WLAN_MAX_6G_SCAN_PARAMS_LIST 4
#define EXT_SCAN_ENHANCE 3
#define IEEE80211_CHAN_PASSIVE_SCAN 1
#define IEEE80211_CHAN_RADAR 2
#define MLAN_SCAN_TYPE_PASSIVE 1
#define MLAN_SCAN_TYPE_PASSIVE_TO_ACTIVE 2
#define MLAN_SCAN_TYPE_ACTIVE 3
#define MIN_SPECIFIC_SCAN_CHAN_TIME 40
#define ACTIVE_SCAN_CHAN_TIME 40
#define PASSIVE_SCAN_CHAN_TIME 110
#define SPECIFIC_SCAN_CHAN_TIME 40
#define MAX_SCAN_TIMEOUT 25000
#define GAP_FLAG_OPTIONAL 0x8000
#define MGMT_MASK_PROBE_REQ 1
#define MLAN_CUSTOM_IE_AUTO_IDX_MASK 0xffff
#define NL80211_SCAN_FLAG_RANDOM_ADDR 1
#define SHORT_SSID_VALID 1
#define UNSOLICITED_PROBE 2
#define MIN(a,b) ((a)<(b)?(a):(b))
#define GET_BSS_ROLE(p) ((p)->bss_type)
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define msecs_to_jiffies(n) (n)

typedef struct moal_handle moal_handle;
typedef struct moal_private moal_private;
struct work_struct { int unused; };
struct delayed_work { struct work_struct work; bool pending, running; };
#define to_delayed_work(w) container_of(w,struct delayed_work,work)
struct net_device { moal_private *priv; };
struct wireless_dev { struct net_device *netdev; };
struct wiphy { int unused; };
struct ieee80211_channel { int hw_value, band, flags; };
struct scan_6ghz { int channel_idx, short_ssid, short_ssid_valid, unsolicited_probe; u8 bssid[6]; };
struct cfg80211_scan_request {
    struct wireless_dev *wdev;
    int done, aborted;
    bool release;
    int n_ssids, n_channels, scan_6ghz, n_6ghz_params, duration, flags;
    struct { u8 ssid[32]; int ssid_len; } ssids[4];
    struct ieee80211_channel *channels[4];
    struct scan_6ghz scan_6ghz_params[4];
    u8 bssid[6], mac_addr[6], mac_addr_mask[6];
    const u8 *ie;
    int ie_len;
};
typedef struct {
    int scan_chan_gap, scan_cfg_only, ext_scan_type, proberesp_only;
    int num_6g_scan_params, keep_previous_scan;
    u8 specific_bssid[6], random_mac[6];
    struct { u8 ssid[32]; int max_len; } ssid_list[4];
    struct { int chan_number, radio_type, scan_type, scan_time, rnr_flag; } chan_list[4];
    struct { int channel, short_ssid, flags; u8 bssid[6]; } scan_param_list[4];
} wlan_user_scan_cfg;
typedef struct { int scan_block; } mlan_bss_info;
typedef struct { int scan_chan_gap, ext_scan; } mlan_scan_cfg;
typedef struct { int time_sec, time_usec; } wifi_timeval;
typedef struct { int sub_command; } mlan_ds_scan;
typedef struct { int req_id, action; void *pbuf; mlan_ds_scan scan; } mlan_ioctl_req;
struct list_head { int unused; };
struct woal_event { struct list_head link; void *priv; int type; t_u64 scan_generation; };
struct moal_handle {
    int scan_req_lock, evt_lock, async_sem;
    t_u8 scan_pending_on_block, scan_starting, scan_stopping, fake_scan_complete;
    t_u32 scan_canceling;
    t_u64 scan_generation, scan_timeout_generation;
    moal_private *scan_priv, *cfg_scan_priv;
    struct cfg80211_scan_request *scan_request;
    struct delayed_work scan_timeout_work, emergency_reset_work;
    struct work_struct evt_work;
    struct list_head evt_queue;
    void *workqueue, *evt_workqueue, *tx_workqueue;
    t_u8 driver_status, surprise_removed, fw_dump, first_scan_done, user_scan_cfg;
    moal_handle *pref_mac;
    void *pmlan_adapter;
    t_u32 scan_timeout;
    int scan_chan_gap;
    wifi_timeval scan_time_start;
    struct { int keep_previous_scan, bandctrl; } params;
};
struct moal_private {
    moal_handle *phandle;
    struct net_device netdev;
    struct wireless_dev wdev;
    int bss_type, fake_scan_complete, last_event, auth_flag;
    int scan_setband_mask, probereq_index, band_ctrl;
    u8 random_mac[6];
};
static int locks, completions, reports, hangs, wifi_status, scenarios, sync_calls;
static int drvdbg;
static int alloc_fail, ie_fail, submit_fail, scan_block;
static moal_private *reported_priv;
static moal_handle *current;
static struct woal_event *queued_event;
static void (*inform_hook)(moal_private *);
static void (*ioctl_hook)(moal_private *);
static void (*sync_hook)(void);
static void (*settle_hook)(void);
static void (*setup_hook)(moal_private *);
#define spin_lock_irqsave(l,f) do { (f)=0; assert(!*(l)); *(l)=1; locks++; } while(0)
#define spin_unlock_irqrestore(l,f) do { (void)(f); assert(*(l)); *(l)=0; locks--; } while(0)
#define spin_lock(l) do { assert(!*(l)); *(l)=1; locks++; } while(0)
#define spin_unlock(l) do { assert(*(l)); *(l)=0; locks--; } while(0)
#define MOAL_REL_SEMAPHORE(s) do { assert(*(s)==0); ++*(s); } while(0)
static void *kmalloc(size_t n, int flags) { if (alloc_fail) { alloc_fail=0; return NULL; } return malloc(n); }
static void *kzalloc(size_t n, int flags) { void *p=kmalloc(n,flags); if(p) memset(p,0,n); return p; }
#define kfree free
static bool cancel_delayed_work(struct delayed_work *w) { bool p=w->pending; w->pending=false; return p; }
static void cancel_delayed_work_sync(struct delayed_work *w)
{
    assert(!locks); sync_calls++;
    if(sync_hook) { void (*hook)(void)=sync_hook; sync_hook=NULL; hook(); }
    w->pending=false; w->running=false;
}
static bool queue_delayed_work(void *q, struct delayed_work *w, unsigned timeout)
{
    assert(q && timeout && !w->pending && !w->running);
    assert(current->scan_req_lock);
    w->pending=true;
    return true;
}
static void woal_cfg80211_scan_done(struct cfg80211_scan_request *r, bool aborted)
{
    assert(current->scan_req_lock && !r->done);
    r->done++; r->aborted=aborted; completions++;
    if(r->release) free(r);
}
static void woal_inform_bss_from_scan_result(moal_private *p, void *unused, int wait)
{
    assert(!locks); reports++; reported_priv=p;
    if(inform_hook) { void (*hook)(moal_private *)=inform_hook; inform_hook=NULL; hook(p); }
}
static void woal_set_scan_time(moal_private *p, int a, int b, int c) { assert(!locks); }
static void woal_mlan_debug_info(moal_private *p) { assert(!locks); }
static void woal_moal_debug_info(moal_private *p, void *x, int y) { assert(!locks); }
static void mlan_set_driver_status(void *p, int status) { assert(status); }
static void woal_process_hang(moal_handle *h) { hangs++; }
static void flush_workqueue(void *q) { assert(!locks); }
static void flush_work(struct work_struct *w);
static void destroy_workqueue(void *q) { assert(!current->scan_timeout_work.pending && !current->scan_timeout_work.running); }
static void woal_flush_evt_queue(moal_handle *h) { free(queued_event); queued_event=NULL; }
#define INIT_LIST_HEAD(l) ((void)0)
static void list_add_tail(struct list_head *l, struct list_head *head) { assert(!queued_event); queued_event=container_of(l,struct woal_event,link); }
static void queue_work(void *q, struct work_struct *w) { assert(q && current->scan_req_lock); }
static mlan_ioctl_req *woal_alloc_mlan_ioctl_req(size_t n)
{
    mlan_ioctl_req *r=kzalloc(sizeof(*r),0); if(r) r->pbuf=&r->scan; return r;
}
static int woal_request_ioctl(moal_private *p, mlan_ioctl_req *r, int wait)
{
    assert(!locks);
    if(ioctl_hook) { void (*hook)(moal_private *)=ioctl_hook; ioctl_hook=NULL; hook(p); }
    return MLAN_STATUS_SUCCESS;
}
static void woal_sched_timeout(int ms)
{
    assert(!locks);
    if(settle_hook) { void (*hook)(void)=settle_hook; settle_hook=NULL; hook(); }
}
#define woal_get_netdev_priv(d) ((d)->priv)
static void woal_cancel_remain_on_channel(moal_private *p) { assert(!locks); }
static int woal_get_bss_info(moal_private *p, int wait, mlan_bss_info *b)
{
    b->scan_block=scan_block;
    if(setup_hook) { void (*hook)(moal_private *)=setup_hook; setup_hook=NULL; hook(p); }
    return 0;
}
#define is_zero_timeval(t) (!(t).time_sec)
static void woal_get_monotonic_time(wifi_timeval *t) { t->time_sec=1; }
static int is_broadcast_ether_addr(const u8 *p) { return !memcmp(p,"\xff\xff\xff\xff\xff\xff",6); }
static void moal_memcpy_ext(moal_handle *h, void *to, const void *from, size_t n, size_t cap) { assert(n<=cap); memcpy(to,from,n); }
static int woal_get_scan_config(moal_private *p, mlan_scan_cfg *c) { return 0; }
static int woal_is_any_interface_active(moal_handle *h) { return 0; }
static int is_scan_band_allowed(moal_private *p, struct ieee80211_channel *c) { return 1; }
static int woal_ieee_band_to_radio_type(int band) { return band; }
static int woal_is_uap_scan_result_expired(moal_private *p) { return 0; }
static int woal_find_wps_ie_in_probereq(const u8 *p, int n) { return 0; }
static int woal_cfg80211_mgmt_frame_ie(moal_private *p, ... ) { assert(!locks); return ie_fail; }
static void get_random_bytes(void *p, size_t n) { memset(p,0x35,n); }
static int wlan_check_scan_table_ageout(moal_private *p) { return 0; }
void woal_scan_pending_start(moal_private *priv);
void woal_scan_pending_complete(moal_handle *h);
static int woal_do_scan(moal_private *p, wlan_user_scan_cfg *c)
{
    assert(p->phandle->scan_request && p->phandle->cfg_scan_priv==p);
    if(submit_fail) return MLAN_STATUS_FAILURE;
    assert(p->phandle->async_sem==1);
    p->phandle->async_sem--;
    woal_scan_pending_start(p);
    return MLAN_STATUS_SUCCESS;
}
#include "scan_production.inc"

static moal_handle h;
static moal_private sta, ap;
static struct cfg80211_scan_request req, next;
static void init_request(struct cfg80211_scan_request *r, moal_private *p)
{
    memset(r,0,sizeof(*r)); r->wdev=&p->wdev;
}
static void reset(void)
{
    assert(!locks && !queued_event);
    memset(&h,0,sizeof(h)); memset(&sta,0,sizeof(sta)); memset(&ap,0,sizeof(ap));
    sta.phandle=ap.phandle=&h; sta.bss_type=MLAN_BSS_TYPE_STA; ap.bss_type=MLAN_BSS_TYPE_UAP;
    sta.netdev.priv=&sta; ap.netdev.priv=&ap;
    sta.wdev.netdev=&sta.netdev; ap.wdev.netdev=&ap.netdev;
    sta.probereq_index=ap.probereq_index=MLAN_CUSTOM_IE_AUTO_IDX_MASK;
    h.evt_workqueue=&h; h.scan_timeout=25000; h.async_sem=1; current=&h;
    init_request(&req,&sta); init_request(&next,&ap);
    completions=reports=hangs=sync_calls=wifi_status=drvdbg=0;
    alloc_fail=ie_fail=submit_fail=scan_block=0;
    inform_hook=ioctl_hook=NULL; sync_hook=settle_hook=NULL; setup_hook=NULL;
    reported_priv=NULL; scenarios++;
}
static void timeout(void)
{
    h.scan_timeout_work.pending=false; h.scan_timeout_work.running=true;
    woal_scan_timeout_handler(&h.scan_timeout_work.work);
    h.scan_timeout_work.running=false;
}
static void deliver(void)
{
    struct woal_event *e=queued_event;
    assert(e); queued_event=NULL;
    woal_send_bss_scan_result(e->priv,e->scan_generation); free(e);
}
static void flush_work(struct work_struct *w)
{
    assert(!locks);
    if(queued_event) deliver();
}
static void firmware_report(moal_private *p)
{
    woal_send_bss_scan_result_event(p);
    woal_scan_pending_complete(&h);
}
static void cancel_during_report(moal_private *p) { woal_cancel_scan(p,MOAL_IOCTL_WAIT); }
static void stop_during_report(moal_private *p) { woal_cfg80211_scan_stop(&h); }
static void stop_during_begin(void) { woal_cfg80211_scan_stop(&h); }
static void stop_during_setup(moal_private *p) { woal_cfg80211_scan_stop(&h); }
static void reuse_during_report(moal_private *p)
{
    woal_cancel_scan(p,MOAL_IOCTL_WAIT);
    assert(req.done==1); init_request(&req,p); /* allocator reuses the same address */
    assert(woal_cfg80211_scan(NULL,&req)==0);
}
static void complete_during_cancel(moal_private *p)
{
    firmware_report(p); deliver();
    assert(h.async_sem==1 && req.done==1);
    assert(woal_cfg80211_scan(NULL,&next)==-EBUSY);
}
static void check_cancel_settling(void)
{
    assert(h.scan_canceling && woal_cfg80211_scan(NULL,&next)==-EBUSY);
}
static void old_timeout_finishes(void)
{
    assert(h.scan_starting && !locks);
    woal_cfg80211_scan_complete(&h,h.scan_generation,MFALSE);
}
static void admission_and_failures(void)
{
    for(int mode=0;mode<3;mode++) {
        reset(); sta.fake_scan_complete=(mode==1); scan_block=(mode==2);
        assert(woal_cfg80211_scan(NULL,&req)==0);
        t_u64 generation=h.scan_generation;
        assert(h.cfg_scan_priv==&sta && h.scan_request==&req);
        assert(woal_cfg80211_scan(NULL,&next)==-EBUSY);
        assert(woal_cfg80211_scan(NULL,&req)==-EBUSY);
        assert(h.scan_generation==generation && h.scan_timeout_work.pending);
        woal_cancel_scan(&sta,MOAL_IOCTL_WAIT);
        assert(req.done==1 && req.aborted && !next.done);
        assert(h.async_sem==1 && !h.scan_request && !h.cfg_scan_priv);
        assert(!h.fake_scan_complete && !h.scan_timeout_work.pending);
    }
    for(int failure=0;failure<5;failure++) {
        reset();
        if(failure==0) alloc_fail=1;
        if(failure==1) { req.ie=(const u8 *)"ie"; req.ie_len=2; ie_fail=1; }
        if(failure==2) { sta.probereq_index=1; ie_fail=1; }
        if(failure==3) setup_hook=stop_during_setup;
        if(failure==4) sync_hook=stop_during_begin;
        assert(woal_cfg80211_scan(NULL,&req)<0);
        assert(!req.done && !h.scan_request && !h.scan_timeout_work.pending);
    }
    reset(); submit_fail=1;
    struct cfg80211_scan_request *heap=calloc(1,sizeof(*heap));
    init_request(heap,&sta); heap->release=true;
    assert(woal_cfg80211_scan(NULL,heap)==0);
    assert(completions==1 && !h.scan_request && !h.scan_timeout_work.pending);
    reset(); h.driver_status=1; assert(woal_cfg80211_scan(NULL,&req)<0);
    h.driver_status=0; h.surprise_removed=1; assert(woal_cfg80211_scan(NULL,&req)<0);
    assert(!req.done && !h.scan_request);
}
static void completion_interleavings(void)
{
    for(int owner=0;owner<2;owner++) for(int mode=0;mode<3;mode++) {
        reset(); moal_private *p=owner?&ap:&sta; init_request(&req,p);
        p->fake_scan_complete=(mode==1); scan_block=(mode==2);
        assert(woal_cfg80211_scan(NULL,&req)==0);
        if(mode) { assert(!h.scan_priv); timeout(); assert(reported_priv==p); }
        else { firmware_report(p); assert(!h.scan_priv); deliver(); }
        assert(req.done==1 && !req.aborted && !h.scan_request);
        woal_cancel_scan(p,MOAL_IOCTL_WAIT); woal_cfg80211_scan_stop(&h); timeout();
        assert(req.done==1 && h.async_sem==1);
    }
    for(int stop=0;stop<2;stop++) {
        reset(); assert(woal_cfg80211_scan(NULL,&req)==0);
        firmware_report(&sta);
        inform_hook=stop?stop_during_report:cancel_during_report;
        deliver();
        assert(req.done==1 && req.aborted && !h.scan_request);
    }
    reset(); assert(woal_cfg80211_scan(NULL,&req)==0);
    t_u64 old=h.scan_generation;
    firmware_report(&sta); inform_hook=reuse_during_report; deliver();
    assert(h.scan_request==&req && h.scan_generation!=old && !req.done);
    assert(h.scan_timeout_work.pending);
    woal_send_bss_scan_result(&sta,old); /* stale event already queued */
    assert(!req.done);
    firmware_report(&sta); deliver(); assert(req.done==1 && completions==2);
    reset(); assert(woal_cfg80211_scan(NULL,&req)==0);
    firmware_report(&sta); old=h.scan_generation;
    woal_cancel_scan(&sta,MOAL_IOCTL_WAIT);
    init_request(&req,&sta); assert(woal_cfg80211_scan(NULL,&req)==0);
    deliver(); assert(!req.done && h.scan_generation!=old);
    woal_cancel_scan(&sta,MOAL_IOCTL_WAIT);
    reset(); assert(woal_cfg80211_scan(NULL,&req)==0);
    ioctl_hook=complete_during_cancel; settle_hook=check_cancel_settling;
    woal_cancel_scan(&sta,MOAL_IOCTL_WAIT);
    assert(req.done==1 && h.async_sem==1 && !h.scan_canceling);
    reset(); assert(woal_cfg80211_scan(NULL,&req)==0); alloc_fail=1;
    assert(woal_cancel_scan(&sta,MOAL_IOCTL_WAIT)==MLAN_STATUS_FAILURE);
    assert(req.done==1 && !h.scan_request && !h.scan_timeout_work.pending);
    woal_scan_pending_complete(&h); assert(h.async_sem==1);
}
static void timeout_and_teardown(void)
{
    for(int owner=0;owner<2;owner++) for(int dump=0;dump<3;dump++) {
        reset(); moal_private *p=owner?&ap:&sta; init_request(&req,p);
        h.fw_dump=(dump==1); drvdbg=(dump==2)?MFW_D:0;
        assert(woal_cfg80211_scan(NULL,&req)==0); timeout();
        assert(req.done==1 && req.aborted==!owner && h.driver_status);
        assert(hangs==!dump && wifi_status==WIFI_STATUS_SCAN_TIMEOUT);
        woal_cfg80211_scan_stop(&h); assert(req.done==1);
        woal_scan_pending_complete(&h);
    }
    for(int owner=0;owner<2;owner++) for(int fake=0;fake<2;fake++) {
        reset(); moal_private *p=owner?&ap:&sta; init_request(&req,p); p->fake_scan_complete=fake;
        assert(woal_cfg80211_scan(NULL,&req)==0);
        woal_terminate_workqueue(&h);
        assert(req.done==1 && req.aborted==!owner && !h.evt_workqueue);
        assert(h.scan_stopping && !h.scan_timeout_work.pending);
        assert(woal_cfg80211_scan(NULL,&next)==-EBUSY);
        woal_scan_pending_complete(&h);
    }
    reset(); sta.fake_scan_complete=1; assert(woal_cfg80211_scan(NULL,&req)==0);
    inform_hook=cancel_during_report; timeout();
    assert(req.done==1 && req.aborted && h.async_sem==1);
    reset(); /* teardown must drain work even without a request */
    h.scan_timeout_work.pending=true; h.scan_timeout_work.running=true;
    woal_terminate_workqueue(&h); assert(sync_calls>=1 && !completions);
    reset(); assert(woal_cfg80211_scan(NULL,&req)==0);
    firmware_report(&sta); woal_cfg80211_scan_stop(&h);
    assert(!queued_event && req.done==1 && reports==0);
    reset(); h.evt_workqueue=NULL; woal_terminate_workqueue(&h); assert(sync_calls>=1);
    reset(); woal_cfg80211_scan_stop(&h); woal_cfg80211_scan_restart(&h);
    assert(woal_cfg80211_scan(NULL,&req)==0); woal_cancel_scan(&sta,MOAL_IOCTL_WAIT);
    /* A previously completed callback can still be running. begin must drain
     * it before assigning the timer a new generation or queueing it again. */
    h.scan_timeout_work.running=true; sync_hook=old_timeout_finishes;
    assert(woal_cfg80211_scan(NULL,&next)==0);
    assert(!next.done && h.scan_request==&next && !h.scan_timeout_work.running);
    woal_cancel_scan(&ap,MOAL_IOCTL_WAIT);
    reset(); h.scan_generation=UINT64_MAX;
    assert(woal_cfg80211_scan(NULL,&req)==0 && h.scan_generation==1);
    woal_cancel_scan(&sta,MOAL_IOCTL_WAIT);
}
static void completion_orders(void)
{
    /* Event, cancellation, timeout and removal can each win. Exercise every
     * ordering for both interfaces and both cached/firmware scan paths. */
    for(int owner=0;owner<2;owner++) for(int fake=0;fake<2;fake++)
    for(int a=0;a<4;a++) for(int b=0;b<4;b++)
    for(int c=0;c<4;c++) for(int d=0;d<4;d++) {
        if(a==b || a==c || a==d || b==c || b==d || c==d) continue;
        reset(); moal_private *p=owner?&ap:&sta; init_request(&req,p);
        p->fake_scan_complete=fake;
        assert(woal_cfg80211_scan(NULL,&req)==0);
        t_u64 generation=h.scan_generation;
        int order[]={a,b,c,d};
        for(int i=0;i<4;i++) {
            switch(order[i]) {
            case 0:
                woal_scan_pending_complete(&h);
                woal_send_bss_scan_result(p,generation);
                break;
            case 1: woal_cancel_scan(p,MOAL_IOCTL_WAIT); break;
            case 2: timeout(); break;
            case 3: woal_cfg80211_scan_stop(&h); break;
            }
        }
        assert(completions==1 && req.done==1 && h.async_sem==1);
        assert(!h.scan_request && !h.cfg_scan_priv && !h.scan_timeout_work.pending);
    }
}
int main(void)
{
    admission_and_failures(); completion_interleavings(); timeout_and_teardown();
    completion_orders();
    assert(!locks && !queued_event);
    printf("%d scan lifecycle scenarios passed\n",scenarios);
    return 0;
}
