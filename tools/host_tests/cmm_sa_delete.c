#include <arpa/inet.h>
#include <assert.h>
#include <linux/rtnetlink.h>
#include <net/ethernet.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "list.h"
#include "fpp.h"
#include "fpp_private.h"

typedef void FCI_CLIENT;
struct cli_def;
#define NEIGHBOR_HASH_TABLE_SIZE 4
#include "route_cache.h"
#include "cmm_sa_types.inc"

#define cmm_print(...) ((void)0)
#define FCI_CB_CONTINUE 0
#define FCI_CB_STOP 1
struct list_head sa_table[SA_HASH_TABLE_SIZE];
pthread_mutex_t sa_lock, ctMutex, rtMutex, neighMutex;
static struct { pthread_mutex_t lock; } itf_table;
static char hardware_client, key_client;
static struct { struct { FCI_CLIENT *fci_handle, *fci_key_handle; } ct; } globalConf = {
    .ct = { &hardware_client, &key_client },
};
static pthread_mutex_t *locks[] = { &itf_table.lock, &ctMutex, &rtMutex, &neighMutex, &sa_lock };
static unsigned depth, flow_calls, sends, route_deletes, route_rejects, cases;
static unsigned hardware_pins, hardware_sa, flow_error, send_error, offload_error;
static unsigned valid_notifications, rekeys;
static struct fpp_rt *binding;
static struct RtEntry cached_route;

static void __pthread_mutex_lock(pthread_mutex_t *lock)
{
    assert(depth < 5 && lock == locks[depth]); depth++;
}
static void __pthread_mutex_unlock(pthread_mutex_t *lock)
{
    assert(depth && lock == locks[depth - 1]); depth--;
}
static struct SATable *__cmmSAFind(unsigned short handle)
{
    assert(depth == 5);
    struct list_head *entry = list_first(&sa_table[0]);
    if (entry == &sa_table[0]) return NULL;
    struct SATable *sa = container_of(entry, struct SATable, list_by_h);
    return sa->SAInfo.sagd == handle ? sa : NULL;
}
static int cmmUpdateFlows(struct SATable *sa)
{
    assert(depth == 5 && (sa->flags & SA_DELETE));
    /* A live flow must be detached while its hardware SA still exists. */
    assert(hardware_sa && sends == 0);
    flow_calls++;
    return flow_error ? -1 : 0;
}
static int cmmSASetOffloadState(FCI_CLIENT *client, unsigned short sagd, bool enabled)
{
    assert(depth == 5 && client == &key_client && sagd == 107);
    return offload_error || !enabled ? -1 : 0;
}
static void cmmUpdateFlowsWithNewSAInfo(struct SATable *sa, unsigned short parent)
{
    assert(depth == 5 && sends == 0 && sa->SAInfo.sagd == 107 && parent == 106);
    rekeys++;
}
static void cmmUpdateCtEntriesInFlowNoSAList(unsigned short sagd)
{
    assert(depth == 0 && sends == 1 && !send_error && sagd == 107);
    valid_notifications++;
}
static int fci_write(FCI_CLIENT *client, unsigned short code, unsigned short len, void *payload)
{
    assert(client == &hardware_client);
    assert(code == FPP_CMD_NETKEY_SA_DELETE || code == FPP_CMD_NETKEY_SA_SET_STATE);
    assert(len == (code == FPP_CMD_NETKEY_SA_DELETE ? sizeof(CommandIPSecDeleteSA) : sizeof(CommandIPSecSetState)));
    assert(*(unsigned short *)payload == 107);
    sends++;
    if (send_error) return -1;
    if (code == FPP_CMD_NETKEY_SA_SET_STATE && ((PCommandIPSecSetState)payload)->state == SA_STATE_VALID)
        return 0;
    if (hardware_sa) {
        if (binding) { assert(hardware_pins); hardware_pins--; }
        hardware_sa = 0;
    }
    return 0;
}
static int cmmFeRouteUpdate(FCI_CLIENT *client, int action, struct fpp_rt *route)
{
    assert(client == &hardware_client && depth == 5 && action == REMOVE && route == binding);
    route_deletes++;
    if (hardware_pins) { route_rejects++; return -1; }
    return 0;
}
void __cmmFPPRoutePut(struct fpp_rt *route)
{
    assert(route == binding && route->count > 0);
    if (--route->count == 0) {
        assert(!hardware_pins);
        free(route); binding = NULL;
    }
}
void __cmmFPPRouteDeregister(FCI_CLIENT *, struct fpp_rt *, const char *);
static void __cmmRouteDeregister(FCI_CLIENT *client, struct ct_route *route, const char *dir)
{
    assert(client == &hardware_client && depth == 5);
    __cmmFPPRouteDeregister(client, route->fpp_route, dir);
    if (route->route) { assert(cached_route.count == 1); cached_route.count--; }
}
static int cmmSACreate(FCI_CLIENT *c, unsigned short f, unsigned short n, unsigned short *p) { abort(); }
static int cmmSASetTunnel(FCI_CLIENT *c, unsigned short f, unsigned short n, unsigned short *p) { abort(); }

#include "cmm_sa_delete.inc"

static struct SATable *setup(int route, int shared)
{
    assert(!depth && !binding);
    for (int i = 0; i < SA_HASH_TABLE_SIZE; i++) list_head_init(&sa_table[i]);
    flow_calls = sends = route_deletes = route_rejects = 0;
    flow_error = send_error = offload_error = valid_notifications = rekeys = 0;
    hardware_sa = 1; hardware_pins = 0;
    cached_route.count = 0;
    struct SATable *sa = calloc(1, sizeof(*sa)); assert(sa);
    sa->SAInfo.sagd = 107; sa->SAInfo.proto_family = AF_INET;
    list_add(&sa_table[0], &sa->list_by_h);
    if (route) {
        binding = calloc(1, sizeof(*binding)); assert(binding);
        binding->count = 1 + shared; binding->id = 107;
        sa->tnl_rt.fpp_route = binding; sa->tnl_rt.route = &cached_route;
        cached_route.count = 1; hardware_pins = 1 + shared;
    }
    return sa;
}
static void reset(void)
{
    struct list_head *entry = list_first(&sa_table[0]);
    if (entry != &sa_table[0]) {
        struct SATable *sa = container_of(entry, struct SATable, list_by_h);
        list_del(entry); free(sa);
    }
    free(binding); binding = NULL;
    assert(!depth); cases++;
}
static int dispatch(int dying, int length_delta)
{
    CommandIPSecDeleteSA del = { .sagd = 107 };
    CommandIPSecSetState state = { .sagd = 107, .state = SA_STATE_DYING };
    return dying ? cmmKeyCatch(FPP_CMD_NETKEY_SA_SET_STATE, sizeof(state) + length_delta, (unsigned short *)&state)
                 : cmmKeyCatch(FPP_CMD_NETKEY_SA_DELETE, sizeof(del) + length_delta, (unsigned short *)&del);
}

int main(void)
{
    for (int dying = 0; dying < 2; dying++)
        for (int route = 0; route < 2; route++)
            for (int shared = 0; shared <= route; shared++)
                for (int flow_fail = 0; flow_fail < 2; flow_fail++)
                    for (int send_fail = 0; send_fail < 2; send_fail++) {
                        setup(route, shared); flow_error = flow_fail; send_error = send_fail;
                        assert(dispatch(dying, 0) == (flow_fail || send_fail ? FCI_CB_STOP : FCI_CB_CONTINUE));
                        assert(!depth && flow_calls == 1 && sends == 1);
                        assert(list_first(&sa_table[0]) == &sa_table[0] && !cached_route.count);
                        assert(hardware_sa == (unsigned)send_fail);
                        assert(route_rejects == (unsigned)(route && !shared && send_fail));
                        if (shared) {
                            assert(binding && binding->count == 1 && route_deletes == 0);
                            if (!send_fail) {
                                hardware_pins--; depth = 5;
                                __cmmFPPRouteDeregister(&hardware_client, binding, "peer"); depth = 0;
                                assert(!binding && route_deletes == 1);
                            }
                        } else if (!send_fail) assert(!binding);
                        /* Transport failures retain the existing orphan tracking,
                         * but must not strand a local SA that prevents handle reuse. */
                        reset();
                    }
    for (int dying = 0; dying < 2; dying++) {
        struct SATable *sa = setup(0, 0); list_del(&sa->list_by_h); free(sa);
        assert(dispatch(dying, 0) == FCI_CB_STOP);
        assert(sends == (unsigned)!dying && !flow_calls); reset();
        setup(1, 0);
        assert(dispatch(dying, -1) == FCI_CB_STOP);
        assert(!sends && !flow_calls && binding->count == 1); reset();
    }
    for (int parent = 0; parent < 2; parent++)
        for (int fail = 0; fail < 2; fail++) {
            setup(1, 0); send_error = fail;
            CommandIPSecSetState state = { .sagd = 107, .state = SA_STATE_VALID, .parent_sa_sagd = parent ? 106 : 0 };
            assert(cmmKeyCatch(FPP_CMD_NETKEY_SA_SET_STATE, sizeof(state), (unsigned short *)&state)
                   == (fail ? FCI_CB_STOP : FCI_CB_CONTINUE));
            assert(sends == 1 && !flow_calls && rekeys == (unsigned)parent);
            assert(valid_notifications == (unsigned)!fail && binding->count == 1 && hardware_pins == 1);
            reset();
        }
    setup(1, 0); offload_error = 1;
    assert(dispatch(1, 0) == FCI_CB_STOP && !sends && !flow_calls); reset();
#ifdef LS1043
    struct SATable *sa = setup(1, 0); sa->SAInfo.proto_family = 0;
    assert(dispatch(1, 0) == FCI_CB_STOP && !sends && !flow_calls); reset();
#endif
    printf("%u SA teardown and state scenarios passed\n", cases);
    return 0;
}
