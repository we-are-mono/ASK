/* Execute the actual SDK creation entry points with allocation probes. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#define __CORE_EXT_H
#define __ERR_MODULE__ MODULE_FM_PCD
#include "fm_pcd.h"
#include "fm_manip.h"
#include "ehash_layout.h"
static unsigned allocations, control_calls, reported;
#undef REPORT_ERROR
#define REPORT_ERROR(level, err, msg) (reported = GET_ERROR_TYPE(err))
/* Stop supported requests at their first allocation. Unsupported requests
 * must return before reaching either allocation/control boundary. */
#define kzalloc(size, flags) (allocations++, (void *)NULL)
#define ehash_hcsync_fault_proc_init() (control_calls++)
#define ManipOrStatsSetNode(...) (allocations++, (t_FmPcdManip *)NULL)
#define FreeEnEhashInfo(...) ((void)0)
#define ReleaseManipHandler(...) ((void)0)
#define IpFragmentation(...) E_OK
#define IPManip(...) E_OK
#define IPSecManip(...) E_OK
#define CapwapFragmentation(...) E_OK
#define CapwapManip(...) E_OK
#define CreateManipActionNew(...) E_OK
static en_exthash_global_mem *en_global_muram_mem;
#include "reassembly_production.inc"
int main(void)
{
    e_NetHeaderType headers[] = {HEADER_TYPE_IPv4, HEADER_TYPE_IPv6, HEADER_TYPE_CAPWAP};
    for (unsigned h = 0; h < sizeof(headers) / sizeof(headers[0]); h++) {
        t_FmPcdManipParams params = {.type = e_FM_PCD_MANIP_REASSEM, .h_NextManip = (void *)1};
        params.u.reassem.hdr = headers[h];
        t_FmPcdManipParams before = params;
        reported = 0;
        assert(FM_PCD_ManipNodeSet((void *)1, &params) == NULL);
        assert(!allocations && !control_calls && reported == E_NOT_SUPPORTED);
        assert(!memcmp(&before, &params, sizeof(params)));
    }
    for (unsigned type = IPV4_REASSM_TABLE; type <= IPV6_REASSM_TABLE; type++) {
        for (unsigned flags = 0; flags < 2; flags++) {
            t_FmPcdHashTableParams params = {.table_type = type | (flags ? 0xfffffff0 : 0),
                .maxNumOfKeys = 2, .hashResMask = 1};
            params.ccNextEngineParamsForMiss.nextEngine = e_FM_PCD_DONE;
            params.ccNextEngineParamsForMiss.h_Manip = (void *)1;
            t_FmPcdHashTableParams before = params;
            reported = 0;
            assert(FM_PCD_HashTableSet((void *)1, &params) == NULL);
            assert(!allocations && !control_calls && reported == E_NOT_SUPPORTED);
            assert(!memcmp(&before, &params, sizeof(params)));
        }
    }
    for (unsigned type = 0; type < IPV4_REASSM_TABLE; type++) {
        t_FmPcdHashTableParams params = {.table_type = type, .maxNumOfKeys = 2, .hashResMask = 1};
        params.ccNextEngineParamsForMiss.nextEngine = e_FM_PCD_DONE;
        assert(FM_PCD_HashTableSet((void *)1, &params) == NULL);
        assert(allocations == 1 && control_calls == 1 && reported == E_NO_MEMORY);
        allocations = control_calls = 0;
    }
    e_FmPcdManipType supported[] = {e_FM_PCD_MANIP_HDR, e_FM_PCD_MANIP_FRAG, e_FM_PCD_MANIP_SPECIAL_OFFLOAD};
    for (unsigned i = 0; i < sizeof(supported) / sizeof(supported[0]); i++) {
        t_FmPcdManipParams params = {.type = supported[i]};
        reported = 0;
        assert(FM_PCD_ManipNodeSet((void *)1, &params) == NULL);
        assert(allocations == 1 && !reported); allocations = 0;
    }
    puts("SDK reassembly creation rejected before allocation, control setup or parameter mutation");
}
