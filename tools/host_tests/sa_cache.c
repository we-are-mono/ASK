/* The IPsec SA cache the XFRM provider installs through, compiled from
 * control_ipsec.c.
 *
 * Two tables index every SA: by handle, which the control path and the DPAA
 * submit hook walk, and by the SEC-to-CPU frame queue, which the portal
 * callback walks. Both are hashed into sixteen buckets, so the cases below put
 * two SAs in one bucket of each and check that every lookup still finds the
 * right one, that an SA marked for deletion is skipped without hiding its
 * bucket neighbours, and that every unlink happens under the cache lock the
 * atomic walkers take. */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t U8;
typedef uint16_t U16;
typedef uint32_t U32;
typedef uint64_t U64;

#define container_of(p, type, member) ((type *)((char *)(p) - offsetof(type, member)))
#define READ_ONCE(x) (*(volatile __typeof__(x) *)&(x))
#define WRITE_ONCE(x, v) (*(volatile __typeof__(x) *)&(x) = (v))
#define printk_ratelimited(...) ((void)0)
#define printk(...) ((void)0)

#include "sa_cache_types.inc"

struct net_device { int id; };
struct qman_fq { int id; };

typedef struct {
	U32 to_cp_fqid;
	void *dpa_ipsecsa_handle;
	struct { U32 auth_type; } auth_data;
	struct { U32 cipher_type; } cipher_data;
} DpaSecSAContext, *PDpaSecSAContext;

typedef struct { int unused; } RouteEntry;

typedef struct {
	struct slist_entry list_h;
	struct slist_entry list_fqid;
	struct { U32 saddr[4]; union { U32 a6[4]; } daddr; U32 spi; U8 proto; } id;
	U8 family;
	U16 handle;
	U16 mtu, dev_mtu;
	U8 direction;
	U64 seq;
	U16 flags;
	U16 hash_by_h;
	struct net_device *netdev;
	RouteEntry *pRtEntry;
	PDpaSecSAContext pSec_sa_context;
} SAEntry, *PSAEntry;

/* The cache lock, as the atomic walkers and the writers take it. Never
 * nested, and never left held. */
static int sa_lock_held, sa_lock_takes;
#define DEFINE_SPINLOCK(l) int l
#define spin_lock_irqsave(l, f) do { (void)(l); (f) = 0; assert(!sa_lock_held); \
	sa_lock_held = 1; sa_lock_takes++; } while (0)
#define spin_unlock_irqrestore(l, f) do { (void)(l); (void)(f); assert(sa_lock_held); \
	sa_lock_held = 0; } while (0)

/* Every link into and unlink from the two tables -- which is every list
 * operation the cache makes -- has to happen under that lock, or an atomic
 * walker can be standing on the entry as it goes. Counted too, so a case can
 * say how many it expects and a path that skips the list altogether shows. */
static unsigned sa_links, sa_unlinks;
static inline void cache_slist_add(struct slist_head *list, struct slist_entry *entry)
{
	assert(sa_lock_held);
	sa_links++;
	slist_add(list, entry);
}
static inline void cache_slist_remove(struct slist_head *list, struct slist_entry *entry)
{
	assert(sa_lock_held);
	sa_unlinks++;
	slist_remove(list, entry);
}
#define slist_add cache_slist_add
#define slist_remove cache_slist_remove

/* The allocators, each able to fail once on request. */
static bool fail_sa_alloc, fail_context_alloc;
static unsigned live_sa, live_context;
static void *Heap_Alloc_ARAM(size_t size)
{
	if (fail_sa_alloc) {
		fail_sa_alloc = false;
		return NULL;
	}
	live_sa++;
	return malloc(size);
}
static void Heap_Free(void *p) { assert(live_sa); live_sa--; free(p); }

static U32 next_fqid;
static PDpaSecSAContext cdx_ipsec_sec_sa_context_alloc(U32 handle)
{
	PDpaSecSAContext ctx;

	(void)handle;
	if (fail_context_alloc) {
		fail_context_alloc = false;
		return NULL;
	}
	ctx = calloc(1, sizeof(*ctx));
	assert(ctx);
	ctx->to_cp_fqid = next_fqid;
	ctx->dpa_ipsecsa_handle = ctx;
	live_context++;
	return ctx;
}
static void cdx_ipsec_sec_sa_context_free(PDpaSecSAContext ctx)
{
	assert(live_context);
	live_context--;
	free(ctx);
}

static struct qman_fq to_sec_fq;
static struct qman_fq *get_to_sec_fq(void *handle)
{
	assert(handle);
	return &to_sec_fq;
}

/* The release the backend's teardown reaches, reduced to what it does to
 * the cache: the fqid unlink and the frees, never while the lock is held. */
void sa_remove_from_list_fqid(PSAEntry pSA);
void sa_free(PSAEntry pSA);
static PSAEntry released;
static void cdx_ipsec_release_sa_resources(PSAEntry pSA)
{
	assert(!sa_lock_held);
	pSA->flags |= SA_DELETE;
	released = pSA;
	sa_remove_from_list_fqid(pSA);
	cdx_ipsec_sec_sa_context_free(pSA->pSec_sa_context);
	pSA->pSec_sa_context = NULL;
	sa_free(pSA);
}

#include "sa_cache.inc"

static U32 addr[4] = { 0x0a000001 }, peer[4] = { 0x0a000002 };

static PSAEntry create(U16 handle, U32 fqid, bool inbound)
{
	PSAEntry sa;

	next_fqid = fqid;
	sa = M_ipsec_sa_cache_create(addr, peer, 0x1000 + handle, IPPROTOCOL_ESP,
				     PROTO_IPV4, handle, 1, 0, 1400, 1500, inbound);
	assert(sa && !sa_lock_held);
	return sa;
}

int main(void)
{
	struct net_device dev_a = { 1 }, dev_b = { 2 };
	PSAEntry a, b;
	U16 got;
	int takes;
	unsigned links, unlinks;

	for (int i = 0; i < NUM_SA_ENTRIES; i++) {
		sa_cache_by_h[i].next = NULL;
		sa_cache_by_fqid[i].next = NULL;
	}

	/* Either allocation failing leaves nothing behind and nothing linked. */
	fail_sa_alloc = true;
	assert(!M_ipsec_sa_cache_create(addr, peer, 1, IPPROTOCOL_ESP, PROTO_IPV4,
					3, 1, 0, 1400, 1500, 0));
	fail_context_alloc = true;
	assert(!M_ipsec_sa_cache_create(addr, peer, 1, IPPROTOCOL_ESP, PROTO_IPV4,
					3, 1, 0, 1400, 1500, 0));
	assert(!live_sa && !live_context && !sa_lock_held);
	assert(!M_ipsec_sa_cache_lookup_by_h(3));
	assert(M_ipsec_sa_cache_entries() == 0);

	/* Two SAs sharing a handle bucket and a frame-queue bucket. */
	takes = sa_lock_takes;
	links = sa_links;
	a = create(3, 0x200 + 5, false);
	b = create(3 + NUM_SA_ENTRIES, 0x200 + 5 + NUM_SA_ENTRIES, true);
	/* Each create links both tables under the lock, and is counted once. */
	assert(sa_lock_takes - takes == 4 && sa_links - links == 4);
	assert(M_ipsec_sa_cache_entries() == 2);
	a->netdev = &dev_a;
	b->netdev = &dev_b;
	assert(a->hash_by_h == b->hash_by_h);
	assert(a->direction == CDX_DPA_IPSEC_OUTBOUND && b->direction == CDX_DPA_IPSEC_INBOUND);
	assert(!(a->flags & SA_ALLOW_SEQ_ROLL) && !(a->flags & SA_ALLOW_EXT_SEQ_NUM));
	assert(a->pSec_sa_context->auth_data.auth_type == OP_PCL_IPSEC_HMAC_NULL);
	assert(a->pSec_sa_context->cipher_data.cipher_type == OP_PCL_IPSEC_NULL_ENC);

	assert(M_ipsec_sa_cache_lookup_by_h(3) == a);
	assert(M_ipsec_sa_cache_lookup_by_h(3 + NUM_SA_ENTRIES) == b);
	assert(!M_ipsec_sa_cache_lookup_by_h(3 + 2 * NUM_SA_ENTRIES));

	/* The portal callback's walk resolves each queue to its own SA. */
	assert(get_netdev_of_SA_by_fqid(0x200 + 5, &got) == &dev_a && got == 3);
	assert(get_netdev_of_SA_by_fqid(0x200 + 5 + NUM_SA_ENTRIES, &got) == &dev_b &&
	       got == 3 + NUM_SA_ENTRIES);
	assert(!get_netdev_of_SA_by_fqid(0x200 + 5 + 2 * NUM_SA_ENTRIES, &got));
	assert(!sa_lock_held);

	/* The submit hook finds a live SA's queue, and not a dying one's. */
	assert(cdx_get_to_sec_fq_handler(3) == &to_sec_fq);
	b->flags |= SA_DELETE;
	assert(!cdx_get_to_sec_fq_handler(3 + NUM_SA_ENTRIES));
	/* A dying SA is skipped, and its bucket neighbour still resolves. */
	assert(!get_netdev_of_SA_by_fqid(0x200 + 5 + NUM_SA_ENTRIES, &got));
	assert(get_netdev_of_SA_by_fqid(0x200 + 5, &got) == &dev_a && got == 3);
	b->flags &= ~SA_DELETE;
	assert(!sa_lock_held);

	/* A handle nobody holds is refused and touches nothing. */
	unlinks = sa_unlinks;
	assert(M_ipsec_sa_cache_delete(3 + 2 * NUM_SA_ENTRIES) == ERR_SA_UNKNOWN);
	assert(!released && live_sa == 2 && sa_unlinks == unlinks);
	assert(M_ipsec_sa_cache_entries() == 2);

	/* Deleting one leaves the other reachable through both tables. Its
	 * two unlinks, one from each table, are both made under the lock:
	 * the list operations above assert it. */
	assert(M_ipsec_sa_cache_delete(3) == NO_ERR);
	assert(released == a && live_sa == 1 && live_context == 1);
	assert(sa_unlinks - unlinks == 2);
	assert(M_ipsec_sa_cache_entries() == 1);
	assert(!M_ipsec_sa_cache_lookup_by_h(3));
	assert(M_ipsec_sa_cache_lookup_by_h(3 + NUM_SA_ENTRIES) == b);
	assert(!get_netdev_of_SA_by_fqid(0x200 + 5, &got));
	assert(get_netdev_of_SA_by_fqid(0x200 + 5 + NUM_SA_ENTRIES, &got) == &dev_b);

	released = NULL;
	assert(M_ipsec_sa_cache_delete(3 + NUM_SA_ENTRIES) == NO_ERR);
	assert(released == b && !live_sa && !live_context && !sa_lock_held);
	assert(sa_unlinks - unlinks == 4 && sa_links - sa_unlinks == 0);
	assert(M_ipsec_sa_cache_entries() == 0);
	for (int i = 0; i < NUM_SA_ENTRIES; i++)
		assert(!sa_cache_by_h[i].next && !sa_cache_by_fqid[i].next);

	/* The flags the create derives from what it was asked. */
	next_fqid = 0x300;
	a = M_ipsec_sa_cache_create(addr, peer, 7, IPPROTOCOL_ESP, PROTO_IPV4,
				    9, 0, 1, 1400, 1500, 1);
	assert(a && (a->flags & SA_ALLOW_SEQ_ROLL) && (a->flags & SA_ALLOW_EXT_SEQ_NUM));
	assert(M_ipsec_sa_cache_delete(9) == NO_ERR && !live_sa && !live_context);

	printf("SA cache: bucket sharing, deletion gate, unlink under lock passed\n");
	return 0;
}
