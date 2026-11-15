/* WireGuard's send to a peer is production code (wg_socket_send_skb_to_peer()),
 * run by the peer's transmit lanes at once: one thread per lane, as each lane
 * is a work item on a CPU of its own, every one sending to the same peer
 * through the endpoint lock held shared. The routing and the UDP transmit
 * under it are the simulated boundary, and every packet leaves. The peer's
 * sent-bytes counter is declared as the tree's peer.h declares it.
 *
 * Built with ThreadSanitizer: an add a lane can lose to another is a race it
 * reports, and the run fails on it before the total is even compared. */
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

typedef uint8_t u8;
typedef uint64_t u64;
typedef int64_t s64;
typedef struct { s64 counter; } atomic64_t;
typedef pthread_rwlock_t rwlock_t;

#define likely(x) __builtin_expect(!!(x), 1)
#define ____cacheline_aligned_in_smp __attribute__((__aligned__(64)))

static inline void atomic64_add(s64 i, atomic64_t *v)
{
	__atomic_fetch_add(&v->counter, i, __ATOMIC_RELAXED);
}

static inline s64 atomic64_read(const atomic64_t *v)
{
	return __atomic_load_n(&v->counter, __ATOMIC_RELAXED);
}

/* Readers of an rwlock exclude only its writers, as in the kernel. */
static inline void read_lock_bh(rwlock_t *lock)
{
	if (pthread_rwlock_rdlock(lock))
		abort();
}

static inline void read_unlock_bh(rwlock_t *lock)
{
	if (pthread_rwlock_unlock(lock))
		abort();
}

struct sk_buff { unsigned int len; };
struct wg_device { int ifindex; };
struct dst_cache { int unused; };
struct endpoint {
	union {
		struct sockaddr addr;
		struct sockaddr_in addr4;
		struct sockaddr_in6 addr6;
	};
};
struct wg_peer {
	struct wg_device *device;
	struct endpoint endpoint;
	struct dst_cache endpoint_cache;
	rwlock_t endpoint_lock;
	/* The tree's declaration of the bytes sent to the peer. */
#include "wireguard_sent_counter.inc"
};

/* The packet left: routed, and handed to the UDP tunnel transmit. */
static int send4(struct wg_device *wg, struct sk_buff *skb, struct endpoint *endpoint,
		 u8 ds, struct dst_cache *cache)
{
	return 0;
}

static int send6(struct wg_device *wg, struct sk_buff *skb, struct endpoint *endpoint,
		 u8 ds, struct dst_cache *cache)
{
	return 0;
}

static void dev_kfree_skb(struct sk_buff *skb)
{
}

#include "wireguard_send_production.inc"

/* What the peer reports as sent, read as the counter is declared. */
#define sent_bytes(peer) _Generic(&(peer)->tx_bytes, \
	atomic64_t *: (u64)atomic64_read((atomic64_t *)&(peer)->tx_bytes), \
	u64 *: *(u64 *)&(peer)->tx_bytes)

#define PACKETS 200000

static struct wg_device device = { 7 };
static struct wg_peer peer = { .device = &device };
static pthread_barrier_t start;

static unsigned int length(unsigned int lane, unsigned int i)
{
	return 32 + (i * 7 + lane * 131) % 1420;
}

static void *lane_worker(void *arg)
{
	unsigned int lane = (unsigned int)(uintptr_t)arg;
	struct sk_buff skb;

	pthread_barrier_wait(&start);
	for (unsigned int i = 0; i < PACKETS; i++) {
		skb.len = length(lane, i);
		if (wg_socket_send_skb_to_peer(&peer, &skb, 0)) {
			fprintf(stderr, "lane %u: a send the transmit took failed\n", lane);
			abort();
		}
	}
	return NULL;
}

int main(void)
{
	pthread_t worker[LANES];
	u64 expected = 0;

	peer.endpoint.addr4.sin_family = AF_INET;
	if (pthread_rwlock_init(&peer.endpoint_lock, NULL) ||
	    pthread_barrier_init(&start, NULL, LANES))
		abort();
	for (unsigned int lane = 0; lane < LANES; lane++)
		for (unsigned int i = 0; i < PACKETS; i++)
			expected += length(lane, i);
	for (unsigned int lane = 0; lane < LANES; lane++)
		if (pthread_create(&worker[lane], NULL, lane_worker, (void *)(uintptr_t)lane))
			abort();
	for (unsigned int lane = 0; lane < LANES; lane++)
		pthread_join(worker[lane], NULL);
	if (sent_bytes(&peer) != expected) {
		fprintf(stderr, "%u lanes sent %llu bytes to one peer, which counted %llu\n",
			LANES, (unsigned long long)expected,
			(unsigned long long)sent_bytes(&peer));
		return 1;
	}
	printf("%u lanes sent %llu bytes to one peer, all counted\n", LANES,
	       (unsigned long long)expected);
	return 0;
}
