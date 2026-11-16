/*
 * The flowtable's walk (nf_flow_table_walk(), compiled from the kernel tree)
 * against a model of the rhashtable walker: one bucket whose chain takes new
 * entries at its head, as rhashtable_insert_fast() does, a removed entry
 * keeping its next pointer for a walker standing on it, and start, next, peek
 * and stop following lib/rhashtable.c -- start finds the entry the walk
 * stopped on again by address and recomputes its position, or forgets it if
 * it is gone, keeping the old position; a resize restarts the walk. Softirqs,
 * RCU and the scheduler are counters and hooks.
 */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define container_of(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))
#define MAX_ERRNO 4095
#define IS_ERR(ptr) ((uintptr_t)(ptr) >= (uintptr_t)-MAX_ERRNO)
#define PTR_ERR(ptr) ((long)(ptr))
#define ERR_PTR(err) ((void *)(long)(err))
#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

struct rhash_head { struct rhash_head *next; };
struct rhashtable {
	struct rhash_head *head;
	/* The next start finds the table resized and restarts the walk. */
	bool resize;
	/* A rehash in progress: a walk reaching the end of the table goes on
	 * in the new one, from its start, after -EAGAIN. */
	bool future;
};
struct rhashtable_iter {
	struct rhashtable *ht;
	struct rhash_head *p;
	unsigned int skip;
	unsigned int slot;	/* 1: past the table's one bucket */
	bool end;
};

struct flow_offload_tuple { int dir; };
struct flow_offload_tuple_rhash {
	struct rhash_head node;
	struct flow_offload_tuple tuple;
};
struct flow_offload {
	struct flow_offload_tuple_rhash tuplehash[2];
	unsigned int visits;
	bool in_table;
};
struct nf_flowtable { struct rhashtable rhashtable; };

static int rcu_depth, bh_depth;
static unsigned int softirq_windows, sleeps;
static bool want_resched;
static void (*on_sleep)(void);

static void local_bh_disable(void) { bh_depth++; }
static void local_bh_enable(void)
{
	assert(bh_depth > 0);
	if (!--bh_depth && rcu_depth)
		softirq_windows++;
}
static bool need_resched(void) { return want_resched; }
static void cond_resched(void)
{
	assert(!rcu_depth && !bh_depth);
	sleeps++;
	if (on_sleep)
		on_sleep();
}

static void *obj(struct rhash_head *he)
{
	return container_of(he, struct flow_offload_tuple_rhash, node);
}
static void rhashtable_walk_enter(struct rhashtable *ht, struct rhashtable_iter *iter)
{
	memset(iter, 0, sizeof(*iter));
	iter->ht = ht;
}
static void rhashtable_walk_exit(struct rhashtable_iter *iter) { iter->ht = NULL; }
static void rhashtable_walk_start(struct rhashtable_iter *iter)
{
	struct rhash_head *he;
	unsigned int skip = 0;

	rcu_depth++;
	if (iter->end)
		return;
	if (iter->ht->resize) {
		iter->ht->resize = false;
		iter->p = NULL;
		iter->skip = 0;
		iter->slot = 0;
		return;
	}
	if (!iter->p)
		return;
	for (he = iter->ht->head; he; he = he->next) {
		skip++;
		if (he == iter->p) {
			iter->skip = skip;
			return;
		}
	}
	iter->p = NULL;
}
static void rhashtable_walk_stop(struct rhashtable_iter *iter)
{
	assert(rcu_depth > 0);
	rcu_depth--;
}
static void *find_next(struct rhashtable_iter *iter)
{
	struct rhash_head *he;
	unsigned int skip = iter->skip;

	if (!iter->slot) {
		for (he = iter->ht->head; he && skip; he = he->next)
			skip--;
		if (he) {
			iter->skip++;
			iter->p = he;
			return obj(he);
		}
		iter->skip = 0;
		iter->slot = 1;
	}
	iter->p = NULL;
	if (iter->ht->future) {
		iter->ht->future = false;
		iter->slot = 0;
		iter->skip = 0;
		return ERR_PTR(-EAGAIN);
	}
	iter->end = true;
	return NULL;
}
static void *rhashtable_walk_next(struct rhashtable_iter *iter)
{
	assert(rcu_depth > 0);
	if (iter->p) {
		struct rhash_head *he = iter->p->next;

		if (he) {
			iter->skip++;
			iter->p = he;
			return obj(he);
		}
		iter->skip = 0;
		iter->slot = 1;
	}
	return find_next(iter);
}
static void *rhashtable_walk_peek(struct rhashtable_iter *iter)
{
	assert(rcu_depth > 0);
	if (iter->p)
		return obj(iter->p);
	if (iter->skip)
		iter->skip--;
	return find_next(iter);
}

#include "walk_production.inc"

static struct nf_flowtable ft;
static struct flow_offload flows[300];
static struct flow_offload extra[8];
static size_t nflows;

static void insert(struct flow_offload_tuple_rhash *t)
{
	t->node.next = ft.rhashtable.head;
	ft.rhashtable.head = &t->node;
}
static void unlink_node(struct flow_offload_tuple_rhash *t)
{
	struct rhash_head **pp;

	for (pp = &ft.rhashtable.head; *pp; pp = &(*pp)->next)
		if (*pp == &t->node) {
			*pp = t->node.next;	/* the node keeps its next */
			return;
		}
	assert(false);
}
/* As flow_offload_add() publishes a flow: the reply direction, then the
 * original one, which the walks iterate, last. */
static void add(struct flow_offload *flow)
{
	memset(flow, 0, sizeof(*flow));
	flow->tuplehash[0].tuple.dir = 0;
	flow->tuplehash[1].tuple.dir = 1;
	insert(&flow->tuplehash[1]);
	insert(&flow->tuplehash[0]);
	flow->in_table = true;
}
static void del(struct flow_offload *flow)
{
	unlink_node(&flow->tuplehash[0]);
	unlink_node(&flow->tuplehash[1]);
	flow->in_table = false;
}
static void setup(size_t n)
{
	memset(&ft, 0, sizeof(ft));
	nflows = n;
	for (size_t i = 0; i < n; i++)
		add(&flows[i]);
	softirq_windows = sleeps = 0;
	want_resched = false;
	on_sleep = NULL;
}

static bool remove_on_visit;
static void visit(struct nf_flowtable *table, struct flow_offload *flow, void *data)
{
	assert(table == &ft && rcu_depth == 1 && bh_depth == 1);
	assert(flow->in_table);
	flow->visits++;
	if (remove_on_visit)
		del(flow);
}
static size_t visited(unsigned int times)
{
	size_t n = 0;

	for (size_t i = 0; i < nflows; i++)
		n += flows[i].visits == times;
	return n;
}
static void walk(bool resched)
{
	assert(nf_flow_table_walk(&ft, visit, NULL, resched) == 0);
	assert(!rcu_depth && !bh_depth);
}

/* The original direction the walk stands before while asleep: in chain order,
 * every entry ahead of it was handled. */
static struct flow_offload *stopped(void)
{
	for (struct rhash_head *he = ft.rhashtable.head; he; he = he->next) {
		struct flow_offload_tuple_rhash *t = obj(he);

		if (!t->tuple.dir) {
			struct flow_offload *flow = container_of(t, struct flow_offload, tuplehash[0]);

			if (!flow->visits)
				return flow;
		}
	}
	return NULL;
}
static struct flow_offload *gone;
static void drop_stopped(void)
{
	if (gone)
		return;
	gone = stopped();
	assert(gone);
	del(gone);
}
/* A flow the packet path failed to add takes its reply direction out again:
 * here, one that the walk has already passed. */
static void drop_reply_ahead(void)
{
	static bool done;

	if (done)
		return;
	done = true;
	unlink_node(&extra[0].tuplehash[1]);
}
/* The hazard that keeps the sweeps beside the GC awake: the GC removes the
 * entry the sweep stopped on and one ahead of it in the bucket. */
static void drop_stopped_and_one_ahead(void)
{
	struct flow_offload *s;

	if (gone)
		return;
	s = stopped();
	gone = s;
	del(s);
	del(&flows[nflows - 1]);	/* the chain's first: handled already */
}
static void add_while_asleep(void)
{
	static bool done;

	if (done)
		return;
	done = true;
	for (size_t i = 0; i < ARRAY_LEN(extra); i++)
		add(&extra[i]);
}
static void drop_stopped_in_rehash(void)
{
	if (gone)
		return;
	drop_stopped();
	ft.rhashtable.future = true;
}
static void resize_while_asleep(void)
{
	static bool done;

	if (done)
		return;
	done = true;
	ft.rhashtable.resize = true;
}

int main(void)
{
	/* Softirqs are held off across each batch and run between batches,
	 * and once more as the walk ends; every flow is handled once. */
	setup(200);
	walk(false);
	assert(visited(1) == 200 && softirq_windows == 200 / NF_FLOW_TABLE_WALK_BATCH + 1);
	assert(!sleeps);

	/* A sweep beside the GC does not sleep, wanted or not. */
	setup(200);
	want_resched = true;
	walk(false);
	assert(visited(1) == 200 && !sleeps);

	/* The GC sleeps at each batch's end when the CPU is wanted, and only
	 * then, and resumes at the flow it stopped before. */
	setup(200);
	walk(true);
	assert(visited(1) == 200 && !sleeps);
	setup(200);
	want_resched = true;
	walk(true);
	assert(visited(1) == 200 && sleeps == 200 / NF_FLOW_TABLE_WALK_BATCH);

	/* Removing what it handles, as the GC does, it still handles each
	 * flow once and empties the table. */
	setup(200);
	want_resched = true;
	remove_on_visit = true;
	walk(true);
	remove_on_visit = false;
	assert(visited(1) == 200 && !ft.rhashtable.head);

	/* A reply direction taken out ahead of it while it sleeps -- a failed
	 * add's -- moves nothing: the stopped flow is found by address. */
	setup(150);
	memset(&extra[0], 0, sizeof(extra[0]));
	extra[0].tuplehash[1].tuple.dir = 1;
	insert(&extra[0].tuplehash[1]);
	want_resched = true;
	on_sleep = drop_reply_ahead;
	walk(true);
	assert(visited(1) == 150);

	/* Flows added while it sleeps land ahead of it: the rest are each
	 * handled once, and the new ones not at all. */
	setup(150);
	want_resched = true;
	on_sleep = add_while_asleep;
	walk(true);
	assert(visited(1) == 150);
	for (size_t i = 0; i < ARRAY_LEN(extra); i++)
		assert(!extra[i].visits);

	/* Had the flow it stopped before gone, it resumes at the next one. */
	setup(150);
	gone = NULL;
	want_resched = true;
	on_sleep = drop_stopped;
	walk(true);
	assert(gone && !gone->visits && visited(1) == 149);

	/* ... and with the table's last flow gone, it ends. */
	setup(NF_FLOW_TABLE_WALK_BATCH);
	gone = NULL;
	want_resched = true;
	on_sleep = drop_stopped;
	walk(true);
	assert(gone == &flows[0] && visited(1) == NF_FLOW_TABLE_WALK_BATCH - 1);

	/* Had one ahead of it gone as well, it would skip a flow present
	 * throughout: why only a walk nothing removes flows beside sleeps. */
	setup(150);
	gone = NULL;
	want_resched = true;
	on_sleep = drop_stopped_and_one_ahead;
	walk(true);
	assert(visited(0) == 2 && visited(1) == 148);

	/* A resize while it sleeps restarts it: every flow is handled, those
	 * before the restart twice. */
	setup(150);
	want_resched = true;
	on_sleep = resize_while_asleep;
	walk(true);
	assert(visited(1) + visited(2) == 150 && visited(2) == NF_FLOW_TABLE_WALK_BATCH - 1);

	/* A rehash met at the table's end goes on in the new table, from its
	 * start, after -EAGAIN: every flow is shown again. */
	setup(150);
	ft.rhashtable.future = true;
	walk(false);
	assert(visited(2) == 150);

	/* ... the peek that resumes the walk meeting it too. */
	setup(NF_FLOW_TABLE_WALK_BATCH);
	gone = NULL;
	want_resched = true;
	on_sleep = drop_stopped_in_rehash;
	walk(true);
	assert(gone == &flows[0] && visited(2) == NF_FLOW_TABLE_WALK_BATCH - 1);

	printf("flowtable walk checks passed\n");
	return 0;
}
