/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Translated sessions (NAT64, SIIT) offered to the hardware by a translator.
 *
 * A translator -- Jool, through a patch of its own -- builds its own packets,
 * routes them itself and steals the originals, so no translated flow ever
 * reaches Netfilter's flowtable (docs/flowtable/nat64.md). This is the
 * admission source it offers its sessions through instead. ask_flowtable
 * decides each one and installs its two directions in the hardware together,
 * or neither, and from then on keeps them valid or retires them exactly as it
 * does a flowtable flow's: one budget, the same route, neighbour, device and
 * tc watches, the same retirement, barrier and teardown.
 *
 * One client at a time. Everything below is translator-neutral: a session is
 * a cookie the client chooses and two directions it describes.
 *
 * What the client must not offer, because the adapter sees no packet and
 * cannot tell (the hardware would do the wrong thing with every one of them):
 *
 *   - IPv4 UDP whose packets carry checksum 0: the hardware emits it as 0,
 *     which IPv6 forbids. Whether a sender checksums is per socket, so a
 *     session does not mix the two;
 *   - ICMP and ICMPv6 of any kind: refused here by protocol, and translated
 *     by the client whatever this says;
 *   - fragments, IPv6 extension headers, and a session whose packets carry
 *     them;
 *   - TCP before it is established, and a session holding a stored packet;
 *   - a session whose translated packets anything after the translation
 *     would treat differently from what the hardware does: a postrouting
 *     rule, a mark the client routes by (routes are looked up with none).
 */
#ifndef ASK_XLAT_H
#define ASK_XLAT_H

#include <linux/netfilter.h>
#include <linux/types.h>

struct net;

/* The TOS or traffic class each arriving packet has, ECN included, carried
 * over as RFC 7915 does; any other value of ask_xlat_flow.tos is a fixed one,
 * as Jool's reset-tos/new-tos and reset-traffic-class configure. */
#define ASK_XLAT_TOS_COPY	0xff

/* One side of a direction, addresses and ports in network byte order. family
 * selects the arm of each address; the unused bytes are zero. */
struct ask_xlat_tuple {
	union nf_inet_addr src;
	union nf_inet_addr dst;
	__be16 sport;
	__be16 dport;
	u8 family;
};

/* One direction of a session: the tuple its packets arrive with, the tuple
 * they leave with in the other family, and the logical device they arrive on
 * (in the initial namespace), as the client received them there. The device
 * the adapter finds the other direction leaving by has to be this one: the
 * physical port and tags a direction arrives with are the ones its sibling
 * leaves with. */
struct ask_xlat_dir {
	struct ask_xlat_tuple match;
	struct ask_xlat_tuple xlat;
	int ifindex;
};

/* A session as ask_xlat_offer() takes it: both directions, TCP or UDP, and the
 * client's own cookie, which names it in every callback and in a withdrawal.
 * net is the namespace the client translates in; only the initial one is
 * offloaded. */
struct ask_xlat_flow {
	const struct net *net;
	u64 cookie;
	u8 proto;
	u8 tos;
	struct ask_xlat_dir dir[2];
};

/* What the adapter tells the client. Both are called in process context,
 * with the adapter's backend transaction held and possibly RTNL, and with no
 * lock of the adapter's that ask_xlat_offer() or ask_xlat_withdraw() takes:
 * they may call either of those, and nothing else of the adapter's. They may
 * not sleep for long, and must not take RTNL -- a thread holding it can be
 * waiting for the transaction the callback runs under. Neither is called once
 * ask_xlat_unregister() has returned.
 *
 * expired: the adapter no longer holds the session the cookie names, in the
 * hardware or on its way there, and does not mean to; it is said once the
 * session's entries are unlinked from the hardware's tables, the barrier that
 * proves the firmware has left them following before the adapter's run ends
 * (ask_xlat_unregister() alone waits for it). Each session the client offers is
 * answered by exactly one, unless the client withdraws it first: when the
 * offer is refused (an unusable path, an MTU the hardware cannot carry, a
 * collision, the budget, a latch), or when the installed session is retired
 * (a route, neighbour or device change, tc, a datapath restart, the client
 * unregistering). An offer of a session the adapter already holds -- queued,
 * being decided, installed, or still leaving the hardware after a retirement
 * -- is folded into it and answered with it. The client offers again while
 * its software path translates the session.
 *
 * used: packets of the session moved in the hardware since it was last said,
 * lastused in jiffies: the keepalive the client's own timers need, since the
 * packets it stands for never reach the client. Said from the counter pass
 * (the stats_ms parameter), at most once a pass per session, and only when
 * packets moved. */
struct ask_xlat_ops {
	void (*expired)(u64 cookie);
	void (*used)(u64 cookie, unsigned long lastused);
};

/* The one client: -EBUSY while another is registered or the last one is still
 * unregistering, -ENODEV while the adapter is not running. The ops must stay
 * valid until ask_xlat_unregister() returns. Process context. */
int ask_xlat_register(const struct ask_xlat_ops *ops);

/* For the ops registered (-EINVAL for any other, nothing done; -EBUSY while
 * an unregistration is under way): refuse every offer from here on, say
 * expired for each still queued, retire every translated session, saying
 * expired for each, and return only once the hardware has been proven to have
 * left them. After that no callback is made. Process context, not from a
 * callback; may sleep for as long as that proof takes. */
int ask_xlat_unregister(const struct ask_xlat_ops *ops);

/* Queue a session for admission. Callable from softirq and from either
 * callback: the flow is copied and decided later by a worker, and nothing here
 * sleeps. True when it was queued, or folded into what already stands for the
 * session: an expired is then owed for the session (above). False -- this
 * offer owing nothing, while whatever already stands for the session still
 * owes its own expired -- for no client registered, another namespace, a protocol
 * other than TCP or UDP, a malformed direction, a full queue, a direction its
 * route's MTU is certain to refuse (the route is read again at each offer),
 * or a session whose expired is being said at that moment, which answers what
 * came before: the client offers again after it. */
bool ask_xlat_offer(const struct ask_xlat_flow *flow);

/* The client no longer has the session: drop any offer of it still queued
 * and retire it from the hardware, saying nothing about it. Callable from
 * softirq and from either callback; the retirement itself is deferred. True
 * when nothing more is said for the session. False when its expired was
 * already being said as the withdrawal landed: that one call is not stopped,
 * and arrives, or has arrived, for the session as it was before -- before the
 * answer to any later offer of the same cookie, all calls being made in turn.
 * A client that never reuses a cookie can ignore the difference. */
bool ask_xlat_withdraw(u64 cookie);

#endif
