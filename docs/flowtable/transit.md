# Transit tunnels

ESP between two IPsec peers, and GRE, IPv4 in IPv4 (IPIP) and IPv6 in IPv4
(6in4) between two tunnel endpoints, forwarded by the router rather than
terminated on it: a LAN host's IPsec VPN without NAT-T, a GRE tunnel, a tunnel
broker's 6in4 run from a LAN host (A386). Conntrack tracks each by its address
pair and protocol, and 1.1.0 left them all to software, because Netfilter's
flowtable carries only TCP, UDP and GREv0 and the adapter only TCP and UDP.

## What carries them

**Software.** Kernel patch 174 has the flowtable carry ESP, IPIP and
IPv6-in-IP as it carries GRE: the tuple is the address pair and the protocol,
the match a driver is handed says no more, and the offload timeout holds the
connection for a day while the flow lives and hands it back with conntrack's
own timeout for such protocols when it goes -- GRE's own included, which the
flowtable had left at the day. They are offered only untranslated, as GRE is.
NPTv6 translates a connection's addresses without marking it NATed, and the
flowtable then rewrote the tuple's zero ports wherever a transport header
would be, here into an SPI or an inner header: the port rewrites now touch TCP
and UDP alone, in software and in the rule a driver is handed.

**The adapter.** `ft_parse()` admits a flow described without the ports key
when `cdx_ft_portless()` names its protocol for its family, with ports zero:
ESP over IPv4 or IPv6, and GRE, IPIP and 6in4 over IPv4 alone. A translated
one is refused, and so is one through a local tunnel device, into a PPPoE
session, or into or out of one of the router's own SAs, whose descriptors are
filled for the TCP and UDP tables alone; those stay in the software flowtable.
One received in a session is carried, bound to the session's ID (below). Every
other rule a routed flow meets applies unchanged, the MTU one among them: a
direction into a narrower path stays in software, as a UDP one does (A385).

**The hardware.** Each direction goes into the routed three-tuple tables,
keyed on the address pair and protocol (`IPV4_MULTICAST_TABLE` and
`IPV6_MULTICAST_TABLE`, which routed multicast and ESP already used), with the
routed actions of any flow. The tables are shared: the IPv4 one holds 512
entries in 256 buckets for routed groups, their listeners and transit flows
together, and an install that finds no room leaves its flow or group in
software. An outer fragment of a tunnel or ESP flow has no transport header
to parse past, so it reaches the three-tuple key directly and is forwarded in
hardware like the rest, where Linux's flowtable leaves fragments to the stack.

## How their frames reach that key

Which classification a frame reaches is read off the hardware:
`/proc/cdx_pcd_schemes` lists every KeyGen scheme a port's frames can be
distributed by with the frames it has taken, a scheme a table's miss hands a
frame to included. Frames of each kind sent into the LAN port showed:

| Frame | Schemes, in order |
|---|---|
| ESP over IPv4 / IPv6 | ESP, three-tuple, bridged multicast, Ethernet |
| GRE with no IP inside | three-tuple, bridged multicast, Ethernet |
| GRE carrying IPv4 TCP, IPIP carrying TCP | TCP4, Ethernet |
| IPIP carrying UDP | UDP4, three-tuple UDP, Ethernet |
| 6in4 carrying TCP | TCP6, Ethernet |
| GRE or IPIP over IPv6 | TCP4, keyed on the inner header |

ESP already reached the three-tuple key through its own table's miss. The
parser takes a tunnel down to the stream it carries -- deliberately, for the
locally terminated tunnels the TCP and UDP schemes' tunnel keys decapsulate --
so a transit tunnel's frames miss in the TCP and UDP tables on their inner
ports. `cdxdrv_set_miss_action()` now hands the TCP tables' and the
three-tuple UDP tables' misses to the IPv4 three-tuple scheme before the
Ethernet table, and that scheme keys the first IPv4 header: the tunnel's outer
one whenever the outer header is IPv4. That is why IPIP, 6in4 and GRE are
carried over IPv4 alone. A frame no transit flow claims misses there too and
goes on as before. That costs every such frame two more lookups on its way to
the Ethernet table, which full-size frames do not show -- the bridged station
pairs still run at 9.36-9.39 Gbit/s in every shape -- and minimum ones do: the
LAN VM flooding a pair with 64-byte frames at 9 Mpps, the pair forwards
2.06-2.17 Mpps through this chain and 2.50 Mpps through 1.0.7's, 13-18% less
(`flowtable_l2bridge.py::test_l2_packet_rate`, A392). Below that rate, and for
frames past about 600 bytes at line rate, nothing is lost either way.

## In a PPPoE session

A transit flow that arrives in a session -- a LAN host's native IPsec over an
IPv6-over-PPPoE WAN above all -- is keyed on the session as well (A391). The
three-tuple keys end with the first four bytes of the frame's PPPoE header,
zeros for a native frame, from the tables' one scheme: the TCP and UDP tables'
misses reach it as well as frames that go to it directly, and a miss names one
scheme. The entry strips the session as a TCP or UDP one does. Unlike theirs,
it binds the session ID and not the concentrator's MAC
([pppoe.md](pppoe.md#receive-identity)). A session frame no longer hits a
native entry with the same addresses, which before it could, routed multicast
groups' included. The way into the session stays in software: what a 1500-byte
LAN may deliver exceeds the session's MTU, and a push from these tables is not
proven.

## Switched on

All of it is behind cdx's `transit` parameter, off by default: off, the TCP
and UDP tables' misses go straight to the Ethernet table, as in 1.0.7, and no
port-less flow is admitted, so a router that never forwards such a tunnel
keeps 1.0.7's rate for every frame no flow claims. On, it is everything this
page describes. Read when the classifier is built, it takes a reboot to
change -- cdx cannot be loaded twice in one boot. `/proc/cdx_flowtable` says
which as `transit`. On OpenWrt it is a module option (`cdx transit=1` in
`/etc/modules.d`), and fw4's rule has to offer the protocols as well (below).
The ASK test image turns it on (`/etc/modprobe.d/ask-transit.conf`), and a
boot with `cdx.transit=0` on the kernel's command line runs the case that
proves it off (`flowtable_transit.py::test_transit_switched_off`).

A 6in4 tunnel's inner ICMPv6, and anything else its parser leaves with no
TCP or UDP behind the inner IPv6 header, reaches the IPv6 three-tuple scheme
on the inner header and misses: those frames go to the CPU, which forwards
them through the software flowtable. A tunnel's inner TCP SYN, FIN and RST go
to the CPU too, as `cdx_sp.xml` sends every such segment.

## Proof on the rig

`flowtable_transit.py` builds real tunnels between the LAN VM and the WAN
host, routed through the DUT and untranslated -- Linux GRE, IPIP and sit
devices at both ends, and for ESP a pair of manual transport-mode SAs over one
TCP port, in IPv4 and in IPv6 -- offers the protocol to a hardware flowtable,
and runs a TCP stream inside. Both directions are installed, their counters
move by the millions of frames in a three-second window, and the DUT's kernel
transmits next to nothing meanwhile. Once the stream ends, both directions
are let go and the connection's timeout is conntrack's own -- GRE's three
minutes, ten for the others -- and a GRE tunnel the image masquerades is never
installed at all:

| Case | Rate inside the tunnel |
|---|---|
| GRE | 9.24 Gbit/s |
| IPIP | 9.26 Gbit/s |
| 6in4 | 9.15 Gbit/s |
| ESP, IPv4 / IPv6 | 5.06 / 5.05 Gbit/s, the endpoints' own encryption the bound |

## For the consumer

A ruleset offers these flows only if its `flow add` rule names them. OpenWrt's
fw4 offers `meta l4proto { tcp, udp }`, so on OpenWrt they stay in software
until fw4's rule lists `esp`, `gre`, `ipip` (4) and `ipv6` (41) as well, and
cdx's `transit` is on -- a change for the OpenWrt port, not for this
repository.
