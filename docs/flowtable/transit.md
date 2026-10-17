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
own timeout for such protocols when it goes. They are offered only
untranslated, as GRE is: the NAT paths rewrite ports wherever a transport
header would be, which here is an SPI or an inner header.

**The adapter.** `ft_parse()` admits a flow described without the ports key
when `cdx_ft_portless()` names its protocol for its family, with ports zero:
ESP over IPv4 or IPv6, and GRE, IPIP and 6in4 over IPv4 alone. A translated
one, or one through a local tunnel device, is refused. Every other rule a
routed flow meets applies unchanged, the MTU one among them: a direction into
a narrower path stays in software, as a UDP one does (A385).

**The hardware.** Each direction goes into the routed three-tuple tables,
keyed on the address pair and protocol (`IPV4_MULTICAST_TABLE` and
`IPV6_MULTICAST_TABLE`, which routed multicast and ESP already used), with the
routed actions of any flow.

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
goes on as before; the bridged station pairs, whose TCP frames now cross two
more lookups on their way to the Ethernet table, still run at 9.36-9.39 Gbit/s
in every shape.

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
transmits next to nothing meanwhile:

| Case | Rate inside the tunnel |
|---|---|
| GRE | 9.24 Gbit/s |
| IPIP | 9.26 Gbit/s |
| 6in4 | 9.15 Gbit/s |
| ESP, IPv4 / IPv6 | 5.06 / 5.05 Gbit/s, the endpoints' own encryption the bound |

## For the consumer

A ruleset offers these flows only if its `flow add` rule names them. OpenWrt's
fw4 offers `meta l4proto { tcp, udp }`, so on OpenWrt they stay in software
until fw4's rule lists `esp`, `gre`, `ipip` (4) and `ipv6` (41) as well -- a
change for the OpenWrt port, not for this repository.
