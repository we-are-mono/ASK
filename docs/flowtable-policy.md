# Linux flowtable policy

`ask-flowtable` manages admission policy for the experimental IPv4 TCP/UDP
backend. Linux still owns connection tracking, routing, firewall decisions and
flow lifetimes. CDX supplies the hardware implementation. Select ownership at
boot with `ask.offload=flowtable`; this tool cannot change the owner.

See the [project overview](linux-flowtable-offload.md) for supported scope and
the [architecture](flowtable-architecture.md) for provider and lifetime contracts.

The installed `/etc/ask/flowtable.json` starts disabled. Its FTP, SIP and PPTP
control exclusions carry over the repository's existing fastforward policy.
The legacy `/etc/config/fastforward` remains the input for CMM boots.

Edit the JSON, validate it, inspect the generated rules, then apply it:

```sh
ask-flowtable check
ask-flowtable render
ask-flowtable apply
ask-flowtable status
ask-flowtable stop
```

`render` requires an enabled policy. `check`, `render` and `apply` accept
`--config /path/to/candidate.json`. Applying a candidate does not write the
persistent configuration file. The flowtable boot hook applies the default file
after gateway setup; `reload` and `restart` repeat the same operation. A CMM
boot skips this hook. Errors propagate to the caller and boot log.

An example confined to a routed, non-NAT peer pair is:

```json
{
  "version": 1,
  "enabled": true,
  "devices": ["eth3", "eth4"],
  "scope": [{"source": "192.0.2.10", "destination": "198.51.100.20"}],
  "exclude": [
    {"name": "FTP control", "protocol": "tcp", "port": 21},
    {"name": "SIP", "protocol": "udp", "port": 5060},
    {"name": "PPTP control", "protocol": "tcp", "port": 1723}
  ]
}
```

Each scope or exclusion object combines its selectors with AND. Objects in a
list are alternatives. Exclusions take precedence over scope. An explicit
`"scope": [{}]` permits any otherwise eligible connection. An empty scope cannot
be enabled, and an empty exclusion object is rejected. Names are metadata.

| Selector | Meaning |
| --- | --- |
| `protocol` | `tcp` or `udp` |
| `source`, `destination` | Original conntrack tuple's IPv4 address or network prefix |
| `reply_source`, `reply_destination` | Reply conntrack tuple's IPv4 address or prefix |
| `source_port`, `destination_port` | Original tuple's port |
| `reply_source_port`, `reply_destination_port` | Reply tuple's port |
| `port` | Any of the four tuple ports; expands to four alternatives |
| `mark` | Conntrack mark as `{"value": 0, "mask": 255}` |

Ports accept an integer from 1 to 65535 or `{"min": 1000, "max": 2000}`.
Prefixes must have their host bits clear. Unknown fields, duplicate JSON keys,
invalid types and configurations over 64 KiB are rejected. Each list permits
at most 256 objects. There is no arbitrary nftables text in this format.

Admission requires established original-direction IPv4 TCP/UDP traffic and a
zero conntrack mark. Routed TCP/UDP, source NAT (static or MASQUERADE) and destination NAT are
eligible; hairpin/double NAT remains outside hardware support. Linux additionally refuses helper and sequence-adjusted connections. See the
[NAT contract](flowtable-nat.md) for mapping and reply-tuple semantics. Nonzero mark
selectors are representable for policy migration but cannot broaden the
backend's zero-mark contract. This tool creates no routes, firewall permissions,
NAT exemptions, helpers or feature-specific acceleration.

## Firewall ordering and revocation

The controller owns only `table inet ask_flowtable`. Its forward admission
chain has priority **10**. All forward firewall chains that decide whether a
connection is permitted must execute before that priority, for example the
standard priority 0 filter chain. Audit this ordering when integrating another
firewall manager. Hardware packets subsequently bypass the forwarding hooks,
as Linux flowtable caching requires.

To revoke a cached flow after a firewall change, stop acceleration, apply the
firewall changes, then apply the intended admission policy. For an exclusion
change, `ask-flowtable apply` performs the retirement itself. Editing unrelated
nftables rules or a configuration file alone does not revoke cached hardware.
The owned table must be modified exclusively through this controller; its
comment records the applied configuration hash, not a tamper detector for
other privileged writers.

Applying a policy validates the candidate before modifying the kernel, acquires
a process lock, deletes the old owned table and waits for bindings, hardware
entries, shared handles, neighbours and quarantine to drain. Only then does it
check and install the new nftables transaction. The check itself can temporarily
bind the backend, so those bindings must also drain before installation.
Completion requires the expected table hash and healthy backend bindings.

This operation has a bounded software-forwarding interval. It preserves
conntracks and sockets. Syntax/schema errors and missing devices leave the old
policy untouched. A kernel rejection after retirement leaves acceleration
disabled and reports an error; it does not restore an obsolete exclusion policy.
A retirement failure reports that recovery is required and never publishes a
replacement. A fatal hardware failure still requires full provider teardown
and a fresh boot. There is no automatic switch to CMM.

Concurrent controller calls serialize on `/run/lock/ask-flowtable.lock`. An nft
child inherits the lease, so killing its parent cannot let an older transaction
commit after a newer controller takes ownership. If interrupted between drain
and installation, forwarding remains in software. If interrupted after commit,
the table's hash exposes the committed policy. Reapply the desired configuration
to reconcile either case. A table with the same name but no controller marker,
or backend bindings owned by another table, is refused.

`status` reports `policy_installed`, `policy_hash`, `admission_ready` and the
backend counters. A present policy does not establish active hardware traffic.
Use directional hardware counters, software interface TX counters and CPU
measurements to prove execution. Global invalidation may leave the policy
installed while admission is stopped; applying it again performs the explicit
recovery boundary.

## Carrying useful CMM settings forward

| Existing responsibility | Linux replacement |
| --- | --- |
| Fastforward protocol, tuple address/port exclusions | `exclude` selectors above; original/reply directions keep conntrack semantics |
| CMM `port` shortcut | `port`, preserving its four tuple-port alternatives |
| CMM `ip_v4_addr` shortcut | Four exclusion objects, one per original/reply address selector |
| Global acceleration enable/disable | `enabled` and `apply`/`stop` |
| Hardware UDP/TCP inactivity policy | Linux `net.netfilter.nf_flowtable_udp_timeout` / `nf_flowtable_tcp_timeout`; verify hardware behaviour when changing lifetime policy |
| Connection table limits and protocol state timeouts | Native `net.netfilter.nf_conntrack_max` and protocol-specific conntrack sysctls |
| Backend hardware capacity | Current bounded 64-direction implementation; no invented sysctl or live resize guarantee |
| Owner and observe mode | Explicit boot selection / immutable provider parameters |
| CMM logging and CLI listener | Retired with the daemon; CLI errors, Linux diagnostics and backend counters replace them |
| VLAN, tunnel, Wi-Fi and asymmetric feature settings | Feature-specific future increments; unsupported traffic continues through Linux |

Use normal persistent Linux sysctl configuration for native scalar settings.
There is no need to duplicate those controls in the policy file or send them
through FCI. A Linux conntrack capacity setting does not resize CDX hardware.
Existing hardware lifetime changes should be applied across a policy stop/apply
boundary when immediate retirement is required. IPv6, further NAT types,
PPPoE, bridge/VLAN, multicast, IPsec and tunnel acceleration need their own
feature increments.
