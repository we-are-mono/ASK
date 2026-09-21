# Linux flowtable policy

`ask-flowtable` manages admission policy for the native IPv4/IPv6 TCP/UDP
backend. Linux still owns connection tracking, routing, firewall decisions and
flow lifetimes. CDX supplies the hardware implementation. Select ownership at
boot with `ask.offload=flowtable`; this tool cannot change the owner.

See the [project overview](linux-flowtable-offload.md) for supported scope and
the [architecture](flowtable-architecture.md) for provider and lifetime contracts.

The installed `/etc/ask/offload.conf` enables eligible traffic across the up
CDX ports, excluding FTP, SIP and PPTP control channels. If this default file
is absent, the daemon uses the same built-in policy. A missing file explicitly
selected at another path is an error. CMM is not involved in this control path.

The file uses one directive per line; `#` begins a comment. Publish edits
atomically, validate them and inspect the rules. The running daemon notices
configuration and backend changes automatically while it has control:

```sh
ask-flowtable check
ask-flowtable render
ask-flowtable resume
ask-flowtable status
```

`render` requires an enabled policy. `check`, `render` and `apply` accept
`--config /path/to/candidate.conf`. Applying a candidate does not write the
persistent configuration file. `resume` takes no configuration argument: it
returns authority to the running daemon's configuration, normally
`/etc/ask/offload.conf`, or the path supplied to `daemon --config`.

An example confined to a routed, non-NAT peer pair is:

```text
enabled yes
devices eth3 eth4
scope 192.0.2.10 -> 198.51.100.20
exclude tcp 21
exclude udp 5060
exclude tcp 1723
```

Each scope or exclusion line combines its selectors with AND. Repeated lines
are alternatives. Exclusions take precedence over scope. `scope any` permits
any otherwise eligible connection. An enabled policy needs a scope, and an
empty exclusion is rejected. Names are metadata.

| Selector | Meaning |
| --- | --- |
| `proto` | `tcp` or `udp`; the protocol alone is also shorthand |
| `saddr`, `daddr` | Original conntrack tuple's IPv4 address or network prefix |
| `reply-saddr`, `reply-daddr` | Reply conntrack tuple's IPv4 address or prefix |
| `sport`, `dport` | Original tuple's port |
| `reply-sport`, `reply-dport` | Reply tuple's port |
| `port` | Any of the four tuple ports; expands to four alternatives |
| `mark` | Conntrack mark as `value/mask`, for example `0x0/0xff` |
| `name` | Optional label; quote text containing spaces |

Ports accept an integer from 1 to 65535 or a range such as `1000-2000`.
Prefixes must have their host bits clear. Unknown directives, duplicate scalar
keys, invalid values and configurations over 64 KiB are rejected. Scope and
exclusion lists each permit at most 256 lines. There is no arbitrary nftables
text in this format.

Admission requires established original-direction IPv4/IPv6 TCP/UDP traffic
and a conntrack mark with no bits outside the backend's allowed QoS mask.
Address selectors currently express IPv4 matches; `scope any` includes both
families. Routed TCP/UDP, source NAT (static or MASQUERADE), destination NAT and
combined/hairpin NAT are eligible within the adapter's physical-port contract. Linux additionally refuses helper and sequence-adjusted connections. See the
[NAT contract](flowtable-nat.md) for mapping and reply-tuple semantics. Mark
selectors cannot broaden the backend's admission contract. This tool creates no routes, firewall permissions,
NAT exemptions, helpers or feature-specific acceleration.

## Automatic recovery and manual control

The daemon checks desired policy, table ownership and backend health every
five seconds. Interface/address events can bring a check forward. Failed
checks or transactions retry after 1, 2, 4, 8, 16 and then at most 30 seconds
between attempts. Continuous events cannot postpone a due check or defeat
backoff. Healthy matching tables are left intact. Missing owned tables,
incorrect binding counts and global invalidation trigger the existing
drain/install/verify transaction even if the desired policy hash is unchanged.

| Command | Authority and effect |
| --- | --- |
| `daemon` | Maintain its configured policy unless reconciliation is paused. |
| `stop` | Pause automatic reconciliation before removing the owned table and draining hardware. Works even with malformed configuration. A failed drain returns an error and leaves reconciliation paused. |
| `apply [--config PATH]` | Validate a candidate, take manual control, and apply it once. Once the transaction starts, reconciliation stays paused on success or failure. Parse/load failures leave existing authority unchanged. |
| `resume` | Release the pause under the transaction lock. The running daemon subsequently validates and reconciles its own configured policy. This command does not install a candidate, start the daemon, or certify recovery; observe `status` and traffic. |
| `status` | Report table/backend state and `reconciliation_paused`. A manually installed table can have healthy admission while reconciliation is paused. |

Manual control is recorded in `/run/lock/ask-flowtable.paused`, protected by
the same `/run/lock/ask-flowtable.lock` as every table transaction. A stop
waiting behind an install takes effect after it, and later checks cannot
undo that stop. The pause survives daemon and service process restarts; it
expires on reboot with `/run`. For a persistent disable, set `enabled no`.

Service `start` and `restart` preserve the pause. Service `stop` pauses and
drains, propagating failure to its caller. Service `reload` explicitly resumes
and starts the daemon if necessary. A fresh boot starts automatic maintenance
of the configured policy. Hung `nft` operations are cancelled and retried;
restarting a crashed daemon still requires process supervision, which remains
outstanding.

One-shot custom policies remain under manual control so the daemon cannot
overwrite a temporary or more restrictive policy with its default. To make a
policy automatically maintained, publish it to the daemon's configuration
file and resume. The daemon never resumes by following a temporary candidate
file that may have disappeared.

See the [resilience test plan](flowtable-resilience.md) for fault coverage and
the distinction between safe degradation and autonomous restoration.

## Firewall ordering and revocation

The controller owns only `table inet ask_flowtable`. Its forward admission
chain has priority **10**. All forward firewall chains that decide whether a
connection is permitted must execute before that priority, for example the
standard priority 0 filter chain. Audit this ordering when integrating another
firewall manager. Hardware packets subsequently bypass the forwarding hooks,
as Linux flowtable caching requires.

To revoke a cached flow after a firewall change, stop acceleration and require
that stop to succeed, apply the firewall changes, publish the intended daemon
policy and resume. Use a one-shot apply to remain under manual control instead.
For an exclusion
change, `ask-flowtable apply` performs the retirement itself. Editing unrelated
nftables rules does not revoke cached hardware. A configuration-file edit is
eventually reconciled, not an immediate revocation boundary; use stop for
coordinated firewall maintenance.
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

Concurrent controller calls serialize on `/run/lock/ask-flowtable.lock`. Each
`nft` invocation has a five-second monotonic deadline covering input, output
and process exit. A guardian owns the child and inherited lease, and cancels
the whole job on timeout or controller death, including adopted descendants
that leave the original process group. Cleanup retains the lease until all
writers have exited, so an older transaction cannot commit after a newer
controller takes ownership. The caller waits at most one additional second
for cleanup. An unkillable kernel task keeps the lease and blocks replacement;
a timeout cannot establish that a transaction did not commit.

After a failed invocation the transaction ends. The next reconciliation
inspects actual table and backend state, preserving an already committed,
healthy policy when its reply was lost. Truncated output or failed inspection
never proves absence. This Linux implementation requires `close_range` and
uses `/proc/thread-self/children` (`CONFIG_CHECKPOINT_RESTORE`) to find detached
descendants; the ASK image provides both. If descendant enumeration fails,
cleanup retains the lease while any child remains.

If interrupted between drain
and installation, forwarding remains in software. If interrupted after commit,
the table's hash exposes the committed policy. The daemon reconciles either
case when it retains automatic authority; a manual transaction remains paused
until explicit apply/resume. A table with the same name but no controller marker,
or backend bindings owned by another table, is refused.

`status` reports `policy_installed`, `policy_hash`, `admission_ready` and the
backend counters. A present policy does not establish active hardware traffic.
Use directional hardware counters, software interface TX counters and CPU
measurements to prove execution. Global invalidation may leave the policy
installed while admission is stopped. The daemon performs a full transaction
to recover it automatically; under manual control, applying it again performs
that boundary. Fatal hardware retirement still requires a fresh boot.

## Carrying useful CMM settings forward

| Existing responsibility | Linux replacement |
| --- | --- |
| Fastforward protocol, tuple address/port exclusions | `exclude` selectors above; original/reply directions keep conntrack semantics |
| CMM `port` shortcut | `port`, preserving its four tuple-port alternatives |
| CMM `ip_v4_addr` shortcut | Four exclusion objects, one per original/reply address selector |
| Global acceleration enable/disable | `enabled` and `apply`/`stop` |
| Hardware UDP/TCP inactivity policy | Linux `net.netfilter.nf_flowtable_udp_timeout` / `nf_flowtable_tcp_timeout`; verify hardware behaviour when changing lifetime policy |
| Connection table limits and protocol state timeouts | Native `net.netfilter.nf_conntrack_max` and protocol-specific conntrack sysctls |
| Backend hardware capacity | 32,768-direction admission budget; see [capacity](flowtable-capacity.md); no live resize guarantee |
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
