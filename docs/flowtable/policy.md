# Linux flowtable policy

`ask-flowtable` manages admission policy for the native IPv4/IPv6 TCP/UDP
backend, and the global on/off of multicast acceleration beside it. Linux
still owns connection tracking, routing, firewall decisions and flow
lifetimes. CDX supplies the hardware implementation; the flowtable adapter is
its only hardware flow owner.

See the [project overview](README.md) for supported scope and
the [architecture](architecture.md) for provider and lifetime contracts.

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
[NAT contract](nat.md) for mapping and reply-tuple semantics. Mark
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
A change in the ports `devices auto` finds up is made to the live table
instead; see [device membership](#device-membership).

| Command | Authority and effect |
| --- | --- |
| `daemon` | Maintain its configured policy in the foreground unless reconciliation is paused. A lifetime lock permits only one controller. |
| `supervise` | Run the foreground supervisor, replacing a crashed controller with capped backoff. |
| `stop` | Pause automatic reconciliation, switch multicast acceleration off, remove the owned table and drain hardware -- unicast entries and both multicast learners' groups. Works even with malformed configuration. A failed drain returns an error and leaves reconciliation paused. |
| `apply [--config PATH]` | Validate a candidate, take manual control, and apply it once. An enabled candidate switches multicast acceleration on; `enabled no` switches it off and drains it with the rest. Once the transaction starts, reconciliation stays paused on success or failure. Parse/load failures leave existing authority unchanged. |
| `resume` | Release the pause under the transaction lock. The running daemon subsequently validates and reconciles its own configured policy, multicast switch included. This command does not install a candidate, start the daemon, or certify recovery; observe `status` and traffic. |
| `status` | Report table/backend state, the multicast switch and both learners' installed groups (`mcast_enabled`, `mcast_installed`, `mroute_installed`), and `reconciliation_paused`. A manually installed table can have healthy admission while reconciliation is paused. |

Manual control is recorded in `/run/lock/ask-flowtable.paused`, protected by
the same `/run/lock/ask-flowtable.lock` as every table transaction. A stop
waiting behind an install takes effect after it, and later checks cannot
undo that stop. The pause survives daemon and service process restarts; it
expires on reboot with `/run`. For a persistent disable, set `enabled no`,
which the daemon reasserts for multicast at every check.

The multicast switch is the adapter's `multicast` parameter
(`/sys/module/ask_flowtable/parameters/multicast`), on at load. The service
owns it while it runs: an enabled policy sets it on at every check, so a
manual write does not last. Reloading the adapter module puts it back on; while
the service is stopped or paused nothing switches it off again, so stop again
after such a reload.

Service `start` and `restart` preserve the pause. Service `stop` pauses and
drains, multicast included, propagating failure to its caller. Service
`reload` explicitly resumes and starts the daemon if necessary. A fresh boot
starts automatic maintenance of the configured policy. Hung `nft` operations
are cancelled and retried.

The boot service now runs a supervisor. An unexpected controller exit, including
exit status zero, restarts after 1, 2, 4, 8, 16 and then 30 seconds. A controller
that runs for at least 60 seconds resets this delay.
Crashes never clear the manual pause. Service `stop` first disables respawning
and terminates/reaps the worker, then performs the locked pause-and-drain
transaction. After two seconds of graceful shutdown it kills a stuck worker;
nft guardians retain their own cleanup and transaction leases.

The init script calls `service-start`, `service-stop` and `service-restart`.
These commands serialize lifecycle changes separately from policy transactions
and address a protected local control socket. PID files are observational:
`/var/run/ask-flowtable.pid` identifies the worker and
`/var/run/ask-flowtable-supervisor.pid` identifies its supervisor. Stale files
never authorize signalling a process. `ask-flowtable service-status` reports
the current supervisor/worker PIDs, restart count, retry delay and stopping
state; ordinary `status` continues to describe policy and backend health.

Diagnostics use best-effort nonblocking syslog delivery, with a nonblocking
console fallback for the minimal image. A stalled logger cannot block a restart.
Killing the supervisor itself kills its worker, preserving transaction safety,
but the BusyBox boot does not automatically recreate the supervisor. That needs
PID 1 supervision or an explicit service start. Platforms with an existing
service manager can instead supervise the foreground `daemon` directly.

One-shot custom policies remain under manual control so the daemon cannot
overwrite a temporary or more restrictive policy with its default. To make a
policy automatically maintained, publish it to the daemon's configuration
file and resume. The daemon never resumes by following a temporary candidate
file that may have disappeared.

See the [resilience test plan](resilience.md) for fault coverage and
the distinction between safe degradation and autonomous restoration.

## Device membership

`devices auto` resolves, on every check, to the CDX physical ports (driver
`fsl_dpa`) whose link is up. Which ports are up is live state, not
configuration: the policy hash, and so the table's marker, covers `auto` but
not the ports it resolved to, and `check` reports the hash the installed table
carries. When the resolved set changes, the daemon changes the live
flowtable's device list in one nft transaction, `add flowtable` for ports that
came up and `delete flowtable` for ports that went down, without deleting the
table or draining the hardware. Ports that stay keep their bindings and their
hardware flows; the adapter binds or unbinds only the ports the update names.
The result is verified as strictly as a replacement: marker, device list, one
binding per device, no invalidation. If the update fails or does not verify,
the same check falls back to the drain/install/verify transaction.

If fewer than two ports are up while a healthy table stands, the table is kept
as it is, with one notice and no retries. Two is the smallest set a policy may
name, a bound port without carrier costs nothing, and a returning port finds
the table already right. With no table, or an unhealthy one, fewer than two
ports is an error that is retried until a second port is up; the old table
stays in place meanwhile.

Only the daemon follows ports, and only while it holds automatic control. A
manual `apply` always performs the full transaction. An explicit device list
is configuration: changing it is a new policy, and the table is replaced.
`status` reports the installed flowtable's `devices`.

## Firewall ordering and revocation

The controller owns only `table inet ask_flowtable`. Its forward admission
chain has priority **10**. All forward firewall chains that decide whether a
connection is permitted must execute before that priority, for example the
standard priority 0 filter chain. Audit this ordering when integrating another
firewall manager. Hardware packets subsequently bypass the forwarding hooks,
as Linux flowtable caching requires.

To revoke a cached flow after a firewall change, stop acceleration and require
that stop to succeed, apply the firewall changes, publish the intended daemon
policy and resume. The stop covers multicast: bridged and routed groups leave
hardware before it returns and stay in software, still learned, until an
enabled policy is applied again (see
[the global switch](multicast.md)). Use a one-shot apply to remain under manual
control instead.
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
policy untouched. A kernel rejection after retirement leaves flowtable
acceleration disabled and reports an error; it does not restore an obsolete
exclusion policy. Multicast stays on, since the policy asks for acceleration.
Disabling the policy drains multicast too: the switch goes off first and the
drain also waits for `mcast_installed` and `mroute_installed`.
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

`status` reports `policy_installed`, `policy_hash`, `devices`, `admission_ready`
and the backend counters. A present policy does not establish active hardware traffic.
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
| Global acceleration enable/disable | `enabled` and `apply`/`stop`, for unicast and multicast alike |
| Hardware UDP/TCP inactivity policy | Linux `net.netfilter.nf_flowtable_udp_timeout` / `nf_flowtable_tcp_timeout`; verify hardware behaviour when changing lifetime policy |
| Connection table limits and protocol state timeouts | Native `net.netfilter.nf_conntrack_max` and protocol-specific conntrack sysctls |
| Backend hardware capacity | 32,768-direction admission budget; see [capacity](capacity.md); no live resize guarantee |
| Observe mode | `ask.flowtable_observe=1` boot parameter / immutable provider parameter |
| CMM logging and CLI listener | Retired with the daemon; CLI errors, Linux diagnostics and backend counters replace them |
| VLAN, tunnel, Wi-Fi and asymmetric feature settings | Feature-specific future increments; unsupported traffic continues through Linux |

Use normal persistent Linux sysctl configuration for native scalar settings.
There is no need to duplicate those controls in the policy file or send them
through FCI. A Linux conntrack capacity setting does not resize CDX hardware.
Existing hardware lifetime changes should be applied across a policy stop/apply
boundary when immediate retirement is required. IPv6, NAT, PPPoE,
bridge/VLAN, multicast, IPsec and tunnel acceleration each have their own
document under [the project overview](README.md).
