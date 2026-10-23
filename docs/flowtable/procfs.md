# The adapter's procfs surface

`ask_flowtable` reports what it has put in the hardware, and why it refused
the rest, through one procfs directory, `/proc/ask_flowtable/`. It replaces
the single file `/proc/cdx_flowtable`, which mixed about 120 scalars with
seven kinds of rows in one stream and rendered all of it under CDX's
transaction on every read.

```
/proc/ask_flowtable/
  status    levels and latches: what the backend holds now      transaction
  stats     events since the module loaded: only ever grows     none
  devices   one row per VLAN, PPPoE session and tunnel device   transaction
  flows     one row per routed unicast direction                transaction, per buffer
  l2        one row per bridged unicast station pair            transaction, per buffer
  mcast     one row per bridged multicast flow or membership    transaction + ft_mc_lock
  mroute    one row per routed multicast group                  transaction + ft_mr_lock
```

All seven are mode 0400, created when the module loads and removed before it
unloads.

## Rules

1. **The standard tool comes first.** Offloaded state shows up where an
   operator already looks: `conntrack -L` for flows, `ip -s link` for ports,
   VLAN, ppp and tunnel devices, `bridge mdb show` and `ip -s mroute` for
   multicast, and `ip -s xfrm state` for SAs. `/proc/ask_flowtable/` is the
   diagnostic that sits beside those tools. It holds what they cannot show:
   admission state, refusal reasons, hardware record slots, and the
   adapter's own event counts.
2. **Levels and events live in separate files**, as `/proc/meminfo` and
   `/proc/vmstat` are separate. `status` says what is true now and can go
   down. `stats` only grows. A consumer polling for a condition reads
   `status`. A consumer taking deltas reads `stats`.
3. **One kind of row per file.** A file that would mix row kinds is split. The
   exception is `devices`, whose three kinds are all "a logical device whose
   encapsulation the hardware carries". There, the leading tag tells them
   apart.
4. **A module parameter is read from sysfs, never repeated here.** The old
   header repeated six of them. They are gone from procfs, and readers take
   them from `/sys/module/*/parameters/`:

   | Old key | Now read from |
   |---|---|
   | `observe` | `/sys/module/cdx/parameters/flowtable_observe` (`Y`/`N`) |
   | `transit` | `/sys/module/cdx/parameters/transit` (`Y`/`N`) |
   | `mcast_enabled` | `/sys/module/ask_flowtable/parameters/multicast` (`Y`/`N`) |
   | `qos_mark_mask` | `/sys/module/ask_flowtable/parameters/qos_mark_mask` |
   | `qos_default_class` | `/sys/module/ask_flowtable/parameters/qos_default_class` |
   | `route_mark_mask` | `/sys/module/ask_flowtable/parameters/route_mark_mask` |

   A value that is *derived* from a parameter and from state stays in
   `status`. Examples: `l2_enabled` is the parameter *and* the bridge hook
   being registered; `detour` is the parameter *and* the offline port being
   up.
5. **The module that owns the state owns the directory.** `ask_flowtable`
   reloads and `cdx` is load-once, so the adapter's directory belongs to the
   adapter and to nothing else. It is a top-level entry, not under
   `/proc/net/`. The test shell runs in a network namespace, and a
   `/proc/net/` entry would show that namespace's view.
6. **Unprefixed keys belong to routed unicast**, the flowtable proper. Every
   other feature's keys carry its prefix: `ipsec_`, `mcast_`, `mroute_`,
   `l2_`, `detour_`, `qos_`, `wifi_`, and the per-kind `session_`, `vlan_`
   and `tunnel_`. The old header already followed this rule, so no key is
   renamed.

## Format

### `status` and `stats`

These use one `key:` and a value per line, laid out like `/proc/meminfo`. The
name and its colon are padded to 36 columns, and the value is right-aligned
in the next 12:

```
entries:                                      12
max_entries:                               32768
bindings:                                      2
fatal:                                         0
```

The values are unsigned decimal integers. A boolean is `0` or `1`. Keys are
at most 34 characters long, so at least one space always separates the
colon from the value, and a value wider than 12 digits simply runs on.
Parse each line by splitting at the first colon:

```python
state = {k: int(v) for k, v in (line.split(":", 1) for line in text.splitlines())}
```

```c
sscanf(line, "%63[^:]: %llu", key, &value);
```

### Row files

These are one record per line: a tag word, then whitespace-separated
`key=value` fields, in the style of `/proc/net/nf_conntrack`. No value
contains whitespace, so `"-"` stands for none. Readers should look fields
up by key, not by position. The tag stays on every line, even in files that
hold one kind, so a line still says what it is once it has been grepped or
pasted on its own.

## Inventory: what can be offloaded and where it is reported

| Offload | Hardware object | Standard tool | `/proc/ask_flowtable/` |
|---|---|---|---|
| Routed unicast IPv4/IPv6 TCP/UDP, including SNAT, MASQUERADE, DNAT, hairpin and IPv6 NAT | one classifier entry per direction | `conntrack -L` (`[HW_OFFLOAD]`, accounting), `/proc/net/stat/nf_flowtable` | `flows` rows; core keys in `status` and `stats` |
| Transit ESP, GRE, IPIP and 6in4, untranslated | the same entry, protocol 50/47/4/41 | `conntrack -L` | `flows` rows |
| 802.1Q VLAN, up to two tags per direction | strip/insert opcodes and a plain stats record per VLAN device | `ip -s link show <vlan>` (folded) | `devices` `vlan` rows; `vlan_records`/`vlan_slots` in `status`; `in_vlan=`/`out_vlan=` on `flows` |
| PPPoE session | strip/insert opcodes and a timestamped record per ppp device | `ip -s link show ppp0` (folded); `/proc/net/pppoe` | `devices` `session` rows; `session_records`/`session_slots`; `in_ppp=`/`out_ppp=` |
| 6in4/4in6 tunnel hop | L3 insert/strip and a plain record per tunnel device | `ip -s link show <tunnel>` (folded) | `devices` `tunnel` rows; `tunnel_records`/`tunnel_slots`; `in_tnl=`/`out_tnl=` |
| Routed through a bridge | fields of the routed entry | none: the bridge device keeps no offloaded counter (see gaps) | `in_br=`/`out_br=` on `flows` |
| Bridged unicast between two ports | an Ethernet-table entry per direction of a station pair | none: `bridge fdb` has no offload flag for it (see gaps) | `l2` rows; `l2_*` in `status` and `stats` |
| Bridged multicast `(S,G)` | a multicast group with its listener chain | `bridge mdb show` (`offload`) | `mcast` rows; `mcast_*` in `status` and `stats` |
| Routed multicast (MFC) | the same encoder | `ip mroute show` (`offload`), `ip -s mroute` (folded on every read of `mroute`) | `mroute` rows; `mroute_*` |
| IPsec ESP packet offload | SEC descriptor and classifier entry per SA | `ip -s xfrm state` (`curlft` folded); `/proc/net/xfrm_stat` on kernels with `CONFIG_XFRM_STATISTICS` | `ipsec_sas`/`ipsec_sa_cache` in `status`; `ipsec_*` refusal counts in `stats`; `sa=`/`in_sa=` on `flows` |
| Wi-Fi VAP | VWD registration on an offline port | `/sys/class/vwd/vwd0/<ifname>` (cdx) | `wifi_vaps` in `status`; `wifi_refused` in `stats` |
| Offline-port detour (IPv4 UDP larger than the path) | offline port | none | `detour`, `detour_flows` in `status`; `detour_*` in `stats`; `detour=` on `flows` |
| QoS: mark to class, DSCP remark, HTB/CEETM, policers | a class field on the entry, the CEETM tree | `tc -s class show`, `tc -s filter show`, `ethtool -S` | `qos=` on `flows`; `qos_*` in `stats` |

Two candidates were considered for rows and rejected, each because a standard
door already shows the same thing:

- **Per-SA rows.** `ip -s xfrm state` lists every offloaded SA with
  its traffic. The flow rows' `sa=` and `in_sa=` are non-zero exactly when a
  direction is encrypted or decrypted, which is all their consumers ask.
- **Per-VAP rows.** The cdx file `/sys/class/vwd/vwd0/<ifname>` appears only
  for a VAP whose registration succeeded. `wifi_vaps` is the count to compare
  it with.

## `status`

Read under CDX's transaction, which several of these values require. The
file is a fixed set of lines with no walk over flows or groups, so the hold
is short. This is the file the controller's health probe and its drain wait
read.

| Key | Meaning |
|---|---|
| `entries` | directions in the hardware |
| `max_entries` | the admission bound, 32,768 directions |
| `bindings` | flowtables bound to the backend |
| `passive` | bound devices whose flows stay in software |
| `parked` | bindings parked behind an invalidation |
| `neighbour_refs`, `handle_refs` | references the entries hold |
| `invalidated` | the global invalidation latch (a lazy latch: `1` at idle is normal) |
| `invalidation_done` | the invalidation has finished its work |
| `fatal` | CDX's latch after a deletion it could not prove |
| `quarantine` | retirements waiting on a barrier or on CDX's proof |
| `owed` | retirements owed only a barrier |
| `rearm_ready` | admission may be rearmed |
| `bypassed` | the classifier ports run past the classifier, forwarding in software |
| `restarts`, `resume_failures` | datapath restarts, and ports one could not start again |
| `ipsec_sas`, `ipsec_sa_cache` | SAs the adapter installed; SAs CDX's cache holds |
| `stats_retained`, `stats_deferred` | device records held back from the pool, and how often a release has had to wait |
| `session_records`, `session_slots`, `vlan_records`, `vlan_slots`, `tunnel_records`, `tunnel_slots` | device records of each kind, and how many of them have a hardware counter slot |
| `detour`, `detour_flows` | the offline-port detour is up; the directions it carries |
| `mcast_hooked`, `mcast_groups`, `mcast_flows`, `mcast_installed`, `mcast_discarding`, `mcast_parked` | the bridged learner's hook, memberships, flows and what is in hardware |
| `mcast_group_ids4`, `mcast_group_ids6`, `mcast_group_id_slots` | group ids held per family, and how many each family has |
| `mroute_groups`, `mroute_installed`, `mroute_policy_rules`, `mroute_ruleset_settled` | the routed learner's groups, what is in hardware, and the policy rules and ruleset state that hold groups back |
| `l2_enabled`, `l2_entries`, `l2_hook_kinds`, `l2_confirming` | bridged unicast switching: active, pairs in hardware, the other bridge hooks present, whether frames confirm pairs |
| `wifi_vaps` | VAPs registered |

`restarts`, `resume_failures` and `stats_deferred` are counts, but they are
read through CDX accessors that require the transaction. They describe the
latch machinery, which is what `status` is about, so they belong here and not
in `stats`.

## `stats`

Read without the transaction. Every value is a counter that only grows while
the module is loaded. The reader loads each one with `READ_ONCE()` or
`atomic64_read()`, while the writers increment them under their own locks.

| Group | Keys |
|---|---|
| admission | `installs`, `deletes`, `rejects`, `errors`, `validated`, `busy`, `rearms`, `finals`, `destroy_deferrals` |
| counter reports | `stats_passes` (counter passes that reached every entry), `stats_requests` (Netfilter's own requests for a flow's counters, which a pass keeps it from making) |
| retirement causes | `neighbour_invalidations`, `route_invalidations`, `mtu_invalidations`, `link_invalidations`, `mac_invalidations`, `fdb_invalidations`, `stp_invalidations`, `qos_invalidations`, `admission_invalidations`, `ipsec_invalidations`, `ipsec_policy_invalidations`, `ipsec_next_hop_updates` |
| QoS | `qos_remark_failures`, `qos_control_overruns` |
| IPsec | `ipsec_sec_refused` and `ipsec_sec_refused_<class>` for each class in `ft_sec_refusal[]`; `ipsec_offline_port_rejected`, `ipsec_sec_input_refused` |
| detour | `detour_delivered`, `detour_unknown`, `detour_failed`, `detour_errors` |
| bridged multicast | `mcast_refused`, `mcast_install_errors`, `mcast_observed`, `mcast_dropped`, `mcast_hook_errors`, `mcast_deferred`, `mcast_passes`, `mcast_forgets`, `mcast_port_probe_errors`, `mcast_discards_evicted`, `mcast_egress_rebuilds` |
| routed multicast | `mroute_refused`, `mroute_install_errors`, `mroute_lost`, `mroute_capped`, `mroute_xfrm_changes`, `mroute_ruleset_changes`, `mroute_confirm_errors`, `mroute_port_probe_errors`, `mroute_xtables_changes` |
| bridged unicast | `l2_installs`, `l2_refused`, `l2_held`, `l2_retired`, `l2_dropped`, `l2_deferred`, `l2_unconfirmed`, `l2_ruleset_changes` |
| Wi-Fi | `wifi_refused` |

## Row files

The fields are the ones `/proc/cdx_flowtable` carried. Only where each kind
lives has changed.

- **`flows`**: `flow cookie= in= out= in_vlan= out_vlan= in_br= out_br=
  in_ppp= out_ppp= in_tnl= out_tnl= family= src= dst= new_src= new_dst=
  proto= mtu= qos= sa= in_sa= detour= nexthop= packets= bytes= lastused=`.
  - The file is paged by cookie-hash bucket. Each read holds the transaction
    for one buffer and resumes by bucket and offset, so a full read at
    capacity runs to several megabytes without one long hold.
- **`l2`**: `l2flow in= out= port_in= port_out= br= dst= src= type= vid=
  tagged= in_vlan= out_vlan= packets= bytes=`.
  - Paged the same way, by pair-hash bucket.
- **`devices`**: three row kinds, all joinable on the flow rows.
  - `session dev= ifindex= pppoe= lower= refs= slot= rx_packets= rx_bytes=
    tx_packets= tx_bytes=` joins on `in_ppp`/`out_ppp`.
  - `vlan dev= ifindex= refs= slot= rx_*= tx_*=`.
  - `tunnel dev= ifindex= tnl= lower= refs= slot= rx_*= tx_*=` joins on
    `in_tnl`/`out_tnl`.
  - The counts are the firmware's whole-frame totals. `ip -s link` shows the
    same records restated in the device's units.
- **`mcast`**: `mcast br= family= group= member_src= src= vid= ports= routed=
  in= in_vid= smac= dmac= state= packets= bytes=`.
  - One row per learned flow, and one per membership no flow speaks for yet.
- **`mroute`**: `mroute family= table= group= src= in= oifs= listeners=
  state= unconfirmed= adds= packets= bytes=`.
  - A read folds each group's hardware count into the MFC, so `ip -s mroute`
    and this file agree. A reader who wants `ip -s mroute` exact reads this
    file first.

`mcast` and `mroute` are each rendered as one record. Their buffer is sized
up front from the learners' counts (`single_open_size()`), so a read at the
caps renders once rather than once per buffer doubling.

## What changed for readers

- **The controller (`flowtable/src`)** reads `status` and `stats`, and its
  parameters from sysfs.
  - Every key it uses is now required. A missing one fails the read, where
    before `entries` and the two masks quietly defaulted to zero and let a
    drain pass.
  - Its JSON is unchanged.
- **The test agent (`tools/askd_agent/observe.py`)**:
  - A `summary` reads `status` and `stats`, as the health probe does: one
    short hold of the transaction.
  - A `state` adds every row file.
  - A snapshot streams `flows` into SQLite and parses the other files into
    its header, as before.
  - Both carry the six module parameters too, read from sysfs under their
    old key names. The test harness polls one place, and procfs still
    repeats nothing.
- **The rig helpers (`tools/tests/_flowtable_rig.py`)**:
  - `status_text()` parses both line forms.
  - `PROC` and `proc_paths()` name the files, so a test reads exactly what it
    needs.
- **Consistency checks that compare a level with a row count** read the two
  files back to back:
  - `entries` with the flow rows;
  - `l2_entries` with the `l2` rows.
  
  They already ran at rest. A full read was never a single snapshot, because
  every buffer was a transaction of its own.

## Other ASK procfs files (not changed here)

CDX owns a few procfs files of its own. None of them is offload state.

| File | What it is | Recommendation |
|---|---|---|
| `/proc/cdx_pcd_schemes` | KeyGen scheme hit counts | keep; a later cleanup could move CDX's files under a `/proc/cdx/` directory of their own |
| `/proc/fqid_stats/{tx,rx,pcd,sa}/…` | per-frame-queue QMan dumps, from NXP | keep; the IPsec tests address `sa/<in_sa>` |
| `/proc/ucode_frag/stats` | microcode fragmentation counters | keep |
| `/proc/ucode_frag/test_alloc_buf_n_free` | a test hook that runs 128 BMan acquire/release cycles per read, **built into production** | remove from production builds, or gate it like the other hooks |
| `/proc/cdx/last_freed_key`, `/proc/cdx_split_key_fail`, `/proc/cdx_mc_hcsync_fail` | test-image hooks (`CDX_DEBUG_*`) | candidates for debugfs, where fault injection belongs |

## Known gaps this layout does not close

- **A bridge device keeps no offloaded counter.** `ip -s link show br-lan`
  misses traffic the hardware routed through the bridge; the physical ports
  count it ([statistics](statistics.md#what-is-not-carried-and-why)).
- **Bridged unicast pairs set no `offload` flag in `bridge fdb`.** The `l2`
  file is the only place a pair shows.
