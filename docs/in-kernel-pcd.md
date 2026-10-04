# In-kernel PCD construction

`cdx` builds the FMan Parse-Classify-Police-Distribute configuration itself, in
`module_init`, with no userspace step. [`cdx/cdx_pcd_desc.c`](../cdx/cdx_pcd_desc.c)
describes the classification groups, [`cdx/cdx_pcd_ports.c`](../cdx/cdx_pcd_ports.c)
discovers the ports, and [`cdx/cdx_pcd.c`](../cdx/cdx_pcd.c) programs them.
[`cdx/dpa_cfg.c`](../cdx/dpa_cfg.c)'s `dpa_cfg_install()` drives that and then
brings up everything hanging off it — interface records, frame queues, policer
profiles and table miss actions.

## What the PCD contains

| Object | Count |
| --- | --- |
| FMan engines | 1 |
| Ports | 7 on gateway-dk (3×1G, 2×10G, 2×OFFLINE) |
| KeyGen schemes | 25: 18 shared-policy schemes and 7 SEC schemes |
| Hash tables | 91: 14 groups × 6 ports, plus 7 SEC groups |
| Network environments | 2: shared and SEC |
| CC root trees | 7, one per port |
| Prefilled hash entries | 0 — keys are added at runtime |

Schemes are shared by ports using the same policy to fit the KeyGen limit of
32. Each scheme selects a group in the receiving port's own CC root tree.
Its `h_CcTree` names the first port using that policy.

The shared policy serves the Ethernet ports and the Wi-Fi offline port:

| Group | Table | Key size | Hash mask |
| --- | --- | --- | --- |
| 0 | `cdx_ethernet_cc` | 15 | 0x00ff |
| 1 | `cdx_pppoe_cc` | 11 | 0x000f |
| 2 | `cdx_tuple3udp6_cc` | 20 | 0x00ff |
| 3 | `cdx_tuple3udp4_cc` | 8 | 0x00ff |
| 4 | `cdx_bridged_mcast6_cc` | 46 | 0x00ff |
| 5 | `cdx_bridged_mcast4_cc` | 22 | 0x00ff |
| 6 | `cdx_multicast6_cc` | 34 | 0x00ff |
| 7 | `cdx_multicast4_cc` | 10 | 0x00ff |
| 8 | `cdx_tcp6_cc` | 55 | 0x7fff |
| 9 | `cdx_udp6_cc` | 55 | 0x7fff |
| 10 | `cdx_tcp4_cc` | 56 | 0x7fff |
| 11 | `cdx_udp4_cc` | 56 | 0x7fff |
| 12 | `cdx_esp6_cc` | 22 | 0x00ff |
| 13 | `cdx_esp4_cc` | 10 | 0x00ff |

The SEC offline port (`dpa-fman0-oh@2`, cell-index 1, logical port 9) has its
own seven groups: Ethernet, TCP6, UDP6, TCP4, UDP4, ESP6 and ESP4. Its TCP/UDP
keys retain the original sizes of 38 bytes for IPv6 and 14 for IPv4. Its network
environment omits PPPoE. The builder rejects a logical-port override that would
make this port disagree with the soft parser's SEC test.

### Changes carried over from the XML loader

The flowtable branch added bridged multicast tables, SEC-specific classification,
and soft-parser fixes for PPPoE and VLAN frames on the SEC path. These are now
represented in the kernel descriptors and the regenerated soft-parser bytecode
(670 bytes, eight labels).

The former loader also changed FMC's model in C, after compiling the XML.
`cdx_pcd_tunnel_key()` preserves those changes: shared TCP/UDP keys include outer
header fields to distinguish tunnel receive identities. Four extra PPPoE schemes
use the peer MAC and session ID in the same tables. Missing generic fields use
a zero default. Port metadata publishes these additional schemes too.

Bridged multicast tables use CDX's distinct bridged lookup types, while their
hardware table classes remain the IPv4/IPv6 multicast classes understood by
the microcode.

### Scheme priority

`relativeSchemeId` controls KeyGen match order: the lowest ID wins. Within each
policy, creation walks groups from ESP back to Ethernet. Each PPPoE TCP/UDP
scheme immediately precedes its native counterpart. This keeps the Ethernet
catch-all below the more specific schemes. The host comparison checks priorities
and each port's complete scheme list.

## Board configuration

Nothing about the port set is board-specific input the kernel does not already
have:

| Value | Source |
| --- | --- |
| which ports participate | DPAA netdevs (ethernet) and the `fsl,dpa-oh` registry `oh_port_probe()` fills (offline) |
| port number | DT `cell-index` |
| logical port id | formula over SoC port counts, below |

Ethernet ports come from walking `init_net` for netdevs whose parent binding is
`fsl,dpa-ethernet`, taking the port class from `mac_dev->max_speed`. Offline
ports come from `offline_port_info[][]`, which the SDK fills from the
`fsl,dpa-oh` node names; the host-command port and unbound OH ports are excluded
by construction because they carry no binding. Results are sorted by port class
then cell-index, so the port the shared schemes bind to does not depend on
interface registration order.

The logical port id is a flat index over the FMan's whole port space:

    1G  cell-index N -> N
    10G cell-index N -> FM_MAX_NUM_OF_1G_RX_PORTS + N
    OH  cell-index N -> FM_MAX_NUM_OF_1G_RX_PORTS + FM_MAX_NUM_OF_10G_RX_PORTS + N

On LS1043/LS1046 that gives 0–5 for 1G, 6–7 for 10G, 8 for OH0 (the
host-command port) and 9–15 for OH1–7. It holds without exception across all
five known `cdx_cfg.xml` variants — the four NXP references and
[`config/pcd/cdx_cfg.xml`](../config/pcd/cdx_cfg.xml) — covering 40 port
entries. The bases come from the SoC integration header, so the id is
SoC-derived rather than board-derived.

The id lands in `prsParam.prsResultPrivateInfo`, which `cdx_sp.xml` reads as
`$logicalportid` and tests against 9 to identify the SEC offline path.
It is also OR'd into FQID bits 16–19 through a 4-bit mask, so a frame's queue
identifies the port it arrived on. Getting it wrong misroutes rather than
failing loudly.

### Device-tree override

A board that departs from the formula sets an optional property on the node that
already carries the `cell-index` — `&fman0 ethernet@eX000` for MACs,
`dpa-fman0-oh@N` for offline ports:

```dts
dpa-fman0-oh@2 {
	compatible = "fsl,dpa-oh";
	fsl,fman-oh-port = <&fman0_oh_0x3>;
	mono,cdx-logical-portid = <9>;   /* optional; default 8 + cell-index */
};
```

A conforming board writes no lines at all; `mono-gateway-dk.dts` needs none,
since all seven of its ports match the formula.

The `mono` vendor prefix is not registered in the kernel's
`vendor-prefixes.yaml`, although `mono,gateway-dk` and `mono,sfp-led` already
ship. Registering it is a prerequisite for open-sourcing and is independent of
this work.

## Miss actions are patched in afterwards

A table's miss action names a scheme, a scheme names a CC tree, and the tree
names the tables. No creation order has the scheme handle available when the
table is created, so `cdxdrv_set_miss_action()` patches the tables with
`FM_PCD_HashTableModifyMissNextEngine()` once everything exists.

## Startup rollback

The SDK patch now implements external-hash deletion and exports
`FM_PCD_HashTableDelete()` to modules. Failed construction detaches configured
ports and releases schemes, trees, tables and both network environments. If a
port cannot detach, its dependencies are retained and a reboot is required.
The later queue/policer setup retains the flowtable branch's rollback and port
state handling.

Normal module unload still follows master's existing lifetime: it detaches the
ports and releases CDX queues, interfaces and policers, but does not retain the
builder state needed to destroy the PCD objects. Reboot before reinstalling the
module after a successful load/unload cycle.

## The XML under `config/pcd/`

`cdx_pcd.xml`, `cdx_sp.xml` and `cdx_cfg.xml` are build-time inputs, not shipped
to the target. They remain the human-readable statement of the configuration and
the source for two generated artifacts:

- `cdx/cdx_softparse.h` — the assembled soft-parser bytecode, via
  `tools/gen_cdx_softparse.py`.
- `tools/host_tests/golden/cdx_pcd_model.json` — the expected PCD, via
  `tools/gen_cdx_pcd_golden.py`. This also reproduces the former loader's tunnel
  and PPPoE transformations, which are not expressed by the XML alone.

Two attributes in `cdx_pcd.xml` are decorative: `external="yes"` and
`aging="yes"` on `<hashtable>` are ignored by `fmc`, which warns `Unknown
attribute`. Tables become external because `FM_PCD_HashTableSet()` returns
`ExternalHashTableSet()` unconditionally under `USE_ENHANCED_EHASH`, never
consulting the `externalHash` field. `agingSupport` is likewise only read on the
internal path, which that build mode never takes.

## Checking the builder without a board

`tools/host_tests/cdx_pcd_build.py` compiles `cdx_pcd.c` and
`cdx_pcd_desc.c` unmodified on the host, replaces only the FMan entry points with
stubs that record their parameters, runs `cdx_pcd_build()`, and compares what it
programmed against `tools/host_tests/golden/cdx_pcd_model.json`. Port discovery
is stubbed with the gateway-dk port set, since it needs netdevs and the
offline-port registry.

It checks the object counts, the distinction units and their order, each CC root
tree holding its own tables in group order, every table shape, every scheme's FQ
base, unit list and extract fields (resolved to their numeric
`NET_HEADER_FIELD_*` values, not just their names), the port-id OR into FQID
bits 16–19, the per-port `prsResultPrivateInfo`, and the scheme match priority. It also fails every environment, table, tree,
scheme and port attachment in turn and checks that all created handles are
released exactly once, with each port returned to its initial enabled state.

## Regenerating the golden

`cdx/cdx_softparse.h` and `tools/host_tests/golden/cdx_pcd_model.json` are the
source of truth. `fmc` and `fmlib` are no longer built or carried: their
recipes and ASK patches were retired, and the last copies live in the
`mono-1.0.x` tags (identical in `mono-1.0.7`). A change to `config/pcd/*.xml`
that has to reach the hardware therefore means rebuilding them from there:
nxp-qoriq `fmlib` at `7a58ecaf0d90` and `fmc` at `5b9f4b16a864`, each with
`git show mono-1.0.7:patches/<fmlib|fmc>/01-mono-ask-extensions.patch` applied.

`fmc` builds in a host-only mode that links against `FMCDummyDriver.c` instead
of the ioctl shim, so the whole compile runs on the development host. Without
`--apply` it writes `fmc_config_data.c`, the complete model as C initialisers,
and `softparse.h`, the compiled soft-parser bytecode.

```sh
make -C <fmc>/source FMCHOSTMODE=1 MACHINE=ls1046 \
     FMD_USPACE_HEADER_PATH=<patched fmlib>/include/fmd
<fmc>/source/fmc -c config/pcd/cdx_cfg.xml \
     -p config/pcd/cdx_pcd.xml -s config/pcd/cdx_sp.xml \
     -d <fmc>/etc/fmc/config/hxs_pdl_v3.xml -t 0x20
tools/gen_cdx_softparse.py softparse.h cdx/cdx_softparse.h
tools/gen_cdx_pcd_golden.py fmc_config_data.c \
     tools/host_tests/golden/cdx_pcd_model.json
```

Use the patched fmlib headers, not a pristine `sources/fmlib`. The
ASK `fmc` patch added `FM_PORT_GetEnabled` calls to `fmc_exec.c` without
stubbing the symbol in `FMCDummyDriver.c`, so host mode needs that one stub
added before it links.

## The soft-parser `$ccbase` offset

`cdx_sp.xml` reaches the PPPoE relay table by a hardcoded offset from the CC
base, and its own comment warns the value must be rechecked whenever a table is
added:

```xml
<if-false>  <!-- PPPoE session packet -->
  <assign-variable name="$ccbase" value="$ccbase + 0x30"/>
```

The shared policy keeps Ethernet at group 0 and PPPoE at group 1, preserving
that offset. The SEC policy has no PPPoE table; the soft parser bypasses this
lookup on logical port 9. The host comparison checks the group layout, but
hardware traffic tests are still required after changes to parser behavior or
CC-root offsets. The flowtable PPPoE tests replace the retired CMM tests.
