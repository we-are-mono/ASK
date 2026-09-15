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
| KeyGen schemes | 12, shared by every port |
| Hash tables | 84 (12 groups × 7 ports) |
| CC nodes, policers, manipulations, replicators, VSP | 0 |
| Prefilled hash entries | 0 — every key is added at runtime |

Roughly 140 calls: one `FM_PCD_PrsLoadSw`, one
`FM_PCD_SetAdvancedOffloadSupport`, one `FM_PCD_NetEnvCharacteristicsSet`
(7 distinction units, shared by every port), 84 `FM_PCD_HashTableSet`, 7
`FM_PCD_CcRootBuild`, 12 `FM_PCD_KgSchemeSet`, a
disable/`FM_PORT_SetPCD`/enable cycle per port, and `FM_PCD_Enable`.

The twelve schemes cannot be per-port: the KeyGen has 32 and seven ports would
need 84. A scheme names a group id, and the CC root tree it dispatches into
comes from the receiving port's own `FM_PORT_SetPCD`, so one scheme serves every
port even though its `h_CcTree` names only the first.

`cdx_pcd_groups[]` is indexed by CC root group id, and port *P*'s tables are
created as `12P … 12P+11` in that order:

| grp | table | key size | hash mask |
| --- | --- | --- | --- |
| 0 | `cdx_ethernet_cc` | 15 | 0x00ff |
| 1 | `cdx_pppoe_cc` | 11 | 0x000f |
| 2 | `cdx_tuple3udp6_cc` | 20 | 0x00ff |
| 3 | `cdx_tuple3udp4_cc` | 8 | 0x00ff |
| 4 | `cdx_multicast6_cc` | 34 | 0x00ff |
| 5 | `cdx_multicast4_cc` | 10 | 0x00ff |
| 6 | `cdx_tcp6_cc` | 38 | 0x7fff |
| 7 | `cdx_udp6_cc` | 38 | 0x7fff |
| 8 | `cdx_tcp4_cc` | 14 | 0x7fff |
| 9 | `cdx_udp4_cc` | 14 | 0x7fff |
| 10 | `cdx_esp6_cc` | 22 | 0x00ff |
| 11 | `cdx_esp4_cc` | 10 | 0x00ff |

### Scheme priority is the reverse of group order

`relativeSchemeId` is the KeyGen's match order — when several schemes match a
frame, the lowest id wins. Priority runs from the most specific group to the
catch-all: ESP, then the L4 5-tuples, then the 3-tuples, then PPPoE, then
ethernet. So the builder assigns `CDX_PCD_NUM_GROUPS - 1 - grp`.

Numbering schemes by group id instead puts `cdx_ethernet_dist` at priority 0 and
the L2 bridge scheme swallows every routed flow. No compiler diagnoses that, and
on hardware it looks like traffic quietly taking the bridge path.
`tools/host_tests/test_cdx_pcd_build.py` asserts the ordering.

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
`$logicalportid` and tests against 9 to tell ethernet ports from offline ports.
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
table is created, so `cdxdrv_set_miss_action()` patches all 84 in with
`FM_PCD_HashTableModifyMissNextEngine()` once everything exists.

## External hash tables cannot be released

Under `USE_ENHANCED_EHASH` the SDK's `FM_PCD_HashTableDelete()` is a stub that
returns an error — `/* delete table code not added for USE_ENHANCED_EHASH */` in
`sdk_fman/Peripherals/FM/Pcd/fm_cc.c` — and `lnxwrp_exp_sym.h` does not export it
to modules in that build. There is no external-hash counterpart.

So a torn-down or failed install leaks its 84 tables and the FMan needs a reboot
before another attempt. `cdx_pcd_teardown()` releases the ports, schemes, trees
and network environment, and logs the tables it cannot reclaim. Tracked as
**A138** in [ISSUES.md](../ISSUES.md).

## The XML under `config/pcd/`

`cdx_pcd.xml`, `cdx_sp.xml` and `cdx_cfg.xml` are build-time inputs, not shipped
to the target. They remain the human-readable statement of the configuration and
the source for two generated artifacts:

- `cdx/cdx_softparse.h` — the assembled soft-parser bytecode, via
  `tools/gen_cdx_softparse.py`.
- `tools/host_tests/golden/cdx_pcd_model.json` — the expected PCD, via
  `tools/gen_cdx_pcd_golden.py`.

Two attributes in `cdx_pcd.xml` are decorative: `external="yes"` and
`aging="yes"` on `<hashtable>` are ignored by `fmc`, which warns `Unknown
attribute`. Tables become external because `FM_PCD_HashTableSet()` returns
`ExternalHashTableSet()` unconditionally under `USE_ENHANCED_EHASH`, never
consulting the `externalHash` field. `agingSupport` is likewise only read on the
internal path, which that build mode never takes.

## Checking the builder without a board

`tools/host_tests/test_cdx_pcd_build.py` compiles `cdx_pcd.c` and
`cdx_pcd_desc.c` unmodified on the host, replaces only the FMan entry points with
stubs that record their parameters, runs `cdx_pcd_build()`, and compares what it
programmed against `tools/host_tests/golden/cdx_pcd_model.json`. Port discovery
is stubbed with the gateway-dk port set, since it needs netdevs and the
offline-port registry.

It checks the object counts, the distinction units and their order, each CC root
tree holding its own tables in group order, every table shape, every scheme's FQ
base, unit list and extract fields (resolved to their numeric
`NET_HEADER_FIELD_*` values, not just their names), the port-id OR into FQID
bits 16–19, the per-port `prsResultPrivateInfo`, and the scheme match priority.

## Regenerating the golden

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

Use the patched fmlib headers from the kas work tree, not `sources/fmlib`. The
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

The builder reproduces fmc's group ordering exactly, so the offset lands where it
always did. That holds on hardware: `test_pppoe_e2e.py` passes all three tiers,
including `test_pppoe_lan_through_dut_iperf_offloaded`, whose second oracle
requires the flow to appear in cmm's connections table with `STRIP_PPPoE_HDR` —
which only happens if ingress PPPoE session frames actually reached the relay
table. That test exists to catch the case where throughput looks fine but FMAN
never engaged.

What has *not* been done is reading the numeric relationship back: nobody has
printed the CC root AD base and each group's AD address to confirm why `0x30`
selects the PPPoE group when it is group 1. The behaviour it controls is
verified; the arithmetic behind it is still folklore. Worth an instrumented boot
before anyone reorders `cdx_pcd_groups[]` or adds a thirteenth group.

## Open

Nothing blocking. See ISSUES.md A138 for the missing external-hash delete, which
makes a failed or torn-down install need a reboot.
