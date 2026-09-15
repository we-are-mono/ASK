# In-kernel PCD construction (retiring dpa_app)

`cdx.ko` currently spawns `/usr/bin/dpa_app` from `module_init` via
`call_usermodehelper(UMH_WAIT_PROC)` ([`cdx/cdx_main.c`](../cdx/cdx_main.c)).
`dpa_app` links `libfmc`, compiles four XML files into an `fmc_model`, applies
it to the hardware through the `/dev/fm*` ioctl shim, then hands the resulting
object ids back to `cdx` over `CDX_CTRL_DPA_SET_PARAMS`
([`cdx/dpa_cfg.c`](../cdx/dpa_cfg.c)).

That round trip exists only because `fmc` is a userspace C++ program. Every
hardware action it performs is an in-kernel FMD call: 28 of the 34 `FM_*` entry
points `fmc_exec.c` uses are already `EXPORT_SYMBOL`'d, and `cdx` already calls
23 of them directly. The six that are not exported — `FM_Open`/`FM_Close`,
`FM_PCD_Open`/`FM_PCD_Close`, `FM_PORT_Open`/`FM_PORT_Close` — are the shim's
own `open()`/`ioctl()` helpers; in kernel those handles come straight out of
`t_LnxWrpFmDev`, as `cdxdrv_get_fman_handles()` already does.

This document plans replacing the XML + `fmc` + `dpa_app` chain with a PCD
builder inside `cdx`.

## What the PCD actually contains

Measured by compiling the shipped XMLs with a host-mode `fmc` (see
[Regenerating the reference model](#regenerating-the-reference-model)):

| Object | Count |
| --- | --- |
| FMan engines | 1 |
| Ports | 7 (3×1G, 2×10G, 2×OFFLINE) |
| KeyGen schemes | 12 (shared; deduplicated by name) |
| Hash tables | 84 (12 shapes × 7 ports) |
| CC nodes, policers, manipulations, replicators, VSP | 0 |
| Prefilled hash entries | 0 — every key is added at runtime |
| Apply-order steps | 119 |

The boot sequence is roughly 140 calls: one `FM_PCD_PrsLoadSw`, one
`FM_PCD_SetAdvancedOffloadSupport`, one `FM_PCD_NetEnvCharacteristicsSet`
(7 distinction units, shared by every port), 84 `FM_PCD_HashTableSet`, 7
`FM_PCD_CcRootBuild`, 12 `FM_PCD_KgSchemeSet`, a
disable/`FM_PORT_SetPCD`/enable cycle per port, and `FM_PCD_Enable`.

All 12 schemes are applied inside port 0's window, so each shared scheme's
`kgNextEngineParams.cc.h_CcTree` names eth1's tree. Per-port dispatch comes
from `FM_PORT_SetPCD(p_CcParams->h_CcTree)`, not from the scheme. Keeping the
schemes shared is mandatory: 7 ports × 12 distributions would need 84 KeyGen
schemes against a hardware budget of 32.

Group order is the reverse of the policy `dist_order`, and `scheme[i].grpId`
equals the port's `ccroot[i]`:

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

Port *P*'s tables are model indices `12P … 12P+11` in that same order.

## Why the XML is not carrying its weight

Every `<fieldref>` in `cdx_pcd.xml` resolves through two flat lookup tables in
`FMCPCDModel.cpp` — protocol name to `HEADER_TYPE_*`, field name to
`NET_HEADER_FIELD_*`. All 15 field names and all 7 protocol names used resolve
to known constants, so none takes the `e_FM_PCD_EXTRACT_FROM_HDR` path that
would need byte offsets from the 82 KB NetPDL. The NetPDL is required only by
the soft-parser assembler, which moves to build time.

`external="yes"` and `aging="yes"` on the `<hashtable>` elements are ignored by
`fmc`, which warns `Unknown attribute`. Tables become external because
`FM_PCD_HashTableSet()` returns `ExternalHashTableSet()` unconditionally under
`USE_ENHANCED_EHASH` (`sdk_fman/Peripherals/FM/Pcd/fm_cc.c`), never consulting
the `externalHash` field. `agingSupport` is likewise only read on the internal
path, which that build mode never takes.

All ten `<policy>` elements are byte-identical, so the per-port `policy`
attribute in `cdx_cfg.xml` carries no information.

## Board configuration

`cdx_cfg.xml` holds nothing that is not already in the device tree.

| Attribute | Source |
| --- | --- |
| which ports participate | DPAA netdevs (ethernet) and the `fsl,dpa-oh` registry `oh_port_probe()` fills (offline) |
| `number` | DT `cell-index` |
| `portid` | formula over SoC port counts, below |
| `policy` | none — all policies identical |

Ethernet ports come from walking `init_net` the way
[`find_osdev_by_fman_params()`](../cdx/devman.c) already does, in the forward
direction. Offline ports come from `offline_port_info[][]`, which the SDK fills
from the `fsl,dpa-oh` node names; the host-command port and unbound OH ports
are excluded by construction because they carry no binding.

`portid` is a flat logical index over the FMan's whole port space:

    1G  cell-index N -> N
    10G cell-index N -> FM_MAX_NUM_OF_1G_RX_PORTS + N
    OH  cell-index N -> FM_MAX_NUM_OF_1G_RX_PORTS + FM_MAX_NUM_OF_10G_RX_PORTS + N

On LS1043/LS1046 that gives 0–5 for 1G, 6–7 for 10G, 8 for OH0 (the
host-command port) and 9–15 for OH1–7. The formula holds without exception
across all five known configurations — the four NXP references in
`ASK-NXP/dpa_app/dpa_app-4.03.0/files/etc/` and
[`config/gateway-dk/cdx_cfg.xml`](../config/gateway-dk/cdx_cfg.xml) — covering
40 port entries. The bases come from the SoC integration header, so `portid` is
SoC-derived rather than board-derived.

`fmc` writes `portid` into `port[].prsParam.prsResultPrivateInfo`, which the
soft parser reads as `$logicalportid`. `cdx_sp.xml` gates on
`$logicalportid lt 9` to mean "is an ethernet port", which is why offline ports
must be 9 or above.

### Device-tree override

A board that departs from the formula sets an optional property on the node
that already carries the `cell-index` — `&fman0 ethernet@eX000` for MACs,
`dpa-fman0-oh@N` for offline ports:

```dts
dpa-fman0-oh@2 {
	compatible = "fsl,dpa-oh";
	fsl,fman-oh-port = <&fman0_oh_0x3>;
	mono,cdx-logical-portid = <9>;   /* optional; default 8 + cell-index */
};
```

`mac_dev->dev->of_node` reaches the MAC node from what the netdev walk already
holds. A conforming board writes no lines at all; `mono-gateway-dk.dts` needs
none, since all seven of its ports match the formula.

The `mono` vendor prefix is not yet registered in the kernel's
`vendor-prefixes.yaml`, although `mono,gateway-dk` and `mono,sfp-led` already
ship. Registering it is a prerequisite for open-sourcing and is independent of
this work.

## Plan

**Phase 0 — soft-parser coupling.** `cdx_sp.xml` computes the PPPoE relay
table address as `$ccbase + 0x30` and its comment warns that the value must be
rechecked whenever a table is added. Group 1 is PPPoE but `0x30` is three
entries in, so either the addressing is not 16 bytes per group or `$ccbase` is
not the CC root base. Instrument a boot, print the CC root AD base and each
group's AD address, and resolve it before writing the builder. If the offset
turns out to depend on FMC's allocation order rather than the group index, the
builder has to reproduce that order explicitly.

**Phase 1 — static tables and soft-parser blob.** Three tables in `cdx`: ports
`{type, number, portid}` (derived, per above), table shapes
`{name, key size, hash mask, cdx table type}`, and schemes
`{protocols[], fields[], qbase, qcount, grpId}`. The compiled soft parser
becomes a generated header; `cdx_sp.xml` stays checked in as the source.

**Phase 2 — the builder.** Around 600 lines walking those tables through the
sequence above, plus unwind. Diff the result against the reference model.

**Phase 3 — remove the round trip.** Delete `dpa_app/`, `start_dpa_app()`, and
the ingestion half of `cdx/dpa_cfg.c` — `get_dist_info` (58 lines),
`get_port_info` (91), `get_cctbl_info` (66), `cdxdrv_get_fman_handles` (49) and
the copy-in prologue of `cdx_ioc_set_dpa_params` (~100 of 212). What remains of
that function — port publishing, policer profiles, CEETM, miss actions,
rollback — becomes a directly called `dpa_cfg_install()`. The `dpa-app`
package, the `81_cdx_cfg_select` preinit hook and the libxml2, libstdc++ and
libcli runtime dependencies go with it.

`cdxdrv_set_miss_action()` stays as it is. An earlier draft of this plan expected
its 84 `FM_PCD_HashTableModifyMissNextEngine` host commands to fold into the
initial `FM_PCD_HashTableSet` parameters; they cannot. A table's miss action names
a scheme, a scheme names a CC tree, and the tree names the tables, so no creation
order has the scheme handle available when the table is created. fmc solves the
same knot for `alwaysDirect` schemes by creating them twice; doing that here would
trade 84 host commands for 12 scheme re-sets but change the creation order that
the soft-parser offset depends on. Not worth it before Phase 0 resolves that
coupling.

**Phase 4 — validation.** Full `make ask-test`, plus a KASAN sweep: this
touches allocation and struct-cast paths.

## External hash tables cannot be released

Under `USE_ENHANCED_EHASH` the SDK's `FM_PCD_HashTableDelete()` is a stub that
returns an error — `/* delete table code not added for USE_ENHANCED_EHASH */` in
`sdk_fman/Peripherals/FM/Pcd/fm_cc.c` — and `lnxwrp_exp_sym.h` does not export it
to modules in that build. There is no external-hash counterpart.

So a torn-down or failed classifier install leaks its 84 tables, and the FMan
needs a reboot before another attempt. This is not a regression: `fmc_clean()`
reached the same stub through the ioctl shim, which is why `dpa_app` printed
*"FMC rollback failed; reboot before retrying"* and why
`cdx_ioc_dpa_init_check()` refuses a second install outright. `cdx_pcd_teardown()`
releases the ports, schemes, trees and network environment, and logs the tables
it cannot reclaim.

Worth revisiting separately: the delete path exists for internal hash tables and
for the non-enhanced external ones, so writing the enhanced-ehash version is a
bounded piece of SDK work that would make the classifier reinstallable without a
reboot.

## Risks

1. **The `$ccbase` offset.** The one unresolved mechanism; Phase 0 exists to
   retire it. Fallback is keeping the group ordering byte-identical, which is
   cheap now that it is written down.
2. **`prsResultPrivateInfo` must stay `portid`.** Offline ports need 9 and 10.
   `cdx_cfg.xml`'s own comment documents an earlier attempt to use 2 and 3,
   which tripped the `espschema` policing gate.
3. **Scheme sharing.** Twelve schemes, all carrying eth1's `h_CcTree`. Giving
   each port its own schemes exhausts the 32-scheme KeyGen budget at 84.
4. **The `/dev/fm*` ioctl surface stays.** Removing it (about 6,000 lines plus
   the generation-tagged cookie registry) is a separate decision;
   `tools/tests/test_dpa_startup.py` and `test_flowtable_offload.py` exercise
   those nodes as negative tests.

## Regenerating the reference model

`fmc` builds in a host-only mode that links against `FMCDummyDriver.c` instead
of the ioctl shim, so the whole compile runs on the development host. Without
`--apply` it writes `fmc_config_data.c`, the complete model as C initialisers,
and `softparse.h`, the compiled soft-parser bytecode.

```sh
make -C <fmc>/source FMCHOSTMODE=1 MACHINE=ls1046 \
     FMD_USPACE_HEADER_PATH=<patched fmlib>/include/fmd
<fmc>/source/fmc -c config/gateway-dk/cdx_cfg.xml \
     -p dpa_app/files/etc/cdx_pcd.xml -s dpa_app/files/etc/cdx_sp.xml \
     -d <fmc>/etc/fmc/config/hxs_pdl_v3.xml -t 0x20
```

Use the patched fmlib headers from the kas work tree, not `sources/fmlib`. The
ASK `fmc` patch added `FM_PORT_GetEnabled` calls to `fmc_exec.c` without
stubbing the symbol in `FMCDummyDriver.c`, so host mode needs that one stub
added before it links.
