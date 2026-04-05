# NXP ASK (Application Solutions Kit) for LS1046A

Hardware-accelerated packet processing for NXP Layerscape LS1046A (and LS1043A) processors. This repository contains the kernel modules, userspace daemons, build patches, and configuration files needed to enable DPAA fast-path offloading.

## Building

Builds on Debian trixie (or newer) targeting aarch64. Everything is cross-compiled — no target hardware needed.

### One-time setup

```sh
make setup    # installs crossbuild-essential-arm64 and arm64 library packages (needs sudo)
```

### Build

```sh
make          # fetches all dependencies into sources/, patches them, builds everything
```

This produces:

| Artifact | Type |
|----------|------|
| `cdx/cdx.ko` | Kernel module — core fast-path offload engine |
| `fci/fci.ko` | Kernel module — CMM-to-CDX communication |
| `auto_bridge/auto_bridge.ko` | Kernel module — L2 bridge flow detection |
| `sources/fmc/source/fmc` | Userspace — FMAN configuration tool |
| `cmm/src/cmm` | Userspace — connection manager daemon |
| `dpa_app/dpa_app` | Userspace — FMAN classification rule loader |

### Other targets

```sh
make modules    # kernel modules only
make userspace  # userspace binaries only
make sources    # fetch + patch + build all dependencies (fmlib, fmc, libfci, libnfnetlink, libnetfilter_conntrack)
make kernel     # build kernel Image + in-tree modules (requires kernel source at KDIR)
make dist       # stage all artifacts into dist/
make serve      # HTTP server on dist/ for target deployment
make clean      # clean build artifacts (keeps fetched sources)
make clean-all  # clean everything including fetched sources
```

### Requirements

- Debian trixie or newer (amd64 host)
- `make setup` installs everything else
- Kernel source tree at `~/Mono/linux` (override with `make KDIR=/path/to/kernel`)
- The kernel must be configured (`.config` present) — use `make kernel` or copy `config/kernel/defconfig`

### How it works

`make` automatically:
1. Clones NXP fmlib and fmc from GitHub at tag `lf-6.12.49-2.2.0`, applies ASK extension patches, cross-compiles them
2. Downloads libnfnetlink and libnetfilter_conntrack tarballs, applies NXP ASK patches, cross-compiles into a local sysroot
3. Builds libfci (in-tree, single source file)
4. Builds kernel modules against the configured kernel tree
5. Builds CMM, FMC, and dpa_app against the patched libraries

All fetched sources go into `sources/` (gitignored). `make clean-all` removes them for a fully fresh rebuild.

### Note for other build systems

CMM requires **patched** versions of libnfnetlink and libnetfilter_conntrack. The stock upstream libraries do not have the NXP ASK extensions (fast-path conntrack attributes, QoS connmark, `IPS_PERMANENT`) and CMM will not compile against them. The patches are in `patches/libnfnetlink/` and `patches/libnetfilter-conntrack/`. If you are building outside this Makefile (e.g., Yocto, OpenWrt, or manually), you must apply these patches to your copies of these libraries.

## Deploying to target

```sh
make dist       # copies all artifacts to dist/
make serve      # starts HTTP server on port 8000

# On the target (Armbian):
wget http://<host>:8000/cdx.ko -P /lib/modules/$(uname -r)/extra/
# ... etc
```

## Overview

Together with the ASK-enabled FMAN microcode (a proprietary NXP binary, not included), this repository provides everything needed to turn any Linux-based distribution or routing system into a hardware-offloading-capable router on LS1046A/LS1043A platforms.

The ASK-enabled FMAN microcode (v210.10.1) must be loaded by U-Boot before Linux boots. Without it, the standard FMAN driver operates normally but CDX will not initialize.

## Components

### Kernel Modules

| Module | Description |
|--------|-------------|
| **cdx** | Control Data Exchange — core fast-path offload engine. Manages hardware flow tables, IPsec offload, and QoS via DPAA/FMAN. |
| **fci** | Fast-path Control Interface — communication channel between CDX and the CMM daemon. Depends on CDX. |
| **auto_bridge** | Automatic L2 bridge flow detection. Monitors bridge ports and notifies CDX of flows eligible for hardware offload. |

### Userspace

| Component | Description |
|-----------|-------------|
| **cmm** | Connection Manager daemon. Monitors netfilter conntrack and offloads eligible flows to CDX. |
| **dpa_app** | Programs FMAN classification rules from XML policy files via FMC. Called by CDX at module load. |
| **fci/lib** (libfci) | Userspace library for communicating with the FCI kernel module. Used by CMM. |

### Patches

| Target | Patch | Purpose |
|--------|-------|---------|
| **kernel** | `003-mono-gateway-ask-kernel_linux_6_12.patch` | DPAA/FMAN driver enhancements, IPsec offload, netfilter QoS marking, bridge fast-path, QBMan NAPI |
| **fmlib** | `01-mono-ask-extensions.patch` | Hash table, IP reassembly, shared scheme support for Frame Manager library |
| **fmc** | `01-mono-ask-extensions.patch` | Port ID, shared scheme replication, PPPoE field fix, libxml2 compatibility |
| **libnetfilter-conntrack** | `01-nxp-ask-comcerto-fp-extensions.patch` | Fast-path info attributes and QoS connmark for CMM |
| **libnfnetlink** | `01-nxp-ask-nonblocking-heap-buffer.patch` | Non-blocking socket mode and heap buffer management for CMM |
| **iptables** | `001-qosmark-extensions.patch` | QOSMARK/QOSCONNMARK target and match extensions |
| **ppp** | `01-nxp-ask-ifindex.patch` | Tunnel interface index support for PPP offload |
| **rp-pppoe** | `01-nxp-ask-cmm-relay.patch` | CMM-aware PPPoE relay |

### Configuration

| File | Description |
|------|-------------|
| `config/ask-modules.conf` | Module load order for systemd |
| `config/cmm.service` | Systemd service for CMM (guarded by `/dev/cdx_ctrl`) |
| `config/fastforward` | CMM traffic exclusion rules (FTP, SIP, PPTP bypass fast path) |
| `config/gateway-dk/cdx_cfg.xml` | FMAN port mapping for Mono Gateway DK |
| `config/kernel/defconfig` | Kernel defconfig for LS1046A with ASK |
| `dpa_app/files/etc/cdx_pcd.xml` | Packet classification rules for FMAN hash tables |

## License

Kernel modules and ASK components are licensed under GPL-2.0+. See individual `COPYING.GPL` files in each component directory.
