# ASK (Application Solutions Kit) for LS1046A

Hardware-accelerated packet processing for NXP Layerscape LS1046A (and LS1043A)
processors. This repository contains the kernel modules, userspace daemons,
kernel patch stack, board device tree, and configuration needed to enable DPAA1
/ FMAN fast-path offloading — turning a Linux router into a hardware-offloading
one.

Together with the ASK-enabled FMAN microcode (a proprietary NXP binary, **not
included**, v210.10.1, loaded by U-Boot before Linux boots) it offloads L2
bridging, L3 forwarding/NAT, QoS, and IPsec to the DPAA/FMAN hardware. Without
the microcode the standard FMAN driver still works, but CDX will not initialize.

## How ASK is consumed

ASK is **not a standalone product** — it is the set of components that enable
DPAA1/FMAN hardware offloading on the NXP LS1046A, meant to be **integrated into
a Linux distribution's build system**. OpenWrt, Armbian, Debian, or any Yocto
image pulls ASK in as a kernel patch stack plus a handful of packages; there is
no "ASK distro" and nothing here runs on its own.

The components:

- **Kernel modules** — `cdx` (the core offload engine: hardware flow tables,
  IPsec offload, and QoS via DPAA/FMAN), `fci` (control channel to the CMM
  daemon), `auto_bridge` (L2 bridge flow detection).
- **Userspace** — `cmm` (offloads netfilter conntrack flows to the classifier),
  `dpa_app` (loads the FMAN classification rules), `fmc` (NXP's FMAN config
  compiler).
- **Supporting libraries** — `libfci`, `fmlib`, `libcli`, and ASK-patched
  `libnfnetlink` / `libnetfilter_conntrack` (CMM's fast-path conntrack).
- **Kernel side** — the `patches/kernel/` stack (`010`–`110`: the vendored
  DPAA/FMAN SDK and ASK's hooks, applied onto stock mainline 6.12) and the board
  device tree in `dts/`.
- **Runtime config** — FMAN port maps, PCD / soft-parser XML, module load order,
  and init scripts (`config/`, `dpa_app/files/`).

### Reference recipes

Each component's **bitbake recipe** is the authoritative, self-contained
description of how to build and package it — flags, dependencies, install layout.
Anyone integrating ASK into another build system should read these as the
reference:

| Component | Recipe |
|-----------|--------|
| `cdx`, `fci`, `auto_bridge` (kernel modules) | `meta-ask/recipes-ask/{cdx,fci,auto-bridge}/` |
| `cmm`, `dpa_app`, `fmc` (userspace) | `meta-ask/recipes-ask/{cmm,dpa-app,fmc}/` |
| `libfci`, `fmlib`, `libcli` (libraries) | `meta-ask/recipes-ask/{libfci,fmlib,libcli}/` |
| patched `libnfnetlink` / `libnetfilter-conntrack` | `meta-ask/recipes-ask/{libnfnetlink,libnetfilter-conntrack}/` |
| kernel + ASK patch stack | `meta-ask/recipes-kernel/linux/linux-ask_6.12.bb` |
| bootable showcase image | `meta-ask/recipes-core/images/ask-image.bb` |

For example, OpenWrt consumes ASK by mirroring these as `package/ask/*` Makefiles
plus a committed copy of the kernel patch series — the same components, packaged
its own way.

### The Yocto layer is a showcase

`meta-ask` is **not a production distro** — it exists to demonstrate how all the
components build and fit together. It wires every one of them into a single
**bootable image that is served over the network and booted entirely in RAM**
(kernel + initramfs over TFTP). That means the full ASK stack comes up on a board
**without touching eMMC**: nothing is flashed, the installed on-board system is
left undisturbed, and a power-cycle returns the board to it. It is both the
reference for how the pieces integrate and a fast, non-destructive way to test
them on real hardware.

## Building the showcase image

The `meta-ask` layer builds that in-RAM image. It is self-contained: it fetches
its own BitBake, OpenEmbedded-core, and meta-openembedded, then builds the
kernel, the ASK modules, the userspace, and an initramfs into one bootable image.
Verified from scratch on a clean Debian 13 (trixie) amd64 host.

### Requirements

- Debian 13 (trixie) or newer, amd64.
- **Disk:** an empty-sstate build uses roughly **85 GB** — about 70 GB for the
  build tree (`meta-ask/build/tmp`), 13 GB of downloads, and a few GB of sstate.
  Provision **≥100 GB free** on the build filesystem.
- **RAM:** 16 GB minimum, 32 GB comfortable for a parallel build. Note that a
  default systemd `/tmp` is a tmpfs sized to half of RAM; a heavily parallel
  native compile can exhaust a small `/tmp`. If you hit `No space left on
  device` while `df` still shows free disk, that tmpfs is the cause — grow it, or
  point `TMPDIR` at real disk.

### 1. Host setup (one-time)

```sh
make setup
```

Installs `kas` and BitBake's host dependencies and generates the `en_US.UTF-8`
locale BitBake requires (needs sudo). `kas` 4.8.x from Debian trixie is
known-good; `pipx install kas` also works if you want a newer release.

### 2. Cache directories (required)

`make setup` seeds `meta-ask/site.conf` from `site.conf.example` — the real
`site.conf` is gitignored, so it's your local, machine-specific copy. **You must
edit it before building.** Create the cache directories first and give your build
user write access:

```sh
sudo mkdir -p /srv/yocto/dl /srv/yocto/sstate
sudo chown "$(id -u):$(id -g)" /srv/yocto/dl /srv/yocto/sstate
```

Then point `site.conf` at the paths you created (and set the parallelism to your
`nproc`):

```sh
# meta-ask/site.conf
DL_DIR            = "/srv/yocto/dl"       # downloaded tarballs (reusable)
SSTATE_DIR        = "/srv/yocto/sstate"   # shared state cache (reusable)
PARALLEL_MAKE     = "-j 24"                # set to your `nproc`
BB_NUMBER_THREADS = "24"                   # set to your `nproc`
```

Keep the caches **outside** the repo so a reclone doesn't wipe them; a warm
sstate cache turns a ~40-minute build into minutes.

### 3. Build

```sh
make ask-image        # = cd meta-ask && kas build .config.yaml
```

The image lands in `meta-ask/build/tmp/deploy/images/ask-ls1046a/` as
`Image.gz-initramfs-ask-ls1046a.bin` (kernel + initramfs, ~104 MB). From an empty
sstate cache the build takes ~40 minutes.

For the KASAN sanitizer (memory-error instrumentation, off by default):

```sh
KASAN=1 make ask-image
```

### Deploying to the board

The image boots in RAM over TFTP from U-Boot on the lab board:

```sh
make stage-image      # copy the image into $TFTP_ROOT (default /srv/tftp)
```

Then, at the DUT's U-Boot prompt: `tftpboot ${loadaddr} <name>; booti ${loadaddr} - ${fdtaddr}`.

### Make targets

The top-level `Makefile` is a thin wrapper around the kas build and the test
harness — it does not build ASK components standalone.

| Target | Does |
|--------|------|
| `make setup` | install host build deps + locale (one-time, sudo) |
| `make ask-image` | build the test image via kas |
| `make stage-image` | copy the built image into the TFTP root |
| `make deploy-agents` | install the askd test agent on the WAN/LAN hosts |
| `make ask-test` | run the end-to-end pytest suite |

## Versioning and branches

ASK is versioned per kernel-compatibility line. In short: `master` is active
development for the newest supported kernel; `mono-6.12` is the 6.12 maintenance
line; releases are tagged (`mono-1.0.0`). See [docs/VERSIONING.md](docs/VERSIONING.md)
for the full branch model.

## License

Kernel modules and ASK components are licensed under GPL-2.0+. See the individual
`COPYING.GPL` files in each component directory and the top-level `LICENSE`.
