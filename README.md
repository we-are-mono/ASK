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
  IPsec offload, and QoS via DPAA/FMAN) and `ask_flowtable` (the adapter that
  lets Linux's native flowtables drive CDX).
- **Userspace** — `ask-flowtable` (the default-on offload policy daemon),
  `dpa_app` (loads the FMAN classification rules), `fmc` (NXP's FMAN config
  compiler).
- **Supporting libraries** — `fmlib`.
- **Retired** — the CMM daemon, its FCI control channel (`libfci`) and the
  `auto_bridge` L2 flow detector are gone from the tree; Linux flowtables
  replaced them. Their sources remain in the `mono-1.0.x` release tags, which
  is what docs citing `cmm/`, `fci/` or `auto_bridge/` paths refer to.
- **Kernel side** — the `patches/kernel/` stack (`010`–`130`: the vendored
  DPAA/FMAN SDK, ASK's hooks, and board drivers, applied onto stock mainline
  6.12) and the board device tree in `dts/`. See
  [fan control](docs/fan-control.md) for the EMC2305 kernel interface and testing.
- **Runtime config** — FMAN port maps, PCD / soft-parser XML, module load order,
  and init scripts (`config/`, `dpa_app/files/`).

### Reference recipes

Each component's **bitbake recipe** is the authoritative, self-contained
description of how to build and package it — flags, dependencies, install layout.
Anyone integrating ASK into another build system should read these as the
reference:

| Component | Recipe |
|-----------|--------|
| `cdx`, `ask_flowtable` (kernel modules) | `meta-ask/recipes-ask/cdx/` |
| `ask-flowtable`, `dpa_app`, `fmc` (userspace) | `meta-ask/recipes-ask/{flowtable,dpa-app,fmc}/` |
| `fmlib` (library) | `meta-ask/recipes-ask/fmlib/` |
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
make stage-image      # copy image + matching DTB into $TFTP_ROOT (default /srv/tftp)
```

Then, at the DUT's U-Boot prompt: `tftpboot ${loadaddr} <name>; booti ${loadaddr} - ${fdtaddr}`.
Also load the staged `mono-gateway-dk.dtb` into the DTB RAM buffer passed to
`booti`; it contains the board's fan curve configuration.

### Make targets

The top-level `Makefile` is a thin wrapper around the kas build and the test
harness — it does not build ASK components standalone.

| Target | Does |
|--------|------|
| `make setup` | install host build deps + locale (one-time, sudo) |
| `make ask-image` | build the test image via kas |
| `make stage-image` | copy the built image and matching DTB into the TFTP root |
| `make test-env` | install the pinned Python runner dependencies |
| `make deploy-agents` | install the askd test agent and runner dependencies on the WAN host |
| `make test` | run host and DUT tests using ignored `.ask-test.mk` bench settings |
| `make test-host` | run host tests without the physical bench |
| `make test-dut` | run the DUT suite |
| `make test-startup` | run startup tests on their dedicated boot |
| `make ask-test` | alias for `make test` |

The [test dependency guide](docs/testing.md#runner-dependencies-and-installation)
covers the Python environment, system packages, source trees, and DUT/LAN
requirements. Python package versions are pinned in
[`tools/requirements.txt`](tools/requirements.txt). Filter a run with
`make test K='ipsec or mcast'`; extra pytest options go in `ARGS`.

## Versioning and branches

ASK is versioned per kernel-compatibility line. In short: `master` is active
development for the newest supported kernel; `mono-6.12` is the 6.12 maintenance
line; releases are tagged (`mono-1.0.0`). See [docs/versioning.md](docs/versioning.md)
for the full branch model.

The `feat/linux-flowtable-offload` branch replaces CMM flow management with
Linux's native flowtables. The test image boots only that path, and the CMM,
FCI and auto_bridge sources have been removed (see the release tags). The
[project overview](docs/flowtable/README.md) links the current
architecture, supported features, operating guides, and historical validation
evidence.

## License

Kernel modules and ASK components are licensed under GPL-2.0+. See the individual
`COPYING.GPL` files in each component directory and the top-level `LICENSE`.
