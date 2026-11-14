SUMMARY = "Linux kernel for ASK LS1046A test target"
DESCRIPTION = "Stock mainline ${LINUX_VERSION} kernel with the NXP DPAA/FMan/QBMan \
SDK overlaid on top and the ASK patch bundle applied. This is the Yocto \
twin of the OpenWrt-first build (scripts/mono-sync-ask-kernel.sh): the \
same mainline base + NXP SDK overlay + ASK hooks, producing a bootable \
Image+initramfs for ASK testing."
LICENSE = "GPL-2.0-only"
LIC_FILES_CHKSUM = "file://COPYING;md5=6bc538ed5bd9a7fc9398086aedcd7e46"

# What every kernel line builds alike. Each line's recipe, linux-ask_<line>.bb,
# sets ASK_KERNEL_LINE and its kernel and SDK pins before requiring this file,
# and lists its patch series after it; ASK_LINE picks the line a build makes
# (conf/distro/ask.conf).

inherit kernel ask-provenance

DEPENDS += "bison-native flex-native bc-native"

# This file and the SDK pin arrive by `require`, outside SRC_URI. The series
# and board directories are recorded whole, so a file that would shadow one in
# SRC_URI counts too. The record reaches the image through the package every
# module depends on.
ASK_PROVENANCE_PATHS = "meta-ask/recipes-kernel/linux/linux-ask.inc \
                        pins/${ASK_KERNEL_LINE}/nxp-sdk-srcrev.inc \
                        patches/kernel/${ASK_KERNEL_LINE} dts"
ASK_PROVENANCE_OWNER = "${KERNEL_PACKAGE_NAME}-base"

# The config fragments are one set for every line (files/).
FILESEXTRAPATHS:prepend := "${THISDIR}/files:"
FILESEXTRAPATHS:prepend := "${ASK_SRCROOT}/patches/kernel/${ASK_KERNEL_LINE}:"
# The board device tree is the canonical Mono Gateway DK source owned by the
# ASK repo (dts/mono-gateway-dk.dts); consume it directly rather than keep a
# drifting copy under files/.
FILESEXTRAPATHS:prepend := "${ASK_SRCROOT}/dts:"

PV = "${LINUX_VERSION}+git${SRCPV}"

# ============================================================================
# Two-pin split: the kernel base and the NXP SDK overlay are pinned SEPARATELY.
# The old recipe conflated them in a single SRCREV against the NXP vendor tree
# (which shipped the SDK drivers in-tree). On stock mainline the SDK is NOT
# in-tree, so it is fetched separately and overlaid (see do_overlay_sdk below).
# ============================================================================

# --- Pin 1: mainline kernel base (kernel.org stable) ---
# A line's KERNEL_SRCREV is the COMMIT its release tag points at, not the
# annotated tag object `git rev-parse v<version>` prints: it is
# `v<version>^{commit}`. bitbake's SRCREV must be a commit (checkout -B /
# branch --contains operate on commits), so pin the peeled commit.
KERNEL_SRC = "git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git;protocol=https"

# --- Pin 2: NXP DPAA/FMan/QBMan SDK overlay ---
# The SDK SRCREV lives in a canonical, format-neutral pin file per line
# (pins/<line>/nxp-sdk-srcrev.inc) so every consumer reads ONE source and nobody
# parses another's format: this recipe `require`s it (bitbake tracks the file's
# checksum, so a pin bump re-triggers the fetch); OpenWrt's sync and the Armbian
# build extract the value with a one-line sed. ASK_VERSION stays the single pin
# — the SDK ref rides inside the pinned ASK tree.
NXP_SDK_SRC = "git://github.com/nxp-qoriq/linux.git;protocol=https"
require ${ASK_SRCROOT}/pins/${ASK_KERNEL_LINE}/nxp-sdk-srcrev.inc

# The line's recipe appends its patch series, in order, one patch per entry.
SRC_URI = "${KERNEL_SRC};branch=${KERNEL_BRANCH};name=kernel \
           ${NXP_SDK_SRC};branch=${NXP_SDK_BRANCH};name=nxpsdk;destsuffix=nxp-sdk \
           file://defconfig \
           file://ask.cfg \
           file://ask-kasan.cfg \
           file://ask-perf.cfg \
           file://mono-gateway-dk.dts \
          "

SRCREV_kernel = "${KERNEL_SRCREV}"
SRCREV_nxpsdk = "${NXP_SDK_SRCREV}"
# Two SCMs in SRC_URI — bitbake needs to know how to compose SRCPV.
SRCREV_FORMAT = "kernel_nxpsdk"

# ============================================================================
# NXP SDK overlay onto stock mainline.
#
# This set is OpenWrt's SDK_PATHS list verbatim
# (scripts/mono-sync-ask-kernel.sh) — kept identical so both builds vendor the
# exact same tree from the exact same NXP ref; a line's recipe adds what its
# SDK release needs beyond it. Two kinds of files:
#   - SDK-only trees (sdk_dpaa, sdk_fman, fsl_qbman, uapi/linux/fmd, the
#     fsl_{bman,qman,usdpaa}.h headers, the *-portals-sdk / dpaa-eth dtsi):
#     absent on mainline, added fresh.
#   - Same-named DPAA device tree (fsl-ls1046a.dtsi, fsl-ls1046-post.dtsi,
#     qoriq-{q,b}man-portals.dtsi, qoriq-fman3-0*.dtsi): mainline ships these
#     with mainline FMan/DPAA bindings the NXP SDK drivers cannot probe, so the
#     overlay must OVERWRITE them.
# ASK-added files (e.g. include/linux/fsl_oh_port.h) arrive with the patch
# series, NOT from this overlay.
# ============================================================================
NXP_SDK_PATHS = "\
    drivers/net/ethernet/freescale/sdk_dpaa \
    drivers/net/ethernet/freescale/sdk_fman \
    drivers/staging/fsl_qbman \
    include/uapi/linux/fmd \
    include/linux/fsl_bman.h \
    include/linux/fsl_qman.h \
    include/linux/fsl_usdpaa.h \
    arch/arm64/boot/dts/freescale/qoriq-qman-portals-sdk.dtsi \
    arch/arm64/boot/dts/freescale/qoriq-bman-portals-sdk.dtsi \
    arch/arm64/boot/dts/freescale/qoriq-dpaa-eth.dtsi \
    arch/arm64/boot/dts/freescale/fsl-ls1046a.dtsi \
    arch/arm64/boot/dts/freescale/fsl-ls1046-post.dtsi \
    arch/arm64/boot/dts/freescale/qoriq-qman-portals.dtsi \
    arch/arm64/boot/dts/freescale/qoriq-bman-portals.dtsi \
    arch/arm64/boot/dts/freescale/qoriq-fman3-0.dtsi \
    arch/arm64/boot/dts/freescale/qoriq-fman3-0-1g-0.dtsi \
    arch/arm64/boot/dts/freescale/qoriq-fman3-0-1g-1.dtsi \
    arch/arm64/boot/dts/freescale/qoriq-fman3-0-1g-2.dtsi \
    arch/arm64/boot/dts/freescale/qoriq-fman3-0-1g-3.dtsi \
    arch/arm64/boot/dts/freescale/qoriq-fman3-0-1g-4.dtsi \
    arch/arm64/boot/dts/freescale/qoriq-fman3-0-1g-5.dtsi \
    arch/arm64/boot/dts/freescale/qoriq-fman3-0-10g-0.dtsi \
    arch/arm64/boot/dts/freescale/qoriq-fman3-0-10g-1.dtsi \
"

# do_patch is a python task (default PATCHTOOL=quilt, which does NOT reset the
# tree), so a shell :prepend on it would not execute — the overlay has to be its
# own shell task. It must run AFTER kernel.bbclass's do_symlink_kernsrc (which
# moves ${WORKDIR}/git into STAGING_KERNEL_DIR and symlinks it back, so ${S}
# only resolves to the final kernel-source tree once that has run) and BEFORE
# do_patch (so the ASK series, which edits the SDK sources, and patch 110, the
# SDK build-compat glue, apply on top of the vendored tree).
do_overlay_sdk() {
    # Locate the NXP SDK checkout (the second git fetch, destsuffix=nxp-sdk).
    # Depending on the OE version the git fetcher lands a destsuffix tree under
    # WORKDIR or under UNPACKDIR; probe both and fail loudly if neither has it.
    sdkroot=""
    for cand in "${WORKDIR}/nxp-sdk" "${UNPACKDIR}/nxp-sdk"; do
        if [ -d "${cand}/drivers/net/ethernet/freescale/sdk_dpaa" ]; then
            sdkroot="${cand}"; break
        fi
    done
    if [ -z "${sdkroot}" ]; then
        bbfatal "NXP SDK overlay: nxp-sdk checkout not found under ${WORKDIR}/nxp-sdk or ${UNPACKDIR}/nxp-sdk (SDK fetch ${NXP_SDK_SRC} @ ${NXP_SDK_SRCREV})"
    fi
    bbnote "NXP SDK overlay: vendoring from ${sdkroot} into ${S}"
    for p in ${NXP_SDK_PATHS}; do
        src="${sdkroot}/${p}"
        dst="${S}/${p}"
        if [ ! -e "${src}" ]; then
            bbfatal "NXP SDK overlay: '${p}' missing in ${NXP_SDK_SRC} @ ${NXP_SDK_SRCREV} (ASK-added files come from the patch series, not the overlay)"
        fi
        if [ -d "${src}" ]; then
            # Full replace so no stale mainline file lingers under an
            # overwritten directory (rsync --delete equivalent).
            rm -rf "${dst}"
            mkdir -p "${dst}"
            cp -a "${src}/." "${dst}/"
        else
            mkdir -p "$(dirname "${dst}")"
            cp -af "${src}" "${dst}"
        fi
    done
}
addtask overlay_sdk after do_symlink_kernsrc before do_patch

# Optional KASAN overlay — flipped on by the user with
# `KASAN=1 kas build .config.yaml`. The env var is propagated to
# bitbake via the kas `env:` block in .config.yaml, which injects it
# before parse (a local_conf_header assignment would be too late).
# Default builds skip ask-kasan.cfg entirely so
# the image stays fast (~13 MB smaller, ~60% faster suite).
KASAN ??= "0"

# Make KASAN's value part of do_configure's task hash. Without this,
# bitbake's signature for the configure step doesn't notice when KASAN
# flips between runs, and we get a stale (cached) .config from the
# previous mode — silently producing a non-instrumented kernel under
# `KASAN=1 kas build`. Listing it as a vardep forces a re-configure
# whenever the value changes.
do_configure[vardeps] += "KASAN"

# Optional throughput overlay, `PERF=1 kas build .config.yaml`: ask-perf.cfg
# drops the runtime-costly debug options ask.cfg turns on, so CPU-bound
# paths measure close to a production kernel. Off by default, KASAN builds
# included: the suite relies on kmemleak, failslab and the production DPAA
# timestamping config it turns off. Passed in and hashed as KASAN is.
PERF ??= "0"
do_configure[vardeps] += "PERF"

S = "${WORKDIR}/git"

# The ASK kernel patches are shared verbatim with the Armbian and OpenWrt
# builds and carry no Yocto Upstream-Status tag; silence the QA rather than
# add a Yocto-only header to shared patches.
ERROR_QA:remove = "patch-status"
WARN_QA:remove  = "patch-status"

do_configure:prepend() {
    cp ${UNPACKDIR}/defconfig ${B}/.config
    cp ${UNPACKDIR}/*.dts ${S}/arch/arm64/boot/dts/freescale/
    # U-Boot loads the device tree apart from this kernel, so the tree names
    # the kernel record of the build that compiled it; the test harness
    # refuses a tree from any other build (tools/ask_orch/manifest.py).
    digest=$(sha256sum ${ASK_PROVENANCE_DIR}/${PN}.json)
    printf '\n/ {\n\tmono,ask-provenance = "%s";\n};\n' "${digest%% *}" \
        >> ${S}/arch/arm64/boot/dts/freescale/mono-gateway-dk.dts
}

# Merge the ASK config fragment after the base defconfig is in place, then
# re-run olddefconfig so implicit dependencies resolve. ask-kasan.cfg is
# layered AFTER ask.cfg when KASAN=1 — its `CONFIG_KASAN=y` lines override
# the `# CONFIG_KASAN is not set` markers in the base fragment.
do_configure:append() {
    cat ${UNPACKDIR}/ask.cfg >> ${B}/.config
    if [ "${PERF}" = "1" ]; then
        cat ${UNPACKDIR}/ask-perf.cfg >> ${B}/.config
    fi
    if [ "${KASAN}" = "1" ]; then
        cat ${UNPACKDIR}/ask-kasan.cfg >> ${B}/.config
    fi
    oe_runmake -C ${S} O=${B} olddefconfig
}
