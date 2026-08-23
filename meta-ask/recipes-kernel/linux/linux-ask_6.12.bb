SUMMARY = "Linux kernel for ASK LS1046A test target"
DESCRIPTION = "Stock mainline 6.12.103 kernel with the NXP DPAA/FMan/QBMan \
SDK overlaid on top and the ASK patch bundle applied. This is the Yocto \
twin of the OpenWrt-first build (scripts/mono-sync-ask-kernel.sh): the \
same mainline base + NXP SDK overlay + ASK hooks, producing a bootable \
Image+initramfs for ASK testing."
LICENSE = "GPL-2.0-only"
LIC_FILES_CHKSUM = "file://COPYING;md5=6bc538ed5bd9a7fc9398086aedcd7e46"

inherit kernel

DEPENDS += "bison-native flex-native bc-native"

FILESEXTRAPATHS:prepend := "${THISDIR}/files:"
FILESEXTRAPATHS:prepend := "${ASK_SRCROOT}/patches/kernel:"
# The board device tree is the canonical Mono Gateway DK source owned by the
# ASK repo (dts/mono-gateway-dk.dts); consume it directly rather than keep a
# drifting copy under files/.
FILESEXTRAPATHS:prepend := "${ASK_SRCROOT}/dts:"

LINUX_VERSION = "6.12.103"
PV = "${LINUX_VERSION}+git${SRCPV}"

# ============================================================================
# Two-pin split: the kernel base and the NXP SDK overlay are pinned SEPARATELY.
# The old recipe conflated them in a single SRCREV against the NXP vendor tree
# (which shipped the SDK drivers in-tree). On stock mainline the SDK is NOT
# in-tree, so it is fetched separately and overlaid (see do_overlay_sdk below).
# ============================================================================

# --- Pin 1: mainline kernel base (kernel.org stable) ---
# NB: this is the COMMIT v6.12.103 points at, not the tag object. The
# annotated tag v6.12.103 is object da1efec88de0..., which `git rev-parse
# v6.12.103` prints; the commit it peels to (`v6.12.103^{commit}`) is the
# value below. bitbake's SRCREV must be a commit (checkout -B / branch
# --contains operate on commits), so pin the peeled commit.
KERNEL_SRC = "git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git;protocol=https"
KERNEL_BRANCH = "linux-6.12.y"
# v6.12.103 (the annotated tag object is da1efec8...; this is its peeled commit).
KERNEL_SRCREV = "25c09b42358e73e1476e517b296edb6344f2e4bd"

# --- Pin 2: NXP DPAA/FMan/QBMan SDK overlay ---
# This is the SINGLE authoritative SDK pin. OpenWrt's kernel-side sync
# (scripts/mono-sync-ask-kernel.sh) currently keeps its own NXP_SDK_REF as a
# second hand-synced pin; its TODO is to fetch ASK and READ this
# NXP_SDK_SRCREV as the one SDK pin so the two can never drift. Keep this
# variable name greppable: NXP_SDK_SRCREV.
NXP_SDK_SRC = "git://github.com/nxp-qoriq/linux.git;protocol=https"
NXP_SDK_BRANCH = "lf-6.12.y"
# NXP tag lf-6.12.49-2.2.0.
NXP_SDK_SRCREV = "df24f9428e38740256a410b983003a478e72a7c0"

SRC_URI = "${KERNEL_SRC};branch=${KERNEL_BRANCH};name=kernel \
           ${NXP_SDK_SRC};branch=${NXP_SDK_BRANCH};name=nxpsdk;destsuffix=nxp-sdk \
           file://defconfig \
           file://ask.cfg \
           file://ask-kasan.cfg \
           file://mono-gateway-dk.dts \
           file://010-ask-fman-dpaa-ehash.patch \
           file://020-ask-bridge-hooks.patch \
           file://030-ask-ipv4-ipv6-forwarding.patch \
           file://040-ask-xfrm-ipsec-offload.patch \
           file://050-ask-conntrack-offload.patch \
           file://060-ask-netfilter-qosmark.patch \
           file://070-ask-ppp-hooks.patch \
           file://080-wext-core-restore-ndo_do_ioctl.patch \
           file://090-qbman-dpa_alloc-preallocate-nodes.patch \
           file://091-sdk_dpaa-dpa_get_channel-use-mutex.patch \
           file://092-sdk_fman-FmPcdLockTryLockAll-nest-annotation.patch \
           file://093-netlink-name-L2FLOW-cb-mutex.patch \
           file://094-sdk-fman-dpaa-qbman-kasan-sanitize-off.patch \
           file://096-sdk_fman-mac-hash-alloc-null-check.patch \
           file://097-xfrm-trans-queue-force-dst-refcount.patch \
           file://098-sdk_dpaa-bp-alloc-slab-build-skb.patch \
           file://099-sdk_fman-ehash-flex-arrays.patch \
           file://100-sdk_dpaa-ethtool-quiet-phyless-ports.patch \
           file://101-sdk_fman-sysfs-restore-irqs-on-early-return.patch \
           file://110-sdk-mainline-build-compat.patch \
          "

SRCREV_kernel = "${KERNEL_SRCREV}"
SRCREV_nxpsdk = "${NXP_SDK_SRCREV}"
# Two SCMs in SRC_URI — bitbake needs to know how to compose SRCPV.
SRCREV_FORMAT = "kernel_nxpsdk"

# ============================================================================
# NXP SDK overlay onto stock mainline.
#
# The overlay set is OpenWrt's SDK_PATHS list verbatim
# (scripts/mono-sync-ask-kernel.sh) — kept identical so both builds vendor the
# exact same tree from the exact same NXP ref. Two kinds of files:
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

S = "${WORKDIR}/git"

# The ASK kernel patches are shared verbatim with the Armbian and OpenWrt
# builds and carry no Yocto Upstream-Status tag; silence the QA rather than
# add a Yocto-only header to shared patches.
ERROR_QA:remove = "patch-status"
WARN_QA:remove  = "patch-status"

do_configure:prepend() {
    cp ${UNPACKDIR}/defconfig ${B}/.config
    cp ${UNPACKDIR}/*.dts ${S}/arch/arm64/boot/dts/freescale/
}

# Merge the ASK config fragment after the base defconfig is in place, then
# re-run olddefconfig so implicit dependencies resolve. ask-kasan.cfg is
# layered AFTER ask.cfg when KASAN=1 — its `CONFIG_KASAN=y` lines override
# the `# CONFIG_KASAN is not set` markers in the base fragment.
do_configure:append() {
    cat ${UNPACKDIR}/ask.cfg >> ${B}/.config
    if [ "${KASAN}" = "1" ]; then
        cat ${UNPACKDIR}/ask-kasan.cfg >> ${B}/.config
    fi
    oe_runmake -C ${S} O=${B} olddefconfig
}
