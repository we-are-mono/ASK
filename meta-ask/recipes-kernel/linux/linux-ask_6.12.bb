SUMMARY = "Linux kernel for ASK LS1046A test target"
DESCRIPTION = "NXP lf-6.12.y kernel with the ASK patch bundle applied. \
Used by meta-ask to produce a bootable Image+initramfs for ASK testing."
LICENSE = "GPL-2.0-only"
LIC_FILES_CHKSUM = "file://COPYING;md5=6bc538ed5bd9a7fc9398086aedcd7e46"

inherit kernel

DEPENDS += "bison-native flex-native bc-native"

FILESEXTRAPATHS:prepend := "${THISDIR}/files:"
FILESEXTRAPATHS:prepend := "${ASK_SRCROOT}/patches/kernel:"

LINUX_VERSION = "6.12.49"
PV = "${LINUX_VERSION}+git${SRCPV}"

LINUX_QORIQ_BRANCH = "lf-6.12.y"
LINUX_QORIQ_SRC = "git://github.com/nxp-qoriq/linux.git;protocol=https"
SRCREV = "df24f9428e38740256a410b983003a478e72a7c0"

SRC_URI = "${LINUX_QORIQ_SRC};branch=${LINUX_QORIQ_BRANCH} \
           file://defconfig \
           file://ask.cfg \
           file://ask-kasan.cfg \
           file://mono-gateway-dk.dts \
           file://001-hwmon-ina2xx-Add-INA234-support.patch \
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
           file://095-sdk_fman-iomem-mem-ops.patch \
          "

# Optional KASAN overlay — flipped on by the user with
# `KASAN=1 kas build .config.yaml`. The env var is propagated to
# bitbake via BB_ENV_PASSTHROUGH_ADDITIONS in .config.yaml's
# local_conf_header. Default builds skip ask-kasan.cfg entirely so
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

# The ASK bundle is shared with Armbian which strips Upstream-Status headers;
# silence the Yocto QA rather than carry a Yocto-only header.
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
