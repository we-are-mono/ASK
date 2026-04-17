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
           file://mono-gateway-dk.dts \
           file://001-hwmon-ina2xx-Add-INA234-support.patch \
           file://002-mono-gateway-ask-kernel_linux_6_12.patch \
          "

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
# re-run olddefconfig so implicit dependencies resolve.
do_configure:append() {
    cat ${UNPACKDIR}/ask.cfg >> ${B}/.config
    oe_runmake -C ${S} O=${B} olddefconfig
}
