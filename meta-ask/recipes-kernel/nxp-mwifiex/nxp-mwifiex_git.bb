SUMMARY = "NXP 88W9098 (moal/mlan) PCIe Wi-Fi driver"
DESCRIPTION = "NXP's MXM Wi-Fi driver for the 88W9098 (u-blox JODY-W3) over \
PCIe, as a cfg80211 full-MAC driver. This is the radio the Mono Gateway DK \
carries, and the same driver and commit the OpenWrt production build ships, \
so the test image exercises the shipping datapath rather than an approximation."

LICENSE = "GPL-2.0-only"
LIC_FILES_CHKSUM = "file://LICENSE;md5=ab04ac0f249af12befccb94447c08b77"

inherit module

FILESEXTRAPATHS:prepend := "${THISDIR}/files:"

SRC_URI = "git://github.com/nxp-imx/mwifiex.git;protocol=https;branch=hotfix/lf-6.12.49_2.2.0_hotfix \
           file://0001-cfg80211-set_monitor_channel-gained-its-netdev-in-6.12.patch \
           file://0002-moal-do-not-free-an-skb-already-handed-to-the-stack.patch \
           file://0003-mlan-revalidate-the-ralist-after-the-send-helpers-drop-the-lock.patch \
           file://0004-moal-do-not-copy-every-transmitted-skb-by-default.patch \
           file://0005-moal-report-scan-results-outside-scan_req_lock.patch \
           file://0006-moal-give-each-mlan-spinlock-its-own-lockdep-class.patch \
           file://0007-mlan-aggregate-an-A-MSDU-under-one-hold-of-the-ralis.patch \
"
SRCREV = "09f41e1423e4806a127507d5fa284cd02c46772f"

S = "${WORKDIR}/git"

DEPENDS += "virtual/kernel"
RDEPENDS:${PN} += "kernel-module-cfg80211 nxp-wifi-firmware"

# Build the PCIe 9098 alone. The driver's Makefile can emit a dozen other
# chips' worth of objects, none of which this board has.
NXP_CHIP_FLAGS = " \
    CONFIG_PCIE9098=y \
    CONFIG_SD8978=n CONFIG_SD8987=n CONFIG_SD9177=n CONFIG_SD9098=n \
    CONFIG_SDIW610=n CONFIG_USBIW610=n CONFIG_SDAW693=n CONFIG_PCIEAW693=n \
    CONFIG_PCIE9097=n CONFIG_PCIE8897=n \
"

# cfg80211 full-MAC, STA and AP, with the legacy wireless-extensions paths off.
# Set on the command line because the driver's own Makefile autodetects these
# by reading CPP macros as make variables, which does not work here; a
# command-line variable is the one thing it cannot override.
#
# Unlike the OpenWrt build this needs no backports headers: that tree carries
# cfg80211 as a backported package, while this kernel provides it natively at
# 6.12, so the driver builds against the in-tree headers directly.
NXP_FEATURE_FLAGS = " \
    CONFIG_NXP_WLAN_DRIVER=m \
    CONFIG_STA_SUPPORT=y \
    CONFIG_UAP_SUPPORT=y \
    CONFIG_STA_CFG80211=y \
    CONFIG_UAP_CFG80211=y \
    CONFIG_STA_WEXT=n \
    CONFIG_UAP_WEXT=n \
"

# mlan_wmm.c and mlan_11n_aggr.c use INT_MAX without including it. OpenWrt
# never sees this because its backports build force-includes
# backport/backport.h, which drags in the header chain that defines it; a
# plain kernel build has no such umbrella. KCFLAGS rather than ccflags-y,
# because the driver's own Makefile appends to ccflags-y and a command-line
# assignment would silently discard everything it adds.
KCFLAGS = "-include linux/limits.h"

EXTRA_OEMAKE = " \
    -C ${STAGING_KERNEL_DIR} \
    M=${S} \
    KERNELDIR=${STAGING_KERNEL_DIR} \
    KCFLAGS='${KCFLAGS}' \
    ${NXP_CHIP_FLAGS} \
    ${NXP_FEATURE_FLAGS} \
"

MODULES_MODULE_SYMVERS_LOCATION = "."

do_compile() {
    oe_runmake modules
}

do_install() {
    install -d ${D}${nonarch_base_libdir}/modules/${KERNEL_VERSION}/extra
    install -m 0644 ${S}/mlan.ko ${D}${nonarch_base_libdir}/modules/${KERNEL_VERSION}/extra/
    install -m 0644 ${S}/moal.ko ${D}${nonarch_base_libdir}/modules/${KERNEL_VERSION}/extra/
}

# Loaded by hand or by the module autoloader; mlan must precede moal.
KERNEL_MODULE_AUTOLOAD += "mlan moal"
