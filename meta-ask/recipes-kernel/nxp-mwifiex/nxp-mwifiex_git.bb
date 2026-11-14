SUMMARY = "NXP 88W9098 (moal/mlan) PCIe Wi-Fi driver"
DESCRIPTION = "NXP's MXM Wi-Fi driver for the 88W9098 (u-blox JODY-W3) over \
PCIe, as a cfg80211 full-MAC driver. This is the radio the Mono Gateway DK \
carries, from NXP's driver release for the image's kernel line: on 6.12 the \
same driver and commit the OpenWrt production build ships, on 6.18 its \
lf-6.18.37_2.1.0 counterpart."

LICENSE = "GPL-2.0-only"
LIC_FILES_CHKSUM = "file://LICENSE;md5=ab04ac0f249af12befccb94447c08b77"

inherit module ask-provenance

# Each kernel line's local fixes live in files/<line>/; NXP's later release
# carries several of the earlier line's itself.
FILESEXTRAPATHS:prepend := "${THISDIR}/files/${ASK_LINE}:"

SRC_URI = "git://github.com/nxp-imx/mwifiex.git;protocol=https;branch=${MWIFIEX_BRANCH}"

MWIFIEX_BRANCH:ask612 = "hotfix/lf-6.12.49_2.2.0_hotfix"
SRCREV:ask612 = "09f41e1423e4806a127507d5fa284cd02c46772f"
SRC_URI:append:ask612 = " \
           file://0001-cfg80211-set_monitor_channel-gained-its-netdev-in-6.12.patch \
           file://0002-moal-do-not-free-an-skb-already-handed-to-the-stack.patch \
           file://0003-mlan-revalidate-the-ralist-after-the-send-helpers-drop-the-lock.patch \
           file://0004-moal-do-not-copy-every-transmitted-skb-by-default.patch \
           file://0005-moal-report-scan-results-outside-scan_req_lock.patch \
           file://0006-moal-give-each-mlan-spinlock-its-own-lockdep-class.patch \
           file://0007-mlan-aggregate-an-A-MSDU-under-one-hold-of-the-ralis.patch \
           file://0008-moal-own-scan-requests-through-completion-and-teardown.patch \
           file://0009-mlan-take-INT_MAX-and-UINT_MAX-from-the-kernel.patch \
"

MWIFIEX_BRANCH:ask618 = "lf-6.18.37_2.1.0"
SRCREV:ask618 = "44f90628e368de23e9991de424fc2a1799c81044"
SRC_URI:append:ask618 = " \
           file://0001-mlan-revalidate-the-ralist-after-the-send-helpers-drop-the-lock.patch \
           file://0002-moal-do-not-copy-every-transmitted-skb-by-default.patch \
           file://0003-moal-report-cached-scan-results-to-cfg80211-outside-scan_req_lock.patch \
           file://0004-mlan-aggregate-an-A-MSDU-under-one-hold-of-the-ralist-lock.patch \
           file://0005-moal-own-cfg80211-scans-through-admission-completion-and-teardown.patch \
"

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
# Set on the command line, the one thing the driver's Makefile cannot override:
# left to itself, the lf-6.18 release derives them from the kernel's
# CONFIG_WIRELESS_EXT and CONFIG_WEXT_PRIV (y in this kernel) and would build
# WEXT in, and the lf-6.12 release reads CPP macros as make variables, which
# does not work here.
#
# Unlike the OpenWrt build this needs no backports headers: that tree carries
# cfg80211 as a backported package, while this kernel provides it natively,
# so the driver builds against the in-tree headers directly.
NXP_FEATURE_FLAGS = " \
    CONFIG_NXP_WLAN_DRIVER=m \
    CONFIG_STA_SUPPORT=y \
    CONFIG_UAP_SUPPORT=y \
    CONFIG_STA_CFG80211=y \
    CONFIG_UAP_CFG80211=y \
    CONFIG_STA_WEXT=n \
    CONFIG_UAP_WEXT=n \
"

EXTRA_OEMAKE = " \
    -C ${STAGING_KERNEL_DIR} \
    M=${S} \
    KERNELDIR=${STAGING_KERNEL_DIR} \
    ${NXP_CHIP_FLAGS} \
    ${NXP_FEATURE_FLAGS} \
"

MODULES_MODULE_SYMVERS_LOCATION = "."

# tools/tests/mwifiex_rx_dut.py builds its probe against this recipe's work
# directory -- moal's headers, its compile flags, the toolchain -- and refuses a
# loaded moal whose build ID differs from the moal.ko there. A package restored
# from another build directory's shared state comes without that directory, and
# its moal, built under another TMPDIR, never matches a local one. Every build
# directory compiles the driver itself, about a minute, so the two always agree.
SSTATE_SKIP_CREATION = "1"

# Under KASAN, GCC's ASan global metadata records each instrumented global's
# source file raw, TMPDIR-prefixed, past any -f*-prefix-map (ISSUES.md A326);
# as for cdx, the paths only appear in KASAN reports.
INSANE_SKIP:kernel-module-mlan-${KERNEL_VERSION} += "buildpaths"
INSANE_SKIP:kernel-module-moal-${KERNEL_VERSION} += "buildpaths"
INSANE_SKIP:${PN}-dbg += "buildpaths"

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
