SUMMARY = "CMM — ASK conntrack-offload daemon"
DESCRIPTION = "Userspace connection manager that monitors netfilter conntrack \
and programs the CDX fast-path hardware classifier."
LICENSE = "GPL-2.0-only"
LIC_FILES_CHKSUM = "file://${ASK_SRCROOT}/LICENSE;md5=b234ee4d69f5fce4486a80fdaf4a4263"

inherit externalsrc

EXTERNALSRC = "${ASK_SRCROOT}/cmm"
EXTERNALSRC_BUILD = "${ASK_SRCROOT}/cmm"

DEPENDS = "libfci libcli libnetfilter-conntrack libnfnetlink libmnl libpcap libxcrypt auto-bridge"

# cmm/Makefile takes LIBFCI_DIR, ABM_DIR, SYSROOT — point them at the Yocto
# sysroot so pkg-config and includes resolve against our patched libraries.
# Yocto's pkg-config wrapper + PKG_CONFIG_* env vars are injected by the
# pkgconfig bbclass through the task environment. We only need to tell
# cmm's Makefile where the static libfci + auto_bridge include tree are.
# Extra defines that Armbian passes to CMM — keep identical so behavior
# matches the production build. Passed via env so cmm/Makefile's
# CFLAGS += ... appends (rather than its := overriding us).
export CFLAGS = "-DFLOW_STATS -DSEC_PROFILE_SUPPORT -DUSE_QOSCONNMARK \
                 -DENABLE_INGRESS_QOS -DIPSEC_NO_FLOW_CACHE -DVLAN_FILTER"

EXTRA_OEMAKE = " \
    CC='${CC}' \
    AR='${AR}' \
    LIBFCI_DIR=${STAGING_DIR_TARGET}${prefix} \
    ABM_DIR=${STAGING_DIR_TARGET}${prefix} \
    SYSROOT=${STAGING_DIR_TARGET}${prefix} \
    LDLIBS='-lpthread -lfci -lcli -lpcap -lnetfilter_conntrack -lnfnetlink -lmnl -lcrypt' \
"

inherit pkgconfig

fakeroot do_compile() {
    # externalsrc shares the source tree with the Debian "make userspace"
    # path. Wipe any stale Debian-toolchain objects before recompiling
    # against the Yocto sysroot — otherwise make decides "nothing to do"
    # and we ship the Debian binary.
    oe_runmake clean || true
    oe_runmake all
}

fakeroot do_install() {
    install -d ${D}${bindir}
    install -m 0755 ${S}/src/cmm ${D}${bindir}/cmm
}

FILES:${PN} = "${bindir}/cmm"

# Yocto's file-rdeps scanner auto-detects the shared-lib packages (libpcap1,
# libmnl0, libcli, libnetfilter-conntrack3, libnfnetlink0) — don't duplicate
# here or we race against parse order.


INHIBIT_PACKAGE_DEBUG_SPLIT = "1"
PACKAGES = "${PN}"
