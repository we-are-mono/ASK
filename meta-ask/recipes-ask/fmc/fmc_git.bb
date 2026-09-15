SUMMARY = "NXP FMAN configuration compiler with ASK extensions"
HOMEPAGE = "https://github.com/nxp-qoriq/fmc"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://LICENSE;md5=a504ab5a8ff235e67c7301214749346c"

SRC_URI = "git://github.com/nxp-qoriq/fmc.git;protocol=https;nobranch=1 \
           file://01-mono-ask-extensions.patch \
"
SRCREV = "5b9f4b16a864e9dfa58cdcc860be278a7f66ac18"

FILESEXTRAPATHS:prepend := "${ASK_SRCROOT}/patches/fmc:"

# Our patch is a bare diff (no commit-message envelope), so it has nowhere
# to carry an Upstream-Status line; silence Yocto's header QA. The tag itself
# is not the obstacle -- the sibling ASK patches (fmlib, libnfnetlink,
# libnetfilter-conntrack) do carry it and Armbian applies them fine.
ERROR_QA:remove = "patch-status"
WARN_QA:remove  = "patch-status"

DEPENDS = "fmlib libxml2 tclap flex-native bison-native"

S = "${WORKDIR}/git"
B = "${S}/source"

EXTRA_OEMAKE = " \
    CC='${CC}' \
    CXX='${CXX}' \
    AR='${AR}' \
    MACHINE=ls1046 \
    FMD_USPACE_HEADER_PATH=${STAGING_INCDIR}/fmd \
    FMD_USPACE_LIB_PATH=${STAGING_LIBDIR} \
    LIBXML2_HEADER_PATH=${STAGING_INCDIR}/libxml2 \
    TCLAP_HEADER_PATH=${STAGING_INCDIR} \
"

do_compile() {
    cd ${B} && oe_runmake default
}

do_install() {
    install -d ${D}${bindir}
    install -m 0755 ${B}/fmc ${D}${bindir}/fmc

    # libfmc.a and its headers are deliberately not installed: nothing links
    # against them. cdx builds the PCD itself, and the host-mode fmc used to
    # regenerate cdx_softparse.h and the PCD golden builds from this source
    # tree rather than from a staged library. See docs/in-kernel-pcd.md.

    # FMAN header-parser PDL + XSD schemas, read from /etc/fmc/config/ by fmc
    # itself. They ship in the fmc source tree, so install them here — from the
    # recipe that already fetches fmc, not an out-of-band source checkout.
    install -d ${D}${sysconfdir}/fmc/config
    install -m 0644 ${S}/etc/fmc/config/hxs_pdl_v3.xml ${D}${sysconfdir}/fmc/config/
    install -m 0644 ${S}/etc/fmc/config/cfgdata.xsd    ${D}${sysconfdir}/fmc/config/
    install -m 0644 ${S}/etc/fmc/config/netpcd.xsd     ${D}${sysconfdir}/fmc/config/
}

FILES:${PN} = "${bindir}/fmc ${sysconfdir}/fmc/config"
FILES:${PN}-dev = "${includedir}/fmc"
FILES:${PN}-staticdev = "${libdir}/libfmc.a"

# fmc includes debug info pointing at TMPDIR; fine for a dev image.
INSANE_SKIP:${PN}-dbg       += "buildpaths"
INSANE_SKIP:${PN}-staticdev += "buildpaths"
