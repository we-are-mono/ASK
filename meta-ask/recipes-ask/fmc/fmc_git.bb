SUMMARY = "NXP FMAN configuration compiler with ASK extensions"
HOMEPAGE = "https://github.com/nxp-qoriq/fmc"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://LICENSE;md5=a504ab5a8ff235e67c7301214749346c"

SRC_URI = "git://github.com/nxp-qoriq/fmc.git;protocol=https;nobranch=1 \
           file://01-mono-ask-extensions.patch \
"
SRCREV = "5b9f4b16a864e9dfa58cdcc860be278a7f66ac18"

FILESEXTRAPATHS:prepend := "${ASK_SRCROOT}/patches/fmc:"

# Our patch is shared with the Armbian build; silence Yocto's header QA
# rather than carry an Upstream-Status line that would break Armbian.
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

    # Static archive + headers consumed by dpa_app at link time.
    install -d ${D}${libdir}
    install -m 0644 ${B}/libfmc.a ${D}${libdir}/libfmc.a
    install -d ${D}${includedir}/fmc
    install -m 0644 ${B}/*.h ${D}${includedir}/fmc/
}

FILES:${PN} = "${bindir}/fmc"
FILES:${PN}-dev = "${includedir}/fmc"
FILES:${PN}-staticdev = "${libdir}/libfmc.a"

# fmc includes debug info pointing at TMPDIR; fine for a dev image.
INSANE_SKIP:${PN}-dbg       += "buildpaths"
INSANE_SKIP:${PN}-staticdev += "buildpaths"
