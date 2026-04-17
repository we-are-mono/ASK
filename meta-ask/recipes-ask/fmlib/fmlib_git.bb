SUMMARY = "NXP FMAN userspace library (libfm.a) with ASK extensions"
HOMEPAGE = "https://github.com/nxp-qoriq/fmlib"
LICENSE = "BSD-3-Clause"
LIC_FILES_CHKSUM = "file://LICENSE;md5=9c7bd5e45d066db084bdb3543d55b1ac"

SRC_URI = "git://github.com/nxp-qoriq/fmlib.git;protocol=https;nobranch=1 \
           file://01-mono-ask-extensions.patch \
"
SRCREV = "7a58ecaf0d90d71d6b78d3ac7998282a472c4394"

FILESEXTRAPATHS:prepend := "${ASK_SRCROOT}/patches/fmlib:"

ERROR_QA:remove = "patch-status"
WARN_QA:remove  = "patch-status"

S = "${WORKDIR}/git"

# fmlib uses kernel headers (sdk_fman) at compile time.
DEPENDS = "virtual/kernel"

# Produces a static archive only; nothing else to link at runtime.
inherit deploy

FMLIB_KINC  = "${STAGING_KERNEL_DIR}/drivers/net/ethernet/freescale/sdk_fman/inc"
FMLIB_UAPI  = "${STAGING_KERNEL_DIR}/include/uapi/linux/fmd"

do_compile() {
    # Same include set the kernel's out-of-tree sdk_fman Kbuild uses, so
    # both sdk_fman-internal defines (FM_MAX_NUM_OF_PFC_PRIORITIES, etc.)
    # and the uapi ioctl headers resolve correctly.
    oe_runmake libfm-arm.a \
        CC="${CC}" \
        AR="${AR}" \
        EXTRA_CFLAGS="-DNCSW_LINUX -DLS1043 \
                      -isystem ${FMLIB_KINC} \
                      -isystem ${FMLIB_KINC}/Peripherals \
                      -isystem ${FMLIB_KINC}/integrations/LS1043 \
                      -isystem ${FMLIB_KINC}/flib \
                      -isystem ${FMLIB_KINC}/cores \
                      -isystem ${FMLIB_KINC}/etc \
                      -isystem ${FMLIB_UAPI} \
                      -isystem ${FMLIB_UAPI}/Peripherals \
                      -isystem ${FMLIB_UAPI}/integrations"
    ln -sf libfm-arm.a ${S}/libfm.a
}

do_install() {
    install -d ${D}${libdir}
    install -m 0644 ${S}/libfm-arm.a ${D}${libdir}/libfm.a
    install -d ${D}${includedir}/fmd
    cp -r ${S}/include/fmd/. ${D}${includedir}/fmd/
}

# libxml2 is not used by fmlib itself, no RDEPENDS besides libc.
ALLOW_EMPTY:${PN} = "1"
FILES:${PN} = ""
FILES:${PN}-dev = "${includedir}/fmd"
FILES:${PN}-staticdev = "${libdir}/libfm.a"

# Static archive embeds debug info referencing TMPDIR; it is consumed at
# build time only and never shipped to the target.
INSANE_SKIP:${PN}-staticdev += "buildpaths"
