SUMMARY = "Fast Control Interface static library (libfci.a)"
LICENSE = "GPL-2.0-only"
LIC_FILES_CHKSUM = "file://${ASK_SRCROOT}/LICENSE;md5=b234ee4d69f5fce4486a80fdaf4a4263"

inherit externalsrc

EXTERNALSRC = "${ASK_SRCROOT}/fci/lib"
EXTERNALSRC_BUILD = "${ASK_SRCROOT}/fci/lib"

fakeroot do_compile() {
    oe_runmake clean || true
    # libfci's Makefile adds -I$(CURDIR)/include itself; don't overwrite CFLAGS.
    oe_runmake CC="${CC}" AR="${AR}"
}

fakeroot do_install() {
    install -d ${D}${libdir}
    install -m 0644 ${S}/libfci.a ${D}${libdir}/libfci.a
    # cmm's Makefile does -I$(LIBFCI_DIR)/include and #include <libfci.h>
    # directly, so ship headers as-is (not under a libfci/ subdir).
    install -d ${D}${includedir}
    install -m 0644 ${S}/include/*.h ${D}${includedir}/
}

ALLOW_EMPTY:${PN} = "1"
FILES:${PN} = ""
FILES:${PN}-dev = "${includedir}/libfci.h"
FILES:${PN}-staticdev = "${libdir}/libfci.a"

INHIBIT_PACKAGE_DEBUG_SPLIT = "1"
PACKAGES = "${PN} ${PN}-dev ${PN}-staticdev"
