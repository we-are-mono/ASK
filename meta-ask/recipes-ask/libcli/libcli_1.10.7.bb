SUMMARY = "Dave Parrish's CLI library — telnet-style command interpreter"
HOMEPAGE = "https://github.com/dparrish/libcli"
LICENSE = "LGPL-2.1-or-later"
LIC_FILES_CHKSUM = "file://COPYING;md5=cb8aedd3bced19bd8026d96a8b6876d7"

DEPENDS = "libxcrypt"

SRC_URI = "git://github.com/dparrish/libcli.git;protocol=https;branch=stable"
SRCREV = "dcfd3b72a5587c11b54c25d7ffe69bd7e03acb59"

S = "${WORKDIR}/git"

do_compile() {
    # GCC 14+ enables -Wcalloc-transposed-args which libcli trips; suppress
    # while compiling the upstream source.
    oe_runmake CC="${CC}" AR="${AR}" \
        CFLAGS="${CFLAGS} -fPIC -Wno-error=calloc-transposed-args"
}

do_install() {
    install -d ${D}${libdir}
    install -d ${D}${includedir}
    install -m 0755 ${S}/libcli.so.* ${D}${libdir}/
    install -m 0644 ${S}/libcli.a ${D}${libdir}/
    install -m 0644 ${S}/libcli.h ${D}${includedir}/
    ln -sf libcli.so.1.10.7 ${D}${libdir}/libcli.so.1
    ln -sf libcli.so.1 ${D}${libdir}/libcli.so
}

FILES:${PN} = "${libdir}/libcli.so.*"
FILES:${PN}-dev = "${libdir}/libcli.so ${libdir}/libcli.a ${includedir}/libcli.h"
