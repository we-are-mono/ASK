SUMMARY = "ASK auto_bridge kernel module (auto_bridge.ko)"
LICENSE = "GPL-2.0-only"
LIC_FILES_CHKSUM = "file://${ASK_SRCROOT}/LICENSE;md5=b234ee4d69f5fce4486a80fdaf4a4263"

inherit module externalsrc

EXTERNALSRC       = "${ASK_SRCROOT}/auto_bridge"
EXTERNALSRC_BUILD = "${ASK_SRCROOT}/auto_bridge"

# CONFIG_ASK_AUTO_BRIDGE gates the obj-m line in Kbuild; the kernel tree
# doesn't define that Kconfig symbol so olddefconfig strips it — force here.
EXTRA_OEMAKE += "KERNEL_SOURCE=${STAGING_KERNEL_DIR} PLATFORM=LS1046A TARG_ARCH=${ARCH} CONFIG_ASK_AUTO_BRIDGE=m"

# auto_bridge's Makefile has only `all` (no modules/modules_install);
# we compile via "all" and install the .ko by hand. kernel-module-split
# still picks it up because it scans /lib/modules recursively.
MAKE_TARGETS = "all"

do_compile:prepend() {
    find ${S} -maxdepth 1 \( -name '*.o' -o -name '.*.cmd' -o -name '*.ko' -o -name '*.mod.c' -o -name 'modules.order' -o -name 'Module.symvers' \) -delete || true
}

fakeroot do_install() {
    install -d ${D}${nonarch_base_libdir}/modules/${KERNEL_VERSION}/extra/ask
    install -m 0644 ${S}/auto_bridge.ko \
        ${D}${nonarch_base_libdir}/modules/${KERNEL_VERSION}/extra/ask/

    # cmm needs auto_bridge.h at build time.
    install -d ${D}${includedir}
    install -m 0644 ${S}/include/auto_bridge.h ${D}${includedir}/
}

FILES:${PN}-dev = "${includedir}/auto_bridge.h"
