SUMMARY = "ASK FCI kernel-userspace control interface (fci.ko)"
LICENSE = "GPL-2.0-only"
LIC_FILES_CHKSUM = "file://${ASK_SRCROOT}/LICENSE;md5=b234ee4d69f5fce4486a80fdaf4a4263"

inherit module externalsrc

EXTERNALSRC       = "${ASK_SRCROOT}/fci"
EXTERNALSRC_BUILD = "${ASK_SRCROOT}/fci"

DEPENDS = "kernel-module-cdx"

# CONFIG_ASK_FCI gates the obj-m line in Kbuild; the kernel tree doesn't
# define that Kconfig symbol so olddefconfig strips it — force here.
EXTRA_OEMAKE += " \
    KERNEL_SOURCE=${STAGING_KERNEL_DIR} \
    BOARD_ARCH=${ARCH} \
    CONFIG_ASK_FCI=m \
"

MAKE_TARGETS = "modules"

do_compile:prepend() {
    find ${S} -maxdepth 1 \( -name '*.o' -o -name '.*.cmd' -o -name '*.ko' -o -name '*.mod.c' -o -name 'modules.order' -o -name 'Module.symvers' \) -delete || true
}

fakeroot do_install() {
    install -d ${D}${nonarch_base_libdir}/modules/${KERNEL_VERSION}/extra/ask
    install -m 0644 ${S}/fci.ko \
        ${D}${nonarch_base_libdir}/modules/${KERNEL_VERSION}/extra/ask/
}
