SUMMARY = "ASK CDX data-plane kernel module (cdx.ko)"
LICENSE = "GPL-2.0-only"
LIC_FILES_CHKSUM = "file://${ASK_SRCROOT}/LICENSE;md5=b234ee4d69f5fce4486a80fdaf4a4263"

inherit module externalsrc

EXTERNALSRC       = "${ASK_SRCROOT}/cdx"
EXTERNALSRC_BUILD = "${ASK_SRCROOT}/cdx"

# Let module.bbclass see this recipe as the provider of
# kernel-module-cdx for cross-module DEPENDS resolution.
PROVIDES = "kernel-module-cdx"

# cdx/Makefile uses KERNELDIR (not KERNEL_SRC). CONFIG_ASK_CDX gates the
# obj-m line in Kbuild; the kernel tree doesn't define that Kconfig symbol,
# so olddefconfig strips it from .config — force it here.
EXTRA_OEMAKE += "KERNELDIR=${STAGING_KERNEL_DIR} PLATFORM=LS1046A CONFIG_ASK_CDX=m"

# ASK's cdx/Makefile has `modules` and `clean` but no `modules_install`.
# Compile via `modules` target; install the .ko by hand —
# kernel-module-split still picks it up because it scans /lib/modules/
# recursively for .ko files.
MAKE_TARGETS = "modules"

do_compile:prepend() {
    find ${S} -maxdepth 1 \( -name '*.o' -o -name '.*.cmd' -o -name '*.ko' -o -name '*.mod.c' -o -name 'modules.order' -o -name 'Module.symvers' \) -delete || true
}

fakeroot do_install() {
    install -d ${D}${nonarch_base_libdir}/modules/${KERNEL_VERSION}/extra/ask
    install -m 0644 ${S}/cdx.ko \
        ${D}${nonarch_base_libdir}/modules/${KERNEL_VERSION}/extra/ask/

    # Publish Module.symvers under the name module.bbclass looks for
    # when another recipe does DEPENDS="kernel-module-cdx".
    install -d ${D}${includedir}/kernel-module-cdx
    install -m 0644 ${S}/Module.symvers ${D}${includedir}/kernel-module-cdx/Module.symvers
}
