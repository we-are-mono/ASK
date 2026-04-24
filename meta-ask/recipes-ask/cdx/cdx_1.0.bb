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

# Silence the [buildpaths] QA warning on the split kernel-module sub-package.
# cdx.ko embeds a handful of TMPDIR-prefixed header paths in its .rodata
# (rcupdate.h, dma-mapping.h, caam/regs.h) from __FILE__ macro expansions
# inside static-inline kernel helpers that cdx calls. We tried both
# `-fmacro-prefix-map` and `-ffile-prefix-map` via KCFLAGS with the canonical
# source paths, and verified the flags reach every gcc invocation — but
# those specific __FILE__ sites still leak through. Kernel's own in-tree
# modules (cfg80211.ko etc.) have the identical leak but aren't packaged as
# separate Yocto sub-packages so QA doesn't run on them. Paths are
# cosmetic (dmesg output gets full paths; no runtime or ABI impact).
#
# Package name format comes from kernel-module-split.bbclass:
#   ${KERNEL_MODULE_PACKAGE_PREFIX}${kernel_pkg}-module-<name>${SUFFIX}
# which for cdx under the default kernel recipe expands to
# `kernel-module-cdx-${KERNEL_VERSION}`. Using the variable keeps it
# version-agnostic across kernel bumps.
INSANE_SKIP:kernel-module-cdx-${KERNEL_VERSION} += "buildpaths"

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
