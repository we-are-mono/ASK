SUMMARY = "ask-flowtable — ASK default-on hardware flow-offload service"
DESCRIPTION = "Installs and maintains the nftables flowtable that drives the \
CDX/FMAN hardware offload, and re-applies it as interfaces and Wi-Fi VAPs \
change. Replaces the tools/ask_flowtable.py helper — a self-contained C \
service with no Python or JSON-library runtime dependency, so it ports \
unchanged to Armbian and NixOS."
LICENSE = "GPL-2.0-only"
LIC_FILES_CHKSUM = "file://${ASK_SRCROOT}/LICENSE;md5=b234ee4d69f5fce4486a80fdaf4a4263"

inherit externalsrc

EXTERNALSRC = "${ASK_SRCROOT}/flowtable"
EXTERNALSRC_BUILD = "${ASK_SRCROOT}/flowtable"

# Depends only on libc. It shells out to the runtime `nft` and reads sysfs and
# a raw NETLINK_ROUTE socket, so there is nothing to link against and no DEPENDS
# beyond the toolchain. Deliberately NO `export CFLAGS`: flowtable/Makefile owns
# its -O2 -g -Wall -Wextra -Werror -fPIE, appended on top of OE's default CFLAGS
# (which carry the sysroot and reproducible-build prefix-maps), exactly as
# cmm_1.0.bb does.
EXTRA_OEMAKE = "CC='${CC}'"

fakeroot do_compile() {
    # externalsrc builds in-place; wipe stale objects from a prior or
    # other-toolchain build before recompiling against the Yocto sysroot.
    oe_runmake clean || true
    oe_runmake all
}

fakeroot do_install() {
    install -d ${D}${sbindir}
    install -m 0755 ${S}/src/ask-flowtable ${D}${sbindir}/ask-flowtable
}

FILES:${PN} = "${sbindir}/ask-flowtable"

# The runtime tools the daemon shells out to.
RDEPENDS:${PN} += "nftables iproute2"

INHIBIT_PACKAGE_DEBUG_SPLIT = "1"
PACKAGES = "${PN}"
