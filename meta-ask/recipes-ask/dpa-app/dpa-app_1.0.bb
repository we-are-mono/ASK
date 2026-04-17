SUMMARY = "dpa_app — FMAN classifier loader (launched by cdx.ko)"
LICENSE = "GPL-2.0-only"
LIC_FILES_CHKSUM = "file://${ASK_SRCROOT}/LICENSE;md5=b234ee4d69f5fce4486a80fdaf4a4263"

inherit externalsrc

EXTERNALSRC = "${ASK_SRCROOT}/dpa_app"
EXTERNALSRC_BUILD = "${ASK_SRCROOT}/dpa_app"

DEPENDS = "fmlib fmc libcli libxml2 libxcrypt"

# The Yocto fmlib recipe installs include/fmd; fmc installs libfmc.a + headers.
EXTRA_OEMAKE = " \
    CC='${CC}' \
    CFLAGS='${CFLAGS} \
            -DENDIAN_LITTLE -DLS1043 -DNCSW_LINUX \
            -DDPAA_DEBUG_ENABLE -DSEC_PROFILE_SUPPORT -DVLAN_FILTER \
            -I${ASK_SRCROOT}/cdx \
            -I${STAGING_INCDIR}/fmc \
            -I${STAGING_INCDIR}/fmd \
            -I${STAGING_INCDIR}/fmd/Peripherals \
            -I${STAGING_INCDIR}/fmd/integrations \
            -I${STAGING_INCDIR}/libxml2' \
    LDFLAGS='${LDFLAGS} -lpthread -lcli -lfmc -lfm -lstdc++ -lxml2 -lm -lcrypt' \
"

# -DLS1043 is MANDATORY: it selects dpaa_integration_LS1043.h which sets
# DPAA_VERSION=11, which controls whether fmc_model includes the
# replicator fields. libfmc.a is built with -DLS1043, so dpa_app MUST
# match or sizeof(fmc_model_t) differs between caller and library, and
# fmc_compile's memset() overruns the BSS allocation and SIGSEGVs.

fakeroot do_compile() {
    oe_runmake clean || true
    oe_runmake all
}

fakeroot do_install() {
    install -d ${D}${bindir}
    install -m 0755 ${S}/dpa_app ${D}${bindir}/dpa_app
}

FILES:${PN} = "${bindir}/dpa_app"

INHIBIT_PACKAGE_DEBUG_SPLIT = "1"
PACKAGES = "${PN}"
